from __future__ import annotations

import datetime
import itertools
import json
import urllib.parse
from types import SimpleNamespace

from fake_fortios import FakeFortiOS, quoted

from netops_admin.access import AccessError
from netops_auditor import l1_fortios

OWN_SECTIONS = ("system api-user", "system accprofile")
NAME_LISTS = ("srcintf", "dstintf", "srcaddr", "dstaddr", "service")


class FakeFortiOSWebhook(FakeFortiOS):
    firmware = ("8.0.2", "0251")

    def __init__(self, hostname="fw-lab"):
        super().__init__(hostname)
        self.credential = SimpleNamespace(login="netops-rw", kind="password")
        self.interface_lines = {"port1": ["set ip 192.0.2.1 255.255.255.0", "set allowaccess ping https ssh"]}
        self.admin_sport = None
        self.webhooks = {}
        self.api_users = {}
        self.accprofiles = {}
        self.calls = []
        self.issued = []
        self.webhook_broken = False
        self.header_override = None
        self.key_answer = None
        self.keys = itertools.count(1)
        self.write_admins = {"netops-rw": "super_admin"}

    def _sections(self, lines):
        own, rest, depth, inside = [], [], 0, None
        for raw in lines:
            tokens = l1_fortios.tokenize(raw.strip())
            if inside is None and tokens[:1] == ["config"] and " ".join(tokens[1:]) in OWN_SECTIONS:
                inside, depth = " ".join(tokens[1:]), 1
                own.append(raw)
                continue
            if inside is not None:
                own.append(raw)
                if tokens[:1] == ["config"]:
                    depth += 1
                elif tokens[:1] == ["end"]:
                    depth -= 1
                    if depth == 0:
                        inside = None
                continue
            rest.append(raw)
        return own, rest

    def _run(self, lines, automatic=False):
        own, rest = self._sections(lines)
        self._own(own)
        self._actions(rest)
        return super()._run(rest, automatic) + len(own)

    def _own(self, lines):
        stack, current, sub = [], None, None
        for raw in lines:
            tokens = l1_fortios.tokenize(raw.strip())
            command = tokens[0]
            if command == "config":
                stack.append(" ".join(tokens[1:]))
            elif command == "end":
                stack.pop()
                sub = None if len(stack) == 1 else sub
            elif command == "edit" and len(stack) == 1:
                current = tokens[1]
                table = self.api_users if stack[0] == "system api-user" else self.accprofiles
                table.setdefault(current, {"trusthost": []} if stack[0] == "system api-user" else {})
            elif command == "edit":
                sub = {}
                self.api_users[current]["trusthost"].append(sub)
            elif command == "delete":
                table = self.api_users if stack[0] == "system api-user" else self.accprofiles
                table.pop(tokens[1], None)
            elif command == "set" and sub is not None and len(stack) == 2:
                sub[tokens[1]] = " ".join(tokens[2:])
            elif command == "set":
                table = self.api_users if stack[0] == "system api-user" else self.accprofiles
                table[current][tokens[1]] = " ".join(tokens[2:])

    def _actions(self, lines):
        stack, current, header = [], None, None
        for raw in lines:
            tokens = l1_fortios.tokenize(raw.strip())
            if not tokens:
                continue
            command = tokens[0]
            if command == "config":
                stack.append(" ".join(tokens[1:]))
            elif command == "end":
                stack.pop()
            elif not stack or stack[0] != "system automation-action":
                continue
            elif command == "delete":
                self.webhooks.pop(tokens[1], None)
            elif command == "edit" and len(stack) == 1:
                current = tokens[1]
            elif command == "edit":
                header = {}
                self.webhooks.setdefault(current, {}).setdefault("headers", []).append(header)
            elif command == "set" and len(stack) == 2:
                header[tokens[1]] = tokens[2]
            elif command == "set" and tokens[1] == "action-type" and tokens[2] == "webhook":
                self.webhooks.setdefault(current, {})
            elif command == "set" and current in self.webhooks:
                self.webhooks[current][tokens[1]] = tokens[2]

    def apply(self, steps, spec):
        lines, stack = [], []
        for step in steps:
            answered = isinstance(step, tuple) and step[0] == "password"
            line = step[1] if answered else step
            tokens = l1_fortios.tokenize(line.strip())
            asks = stack == ["system api-user"] and tokens[:1] in (["next"], ["delete"])
            if tokens[:1] == ["config"]:
                stack.append(" ".join(tokens[1:]))
            elif tokens[:1] == ["end"] and stack:
                stack.pop()
            lines.append(line)
            if asks and not answered:
                super().apply(lines, spec)
                raise AccessError("interactive session failed after %d lines: the session to 192.0.2.1 ended before"
                                  " any of the 2 awaited pattern(s) matched, 86 byte(s) seen" % (len(lines) - 1),
                                  len(lines) - 1)
        return super().apply(lines, spec)

    def _fire(self):
        for name, stitch in list(self.stitches.items()):
            trigger = self.triggers.get(stitch["trigger"])
            if name in self.fired or trigger is None:
                continue
            if self.clock < datetime.datetime.strptime(trigger, "%Y-%m-%d %H:%M:%S"):
                continue
            self.fired.add(name)
            if stitch["action"] in self.webhooks:
                self._call(self.webhooks[stitch["action"]])
            else:
                self._run(self.actions[stitch["action"]].split("\n"), automatic=True)

    def _call(self, hook):
        host, _, path = hook.get("uri", "").partition("/")
        token = next((h.get("value", "")[7:] for h in hook.get("headers", []) if h.get("key") == "Authorization"), "")
        user = next((u for u in self.api_users.values() if u.get("api-key") == token), None)
        allowed = (user is not None and not self.webhook_broken and hook.get("protocol") == "https"
                   and any(t.get("ipv4-trusthost") == host + " 255.255.255.255" for t in user["trusthost"])
                   and self.accprofiles.get(user.get("accprofile"), {}).get("fwgrp") == "read-write")
        if not allowed:
            self.calls.append((hook.get("method"), path, 401))
            return
        parts = [urllib.parse.unquote(p) for p in path.split("/")]
        table = {"firewall/policy": self.policies, "firewall/address": self.addresses}["/".join(parts[3:5])]
        method = hook.get("method")
        body = json.loads(hook.get("http-body") or "{}")
        values = {k: " ".join(i["name"] for i in v) if isinstance(v, list) else str(v) for k, v in body.items()}
        if method == "delete":
            table.pop(parts[5], None)
        elif method == "put":
            table[parts[5]].update({k: v for k, v in values.items() if v != ""})
            for k in [k for k, v in values.items() if v == ""]:
                table[parts[5]].pop(k, None)
        elif method == "post":
            key = values.pop("policyid", None) or values.pop("name")
            table[key] = dict({"uuid": self._uuid()}, **values)
        self.calls.append((method, path, 200))

    def generate_api_key(self, command, spec):
        assert spec.anchor == ("\n%s" % self.hostname).encode("ascii")
        self._connect()
        self.applied_blocks.append([command])
        user = l1_fortios.tokenize(command)[3]
        if user not in self.api_users:
            return "entry is not found in table\nCommand fail. Return code -3\n"
        token = "tk%028d" % next(self.keys)
        self.api_users[user]["api-key"] = token
        self.issued.append(token)
        if self.key_answer is not None:
            return self.key_answer
        return ("Please enter current administrator password:\nNew API key: %s\n\nNOTE: The bearer of this API key"
                " will be granted all access privileges assigned to the api-user %s.\n" % (token, user))

    def _webhook_lines(self, name):
        hook = self.webhooks[name]
        lines = ['    edit "%s"' % name, "        set description ''", "        set action-type webhook",
                 "        set minimum-interval 0", '        set message "%%log.logdesc%%"']
        for key in ("protocol", "method", "uri", "http-body", "port", "verify-host-cert"):
            if key in hook:
                value = hook[key]
                lines.append("        set %s %s" % (key, quoted(value) if key in ("uri", "http-body") else value))
            elif key == "http-body":
                lines.append("        set http-body ''")
        lines.append("        config http-headers")
        for number, header in enumerate(hook.get("headers", []), 1):
            value = self.header_override if self.header_override is not None else header.get("value", "")
            lines += ["            edit %d" % number, '                set key "%s"' % header.get("key", ""),
                      "                set value %s" % quoted(value), "            next"]
        return lines + ["        end", "    next"]

    def _user_lines(self, name, full):
        user = self.api_users[name]
        lines = ['    edit "%s"' % name]
        if "accprofile" in user:
            lines.append('        set accprofile "%s"' % user["accprofile"])
        if full and "api-key" in user:
            lines.append("        set api-key ENC SH2-not-the-token")
        lines.append("        config trusthost")
        for number, host in enumerate(user["trusthost"], 1):
            lines += ["            edit %d" % number, "                set ipv4-trusthost %s" % host.get("ipv4-trusthost", ""),
                      "            next"]
        return lines + ["        end", "    next"]

    def _profile_lines(self, name):
        return ['    edit "%s"' % name] + ["        set %s %s" % item for item in self.accprofiles[name].items()] + ["    next"]

    def snapshot(self):
        text = super().snapshot()
        admins = "".join('    edit "%s"\n        set accprofile "%s"\n    next\n' % item for item in self.write_admins.items())
        text = text.replace("config system admin\n", "config system admin\n" + admins, 1)
        for name, lines in self.interface_lines.items():
            text = text.replace('    edit "%s"\n    next' % name,
                                '    edit "%s"\n' % name + "".join("        %s\n" % line for line in lines) + "    next")
        extra = ["config system api-user"]
        for name in self.api_users:
            extra += self._user_lines(name, True)
        extra += ["end", "config system accprofile", '    edit "prof_admin"', "        set fwgrp read-write", "    next"]
        for name in self.accprofiles:
            extra += self._profile_lines(name)
        extra += ["end", "config system automation-action"]
        for name in self.webhooks:
            extra += self._webhook_lines(name)
        extra += ["end"]
        if self.admin_sport is not None:
            text = text.replace("config system global\n", "config system global\n    set admin-sport %d\n" % self.admin_sport, 1)
        return text + "\n".join(extra) + "\n"

    def query(self, command):
        words = command.split()
        if command == "show system global":
            self._connect()
            port = "" if self.admin_sport is None else "    set admin-sport %d\n" % self.admin_sport
            return 'config system global\n    set hostname "%s"\n%send\n' % (self.hostname, port)
        if words[:3] == ["show", "full-configuration", "system"] and words[3] == "automation-action":
            self._connect()
            self._fire()
            if words[4] not in self.webhooks:
                return "entry is not found in table\n"
            return "config system automation-action\n" + "\n".join(self._webhook_lines(words[4])) + "\nend\n"
        if words[:3] == ["show", "system", "api-user"]:
            self._connect()
            if words[3] not in self.api_users:
                return "entry is not found in table\n"
            return "config system api-user\n" + "\n".join(self._user_lines(words[3], True)) + "\nend\n"
        if words[:3] == ["show", "system", "accprofile"]:
            self._connect()
            if words[3] not in self.accprofiles:
                return "entry is not found in table\n"
            return "config system accprofile\n" + "\n".join(self._profile_lines(words[3])) + "\nend\n"
        return super().query(command)
