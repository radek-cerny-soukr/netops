from __future__ import annotations

import datetime
import itertools
import re
from types import SimpleNamespace

from netops_auditor import l1_fortios

HEADER = "#config-version=FGT60F-%s-FW-build%s-260420:opmode=1:vdom=0:user=netops-rw"


def quoted(value):
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


READ_PROFILE = {"secfabgrp": "read", "ftviewgrp": "read", "authgrp": "read", "sysgrp": "read", "netgrp": "read",
                "loggrp": "read", "fwgrp": "read", "vpngrp": "read", "utmgrp": "read", "wifi": "read",
                "cli-diagnose": "enable", "cli-get": "enable", "cli-show": "enable", "cli-exec": "enable"}


class DeviceRefused(Exception):
    def __init__(self, accepted_lines):
        super().__init__("refused")
        self.accepted_lines = accepted_lines


class FakeFortiOS:
    firmware = ("8.0.0", "0167")

    def __init__(self, hostname="fw-lab"):
        self.hostname = hostname
        self.clock = datetime.datetime(2026, 9, 23, 12, 0, 0)
        self.uuids = itertools.count(1)
        self.addresses = {
            "all": {"uuid": self._uuid()},
            "srv-web": {"uuid": self._uuid(), "subnet": "192.0.2.20 255.255.255.255", "comment": "web"},
            "spare-host": {"uuid": self._uuid(), "subnet": "192.0.2.21 255.255.255.255", "comment": "unused"},
        }
        self.admins = ["netops-rw"]
        self.admin_comments = {}
        self.foreign_session_users = []
        self.actions, self.triggers, self.stitches = {}, {}, {}
        self.fired = set()
        self.credential = SimpleNamespace(login="netops-rw")
        self.check_credential = SimpleNamespace(login="netops-check")
        self.fail_at_line = None
        self.drop_comment = False
        self.on_apply = None
        self.unreadable = False
        self.applied_blocks = []
        self.trigger_override = None
        self.trigger_types = {}
        self.trigger_type_override = None
        self.check_override = None
        self.check_unreadable = False
        self.policies = {"1": {"dstaddr": "srv-web"}}
        self.interfaces = ["port1", "port2", "wan1"]
        self.services = ["HTTP", "HTTPS"]
        self.snapshot_extra = []
        self.policy_hidden = {"status": "enable", "action": "deny"}
        self.policy_front = False
        self.unreachable = False
        self.unreachable_after_apply = None
        self.fail_next = 0
        self.account_profiles = {"netops-rw": "netops-write", "netops-check": "netops-check"}
        self.profile_rights = {"netops-check": dict(READ_PROFILE)}
        self.rights_answers = {}
        self.rights_unreadable = False
        self.rights_queries = []

    def _uuid(self):
        return "00000000-0000-4000-8000-%012d" % next(self.uuids)

    def advance(self, seconds):
        self.clock += datetime.timedelta(seconds=seconds)
        self._fire()

    def _connect(self):
        if self.unreachable:
            raise RuntimeError("device unreachable")
        if self.fail_next > 0:
            self.fail_next -= 1
            raise RuntimeError("injected failure")

    def _fire(self):
        for name, stitch in list(self.stitches.items()):
            trigger = self.triggers.get(stitch["trigger"])
            if name in self.fired or trigger is None:
                continue
            due = datetime.datetime.strptime(trigger, "%Y-%m-%d %H:%M:%S")
            if self.clock >= due:
                self.fired.add(name)
                self._run(self.actions[stitch["action"]].split("\n"), automatic=True)

    def _run(self, lines, automatic=False):
        stack, current, pending, owner = [], None, None, None
        accepted = 0
        for number, raw in enumerate(lines, 1):
            if pending is not None:
                pending.append(raw)
                text = "\n".join(pending)
                if not l1_fortios._quote_state(text)[0]:
                    body = l1_fortios.tokenize(text[text.index('"'):])[0]
                    self.actions.setdefault(current, {})
                    self.actions[current] = body
                    pending = None
                accepted += 1
                continue
            tokens = l1_fortios.tokenize(raw.strip())
            if not tokens:
                continue
            if self.fail_at_line == number and not automatic:
                raise DeviceRefused(accepted)
            command = tokens[0]
            section = stack[-1] if stack else None
            if command == "config":
                stack.append(" ".join(tokens[1:]))
            elif command == "end":
                stack.pop()
                current = None
            elif command == "edit":
                current = tokens[1]
                if section == "firewall policy":
                    if current not in self.policies:
                        entry = {"uuid": self._uuid()}
                        if self.policy_front:
                            self.policies = {current: entry, **self.policies}
                        else:
                            self.policies[current] = entry
                if section == "firewall address" and current not in self.addresses:
                    self.addresses[current] = {"uuid": self._uuid()}
                elif section == "system automation-stitch":
                    owner = current
                    self.stitches.setdefault(current, {"trigger": None, "action": None})
            elif command == "next":
                current = None
            elif command == "delete":
                target = {"firewall policy": self.policies, "firewall address": self.addresses, "system automation-action": self.actions,
                          "system automation-trigger": self.triggers, "system automation-stitch": self.stitches}[section]
                target.pop(tokens[1], None)
                self.fired.discard(tokens[1])
            elif command == "set" and tokens[1] == "script" and section == "system automation-action":
                if not l1_fortios._quote_state(raw)[0]:
                    self.actions[current] = l1_fortios.tokenize(raw[raw.index('"'):])[0]
                else:
                    pending = [raw.strip()]
            elif command == "set" and section == "firewall policy":
                self.policies[current][tokens[1]] = " ".join(tokens[2:])
                if tokens[1:3] == ["action", "deny"]:
                    self.policies[current]["logtraffic"] = "disable"
            elif command == "unset" and section == "firewall policy":
                self.policies[current].pop(tokens[1], None)
            elif command == "set" and section == "firewall address":
                if tokens[1] == "comment" and self.drop_comment and not automatic:
                    pass
                else:
                    self.addresses[current][tokens[1]] = " ".join(tokens[2:])
            elif command == "unset" and section == "firewall address":
                self.addresses[current].pop(tokens[1], None)
            elif command == "set" and section == "system automation-trigger" and tokens[1] == "trigger-type":
                self.trigger_types[current] = tokens[2]
            elif command == "set" and section == "system automation-trigger" and tokens[1] == "trigger-datetime":
                self.triggers[current] = " ".join(tokens[2:])
            elif command == "set" and section == "system automation-stitch" and tokens[1] == "trigger":
                self.stitches[current]["trigger"] = tokens[2]
            elif command == "set" and section == "actions":
                self.stitches[owner]["action"] = tokens[2]
            accepted += 1
        return accepted

    def snapshot(self):
        self._connect()
        self._fire()
        if self.unreadable:
            raise RuntimeError("snapshot unavailable")
        lines = [HEADER % self.firmware, "config system global", '    set hostname "%s"' % self.hostname, "end",
                 "config system admin", '    edit "admin-example"', "        set trusthost1 192.0.2.0 255.255.255.0",
                 "        set ip6-trusthost1 2001:db8::/32", "    next", "end",
                 "config firewall address"]
        for name, attributes in self.addresses.items():
            lines.append('    edit "%s"' % name)
            for key in ("uuid", "comment", "subnet"):
                if key in attributes:
                    value = attributes[key]
                    lines.append('        set %s %s' % (key, quoted(value) if key == "comment" else value))
            lines.append("    next")
        lines.append("end")
        lines.append("config system interface")
        for name in self.interfaces:
            lines += ['    edit "%s"' % name, "    next"]
        lines.append("end")
        lines.append("config firewall service custom")
        for name in self.services:
            lines += ['    edit "%s"' % name, "    next"]
        lines.append("end")
        lines += self.snapshot_extra
        lines.append("config firewall policy")
        for name, attributes in self.policies.items():
            lines.append("    edit %s" % name)
            for key, value in attributes.items():
                if self.policy_hidden.get(key) == value:
                    continue
                lines.append("        set %s %s" % (key, value if key == "uuid" else (quoted(value) if key in ("name", "comments", "schedule") else " ".join(quoted(v) for v in value.split()))))
            lines.append("    next")
        lines.append("end")
        return "\n".join(lines) + "\n"

    def query(self, command):
        self._connect()
        self._fire()
        if command == "get system status":
            return "Version: FortiGate-60F v%s,build%s,260420 (GA.F)\nSystem time: %s\n" % \
                (self.firmware + (self.clock.strftime("%a %b %d %H:%M:%S %Y"),))
        if command == "get system admin list":
            rows = ["netops-rw            ssh            wan1:192.0.2.1:22        root     netops-rw   192.0.2.9:4000   now"]
            rows += ["%-20s ssh            wan1:192.0.2.1:22        root     super_admin 192.0.2.8:4000   now" % name
                     for name in self.foreign_session_users]
            return ("FortiGate-60F $ username             local          device                   vdom     profile"
                    "     remote           started\nFortimanager_Access  fgc  N/A  root  super_admin  :0  now\n"
                    + "\n".join(rows) + "\n")
        if command == "show system admin":
            return "config system admin\n" + "".join(
                '    edit "%s"\n        set comments "%s"\n    next\n' % (name, self.admin_comments.get(name, "account"))
                for name in self.admins) + "end\n"
        if command == "show system automation-stitch":
            return "config system automation-stitch\n" + "".join(
                '    edit "%s"\n    next\n' % name for name in self.stitches) + "end\n"
        words = command.split()
        kind, name = words[2], words[3]
        if kind == "automation-action":
            if name not in self.actions:
                return "entry is not found in table\n"
            return ('config system automation-action\n    edit "%s"\n        set action-type cli-script\n'
                    '        set script %s\n    next\nend\n' % (name, quoted(self.actions[name])))
        if kind == "automation-trigger":
            if name not in self.triggers:
                return "entry is not found in table\n"
            kind = self.trigger_type_override or self.trigger_types.get(name)
            typed = "" if kind is None else "        set trigger-type %s\n" % kind
            return ('config system automation-trigger\n    edit "%s"\n%s'
                    '        set trigger-frequency once\n        set trigger-datetime %s\n    next\nend\n'
                    % (name, typed, self.trigger_override or self.triggers[name]))
        if name not in self.stitches:
            return "entry is not found in table\n"
        stitch = self.stitches[name]
        return ('config system automation-stitch\n    edit "%s"\n        set trigger "%s"\n        config actions\n'
                '            edit 1\n                set action "%s"\n            next\n        end\n    next\nend\n'
                % (name, stitch["trigger"], stitch["action"]))

    def apply(self, lines, spec):
        assert spec.anchor == ("\n%s" % self.hostname).encode("ascii")
        assert all(isinstance(line, str) for line in lines)
        self._connect()
        self._fire()
        self.applied_blocks.append(list(lines))
        if self.on_apply is not None:
            self.on_apply(self, lines)
        done = self._run(lines)
        if self.unreachable_after_apply is not None and self.unreachable_after_apply(lines):
            self.unreachable = True
        return done

    def check_query(self, command):
        self._connect()
        self._fire()
        if self.check_unreadable:
            raise RuntimeError("check account unavailable")
        key = command.split('"')[1]
        if command.startswith("show firewall policy"):
            return self._policy_show(key)
        attributes = self.addresses.get(key)
        if self.check_override is not None and key in self.check_override:
            attributes = self.check_override[key]
        if attributes is None:
            return "entry is not found in table\n"
        lines = ["FortiGate-60F $ config firewall address", '    edit "%s"' % key]
        for name in ("uuid", "comment", "subnet"):
            if name in attributes:
                value = attributes[name]
                lines.append("        set %s %s" % (name, quoted(value) if name == "comment" else value))
        return "\n".join(lines + ["    next", "end", ""])

    def _policy_show(self, key):
        attributes = self.policies.get(key)
        if attributes is None:
            return "entry is not found in table\n"
        lines = ["FortiGate-60F $ config firewall policy", "    edit %s" % key]
        for name, value in attributes.items():
            if self.policy_hidden.get(name) == value:
                continue
            if name == "uuid":
                lines.append("        set uuid %s" % value)
            elif name in ("name", "comments", "schedule"):
                lines.append("        set %s %s" % (name, quoted(value)))
            else:
                lines.append("        set %s %s" % (name, " ".join(quoted(v) for v in value.split())))
        return "\n".join(lines + ["    next", "end", ""])

    def own_query(self, command, check=False):
        self._connect()
        login = (self.check_credential if check else self.credential).login
        self.rights_queries.append((login, command))
        if self.rights_unreadable:
            raise RuntimeError("rights unavailable")
        if command in self.rights_answers:
            return self.rights_answers[command]
        admin = re.fullmatch(r'show system admin "(.+)"', command)
        if admin is not None:
            assert admin.group(1) == login, command
            profile = self.account_profiles.get(login)
            if profile is None:
                return "entry is not found in table\n"
            return ('config system admin\n    edit "%s"\n        set vdom "root"\n'
                    '        set trusthost1 192.0.2.9 255.255.255.255\n        set accprofile "%s"\n'
                    '        set password ENC SH2c2VjcmV0LWhhc2gtdmFsdWU=\n    next\nend\n' % (login, profile))
        profile = re.fullmatch(r'show system accprofile "(.+)"', command)
        assert profile is not None and check, command
        rights = self.profile_rights.get(profile.group(1))
        if rights is None:
            return "config system accprofile\nend\n"
        return ('config system accprofile\n    edit "%s"\n' % profile.group(1)
                + "".join("        set %s %s\n" % item for item in rights.items()) + "    next\nend\n")
