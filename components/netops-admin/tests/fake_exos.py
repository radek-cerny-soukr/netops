from __future__ import annotations

import datetime
import shlex
from types import SimpleNamespace

from fake_fortios import DeviceRefused

FIRMWARE = "33.7.1.6"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class FakeExos:
    def __init__(self, hostname="sw-lab"):
        self.hostname = hostname
        self.firmware = FIRMWARE
        self.clock = datetime.datetime(2026, 9, 23, 12, 0, 0)
        self.vlans = {
            "Default": {"tag": "1"},
            "DATA": {"tag": "10"},
            "spare": {"tag": "3990", "description": "unused"},
        }
        self.accounts = ["admin", "netops-rw"]
        self.account_hashes = {}
        self.port_strings = {"11": "Zyxel-5p", "12": "Uplink-SW3"}
        self.foreign_session_users = []
        self.profiles, self.timers = {}, {}
        self.unsaved = False
        self.saves = 0
        self.credential = SimpleNamespace(login="netops-rw")
        self.fail_at_line = None
        self.drop_description = False
        self.timer_shift = 0
        self.body_override = None
        self.check_override = None
        self.check_unreadable = False
        self.refuse_save = False
        self.on_apply = None
        self.unreadable = False
        self.applied_blocks = []

    def advance(self, seconds):
        self.clock += datetime.timedelta(seconds=seconds)
        self._fire()

    def _fire(self):
        for timer in self.timers.values():
            if timer["next"] is not None and self.clock >= timer["next"]:
                timer["next"] = None
                self._run(self.profiles.get(timer["profile"], []), automatic=True)

    def _run(self, lines, automatic=False):
        self.persistent_mode = not automatic
        self.ignore_errors = not automatic
        for line in lines:
            if not self._command(shlex.split(line), automatic) and not self.ignore_errors:
                break

    def _command(self, words, automatic):
        if words == ["configure", "cli", "mode", "persistent"]:
            self.persistent_mode = True
            return True
        if words == ["configure", "cli", "mode", "scripting", "ignore-error"]:
            self.ignore_errors = True
            return True
        if words[:2] == ["create", "vlan"] and len(words) == 5 and words[3] == "tag":
            if words[2] in self.vlans:
                return False
            self.vlans[words[2]] = {"tag": words[4]}
        elif words[:2] == ["configure", "vlan"] and len(words) == 5 and words[3] == "description":
            if words[2] not in self.vlans:
                return False
            if not (self.drop_description and not automatic):
                self.vlans[words[2]]["description"] = words[4]
        elif words[:2] == ["unconfigure", "vlan"] and words[3:] == ["description"]:
            if words[2] not in self.vlans:
                return False
            self.vlans[words[2]].pop("description", None)
        elif words[:2] == ["delete", "vlan"] and len(words) == 3:
            if self.vlans.pop(words[2], None) is None:
                return False
        elif words[:2] == ["configure", "ports"] and len(words) == 5 and words[3] == "display-string":
            self.port_strings[words[2]] = words[4]
        elif words[:2] == ["unconfigure", "ports"] and words[3:] == ["display-string"]:
            self.port_strings.pop(words[2], None)
        elif words[:3] == ["create", "upm", "timer"] and len(words) == 4:
            self.timers[words[3]] = {"profile": None, "next": None}
        elif words[:3] == ["configure", "upm", "timer"] and words[4:5] == ["profile"]:
            self.timers[words[3]]["profile"] = words[5]
        elif words[:3] == ["configure", "upm", "timer"] and words[4:5] == ["after"]:
            self.timers[words[3]]["next"] = self.clock + datetime.timedelta(seconds=int(words[5]) + self.timer_shift)
        elif words[:3] == ["delete", "upm", "timer"]:
            if self.timers.pop(words[3], None) is None:
                return False
        elif words[:3] == ["delete", "upm", "profile"]:
            if self.profiles.pop(words[3], None) is None:
                return False
        else:
            return False
        self.unsaved = True
        return True

    def apply(self, steps, spec):
        assert spec.anchor == ("%s." % self.hostname).encode("ascii")
        self._fire()
        self.applied_blocks.append(list(steps))
        if self.on_apply is not None:
            self.on_apply(self, steps)
        accepted, body, profile, plain = 0, None, None, 0
        for step in steps:
            if isinstance(step, tuple) and step[0] == "ask":
                if step[1] == "save configuration":
                    body = "save"
                else:
                    profile, body = step[1].split()[3], []
            elif isinstance(step, tuple) and step[0] == "raw":
                body.append(step[1])
            elif body == "save":
                assert step == "y"
                if self.refuse_save:
                    raise DeviceRefused(accepted)
                self.unsaved, body = False, None
                self.saves += 1
            elif body is not None:
                assert step == "."
                self.profiles[profile], body = list(self.body_override or body), None
                self.unsaved = True
            else:
                plain += 1
                if self.fail_at_line == plain or not self._command(shlex.split(step), False):
                    raise DeviceRefused(accepted)
            accepted += 1
        return accepted

    def login_prefix(self, spec):
        return b"*" if self.unsaved else b""

    def snapshot(self):
        self._fire()
        if self.unreadable:
            raise RuntimeError("snapshot unavailable")
        lines = ["#", "# Module aaa configuration.", "#"]
        for name in self.accounts:
            lines.append('create account admin %s encrypted "%s"' % (name, self.account_hashes.get(name, "$5$x$y")))
        lines += ["#", "# Module vlan configuration.", "#"]
        for name, attributes in self.vlans.items():
            if name != "Default":
                lines.append('create vlan "%s"' % name)
            if "description" in attributes:
                lines.append('configure vlan %s description "%s"' % (name, attributes["description"]))
            if name != "Default":
                lines.append("configure vlan %s tag %s" % (name, attributes["tag"]))
        if "DATA" in self.vlans:
            lines.append("configure vlan DATA add ports 1-4 untagged")
        for port, text in sorted(self.port_strings.items()):
            lines.append("configure ports %s display-string %s" % (port, text))
        lines.append("configure ports 10 description-string \"Default settings for the access port\"")
        lines += ["#", "# Module upm configuration.", "#"]
        for name, body in self.profiles.items():
            lines.append("create upm profile %s" % name)
            lines.extend(body)
            lines += ["", "."]
        for name, timer in self.timers.items():
            lines.append("create upm timer %s" % name)
            if timer["profile"]:
                lines.append("configure upm timer %s profile %s" % (name, timer["profile"]))
        return "\n".join(lines) + "\n"

    def query(self, command):
        self._fire()
        if command == "show switch":
            return "\nSysName:          %s\nCurrent Time:     %s\n" % (self.hostname, self.clock.strftime("%a %b %e %H:%M:%S %Y"))
        if command == "show session":
            rows = ["*753        Wed Sep 23 17:18:01 2026 netop .. ssh2    sshKey        dis  192.0.2.9"]
            rows += [" %d        Wed Sep 23 10:11:01 2026 %-8s ssh2    sshKey        dis  192.0.2.8" % (400 + index, name)
                     for index, name in enumerate(self.foreign_session_users)]
            return "    #       Login Time               User     Type    Auth          Auth Location\n====\n" + \
                "\n".join(rows) + "\n"
        if command == "show version":
            return "Image   : ExtremeXOS version %s by release-manager\n" % self.firmware
        if command == "show upm timers":
            rows = "".join("%-16s %-14s eo            %s\n" % (name, timer["profile"] or "",
                                                               timer["next"].strftime(TIME_FORMAT) if timer["next"] else "")
                           for name, timer in self.timers.items())
            clock = "Current Time: %s\n" % self.clock.strftime(TIME_FORMAT) if self.timers else ""
            return "%s----\nUPM               Profile       Flags              Next Execution\n----\n%s----\n" % (
                clock, rows)
        if command == "show upm profile":
            return "====\nUPM Profile          Events                 Flags Ports\n====\n" + "".join(
                "%-20s UPM-Timer(%s e \n" % (name, name[:13]) for name in self.profiles) + "====\n"
        if command.startswith("show upm profile "):
            name = command.split()[3]
            if name not in self.profiles:
                return "%% Invalid input detected at '^' marker.\n"
            return ("Created at : x\n\n************Profile Contents Begin************\n%s\n\n"
                    "************Profile Contents Ends*************\n\nProfile State: Enabled\n"
                    % "\n".join(self.profiles[name]))
        raise AssertionError("unexpected query %r" % command)

    def check_query(self, command):
        self._fire()
        if self.check_unreadable:
            raise RuntimeError("check account unavailable")
        if command.startswith("show ports "):
            port = command.split()[2]
            if self.check_override is not None and port in self.check_override:
                text = self.check_override[port]
            elif not port.isdigit() or not 1 <= int(port) <= 16:
                return "%% Invalid port number detected.\n"
            else:
                text = self.port_strings.get(port)
            return "Port:\t%s(%s):\n\tVirtual-router:\tVR-Default\n" % (port, text) if text else "Port:\t%s\n" % port
        key = command.split()[2]
        attributes = self.vlans.get(key)
        if self.check_override is not None and key in self.check_override:
            attributes = self.check_override[key]
        if attributes is None:
            return "                               ^\n%% Invalid numeric list detected at '^' marker.\n"
        return ("VLAN Interface with name %s created by user\n"
                "    Admin State:\t Enabled     Tagging:\t802.1Q Tag %s \n"
                "    Description:\t %s \n"
                "    Ports:   0. \t  (Number of active ports=0)\n"
                % (key, attributes["tag"], attributes.get("description", "None")))
