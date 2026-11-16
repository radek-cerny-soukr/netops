"""Simulated Arista cEOS 4.36.1F for netops-admin tests.

Every answer is built from an anonymised output measured on cEOSLab 4.36.1F (fixtures/eos_4_36_1F, task
netops-provoz-20261116-301 and the read of task netops-20261116-304): the running configuration starts from the real
baseline and only the lines of the changed interface, VLAN blocks and sessions follow the measured behaviour
(safeguard session with commit timer, configure terminal under it, confirmation, expiry with revert and log lines,
abort, refusal of a second timer, write memory that saves whatever is running).
"""
from __future__ import annotations

import copy
import datetime
import json
import re
from pathlib import Path
from types import SimpleNamespace

from fake_fortios import DeviceRefused

from netops_admin.access import AccessError

FIRMWARE = "4.36.1F"
HOSTNAME = "host01"
FIXTURES = Path(__file__).parent / "fixtures" / "eos_4_36_1F"
START_EPOCH = 1794781830.0  # show clock | json of the measurement (2026-11-15 22:30:30 UTC)


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def short(name: str) -> str:
    return name.replace("Ethernet", "Et").replace("Management", "Ma")


class FakeEos:
    def __init__(self):
        self.hostname = HOSTNAME
        self.firmware = FIRMWARE
        self.lines = fixture("show-running-config__baseline.txt").rstrip("\n").split("\n")
        self.saved = list(self.lines)
        self.epoch = START_EPOCH
        self.uptime = 0.0
        self.sessions = {}
        self.timer = None
        self.log = []
        self.privilege = 15
        self.saves = 0
        self.saved_while_pending = 0
        self.applied_blocks = []
        self.check_queries = []
        self.lldp_extra = []
        self.learned_macs = {}
        self.foreign_users = []
        self.check_unreadable = False
        self.check_override = None
        self.refuse_commit_timer = False
        self.timer_shift = 0
        self.on_apply = None
        self.credential = SimpleNamespace(login="netops-admin")

    # ---- clock and the commit timer ----
    def advance(self, seconds):
        self.epoch += seconds
        self.uptime += seconds
        self._fire()

    def _stamp(self) -> str:
        return datetime.datetime.fromtimestamp(self.epoch, datetime.timezone.utc).strftime("%b %d %H:%M:%S")

    def _logged(self, text):
        self.log.append("%s %s ConfigAgent: %s" % (self._stamp(), self.hostname, text))

    def _fire(self):
        if self.timer is not None and self.epoch >= self.timer["expire"]:
            name = self.timer["name"]
            self._logged("%%SYS-3-CONFIG_SESSION_COMMIT_TIMER_TIMEDOUT: The commit timer on session %s has expired "
                         "and running-config will be reverted to a previous checkpoint" % name)
            self.lines = list(self.timer["checkpoint"])
            self._logged("%%SYS-4-CONFIG_SESSION_COMMIT_REVERTED: The commit of configuration session %s was "
                         "reverted (cancel commit timer)" % name)
            self._logged("%%SYS-5-CONFIG_SESSION_COMMIT_TIMER_CANCELED: The commit timer on session %s has been "
                         "canceled" % name)
            self._logged("%%SYS-5-CONFIG_SESSION_ABORTED: User root aborted configuration session %s on UnknownTty "
                         "(UnknownIpAddr)" % name)
            self.sessions.pop(name, None)
            self.timer = None

    # ---- configuration lines ----
    def _block(self, header):
        start = self.lines.index(header)
        end = start + 1
        while end < len(self.lines) and self.lines[end].startswith(" "):
            end += 1
        return start, end

    def interface(self, name) -> list:
        header = "interface %s" % name
        if header not in self.lines:
            return None
        start, end = self._block(header)
        return [line.strip() for line in self.lines[start + 1:end]]

    def _set(self, name, drop, add=None):
        start, end = self._block("interface %s" % name)
        children = [line for line in self.lines[start + 1:end] if not drop.match(line.strip())]
        if add:
            children.append("   " + add)
        order = {"description": 0, "shutdown": 1, "switchport": 2}
        children.sort(key=lambda line: order.get(line.split()[0], 3))
        self.lines[start + 1:end] = children

    def vlans(self) -> set:
        return {"1"} | {line.split()[1] for line in self.lines if re.fullmatch(r"vlan [0-9]+", line)}

    def _add_vlan(self, vlan):
        index = max(i for i, line in enumerate(self.lines) if line.startswith("vlan ")) + 1
        while self.lines[index].startswith(" "):
            index += 1
        self.lines[index + 1:index + 1] = ["vlan %s" % vlan, "!"]

    def _add_interface(self, name):
        index = self.lines.index("interface Loopback0")
        self.lines[index:index] = ["interface %s" % name, "!"]

    def snapshot(self):
        """show running-config as the ssh exec of the write account returns it (measured in task 304): an empty
        line, the echo "> show running-config" and the header "! Command: show running-config at line 1"."""
        self._fire()
        body = "\n".join(self.lines) + "\n"
        return "\n> show running-config\n" + body.replace("! Command: show running-config\n",
                                                           "! Command: show running-config at line 1\n", 1)

    # ---- interactive session (access.apply) ----
    def apply(self, steps, spec):
        assert spec.anchor == ("\n%s" % self.hostname).encode("ascii")
        self._fire()
        self.applied_blocks.append(list(steps))
        if self.on_apply is not None:
            self.on_apply(self, steps)
        mode, accepted = ["exec"], 0
        for step in steps:
            assert isinstance(step, str)
            answer = self._line(step, mode)
            if spec.error("%s\n%s" % (step, answer)) is not None:
                raise DeviceRefused(accepted)
            accepted += 1
        if mode[0].startswith("session:"):
            # end of the connection inside an uncommitted session: EOS keeps it pending without user and terminal
            self.sessions[mode[0].split(":", 1)[1]]["user"] = ""
        return accepted

    def _line(self, line, mode) -> str:
        words = line.split()
        current = mode[0]
        if current == "exec":
            return self._exec(words, mode)
        if current.startswith("session:"):
            name = current.split(":", 1)[1]
            if words[:2] == ["commit", "timer"]:
                if self.refuse_commit_timer or (self.timer is not None and self.timer["name"] != name):
                    other = self.timer["name"] if self.timer else "netops-foreign"
                    return fixture("commit-timer__rejected-other-pending.txt").replace("netops-c7-7", name).replace(
                        "netops-c7-6", other)
                hours, minutes, seconds = (int(part) for part in words[2].split(":"))
                self.timer = {"name": name, "checkpoint": list(self.lines),
                              "expire": self.epoch + hours * 3600 + minutes * 60 + seconds + self.timer_shift}
                self.sessions[name]["state"] = "committed"
                self.sessions[name]["completed"] = self.epoch
                self._logged("%%SYS-5-CONFIG_SESSION_COMMIT_TIMER_STARTED: User netops-admin committed session %s "
                             "on vty4 (192.0.2.36), with timer %d:%d:%d(hr:min:sec)" % (name, hours, minutes, seconds))
                mode[0] = "exec"
                return ""
            if words == ["abort"]:
                self.sessions.pop(name, None)
                mode[0] = "exec"
                return ""
            raise AssertionError("unexpected session line %r" % line)
        if words == ["end"]:
            mode[0] = "exec"
            return ""
        if words[:1] == ["interface"] and len(words) == 2:
            answer = ""
            if self.interface(words[1]) is None:
                answer = fixture("interface-Ethernet99__nonexistent.txt")
                self._add_interface(words[1])
            mode[0] = "interface:" + words[1]
            return answer
        if current.startswith("interface:"):
            name = current.split(":", 1)[1]
            if words[0] == "description" and len(words) >= 2:
                self._set(name, re.compile(r"^description "), line.strip())
            elif words == ["no", "description"]:
                self._set(name, re.compile(r"^description "))
            elif words == ["shutdown"]:
                self._set(name, re.compile(r"^shutdown$"), "shutdown")
            elif words == ["no", "shutdown"]:
                self._set(name, re.compile(r"^shutdown$"))
            elif words[:3] == ["switchport", "access", "vlan"] and len(words) == 4:
                answer = ""
                if words[3] not in self.vlans():
                    answer = fixture("switchport-access-vlan__nonexistent-3999.txt").replace("3999", words[3])
                    self._add_vlan(words[3])
                self._set(name, re.compile(r"^switchport access vlan "),
                          None if words[3] == "1" else "switchport access vlan %s" % words[3])
                return answer
            elif words == ["no", "switchport", "access", "vlan"]:
                self._set(name, re.compile(r"^switchport access vlan "))
            else:
                raise AssertionError("unexpected interface line %r" % line)
            return ""
        raise AssertionError("unexpected configuration line %r" % line)

    def _exec(self, words, mode) -> str:
        if words == ["configure", "terminal"]:
            mode[0] = "config"
            return ""
        if words[:2] == ["configure", "session"] and len(words) == 3:
            self.sessions.setdefault(words[2], {"state": "pending", "user": "netops-admin"})
            mode[0] = "session:" + words[2]
            return ""
        if words[:2] == ["configure", "session"] and words[3:] == ["commit"]:
            name = words[2]
            if self.timer is not None and self.timer["name"] == name:
                self.timer = None
                self._logged("%%SYS-5-CONFIG_SESSION_COMMIT_TIMER_COMPLETED: User netops-admin has confirmed the "
                             "session %s on vty4 (192.0.2.36)." % name)
                return ""
            return "% Session " + name + " not found or already committed"
        if words[:2] == ["configure", "session"] and words[3:] == ["abort"]:
            name = words[2]
            if self.timer is not None and self.timer["name"] == name:
                self.lines = list(self.timer["checkpoint"])
                self.timer = None
                self.sessions.pop(name, None)
                return fixture("configure-session-abort__timer-armed.txt")
            self.sessions.pop(name, None)
            return ""
        if words[:3] == ["no", "configure", "session"] and len(words) == 4:
            if (self.sessions.get(words[3]) or {}).get("state") != "committed":
                return "% Session " + words[3] + " is not a completed session"
            del self.sessions[words[3]]
            return ""
        if words == ["write", "memory"]:
            if self.timer is not None:
                self.saved_while_pending += 1
            self.saved = list(self.lines)
            self.saves += 1
            return fixture("write-memory__ok.txt")
        raise AssertionError("unexpected exec line %r" % " ".join(words))

    # ---- reads of the write account ----
    def query(self, command):
        self._fire()
        if command == "show running-config":
            return self.snapshot()
        if command == "show privilege":
            return fixture("show-privilege__after-enable.txt" if self.privilege == 15 else "show-privilege__priv1.txt")
        if command == "show version":
            return fixture("show-version.txt").replace("4.36.1F-", self.firmware + "-", 1)
        if command == "show running-config diffs":
            return "" if self.lines == self.saved else fixture("show-running-config-diffs__unsaved-desc-vlan10.txt")
        if command == "show configuration sessions detail | json":
            return self.sessions_json()
        if command == "show clock | json":
            data = json.loads(fixture("show-clock-json__utc.json"))
            data["utcTime"] = self.epoch
            return json.dumps(data, indent=4)
        if command == "show users":
            text = fixture("show-users.txt")
            for number, user in enumerate(self.foreign_users, 2):
                text += "   %d vty %d  %-13s idle    0:01:00  192.0.2.40\n" % (number, number + 3, user)
            return text
        if command == "show lldp neighbors":
            text = fixture("show-lldp-neighbors__baseline.txt")
            return text + "".join("%-4s host09                Gi0/9            120\n" % port for port in self.lldp_extra)
        match = re.fullmatch(r"show mac address-table interface (\S+)", command)
        if match:
            count = self.learned_macs.get(match.group(1), 0)
            text = fixture("show-mac-address-table-interface-Ethernet10__empty.txt")
            if count:
                rows = "".join("   1    0000.5e00.53%02x    DYNAMIC     %s       1       0:00:10 ago\n"
                               % (index, short(match.group(1))) for index in range(count))
                text = text.replace("Total Mac Addresses for this criterion: 0", rows.rstrip("\n")
                                    + "\nTotal Mac Addresses for this criterion: %d" % count, 1)
            return text
        match = re.fullmatch(r"show vlan id ([0-9]+)", command)
        if match:
            if match.group(1) not in self.vlans():
                return fixture("show-vlan-id-3999__missing.txt").replace("3999", match.group(1))
            return fixture("show-vlan-id-10__baseline.txt").replace("10    D10  ", "%-5s %-4s " % (
                match.group(1), "D" + match.group(1)), 1)
        match = re.fullmatch(r"show logging last ([0-9]+) minutes \| include (\S+)", command)
        if match:
            return "".join(line + "\n" for line in self.log if match.group(2) in line)
        answer = self._interface_query(command)
        if answer is not None:
            return answer
        raise AssertionError("unexpected query %r" % command)

    def sessions_json(self) -> str:
        data = json.loads(fixture("show-configuration-sessions-detail-json__none.json"))
        for name, item in self.sessions.items():
            entry = {"state": item["state"], "commitUser": item.get("user", ""), "description": "", "instances": {}}
            if item["state"] == "committed":
                entry["completedTime"] = item.get("completed", self.epoch)
            data["sessions"][name] = entry
        if self.timer is not None:
            data["commitTimerSessionName"] = self.timer["name"]
            data["commitTimerExpireTime"] = self.timer["expire"]
        return json.dumps(data, indent=4)

    def _interface_query(self, command):
        match = re.fullmatch(r"show interfaces (\S+) (status|description|switchport)", command)
        if match is None:
            return None
        name, kind = match.groups()
        lines = self.interface(name)
        if lines is None:
            return "% Invalid input\n"
        description = next((line[len("description "):] for line in lines if line.startswith("description ")), "")
        disabled = "shutdown" in lines
        vlan = next((line.split()[-1] for line in lines if line.startswith("switchport access vlan ")), "1")
        trunk = "switchport mode trunk" in lines
        if kind == "status":
            width = max(len(description) + 1, 7)
            header = "Port       %-*sStatus       Vlan     Duplex Speed  Type            Flags Encapsulation" % (
                width, "Name")
            row = "%-11s%-*s%-13s%-9sfull   1G     EbraTestPhyPort                   " % (
                short(name), width, description, "disabled" if disabled else "connected", "trunk" if trunk else vlan)
            return header + "\n" + row + "\n"
        if kind == "description":
            status = "admin down" if disabled else "up"
            return ("Interface                      Status         Protocol           Description\n"
                    "%-31s%-15s%-19s%s\n" % (short(name), status, "down" if disabled else "up", description))
        template = fixture("show-interfaces-Ethernet10-switchport__baseline.txt").replace("Name: Et10",
                                                                                          "Name: " + short(name))
        if trunk:
            template = template.replace("Administrative Mode: static access", "Administrative Mode: trunk")
        names = {"1": "default", "10": "D10", "20": "D20"}
        return template.replace("Access Mode VLAN: 1 (default)", "Access Mode VLAN: %s (%s)" % (
            vlan, names.get(vlan, "VLAN%04d" % int(vlan))))

    # ---- reads of the check account (privilege 1) ----
    def check_query(self, command):
        self._fire()
        self.check_queries.append(command)
        if self.check_unreadable:
            raise AccessError("check account unavailable")
        if self.check_override is not None and command in self.check_override:
            return self.check_override[command]
        answer = self._interface_query(command)
        if answer is None:
            raise AssertionError("unexpected check query %r" % command)
        return answer

    def state(self, name="Ethernet10") -> dict:
        return {"lines": self.interface(name), "sessions": copy.deepcopy(self.sessions), "timer": self.timer}
