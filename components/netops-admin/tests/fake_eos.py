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
from itertools import groupby
from pathlib import Path
from types import SimpleNamespace

from fake_fortios import DeviceRefused

from netops_admin.access import AccessError
from netops_admin.eos import hardware_speeds as eos_speeds

FIRMWARE = "4.36.1F"
HOSTNAME = "host01"
FIXTURES = Path(__file__).parent / "fixtures" / "eos_4_36_1F"
# 1.0.12 G122: VLAN, trunk, phone VLAN, 802.1X and UTF-8 description outputs of cEOSLab 4.36.1F (Ethernet12)
G122 = Path(__file__).parent / "fixtures" / "eos_g122"
# 1.0.12 G123: hardware, MTU, PoE and status outputs of cEOSLab 4.36.1F (Ethernet12) and the Arista EOS manual
G123 = Path(__file__).parent / "fixtures" / "eos_g123"
START_EPOCH = 1794781830.0  # show clock | json of the measurement (2026-11-15 22:30:30 UTC)


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def g122(name: str) -> str:
    return (G122 / name).read_text(encoding="utf-8")


def g123(name: str) -> str:
    return (G123 / name).read_text(encoding="utf-8")


def g123_answer(name: str) -> str:
    """The answer line of a measured interactive line (fixtures/eos_g123/interface-line-*.txt)."""
    return g123(name).split("\n")[3] + "\n"


def short(name: str) -> str:
    return name.replace("Ethernet", "Et").replace("Management", "Ma")


def g122_missing_vlan(vlan) -> str:
    # measured answer of a native or phone VLAN that does not exist (task-evidence/g122/raw/probe4)
    return "! VLAN id %s not found in current VLAN configuration\n" % vlan


class FakeEos:
    line_sent = None
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
        self.ssh_source = "192.0.2.36"
        self.ssh_status = g123("show-management-ssh.txt")
        self.check_unreadable = False
        self.check_override = None
        self.refuse_commit_timer = False
        self.timer_shift = 0
        self.on_apply = None
        self.credential = SimpleNamespace(login="netops-admin")
        # G123: ports with PoE (port -> Port State while powered); a switch without PoE answers as cEOS (measured)
        self.poe_ports = {}
        self.poe_states_off = "disabled"
        # G123: hardware answer of the port (measured cEOS by default) and the link of the port while it is enabled
        self.hardware = None
        self.link = "connected"
        self.link_after_bounce = None
        self.poe_after_cycle = None
        self.status_reads = []
        self.all_status = None

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

    def vlan_name(self, vlan):
        if vlan == "1":
            return "default"
        if vlan not in self.vlans():
            return None
        start, end = self._block("vlan %s" % vlan)
        names = [line.split()[1] for line in self.lines[start + 1:end] if line.startswith("   name ")]
        return names[0] if names else "VLAN%04d" % int(vlan)

    def _add_vlan(self, vlan):
        # EOS lists VLAN blocks in numeric order (measured)
        headers = [(i, int(line.split()[1])) for i, line in enumerate(self.lines) if re.fullmatch(r"vlan [0-9]+", line)]
        after = [i for i, number in headers if number < int(vlan)]
        index = (after[-1] if after else headers[0][0] - 1) + 1
        while index < len(self.lines) and self.lines[index].startswith(" "):
            index += 1
        if after:
            index += 1
        self.lines[index:index] = ["vlan %s" % vlan, "!"]

    def _vlan_line(self, vlan, words, line):
        start, end = self._block("vlan %s" % vlan)
        if words[0] == "name" and len(words) == 2 and words[1] == "VLAN%04d" % int(vlan):
            # measured (task-evidence/g122/r2/raw/probe9): the default name VLANnnnn of the VLAN stores no name line
            self.lines[start + 1:end] = []
        elif words[0] == "name" and len(words) == 2:
            self.lines[start + 1:end] = ["   name %s" % words[1][:32]]
        elif words == ["no", "name"]:
            self.lines[start + 1:end] = []
        else:
            raise AssertionError("unexpected VLAN line %r" % line)

    def _add_interface(self, name):
        index = self.lines.index("interface Loopback0")
        self.lines[index:index] = ["interface %s" % name, "!"]

    def snapshot(self):
        """show running-config as the ssh exec of the write account returns it (measured in task 304): an empty
        line, the echo "> show running-config" and the header "! Command: show running-config at line 1"."""
        self._fire()
        # Keep the simulated commands working on individual VLANs. Running-config groups adjacent default VLANs
        # as measured in fixtures/eos_g122/show-session-config-diffs__adjacent-default-vlans.txt.
        lines = "\n".join(self.lines) + "\n"
        def group_defaults(match):
            ids = [int(vid) for vid in re.findall(r"vlan ([0-9]+)", match[0])]
            blocks = []
            for _, group in groupby(enumerate(ids), key=lambda pair: pair[1] - pair[0]):
                run = [vid for _, vid in group]
                suffix = "-%s" % run[-1] if len(run) > 1 else ""
                blocks.append("vlan %s%s\n!\n" % (run[0], suffix))
            return "".join(blocks)

        body = re.sub(r"(?:^vlan [0-9]+\n!\n)+", group_defaults, lines, flags=re.MULTILINE)
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
        for number, step in enumerate(steps, 1):
            assert isinstance(step, str)
            if self.line_sent is not None:
                self.line_sent(number)
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
        if words == ["exit"]:
            mode[0] = "config"
            return ""
        if current.startswith("vlan:"):
            self._vlan_line(current.split(":", 1)[1], words, line)
            return ""
        if words[:1] == ["vlan"] and len(words) == 2 and words[1].isdigit():
            if words[1] not in self.vlans():
                self._add_vlan(words[1])
            mode[0] = "vlan:" + words[1]
            return ""
        if words[:2] == ["no", "vlan"] and len(words) == 3:
            if words[2] in self.vlans():
                start, end = self._block("vlan %s" % words[2])
                del self.lines[start:end + (1 if end < len(self.lines) and self.lines[end] == "!" else 0)]
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
                return self._g122_line(name, words, line)
            return ""
        raise AssertionError("unexpected configuration line %r" % line)

    def _g122_line(self, name, words, line) -> str:
        """1.0.12 G122: mode, trunk, phone VLAN and 802.1X lines as measured (canonical lines in running-config; a
        missing native or phone VLAN gives the measured warning)."""
        mode_line = re.compile(r"^switchport mode ")
        if words[:2] == ["switchport", "mode"]:
            self._set(name, mode_line, None if words[2:] == ["access"] else line.strip())
        elif words[:4] == ["switchport", "trunk", "allowed", "vlan"]:
            self._set(name, re.compile(r"^switchport trunk allowed vlan "), line.strip())
        elif words == ["no", "switchport", "trunk", "allowed", "vlan"]:
            self._set(name, re.compile(r"^switchport trunk allowed vlan "))
        elif (words[:4] == ["switchport", "trunk", "native", "vlan"] and len(words) == 5) \
                or (words[:3] == ["switchport", "phone", "vlan"] and len(words) == 4):
            prefix = " ".join(words[:-1])
            self._set(name, re.compile("^" + prefix + " "), line.strip())
            if words[-1] not in self.vlans():
                return g122_missing_vlan(words[-1])
        elif words[:1] == ["no"] and " ".join(words[1:]) in ("switchport trunk native vlan", "switchport phone vlan"):
            self._set(name, re.compile("^" + " ".join(words[1:]) + " "))
        elif line.strip() in ("dot1x pae authenticator", "dot1x port-control auto", "dot1x mac based authentication"):
            self._set(name, re.compile("^" + re.escape(line.strip()) + "$"), line.strip())
        elif words[:1] == ["no"] and " ".join(words[1:]) in ("dot1x pae authenticator", "dot1x port-control",
                                                             "dot1x mac based authentication"):
            self._set(name, re.compile("^" + re.escape(" ".join(words[1:]))))
        else:
            return self._g123_line(name, words, line)
        return ""

    def _g123_line(self, name, words, line) -> str:
        """1.0.12 G123: speed, mtu and poe lines with the measured refusals of cEOS 4.36.1F (fixtures/eos_g123)."""
        if words[:1] == ["speed"] and len(words) >= 2:
            speeds = eos_speeds(self.hardware_answer(name), name)
            if words[1] == "auto" and len(words) == 3 and "auto" not in speeds:
                return g123_answer("interface-line-speed-auto-1g__cannot-advertise.txt").replace("Ethernet12", name)
            self._set(name, re.compile(r"^speed "), line.strip())
        elif words == ["no", "speed"]:
            self._set(name, re.compile(r"^speed "))
        elif words[:1] == ["mtu"] and len(words) == 2:
            if int(words[1]) > 9214:
                return g123_answer("interface-line-mtu-9215__max.txt").replace("Ethernet12", name)
            self._set(name, re.compile(r"^mtu "), line.strip())
        elif words == ["no", "mtu"]:
            self._set(name, re.compile(r"^mtu "))
        elif line.strip() in ("poe disabled", "no poe disabled"):
            if name not in self.poe_ports:
                return g123_answer("interface-line-poe-disabled__unavailable.txt")
            self._set(name, re.compile(r"^poe disabled$"), "poe disabled" if words[0] == "poe" else None)
            if words[0] == "no" and self.poe_after_cycle is not None:
                self.poe_ports[name] = self.poe_after_cycle
        else:
            raise AssertionError("unexpected interface line %r" % line)
        return ""

    def hardware_answer(self, name) -> str:
        if self.hardware is not None:
            return self.hardware
        return g123("show-interfaces-Ethernet12-hardware.txt").replace("Ethernet12", name)

    def poe_answer(self, name) -> tuple:
        """show poe interface N: measured refusal (exit status 1) without PoE, the manual layout with PoE."""
        if name not in self.poe_ports:
            return 1, g123("show-poe-interface-Ethernet12__unavailable-exec-rc1.txt").replace("Ethernet12", name)
        number = name[len("Ethernet"):]
        if "poe disabled" in (self.interface(name) or []):
            row = g123("show-poe-interface-Ethernet46__disabled-derived.txt").split("\n")
            row[3] = row[3].replace("disabled", "%-8s" % self.poe_states_off, 1).rstrip() if \
                self.poe_states_off != "disabled" else row[3]
        else:
            row = g123("show-poe-interface-Ethernet46__arista-doc.txt").split("\n")
            row[3] = row[3].replace("powered", "%-7s" % self.poe_ports[name], 1)
        row[3] = "%-4s" % number + row[3][4:]
        return 0, "\n".join(row)

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
        if command == "show users detail | json":
            text = g123("show-users-detail__ssh.json")
            return text.replace("192.0.2.36", self.ssh_source)
        if command == "show management ssh":
            return self.ssh_status
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
            return self.vlan_answer(match.group(1))
        match = re.fullmatch(r"show mac address-table vlan ([0-9]+)", command)
        if match:
            if self.learned_macs.get("vlan " + match.group(1)):
                return g122("show-mac-address-table-vlan-10__learned.txt").replace("  10 ", "%4s " % match.group(1))
            return g122("show-mac-address-table-vlan-3990__empty.txt")
        match = re.fullmatch(r"show logging last ([0-9]+) minutes \| include (\S+)", command)
        if match:
            return "".join(line + "\n" for line in self.log if match.group(2) in line)
        if command == "show interfaces status":
            if self.all_status is not None:
                return self.all_status
            rows = g123("show-interfaces-Ethernet12-status__connected.txt").splitlines()
            return "\n".join(rows + [rows[1].replace("Et12", "Et10")]) + "\n"
        answer = self._interface_query(command)
        if answer is not None:
            return answer
        match = re.fullmatch(r"show interfaces (\S+) hardware", command)
        if match:
            return self.hardware_answer(match.group(1))
        match = re.fullmatch(r"show interfaces (Ethernet[0-9]+)", command)
        if match:
            return g123("show-interfaces-Ethernet12__baseline.txt").replace("Ethernet12", match.group(1))
        match = re.fullmatch(r"show poe interface (\S+)", command)
        if match:
            status, text = self.poe_answer(match.group(1))
            if status:
                raise AccessError("exit status %d" % status)
            return text
        raise AssertionError("unexpected query %r" % command)

    def vlan_answer(self, vlan) -> str:
        name = self.vlan_name(vlan)
        if name is None:
            return fixture("show-vlan-id-3999__missing.txt").replace("3999", vlan)
        if vlan == "10" and name == "D10":
            return fixture("show-vlan-id-10__baseline.txt")
        # measured layout (fixtures/eos_g122/show-vlan-id-3990__created.txt)
        lines = g122("show-vlan-id-3990__created.txt").split("\n")
        lines[2] = "%-5s %-32s %-9s %s" % (vlan, name, "active", lines[2].split()[-1])
        return "\n".join(lines)

    def dot1x_answer(self, name) -> str:
        lines = self.interface(name) or []
        if not any(line.startswith("dot1x ") for line in lines):
            return g122("show-dot1x-interface-Ethernet12__none.txt")
        text = g122("show-dot1x-interface-Ethernet12__auto-mab.txt").replace("Ethernet12", name)
        if "dot1x port-control auto" not in lines:
            text = text.replace("Port control: auto", "Port control: force-authorized")
        if "dot1x mac based authentication" not in lines:
            text = text.replace("MAC-based authentication: enabled", "MAC-based authentication: disabled")
        return text

    def query_status(self, command):
        """Exit status and answer (ssh exec): a missing VLAN answers with exit status 1 (measured, eos_g122)."""
        match = re.fullmatch(r"show vlan id ([0-9]+)", command)
        if match and match.group(1) not in self.vlans():
            self._fire()
            return 1, g122("show-vlan-id-3999__missing-exec-rc1.txt").replace("3999", match.group(1))
        match = re.fullmatch(r"show poe interface (\S+)", command)
        if match:
            self._fire()
            return self.poe_answer(match.group(1))
        return 0, self.query(command)

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
            if self.link_after_bounce is not None and "shutdown" in lines:
                # G123: the link that the port gets after the next no shutdown
                self.link, self.link_after_bounce = self.link_after_bounce, None
            self.status_reads.append("disabled" if disabled else self.link)
            width = max(len(description) + 1, 7)
            header = "Port       %-*sStatus       Vlan     Duplex Speed  Type            Flags Encapsulation" % (
                width, "Name")
            row = "%-11s%-*s%-13s%-9sfull   1G     EbraTestPhyPort                   " % (
                short(name), width, description, "disabled" if disabled else self.link, "trunk" if trunk else vlan)
            return header + "\n" + row + "\n"
        if kind == "description":
            status = "admin down" if disabled else "up"
            return ("Interface                      Status         Protocol           Description\n"
                    "%-31s%-15s%-19s%s\n" % (short(name), status, "down" if disabled else "up", description))
        template = fixture("show-interfaces-Ethernet10-switchport__baseline.txt").replace("Name: Et10",
                                                                                          "Name: " + short(name))
        mode = next((line[len("switchport mode "):] for line in lines if line.startswith("switchport mode ")), None)
        if mode is not None:
            shown = "trunk phone" if mode == "trunk phone" else "trunk"
            template = template.replace("Administrative Mode: static access", "Administrative Mode: " + shown)
            template = template.replace("Operational Mode: static access", "Operational Mode: " + shown)
        native = next((line.split()[-1] for line in lines if line.startswith("switchport trunk native vlan ")), "1")
        allowed = next((line.split()[-1] for line in lines if line.startswith("switchport trunk allowed vlan ")), "ALL")
        template = template.replace("Trunking Native Mode VLAN: 1 (default)", "Trunking Native Mode VLAN: %s (%s)" % (
            native, self.vlan_name(native) or "inactive"))
        template = template.replace("Trunking VLANs Enabled: ALL", "Trunking VLANs Enabled: %s" % allowed.upper())
        phone = next((line.split()[-1] for line in lines if line.startswith("switchport phone vlan ")), None)
        if mode == "trunk phone" and phone is not None:
            # measured (fixtures/eos_g122/...switchport__trunk-phone.txt): listed only in trunk phone mode
            template = template.replace("VLAN forwarding mode: allowedVlansOnly\n", "VLAN forwarding mode: "
                                        "allowedVlansOnly\nPhone VLAN: %s\nPhone trunk tagging: tagged\n" % phone)
        return template.replace("Access Mode VLAN: 1 (default)", "Access Mode VLAN: %s (%s)" % (
            vlan, self.vlan_name(vlan) or "inactive"))

    # ---- reads of the check account (privilege 1) ----
    def check_query(self, command):
        self._fire()
        self.check_queries.append(command)
        if self.check_unreadable:
            raise AccessError("check account unavailable")
        if self.check_override is not None and command in self.check_override:
            return self.check_override[command]
        match = re.fullmatch(r"show dot1x interface (\S+)", command)
        if match:
            return self.dot1x_answer(match.group(1))
        match = re.fullmatch(r"show vlan id ([0-9]+)", command)
        if match:
            return self.vlan_answer(match.group(1))
        answer = self._interface_query(command)
        if answer is None:
            raise AssertionError("unexpected check query %r" % command)
        return answer

    def state(self, name="Ethernet10") -> dict:
        return {"lines": self.interface(name), "sessions": copy.deepcopy(self.sessions), "timer": self.timer}
