"""Simulated Cisco IOS and IOS XE devices for netops-admin tests.

Every answer is built from an anonymised output measured in the GNS3 lab (fixtures/ios_c45/<node>, task
netops-provoz-20261116-310 and the exec reads of task netops-20261116-315): IOSv 15.9(3)M12 (router), IOSvL2
15.2(20200924:215240) (switch), IOL XE 17.18.2 (router) and IOL-L2 XE 17.18.2 (switch). The running configuration
starts from the real exec answer; only the lines of the changed interface, the revert timer, the archive files and
the ARCHIVE_DIFF log lines follow the measured behaviour: ``configure terminal revert timer N`` saves an archive at
once and starts the timer at ``end``; ``configure confirm`` ends it; at expiry the whole running configuration returns
to the archive (IOS XE at once, IOS 7 seconds later, during which the timer is still shown); ``configure revert now``
returns to the archive at once and ends the timer; a second revert timer is refused; ``write memory`` saves whatever
is running, also during a pending timer. Like DeviceAccess, apply keeps the answers of its lines in ``last_answers``
and asks ``line_guard`` (when set) before every line; ``sent_lines`` lists the lines that reached the device.
"""
from __future__ import annotations

import copy
import datetime
import re
from pathlib import Path
from types import SimpleNamespace

from fake_fortios import DeviceRefused

from netops_admin.access import AccessError

FIXTURES = Path(__file__).parent / "fixtures" / "ios_c45"
G61 = Path(__file__).parent / "fixtures" / "ios_g61"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
NODES = {
    # node: platform, firmware, switch, test port, archive path, rollback seconds after the expiry
    "iosv": ("ios", "15.9(3)M12", False, "GigabitEthernet0/2", "flash:", 7),
    "iosvl2": ("ios", "15.2(20200924:215240)", True, "GigabitEthernet1/0", "flash:", 7),
    "iolxe": ("iosxe", "17.18.2", False, "Ethernet0/2", "unix:", 0),
    "iolxe-l2": ("iosxe", "17.18.2", True, "Ethernet0/1", "unix:", 0),
}
SHORT = (("GigabitEthernet", "Gi"), ("Ethernet", "Et"), ("Vlan", "Vl"), ("Loopback", "Lo"), ("Serial", "Se"))


def fixture(node: str, name: str) -> str:
    return (FIXTURES / node / name).read_text(encoding="utf-8")


def g61(name: str) -> str:
    return (G61 / name).read_text(encoding="utf-8")


def short(name: str) -> str:
    for long, abbreviation in SHORT:
        if name.startswith(long):
            return abbreviation + name[len(long):]
    return name


class FakeIos:
    def __init__(self, node="iosvl2"):
        self.node = node
        self.platform, self.firmware, self.switch, self.port, self.path, self.rollback_seconds = NODES[node]
        text = fixture(node, "show-running-config__exec.txt")
        self.header = text[:text.index("Building configuration...")]
        body = text[text.index("Building configuration..."):].rstrip("\n").split("\n")
        self.lines = body
        self.hostname = next(line.split()[1] for line in body if line.startswith("hostname "))
        self.saved = list(self.lines)
        clock = fixture(node, "show-clock.txt").strip()
        match = re.match(r"^\*([0-9:]+)\.[0-9]+ (\S+) \S+ (\S+) ([0-9]+) ([0-9]+)$", clock)
        hour, minute, second = (int(part) for part in match.group(1).split(":"))
        self.zone = match.group(2)
        self.now = datetime.datetime(int(match.group(5)), MONTHS.index(match.group(3)) + 1, int(match.group(4)),
                                     hour, minute, second)
        self.uptime = 0.0
        self.timer = None
        self.rolling = None
        self.archives = []
        self.log = []
        self.vlans = {"1", "10", "20", "99"} if self.switch else set()
        self.privilege = 15
        self.check_privilege = 1
        self.saves = 0
        self.saved_while_pending = 0
        self.applied_blocks = []
        self.check_queries = []
        self.queries = []
        self.lldp_extra = []
        self.cdp_extra = []
        self.learned_macs = {}
        self.foreign_users = []
        self.foreign_timer = None
        self.foreign_touched = []
        self.check_unreadable = False
        self.check_override = None
        self.query_override = {}
        self.log_lost = False
        self.timer_shift = 0
        self.timer_user = "netops-admin"
        self.on_apply = None
        self.on_query = None
        self.on_check_query = None
        self.line_guard = None
        self.line_sent = None
        self.last_answers = ()
        self.unsent_lines = 0
        self.sent_lines = []
        self.line_seconds = 0
        self.revert_now_ignored = False
        # 1.0.12 G61: link of the test ports (the lab ports have no peer) and PoE (the lab nodes have none: the
        # commands are refused as measured; poe_ports names ports with PoE and whether a device is attached)
        self.link_up = set()
        self.link_delay = 0
        self.poe_ports = {}
        self.enabled_at = {}
        self.credential = SimpleNamespace(login="netops-admin")

    # ---- clock, archive and the revert timer ----
    def advance(self, seconds):
        self.now += datetime.timedelta(seconds=seconds)
        self.uptime += seconds
        self._fire()

    def _stamp(self) -> str:
        return "*%s %2d %s.123" % (MONTHS[self.now.month - 1], self.now.day, self.now.strftime("%H:%M:%S"))

    def _logged(self, event, text):
        self.log.append("%s: %%ARCHIVE_DIFF-5-ROLLBK_CNFMD_CHG_%s: %s" % (self._stamp(), event, text))

    def _fire(self):
        if self.timer is not None and self.rolling is None and self.now >= self.timer["fire"]:
            self._logged("ROLLBACK_START", "Start rolling to: %s" % self.timer["archive"])
            self.rolling = self.timer["fire"] + datetime.timedelta(seconds=self.rollback_seconds)
        if self.rolling is not None and self.now >= self.rolling:
            self.lines = list(self.timer["checkpoint"])
            self.timer, self.rolling = None, None

    def _archive(self) -> str:
        stamp = "%s-%02d-%s.%03d" % (MONTHS[self.now.month - 1], self.now.day, self.now.strftime("%H-%M-%S"),
                                     len(self.archives) % 1000)
        name = "%snetops-archive-%s-%d" % (self.path, stamp, len(self.archives) % 14)
        self.archives.append(name)
        return name

    def _clock_text(self, when) -> str:
        return "%s %s %s %s %d %d" % (when.strftime("%H:%M:%S"), self.zone, DAYS[when.weekday()],
                                      MONTHS[when.month - 1], when.day, when.year)

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
            children.append(" " + add)
        order = {"description": 0, "switchport": 1, "power": 2, "no": 3, "shutdown": 4}
        children.sort(key=lambda line: order.get(line.split()[0], 5))
        self.lines[start + 1:end] = children

    def snapshot(self):
        """show running-config as the ssh exec of the write account returns it (empty lines first)."""
        self._fire()
        return self.header + "\n".join(self.lines) + "\n"

    # ---- interactive session (access.apply) ----
    def apply(self, steps, spec):
        assert spec.anchor == ("\n%s" % self.hostname).encode("ascii")
        self._fire()
        self.applied_blocks.append(list(steps))
        if self.on_apply is not None:
            self.on_apply(self, steps)
        mode, accepted, answers = ["exec"], 0, []
        self.last_answers = answers
        guard = self.line_guard
        for number, step in enumerate(steps, 1):
            assert isinstance(step, str)
            if guard is not None and not guard():
                self.unsent_lines += 1
                raise AccessError("line was not sent: the safeguard of the device has too little time left", accepted)
            self.sent_lines.append(step)
            if self.line_sent is not None:
                self.line_sent(number)
            answer = self._line(step, mode)
            # the interactive answer: the echo of the line, the answer and the prompt
            answers.append("%s\n%s\n%s#" % (step, answer, self.hostname))
            if self.line_seconds:
                self.advance(self.line_seconds)
            if spec.error("%s\n%s" % (step, answer)) is not None:
                raise DeviceRefused(accepted)
            accepted += 1
        return accepted

    def _line(self, line, mode) -> str:
        words = line.split()
        current = mode[0]
        if current == "exec":
            return self._exec(words, mode)
        if words == ["end"]:
            mode[0] = "exec"
            if self.timer is not None and self.timer.get("fire") is None:
                timer = self.timer
                timer["configured"] = self.now
                timer["fire"] = self.now + datetime.timedelta(minutes=timer["minutes"], seconds=self.timer_shift)
                self._logged("BACKUP", "Backing up current running config to %s" % timer["archive"])
                self._logged("START_ABSTIMER", "User: %s(Priv: 15, View: 0): Scheduled to rollback to config %s in "
                             "%d minutes" % (timer["user"], timer["archive"], timer["minutes"]))
            return ""
        if words[:1] == ["interface"] and len(words) == 2:
            if self.interface(words[1]) is None:
                return fixture(self.node, "config__interface-nonexistent.txt")
            mode[0] = "interface:" + words[1]
            return ""
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
                self.enabled_at[name] = self.now
            elif words[:2] == ["power", "inline"]:
                if name not in self.poe_ports:
                    return g61("config__power-inline-never__invalid-input.txt")
                if not re.fullmatch(r"power inline (?:auto|never|static)(?: max [0-9]+)?", line.strip()):
                    return g61("config__power-inline-never__invalid-input.txt")
                previous = self._poe_admin(name)
                # "power inline auto" without a maximum is the default and shows no line in the configuration
                self._set(name, re.compile(r"^power inline "), None if line.strip() == "power inline auto" else line.strip())
                if previous == "off" and self._poe_admin(name) != "off":
                    self.enabled_at[name] = self.now
            elif words[:3] == ["switchport", "access", "vlan"] and len(words) == 4:
                if not self.switch:
                    return fixture(self.node, "config__switchport-access-vlan-10-router.txt")
                answer = ""
                if words[3] not in self.vlans:
                    answer = fixture(self.node, "config__switchport-access-vlan-3999-nonexistent.txt").replace(
                        "3999", words[3])
                    self.vlans.add(words[3])
                self._set(name, re.compile(r"^switchport access vlan "),
                          None if words[3] == "1" else "switchport access vlan %s" % words[3])
                return answer
            else:
                raise AssertionError("unexpected interface line %r" % line)
            return ""
        raise AssertionError("unexpected configuration line %r" % line)

    def _exec(self, words, mode) -> str:
        if " ".join(words) == "show archive config rollback timer":
            # the same answer as the exec read of the write account (measured; interactive read since task 320)
            return self._timer_text()
        if words == ["configure", "terminal"]:
            mode[0] = "config"
            return "Enter configuration commands, one per line.  End with CNTL/Z."
        if words[:4] == ["configure", "terminal", "revert", "timer"] and len(words) == 5:
            if self.timer is not None or self.foreign_timer is not None:
                return fixture(self.node, "configure-terminal-revert-timer__second-while-pending.txt")
            archive = self._archive()
            self.timer = {"archive": archive, "checkpoint": list(self.lines), "minutes": int(words[4]),
                          "user": self.timer_user, "fire": None, "configured": None}
            mode[0] = "config"
            text = fixture(self.node, "configure-terminal-revert-timer-1__empty-safeguard.txt")
            return re.sub(r"to \S+netops-archive-\S+", "to " + archive, text)
        if words == ["configure", "confirm"]:
            if self.foreign_timer is not None:
                # the timer is global: a confirm of any privilege-15 session ends the timer of someone else
                self.foreign_touched.append("configure confirm")
                self.foreign_timer = None
                return fixture(self.node, "configure-confirm__ok.txt")
            if self.timer is not None and self.rolling is None:
                self._logged("CONFIRM", "User: netops-admin: Confirm the configuration change")
                self.timer = None
                return fixture(self.node, "configure-confirm__ok.txt")
            return fixture(self.node, "configure-confirm__nothing-pending.txt")
        if words == ["configure", "revert", "now"]:
            if self.timer is not None and self.timer.get("fire") is not None and not self.revert_now_ignored:
                self._logged("REVERTNOW", "User: netops-admin: Rollback immediately.")
                self._logged("ROLLBACK_START", "Start rolling to: %s" % self.timer["archive"])
                text = fixture(self.node, "configure-revert-now__ok.txt")
                text = re.sub(r"rolling to:\S+", "rolling to:" + self.timer["archive"], text)
                self.lines = list(self.timer["checkpoint"])
                self.timer, self.rolling = None, None
                return text
            if self.foreign_timer is not None:
                self.foreign_touched.append("configure revert now")
                self.foreign_timer = None
                return re.sub(r"rolling to:\S+", "rolling to:%snetops-archive-foreign" % self.path,
                              fixture(self.node, "configure-revert-now__ok.txt"))
            if self.timer is not None and self.revert_now_ignored:
                return ""
            return fixture(self.node, "configure-revert-now__nothing-pending.txt")
        if words == ["write", "memory"]:
            if self.foreign_timer is not None:
                self.foreign_touched.append("write memory")
            if self.timer is not None:
                self.saved_while_pending += 1
            self.saved = list(self.lines)
            self.saves += 1
            return fixture(self.node, "write-memory__after-confirm.txt")
        raise AssertionError("unexpected exec line %r" % " ".join(words))

    # ---- reads of the write account ----
    def _timer_text(self) -> str:
        timer = self.foreign_timer or (self.timer if self.timer and self.timer.get("fire") else None)
        if timer is None:
            return fixture(self.node, "show-archive-config-rollback-timer__none.txt")
        return ("Time configured(or reconfigured): %s\nTimer type: absolute timer\nTimer value: %d min\nUser: %s\n"
                % (self._clock_text(timer["configured"]), timer["minutes"], timer["user"]))

    def _archive_text(self) -> str:
        lines = ["The maximum archive configurations allowed is 14.",
                 "There are currently %s archive configurations saved." % (len(self.archives) or "no"),
                 "The next archive file will be named %snetops-archive-<timestamp>-%d"
                 % (self.path, len(self.archives) % 14), " Archive #  Name"]
        if not self.archives:
            lines[1] = "There are currently no configuration saved."
        for number in range(1, 15):
            name = self.archives[number - 1] if number <= len(self.archives) else ""
            recent = " <- Most Recent" if name and number == len(self.archives) else ""
            lines.append("   %-9d%s%s" % (number, name, recent))
        return "\n".join(lines) + "\n"

    def _unsaved_text(self) -> str:
        text = fixture(self.node, "show-archive-config-differences-startup-running__baseline.txt")
        if self.lines == self.saved:
            return text
        diff = [line for line in self.lines if line not in self.saved]
        header, rest = text.split("\n", 1)
        rest = rest.replace("!No changes were found\n", "").replace("!No changes were found", "")
        return header + "\n" + "".join("+%s\n" % line for line in diff) + rest

    def query(self, command):
        self._fire()
        self.queries.append(command)
        if self.on_query is not None:
            self.on_query(self, command)
        if command in self.query_override:
            return self.query_override[command]
        if command == "show running-config":
            return self.snapshot()
        if command == "show privilege":
            text = fixture(self.node, "show-privilege__admin-priv15.txt")
            return text.replace("15", str(self.privilege))
        if command == "show version":
            text = fixture(self.node, "show-version.txt")
            return text.replace(NODES[self.node][1], self.firmware, 1)
        if command == "show clock":
            return "\n\n*%s.%03d %s\n" % (self.now.strftime("%H:%M:%S"), 512,
                                         self._clock_text(self.now).split(" ", 1)[1])
        if command == "show archive config rollback timer":
            return self._timer_text()
        if command == "show archive":
            return self._archive_text()
        if command == "show archive config differences nvram:startup-config system:running-config":
            return self._unsaved_text()
        if command == "show users":
            text = fixture(self.node, "show-users__single.txt")
            head, tail = text.split("\n\n", 1)
            for number, user in enumerate(self.foreign_users, 3):
                head += "\n   %d vty %d     %-10s idle                 00:01:00 192.0.2.40" % (number, number - 2, user)
            return head + "\n\n" + tail
        if command == "show tcp brief":
            return fixture(self.node, "show-tcp-brief__exec.txt")
        if command == "show ip interface brief":
            return fixture(self.node, "show-ip-interface-brief__baseline.txt")
        if command == "show lldp neighbors":
            text = fixture(self.node, "show-lldp-neighbors__baseline.txt")
            rows = "".join("%-20s%-15s120        R               Gi0/9\n" % ("host09", short(port))
                           for port in self.lldp_extra)
            return text.replace("\nTotal entries", "\n" + rows + "\nTotal entries", 1) if rows else text
        if command == "show cdp neighbors":
            text = fixture(self.node, "show-cdp-neighbors__baseline.txt")
            rows = "".join("host09\n                 %-18s142              R B             Gig 0/9\n"
                           % (port[:3] + " " + re.sub(r"^[A-Za-z-]+", "", port)) for port in self.cdp_extra)
            return text.replace("\nTotal cdp", "\n" + rows + "\nTotal cdp", 1) if rows else text
        if command == "show logging | include ROLLBK_CNFMD_CHG":
            return "" if self.log_lost else "".join(line + "\n" for line in self.log)
        match = re.fullmatch(r"show mac address-table interface (\S+)", command)
        if match:
            if not self.switch:
                return fixture(self.node, "exec__invalid-command__rc0.txt").replace("show bogus-command", command)
            count = self.learned_macs.get(match.group(1), 0)
            text = fixture(self.node, "show-mac-address-table-interface__baseline.txt").rstrip("\n") + "\n"
            rows = "".join("  10    0000.5e00.53%02x    DYNAMIC     %s\n" % (index, short(match.group(1)))
                           for index in range(count))
            return text + rows + ("Total Mac Addresses for this criterion: %d\n" % count if count else "")
        match = re.fullmatch(r"show vlan id ([0-9]+)", command)
        if match:
            if not self.switch:
                return fixture(self.node, "exec__invalid-command__rc0.txt").replace("show bogus-command", command)
            if match.group(1) not in self.vlans:
                return fixture(self.node, "show-vlan-id-3999__missing.txt").replace("3999", match.group(1))
            return fixture(self.node, "show-vlan-id-10__exec.txt").replace("\n10   D10   ", "\n%-4s %-5s " % (
                match.group(1), "D" + match.group(1)), 1)
        answer = self._interface_query(command)
        if answer is not None:
            return answer
        raise AssertionError("unexpected query %r" % command)

    def _link(self, name) -> str:
        lines = self.interface(name) or []
        if "shutdown" in lines:
            return "disabled"
        if name in self.link_up:
            started = self.enabled_at.get(name)
            if started is not None and (self.now - started).total_seconds() < self.link_delay:
                return "notconnect"
            return "connected"
        base = {row.split()[0]: row.split()[1] for row in
                fixture(self.node, "show-interfaces-description__ro-baseline.txt").splitlines()[1:]}
        return "connected" if base.get(short(name)) == "up" and not name.startswith("Vlan") else "notconnect"

    def _status_row(self, name) -> str:
        status = self._link(name)
        duplex = "  auto" if status == "disabled" else "a-full"
        trunk = "trunk" if "switchport mode trunk" in (self.interface(name) or []) else "1"
        return "%-10s%-19s%-13s%-11s%s   auto RJ45" % (short(name), "", status, trunk, duplex)

    def _poe_admin(self, name) -> str:
        for line in self.interface(name) or []:
            if line.startswith("power inline never"):
                return "off"
            if line.startswith("power inline static"):
                return "static"
        return "auto"

    def _poe_text(self, name) -> str:
        admin = self._poe_admin(name)
        attached = self.poe_ports[name].get("device", False)
        boot = self.poe_ports[name].get("boot_delay", 0)
        started = self.enabled_at.get(name)
        powered = admin != "off" and attached and (started is None or (self.now - started).total_seconds() >= boot)
        found = re.search(r"max ([0-9]+)", " ".join(self.interface(name) or []))
        maximum = int(found.group(1)) / 1000 if found else 30.0
        row = "%-10s %-6s %-10s %-7s %-19s %-5s %.1f" % (
            short(name), admin, "on" if powered else "off", "8.9" if powered else "0.0",
            "IP Phone 8851" if powered else "n/a", "4" if powered else "n/a", maximum)
        return ("Interface  Admin   Oper      Power      Device          Class  Max\n"
                "                            (Watts)\n--------- ------ ---------- ------- ------------------- -----  ----\n"
                + row + "\n")

    def _interface_query(self, command):
        match = re.fullmatch(r"show interfaces (\S+) status", command)
        if match:
            if self.interface(match.group(1)) is None:
                return "% Invalid input detected at '^' marker.\n"
            return "\nPort      Name               Status       Vlan       Duplex  Speed Type \n" + \
                self._status_row(match.group(1)) + "\n"
        if command == "show interfaces status":
            names = [line.split()[1] for line in self.lines if line.startswith("interface ")
                     and re.match(r"interface (?:Gigabit|Ethernet)", line)]
            return "\nPort      Name               Status       Vlan       Duplex  Speed Type \n" + "".join(
                self._status_row(name) + "\n" for name in names)
        match = re.fullmatch(r"show power inline (\S+)", command)
        if match:
            if match.group(1) not in self.poe_ports:
                return g61("show-power-inline__exec-refused.txt").replace("GigabitEthernet1/2", match.group(1))
            return self._poe_text(match.group(1))
        if command == "show interfaces description":
            text = fixture(self.node, "show-interfaces-description__ro-baseline.txt")
            rows = []
            for row in text.rstrip("\n").split("\n"):
                name = row.split()[0]
                full = next((line.split()[1] for line in self.lines
                             if line.startswith("interface ") and short(line.split()[1]) == name), None)
                lines = self.interface(full) if full else None
                if lines is not None and name != "Interface":
                    description = next((line[len("description "):] for line in lines
                                        if line.startswith("description ")), "")
                    disabled = "shutdown" in lines
                    status = row[31:46].strip()
                    if disabled:
                        status = "admin down"
                    elif status == "admin down":
                        status = "down"
                    protocol = "down" if disabled else row[46:55].strip()
                    if not disabled and self._link(full) == "connected" and status == "down":
                        status = protocol = "up"
                    row = "%-31s%-15s%-9s%s" % (name, status, protocol, description)
                rows.append(row)
            return "\n".join(rows) + "\n"
        match = re.fullmatch(r"show interfaces (\S+) switchport", command)
        if match is None:
            return None
        name = match.group(1)
        if not self.switch:
            return fixture(self.node, "exec__invalid-command__rc0.txt").replace("show bogus-command", command)
        lines = self.interface(name)
        if lines is None:
            return "% Invalid input detected at '^' marker.\n"
        vlan = next((line.split()[-1] for line in lines if line.startswith("switchport access vlan ")), "1")
        mode = "static access" if "switchport mode access" in lines else (
            "trunk" if "switchport mode trunk" in lines else "dynamic auto")
        template = fixture(self.node, "show-interfaces-port-switchport__ro-baseline.txt")
        template = re.sub(r"^Name: \S+", "Name: " + short(name), template, flags=re.MULTILINE)
        template = template.replace("Administrative Mode: static access", "Administrative Mode: " + mode)
        allowed = next((line.split()[-1] for line in lines if line.startswith("switchport trunk allowed vlan ")), None)
        if allowed is not None and mode == "trunk":
            template = template.replace("Trunking VLANs Enabled: ALL", "Trunking VLANs Enabled: " + allowed)
        names = {"1": "default", "10": "D10", "20": "D20", "99": "D-MGMT"}
        return re.sub(r"^Access Mode VLAN: .*$", "Access Mode VLAN: %s (%s)" % (
            vlan, names.get(vlan, "VLAN%04d" % int(vlan))), template, flags=re.MULTILINE)

    # ---- reads of the check account (privilege 1) ----
    def check_query(self, command):
        self._fire()
        self.check_queries.append(command)
        if self.on_check_query is not None:
            self.on_check_query(self, command)
        if self.check_unreadable:
            raise AccessError("check account unavailable")
        if self.check_override is not None and command in self.check_override:
            return self.check_override[command]
        if command == "show privilege":
            return fixture(self.node, "show-privilege__ro-priv1.txt").replace(" 1", " %d" % self.check_privilege)
        if command == "show running-config":
            return fixture(self.node, "exec__ro-show-running-config-denied__rc0.txt")
        answer = self._interface_query(command)
        if answer is None:
            raise AssertionError("unexpected check query %r" % command)
        return answer

    def state(self, name=None) -> dict:
        return {"lines": self.interface(name or self.port), "timer": copy.deepcopy(self.timer)}
