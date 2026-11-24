"""Simulated IOS 15.9 / IOS XE 17.18 router for the IOS-ACCESS-CONTROL tests (ACL rules and attachments).

The running configuration, the ACL listings and the check account answers start from the anonymised outputs measured
on the GNS3 routers iosv (IOSv 15.9(3)M12) and iol-xe-router (IOL XE 17.18.2), fixtures/ios_ios_access_control (PROVENANCE.md). The fake
changes the configuration lines like the measured devices (test_ios_ios_access_control.py compares its states with the measured
ones): IOS 15.9 prints no sequence numbers of IPv4 rules and only the IPv6 numbers that differ from the automatic
10, 20, ... numbering, IOS XE prints them all; both list every rule with its number in show ip access-lists and
show ipv6 access-list. A rollback to an archive renumbers the rules of IOS 15.9 (the archive text has no numbers).
"""
from __future__ import annotations

import re
from pathlib import Path

from fake_ios import FakeIos

from netops_admin import ios, ios_acl
from netops_admin.access import AccessError

F = Path(__file__).parent / "fixtures" / "ios_ios_access_control"
NODES = {"iosv": ("ios", "15.9(3)M12", "GigabitEthernet0/2"), "iolxe": ("iosxe", "17.18.2", "Ethernet0/2")}
# the names IOS prints for numbers (measured: 80 -> www, 23 -> telnet, 123 -> ntp, 161 -> snmp, 22 stays 22)
NAMES = {("tcp", 80): "www", ("tcp", 23): "telnet", ("udp", 123): "ntp", ("udp", 161): "snmp", ("tcp", 25): "smtp"}
INVALID_IPV6 = "% Invalid input detected at '^' marker."
DUPLICATE = {"iosv": "% Duplicate sequence number", "iolxe": "% Duplicate sequence number\n% Failed to add ace to access-list"}


def fixture(node, name):
    return (F / node / name).read_text()


def body(text):
    return text[text.index("Building configuration..."):].rstrip("\n").split("\n")


def device_body(text):
    """A rule as the device prints it: port numbers become the keywords it knows."""
    words = text.split()
    if "eq" in words and words[1] in ("tcp", "udp") and words[-1].isdigit():
        words[-1] = NAMES.get((words[1], int(words[-1])), words[-1])
    return " ".join(words)


class G64Ios(FakeIos):
    def __init__(self, node, state="baseline"):
        super().__init__(node)
        text = fixture(node, "admin-show-running-config__%s.txt" % state)
        self.header = text[:text.index("Building configuration...")]
        self.lines = body(text)
        self.saved = list(self.lines)
        self.hostname = next(line.split()[1] for line in self.lines if line.startswith("hostname "))
        self.node = node
        self.sequences = self._measured_sequences(state)
        self._sequence_lines = self.lines
        # the anonymiser widened some columns (two spaces after an IPv6 host); print every rule like the device does
        for family, rows in self.acls().items():
            for name, rules in rows.items():
                self._write(family, name, rules)
        self.saved = list(self.lines)
        self.query_override.update({
            "show tcp brief": fixture(node, "admin-show-tcp-brief.txt"),
            "show ip interface brief": fixture(node, "admin-show-ip-interface-brief.txt")})
        self.status_rows = fixture(node, "ro-show-interfaces-description.txt")
        self.sent = []

    # ---- the model: ACLs of the configuration lines, numbers in a side table ----
    def _measured_sequences(self, state):
        found = {"ipv4": {}, "ipv6": {}}
        name = family = None
        for line in fixture(self.node, "admin-show-ip-access-lists__%s.txt" % state).split("\n") + [
                "IPv6"] + fixture(self.node, "admin-show-ipv6-access-list__%s.txt" % state).split("\n"):
            if line == "IPv6":
                family = None
                continue
            match = re.fullmatch(r"(?:Extended IP|IPv6) access list (\S+)", line.strip())
            if match:
                name, family = match.group(1), ("ipv6" if line.startswith("IPv6") else "ipv4")
                found[family][name] = []
            elif name and line.startswith("    "):
                rule = re.sub(r" \([0-9]+ match(?:es)?\)", "", line.strip())
                seq = re.fullmatch(r"([0-9]+) .*", rule) if family == "ipv4" else re.fullmatch(r".* sequence ([0-9]+)", rule)
                found[family][name].append(int(seq.group(1)))
        return found

    def acls(self):
        """{family: {name: [(sequence, body)]}} of the configuration lines (numbers of the side table on IOS 15.9)."""
        if self._sequence_lines is not self.lines:
            # a return to an archive: its text has no numbers on IOS 15.9, the rules are numbered 10, 20, ... again
            self.sequences = {"ipv4": {}, "ipv6": {}}
            self._sequence_lines = self.lines
        found = {"ipv4": {}, "ipv6": {}}
        index = 0
        while index < len(self.lines):
            line = self.lines[index]
            match = re.fullmatch(r"ip access-list extended (\S+)", line) or re.fullmatch(r"ipv6 access-list (\S+)", line)
            if match is None:
                index += 1
                continue
            family = "ipv4" if line.startswith("ip ") else "ipv6"
            rules, end = [], index + 1
            while end < len(self.lines) and self.lines[end].startswith(" "):
                rules.append(" ".join(self.lines[end].split()))
                end += 1
            numbers = self.sequences[family].get(match.group(1)) if self.node == "iosv" and family == "ipv4" else None
            result, previous = [], 0
            for position, rule in enumerate(rules):
                parsed = re.fullmatch(r"(?:(?:sequence )?([0-9]+) )?(.*?)(?: sequence ([0-9]+))?", rule)
                explicit = parsed.group(1) or parsed.group(3)
                if explicit is not None:
                    seq = int(explicit)
                elif numbers is not None and len(numbers) == len(rules):
                    seq = numbers[position]
                else:
                    seq = previous + 10
                result.append((seq, parsed.group(2)))
                previous = seq
            found[family][match.group(1)] = result
            index = end
        return found

    def _write(self, family, name, rules):
        """Replace the lines of an ACL (rules None: remove it) and keep the sequence numbers aside."""
        header = ("ip access-list extended " if family == "ipv4" else "ipv6 access-list ") + name
        start = end = None
        if header in self.lines:
            start = self.lines.index(header)
            end = start + 1
            while end < len(self.lines) and self.lines[end].startswith(" "):
                end += 1
        if rules is None or (family == "ipv6" and not rules):
            # an IPv6 ACL without rules is not part of the running configuration (measured on both images)
            if start is not None:
                del self.lines[start:end]
            self.sequences[family].pop(name, None)
            return
        block = [header]
        previous = 0
        for seq, rule in rules:
            if self.node == "iolxe":
                block.append(" %s" % (("%d %s" % (seq, rule)) if family == "ipv4" else "sequence %d %s" % (seq, rule)))
            elif family == "ipv4":
                block.append(" " + re.sub(r"^deny ", "deny   ", rule))
            else:
                block.append(" " + (rule if seq == previous + 10 else "sequence %d %s" % (seq, rule)))
            previous = seq
        self.sequences[family][name] = [seq for seq, _ in rules]
        if start is not None:
            self.lines[start:end] = block
            return
        names = sorted(self.acls()[family])
        following = next((other for other in names if other > name), None)
        if following is not None:
            at = self.lines.index(("ip access-list extended " if family == "ipv4" else "ipv6 access-list ") + following)
        elif names:
            last = ("ip access-list extended " if family == "ipv4" else "ipv6 access-list ") + names[-1]
            at = self.lines.index(last) + 1
            while at < len(self.lines) and self.lines[at].startswith(" "):
                at += 1
        else:
            at = self._anchor(family)
        self.lines[at:at] = block

    def _anchor(self, family):
        """Where the first ACL of a family appears in the running configuration (measured: fixtures of the state acls)."""
        measured = [line for line in body(fixture(self.node, "admin-show-running-config__acls.txt")) if line != "!"]
        prefix = "ip access-list extended NETOPS" if family == "ipv4" else "ipv6 access-list NETOPS"
        previous = measured[next(i for i, line in enumerate(measured) if line.startswith(prefix)) - 1]
        return self.lines.index(previous) + 1

    # ---- the interactive session ----
    def _line(self, line, mode):
        words = line.split()
        current = mode[0]
        self.sent.append(line)
        if current == "exec" or words == ["end"]:
            return super()._line(line, mode)
        if words == ["exit"] and current.startswith("interface:"):
            mode[0] = "config"
            return ""
        if words[:3] == ["no", "ip", "access-list"] and len(words) == 5:
            self._write("ipv4", words[4], None)
            return ""
        if words[:3] == ["no", "ipv6", "access-list"] and len(words) == 4:
            self._write("ipv6", words[3], None)
            return ""
        if current == "config" and words[:3] == ["ip", "access-list", "extended"] and len(words) == 4:
            if words[3] not in self.acls()["ipv4"]:
                self._write("ipv4", words[3], [])
            mode[0] = "acl4:" + words[3]
            return ""
        if current == "config" and words[:2] == ["ipv6", "access-list"] and len(words) == 3:
            mode[0] = "acl6:" + words[2]
            return ""
        if current.startswith(("acl4:", "acl6:")):
            return self._acl_line(line, words, mode)
        if current.startswith("interface:"):
            plain = words[1:] if words[:1] == ["no"] else words
            if len(plain) == 4 and plain[:2] in (["ip", "access-group"], ["ipv6", "traffic-filter"]):
                return self._group_line(current.split(":", 1)[1], words)
        return super()._line(line, mode)

    def _acl_line(self, line, words, mode):
        family = "ipv4" if mode[0].startswith("acl4:") else "ipv6"
        name = mode[0].split(":", 1)[1]
        rules = list(self.acls()[family].get(name, []))
        if words == ["exit"]:
            mode[0] = "config"
            return ""
        if family == "ipv4":
            if words[0] == "no" and len(words) == 2 and words[1].isdigit():
                rules = [rule for rule in rules if rule[0] != int(words[1])]
            elif words[0].isdigit() and words[1] in ("permit", "deny"):
                if any(seq == int(words[0]) for seq, _ in rules):
                    return DUPLICATE[self.node]
                rules = sorted(rules + [(int(words[0]), device_body(" ".join(words[1:])))])
            else:
                raise AssertionError("unexpected IPv4 ACL line %r" % line)
        else:
            if words[0] == "no" and words[1:2] == ["sequence"] and len(words) == 3:
                rules = [rule for rule in rules if rule[0] != int(words[2])]
            elif words[0] == "sequence" and words[2] in ("permit", "deny"):
                seq = int(words[1])
                rules = sorted([rule for rule in rules if rule[0] != seq] + [(seq, device_body(" ".join(words[2:])))])
            elif words[0] in ("permit", "deny"):
                rules = rules + [((rules[-1][0] if rules else 0) + 10, device_body(line.strip()))]
            else:
                return INVALID_IPV6
        self._write(family, name, rules)
        return ""

    def _group_line(self, interface, words):
        negate = words[0] == "no"
        words = words[1:] if negate else words
        family = "ipv4" if words[0] == "ip" else "ipv6"
        name, direction = words[2], words[3]
        keyword = "ip access-group" if family == "ipv4" else "ipv6 traffic-filter"
        start, end = self._block("interface " + interface)
        children = [child for child in self.lines[start + 1:end]
                    if not re.fullmatch(r" %s \S+ %s" % (keyword, direction), child)]
        if not negate:
            added = " %s %s %s" % (keyword, name, direction)
            marker = " ip address " if family == "ipv4" else " ipv6 "
            groups = [i for i, child in enumerate(children) if child.startswith(" %s " % keyword)]
            if groups:
                at = groups[-1] + 1 if direction == "out" else groups[0]
            else:
                at = max(i for i, child in enumerate(children) if child.startswith(marker)) + 1
            children.insert(at, added)
        self.lines[start + 1:end] = children
        return ""

    # ---- reads ----
    def listing(self, family, name=None):
        rows = self.acls()[family]
        names = sorted(rows) if name is None else ([name] if name in rows else [])
        text = ""
        for each in names:
            text += ("Extended IP access list %s\n" if family == "ipv4" else "IPv6 access list %s\n") % each
            for seq, rule in rows[each]:
                text += ("    %d %s\n" % (seq, rule)) if family == "ipv4" else "    %s sequence %d\n" % (rule, seq)
        return "\n\n" + text if text else "\n\n"

    def snapshot(self):
        text = super().snapshot()
        if re.search(r"^(?:ip|ipv6) access-list ", text, re.MULTILINE):
            text = ios_acl.with_listing(text, self.listing("ipv4"), self.listing("ipv6"))
        return text

    def interface_text(self, interface, family):
        lines = self.interface(interface) or []
        groups = {}
        for line in lines:
            match = re.fullmatch(r"(?:ip access-group|ipv6 traffic-filter) (\S+) (in|out)", line)
            if match and line.startswith("ip " if family == "ipv4" else "ipv6 "):
                groups[match.group(2)] = match.group(1)
        short = ios.short_name(interface)
        base = fixture(self.node, "ro-show-%s-interface-%s__baseline.txt" % ("ip" if family == "ipv4" else "ipv6", self.port.replace("/", "-")))
        text = base.replace(self.port, interface)
        if family == "ipv4":
            address = next((line.split()[2] for line in lines if line.startswith("ip address ")), "unassigned")
            text = re.sub(r"Internet address is \S+", "Internet address is %s/24" % address, text)
            for word, key in (("Outgoing", "out"), ("Inbound ", "in")):
                text = re.sub(r"(?m)^  %s access list is not set" % word, "  %s access list is %s" % (word, groups.get(key, "not set")), text)
            if "in" in groups:
                text = text.replace("  Input features: MCI Check", "  Input features: Access List, MCI Check")
            if "out" in groups:
                text = re.sub(r"(?m)^(  Input features: .*)$", lambda m: m.group(1) + "\n  Output features: Access List", text, count=1)
            return text
        features = ("  Input features: Access List\n" if "in" in groups else "") + (
            "  Output features: Access List\n" if "out" in groups else "")
        names = ("  Inbound access list %s\n" % groups["in"] if "in" in groups else "") + (
            "  Outgoing access list %s\n" % groups["out"] if "out" in groups else "")
        return text.replace("  ND DAD is enabled", features + names + "  ND DAD is enabled", 1)

    def _own_answer(self, command):
        match = re.fullmatch(r"show (ip access-lists|ipv6 access-list)(?: (\S+))?", command)
        if match:
            return self.listing("ipv4" if match.group(1) == "ip access-lists" else "ipv6", match.group(2))
        match = re.fullmatch(r"show (ip|ipv6) interface (\S+)", command)
        if match and self.interface(match.group(2)) is not None:
            return self.interface_text(match.group(2), "ipv4" if match.group(1) == "ip" else "ipv6")
        if command == "show interfaces description":
            return self.status_rows
        return None

    def query(self, command):
        answer = self._own_answer(command)
        if answer is not None and command not in self.query_override:
            self._fire()
            self.queries.append(command)
            return answer
        return super().query(command)

    def check_query(self, command):
        if self.check_unreadable:
            raise AccessError("check account unavailable")
        answer = self._own_answer(command)
        if answer is not None and (self.check_override is None or command not in self.check_override):
            self._fire()
            self.check_queries.append(command)
            return answer
        return super().check_query(command)
