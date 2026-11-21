"""Simulated IOL XE 17.18.2 router (d-iolxe) for the G82 tests (ACL rules and their attachment).

Every answer comes from the anonymised measurements of task netops-20261119-639 (fixtures/iosxe_g82): the running
configuration is the measured one and its ACL and interface lines change the way the measured device changes them
(sequence order, printed port names, the refusals of a duplicate number or rule body, an IPv6 ACL that exists only while it
has a rule, the replacement of the ACL of the same direction). The answers of the check account (show ip access-lists,
show ipv6 access-list, show ip/ipv6 interface) are built from the configuration lines in the measured shapes.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from fake_ios import FakeIos, short

F = Path(__file__).parent / "fixtures" / "iosxe_g82"
MEASURED = json.loads((F / "ports-measured.json").read_text())
PRINT = {(family, protocol): {number: name for name, number in MEASURED["%s-%s" % (family, protocol)].items()}
         for family in ("v4", "v6") for protocol in ("tcp", "udp")}
MARK_V4 = re.compile(r"(\d+) (permit|deny) ")


def fixture(name):
    return (F / name).read_text()


def answer(name):
    """The answer of an interactive line without its echo and the prompt (fixtures config__*)."""
    return "\n".join(fixture(name).rstrip("\n").split("\n")[1:-1])


def body(text):
    return text[text.index("Building configuration..."):].rstrip("\n").split("\n")


class G82Ios(FakeIos):
    def __init__(self, text):
        super().__init__("iolxe")
        self.header = text[:text.index("Building configuration...")]
        self.lines = body(text)
        self.saved = list(self.lines)
        self.hostname = next(line.split()[1] for line in self.lines if line.startswith("hostname "))
        self.hits = {}
        self.down = set()
        self.query_override = {
            "show version": fixture("admin-show-version.txt"),
            "show tcp brief": fixture("admin-show-tcp-brief.txt"),
            "show ip interface brief": fixture("admin-show-ip-interface-brief.txt"),
        }

    # ---- the configuration of the device ----
    def _printed(self, words, family):
        """The rule (action, protocol, ...) as the device prints it: named ports, IPv6 in capitals."""
        words = list(words)
        if "eq" in words and words[1] in ("tcp", "udp") and words[words.index("eq") + 1].isdecimal():
            at = words.index("eq") + 1
            words[at] = PRINT[(family, words[1])].get(int(words[at]), words[at])
        return [word.upper() if ":" in word and family == "v6" else word for word in words]

    def _acl_block(self, family, name):
        header = ("ip access-list extended " if family == "v4" else "ipv6 access-list ") + name
        return header if header in self.lines else None

    def _insert_acl(self, family, name):
        """A new ACL block stands among the blocks of its type in the order of the names (measured on d-iolxe)."""
        prefix = "ip access-list extended " if family == "v4" else "ipv6 access-list "
        header = prefix + name
        same = [line for line in self.lines if line.startswith(prefix)]
        later = [line for line in same if line > header]
        if later:
            index = self.lines.index(later[0])
        elif same:
            index = self._block(same[-1])[1]
        else:
            index = self.lines.index("ip sla 69" if family == "v4" else "control-plane")
            if self.lines[index - 1] == "!":
                index -= 1  # the separator of the configuration follows the new block
        self.lines[index:index] = [header]
        return header

    def _rules(self, header):
        start, end = self._block(header)
        return start, end, [line.strip() for line in self.lines[start + 1:end]]

    def _acl_line(self, mode, line, words):
        family, name = mode.split(":", 1)[0][3:], mode.split(":", 1)[1]
        family = "v4" if family == "4" else "v6"
        header = self._acl_block(family, name)
        if words[0] == "no":
            rest = words[1:]
            seq = rest[0] if family == "v4" else (rest[1] if rest[:1] == ["sequence"] else None)
            if header is not None and seq is not None:
                start, end, rules = self._rules(header)
                keep = [rule for rule in rules if (rule.split()[0] if family == "v4" else rule.split()[1]) != seq]
                self.lines[start + 1:end] = [" " + rule for rule in keep]
                if family == "v6" and not keep:
                    del self.lines[start:start + 1]  # measured: an IPv6 ACL without rules does not exist
            return ""
        if family == "v4":
            seq, rest = words[0], words[1:]
            rule_words = [seq] + self._printed(rest, family)
        else:
            if words[0] != "sequence":
                return answer("config__v6-number-without-sequence.txt")
            seq, rest = words[1], words[2:]
            rule_words = ["sequence", seq] + self._printed(rest, family)
        if header is None:
            header = self._insert_acl(family, name)
        start, end, rules = self._rules(header)
        number = (lambda rule: rule.split()[0]) if family == "v4" else (lambda rule: rule.split()[1])
        text = lambda rule: rule.split(None, 1)[1] if family == "v4" else rule.split(None, 2)[2]  # noqa: E731
        if family == "v4" and any(number(rule) == seq for rule in rules):
            return answer("config__v4-duplicate-sequence.txt")
        if family == "v6":
            rules = [rule for rule in rules if number(rule) != seq]  # measured: a taken IPv6 number is replaced
        same = [number(rule) for rule in rules if text(rule) == " ".join(rule_words[1 if family == "v4" else 2:])]
        if same:
            return answer("config__v4-duplicate-entry.txt").replace("sequence 30", "sequence " + same[0])
        rules.append(" ".join(rule_words))
        rules.sort(key=lambda rule: int(number(rule)))
        self.lines[start + 1:end] = [" " + rule for rule in rules]
        return ""

    def _interface_group(self, name, words, line):
        negative = words[0] == "no"
        words = words[1:] if negative else words
        family_word = "ip access-group" if words[:2] == ["ip", "access-group"] else "ipv6 traffic-filter"
        acl, direction = words[2], words[3]
        start, end = self._block("interface " + name)
        children = self.lines[start + 1:end]
        current = [child for child in children if child.strip().startswith(family_word + " ")
                   and child.split()[-1] == direction]
        if negative:
            if not current or current[0].split()[2] != acl:
                return answer("config__v4-no-binding-wrong-name.txt" if family_word == "ip access-group"
                              else "config__v6-no-binding-wrong-name.txt").replace("WRONGNAME", acl)
            children.remove(current[0])
        else:
            if current:
                children.remove(current[0])
            same = [child for child in children if child.strip().startswith(family_word + " ")]
            groups = sorted(same + [" %s %s %s" % (family_word, acl, direction)], key=lambda child: child.split()[-1] != "in")
            children = [child for child in children if child not in same]
            anchors = ("ip address",) if family_word == "ip access-group" else ("ipv6 nd", "ipv6 address")
            index = len(children)
            for anchor in anchors:
                found = [i for i, child in enumerate(children) if child.strip().startswith(anchor)]
                if found:
                    index = found[-1] + 1
                    break
            children[index:index] = groups
        self.lines[start + 1:end] = children
        return ""

    def _line(self, line, mode):
        words = line.split()
        current = mode[0]
        if current == "exec" or words == ["end"]:
            return super()._line(line, mode)
        if words == ["exit"]:
            mode[0] = "config"
            return ""
        if current.startswith(("acl4:", "acl6:")):
            return self._acl_line(current, line, words)
        if current == "config":
            if words[:3] == ["ip", "access-list", "extended"] and len(words) == 4:
                if self._acl_block("v4", words[3]) is None:
                    self._insert_acl("v4", words[3])
                mode[0] = "acl4:" + words[3]
                return ""
            if words[:2] == ["ipv6", "access-list"] and len(words) == 3:
                mode[0] = "acl6:" + words[2]
                return ""
            if words[:4] == ["no", "ip", "access-list", "extended"] or words[:3] == ["no", "ipv6", "access-list"]:
                family = "v4" if words[1] == "ip" else "v6"
                header = self._acl_block(family, words[-1])
                if header is not None:
                    start, end = self._block(header)
                    del self.lines[start:end]
                return ""
        if current.startswith("interface:") and (
                words[:2] in (["ip", "access-group"], ["ipv6", "traffic-filter"]) or (
                    words[:1] == ["no"] and words[1:3] in (["ip", "access-group"], ["ipv6", "traffic-filter"]))):
            return self._interface_group(current.split(":", 1)[1], words, line)
        return super()._line(line, mode)

    # ---- the answers ----
    def _show_acl(self, command, name):
        family = "v4" if command == "ip access-lists" else "v6"
        header = self._acl_block(family, name)
        if header is None:
            return fixture("ro-show-ip-access-lists-NOPE-X__acls.txt")
        _, _, rules = self._rules(header)
        rows = []
        for rule in rules:
            if family == "v4":
                seq = rule.split()[0]
                counter = self.hits.get(("ipv4", name, int(seq)), "")
                rows.append("    %s%s" % (rule, " " + counter if counter else ""))
            else:
                words = rule.split()
                seq, rest = words[1], words[2:]
                counter = self.hits.get(("ipv6", name, int(seq)), "")
                rows.append("    %s%s sequence %s" % (" ".join(rest), " " + counter if counter else "", seq))
        title = ("Extended IP access list " if family == "v4" else "IPv6 access list ") + name
        return "\n\n\n%s\n%s\n" % (title, "\n".join(rows)) if rows else "\n\n\n%s\n" % title

    def _bound(self, name, word, direction):
        found = [line.split()[2] for line in self.interface(name) or [] if line.startswith(word + " ")
                 and line.split()[-1] == direction]
        return found[0] if found else None

    def _interface_query(self, command):
        match = re.fullmatch(r"show (ip access-lists|ipv6 access-list) (\S+)", command)
        if match:
            return self._show_acl(*match.groups())
        if command == "show interfaces description":
            rows = fixture("ro-show-interfaces-description__acls.txt").rstrip("\n").split("\n")
            result = []
            for row in rows:
                if row.split()[:1] and row.split()[0] in self.down:
                    row = "%-31s%-15s%-9s%s" % (row.split()[0], "admin down", "down", row[55:].strip())
                result.append(row)
            return "\n".join(result) + "\n"
        match = re.fullmatch(r"show ip interface (\S+)", command)
        if match:
            name = match.group(1)
            text = fixture("ro-show-ip-interface-Ethernet0-2__acls.txt").replace("Ethernet0/2", name)
            for label, direction in (("Inbound  access list is", "in"), ("Outgoing access list is", "out")):
                bound = self._bound(name, "ip access-group", direction)
                if bound:
                    text = text.replace(label + " not set", label + " " + bound)
            return text
        match = re.fullmatch(r"show ipv6 interface (\S+)", command)
        if match:
            name = match.group(1)
            lines = fixture("ro-show-ipv6-interface-Ethernet0-2__acls.txt").replace("Ethernet0/2", name).split("\n")
            ins, out = (self._bound(name, "ipv6 traffic-filter", direction) for direction in ("in", "out"))
            extra = ([] if not ins else ["  Input features: Access List"]) + ([] if not out else [
                "  Output features: Access List"]) + ([] if not ins else ["  Inbound access list " + ins]) + (
                [] if not out else ["  Outgoing access list " + out])
            lines[19:19] = extra
            return "\n".join(lines)
        return super()._interface_query(command)


def row_down(device, name):
    device.down.add(short(name))
