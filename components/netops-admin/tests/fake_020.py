import copy

from fake_fortios import FakeFortiOS, DeviceRefused
from fake_exos import FakeExos
from netops_auditor.l1_fortios import tokenize


def table(name, objects):
    lines = ["config " + name]
    for key, attrs in objects.items():
        lines.append('edit "' + key + '"')
        for attr, value in attrs.items():
            values = value.split() if attr == "member" else [value]
            lines.append("set " + attr + " " + " ".join('"' + item + '"' for item in values))
        lines.append("next")
    return "\n".join(lines + ["end", ""])


class FortiOS767(FakeFortiOS):
    def __init__(self):
        super().__init__()
        self.groups = {"group-example": {"member": "srv-web spare-host", "comment": "example"}}
        self.reservations = {"1": {"ip": "192.0.2.101", "mac": "00:00:5e:00:53:01", "description": "first"}}

    def snapshot(self):
        text = super().snapshot().replace("8.0.0-FW-build0167", "7.6.7-FW-build3704")
        text += table("firewall addrgrp", self.groups)
        text += self.dhcp()
        return text

    def dhcp(self):
        return ("config system dhcp server\nedit 1\nset default-gateway 192.0.2.1\n"
                "set netmask 255.255.255.0\nset interface internal\n" +
                table("reserved-address", self.reservations) + "next\nend\n")

    def _run(self, lines, automatic=False):
        first = lines[0].strip()
        if first not in ("config firewall addrgrp", "config system dhcp server"):
            return super()._run(lines, automatic)
        objects = self.groups if "addrgrp" in first else self.reservations
        nested = "dhcp" in first
        in_child = not nested
        key = None
        for number, line in enumerate(lines, 1):
            if self.fail_at_line == number and not automatic:
                raise DeviceRefused(number - 1)
            tokens = tokenize(line.strip())
            if not tokens:
                continue
            if tokens[:2] == ["config", "reserved-address"]:
                in_child = True
            elif in_child and tokens[0] == "edit":
                key = tokens[1]
                objects.setdefault(key, {})
            elif in_child and tokens[0] == "set":
                objects[key][tokens[1]] = " ".join(tokens[2:])
            elif in_child and tokens[0] == "unset":
                objects[key].pop(tokens[1], None)
            elif in_child and tokens[0] == "delete":
                objects.pop(tokens[1], None)
            elif in_child and tokens[0] == "end":
                in_child = False
        return len(lines)

    def check_query(self, command):
        self._fire()
        if self.check_unreadable:
            raise RuntimeError("check account unavailable")
        if command.startswith("show firewall addrgrp "):
            key = command.split('"')[1]
            return table("firewall addrgrp", {key: self.groups[key]}) if key in self.groups else "entry is not found in table"
        if command == "show system dhcp server 1":
            return self.dhcp()
        return super().check_query(command)


class ExosMembership(FakeExos):
    def __init__(self):
        super().__init__()
        self.vlans.update({"users": {"tag": "20"}, "staging": {"tag": "30"}, "guest": {"tag": "40"}})
        self.memberships = {"10": {"untagged": "users", "tagged": {"guest"}}}
        self.persisted_memberships = copy.deepcopy(self.memberships)

    def _command(self, words, automatic):
        if words[:2] == ["configure", "vlan"] and words[3:5] in (["add", "ports"], ["delete", "ports"]):
            vlan, port = words[2], words[5]
            current = self.memberships[port]
            if words[3] == "delete":
                if vlan not in current["tagged"] and current["untagged"] != vlan:
                    return False
                current["tagged"].discard(vlan)
                if current["untagged"] == vlan:
                    current["untagged"] = None
            elif words[6] == "tagged":
                current["tagged"].add(vlan)
            else:
                current["untagged"] = vlan
                current["tagged"].discard(vlan)
            if not automatic or self.persistent_mode:
                self.persisted_memberships = copy.deepcopy(self.memberships)
                self.unsaved = True
            return True
        return super()._command(words, automatic)

    def snapshot(self):
        text = super().snapshot()
        added = []
        for port, modes in self.persisted_memberships.items():
            if modes["untagged"]:
                added.append("configure vlan %s add ports %s untagged" % (modes["untagged"], port))
            added += ["configure vlan %s add ports %s tagged" % (vlan, port) for vlan in sorted(modes["tagged"])]
        return text.replace("# Module upm configuration.", "\n".join(added) + "\n# Module upm configuration.")

    def check_query(self, command):
        self._fire()
        if command.endswith(" vlan") and command.startswith("show ports "):
            if self.check_unreadable:
                raise RuntimeError("check account unavailable")
            port = command.split()[2]
            modes = self.memberships[port]
            text = "Port /Tagged VLAN Name(s)\n"
            text += "%s Untagged %s\n" % (port, modes["untagged"])
            if modes["tagged"]:
                text += "         Tagged " + ", ".join(sorted(modes["tagged"])) + "\n"
            return text
        return super().check_query(command)
