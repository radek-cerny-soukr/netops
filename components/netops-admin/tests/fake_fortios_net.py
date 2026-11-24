"""Simulated FortiGate-60F 7.6.8 build3744 with system interface and router static (1.0.12 FIREWALL-ROUTING-ADMIN, verification).

The interface and route tables start from the anonymised `show system interface` and `show router static` of the lab
FortiGate-60F (fixtures/fortios_7_6_8_net). Only the measured behaviour of that build is simulated (verification,
private measurement record): a new VLAN gets `device-identification enable` and the next `snmp-index`; without an
explicit role it inherits the role of its parent, and role lan with an address creates the firewall address
"<name> address" (type interface-subnet); `role undefined`, `status up`, `distance 10`, `status enable` and
`dynamic-gateway disable` are defaults that show omits; quoted option values are accepted; deleting an interface still
named by another object fails with "The entry is used by other N entries" (-23). Everything else (addresses, the
automation safeguard, admins) is the generic FakeFortiOS.
"""
from __future__ import annotations

from pathlib import Path

from fake_fortios import DeviceRefused, FakeFortiOS, quoted

from netops_auditor import l1_fortios

FIXTURES = Path(__file__).parent / "fixtures" / "fortios_7_6_8_net"
TABLES = ("system interface", "router static")
# attribute order of show on 7.6.8 build3744 (fixtures: baseline, created-role-undefined, status-down, route readbacks)
ORDER = {
    "system interface": ("vdom", "mode", "ip", "allowaccess", "status", "type", "src-check", "description", "alias",
                         "security-mode", "replacemsg-override-group", "device-identification", "role", "snmp-index",
                         "interface", "vlanid"),
    "router static": ("status", "dst", "gateway", "distance", "device", "comment", "dynamic-gateway"),
}
QUOTED = {"vdom", "description", "alias", "interface", "device", "comment", "member", "replacemsg-override-group",
          "switch-controller-nac", "switch-controller-dynamic", "switch-controller-traffic-policy"}
DEFAULTS = {
    "system interface": {"status": "up", "role": "undefined", "ip": "0.0.0.0 0.0.0.0"},
    "router static": {"status": "enable", "distance": "10", "dynamic-gateway": "disable", "gateway": "0.0.0.0"},
}
NOT_FOUND = "entry is not found in table\n"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def parse_table(text: str) -> dict:
    """{key: {"attrs": {name: value}, "nested": [raw lines]}} of one shown table, attribute order kept."""
    entries, current, depth = {}, None, 0
    for raw in text.splitlines():
        tokens = l1_fortios.tokenize(raw.strip())
        if not tokens:
            continue
        if current is None:
            if tokens[0] == "edit":
                current = entries.setdefault(tokens[1], {"attrs": {}, "nested": []})
            continue
        if depth == 0 and tokens[0] == "next":
            current = None
        elif depth == 0 and tokens[0] == "set":
            current["attrs"][tokens[1]] = " ".join(tokens[2:])
        else:
            current["nested"].append(raw)
            depth += 1 if tokens[0] == "config" else -1 if tokens[0] == "end" else 0
    return entries


class FakeFortiOSNet(FakeFortiOS):
    firmware = ("7.6.8", "3744")

    def __init__(self, hostname="fw-lab"):
        super().__init__(hostname)
        self.interfaces = []
        self.net = {"system interface": parse_table(fixture("show-system-interface__baseline.txt")),
                    "router static": parse_table(fixture("show-router-static__baseline.txt"))}

    # --- device side -------------------------------------------------------------------------------------------
    def _set(self, table, entry, name, value):
        if DEFAULTS[table].get(name) == value:
            entry["attrs"].pop(name, None)
            return
        attrs = entry["attrs"]
        if name in attrs:
            attrs[name] = value
            return
        order = ORDER[table]
        rank = order.index(name) if name in order else len(order)
        items = list(attrs.items())
        position = next((i for i, (other, _) in enumerate(items)
                         if (order.index(other) if other in order else len(order)) > rank), len(items))
        items.insert(position, (name, value))
        entry["attrs"] = dict(items)

    def _finish(self, table, key, entry):
        attrs = entry["attrs"]
        if table != "system interface" or "interface" not in attrs:
            return
        parent = self.net[table].get(attrs["interface"], {"attrs": {}})["attrs"]
        explicit = entry.pop("role", None)
        role = parent.get("role", "undefined") if explicit is None else explicit
        if role != "undefined":
            self._set(table, entry, "role", role)
        self._set(table, entry, "device-identification", "enable")
        indexes = [int(e["attrs"].get("snmp-index", 0)) for e in self.net[table].values()]
        self._set(table, entry, "snmp-index", str(max(indexes) + 1))
        if role == "lan" and "ip" in attrs:
            ip, mask = attrs["ip"].split()
            import ipaddress
            network = ipaddress.IPv4Interface("%s/%s" % (ip, mask)).network
            self.addresses[key + " address"] = {"uuid": self._uuid(),
                                                "subnet": "%s %s" % (network.network_address, network.netmask),
                                                "interface": key}

    def _users(self, name):
        found = [key for key, attributes in self.addresses.items() if attributes.get("interface") == name]
        for table, entries in self.net.items():
            for key, entry in entries.items():
                if key != name and name in (entry["attrs"].get("interface"), entry["attrs"].get("device")):
                    found.append(key)
        return found

    def _net_line(self, state, tokens, accepted):
        table = state["table"]
        entries = self.net[table]
        command = tokens[0]
        if command == "edit":
            key = tokens[1]
            state["key"] = key
            if key not in entries:
                entries[key] = {"attrs": {}, "nested": [], "new": True}
        elif command == "set":
            entry = entries[state["key"]]
            value = " ".join(tokens[2:])
            if table == "system interface" and tokens[1] == "role" and entry.get("new"):
                entry["role"] = value
                if value != "undefined":
                    self._set(table, entry, "role", value)
            else:
                self._set(table, entry, tokens[1], value)
        elif command == "unset":
            entries[state["key"]]["attrs"].pop(tokens[1], None)
        elif command == "next":
            entry = entries[state["key"]]
            if entry.pop("new", None):
                self._finish(table, state["key"], entry)
            state["key"] = None
        elif command == "delete":
            if table == "system interface" and tokens[1] in entries and self._users(tokens[1]):
                raise DeviceRefused(accepted)
            entries.pop(tokens[1], None)
        elif command == "end":
            state["table"] = None

    def _run(self, lines, automatic=False):
        accepted, chunk, start, state, quote = 0, [], 0, {"table": None, "key": None}, False

        def flush():
            nonlocal chunk, accepted
            if not chunk:
                return
            saved = self.fail_at_line
            if saved is not None and not automatic:
                self.fail_at_line = saved - start if start < saved <= start + len(chunk) else None
            try:
                accepted += super(FakeFortiOSNet, self)._run(chunk, automatic)
            except DeviceRefused as exc:
                raise DeviceRefused(accepted + exc.accepted_lines) from None
            finally:
                self.fail_at_line = saved
            chunk = []

        for number, raw in enumerate(lines, 1):
            tokens = [] if quote else _tokens(raw)
            if state["table"] is None and not quote and tokens[:1] == ["config"] and " ".join(tokens[1:]) in TABLES:
                flush()
                state["table"] = " ".join(tokens[1:])
                accepted += 1
                continue
            if state["table"] is not None:
                if self.fail_at_line == number and not automatic:
                    raise DeviceRefused(accepted)
                if tokens:
                    self._net_line(state, tokens, accepted)
                accepted += 1
                continue
            if not chunk:
                start = number - 1
            chunk.append(raw)
            text = "\n".join(chunk)
            quote = bool(l1_fortios._quote_state(text)[0])
        flush()
        return accepted

    # --- read side -----------------------------------------------------------------------------------------------
    def _lines(self, table, key):
        lines = ['    edit %s' % (key if table == "router static" else quoted(key))]
        for name, value in self.net[table][key]["attrs"].items():
            if name in QUOTED:
                value = " ".join(quoted(item) for item in l1_fortios.tokenize(value)) if name == "member" else quoted(value)
            lines.append("        set %s %s" % (name, value))
        lines.extend(self.net[table][key]["nested"])
        return lines + ["    next"]

    def _table_text(self, table, keys=None):
        lines = ["config " + table]
        for key in self.net[table] if keys is None else keys:
            lines += self._lines(table, key)
        return lines + ["end"]

    def snapshot(self):
        text = super().snapshot()
        text = text.replace("config system interface\nend\n", "", 1)
        extra = self._table_text("system interface") + self._table_text("router static")
        return text + "\n".join(extra) + "\n"

    def show(self, table, key):
        if key not in self.net[table]:
            return NOT_FOUND
        return "\n".join(self._table_text(table, [key])) + "\n"

    def check_query(self, command):
        for table in TABLES:
            if command.startswith("show %s " % table):
                self._connect()
                self._fire()
                if self.check_unreadable:
                    raise RuntimeError("check account unavailable")
                return self.show(table, command.split('"')[1])
        return super().check_query(command)


def _tokens(raw):
    try:
        return l1_fortios.tokenize(raw.strip())
    except Exception:
        return raw.split()
