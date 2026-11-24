"""1.0.13 A1-R: a FortiOS simulator for the tables of the registry (fortios_tables).

It behaves like the device in the points the registry depends on (measured on FortiGate-60F 7.6.8 build3744, see
fixtures/fortios_7_6_8_dhcp_dns/PROVENANCE.md for the DHCP server layout):

- a singleton is a section without edit/next (``config system dns`` ... ``end``), always present;
- a nested table lives below its parent (``config ip-range`` inside ``edit <server>``); ``show`` prints a child
  section only while it holds an entry;
- ``show`` omits an object table without any object (the stored ``show`` of 7.6.8 has no ``config router static6``);
  ``Table(print_empty=True)`` prints the empty ``config``/``end`` wrapper instead;
- ``show`` omits an attribute set to its default value (``show full-configuration`` would print it);
- ``edit`` is an upsert: it opens an existing object or creates it;
- ``delete`` of an object another object refers to is refused with -23 (``used by``), nothing changes;
- a line the device refuses (``fail_at_line``) ends the block, the earlier lines stay written.

The managed tables are given per instance; any other block goes to the base fake (address, policy, automation).
"""
from __future__ import annotations

from fake_fortios import DeviceRefused, FakeFortiOS, quoted
from fake_webhook import FakeFortiOSWebhook

from netops_auditor import l1_fortios

USED_BY = "Command fail. Return code -23"


class Table:
    """One managed table: kind object|singleton, its default values, the attributes printed in quotes and the child
    sections an object can hold."""

    def __init__(self, kind="object", defaults=None, quoted_names=(), children=(), numeric_keys=False, order=(),
                 print_empty=False):
        self.kind = kind
        self.print_empty = print_empty
        self.defaults = dict(defaults or {})
        self.quoted_names = frozenset(quoted_names)
        self.children = tuple(children)
        self.numeric_keys = numeric_keys
        self.order = tuple(order)  # FortiOS prints attributes in its schema order, not in the order they were set
        self.attrs = {}      # singleton: name -> value (a string; lists hold their tokens joined by spaces)
        self.objects = {}    # object: key -> {"attrs": {...}, "children": {section: {id: {...}}}}


def _value(table, name, value):
    if name in table.quoted_names:
        return " ".join(quoted(item) for item in l1_fortios.tokenize(value)) if value else '""'
    return value


def _ordered(table, attrs):
    known = [name for name in table.order if name in attrs]
    return [(name, attrs[name]) for name in known + [name for name in attrs if name not in table.order]]


def _key(table, key):
    return key if table.numeric_keys and key.isdigit() else quoted(key)


class TablesMixin:
    def _tables_init(self, tables):
        self.tables = dict(tables)
        self.referenced = set()          # (table, key) refused by delete with -23
        self.tables_refused = []         # the lines the device refused
        self.tables_written = 0          # the blocks the write account ran on the managed tables
        # the answer of the check account to a command once the write account changed a managed table (the snapshot
        # stays as the device holds it; only the independent read differs)
        self.check_after_write = {}

    def tables_check_override(self, command):
        if self.tables_written and command in self.check_after_write:
            return self.check_after_write[command]
        return None

    # ------------------------------------------------------------------------------------------- show

    def table_lines(self, name, key=None):
        table = self.tables[name]
        lines = ["config " + name]
        if table.kind == "singleton":
            lines += ["    set %s %s" % (attr, _value(table, attr, value)) for attr, value in table.attrs.items()
                      if table.defaults.get(attr) != value]
            return lines + ["end"]
        for item_key, item in table.objects.items():
            if key is not None and item_key != key:
                continue
            lines.append("    edit " + _key(table, item_key))
            for attr, value in _ordered(table, item["attrs"]):
                if table.defaults.get(attr) != value:
                    lines.append("        set %s %s" % (attr, _value(table, attr, value)))
            for section, children in item["children"].items():
                if not children:
                    continue  # FortiOS does not print an empty child section
                lines.append("        config " + section)
                for child_id, attrs in children.items():
                    lines.append("            edit " + child_id)
                    lines += ["                set %s %s" % (attr, value) for attr, value in _ordered(table, attrs)]
                    lines.append("            next")
                lines.append("        end")
            lines.append("    next")
        return lines + ["end"]

    def tables_snapshot(self):
        return "".join("\n".join(self.table_lines(name)) + "\n" for name, table in self.tables.items()
                       if table.kind == "singleton" or table.objects or table.print_empty)

    def tables_show(self, command):
        for name, table in self.tables.items():
            if table.kind == "singleton" and command == "show " + name:
                return "\n".join(self.table_lines(name)) + "\n"
            if table.kind == "object" and command.startswith("show %s " % name):
                key = command[len("show %s " % name):].strip().strip('"')
                if key not in table.objects:
                    return "entry is not found in table\n"
                return "\n".join(self.table_lines(name, key)) + "\n"
        return None

    # ------------------------------------------------------------------------------------------- writes

    def tables_run(self, lines, automatic):
        first = l1_fortios.tokenize(lines[0].strip()) if lines else []
        name = " ".join(first[1:]) if first[:1] == ["config"] else None
        if name not in self.tables:
            return None
        table = self.tables[name]
        if not automatic:
            self.tables_written += 1
        current = section = child = None
        accepted = 0
        for number, raw in enumerate(lines, 1):
            tokens = l1_fortios.tokenize(raw.strip())
            if not tokens:
                continue
            if self.fail_at_line == number and not automatic:
                self.tables_refused.append(raw)
                raise DeviceRefused(accepted)
            command = tokens[0]
            if number == 1:
                pass
            elif command == "config" and current is not None:
                section = tokens[1]
                current["children"].setdefault(section, {})
            elif command == "edit" and section is not None:
                child = current["children"][section].setdefault(tokens[1], {})
            elif command == "edit":
                current = table.objects.setdefault(tokens[1], {"attrs": {}, "children": {}})
            elif command == "delete" and section is not None:
                current["children"][section].pop(tokens[1], None)
            elif command == "delete":
                if (name, tokens[1]) in self.referenced:
                    self.tables_refused.append(raw)
                    raise DeviceRefused(accepted)
                table.objects.pop(tokens[1], None)
            elif command in ("set", "unset"):
                target = (child if child is not None else current["attrs"] if current is not None else table.attrs)
                if command == "set":
                    target[tokens[1]] = " ".join(tokens[2:])
                elif tokens[1] in table.defaults and target is table.attrs:
                    target[tokens[1]] = table.defaults[tokens[1]]
                else:
                    target.pop(tokens[1], None)
            elif command == "next" and child is not None:
                child = None
            elif command == "next":
                current = None
            elif command == "end" and section is not None:
                section = None
            accepted += 1
        return accepted


class FakeFortiOSTables(TablesMixin, FakeFortiOS):
    """FortiOS 7.6.8 build3744 (cli-script safeguard) with the managed tables of the registry."""

    firmware = ("7.6.8", "3744")

    def __init__(self, tables):
        super().__init__()
        self._tables_init(tables)

    def snapshot(self):
        return super().snapshot() + self.tables_snapshot()

    def _run(self, lines, automatic=False):
        done = self.tables_run(lines, automatic)
        return super()._run(lines, automatic) if done is None else done

    def check_query(self, command):
        self._fire()
        if self.check_unreadable:
            raise RuntimeError("check account unavailable")
        if self.check_override is not None and command in self.check_override:
            return self.check_override[command]
        shown = self.tables_check_override(command) or self.tables_show(command)
        return super().check_query(command) if shown is None else shown


class FakeFortiOSTablesWebhook(TablesMixin, FakeFortiOSWebhook):
    """FortiOS 8.0.2 build0251 (webhook safeguard) with the managed tables of the registry."""

    def __init__(self, tables):
        super().__init__()
        self._tables_init(tables)

    def snapshot(self):
        return super().snapshot() + self.tables_snapshot()

    def _run(self, lines, automatic=False):
        done = self.tables_run(lines, automatic)
        return super()._run(lines, automatic) if done is None else done

    def check_query(self, command):
        shown = self.tables_check_override(command) or self.tables_show(command)
        return super().check_query(command) if shown is None else shown
