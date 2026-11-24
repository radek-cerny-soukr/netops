"""1.0.13 A2: a FortiOS simulator for firewall service group, firewall schedule recurring and firewall schedule onetime.

Built on fake_fortios_tables (the registry simulator of A1-R) with the layout measured on FortiGate-60F 7.6.8
build3744 (fixtures/fortios_a2/PROVENANCE.md):

- the starting objects are the captured ``show`` answers (service-group-show.txt, schedule-recurring-show.txt; the
  lab had no one-time schedule and no schedule group, and ``show`` omits both tables);
- ``edit`` of a new object assigns a UUID that ``show`` prints first (show prints uuid for every object of the three
  tables);
- ``show`` omits the measured defaults (recurring start/end 00:00, one-time expiration-days 3, comment '', color 0,
  fabric-object disable) and prints the recurring day list in week order whatever order it was set in;
- the member list and the comment of a service group are printed quoted, the times of a schedule unquoted;
- the firewall policies of the base simulator name the objects (service, schedule) and print inspection-mode only
  when it is not the default flow (the policy profile does not manage it).

FortiOS refuses a quoted one-time start or end with return code -160 (probe-onetime-recurring-group.txt); with the
OpenSSH test client a test reproduces that refusal through the ``refuse-line`` file of fortinet_ssh_fixture.
"""
from __future__ import annotations

from pathlib import Path

from fake_fortios_tables import FakeFortiOSTables, FakeFortiOSTablesWebhook, Table

from netops_auditor import l1_fortios

FIXTURES = Path(__file__).parent / "fixtures" / "fortios_a2"
GROUP = "firewall service group"
RECURRING = "firewall schedule recurring"
ONETIME = "firewall schedule onetime"
SCHEDULE_GROUP = "firewall schedule group"
WEEK = ("sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday")


def a2_tables(captured=True):
    tables = {
        GROUP: Table(defaults={"comment": "", "color": "0", "fabric-object": "disable"},
                     quoted_names=("member", "comment"), order=("uuid", "member", "comment")),
        RECURRING: Table(defaults={"start": "00:00", "end": "00:00", "label-day": "none", "color": "0",
                                   "fabric-object": "disable"}, order=("uuid", "start", "end", "day")),
        ONETIME: Table(defaults={"start": "00:00 2001/01/01", "end": "00:00 2001/01/01", "expiration-days": "3",
                                 "color": "0", "fabric-object": "disable"},
                       order=("uuid", "start", "end", "expiration-days")),
        SCHEDULE_GROUP: Table(quoted_names=("member",), order=("uuid", "member")),
    }
    if captured:
        for table, name in ((GROUP, "service-group-show.txt"), (RECURRING, "schedule-recurring-show.txt")):
            section = l1_fortios.parse((FIXTURES / name).read_text()).sub[table]
            for key, node in section.entries.items():
                tables[table].objects[key] = {"attrs": {attr: item.value() for attr, item in node.attrs.items()},
                                              "children": {}}
    return tables


class A2Mixin:
    def _a2_init(self):
        self.policies = {}
        # show omits the defaults; inspection-mode is printed only when it is proxy (outside the policy profile)
        self.policy_hidden = {"status": "enable", "action": "deny", "inspection-mode": "flow"}
        self.services = {"HTTP": {}, "HTTPS": {}, "DNS": {}, "SSH": {}}
        self.interfaces = ["port1", "port2", "wan1", "internal"]

    def _a2_known(self):
        return {(name, key) for name in (GROUP, RECURRING, ONETIME, SCHEDULE_GROUP)
                for key in self.tables[name].objects}

    def _a2_settle(self, known):
        """What FortiOS does when it saves an edited object: a UUID for a new object, the day list in week order."""
        for name in (GROUP, RECURRING, ONETIME, SCHEDULE_GROUP):
            for key, item in self.tables[name].objects.items():
                attrs = item["attrs"]
                if (name, key) not in known and "uuid" not in attrs:
                    item["attrs"] = attrs = {"uuid": self._uuid(), **attrs}
                if "day" in attrs:
                    days = attrs["day"].split()
                    attrs["day"] = " ".join(day for day in WEEK if day in days) + "".join(
                        " " + day for day in days if day not in WEEK)


class FakeFortiOSA2(A2Mixin, FakeFortiOSTables):
    """FortiGate-60F, FortiOS 7.6.8 build3744 (cli-script safeguard)."""

    def __init__(self, captured=True):
        super().__init__(a2_tables(captured))
        self._a2_init()

    def _run(self, lines, automatic=False):
        known = self._a2_known()
        try:
            return super()._run(lines, automatic)
        finally:
            self._a2_settle(known)


class FakeFortiOSA2Webhook(A2Mixin, FakeFortiOSTablesWebhook):
    """The FortiGate 80F HA pair, FortiOS 8.0.2 build0251 (webhook safeguard)."""

    def __init__(self, captured=True):
        super().__init__(a2_tables(captured))
        self._a2_init()

    def _run(self, lines, automatic=False):
        known = self._a2_known()
        try:
            return super()._run(lines, automatic)
        finally:
            self._a2_settle(known)


def lose_check_after(table):
    """on_apply hook: the check account is lost once the write account changed ``table`` (the safeguard returns it)."""
    return _LoseCheck(table)


class _LoseCheck:
    def __init__(self, table):
        self.table = table

    def __call__(self, fake, block):
        if block and block[0] == "config " + self.table:
            fake.check_unreadable = True
