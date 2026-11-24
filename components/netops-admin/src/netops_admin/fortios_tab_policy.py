"""1.0.13 A2 FortiOS tables (firewall service group, firewall schedule recurring, firewall schedule onetime).

Registered in fortios_tables.MODULES as TABLES = {table: TableHooks(...)}. The shared code (fortios_tables) gives the
three tables the generic object path: the plan reads the whole object (every printed attribute outside the profile
refuses the plan), apply needs the approved preview (fortios_object_preview_required), delete of an object another
object names is refused (fortios_object_referenced), and a change of an object a firewall policy uses follows the
policy rules (policy_attributes): refused for a protected policy, endpoint_impact naming the object for an active one.

The hooks here add what the generic path does not know (measured on FortiGate-60F 7.6.8 build3744, see
tests/fixtures/fortios_a2/PROVENANCE.md):

- a service group holds only existing custom services and service groups, never itself through any other group, and
  no member name with a space (FortiOS prints the member list quoted; Admin compares it as a list of single names);
- a policy that uses a group holding the object (a service group in a service group, a schedule in a schedule group)
  counts like a policy that names the object itself;
- a recurring schedule holds weekday names only; a one-time schedule ends after it starts;
- FortiOS refuses a quoted one-time start or end ("set start "10:00 2026/12/01"" returns -160), so both are written as
  the two words FortiOS prints (``set start 10:00 2026/12/01``); the strict patterns of the profile admit no other text.

No REST inverse is verified on FortiOS 8.0.x for these tables (rest_verified is empty): every operation is refused
there before any write with safeguard_no_rest_inverse.
"""
from __future__ import annotations

import re

from netops_auditor import l1_fortios

from netops_admin.errors import Rejected
from netops_admin.fortios_tables import TableHooks

SERVICE_GROUP = "firewall service group"
SERVICE_CUSTOM = "firewall service custom"
RECURRING = "firewall schedule recurring"
ONETIME = "firewall schedule onetime"
SCHEDULE_GROUP = "firewall schedule group"
POLICY = "firewall policy"
WEEKDAYS = ("sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday")
ONETIME_UNQUOTED = ("start", "end")
MOMENT = re.compile(r"([01][0-9]|2[0-3]):([0-5][0-9]) ([0-9]{4})/(0[1-9]|1[0-2])/([0-3][0-9])")
MONTH_DAYS = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _entries(snapshot, table, label):
    entries = snapshot.entries(table)
    if entries is None:
        raise Rejected(["the snapshot holds no complete %s section; %s cannot be evaluated" % (table, label)])
    return entries


def _members(entry) -> set:
    attr = entry.attrs.get("member")
    return set() if attr is None else {item.casefold() for item in attr.values}


def _containing(entries, key: str) -> set:
    """The groups that hold key directly or through another group of the same table."""
    groups = {name: _members(entry) for name, entry in entries.items()}
    found, pending = set(), [key.casefold()]
    while pending:
        inner = pending.pop()
        for name, members in groups.items():
            if inner in members and name not in found:
                found.add(name)
                pending.append(name.casefold())
    return found


def _group_policy_use(snapshot, profile, op, key, before, after, protected, impact, undo, groups_table, attribute):
    """A policy that names a group holding the object uses the object as well (the generic check covers a policy that
    names the object itself)."""
    if op not in ("update", "delete"):
        return []
    changed = {name for name in set(before or {}) | set(after or {})
               if (before or {}).get(name) != (after or {}).get(name)} - {"comment", "comments"}
    if not changed and op != "delete":
        return []
    # show omits an empty table (measured: the stored show of 7.6.8 has no firewall schedule group section)
    groups = snapshot.entries(groups_table) or {}
    holders = _containing(groups, key) - {key}
    if not holders:
        return []
    from netops_admin import fortios
    guarded, active = fortios.policy_use(snapshot, holders, (attribute,), protected)
    if guarded:
        raise Rejected(["%s %s is used through %s by the protected firewall policies %s"
                        % (profile.table, key, ", ".join(sorted(holders)), ", ".join(guarded))])
    if active and impact is None and not undo:
        raise Rejected(["%s %s is used through %s by the active firewall policies %s: the change alters the traffic"
                        " they match; endpoint_impact naming the object is required"
                        % (profile.table, key, ", ".join(sorted(holders)), ", ".join(active))],
                       reason_codes=["fortios_policy_impact_required"])
    return []


def service_group_prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) -> list:
    reasons = []
    groups = _entries(snapshot, SERVICE_GROUP, "the service group members")
    if after is not None:
        customs = _entries(snapshot, SERVICE_CUSTOM, "the service group members")
        members = l1_fortios.tokenize(after.get("member", ""))
        if not members:
            reasons.append("a service group needs at least one member")
        spaced = sorted(name for name in members if any(c.isspace() or c in "\"'\\" for c in name))
        if spaced:
            reasons.append("service group members with a space or a quote in the name are not supported: %s"
                           % ", ".join(spaced))
        known = {name.casefold() for name in (*customs, *groups)}
        missing = sorted(name for name in members if name.casefold() not in known)
        if missing:
            reasons.append("the service group names services missing from the snapshot: %s" % ", ".join(missing))
        # no cycle: the group must not hold itself directly or through any member group
        holders = _containing(groups, key) | {key.casefold()}
        looped = sorted(name for name in members if name.casefold() in {item.casefold() for item in holders})
        if looped:
            reasons.append("the service group would hold itself through %s" % ", ".join(looped))
    reasons.extend(_group_policy_use(snapshot, profile, op, key, before, after, protected, impact, undo,
                                     SERVICE_GROUP, "service"))
    return reasons


def recurring_prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) -> list:
    reasons = []
    if after is not None:
        days = l1_fortios.tokenize(after.get("day", ""))
        if not days or any(day not in WEEKDAYS for day in days):
            reasons.append("day must name one or more weekdays (%s)" % ", ".join(WEEKDAYS))
    reasons.extend(_group_policy_use(snapshot, profile, op, key, before, after, protected, impact, undo,
                                     SCHEDULE_GROUP, "schedule"))
    return reasons


def _moment(value):
    """(year, month, day, hour, minute) of a one-time schedule time HH:MM YYYY/MM/DD as FortiOS prints it, or None."""
    match = MOMENT.fullmatch(value or "")
    if match is None:
        return None
    hour, minute, year, month, day = (int(item) for item in match.groups())
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    if not 1 <= day <= MONTH_DAYS[month - 1] - (month == 2 and not leap):
        return None
    return year, month, day, hour, minute


def onetime_prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) -> list:
    reasons = []
    if after is not None:
        start, end = _moment(after.get("start")), _moment(after.get("end"))
        if start is None or end is None:
            reasons.append("start and end must be given as HH:MM YYYY/MM/DD")
        elif end <= start:
            # measured: FortiOS itself accepts an end before the start
            reasons.append("end must be later than start")
    reasons.extend(_group_policy_use(snapshot, profile, op, key, before, after, protected, impact, undo,
                                     SCHEDULE_GROUP, "schedule"))
    return reasons


def _onetime_value(profile, name, value):
    from netops_admin import fortios
    if name in ONETIME_UNQUOTED:
        if _moment(value) is None:
            raise Rejected(["%s must be given as HH:MM YYYY/MM/DD" % name])
        return value
    return fortios._value(profile, name, value)


def onetime_render(profile, op, key, assign, remove) -> list:
    """The generic object rendering with start and end unquoted (FortiOS refuses them quoted, return code -160)."""
    from netops_admin import fortios
    if op == "delete":
        return ["config " + profile.table, "    delete " + fortios._quoted(key), "end"]
    lines = ["config " + profile.table, "    edit " + fortios._quoted(key)]
    # start before end, as FortiOS prints them
    for name in sorted(assign, key=lambda item: (item not in ONETIME_UNQUOTED, ONETIME_UNQUOTED.index(item)
                                                 if item in ONETIME_UNQUOTED else 0, item)):
        lines.append("        set %s %s" % (name, _onetime_value(profile, name, assign[name])))
    lines.extend("        unset %s" % name for name in sorted(remove))
    return lines + ["    next", "end"]


TABLES = {
    SERVICE_GROUP: TableHooks(SERVICE_GROUP, rest_path="firewall.service/group", rest_key="name",
                              rest_permission="fwgrp", impact=True, policy_attributes=("service",),
                              prechecks=service_group_prechecks),
    RECURRING: TableHooks(RECURRING, rest_path="firewall.schedule/recurring", rest_key="name",
                          rest_permission="fwgrp", impact=True, policy_attributes=("schedule",),
                          prechecks=recurring_prechecks),
    ONETIME: TableHooks(ONETIME, rest_path="firewall.schedule/onetime", rest_key="name",
                        rest_permission="fwgrp", impact=True, policy_attributes=("schedule",),
                        prechecks=onetime_prechecks, render=onetime_render),
}
