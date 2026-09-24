from __future__ import annotations

import datetime

from netops_admin import exos, membership
from netops_admin.errors import Rejected
from netops_admin.exec_fortios import PromptSpec

TIMER_TOLERANCE_SECONDS = 10
UNSAVED_MARKER = b"*"


def prompt_spec(hostname: str) -> PromptSpec:
    return PromptSpec(anchor=("%s." % hostname).encode("ascii"), ends=(b"# ", b"> "), continuation=None,
                      error=exos.cli_error)


def safeguard_label(change_id: str) -> str:
    return exos.safeguard_names(change_id)["timer"]


def hostname(access, snapshot_text: str) -> str:
    return exos.switch_field(exos.SYSNAME, access.query(exos.QUERY_SWITCH), "system name")


def clock(access) -> datetime.datetime:
    text = exos.switch_field(exos.SWITCH_TIME, access.query(exos.QUERY_SWITCH), "clock")
    return datetime.datetime.strptime(text, exos.SWITCH_CLOCK_FORMAT)


def accounts_check(access, device, snapshot_text) -> str:
    snapshot = exos.Snapshot(snapshot_text, device.firmware)
    present = exos.accounts(snapshot)
    if present != sorted(device.accounts):
        raise Rejected(["the switch accounts differ from the expected list (%d present, %d expected)"
                        % (len(present), len(device.accounts))])
    return exos.account_fingerprint(snapshot)


def prechecks(access, device, snapshot_text, spec) -> list:
    reasons = []
    running = exos.switch_field(exos.IMAGE_VERSION, access.query(exos.QUERY_VERSION), "software version")
    if running != device.firmware:
        reasons.append("the switch runs %s, not the configured %s" % (running, device.firmware))
    if UNSAVED_MARKER in access.login_prefix(spec):
        reasons.append("the switch has unsaved configuration changes of someone else")
    return reasons


def leftovers(access) -> list:
    return sorted(set(exos.listed_names(access.query(exos.QUERY_PROFILES)))
                  | set(exos.listed_names(access.query(exos.QUERY_TIMERS))))


def install_safeguard(access, record, plan, device, spec) -> list:
    names = exos.safeguard_names(record["change_id"])
    access.apply(exos.render_safeguard(record["change_id"], plan["inverse"], device.safeguard_seconds), spec)
    problems = []
    contents = exos.profile_contents(access.query("%s %s" % (exos.QUERY_PROFILES, names["profile"])))
    if contents != exos.safeguard_script(plan["inverse"]):
        problems.append("safeguard profile differs from the planned inverse")
    row = exos.timer_row(access.query(exos.QUERY_TIMERS), names["timer"])
    if row is None or row["profile"] != names["profile"] or "o" not in row["flags"] or not row["next"]:
        problems.append("safeguard timer is missing, periodic, unscheduled or bound to another profile")
    else:
        planned = datetime.datetime.strptime(record["safeguard"]["fire_at"], exos.TIME_FORMAT)
        scheduled = datetime.datetime.strptime(row["next"], exos.TIME_FORMAT)
        if abs((scheduled - planned).total_seconds()) > TIMER_TOLERANCE_SECONDS:
            problems.append("safeguard timer fires at another time than planned")
        record["safeguard"]["fire_at"] = row["next"]
    return problems


def remove_safeguard(access, record, spec) -> bool:
    try:
        access.apply(exos.render_safeguard_removal(record["change_id"]), spec)
    except Exception:
        pass
    return safeguard_absent(access, record)


def safeguard_absent(access, record) -> bool:
    names = exos.safeguard_names(record["change_id"])
    try:
        listed = set(exos.listed_names(access.query(exos.QUERY_PROFILES))) | set(
            exos.listed_names(access.query(exos.QUERY_TIMERS)))
    except Exception:
        return False
    return not ({names["profile"], names["timer"]} & listed)


def persist(access, spec) -> bool:
    access.apply([("ask", "save configuration", b"(y/N)"), "y"], spec)
    return True


def observe(access, plan):
    if plan["table"] == "vlan-membership":
        return membership.shown(access.check_query("show ports %s vlan" % plan["key"]), plan["key"])
    if plan["table"] == "ports":
        return exos.shown_port(access.check_query("show ports %s information detail" % plan["key"]), plan["key"])
    text = access.check_query("show vlan %s" % plan["key"])
    try:
        return exos.shown_vlan(text, plan["key"])
    except Rejected:
        if "A number within the range of 1-4094 is expected." not in text:
            raise
        if exos.vlan_absent_from_list(access.check_query("show vlan"), plan["key"]):
            return None
        raise Rejected(["the check account cannot establish the VLAN state"]) from None


def foreign_sessions(access, device) -> int:
    return exos.foreign_sessions(access.query(exos.QUERY_SESSIONS))
