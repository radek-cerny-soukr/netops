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


def plan_prechecks(access, device, plan, snapshot_text="") -> list:
    before, after = plan["predicted"]["before"] or {}, plan["predicted"]["after"] or {}
    if plan["table"] == "ports" and before.get("admin-state") != after.get("admin-state"):
        _port_prechecks(access, device, plan, snapshot_text)
    elif plan["table"] == "inline-power":
        _poe_prechecks(access, device, plan)
    return []


def _sides(plan) -> set:
    return set(plan["predicted"]["before"] or {}) | set(plan["predicted"]["after"] or {})


def _port_prechecks(access, device, plan, snapshot_text) -> None:
    key = plan["key"]
    shown = exos.port_configuration(access.query("show ports %s configuration no-refresh" % key), key)
    if shown is None:
        plan["prechecks"].append("port %s: show ports configuration is not recognised (informational)" % key)
    else:
        plan["prechecks"].append("port %s now: port state %s, link state %s"
                                 % (key, shown["port_state"], shown["link_state"]))
    if (plan["predicted"]["after"] or {}).get("admin-state") != "disabled" \
            or (plan["predicted"]["before"] or {}).get("admin-state") == "disabled":
        return
    snapshot = exos.Snapshot(snapshot_text, device.firmware)
    if not exos.vlan_module_closed(snapshot):
        raise Rejected(["the configuration ends inside its vlan module; VLAN membership of port %s cannot be read "
                        "completely" % key], reason_codes=["port_usage_unreadable"])
    if "ports" in plan:
        snapshot.inventory = frozenset(plan["ports"])
    vlans = (device.audit_policy or {}).get("management_vlans", [])
    if exos.management_vlan_member(snapshot, key, vlans):
        raise Rejected(["port %s is a member of a management VLAN of the audit policy" % key],
                       reason_codes=["port_management_vlan"])
    if key in exos.lldp_ports(access.query(exos.QUERY_LLDP)):
        raise Rejected(["port %s has an LLDP neighbor (uplink or managed device); disabling it is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    if key in exos.fdb_ports(access.query(exos.QUERY_FDB)):
        raise Rejected(["port %s has learned MAC addresses; disabling a port in use is refused" % key],
                       reason_codes=["port_learned_mac"])
    plan["prechecks"].append("port %s has no LLDP neighbor and no learned MAC address" % key)


def poe_state(access, key: str, check=False) -> dict:
    """Configured admin state and inline power state of a port, read by the check account or the write account."""
    query = access.check_query if check else access.query
    return exos.poe_detail(query("show inline-power info detail ports %s" % key), key)


def _poe_prechecks(access, device, plan) -> None:
    key = plan["key"]
    command = "show inline-power info ports %s" % key
    rc, text = access.query_status(command)
    if exos.poe_not_capable_answer(rc, text, key):
        raise exos.NotInlinePower(["port %s is not inline-power capable" % key], reason_codes=["poe_not_capable"])
    if rc != 0:
        from netops_admin.access import AccessError
        raise AccessError("query ended with exit status %s" % rc)
    row = exos.poe_info(text, key)
    if row["state"] == "disabled":
        raise Rejected(["inline power of port %s is disabled (not delivering and not searching); a cycle is refused"
                        % key], reason_codes=["poe_disabled"])
    plan["prechecks"].append("port %s inline power before the cycle: %s, class %s, %s W, fault %s"
                             % (key, row["state"], row["class"], row["power_watts"], row["fault"]))


def ports(access, table: str):
    if table not in ("vlan-membership", "ports", "inline-power"):
        return None
    return exos.switch_ports(access.query(exos.QUERY_PORTS))


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
        profiles = access.query(exos.QUERY_PROFILES)
        timers = access.query(exos.QUERY_TIMERS)
    except Exception:
        return False
    if not (exos.upm_listing_complete(profiles, "Profiles") and exos.upm_listing_complete(timers, "Timers")):
        return False
    listed = set(exos.listed_names(profiles)) | set(exos.listed_names(timers))
    return not ({names["profile"], names["timer"]} & listed)


def remove_remaining(access, record, spec) -> bool:
    names = exos.safeguard_names(record["change_id"])
    try:
        listed = set(exos.listed_names(access.query(exos.QUERY_PROFILES))) | set(exos.listed_names(access.query(exos.QUERY_TIMERS)))
        lines = [line for line, name in zip(exos.render_safeguard_removal(record["change_id"]),
                                            (names["timer"], names["profile"])) if name in listed]
        if lines:
            access.apply(lines, spec)
    except Exception:
        pass
    return safeguard_absent(access, record)


def safeguard_disarmed(access, record) -> bool:
    try:
        timers = access.query(exos.QUERY_TIMERS)
    except Exception:
        return False
    return (exos.upm_listing_complete(timers, "Timers")
            and exos.safeguard_names(record["change_id"])["timer"] not in exos.listed_names(timers))


FIRING_OBSERVED = True


def safeguard_fired(access, record) -> bool:
    names = exos.safeguard_names(record["change_id"])
    try:
        timers = access.query(exos.QUERY_TIMERS)
    except Exception:
        return False
    row = exos.timer_row(timers, names["timer"])
    return (exos.upm_listing_complete(timers, "Timers") and row is not None and row["profile"] == names["profile"]
            and not row["next"] and "o" not in row["flags"])


def persist(access, spec) -> bool:
    access.apply([("ask", "save configuration", b"(y/N)"), "y"], spec)
    return True


def observe(access, plan):
    if plan["table"] == "vlan-membership":
        text = access.check_query("show ports %s vlan" % plan["key"])
        alias = None
        if membership.label(text) is not None:
            port = exos.shown_port(access.check_query("show ports %s information detail" % plan["key"]), plan["key"])
            alias = (port or {}).get("display-string")
        return membership.shown(text, plan["key"], alias)
    if plan["table"] == "ports":
        return exos.shown_port(access.check_query("show ports %s information detail" % plan["key"]), plan["key"],
                               admin_state="admin-state" in _sides(plan))
    if plan["table"] == "inline-power":
        state = poe_state(access, plan["key"], check=True)
        return {"admin-state": "disabled"} if state["configured"] == "disabled" else {}
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
