"""Arista EOS execution adapter (measured on cEOSLab 4.36.1F, ref/c7-mereni).

Safeguard first, as execute.py needs it: an empty configuration session with a commit timer is committed before the
change; its checkpoint holds the configuration before the change. The change itself runs line by line through
configure terminal in an interactive session (an ssh exec batch continues after an error and would run the rest).
Confirmation commits the session (configure session NAME commit, also from another connection) and deletes its
record; an expired timer returns the whole running configuration to that checkpoint, which only the log proves
(CONFIG_SESSION_COMMIT_TIMER_TIMEDOUT, CONFIG_SESSION_COMMIT_REVERTED), because the session disappears. While the
timer is pending EOS refuses another commit timer and the commit of any other session, and write memory would save
the unconfirmed state, so persist runs only after the confirmation.

The write account must log in with privilege 15 (aaa authorization exec default local and username ... privilege
15): Admin reads the running configuration with one ssh exec command and never sends enable or an enable secret.
"""
from __future__ import annotations

import datetime
import hashlib
import json

from netops_admin import eos
from netops_admin.errors import Rejected
from netops_admin.exec_fortios import PromptSpec

TIMER_TOLERANCE_SECONDS = 10
LOG_MINUTES = 60
QUERY_SESSIONS = "show configuration sessions detail | json"
QUERY_CLOCK = "show clock | json"
QUERY_VERSION = "show version"
QUERY_PRIVILEGE = "show privilege"
QUERY_DIFFS = "show running-config diffs"
QUERY_LLDP = "show lldp neighbors"
QUERY_USERS = "show users"
FIRED = ("CONFIG_SESSION_COMMIT_TIMER_TIMEDOUT", "CONFIG_SESSION_COMMIT_REVERTED")
CONFIRMED = "CONFIG_SESSION_COMMIT_TIMER_COMPLETED"
FIRING_OBSERVED = True


def prompt_spec(hostname: str) -> PromptSpec:
    # measured prompts: "d-ceos>", "d-ceos#", "d-ceos(config-if-Et10)#", "d-ceos(config-s-netops-c7-)#"
    return PromptSpec(anchor=("\n%s" % hostname).encode("ascii"), ends=(b"#", b">"), continuation=None,
                      error=eos.cli_error)


def safeguard_label(change_id: str) -> str:
    return eos.SESSION_PREFIX + change_id[:12]


def hostname(access, snapshot_text: str) -> str:
    return eos.load(snapshot_text, None).hostname


def clock(access) -> datetime.datetime:
    data = _json(access.query(QUERY_CLOCK), "clock")
    value = data.get("utcTime")
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise Rejected(["the device does not report its UTC time"])
    return _utc(value)


def _utc(epoch) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).replace(tzinfo=None, microsecond=0)


def _json(text: str, what: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError:
        raise Rejected(["the %s answer is not JSON" % what]) from None
    if not isinstance(data, dict):
        raise Rejected(["the %s answer is not a JSON object" % what])
    return data


ACCOUNT_LINES = ("username ", "enable ", "aaa ", "no aaa ")


def accounts_check(access, device, snapshot_text) -> str:
    snapshot = eos.load(snapshot_text, None)
    present = sorted({line.split()[1] for line in snapshot.lines
                      if line.startswith("username ") and len(line.split()) >= 2})
    if present != sorted(device.accounts):
        raise Rejected(["the switch accounts differ from the expected list (%d present, %d expected)"
                        % (len(present), len(device.accounts))])
    lines = sorted(line for line in snapshot.lines if line.startswith(ACCOUNT_LINES))
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def sessions(access) -> dict:
    data = _json(access.query(QUERY_SESSIONS), "configuration session")
    if not isinstance(data.get("sessions"), dict):
        raise Rejected(["the configuration session list is not readable"])
    return data


def prechecks(access, device, snapshot_text, spec) -> list:
    reasons = []
    level = eos.privilege(access.query(QUERY_PRIVILEGE))
    if level != 15:
        raise Rejected(["the write account logs in with privilege %d; Admin needs privilege 15 at login "
                        "(aaa authorization exec default local and username ... privilege 15) and never sends "
                        "enable" % level], reason_codes=["write_account_privilege"])
    running = eos.image_version(access.query(QUERY_VERSION))
    expected = device.firmware or eos.firmware_of(snapshot_text)
    if running != expected:
        reasons.append("the switch runs %s, not the configured %s" % (running, expected))
    if access.query(QUERY_DIFFS).strip():
        reasons.append("the switch has unsaved configuration changes of someone else (show running-config diffs)")
    data = sessions(access)
    timer = data.get("commitTimerSessionName")
    foreign = sorted(name for name, item in data["sessions"].items()
                     if not name.startswith(eos.SESSION_PREFIX) and (item or {}).get("state") == "pending")
    if timer and not str(timer).startswith(eos.SESSION_PREFIX):
        raise Rejected(["configuration session %s of someone else has a pending commit timer; EOS refuses "
                        "every other commit until it ends" % timer], reason_codes=["foreign_config_session"])
    if foreign:
        raise Rejected(["%d configuration sessions of someone else are open (pending)" % len(foreign)],
                       reason_codes=["foreign_config_session"])
    return reasons


def plan_prechecks(access, device, plan, snapshot_text="") -> list:
    key, table = plan["key"], plan["table"]
    if table not in ("interface", "vlan-membership"):
        return []
    status = eos.status_row(access.query("show interfaces %s status" % key), key)
    if status is None:
        raise Rejected(["the switch does not report interface %s" % key], reason_codes=["port_usage_unreadable"])
    plan["prechecks"].append("interface %s now: %s" % (key, status))
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    if table == "vlan-membership":
        wanted = (after or {}).get("access-vlan", eos.DEFAULT_VLAN)
        if not eos.vlan_exists(access.query("show vlan id %s" % wanted), wanted):
            raise Rejected(["VLAN %s does not exist on the switch; EOS would create it without an error, so the "
                            "change is refused" % wanted], reason_codes=["vlan_missing"])
        shown = eos.switchport(access.query("show interfaces %s switchport" % key), key)
        if shown["mode"] != "static access":
            raise Rejected(["port %s is in %s mode, not static access" % (key, shown["mode"])],
                           reason_codes=["port_uplink"])
        plan["prechecks"].append("VLAN %s exists; port %s is a static access port" % (wanted, key))
    if not eos.disruptive(table, before, after):
        return []
    if eos.short_name(key) in eos.lldp_ports(access.query(QUERY_LLDP)):
        raise Rejected(["port %s has an LLDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    if eos.learned_macs(access.query("show mac address-table interface %s" % key)):
        raise Rejected(["port %s has learned MAC addresses; changing a port in use is refused" % key],
                       reason_codes=["port_learned_mac"])
    plan["prechecks"].append("port %s has no LLDP neighbor and no learned MAC address" % key)
    return []


def ports(access, table: str):
    return None


def leftovers(access) -> list:
    data = sessions(access)
    names = {name for name in data["sessions"] if name.startswith(eos.SESSION_PREFIX)}
    timer = data.get("commitTimerSessionName")
    if timer and str(timer).startswith(eos.SESSION_PREFIX):
        names.add(str(timer))
    return sorted(names)


def _timer(seconds: int) -> str:
    return "%02d:%02d:%02d" % (seconds // 3600, seconds // 60 % 60, seconds % 60)


def install_safeguard(access, record, plan, device, spec) -> list:
    label = safeguard_label(record["change_id"])
    access.apply(["configure session %s" % label, "commit timer %s" % _timer(device.safeguard_seconds)], spec)
    data = sessions(access)
    problems = []
    item = data["sessions"].get(label) or {}
    expire = data.get("commitTimerExpireTime")
    if data.get("commitTimerSessionName") != label or item.get("state") != "committed" \
            or not isinstance(expire, (int, float)):
        problems.append("safeguard session is missing, not committed or has no pending commit timer")
    else:
        planned = datetime.datetime.strptime(record["safeguard"]["fire_at"], "%Y-%m-%d %H:%M:%S")
        scheduled = _utc(expire)
        if abs((scheduled - planned).total_seconds()) > TIMER_TOLERANCE_SECONDS:
            problems.append("safeguard commit timer expires at another time than planned")
        record["safeguard"]["fire_at"] = scheduled.strftime("%Y-%m-%d %H:%M:%S")
    return problems


def _cleanup_lines(data, label) -> list:
    """Lines that end the own safeguard session: confirm a pending timer, abort an uncommitted session, then delete
    the record of the committed session (EOS keeps one completed session)."""
    item = data["sessions"].get(label)
    if data.get("commitTimerSessionName") == label:
        return ["configure session %s commit" % label, "no configure session %s" % label]
    if item is None:
        return []
    if item.get("state") == "pending":
        return ["configure session %s abort" % label]
    return ["no configure session %s" % label]


def remove_safeguard(access, record, spec) -> bool:
    label = safeguard_label(record["change_id"])
    try:
        lines = _cleanup_lines(sessions(access), label)
        if lines:
            access.apply(lines, spec)
    except Exception:
        pass
    return safeguard_absent(access, record)


def safeguard_absent(access, record) -> bool:
    label = safeguard_label(record["change_id"])
    try:
        data = sessions(access)
    except Exception:
        return False
    return label not in data["sessions"] and data.get("commitTimerSessionName") != label


remove_remaining = remove_safeguard


def safeguard_disarmed(access, record) -> bool:
    try:
        data = sessions(access)
    except Exception:
        return False
    return data.get("commitTimerSessionName") != safeguard_label(record["change_id"])


def log_lines(access, label) -> list:
    text = access.query("show logging last %d minutes | include %s" % (LOG_MINUTES, label))
    return [line for line in text.split("\n") if ("session %s " % label) in line + " "]


def safeguard_fired(access, record) -> bool:
    """The timer expired and EOS reverted: the session is gone and the log names the timeout and the revert."""
    if not safeguard_absent(access, record):
        return False
    try:
        lines = log_lines(access, safeguard_label(record["change_id"]))
    except Exception:
        return False
    return all(any(marker in line for line in lines) for marker in FIRED)


def persist(access, spec) -> bool:
    access.apply(["write memory"], spec)
    return True


def observe(access, plan):
    key = plan["key"]
    if plan["table"] == "vlan-membership":
        shown = eos.switchport(access.check_query("show interfaces %s switchport" % key), key)
        return {"access-vlan": shown["access-vlan"]}
    row = eos.description_row(access.check_query("show interfaces %s description" % key), key)
    status = eos.status_row(access.check_query("show interfaces %s status" % key), key)
    if row is None or status is None:
        return None
    state = {"description": row["description"]} if row["description"] else {}
    if status == "disabled":
        state["admin-state"] = "disabled"
    return state


def foreign_sessions(access, device) -> int:
    return eos.users(access.query(QUERY_USERS))[1]
