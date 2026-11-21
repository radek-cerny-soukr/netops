"""Juniper Junos ELS execution adapter (measured on vJunos-switch 26.2R1.7, ref/mereni-c8).

Safeguard first, as execute.py needs it: an empty "commit confirmed N comment \"netops-<id>\"" in configure exclusive
is committed before the change and verified by its row "rollback pending" in show system commit. The change runs line
by line in an interactive session (an ssh exec batch continues after an error and its answer is always status 0):
configure exclusive, an empty candidate, the set and delete lines, show | compare and again "commit confirmed N",
which restarts the timer from the new commit (measured: an expiry then returns the change as well). Admin never sends
commit check, and it never commits the change with a plain commit while the timer is pending, because a plain commit
and commit check both confirm it (measured; commit check leaves no trace at all). The plain commits during the pending
timer end the proven own timer: the confirmation "commit comment \"netops-<id>-ok\"" in configure exclusive, sent
after the readback of the change with at least confirm_margin_seconds left, and the immediate return (started with at
least REVERT_NOW_SECONDS left): the confirmation of the empty safeguard when no change commit exists yet (a snapshot
then checks the state before), otherwise the inverse lines committed with "commit comment \"netops-<id>-revert\"";
the row "rollback pending" must then be gone. An expired timer is an automatic rollback committed as "root via other"
above the change (with the broadcast "Commit was not confirmed; automatic rollback complete"); Admin proves it with
that commit row. The rollback returns the configuration before the NEWEST commit confirmed, not before the first one
(measured in task 378: after an empty safeguard, a change and an inverse each committed with commit confirmed, the
expiry brought the change back); with the empty safeguard first and the change as the only later commit confirmed,
that is the state before the change.

Ownership (review pattern 1 of IOS and NX-OS). Junos gives a pending commit confirmed no owner: every commit of any
session confirms it, also of the same account. A pending row is Admin's own only with proof from its own session:
the own install session answered "commit complete" and right after it the newest commit row (record 0) is the own
comment netops-<id> of the write account with "rollback pending"; Admin records that row (time, user, comment) as the
safeguard and the later own commit confirmed (the change) as its head. A plain commit (the confirmation, the
immediate return) or another own commit is sent only while the newest row is exactly the recorded head above the
recorded safeguard row. In the session itself the answer of "show | compare" carries the banner "# commit confirmed will be
rolled back in N minutes" while any commit confirmed is pending (measured): the safeguard commit is not sent when the
banner is there (someone else's timer appeared after the prechecks; refused, nothing changed), the confirmation and
the immediate return are not sent when it is gone (the own timer ended; a commit during the automatic rollback would
make it fail, measured). A race of seconds between the last read and the commit line stays possible: Junos has no
identity of the owner of the timer.

Time (review pattern 2). Admin never reads the device clock for the safeguard (TIMER_WATCH in execute.py): the timer
counts whole minutes from its commit row, written at the end of the commit, and expired 0-60 s after them (measured),
so it is counted on the monotonic clock of Admin from the moment before the safeguard was requested, shortened by
DRIFT_FRACTION. Before the change session the own timer must still be pending (read now) with at least
SESSION_BUDGET_SECONDS left for the session and its commit and READBACK_BUDGET_SECONDS + confirm_margin_seconds for
what follows the commit; each line up to the change commit is sent only with COMMIT_BUDGET_SECONDS left. The change
commit restarts the timer: its end moves by the device time between the safeguard row and the change row (both on
the device clock), never past the answer of the session (execute._restarted_end).

Immediate return (review pattern 3). A failed write or readback of a normal operation is returned at once while the
own timer is pending with SESSION_BUDGET_SECONDS left (exec_junos.REVERT_NOW_SECONDS): when no own change commit exists
yet, the empty safeguard needs no return and is confirmed; else the inverse set/delete lines of the plan are committed
with the plain "commit comment \"netops-<id>-revert\"", which ends the own timer and keeps the inverse. It is not
committed with commit confirmed: an inverse under a timer is undone by its expiry, which returns the state before the
newest commit confirmed, so an interrupted return (no confirmation after the inverse) brought the change back
(measured in task 378, S1). execute.py then judges the state by a fresh snapshot against the state before (reverted,
revert-failed, or unknown when it is not readable). When the read after the change commit failed, the change row
becomes the head before the return only by a new read (adopt_change_head). Chosen over "rollback N": the inverse was
measured (P3e, undo in the E2E of task 319) and touches only the planned object, while the index of rollback N moves
with every commit (measured: rollback 1 is wrong after a confirmation) and a rollback during a pending timer was not
measured.

Recover (review pattern 4) decides by show system commit only: armed while a rollback is pending at or above the own
safeguard row, ended with "root via other" or the own plain "-revert" row above it and nothing pending, disarmed with
the own "-ok" row above it.

Timing (measured on the lab, where the vJunos runs under load 15-26): a commit takes 15-150 s (a change session took
126-235 s in task 319), the timer counts whole minutes from the commit row and expires 0-60 s after N minutes, the
automatic rollback commit takes another 55-273 s. N is 10 minutes (safeguard_seconds 600, required by the
configuration). A commit is the save on Junos, so persist has nothing to do.

The write account needs the permission configure (and view, view-configuration for the snapshot); the lab uses the
existing super-user account. The check account of class read-only reads the operational state only (it cannot read
the configuration nor the log, measured).
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import re
from time import sleep

from netops_admin import (exec_junos_dhcp, exec_junos_filter, exec_junos_g140, exec_junos_routing, exec_junos_srx, junos,
                          junos_clear, junos_dhcp, junos_g140)
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin.exec_fortios import PromptSpec

QUERY_COMMITS = "show system commit"
QUERY_CLOCK = "show system uptime | display json"
QUERY_VERSION = "show version"
QUERY_AUTHORIZATION = "show cli authorization"
QUERY_USERS = "show system users"
QUERY_LLDP = "show lldp neighbors"
QUERY_DESCRIPTIONS = "show interfaces descriptions"
QUERY_VLANS = "show vlans"
DEDICATED_MANAGEMENT = re.compile(r"(?:fxp0|em0|re0:mgmt-0|vme)(?:\.[0-9]+)?")
SSH_CONNECTIONS = 'show system connections | match "Local Address|ESTABLISHED" | no-more'
DEFAULT_ROUTES = ("show route 0.0.0.0/0 exact", "show route ::/0 exact")
NEEDED_PERMISSIONS = ("configure", "view", "view-configuration")
CONFIRM_MINUTES = junos.CONFIRM_MINUTES
SAFEGUARD_SECONDS = CONFIRM_MINUTES * 60
MIN_CONFIRM_MARGIN_SECONDS = 240
COMMIT_LINE_SECONDS = 420
LINE_SECONDS = 90
# the slack of the wait for the proof of an expiry (execute.py: the longest timer plus grace plus this, 1820 s on the
# monotonic clock of Admin from the start of the wait): 0-60 s of minute granularity (measured 7-9 s in task 319),
# the automatic rollback commit (55-112 s in task 308, 93 and 273 s in task 319) and a change commit of up to about
# 240 s (task 319) that restarted the timer; admin recover after SIGKILL in task 319 saw the proof 530 s after the
# expiry of the safeguard commit. The wait ends as soon as the proof is read.
FIRING_SLACK_SECONDS = 900
FIRING_OBSERVED = True
TIME = "%Y-%m-%d %H:%M:%S"
# the safeguard is watched on the monotonic clock of Admin and by reading show system commit, never by the device
# clock (execute.py: TIMER_WATCH); the expiry the device shows is kept in safeguard.device_expiry for the journal
TIMER_WATCH = True
FIRE_AT_TEXT = "device commit confirmed timer"
# someone else's commit confirmed appeared between the prechecks and the safeguard commit: refused like in the prechecks
REFUSED_REASON_CODE = "foreign_config_session"
# the timer runs on the device clock, whose drift was not measured on vJunos; the allowance of the IOS adapter (1.7 %
# measured on IOSv) is used
DRIFT_FRACTION = 0.02
# the change session up to the end of its commit: 126-235 s in the E2E of task 319 (commits 15-150 s in task 308)
SESSION_BUDGET_SECONDS = 240
# a line up to the change commit is sent only with this much of the timer left (a commit took up to 150 s)
COMMIT_BUDGET_SECONDS = 180
# after the change commit: the timer read, the snapshot, the account check, the check account and the final snapshot
# (63-90 s from the end of the change session to the confirmation in the E2E of task 319, with a device clock read)
READBACK_BUDGET_SECONDS = 90
# the restart of the timer is counted from two commit rows of whole seconds on the device clock
RESTART_SLACK_SECONDS = 15
# the immediate return commits the inverse while the own timer is pending: started only with a whole session left
REVERT_NOW_SECONDS = SESSION_BUDGET_SECONDS
# the inverse is committed with a plain commit, which ends the own timer (an inverse under the timer is undone by its
# expiry, measured in task 378); execute.py judges the state by a fresh snapshot and confirms nothing afterwards
REVERT_NOW_KEEPS_SAFEGUARD = False


def _line_seconds(text: str) -> float:
    return COMMIT_LINE_SECONDS if text.split()[:1] == ["commit"] else LINE_SECONDS


def prompt_spec(hostname: str, others=()) -> PromptSpec:
    """measured prompts: "netops-admin@d-vjunos> " and, in configuration mode, "[edit]" above "netops-admin@d-vjunos# ".

    1.0.12 G145: the anchor is "@<host name>", the part of the prompt after the account. The bare host name was also
    found in the echo of a typed line ("set system host-name <name>"), and the end that follows it was then the "# "
    of the pending commit confirmed banner, not of the prompt. A host-name change shows the new name in the prompt
    right after its commit, in the same session (measured), so the sessions of such a plan accept both names
    (others: the alternative names, plan_hostnames)."""
    return PromptSpec(anchor=b"@" + hostname.encode("ascii"), ends=(b"> ", b"# "), continuation=None,
                      error=junos.cli_error, seconds=_line_seconds,
                      anchors=tuple(b"@" + name.encode("ascii") for name in others if name != hostname))


def plan_hostnames(plan, hostname: str) -> tuple:
    """The other host names the prompt of a session of the plan can show (1.0.12 G145: the old and the new host name
    of a system plan; the timer, the undo and the recovery can meet either)."""
    names = [(state or {}).get("host-name") for step in plan.get("batch_steps", [plan])
             if step.get("table") == junos.SYSTEM_TABLE for state in step["predicted"].values()]
    return tuple(sorted({name for name in names if name and name != hostname}))


def safeguard_label(change_id: str) -> str:
    return junos.SESSION_PREFIX + change_id[:12]


def _confirmation(label: str) -> str:
    return label + "-ok"


def _reverting(label: str) -> str:
    return label + "-revert"


def pending_banner(answer: str) -> bool:
    """The answer of an interactive line carries the banner of a pending commit confirmed (measured after every line
    in configuration mode, of any user, while a commit confirmed of anyone is pending)."""
    return any(junos.BANNER.match(row.strip()) for row in answer.replace("\r", "").split("\n"))


def timer_seconds(device) -> float:
    """How long the own timer protects on the monotonic clock of Admin, counted from the moment before its commit was
    requested: the whole minutes from its commit row, which is written at the end of the commit, less the drift
    allowance of the device clock (the expiry came 0-60 s after the minutes, measured)."""
    return CONFIRM_MINUTES * 60 * (1 - DRIFT_FRACTION)


def hostname(access, snapshot_text: str) -> str:
    name = junos.load(snapshot_text, None).hostname
    if not name:
        raise Rejected(["the configuration does not name the device (set system host-name)"])
    return name


def _read(access, command: str) -> str:
    text = access.query(command)
    refused = junos.refused_answer(text)
    if refused is not None:
        raise Rejected(["the device refused %r: %s" % (command, refused)])
    return text


def clock(access) -> datetime.datetime:
    try:
        data = json.loads(_read(access, QUERY_CLOCK))
        value = data["system-uptime-information"][0]["current-time"][0]["date-time"][0]["attributes"][
            "junos:seconds"]
        epoch = int(value)
    except (ValueError, KeyError, IndexError, TypeError):
        raise Rejected(["the device does not report its UTC time"]) from None
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).replace(tzinfo=None, microsecond=0)


def accounts_check(access, device, snapshot_text) -> str:
    snapshot = junos.load(snapshot_text, None)
    present = sorted({line.split()[4] for line in snapshot.lines
                      if line.startswith("set system login user ") and len(line.split()) >= 5})
    if present != sorted(device.accounts):
        raise Rejected(["the switch accounts differ from the expected list (%d present, %d expected)"
                        % (len(present), len(device.accounts))])
    # names, classes and login classes; the authentication lines (password hashes, keys) are left out
    lines = sorted(line for line in snapshot.lines
                   if line.startswith("set system login ") and " authentication " not in line)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def history(access) -> list:
    return junos.commits(_read(access, QUERY_COMMITS))


def _login(access):
    return getattr(getattr(access, "credential", None), "login", None)


def prechecks(access, device, snapshot_text, spec, *, clearing=False) -> list:
    login, klass, permissions = junos.authorization(_read(access, QUERY_AUTHORIZATION))
    # 1.0.12 G146: a clear needs the clear permission, no configuration mode and no timer of its own
    missing = [name for name in (("clear", "view", "view-configuration") if clearing else NEEDED_PERMISSIONS)
               if name not in permissions]
    if missing:
        raise Rejected(["the write account %s (class %s) lacks the permissions %s"
                        % (login, klass, ", ".join(missing))], reason_codes=["write_account_privilege"])
    running = junos.running_version(_read(access, QUERY_VERSION))
    expected = device.firmware or junos.firmware_of(snapshot_text)
    if running != expected:
        return ["the switch runs Junos %s, not the configured %s" % (running, expected)]
    if clearing:
        return []
    newest = history(access)[0]
    if newest.pending and not (newest.comment or "").startswith(junos.SESSION_PREFIX):
        raise Rejected(["a commit confirmed of someone else is pending; every commit of Admin, even commit check, "
                        "would confirm it"], reason_codes=["foreign_config_session"])
    # the shared configuration mode shows other users in configuration mode and someone else's uncommitted change;
    # it is left again without a change (measured, also with an uncommitted change of someone else)
    try:
        access.apply([junos.SCREEN, "configure", junos.LEAVE], spec)
    except Rejected:
        raise
    except Exception as exc:
        if "was refused by the device" in str(exc):
            raise Rejected(["another user is in configuration mode or the candidate configuration holds an "
                            "uncommitted change (%s)" % str(exc)[-160:]],
                           reason_codes=["foreign_config_session"]) from None
        raise
    return []


def plan_prechecks(access, device, plan, snapshot_text="", *, batch_baseline=None, earlier=()) -> list:
    key, table = plan["key"], plan["table"]
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    if table in junos.G139_TABLES:
        return _l3_plan_prechecks(access, device, plan, snapshot_text)
    if table in junos_g140.TABLES:
        try:
            return _g140_prechecks(access, device, plan, snapshot_text)
        except AccessError as exc:
            raise _g140_read_error(exc) from None
    if table in junos.routing.TABLES:
        return exec_junos_routing.prechecks(access, device, plan, snapshot_text)
    if table in junos.fltr.TABLES:
        return exec_junos_filter.prechecks(access, device, plan, snapshot_text)
    if table in junos.srx.TABLES:
        return exec_junos_srx.prechecks(access, device, plan, snapshot_text)
    if table == "vlan":
        return _vlan_prechecks(access, plan, snapshot_text, batch_baseline, earlier)
    if table not in ("interface", "vlan-membership", *junos.POE_TABLES, junos.BOUNCE_TABLE):
        return []
    row = junos.interface_row(access.query("show interfaces %s terse" % key), key)
    if row is None:
        raise Rejected(["interface %s does not exist on the switch; Junos would accept its configuration without an "
                        "error, so the change is refused" % key], reason_codes=["port_missing"])
    plan["prechecks"].append("interface %s now: admin %s, link %s" % (key, row["admin"], row["link"]))
    if _removes_speed(plan):
        if row["link"] not in ("up", "down"):
            raise junos.unreadable("physical link state")
        plan["link_before"] = row["link"]
    if table == "vlan-membership":
        state = after or {}
        wanted = sorted(set(junos._members(state) + ([state["voice-vlan"]] if state.get("voice-vlan") else [])))
        pending = set()
        if batch_baseline is not None:
            projected = junos.load(snapshot_text, None)
            pending = projected.vlans - batch_baseline.vlans
        for name in wanted:
            if name not in pending and not junos.vlan_exists(access.query("show vlans %s" % name), name):
                raise Rejected(["VLAN %s does not exist on the switch (show vlans %s is empty); the change is refused"
                                % (name, name)], reason_codes=["vlan_missing"])
        native = state.get("native-vlan")
        if (native is not None and not (pending and projected.vlan_name(native) in pending)
                and not junos.vlan_tags(_read(access, QUERY_VLANS)).get(native)):
            raise Rejected(["the native VLAN ID %s is not a VLAN of the switch" % state["native-vlan"]],
                           reason_codes=["vlan_missing"])
        if not junos.switching(access.query("show ethernet-switching interface %s" % key), key):
            raise Rejected(["port %s is not a switching port on the device" % key], reason_codes=["port_not_access"])
        _inheritance_matches(access, key, snapshot_text if batch_baseline is None else "\n".join(batch_baseline.lines) + "\n")
        plan["prechecks"].append("VLAN %s exists; port %s is an access port" % (wanted[0], key)
                                 if state.get("mode", "access") == "access" and len(wanted) == 1
                                 else "VLANs %s exist; port %s is a switching port" % (", ".join(wanted), key))
    if table in junos.POE_TABLES:
        _poe_capability(access, plan, key)
    if not junos.disruptive(table, before, after):
        return []
    return _port_in_use(access, device, plan, key, snapshot_text)


def batch_read_error(exc):
    return _g140_read_error(exc)


def _batch_live_impact(access, plan, baseline, projected):
    table, key = plan["table"], plan["key"]
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    if table in ("interface", "vlan-membership", junos.POE_TABLE, junos.IRB_TABLE, junos.VRRP_TABLE,
                 junos_g140.LAG, junos_g140.RSTP_PORT):
        interface = key.partition(":")[0]
        if ((table in (junos.IRB_TABLE, junos.VRRP_TABLE) and interface not in baseline.entries(junos.IRB_TABLE))
                or (table == junos_g140.LAG and interface not in baseline.entries(table))):
            return False
        text = _read(access, "show interfaces %s terse" % interface)
        row = junos.interface_row(text, interface)
        if row is None:
            raise junos.unreadable("Junos batch interface status")
        if row["admin"] not in ("up", "down") or row["link"] not in ("up", "down"):
            raise junos.unreadable("Junos batch interface status")
        return row["admin"] == row["link"] == "up" and (
            table != "interface" or junos.disruptive(table, before, after))
    if table in (junos.NTP_TABLE, junos.SYSLOG_TABLE):
        return after is None and len(projected.entries(table)) == 1
    if table == junos.SYSTEM_TABLE:
        return bool(before.get("name-servers") and not after.get("name-servers"))
    return False


def batch_step_for_read(plan, snapshot, side):
    from netops_admin import engine
    from netops_admin.profiles import find_profile

    table, key = plan["table"], plan["key"]
    profile = find_profile("junos", table, snapshot.firmware)
    entry = engine._find_entry(snapshot.entries(table), key)
    state, unsupported = (({} if profile.implicit_keys else None), []) if entry is None else engine._entry_state(
        snapshot, profile, entry)
    if unsupported:
        raise junos.unreadable("Junos batch object state")
    states = {**plan["predicted"], side: state}
    if table == junos.IRB_TABLE:
        # An earlier creation or a later deletion can make a referenced VLAN absent on this side.
        states = {name: {field: value for field, value in values.items()
                         if field != "vlan" or value in snapshot.vlans} if values is not None else None
                  for name, values in states.items()}
    return dict(plan, predicted=states)


def batch_prechecks(access, device, plan, snapshot_text, earlier, *, undo=False, baseline_text):
    from netops_admin import engine

    baseline = junos.load(baseline_text, None)
    try:
        if _batch_live_impact(access, plan, baseline, junos.load(snapshot_text, None)) and \
                plan.get("endpoint_impact") != plan["key"]:
            raise Rejected(["the active target %s requires endpoint_impact" % plan["key"]],
                           reason_codes=["endpoint_impact_required"])
        reasons = plan_prechecks(access, device, plan, snapshot_text, batch_baseline=baseline if earlier else None,
                                 earlier=earlier)
        if reasons:
            raise Rejected(reasons)
        current = batch_step_for_read(plan, baseline, "before")
        observed = engine.observed_state(current, observe(access, current, side="before"))
        if observed != engine.check_view(current, current["predicted"]["before"]):
            raise junos.unreadable("agreement between the check account and the Junos batch starting state")
    except AccessError as exc:
        raise batch_read_error(exc) from None


def _g140_read_error(exc):
    if re.search(r"timed? out|timeout", str(exc), re.IGNORECASE):
        return Rejected(["Junos link preflight did not answer within the read timeout"],
                        reason_codes=["junos_link_read_timeout"])
    return junos.unreadable("Junos link preflight")


def _g140_prechecks(access, device, plan, snapshot_text):
    table, key = plan["table"], plan["key"]
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    snapshot = junos.load(snapshot_text, None)
    ports = junos_g140.affected_ports(snapshot, table, key, before, after)
    if table == junos_g140.LAG and before is not None and not before.get("empty-aggregate"):
        ports.add(key)
        seen = exec_junos_g140.lacp(access.check_query("show lacp interfaces %s" % key), key)
        carrying = any("collecting" in mux or "distributing" in mux for _mode, mux in seen.values())
        if carrying and plan.get("endpoint_impact") != key:
            raise Rejected(["aggregate %s carries live LACP traffic; acknowledge endpoint_impact" % key],
                           reason_codes=["port_learned_mac"])
    if not ports:
        return []
    terse = _read(access, "show interfaces terse")
    up = junos.physical_up(terse)
    if up and set(up) <= ports:
        raise Rejected(["the operation would affect all active physical paths"],
                       reason_codes=["port_management_interface"])
    if table == junos_g140.LAG and before is None and after.get("switching") and _carries_management_vlan(
            access, device, snapshot, key, [junos.SWITCHING], terse, configured_only=True):
        raise Rejected(["the new aggregate would carry the default VLAN used by management"],
                       reason_codes=["port_management_interface"])
    for port in sorted(ports):
        if junos.interface_row(terse, port) is None:
            raise Rejected(["interface %s does not exist on the switch" % port], reason_codes=["port_missing"])
        # A consent naming the aggregate covers its members. Global BPDU protection never overrides port protections.
        _port_in_use(access, device, plan, port, snapshot_text,
                     impact=plan.get("endpoint_impact") == key and table != junos_g140.RSTP)
    return []


def _poe_capability(access, plan, key):
    """1.0.12 G138 (J09, J10): the port has a PoE controller (show poe interface answers its block; vJunos answers only
    a warning) and, for the cycle, the power is on before; a port with PoE disabled in the configuration cannot be
    cycled (the engine refuses it before)."""
    state = junos.poe_state(_read(access, "show poe interface %s" % key), key)
    if state is None:
        raise Rejected(["port %s has no PoE controller (show poe interface %s names no PoE port)" % (key, key)],
                       reason_codes=["poe_not_capable"])
    plan["prechecks"].append("port %s PoE now: %s, %s" % (key, state["configured"], state["state"]))
    if plan["table"] == junos.POE_CYCLE_TABLE:
        if state["state"] != "powered":
            raise Rejected(["port %s does not power a device now (%s); a PoE cycle needs a powered port"
                            % (key, state["state"])], reason_codes=["poe_device_not_powered"])
        plan.setdefault("cycle_state", {})["poe"] = state["state"]


def _port_in_use(access, device, plan, key, snapshot_text, *, impact=None):
    """Endpoint consent covers learned MAC addresses, while uplinks and potential management paths stay protected."""
    table = plan["table"]
    if impact is None:
        impact = plan.get("endpoint_impact") == key
    guarded = table != "vlan-membership"
    try:
        lldp = key in junos.lldp_ports(_read(access, QUERY_LLDP))
        macs = junos.learned_macs(_read(access, "show ethernet-switching table interface %s" % key), key)
        terse = _read(access, "show interfaces terse")
        up = junos.physical_up(terse)
        if junos.interface_row(terse, key) is None:
            raise junos.unreadable("interface list")
    except Exception as exc:
        if table in junos_g140.TABLES and isinstance(exc, AccessError):
            raise _g140_read_error(exc) from None
        raise Rejected(["the LLDP neighbors, the MAC table or the interface list of the switch cannot be read"],
                       reason_codes=["port_usage_unreadable"]) from None
    if table in junos.CYCLE_TABLES:
        plan["cycle_state"] = dict(plan.get("cycle_state", {}), link="up" if key in up else "down",
                                   lldp=str(lldp), learned_macs=str(macs))
    if guarded:
        snapshot = junos.load(snapshot_text, None)
        sources, unsupported = snapshot.sources(key)
        if unsupported:
            raise junos.unreadable("interface configuration inheritance")
        lines = [line for source in sources for line in source.lines]
        if any(junos.TRUNK.match(line) for line in lines):
            raise Rejected(["port %s is a trunk and is protected as an uplink" % key], reason_codes=["port_uplink"])
        if up == [key]:
            raise Rejected(["port %s is the only port with a link up and may carry the management path" % key],
                           reason_codes=["port_management_interface"])
    if lldp and (guarded or not impact):
        raise Rejected(["port %s has an LLDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    if guarded and _carries_management_vlan(access, device, snapshot, key, lines, terse):
        raise Rejected(["port %s carries a VLAN whose IRB carries or may carry the management path" % key],
                       reason_codes=["port_management_interface"])
    if macs and not impact:
        raise Rejected(["port %s has learned MAC addresses; changing a port in use is refused" % key],
                       reason_codes=["port_learned_mac"])
    plan["prechecks"].append(("endpoint impact explicitly accepted on %s (MACs %d, LLDP neighbor: %s); "
                              "traffic, phone or AP connectivity may be interrupted"
                              % (key, macs, "present" if lldp else "absent"))
                             if impact else "port %s has no LLDP neighbor and no learned MAC address" % key)
    return []


def _carries_management_vlan(access, device, snapshot, key, lines, terse, *, configured_only=False):
    bindings = {}
    for line in snapshot.lines:
        if not junos.IRB_BINDING.fullmatch(line):
            continue
        match = junos.IRB_VLAN.fullmatch(line)
        if match is None:
            raise junos.unreadable("VLAN bindings to IRB interfaces")
        bindings.setdefault(match[1], set()).add(line.split()[-1])
    if not bindings:
        return False
    members = set()
    for line in lines:
        if line.startswith((junos.MEMBERS + " ", junos.NATIVE + " ")):
            members.add(line.split()[-1])
    if not members and any(line.startswith(junos.SWITCHING) for line in lines):
        members.add(junos.DEFAULT_VLAN)
    members.update(snapshot.voip.get(key, []))
    carried = {name for name in bindings if members & {name, "all"} or any(
        rest.startswith("vlan-id ") and rest.split()[1] in members for rest in snapshot.vlan_lines.get(name, []))}
    try:
        if not configured_only and carried != bindings.keys():
            observed = junos.switching(_read(access, "show ethernet-switching interface %s" % key), key)
            carried.update(name for name, _tagging in observed or [] if name in bindings)
    except Exception:
        raise Rejected(["the VLAN membership of port %s cannot be read to rule out a management path" % key],
                       reason_codes=["port_usage_unreadable"]) from None
    return bool(carried) and _uses_management_irb(
        access, device, snapshot, terse, set().union(*(bindings[name] for name in carried)))


def _local_ip(value):
    try:
        return ipaddress.ip_address(value.split("%", 1)[0].split("/", 1)[0])
    except ValueError:
        return None


def _interface_addresses(terse):
    # Junos omits the interface and protocol columns on continuation rows for multiple local addresses.
    local = {}
    interface = None
    family = None
    for row in junos.answer_rows(terse)[1:]:
        fields = row.split()
        if row[0].isspace():
            if fields[0] in ("inet", "inet6"):
                family = fields.pop(0)
            elif not fields or _local_ip(fields[0]) is None:
                family = None
        else:
            interface, _, _, *fields = fields
            family = fields.pop(0) if fields else None
        if interface and family in ("inet", "inet6") and fields:
            address = _local_ip(fields[0])
            if address is not None:
                local.setdefault(address, set()).add(interface)
    return local


def _ssh_connections(text, port):
    # During the query there is at least one established socket for the SSH command itself.
    rows = junos.answer_rows(text)
    if not rows or "Local Address" not in rows[0] or "---(more" in text.lower():
        raise ValueError("unreadable SSH connections")
    sockets = set()
    for row in rows:
        fields = row.split()
        if fields[:2] == ["Proto", "Recv-Q"]:
            continue
        if len(fields) != 6:
            raise ValueError("unreadable SSH socket")
        protocol, _, _, local, peer, state = fields
        if protocol in ("tcp4", "tcp6", "tcp") and state == "ESTABLISHED" and local.endswith("." + port):
            addresses = (_local_ip(local.rsplit(".", 1)[0]), _local_ip(peer.rsplit(".", 1)[0]))
            if None in addresses:
                raise ValueError("unreadable SSH addresses")
            sockets.add(addresses)
    return sockets


def _route_interfaces(text):
    routes, = json.loads(text)["route-information"]
    return {interface["data"] for table in routes.get("route-table", []) for route in table["rt"]
            for entry in route["rt-entry"] for hop in entry.get("nh", []) for interface in hop.get("via", [])}


def _uses_management_irb(access, device, snapshot, terse, irbs, *, report_errors=False):
    try:
        if "---(more" in terse.lower():
            return True
        local = _interface_addresses(terse)
        targets = {device.address, device.check_address or device.address}
        # All local addresses of either SSH target must belong to dedicated interfaces.
        def dedicated(address):
            interfaces = local.get(address, set())
            return bool(interfaces) and all(DEDICATED_MANAGEMENT.fullmatch(name) for name in interfaces)

        if any(local.get(_local_ip(target)) and not dedicated(_local_ip(target)) for target in targets):
            return True
        ports = {line.split()[-1] for line in snapshot.lines
                 if re.fullmatch(r"set system services ssh port [0-9]+", line)}
        if len(ports) > 1:
            return True
        port = next(iter(ports), "22")
        sockets = _ssh_connections(_read(access, SSH_CONNECTIONS), port)
        if any(not dedicated(_local_ip(target)) for target in targets):
            # A translated address or a hostname can be identified from the connections made through each target.
            if not sockets or any(not dedicated(address) for address, _peer in sockets):
                return True
            if device.check_address and device.check_address != device.address and not dedicated(
                    _local_ip(device.check_address)):
                checked = _ssh_connections(access.check_query(SSH_CONNECTIONS), port)
                if not checked or any(not dedicated(address) for address, _peer in checked):
                    return True
                sockets.update(checked)
        commands = list(DEFAULT_ROUTES)
        if any(line == "set system management-instance" or line.startswith("set routing-instances mgmt_junos ")
               for line in snapshot.lines):
            commands.append("show route table mgmt_junos")
        commands.extend("show route %s" % peer for peer in sorted({peer for _address, peer in sockets}, key=str))
        return any(irbs & _route_interfaces(_read(access, command + " | display json")) for command in commands)
    except Exception:
        if report_errors:
            raise
        # Incomplete management evidence leaves the port protected.
        return True


def _inheritance_matches(access, key, snapshot_text):
    """1.0.12 G137 JP12: when a VLAN statement of the port is inherited (interface-range or group), the VLAN
    statements of the device's own view (display inheritance) must equal the evaluation of Admin; otherwise the
    change is refused, nothing is assumed."""
    if not snapshot_text:
        return
    snapshot = junos.load(snapshot_text, None)
    found, _unsupported = snapshot.sources(key)
    if all(source.kind == "interface" for source in found):
        return
    patterns = junos.CATEGORIES["vlan-membership"].values()
    expected = sorted("set interfaces %s %s" % (key, rest) for rest in snapshot.effective(key)
                      if any(pattern.match(rest) for pattern in patterns))
    text = _read(access, "show configuration interfaces %s | display inheritance | display set" % key)
    prefix = "set interfaces %s " % key
    seen = sorted(row for row in junos.answer_rows(text) if row.startswith(prefix)
                  and any(pattern.match(row[len(prefix):]) for pattern in patterns))
    if seen != expected:
        raise Rejected(["the inherited VLAN statements of %s on the device (display inheritance) differ from the "
                        "evaluation of Admin; the change is refused" % key])


def _vlan_prechecks(access, plan, snapshot_text="", batch_baseline=None, earlier=()) -> list:
    key, op = plan["key"], plan["op"]
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    tags = junos.vlan_tags(_read(access, QUERY_VLANS))
    live_name = (before or {}).get("name")
    if batch_baseline is not None:
        baseline_name = batch_baseline.vlan_name(key)
        if tags.get(key) != baseline_name:
            raise junos.unreadable("Junos VLAN baseline")
        projected = junos.load(snapshot_text, None)
        if projected.vlan_name(key) != baseline_name:
            live_name = baseline_name
    if op == "create":
        if key in tags or after["name"] in tags.values():
            raise Rejected(["VLAN ID %s or name %s already exists on the switch" % (key, after["name"])])
        plan["prechecks"].append("VLAN ID %s and name %s are free on the switch" % (key, after["name"]))
        return []
    if tags.get(key) != live_name:
        raise Rejected(["the switch shows VLAN ID %s as %s, not %s" % (key, tags.get(key), live_name)])
    if after is not None and after["name"] != live_name and after["name"] in tags.values():
        raise Rejected(["VLAN name %s already exists on the switch" % after["name"]])
    if op == "delete" and live_name is not None:
        detail = junos.vlan_detail(_read(access, "show vlans %s extensive" % live_name), live_name)
        vacated = {step["key"] + ".0" for step in earlier if step["table"] == "vlan-membership"
                   and live_name in junos._members(step["predicted"]["before"] or {})
                   and live_name not in junos._members(step["predicted"]["after"] or {})}
        if set(detail["interfaces"]) - vacated or detail["macs"]:
            raise Rejected(["VLAN %s has %d ports and %d learned MAC addresses on the switch; the delete is refused"
                            % (before["name"], len(detail["interfaces"]), detail["macs"])],
                           reason_codes=["port_learned_mac"] if detail["macs"] else None)
        plan["prechecks"].append("VLAN %s has no remaining port or learned MAC address" % live_name)
    return []


def ports(access, table: str):
    return None


def leftovers(access) -> list:
    return sorted({commit.comment for commit in history(access)
                   if commit.pending and (commit.comment or "").startswith(junos.SESSION_PREFIX)})


def _label_index(commits, label):
    return next((commit.index for commit in commits if commit.comment == label), None)


def _at(text: str) -> datetime.datetime:
    return datetime.datetime.strptime(text, TIME)


def _expiry(commit) -> str:
    return (_at(commit.at) + datetime.timedelta(minutes=commit.minutes)).strftime(TIME)


def _row(commit) -> dict:
    return {"at": commit.at, "user": commit.user, "comment": commit.comment}


def _same(commit, row) -> bool:
    return isinstance(row, dict) and (commit.at, commit.user, commit.comment) == (
        row.get("at"), row.get("user"), row.get("comment"))


class _Banner(Exception):
    pass


def _session(access, lines, spec, banner_wanted):
    """One interactive session; the answer of its line 3 (show | compare of the empty candidate) must carry the banner
    of a pending commit confirmed (banner_wanted True) or must not (False), else the session ends before the commit
    line is sent (_Banner)."""
    def answered(number, answer):
        if number == 3 and pending_banner(answer) is not banner_wanted:
            raise _Banner("a commit confirmed is pending" if not banner_wanted else "no commit confirmed is pending")

    access.line_answered = answered
    try:
        access.apply(lines, spec)
    finally:
        access.line_answered = None


def install_safeguard(access, record, plan, device, spec) -> list:
    """Commit the empty safeguard and prove that it is the own one: the own session answered "commit complete" (else
    apply raises) and right after it the newest row (record 0) is netops-<id> of the write account, a pending commit
    confirmed of CONFIRM_MINUTES. Only then safeguard.verified is set and the row is recorded as the safeguard and the
    head. When the empty candidate already shows the banner of a pending commit confirmed (someone else's, it appeared
    after the prechecks), the commit is not sent: install "refused", nothing changed."""
    label = safeguard_label(record["change_id"])
    item = record["safeguard"]
    item["minutes"] = CONFIRM_MINUTES
    try:
        _session(access, [junos.SCREEN, junos.ENTER, junos.COMPARE_EMPTY,
                          'commit confirmed %d comment "%s"' % (CONFIRM_MINUTES, label), junos.LEAVE], spec, False)
    except _Banner:
        item["install"] = "refused"
        return ["a commit confirmed of someone else is pending in the session of the safeguard; every commit of Admin "
                "would confirm it, so nothing was committed"]
    return _record_safeguard(access, item, label)


def _record_safeguard(access, item, label):
    newest = history(access)[0]
    login = _login(access)
    if not (newest.comment == label and newest.pending and newest.confirmed and newest.minutes == CONFIRM_MINUTES
            and (login is None or newest.user == login)):
        return ["the safeguard commit is missing or its rollback is not pending"]
    item["commit"] = _row(newest)
    item["head"] = _row(newest)
    item["device_expiry"] = _expiry(newest)
    item["verified"] = True
    return []


def apply_batch(access, record, plan, spec, begin_step, now):
    """Write one exclusive candidate and arm its own commit-confirmed timer."""
    from netops_admin import engine

    item = record["safeguard"]
    item["minutes"] = CONFIRM_MINUTES
    label = safeguard_label(record["change_id"])
    lines = list(plan["commands"])
    lines[-2] = 'commit confirmed %d comment "%s"' % (CONFIRM_MINUTES, label)
    start_step = {}
    position = 3
    for index, step in enumerate(plan["batch_steps"], 1):
        start_step[position] = index
        position += len(junos.batch_edits(step["commands"]))
    requested, committed, failed_index = None, False, None

    def answered(number, answer):
        nonlocal requested, committed, failed_index
        echo, body = junos._body(answer)
        if number in (3, len(lines) - 2) and pending_banner(answer):
            raise _Banner("a commit confirmed is already pending")
        if number == 3:
            if echo != junos.BATCH_BASELINE or engine.verify(
                    plan, ("\n".join(body) + "\n").encode(), "before")["result"] != "match":
                raise Rejected(["the exclusive candidate differs from the approved starting configuration"],
                               reason_codes=["plan_changed"])
        if number in start_step:
            failed_index = start_step[number]
            begin_step(failed_index)
        if number == len(lines) - 2:
            if echo != junos.BATCH_COMPARE or not any(row.startswith(("+", "-")) for row in body) \
                    or any("(more" in row.lower() for row in body):
                raise Rejected(["the candidate comparison is empty or incomplete"])
            failed_index = None
            requested = now()
        if number == len(lines) - 1:
            committed = True

    access.line_answered = answered
    try:
        access.apply(lines, spec)
    except (AccessError, Rejected, _Banner) as exc:
        if not committed:
            # A lost or ambiguous commit reply leaves the device timer alone for recovery.
            if requested is not None:
                return ["the Junos batch commit was not proven"], requested, failed_index
            if isinstance(exc, _Banner):
                item["install"] = "refused"
                return ["a foreign commit confirmed is pending"], requested, failed_index
            if not failed_index and isinstance(exc, Rejected) and exc.reason_codes == ["plan_changed"]:
                item["install"] = "refused"
                item["refused_code"] = "plan_changed"
                return ["the exclusive candidate differs from the approved state"], requested, failed_index
            if not history(access)[0].pending and engine.verify(
                    plan, access.snapshot().encode(), "before")["result"] == "match":
                item["install"] = "candidate-discarded"
                return ["the Junos candidate was discarded"], requested, failed_index
            return ["the Junos candidate return could not be verified"], requested, failed_index
    finally:
        access.line_answered = None
        access.last_answers = ()
    if not committed:
        return ["the Junos batch commit was not proven"], requested, failed_index
    return _record_safeguard(access, item, label), requested, failed_index


def _owned(commits, record) -> bool:
    """The pending timer is the own one: the installation was proven (safeguard.verified), the newest row is the
    recorded head (the last own commit confirmed) with its rollback pending, and the recorded safeguard row is still
    in the history. The same account, the prefix netops- or the comment alone are never enough."""
    item = record.get("safeguard") or {}
    if item.get("verified") is not True or not commits:
        return False
    newest = commits[0]
    if not (newest.pending and newest.confirmed and newest.minutes == CONFIRM_MINUTES and _same(newest, item.get("head"))):
        return False
    index = _label_index(commits, safeguard_label(record["change_id"]))
    return index is not None and _same(commits[index], item.get("commit"))


def safeguard_rearmed(access, record) -> list:
    """After the change commit: its own commit confirmed restarted the timer. The newest row must be the change commit
    of the write account, pending, right above the own safeguard row, which was the head; it becomes the head, and
    the device time between the two rows (shortened for the drift) moves the end of the timer (execute.py)."""
    label = safeguard_label(record["change_id"])
    item = record["safeguard"]
    commits = history(access)
    newest = commits[0]
    login = _login(access)
    if not (newest.comment == junos.CHANGE_COMMENT and newest.pending and newest.minutes == CONFIRM_MINUTES
            and (login is None or newest.user == login)):
        return ["the change commit is not a pending commit confirmed of Admin"]
    item["device_expiry"] = _expiry(newest)
    if _label_index(commits, label) != 1 or not _same(commits[1], item.get("head")) \
            or not _same(commits[1], item.get("commit")):
        return ["another commit lies between the safeguard and the change"]
    item["head"] = _row(newest)
    moved = (_at(newest.at) - _at(commits[1].at)).total_seconds()
    item["restart_offset_seconds"] = max(0.0, moved - 1) * (1 - DRIFT_FRACTION)
    return []


def adopt_change_head(access, record) -> bool:
    """Before an immediate return (execute.py, read within the time left above REVERT_NOW_SECONDS): the change commit
    of this operation is taken as the head also when safeguard_rearmed could not record it (its read failed once, or
    the connection failed at the exit after the commit). Only while the recorded head is still the proven safeguard
    row, and only when show system commit, read again now, has exactly one row above that row: the change comment of
    this operation (the commit line of its plan) of the write account, a pending commit confirmed of CONFIRM_MINUTES.
    Anything else (a foreign commit, more rows, none) adopts nothing: the immediate return then refuses (_owned) and
    the timer returns the change. True when the head was adopted."""
    item = record.get("safeguard") or {}
    if "batch_snapshots" in record["plan"]:
        return False
    if item.get("verified") is not True or not _same_row(item.get("head"), item.get("commit")):
        return False
    planned = [line for line in record["plan"]["commands"] if _commit_line(line)]
    commits = history(access)
    if len(planned) != 1 or len(commits) < 2:
        return False
    newest, login = commits[0], _login(access)
    if not (planned[0] == 'commit confirmed %d comment "%s"' % (CONFIRM_MINUTES, newest.comment)
            and newest.comment == junos.CHANGE_COMMENT and newest.pending and newest.confirmed
            and newest.minutes == CONFIRM_MINUTES and (login is None or newest.user == login)):
        return False
    if _label_index(commits, safeguard_label(record["change_id"])) != 1 or not _same(commits[1], item.get("commit")):
        return False
    item["head"] = _row(newest)
    item["device_expiry"] = _expiry(newest)
    return True


def _same_row(one, other) -> bool:
    return isinstance(one, dict) and isinstance(other, dict) and all(
        one.get(name) == other.get(name) for name in ("at", "user", "comment"))


def before_write(access, record, left, device):
    """None when the change may be written: the own timer is still pending (read now) and, on the monotonic clock of
    Admin, enough of it is left for the change session with its commit and, since the change commit restarts the
    timer with the same uncertainty of its start, for the readback and the confirmation margin; else the reason."""
    needed = max(SESSION_BUDGET_SECONDS, READBACK_BUDGET_SECONDS + device.confirm_margin_seconds + RESTART_SLACK_SECONDS)
    if left < needed:
        return "%d s of the safeguard left, %d s needed to write, read back and confirm" % (max(left, 0), needed)
    try:
        commits = history(access)
    except Exception as exc:
        return "the commit history is not readable (%s)" % type(exc).__name__
    if not _owned(commits, record):
        return "the own commit confirmed is no longer pending"
    return None


def _commit_line(step) -> bool:
    return isinstance(step, str) and step.split()[:2] == ["commit", "confirmed"]


def line_guard_for(steps, left):
    """The guard of the change session (access.line_guard): every line up to the change commit is sent only with
    COMMIT_BUDGET_SECONDS of the own timer left; the change commit restarts the timer, so the lines after it are
    always sent (leaving the configuration mode)."""
    position = iter(list(steps))
    restarted = []

    def allowed() -> bool:
        step = next(position, None)
        if restarted:
            return True
        if left() < COMMIT_BUDGET_SECONDS:
            return False
        if _commit_line(step):
            restarted.append(True)
        return True

    return allowed


def line_allowed(left) -> bool:
    return left >= COMMIT_BUDGET_SECONDS


def _pending(commits, label) -> bool:
    index = _label_index(commits, label)
    return index is not None and any(commit.pending for commit in commits[:index + 1])


def _own_plain(commit, comment, login) -> bool:
    """A plain (not commit confirmed) commit of the write account with the given own comment."""
    return commit.comment == comment and not commit.confirmed and not commit.pending and (
        login is None or commit.user == login)


def _settled(commits, label, login) -> bool:
    """No rollback is pending and the end of the own timer is proven above the own safeguard row: the own
    confirmation (netops-<id>-ok of the write account), the own immediate return (the plain netops-<id>-revert of the
    write account) or the automatic rollback (root via other). A timer that ended without any of them (an automatic
    rollback still running, or a commit of someone else that confirmed it) is not settled."""
    if commits[0].pending:
        return False
    index = _label_index(commits, label)
    if index is None:
        return False
    above = commits[:index]
    return (any(commit.comment == _confirmation(label) and (login is None or commit.user == login) for commit in above)
            or any(_own_plain(commit, _reverting(label), login) for commit in above)
            or any((commit.user, commit.via) == ("root", "other") for commit in above))


def remove_safeguard(access, record, spec) -> bool:
    """Confirm the own pending timer. A pending timer that is not proven the own one is never confirmed (False); the
    confirmation is sent only while the empty candidate still shows the banner of the pending timer (a plain commit
    during the automatic rollback would make it fail, measured). True only when the end of the own timer is proven
    (_settled), so a timer that ended unconfirmed is never taken for a confirmation."""
    label = safeguard_label(record["change_id"])
    login = _login(access)
    try:
        commits = history(access)
        if not commits[0].pending:
            return _settled(commits, label, login)
        if not _owned(commits, record):
            return False
        _session(access, [junos.SCREEN, junos.ENTER, junos.COMPARE_EMPTY, 'commit comment "%s"' % _confirmation(label),
                          junos.LEAVE], spec, True)
    except Exception:
        pass
    try:
        return _settled(history(access), label, login)
    except Exception:
        return False


def remove_remaining(access, record, spec) -> bool:
    """recover: the own pending timer is confirmed only with proof of the own installation (remove_safeguard);
    without it nothing is sent and the safeguard counts as removed only when no rollback is pending at all."""
    if (record.get("safeguard") or {}).get("verified") is True:
        return remove_safeguard(access, record, spec)
    try:
        return not history(access)[0].pending
    except Exception:
        return False


def safeguard_absent(access, record) -> bool:
    """Nothing of the own timer can still change the configuration: the own safeguard row is not in the history (the
    installation never committed), or its end is proven (_settled). A rollback pending at or above it, or a timer
    that ended without proof (an automatic rollback may still run), is present."""
    label = safeguard_label(record["change_id"])
    try:
        commits = history(access)
        if _label_index(commits, label) is None:
            return not commits[0].pending
        return _settled(commits, label, _login(access))
    except Exception:
        return False


def revert_now(access, record, spec) -> bool:
    """Return a failed change at once while the own timer is pending (execute.py sends it only with
    REVERT_NOW_SECONDS left).

    Only while the own timer is pending (_owned). When the head is still the empty safeguard itself, no change commit
    exists and the configuration is the one of the empty safeguard: the return is its confirmation (execute.py then
    proves the state before by a fresh snapshot). Else the inverse lines of the plan are committed with the plain
    "commit comment netops-<id>-revert" (the empty candidate must still show the banner of the pending timer), which
    ends the own timer and keeps the inverse: the timer must not stay pending over the inverse, because its expiry
    returns the state before the newest commit confirmed and an inverse committed with commit confirmed then brings
    the change back (measured in task 378). The new row must be that plain own row right above the head with no
    rollback pending; it becomes the head. True when the return is committed, False otherwise (then execute.py waits
    for the end of the timer: its expiry, or the own -revert row when the commit went through unseen)."""
    item = record.get("safeguard") or {}
    label = safeguard_label(record["change_id"])
    try:
        commits = history(access)
        if not _owned(commits, record):
            return False
        batch = "batch_snapshots" in record["plan"]
        if not batch and _same(commits[0], item.get("commit")):
            # no own change commit exists: the configuration is the one of the empty safeguard (the state before),
            # so the return is its confirmation; when that cannot be proven the timer returns it
            return remove_safeguard(access, record, spec)
        change = 'commit comment "%s"' % _reverting(label)
        lines = [change if _commit_line(line) else line for line in record["plan"]["inverse"]]
        if batch:
            lines[2] = junos.COMPARE_EMPTY
        if lines.count(change) != 1 or lines[:3] != [junos.SCREEN, junos.ENTER, junos.COMPARE_EMPTY]:
            return False
        try:
            _session(access, lines, spec, True)
        except Exception:
            pass
        commits = history(access)
    except Exception:
        return False
    newest, login = commits[0], _login(access)
    if not (_own_plain(newest, _reverting(label), login) and len(commits) > 1 and _same(commits[1], item.get("head"))):
        return False
    item["head"] = _row(newest)
    return True


def safeguard_disarmed(access, record) -> bool:
    label = safeguard_label(record["change_id"])
    try:
        commits = history(access)
    except Exception:
        return False
    index = _label_index(commits, label)
    if index is None or _pending(commits, label):
        return False
    above = commits[:index]
    return (any(commit.comment == _confirmation(label) for commit in above)
            and not any((commit.user, commit.via) == ("root", "other") for commit in above))


def safeguard_fired(access, record) -> bool:
    """The own timer ended without a confirmation: no rollback is pending and above the safeguard the automatic
    rollback is committed as "root via other" (measured; a confirmation that wins the race leaves no such row), or the
    own plain -revert row of an immediate return that went through although its answer was not seen (it ended the
    timer, so no expiry follows; the fresh snapshot of execute.py then judges the state). Decided by show system
    commit only, never by the device clock; unreadable is not fired (execute.py keeps reading until its wait limit on
    the monotonic clock of Admin)."""
    label = safeguard_label(record["change_id"])
    try:
        commits = history(access)
    except Exception:
        return False
    index = _label_index(commits, label)
    if index is None or _pending(commits, label):
        return False
    login = _login(access)
    return any((commit.user, commit.via) == ("root", "other") or _own_plain(commit, _reverting(label), login)
               for commit in commits[:index])


def persist(access, spec) -> bool:
    # a Junos commit is the saved configuration; nothing is left to save
    return False


def _removes_speed(plan):
    if plan["table"] != "interface":
        return False
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    return "speed" in before and "speed" not in after


def observe(access, plan, *, operational=False, side=None):
    key = plan["key"]
    if plan["table"] in junos.G139_TABLES:
        try:
            return _observe_l3(access, plan, operational=operational)
        except (AccessError, TimeoutError) as exc:
            _l3_read_failure(exc)
        except (IndexError, KeyError, StopIteration, TypeError, ValueError) as exc:
            _l3_read_failure(exc)
    if plan["table"] in junos_g140.TABLES:
        try:
            return exec_junos_g140.observe(access, plan, side or ("after" if operational else "before"))
        except AccessError as exc:
            raise _g140_read_error(exc) from None
    if plan["table"] in junos.routing.TABLES:
        return exec_junos_routing.observe(access, plan, operational)
    if plan["table"] in junos.fltr.TABLES:
        return exec_junos_filter.observe(access, plan, operational)
    if plan["table"] in junos.srx.TABLES:
        return exec_junos_srx.observe(access, plan, operational)
    if plan["table"] in junos_dhcp.TABLES:
        return exec_junos_dhcp.observe(access, plan)
    if plan["table"] in junos.G145_TABLES:
        return _observe_g145(access, plan)
    if plan["table"] == "vlan":
        return _observe_vlan(access, plan)
    if plan["table"] == "vlan-membership":
        return _observe_membership(access, key)
    row = junos.interface_row(access.check_query("show interfaces %s terse" % key), key)
    if row is None:
        return None
    if plan["table"] in junos.POE_TABLES:
        poe = junos.poe_state(access.check_query("show poe interface %s" % key), key)
        if poe is None:
            return None
        disabled = poe["configured"] == "disabled"
        states = ("disabled",) if disabled else ("powered", "off")
        if operational and poe["state"] not in states:
            return None
        return {"admin-state": "disabled"} if disabled else {}
    if plan["table"] == junos.BOUNCE_TABLE:
        return {"admin-state": "disabled"} if row["admin"] == "down" else {}
    if operational:
        before, after = plan["predicted"]["before"], plan["predicted"]["after"]
        removes_speed = _removes_speed(plan)
        wanted = {name: after.get(name, junos.LINK_DEFAULTS[name]) for name in junos.LINK_PARAMETERS
                  if before.get(name) != after.get(name) and (name != "speed" or not removes_speed)}
        if wanted or removes_speed:
            seen = junos.link_parameters(access.check_query("show interfaces %s" % key), key)
            if any(seen.get(name) != value for name, value in wanted.items()):
                return None
            # The write-account snapshot already proves the speed statement is absent.
            # Junos reports the operational rate for the automatic setting.
            if removes_speed and (not seen.get("speed") or row["link"] != plan["link_before"]):
                return None
    description = junos.description_of(access.check_query(QUERY_DESCRIPTIONS), key)
    state = {"description": description} if description else {}
    if row["admin"] == "down":
        state["admin-state"] = "disabled"
    return state


def _observe_membership(access, key):
    """The check account: the VLANs of the port and their tagging (show ethernet-switching interface) and the mode of
    the port (access or trunk, show vlans <one of them> extensive). Measured: an access port shows its VLAN untagged
    and a voice VLAN tagged, a trunk its members tagged and the native VLAN untagged."""
    vlans = junos.switching(access.check_query("show ethernet-switching interface %s" % key), key)
    if not vlans:
        return None
    mode = junos.vlan_port_mode(access.check_query("show vlans %s extensive" % vlans[0][0]), key)
    untagged = [name for name, tagging in vlans if tagging == "untagged"]
    tagged = sorted(name for name, tagging in vlans if tagging == "tagged")
    if mode == "access":
        if len(untagged) != 1 or len(tagged) > 1:
            return None
        state = {"access-vlan": untagged[0]}
        if untagged[0] == junos.DEFAULT_VLAN:
            # The operational VLAN is identical with or without an explicit members default statement.
            text = _read(access, "show configuration interfaces %s | display inheritance | display set" % key)
            prefix = "set interfaces %s " % key
            rows = junos.answer_rows(text)
            if prefix + junos.ACCESS_MODE not in rows:
                raise Rejected(["the access VLAN configuration is incomplete"])
            members = [row[len(prefix + junos.MEMBERS + " "):] for row in rows
                       if row.startswith(prefix + junos.MEMBERS + " ")]
            if not members:
                del state["access-vlan"]
            elif members != [junos.DEFAULT_VLAN]:
                return None
        if tagged:
            state["voice-vlan"] = tagged[0]
        return state
    if mode != "trunk" or len(untagged) > 1:
        return None
    state = {"mode": "trunk", "trunk-vlans": " ".join(sorted(name for name, _tagging in vlans))}
    if untagged:
        tags = junos.vlan_tags(access.check_query(QUERY_VLANS))
        native = [number for number, name in tags.items() if name == untagged[0]]
        if len(native) != 1:
            return None
        state["native-vlan"] = native[0]
    return state


def _observe_vlan(access, plan):
    """Read the operational VLAN from the check account and its description and IRB from the scoped configuration."""
    tags = junos.vlan_tags(access.check_query(QUERY_VLANS))
    name = tags.get(plan["key"])
    if name is None:
        return None
    if not junos.VLAN_NAME.fullmatch(name):
        raise Rejected(["the VLAN name is not recognised"])
    state = {"name": name}
    prefix = "set vlans %s " % name
    text = _read(access, "show configuration vlans %s | display set" % name)
    rows = junos.answer_rows(text)
    if [row for row in rows if row.startswith(prefix + "vlan-id ")] != [prefix + "vlan-id " + plan["key"]]:
        raise Rejected(["the VLAN configuration does not identify the expected VLAN ID"])
    for field in ("description", "l3-interface"):
        path = prefix + field + " "
        values = [row[len(path):] for row in rows if row.startswith(path)]
        if values:
            value = junos.unquoted(values[0])
            if len(values) != 1 or value is None or (field == "l3-interface" and not junos.VLAN_IRB_VALUE.fullmatch(value)):
                raise Rejected(["the VLAN %s is not readable" % field])
            state[field] = value
    return state


# 1.0.12 G145: the scoped configuration reads of an object (write account; the check account of class read-only
# cannot read the configuration, measured); each answer holds only set lines of the object's stanza
G145_READS = {
    junos.SYSTEM_TABLE: ("show configuration system host-name | display set",
                         "show configuration system domain-name | display set",
                         "show configuration system name-server | display set",
                         "show configuration system ntp | display set"),
    junos.NTP_TABLE: ("show configuration system ntp | display set",),
    junos.SYSLOG_TABLE: ("show configuration system syslog host %s | display set",),
}


G145_HOST_NAME_READ = "show configuration system host-name | display set"
CHECK_HOSTNAME = re.compile(r"^Hostname:[ \t]+(\S+)[ \t]*$", re.MULTILINE)


def _check_identity(access, host_rows):
    """1.0.12 G145: the check account (class read-only) cannot read the configuration, so the stanza is read back by
    the write account; the check account confirms the device and its committed state by the Hostname of show version
    (measured on d-vjunos: the new host name right after its commit), which must equal the configured host name. A
    check account that cannot log in or answer refuses the readback, so check_identity_passed is never recorded on
    reads of the write account alone."""
    configured = [junos.HOST_NAME.match(row) for row in host_rows]
    if len(configured) != 1 or configured[0] is None:
        raise Rejected(["the configured host name is not readable"])
    seen = CHECK_HOSTNAME.findall(access.check_query(QUERY_VERSION).replace("\r", ""))
    if seen != [configured[0].group(1)]:
        raise Rejected(["the check account does not see the device as %s (show version Hostname %s)"
                        % (configured[0].group(1), ", ".join(seen) or "missing")])


def _observe_g145(access, plan):
    """The object read back from the scoped configuration, parsed like the snapshot (junos.g145_entries)."""
    table, key = plan["table"], plan["key"]
    rows = []
    for command in G145_READS[table]:
        text = _read(access, command % key if "%s" in command else command)
        found = [row for row in junos.answer_rows(text) if row.strip()]
        if any(not row.startswith("set system ") for row in found):
            raise Rejected(["the %s read back is not readable" % junos.G145_NAMES[table]])
        rows += found
    if table != junos.SYSTEM_TABLE:
        rows_of_name = [row for row in junos.answer_rows(_read(access, G145_HOST_NAME_READ)) if row.strip()]
    else:
        rows_of_name = rows
    _check_identity(access, [row for row in rows_of_name if row.startswith("set system host-name ")])
    scoped = junos.load("set version %s\n" % plan["firmware"] + "".join(row + "\n" for row in rows), None)
    entry = junos.g145_entries(scoped, table).get(key)
    if entry is None:
        return None
    if entry.unsupported:
        raise Rejected(["the %s %s holds configuration outside the profile: %s"
                        % (junos.G145_NAMES[table], key, ", ".join(entry.unsupported))])
    return dict(entry.attributes)


def foreign_sessions(access, device) -> int:
    return junos.users(_read(access, QUERY_USERS))


# G139 uses structured operational output for routes, IRB addresses and VLAN bindings.
VRRP_QUERY = "show vrrp detail | no-more"
VRRP_EMPTY = "warning: vrrp subsystem not running - not needed by configuration."
VRRP_ADDRESS = re.compile(r"Physical interface: (\S+), Unit: ([0-9]+), .*?Address: (\S+)")
VRRP_GROUP = re.compile(r"Interface state: \S+, Group: ([0-9]+), State: \S+.*")
VRRP_PRIORITY = re.compile(r"Priority: ([0-9]+),.*")
VRRP_VIPS = re.compile(r"Preempt: (yes|no), .*?VIP count: ([0-9]+), VIP: (.+)")


def _json_root(text, key, namespace):
    document = json.loads(text)
    if set(document) - {key, "cli"}:
        raise ValueError("unexpected Junos JSON response")
    root, = document[key]
    uri = root["attributes"]["xmlns"]
    if not uri.startswith("http://xml.juniper.net/junos/") or not uri.endswith("/" + namespace):
        raise ValueError("unexpected Junos report namespace")
    return root


def _field(row, name):
    field, = row[name]
    value = field["data"]
    if not isinstance(value, str) or not value:
        raise ValueError("missing Junos field")
    return value


def _records(row, name):
    rows = row.get(name, [])
    if not isinstance(rows, list) or any(not isinstance(item, dict) for item in rows):
        raise ValueError("invalid Junos list")
    return rows


def _route_query(network, *, hidden=False):
    table = "inet6.0" if network.version == 6 else "inet.0"
    return f"show route table {table} {network} exact" + (" hidden" if hidden else "") + " | display json | no-more"


def _route_tables(text):
    root = _json_root(text, "route-information", "junos-routing")
    if set(root) - {"attributes", "route-table"}:
        raise ValueError("unrecognised routing report")
    return _records(root, "route-table")


def _exact_static(text, network):
    state = None
    table_name = "inet6.0" if network.version == 6 else "inet.0"
    for table in _route_tables(text):
        if _field(table, "table-name") != table_name:
            raise ValueError("unexpected routing table")
        routes = _records(table, "rt")
        if not routes and int(_field(table, "destination-count")):
            raise ValueError("routing table has no route details")
        for route in routes:
            if ipaddress.ip_network(_field(route, "rt-destination")) != network:
                raise ValueError("route lookup returned a different network")
            entries = route["rt-entry"]
            if not entries:
                raise ValueError("route has no entries")
            for entry in entries:
                if _field(entry, "protocol-name") != "Static":
                    continue
                if state is not None:
                    raise ValueError("more than one static route matches")
                hop, = entry["nh"]
                address = ipaddress.ip_address(_field(hop, "to"))
                if address.version != network.version:
                    raise ValueError("static route next hop has the wrong family")
                state = {"next-hop": str(address), "preference": str(int(_field(entry, "preference")))}
    return state


def _observed_irb(text, key):
    root = _json_root(text, "interface-information", "junos-interface")
    if set(root) - {"attributes", "physical-interface", "logical-interface"}:
        raise ValueError("unrecognised IRB report")
    interfaces = list(_records(root, "logical-interface"))
    for physical in _records(root, "physical-interface"):
        if _field(physical, "name") != "irb":
            raise ValueError("unexpected physical interface")
        interfaces.extend(_records(physical, "logical-interface"))
    if not interfaces:
        return None
    row, = interfaces
    if _field(row, "name") != key or _field(row, "admin-status") not in ("up", "down"):
        raise ValueError("unexpected IRB interface")
    state = {}
    for family in _records(row, "address-family"):
        name = junos.IRB_FAMILIES.get(_field(family, "address-family-name"))
        if name is None:
            continue
        for item in _records(family, "interface-address"):
            address = ipaddress.ip_interface(_field(item, "ifa-local"))
            # Junos automatically creates this address when IPv6 is enabled.
            if address.version == 6 and address.ip.is_link_local:
                continue
            if name in state:
                raise ValueError("IRB has multiple addresses in a family")
            state[name] = str(address)
    return state


def _vlan_binding(text, name):
    root = _json_root(text, "l2ng-l2ald-vlan-instance-information", "junos-l2al")
    row, = _records(root, "l2ng-l2ald-vlan-instance-group")
    if _field(row, "l2ng-l2rtb-vlan-name") != name or _field(row, "l2ng-l2rtb-name") != "default-switch":
        raise ValueError("unexpected VLAN")
    field = "l2ng-l2rtb-vlan-l3-interface"
    return _field(row, field) if field in row else None


def _observed_vrrp(text, key):
    rows = [row.strip() for row in junos.answer_rows(text)]
    if rows == [VRRP_EMPTY]:
        return None
    if not rows or "---(more" in text.lower() or junos.refused_answer(text):
        raise ValueError("missing VRRP detail")
    blocks = []
    for row in rows:
        if row.startswith("Physical interface:"):
            if not VRRP_ADDRESS.fullmatch(row):
                raise ValueError("unrecognised VRRP interface")
            blocks.append([])
        if not blocks:
            raise ValueError("unrecognised VRRP detail")
        blocks[-1].append(row)
    matching = []
    for header, *body in blocks:
        interface, unit, _address = VRRP_ADDRESS.fullmatch(header).groups()
        group, = [match[1] for row in body if (match := VRRP_GROUP.fullmatch(row))]
        if f"{interface}.{unit}:{group}" != key:
            continue
        priority, = [match[1] for row in body if (match := VRRP_PRIORITY.fullmatch(row))]
        mode, count, vip = next(match.groups() for row in body if (match := VRRP_VIPS.fullmatch(row)))
        if count != "1":
            raise ValueError("VRRP group has more than one virtual address")
        matching.append({"virtual-address": str(ipaddress.IPv4Address(vip)), "priority": priority,
                         "preempt": "enabled" if mode == "yes" else "disabled"})
    if len(matching) > 1:
        raise ValueError("duplicate VRRP group")
    return matching[0] if matching else None


def _observe_l3(access, plan, *, operational):
    table, key = plan["table"], plan["key"]
    if table == junos.ROUTE_TABLE:
        network = junos.route_network(key)
        state = _exact_static(access.check_query(_route_query(network)), network)
        if state is None:
            return _exact_static(access.check_query(_route_query(network, hidden=True)), network)
        return state
    if table == junos.VRRP_TABLE:
        # The control process can still be starting when commit confirmed has returned.
        attempts = 5 if operational else 1
        expected = junos.check_view(table, plan["predicted"]["after"])
        for attempt in range(attempts):
            if attempt:
                sleep(1)
            last = attempt == attempts - 1
            try:
                observed = _observed_vrrp(access.check_query(VRRP_QUERY), key)
            except (ValueError, StopIteration):
                if last:
                    raise
            else:
                if last or observed == expected:
                    return observed
    state = _observed_irb(access.check_query(f"show interfaces {key} terse | display json | no-more"), key)
    before, after = plan["predicted"]["before"] or {}, plan["predicted"]["after"] or {}
    for vlan in {before.get("vlan"), after.get("vlan")} - {None}:
        attached = _vlan_binding(access.check_query(f"show vlans {vlan} extensive | display json | no-more"), vlan)
        if attached == key and (state is None or "vlan" in state):
            raise ValueError("IRB and VLAN operational bindings disagree")
        if attached == key:
            state["vlan"] = vlan
    return state


def _l3_read_failure(exc):
    if isinstance(exc, TimeoutError) or (isinstance(exc, AccessError) and
                                         re.search(r"timed? ?out|timeout", str(exc), re.IGNORECASE)):
        raise Rejected(["the Junos operational read timed out"], reason_codes=["junos_l3_read_timeout"]) from None
    raise Rejected(["the Junos operational answer is incomplete or unavailable"],
                   reason_codes=["junos_l3_read_unavailable"]) from None


def _management_endpoints(access, device, snapshot):
    terse = _read(access, "show interfaces terse | no-more")
    rows = junos.answer_rows(terse)
    if not rows or not rows[0].startswith("Interface ") or "---(more" in terse.lower():
        raise ValueError("missing management interface information")
    local = _interface_addresses(terse)
    port_lines = [row.split()[-1] for row in snapshot.lines if re.fullmatch(r"set system services ssh port [0-9]+", row)]
    port = port_lines[0] if port_lines else "22"
    sockets = _ssh_connections(_read(access, SSH_CONNECTIONS), port)
    targets = {device.address, device.check_address or device.address}
    if len(targets) > 1:
        checked = _ssh_connections(access.check_query(SSH_CONNECTIONS), port)
        if not checked:
            raise ValueError("missing check-account SSH socket")
        sockets.update(checked)
    if not sockets:
        raise ValueError("missing write-account SSH socket")
    addresses = {address for address, _peer in sockets}
    for target in targets:
        literal = _local_ip(target)
        if literal is not None:
            addresses.add(literal)
            continue
        resolved = {_local_ip(address) for address in access.resolve_addresses(target)}
        if not resolved or None in resolved:
            raise ValueError("SSH destination could not be resolved")
        addresses.update(resolved)
    return addresses, sockets, local, terse


def _default_preserves_management(access, network, sockets, local):
    for address, peer in sockets:
        if address.version != network.version:
            continue
        interfaces = local.get(address, set())
        if not interfaces or any(not DEDICATED_MANAGEMENT.fullmatch(interface) for interface in interfaces):
            return False
        tables = _route_tables(_read(access, f"show route {peer} | display json | no-more"))
        routes = [route for table in tables for route in _records(table, "rt")]
        destinations = [ipaddress.ip_network(_field(route, "rt-destination")) for route in routes]
        if not destinations or any(destination.prefixlen == 0 or peer not in destination for destination in destinations):
            return False
    return True


def _l3_plan_prechecks(access, device, plan, snapshot_text):
    table, key = plan["table"], plan["key"]
    before, after = plan["predicted"]["before"] or {}, plan["predicted"]["after"] or {}
    snapshot = junos.load(snapshot_text, None)
    if table == junos.ROUTE_TABLE:
        network = junos.route_network(key)
        if network.prefixlen == 0 and plan.get("endpoint_impact") != key:
            raise Rejected(["the default route requires explicit endpoint_impact"], reason_codes=["endpoint_impact_required"])
    else:
        irb = key.split(":")[0]
        irb_entry = junos.l3_entries(snapshot, junos.IRB_TABLE).get(irb)
        vlans = {before.get("vlan"), after.get("vlan"), irb_entry.attributes.get("vlan") if irb_entry else None}
        vlans.discard(None)
        guarded = {name.casefold() for names in device.protected.values() for name in names}
        vlan_ids = {line.split()[1] for vlan in vlans for line in snapshot.vlan_lines.get(vlan, ())
                    if re.fullmatch(r"vlan-id [0-9]+", line)}
        if guarded & {name.casefold() for name in {irb, "irb"} | vlans | vlan_ids}:
            raise Rejected(["the IRB or a linked VLAN is protected"], reason_codes=["port_protected"])

    try:
        endpoints, sockets, addresses, terse = _management_endpoints(access, device, snapshot)
        if table == junos.ROUTE_TABLE:
            protected = (not _default_preserves_management(access, network, sockets, addresses) if network.prefixlen == 0
                         else any(address in network for address in endpoints | {peer for _, peer in sockets}))
        else:
            configured = junos.irb_addresses(snapshot, irb, "inet") | junos.irb_addresses(snapshot, irb, "inet6")
            proposed = {state.get(name) for name in junos.IRB_FAMILIES.values()
                        for state in (before, after)} - {None}
            virtual = {state.get("virtual-address") for state in (before, after)} - {None}
            management = endpoints | {peer for _, peer in sockets}
            # Adding a connected network can divert the SSH return path even when the IRB uses another address.
            affected = {ipaddress.ip_interface(address).network for address in configured | proposed}
            protected = (any(address in network for address in management for network in affected)
                         or any(_local_ip(address) in management for address in virtual)
                         or junos.DEFAULT_VLAN in vlans
                         or _uses_management_irb(access, device, snapshot, terse, {irb}, report_errors=True))
    except (AccessError, TimeoutError) as exc:
        _l3_read_failure(exc)
    except (ValueError, OSError, KeyError, TypeError, Rejected):
        raise Rejected(["the management path cannot be determined"], reason_codes=["junos_l3_management_unreadable"]) from None
    if protected:
        raise Rejected(["this change can affect the management path"], reason_codes=["junos_l3_management_path"])
    if table == junos.VRRP_TABLE:
        try:
            answer = access.check_query(VRRP_QUERY)
        except (AccessError, TimeoutError) as exc:
            _l3_read_failure(exc)
        if "not supported" in answer.casefold() or re.search(r"syntax error|unknown command", answer, re.IGNORECASE):
            raise Rejected(["operational VRRP is unavailable on the device"], reason_codes=["junos_vrrp_unsupported"])
    plan["prechecks"].append("the management path is outside the scope of the change")
    return []


# ---- 1.0.12 G146: targeted operational clear (junos_clear.py) ----

def observe_clear(access, table, target):
    try:
        text = access.check_query(target.read)
    except AccessError:
        raise Rejected(["the check account could not read the Junos clear target"],
                       reason_codes=["clear_readback_unreadable"]) from None
    return junos_clear.observe(table, target, text)


def _refuse_clear(why):
    raise Rejected(["the selected clear scope includes a protected object: " + why],
                   reason_codes=["clear_protected_target"])


def _vlan_irbs(snapshot, vlan):
    irbs = set()
    for line in snapshot.lines:
        if junos.IRB_BINDING.fullmatch(line):
            match = junos.IRB_VLAN.fullmatch(line)
            if match is None:
                raise junos.unreadable("VLAN bindings to IRB interfaces")
            if match[1] == vlan:
                irbs.add(line.split()[-1])
    return irbs


def clear_prechecks(access, device, table, target, before, snapshot_text="") -> list:
    """1.0.12 G146: the protections of the port path apply to every port, VLAN and routed interface that the clear
    touches: protected interfaces and VLANs, dedicated management interfaces, ports with an LLDP neighbor (uplink),
    trunk ports, the only port with a link, ports and VLANs whose IRB carries or may carry the management path.
    Anything that cannot be read leaves the clear refused (clear_readback_unreadable)."""
    if table == junos_clear.BGP:
        return ["the session of peer %s is not reset" % target.key]
    policy = device.audit_policy or {}
    protected = {name.casefold() for name in (*device.protected.get("interface", ()), *device.protected.get("ports", ()))}
    vlans = ({name.casefold() for name in device.protected.get("vlan", ())}
             | {name.casefold() for name in policy.get("management_vlans", ())})
    entries = before.get("entries", ())
    port_units, irbs, named_vlans = set(), set(), set()
    if table == junos_clear.PORT_COUNTERS:
        port_units.add(before["port"])
    for entry in entries:
        interface = entry["interface"]
        if table == junos_clear.FDB:
            port_units.add(interface)
            named_vlans.add(entry["vlan"])
        elif re.fullmatch(r"irb\.[0-9]+", interface):
            irbs.add(interface)
            if entry["port"]:
                port_units.add(entry["port"])
        else:
            _refuse_clear("%s is not a switching or routed user interface" % interface)
    ports = {name.split(".", 1)[0] for name in port_units}
    for port in sorted(ports):
        if DEDICATED_MANAGEMENT.fullmatch(port) or not junos.PHYSICAL.fullmatch(port):
            _refuse_clear("%s is a management or internal interface" % port)
    for name in sorted(named_vlans):
        if name.casefold() in vlans:
            _refuse_clear("VLAN %s is a management or protected VLAN" % name)
    try:
        snapshot = junos.load(snapshot_text, None)
        for name in sorted(named_vlans):
            irbs |= _vlan_irbs(snapshot, name)
        for interface in sorted(port_units | irbs):
            folded = interface.casefold()
            if {folded, folded.split(".", 1)[0]} & protected:
                _refuse_clear("interface %s is protected" % interface)
        terse = _read(access, "show interfaces terse")
        lldp = junos.lldp_ports(_read(access, QUERY_LLDP))
        up = junos.physical_up(terse)
        uplinks = sorted(ports & lldp)
        if uplinks:
            _refuse_clear("port %s has an LLDP neighbor (uplink or managed device)" % ",".join(uplinks))
        for port in sorted(ports):
            sources, unsupported = snapshot.sources(port)
            if unsupported:
                raise junos.unreadable("interface configuration inheritance")
            lines = [line for source in sources for line in source.lines]
            if any(junos.TRUNK.match(line) for line in lines):
                _refuse_clear("port %s is a trunk and is protected as an uplink" % port)
            if up == [port]:
                _refuse_clear("port %s is the only port with a link up and may carry the management path" % port)
            if _carries_management_vlan(access, device, snapshot, port, lines, terse):
                _refuse_clear("port %s carries a VLAN whose IRB carries or may carry the management path" % port)
        if irbs and _uses_management_irb(access, device, snapshot, terse, irbs):
            _refuse_clear("%s carries or may carry the management path" % ", ".join(sorted(irbs)))
    except Rejected as exc:
        if exc.reason_codes == ["clear_protected_target"]:
            raise
        raise Rejected(["the port, VLAN or management path of the clear scope cannot be read: %s" % "; ".join(exc.reasons)],
                       reason_codes=["clear_readback_unreadable"]) from None
    except Exception:
        raise Rejected(["the port, VLAN or management path of the clear scope cannot be read"],
                       reason_codes=["clear_readback_unreadable"]) from None
    return ["%s: not protected, no LLDP neighbor, no trunk, no management path" % ", ".join(sorted(ports | irbs))]


CLEAR_READBACK_ATTEMPTS = 4
CLEAR_READBACK_PAUSE_SECONDS = 2


def read_back_clear(access, plan, target, sleep):
    """The proof against the state BEFORE the command (junos_clear.readback); a BGP counter or a table may follow
    the command by a second, so a mismatch is read again a few times before it is reported."""
    for attempt in range(CLEAR_READBACK_ATTEMPTS):
        matches, shown = junos_clear.readback(plan, observe_clear(access, plan["table"], target))
        if matches or attempt + 1 == CLEAR_READBACK_ATTEMPTS:
            return matches, shown
        sleep(CLEAR_READBACK_PAUSE_SECONDS)
