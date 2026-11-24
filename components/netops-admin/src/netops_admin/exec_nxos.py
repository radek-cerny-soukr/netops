"""Cisco NX-OS execution adapter (measured on Nexus 9000v N9K-C9300v, NX-OS 9.3(12), private measurement record).

NX-OS 9.3(12) has no commit timer and no EEM timer event; the only session-independent timed return is a one-time
job of `feature scheduler` that rolls the running configuration back to a checkpoint ("variant 3" of the
measurement). The safeguard is installed before the change, in one interactive session, in this order:

1. `checkpoint L` (a placeholder: the scheduler parser accepts the job only when the checkpoint exists);
2. `scheduler job name L` with `rollback running-config checkpoint L atomic`, `scheduler schedule name L` with
   `job name L` and `time start +M`;
3. `no checkpoint L` and `checkpoint L` again: the checkpoint now holds the job and the schedule, so the rollback
   patch never has to delete the running job (a job created after its checkpoint blocks the scheduler until
   `no feature scheduler`, measured as variant 1);
4. `copy running-config bootflash:L-pred.cfg`, the file of the immediate return (`configure replace` of it).

Ownership (review finding 2): the name L must be free of every object right before the installation, and an
object is the own one only when the line that creates it was answered without an error in the own session. Admin
notes that line by line in record["safeguard"]["own"] and the journal saves each note at once (INSTALL_JOURNAL);
every removal touches only own objects, so a foreign object of the same name is never deleted.

Interrupted or unverified installation (finding 1): as long as the change was not sent, the safeguard is discarded
at once (discard_installation, also by recover): a pending own schedule is removed first, then the own job, so a job
that its checkpoint does not hold yet (the phase between `time start` and the second `checkpoint L`) does not run when
the removal succeeds before the minute of the job; after an interruption of the Admin process that holds only when
recover runs in time. When the job of such a phase has already run and stays "schedule in progress", the removal
fails or an object is not proven own, the operation ends unknown with the manual procedure (manual_cleanup); Admin
never sends `no feature scheduler`.

Protection during the whole change (finding 3): Admin never reads the device clock. The job runs at the next whole
minute plus M-1 minutes after the device took `time start +M`, so at least M-1 minutes after the installation
started; Admin counts that on its monotonic clock from the moment before the installation (TIMER_WATCH in
execute.py), 2 % shorter for the drift of the device clock, and never longer than the lead the device itself shows
(the schedule time less the creation time of the checkpoint, both on the device clock). Before the change is written
the own schedule must still be pending with enough time left for the write, the readback and the confirmation
margin; every line is sent only while LINE_MARGIN_SECONDS are left. A failed write or readback is returned at once by
`configure replace bootflash:L-pred.cfg` (measured Success, also for the access VLAN) while REVERT_NOW_SECONDS of
the timer are left; otherwise, and for the enrollment self-test and recover, the job is awaited by reading the
scheduler, and when the object is still not in its state before after the job ran (a late line, or a change of
someone else after the return), the same replace is tried before giving up. `configure replace... commit-timeout`
is never used, because its automatic return leaves a changed access VLAN in place (measured).

Recover (finding 4) decides by the state of the scheduler (`show scheduler schedule name L`, `show scheduler
logfile`, `show rollback log`), never by the device clock, limited on the monotonic clock of Admin.

The schedule has a granularity of one minute; Admin takes M = ceil(safeguard_seconds / 60) + 1. The rollback returns
the WHOLE running configuration to the checkpoint, so a change of someone else made in the window is returned too.
Confirmation removes the schedule, then the job, then the checkpoint and the file; `copy running-config
startup-config` runs only after it. The same removal (after the run: job first, repeated while the switch answers
"schedule in progress") cleans up after the job ran.

`feature scheduler` is a precondition of the switch, enabled once by its administrator: Admin never enables or
disables it (`no feature scheduler` creates a system checkpoint and evicts the oldest of the five).
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import re
import time

from netops_admin import jsontext, nxos, nxos_clear
from netops_admin.access import AccessError
from netops_admin.errors import Rejected, SnapshotRejected
from netops_admin.exec_fortios import PromptSpec

FIRING_OBSERVED = True
# the safeguard is watched on the monotonic clock of Admin and by reading the scheduler, never by the device clock
# (execute.py: TIMER_WATCH); record["safeguard"]["fire_at"] says so, the device time of the job is in device_time
TIMER_WATCH = True
FIRE_AT_TEXT = "device scheduler job"
# install_safeguard notes the own objects line by line and execute.py saves each note at once
INSTALL_JOURNAL = True
# configure replace leaves the job, the schedule and the checkpoint; execute.py removes them after the proven return
REVERT_NOW_KEEPS_SAFEGUARD = True
# after the job ran, an object that is not in its state before is returned by the same configure replace
REVERT_AFTER_EXPIRY = True
# configure replace took 13-15 s measured (19 s in the E2E of verification), with login, the snapshot and the readback
# of the result about 30 s; with less than this of the own timer left the job is awaited instead
REVERT_NOW_SECONDS = 60
# the device clock drift was not measured on NX-OS; the allowance of the IOS adapter (1.7 % measured on IOSv) is used
DRIFT_FRACTION = 0.02
# a write session: login 2.5 s + at most 5 lines (measured well under 1 s each)
WRITE_BUDGET_SECONDS = 20
# the snapshot (ssh exec show running-config), the account check, three reads of the check account and the final
# snapshot, each its own ssh login of about 2-2.5 s
READBACK_BUDGET_SECONDS = 40
# a configuration line is sent only while this much of the own timer is left
LINE_MARGIN_SECONDS = 15
QUERY_RUNNING = "show running-config"
QUERY_VERSION = "show version"
QUERY_FEATURE = "show feature"
QUERY_DIFF = "show running-config diff"
QUERY_SESSIONS = "show configuration session summary"
QUERY_ROLLBACK_VERIFY = "show rollback log verify"
QUERY_ROLLBACK_EXEC = "show rollback log exec"
QUERY_CHECKPOINTS = "show checkpoint summary user"
QUERY_SCHEDULER_LOG = "show scheduler logfile"
QUERY_FILES = "dir bootflash:"
QUERY_TRUNKS = "show interface trunk"
QUERY_LLDP = "show lldp neighbors"
QUERY_USERS = "show users"
QUERY_SSH_SOCKETS = "show sockets connection tcp foreign %s"
QUERY_DESCRIPTIONS = "show interface description"
QUERY_CHANNELS = "show port-channel summary | json"
QUERY_VPC = "show vpc brief | json"
QUERY_KEEPALIVE = "show vpc peer-keepalive | json"
HOLD_SECONDS = 5
LINK_WAIT_SECONDS = 30
BOUNCE = "port-bounce"
TABLES = {BOUNCE: nxos.BOUNCE_TABLE}
# after the job ran, NX-OS refuses to delete the schedule for a while ("schedule in progress", measured ~1.5 min
# after the run, deleted ~3 min after it)
CLEANUP_PAUSE_SECONDS = 20
CLEANUP_LIMIT_SECONDS = 300
IN_PROGRESS = "in progress"
PAUSE = time.sleep
MONTHS = nxos.MONTHS
RUN_ONCE = re.compile(r"^Schedule Type\s*:\s*Run once on [A-Z][a-z]{2} ([A-Z][a-z]{2}) +([0-9]{1,2}) "
                      r"([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{4})\s*$", re.MULTILINE)
SCHEDULE_NAME = re.compile(r"^Schedule Name\s*:\s*(\S+)\s*$", re.MULTILINE)
LAST_EXECUTION = re.compile(r"^Last Execution Time\s*:\s*(.+?)\s*$", re.MULTILINE)
EXECUTION_COUNT = re.compile(r"^Execution count\s*:\s*([0-9]+)\s*$", re.MULTILINE)
CHECKPOINT_ROW = re.compile(r"^[0-9]+\) (\S+):\s*$", re.MULTILINE)
FILE_ROW = re.compile(r"^\s*[0-9]+\s+[A-Z][a-z]{2}\s+[0-9]{1,2}\s+[0-9:]{8}\s+[0-9]{4}\s+(\S+)\s*$", re.MULTILINE)
NO_SESSIONS = "There are no active configuration sessions"


def _read(access, command: str) -> str:
    """The answer of a write-account query whose refusal text the adapter judges itself ("Error: entry not found",
    "ERROR: Log Not Available", "VLAN N not found"): NX-OS may end such an exec command with a nonzero status."""
    query_status = getattr(access, "query_status", None)
    if query_status is None:
        return access.query(command)
    _status, text = query_status(command)
    return text


def prompt_spec(hostname: str) -> PromptSpec:
    # NX-OS 9.3(12) on Nexus 9300v writes a carriage return before the hostname in
    # each interactive prompt. Configuration modes append a suffix before "# ".
    return PromptSpec(anchor=("\r%s" % hostname).encode("ascii"), ends=(b"# ",), continuation=None,
                      error=nxos.cli_error)


def safeguard_label(change_id: str) -> str:
    return nxos.safeguard_label(change_id)


def pred_file(label: str) -> str:
    return "bootflash:%s-pred.cfg" % label


def hostname(access, snapshot_text: str) -> str:
    return nxos.load(snapshot_text, None).hostname


ACCOUNT_LINES = ("username ", "aaa ", "no aaa ")


def accounts_check(access, device, snapshot_text) -> str:
    snapshot = nxos.load(snapshot_text, None)
    present = sorted({line.split()[1] for line in snapshot.lines
                      if line.startswith("username ") and len(line.split()) >= 2})
    if present != sorted(device.accounts):
        raise Rejected(["the switch accounts differ from the expected list (%d present, %d expected)"
                        % (len(present), len(device.accounts))])
    lines = [line for line in snapshot.lines if line.startswith(ACCOUNT_LINES)]
    for block in snapshot.blocks:
        if block.header.startswith("role name "):
            lines.extend([block.header] + block.children)
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def sessions(text: str) -> list:
    """Names of the open configuration sessions in show configuration session summary."""
    if NO_SESSIONS in text:
        return []
    if "Session Manager Database" not in text:
        raise Rejected(["the configuration session list is not readable"])
    rows, started = [], False
    for line in text.replace("\r", "").split("\n"):
        if set(line.strip()) == {"-"}:
            started = True
            continue
        if not started or not line.strip() or line.startswith("Number of active") or line.startswith("Name "):
            continue
        rows.append(line.split()[0])
    return rows


def rollback_running(text: str) -> bool:
    """A rollback or configure replace that started and has not ended (show rollback log verify)."""
    if "Log Not Available" in text:
        return False
    return "Start Time UTC" in text and "End Time UTC" not in text


def prechecks(access, device, snapshot_text, spec, *, saving=False) -> list:
    reasons = []
    running = nxos.nxos_version(access.query(QUERY_VERSION))
    expected = device.firmware or nxos.firmware_of(snapshot_text)
    if running != expected:
        reasons.append("the switch runs NX-OS %s, not the configured %s" % (running, expected))
    if not saving and nxos.feature_state(access.query(QUERY_FEATURE), "scheduler") != "enabled":
        raise Rejected(["feature scheduler is not enabled on the switch; the timed return of Admin needs it. Its "
                        "administrator enables it once (configure terminal, feature scheduler, end, copy "
                        "running-config startup-config) and leaves it enabled: Admin never enables or disables it, "
                        "because every 'no feature scheduler' creates a system checkpoint and evicts the oldest"],
                       reason_codes=["scheduler_feature_disabled"])
    if not saving and access.query(QUERY_DIFF).strip():
        reasons.append("the switch has unsaved configuration changes (show running-config diff is not empty); the "
                       "timed return would roll them back too")
    save_prechecks(access)
    return reasons


def save_prechecks(access):
    open_sessions = sessions(access.query(QUERY_SESSIONS))
    if open_sessions:
        raise Rejected(["%d configuration sessions are open on the switch" % len(open_sessions)],
                       reason_codes=["foreign_config_session"])
    if rollback_running(_read(access, QUERY_ROLLBACK_VERIFY)):
        raise Rejected(["a rollback or configure replace is running on the switch"],
                       reason_codes=["rollback_in_progress"])


def plan_prechecks(access, device, plan, snapshot_text="", *, undo=False, pending_vlans=(), pending_ports=(),
                   earlier=()) -> list:
    table = plan["table"]
    if table in nxos.ACL_TABLES:
        acl_plan_prechecks(access, plan, snapshot_text)
        return []
    if table == nxos.SAVE_TABLE or table in nxos.SERVICE_TABLES:
        return []
    if table in nxos.STATE_TABLES:
        return state_prechecks(access, plan, snapshot_text)
    try:
        if table == nxos.VLAN_TABLE:
            vlan_prechecks(access, plan, pending_ports=pending_ports)
            return []
        if table in nxos.LINK_TABLES and table != nxos.BOUNCE_TABLE:
            link_prechecks(access, device, plan, nxos.load(snapshot_text, plan["firmware"]), earlier=earlier)
            return []
        return port_prechecks(access, device, plan, snapshot_text, undo=undo, pending_vlans=pending_vlans)
    except AccessError as exc:
        if re.search(r"timed out|timeout", str(exc), re.IGNORECASE):
            raise Rejected(["the NX-OS port or VLAN preflight read timed out"],
                           reason_codes=["nxos_l2_read_timeout"]) from exc
        raise nxos.unreadable("NX-OS port or VLAN preflight response") from exc


def vlan_prechecks(access, plan, *, pending_ports=()):
    key = plan["key"]
    answer = access.query("show system vlan reserved")
    current = re.findall(r"^system current running vlan reservation: (\d+)-(\d+)\s*$", answer, re.MULTILINE)
    future = re.findall(r"^system future running vlan reservation: (\d+)-(\d+)\s*$", answer, re.MULTILINE)
    if len(current) != 1 or len(future) > 1 or any(not 1 <= int(low) <= int(high) <= 4095
                                                   for low, high in current + future):
        raise nxos.unreadable("current and future VLAN reservations")
    if any(int(low) <= int(key) <= int(high) for low, high in current + future):
        raise Rejected(["VLAN %s is in a device reservation" % key], reason_codes=["vlan_reserved"])
    command = "show vlan id %s" % key
    shown = nxos.vlan_status(_read(access, command), key)
    before = plan["predicted"]["before"]
    if shown is not None and (set(shown["ports"]) - set(pending_ports)
                              or nxos.learned_macs(access.query("show mac address-table vlan " + key))):
        raise Rejected(["VLAN %s has port membership or MAC entries" % key], reason_codes=["vlan_in_use"])
    expected = None if before is None else before.get("name", nxos.vlan_name(key))
    if (None if shown is None else shown["name"]) != expected or (shown and shown["status"] != "active"):
        raise nxos.unreadable("agreement between the running configuration and VLAN %s" % key)
    if observe_vlan(access, plan, pending_ports=pending_ports) != before:
        raise nxos.unreadable("VLAN %s with the check account" % key)
    plan["prechecks"].append("VLAN %s is %s in both accounts and has no ports or MAC entries" %
                             (key, "present" if shown else "absent"))


def port_prechecks(access, device, plan, snapshot_text, *, undo=False, pending_vlans=()):
    key, table = plan["key"], plan["table"]
    bounce = table == nxos.BOUNCE_TABLE
    if table not in ("interface", nxos.MEMBERSHIP_TABLE, nxos.BOUNCE_TABLE):
        return []
    status = nxos.status_row(access.query("show interface %s status" % key), key)
    if status is None:
        raise Rejected(["the switch does not report interface %s" % key], reason_codes=["port_usage_unreadable"])
    plan["prechecks"].append("interface %s now: status %s, VLAN %s" % (key, status["status"], status["vlan"]))
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    membership = table == nxos.MEMBERSHIP_TABLE
    impact = plan.get("endpoint_impact") == key
    trunk_change = membership and (before.get("mode") == "trunk" or after.get("mode") == "trunk")
    command = "show interface %s switchport" % key
    if membership:
        if status["vlan"] == "trunk" and before.get("mode") != "trunk":
            raise Rejected(["port %s is operationally a trunk" % key], reason_codes=["port_uplink"])
        for wanted in sorted(nxos.membership_vlans(before, after), key=int):
            if wanted not in pending_vlans and not nxos.vlan_exists(_read(access, "show vlan id %s" % wanted), wanted):
                raise Rejected(["VLAN %s does not exist on the switch" % wanted], reason_codes=["vlan_missing"])
        if nxos.membership_status(access.query(command), key) != nxos.MEMBERSHIP_DEFAULTS | before:
            raise nxos.unreadable("agreement between the running configuration and switchport state")
    if not nxos.disruptive(table, before, after):
        return []
    short = nxos.short_name(key)
    idle = status["status"] in ("notconnec", "notconnect", "disabled")
    if (short in nxos.trunk_ports(access.query(QUERY_TRUNKS)) and not (trunk_change and idle)
            or trunk_change and not idle or status["vlan"] == "routed"):
        raise Rejected(["port %s is a trunk (show interface trunk); a trunk is treated as an uplink and is not "
                        "changed" % key], reason_codes=["port_uplink"])
    mac_types = nxos.mac_types(access.query("show mac address-table interface %s" % key))
    count = len(mac_types)
    if count and not impact:
        raise Rejected(["port %s has learned MAC addresses; changing a port in use is refused" % key],
                       reason_codes=["port_learned_mac"])
    if short in nxos.lldp_ports(access.query(QUERY_LLDP)):
        raise Rejected(["port %s has an LLDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    # A client may stay connected without sending traffic after its access VLAN changes.
    restoring_access_vlan = (undo and impact and membership and not trunk_change and not mac_types
                             and before.get("access-vlan") != after.get("access-vlan"))
    if not idle and (status["status"] != "connected" or not status["vlan"].isdigit()
                     or (mac_types != ["dynamic"] and not restoring_access_vlan)):
        raise Rejected(["port %s is up without one identifiable access endpoint" % key], reason_codes=["port_uplink"])
    if trunk_change and not impact:
        raise Rejected(["trunk or mode changes require endpoint_impact naming %s" % key],
                       reason_codes=["endpoint_impact_required"])
    if short in nxos.cdp_ports(access.query("show cdp neighbors")):
        raise Rejected(["port %s has a CDP neighbor" % key], reason_codes=["port_cdp_neighbor"])
    if snapshot_text:
        snapshot = nxos.load(snapshot_text, plan["firmware"])
        protected = set(device.protected.get("vlan", ()))
        svi = {match[1] for name in snapshot.interfaces if (match := nxos.SVI.fullmatch(name))
               and any(line.startswith(("ip address ", "ipv6 address ", "ip unnumbered "))
                       for line in snapshot.interface_lines(name))}
        vlans = {status["vlan"]}
        if membership:
            vlans = {vid for vid in protected | svi if any(
                vid == state.get("access-vlan", "1") if state.get("mode") != "trunk"
                else vid == state.get("native-vlan", "1") or int(vid) in nxos.trunk_vlans(state.get("allowed-vlans", "all"))
                for state in (before, after) if vid.isdecimal())}
        if protected.intersection(vlans):
            raise Rejected(["port %s carries a protected VLAN" % key], reason_codes=["port_protected"])
        if svi.intersection(vlans):
            _require_oob_management(access, snapshot)
    if impact:
        plan["port_impact"] = {"link": status["status"], "mode": "trunk" if status["vlan"] == "trunk" else "access",
                               "vlan": status["vlan"], "learned_macs": str(count)}
    if bounce:
        state = interface_operational(access, key)
        if state["admin"] != "up" or state["link"] != ("up" if status["status"] == "connected" else "down"):
            raise nxos.unreadable("agreement between administrative and operational port state")
        plan["cycle_state"] = {"link": state["link"], "lldp": "none", "learned_macs": str(count)}
        plan["prechecks"].append("bounce holds the port down for %d seconds before restoring it" % HOLD_SECONDS)
    plan["prechecks"].append("port %s: %s learned MAC entries, no LLDP neighbor" % (key, count))
    return []


def _checked_read(access, command):
    reader = getattr(access, "check_query_status", None)
    return (0, access.check_query(command)) if reader is None else reader(command)


def _document(text, label):
    try:
        data = jsontext.parse(text.encode("utf-8"))
    except jsontext.JsonRefused:
        raise nxos.unreadable(label) from None
    if not isinstance(data, dict):
        raise nxos.unreadable(label)
    return data


def _rows(data, kind, *, optional=False):
    table = "TABLE_" + kind
    if optional and table not in data:
        return []
    wrapper = data.get(table)
    if not isinstance(wrapper, dict) or "ROW_" + kind not in wrapper:
        raise nxos.unreadable("NX-OS " + kind + " table")
    rows = wrapper["ROW_" + kind]
    rows = [rows] if isinstance(rows, dict) else rows
    if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
        raise nxos.unreadable("NX-OS " + kind + " rows")
    return rows


def _number(value, maximum):
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,3}", value) and int(value) <= maximum


def _channel_summary(access):
    status, text = _checked_read(access, QUERY_CHANNELS)
    if status:
        raise nxos.unreadable("port-channel summary")
    # NX-OS 9.3(12) prints zero bytes with exit 0 when there are no port-channels.
    if not text.strip():
        return {}
    result, seen = {}, set()
    for row in _rows(_document(text, "port-channel summary"), "channel"):
        number = row.get("group")
        key = row.get("port-channel")
        if (not _number(number, 4096) or key != nxos.channel_key(number) or key in result
                or row.get("layer") not in ("S", "R") or row.get("status") not in ("D", "U", "M")
                or row.get("type") != "Eth" or row.get("prtcl") not in ("LACP", "NONE", "--", "none")):
            raise nxos.unreadable("port-channel summary row")
        members = {}
        for member in _rows(row, "member", optional=True):
            port, state = member.get("port"), member.get("port-status")
            if (not isinstance(port, str) or not nxos.ETHERNET.fullmatch(port) or port in seen
                    or state not in ("D", "P", "I", "H", "s", "r", "b", "p", "M", "w")):
                raise nxos.unreadable("port-channel summary member")
            members[port] = state
            seen.add(port)
        result[key] = {"group": number, "layer": row["layer"], "status": row["status"],
                       "protocol": row["prtcl"], "members": members}
    return result


def _vpc_summary(access):
    status, text = _checked_read(access, QUERY_VPC)
    if status:
        raise nxos.unreadable("vPC status")
    data = _document(text, "vPC status") if text.strip() else {}
    domain, count = data.get("vpc-domain-id"), data.get("num-of-vpcs")
    if not data or (domain in ("0", "Not configured", "not configured") and count in (None, "0")
                    and not {"TABLE_vpc", "TABLE_peerlink"}.intersection(data)):
        # The text form identifies an unconfigured domain even when the JSON has no tables or row counts.
        status, plain = _checked_read(access, "show vpc brief")
        if (status or not re.search(r"(?m)^vPC domain id[ \t]*:[ \t]*Not configured[ \t\r]*$", plain)
                or re.search(r"--More--|(?m:^[ \t]*[0-9]+[ \t]+Po[0-9]+)", plain)):
            raise nxos.unreadable("absence of a vPC domain")
        return {"domain": None, "assignments": {}, "peer_link": None, "healthy": False, "keepalive": None}
    # NX-OS 9.3(12) closes the peer-link and vPC tables with "vpc-end"; a domain without a peer-link and without vPC
    # rows (an unpaired domain, or a pair before its peer-link is assigned) has neither the tables nor "vpc-end"
    # (measured), so the end marker is required only when a table is present
    tables = {"TABLE_vpc", "TABLE_peerlink"}.intersection(data)
    if (not _number(domain, 1000)
            or not isinstance(count, str) or not re.fullmatch(r"[0-9]{1,4}", count)
            or not isinstance(data.get("vpc-peer-status"), str)
            or not isinstance(data.get("vpc-peer-keepalive-status"), str)
            or tables and "vpc-end" not in data):
        raise nxos.unreadable("vPC status summary")
    rows = _rows(data, "vpc", optional=True)
    links = _rows(data, "peerlink", optional=True)
    if int(count) != len(rows) or len(links) > 1:
        raise nxos.unreadable("vPC status row count")
    assignments = {}
    for row in rows:
        channel, number = row.get("vpc-ifindex"), row.get("vpc-id")
        if (not isinstance(channel, str) or not re.fullmatch(r"Po[1-9][0-9]{0,3}", channel)
                or not _number(channel[2:], 4096) or not _number(number, 4096) or channel in assignments
                or number in assignments.values() or row.get("vpc-port-state") not in ("0", "1")):
            raise nxos.unreadable("vPC interface row")
        assignments[channel] = number
    link = links[0] if links else {}
    peer_link = link.get("peerlink-ifindex")
    if link and (not isinstance(peer_link, str) or not re.fullmatch(r"Po[1-9][0-9]{0,3}", peer_link)
                 or not _number(peer_link[2:], 4096) or peer_link in assignments
                 or link.get("peer-link-port-state") not in ("0", "1")):
        raise nxos.unreadable("vPC peer-link row")
    healthy = (data["vpc-peer-status"] == "peer-ok" and data["vpc-peer-keepalive-status"] == "peer-alive"
               and data.get("vpc-peer-consistency") == "consistent" and link.get("peer-link-port-state") == "1")
    return {"domain": domain, "assignments": assignments,
            "peer_link": peer_link, "healthy": healthy, "keepalive": data["vpc-peer-keepalive-status"]}


def _keepalive(access):
    status, text = _checked_read(access, QUERY_KEEPALIVE)
    if status:
        raise nxos.unreadable("vPC peer-keepalive")
    data = _document(text, "vPC peer-keepalive")
    dest, vrf = data.get("vpc-keepalive-dest"), data.get("vpc-keepalive-vrf")
    if isinstance(dest, list) and dest and all(value == dest[0] for value in dest):
        dest = dest[0]
    try:
        if not (isinstance(dest, str) and isinstance(vrf, str) and nxos.VRF.fullmatch(vrf)):
            raise ValueError
        return {"destination": str(ipaddress.IPv4Address(dest)), "vrf": vrf}
    except ValueError:
        raise nxos.unreadable("vPC peer-keepalive endpoint and VRF") from None


def interface_operational(access, key):
    status, text = _checked_read(access, "show interface %s | json" % key)
    if status:
        raise nxos.unreadable("interface state")
    rows = _rows(_document(text, "interface state"), "interface")
    if len(rows) != 1 or rows[0].get("interface") != key:
        raise nxos.unreadable("interface identity")
    link, admin = rows[0].get("state"), rows[0].get("admin_state")
    if link not in ("up", "down") or admin not in ("up", "down") or (admin == "down" and link == "up"):
        raise nxos.unreadable("administrative and link state")
    return {"admin": admin, "link": link}


def _idle_channel(access, device, snapshot, channel, members, physical=None, *, channel_pending=False):
    ports = {channel, *members}
    if physical is not None:
        ports.add(physical)
    lldp = set()
    # A channel with no physical ports cannot have an LLDP neighbor when the device reports LLDP disabled.
    if members or physical is not None or nxos.feature_state(access.query(QUERY_FEATURE), "lldp") != "disabled":
        lldp = nxos.lldp_ports(access.query(QUERY_LLDP))
    cdp = nxos.cdp_ports(access.query("show cdp neighbors"))
    for port in sorted(ports):
        if port == channel and channel_pending:
            continue
        status = nxos.status_row(access.query("show interface %s status" % port), port)
        if status is None:
            raise nxos.unreadable("port-channel interface status")
        idle = status["status"] in ("notconnec", "notconnect", "disabled", "sfpAbsent")
        if not idle and not (port == channel and status["status"] == "noOperMem"):
            raise Rejected(["interface %s is not idle" % port], reason_codes=["port_lag_active"])
        short = nxos.short_name(port)
        if short in lldp or short in cdp or nxos.learned_macs(access.query("show mac address-table interface " + port)):
            raise Rejected(["interface %s has a neighbor or MAC entry" % port], reason_codes=["port_lag_active"])
    protected = set(device.protected.get("vlan", ()))
    svis = {match[1] for key in snapshot.interfaces if (match := nxos.SVI.fullmatch(key))
            and any(line.startswith(("ip address ", "ipv6 address ", "ip unnumbered "))
                    for line in snapshot.interface_lines(key))}
    for port in sorted(ports):
        mode = nxos.link_mode(snapshot, port)
        state = nxos.MEMBERSHIP_DEFAULTS | snapshot._entry(
            nxos.MEMBERSHIP_TABLE, port, snapshot.interfaces[port]).attributes
        carried = ({state["access-vlan"]} if mode == "access" else
                   {str(vlan) for vlan in nxos.trunk_vlans(state["allowed-vlans"])} | {state["native-vlan"]})
        if carried & protected:
            raise Rejected(["an affected interface carries a protected VLAN"], reason_codes=["port_protected"])
        if carried & svis:
            _require_oob_management(access, snapshot)
            svis.clear()


def link_prechecks(access, device, plan, snapshot, *, earlier=()):
    table, key = plan["table"], plan["key"]
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    feature = "lacp" if table == nxos.CHANNEL_MEMBER_TABLE else "vpc" if table in nxos.VPC_TABLES else None
    if feature is not None:
        state = nxos.feature_state(access.query("show feature | include " + feature), feature)
        if state == "disabled":
            raise Rejected(["feature %s is disabled" % feature], reason_codes=["nxos_link_feature_disabled"])
        if state != "enabled":
            raise nxos.unreadable(feature + " feature state")
    if table in nxos.VPC_TABLES:
        topology = _vpc_summary(access)
        roles = nxos.vpc_channels(snapshot)
        domains = nxos.link_entries(snapshot, nxos.VPC_DOMAIN_TABLE)
        if (set(domains) != ({topology["domain"]} if topology["domain"] else set())
                or {nxos.short_name(name): role[4:] for name, role in roles.items() if role != "vpc peer-link"}
                != topology["assignments"]
                or {nxos.short_name(name) for name, role in roles.items() if role == "vpc peer-link"}
                != ({topology["peer_link"]} if topology["peer_link"] else set())):
            raise nxos.unreadable("agreement between configured and operational vPC topology")
        if table == nxos.VPC_DOMAIN_TABLE:
            return
        if (not topology["domain"] or table == nxos.VPC_PORT_TABLE and after and not topology["healthy"]
                or table == nxos.VPC_PEER_LINK_TABLE and after and topology["keepalive"] != "peer-alive"):
            raise Rejected(["the vPC topology does not meet the prerequisites for this change"],
                           reason_codes=["nxos_vpc_dependency"])
    channel = nxos.channel_key((before or after)["group"]) if table == nxos.CHANNEL_MEMBER_TABLE else key
    summary = _channel_summary(access)
    row = summary.get(channel)
    members = nxos.channel_members(snapshot, channel)
    if table == nxos.CHANNEL_MEMBER_TABLE and any(key in item["members"] for name, item in summary.items()
                                                  if name != channel):
        raise nxos.unreadable("the Ethernet interface's port-channel")
    if table == nxos.CHANNEL_MEMBER_TABLE and row is None and not before and not members and any(
            step["table"] == nxos.CHANNEL_TABLE and step["key"] == channel and step["op"] == "create"
            for step in earlier):
        # The earlier step proved the channel absent. Check the physical member
        # now and check the created channel again immediately before the write.
        _idle_channel(access, device, snapshot, channel, members, key, channel_pending=True)
        return
    if (row is None) != (channel not in snapshot.interfaces):
        raise nxos.unreadable("agreement between configured and operational port-channel members")
    if row is None:
        return  # An absent port-channel has no interfaces to inspect.
    observed_members = set(row["members"])
    if observed_members != members:
        pending_detach = {step["key"] for step in earlier if step["table"] == nxos.CHANNEL_MEMBER_TABLE
                          and not step["predicted"]["after"] and step["predicted"]["before"]
                          and nxos.channel_key(step["predicted"]["before"]["group"]) == channel}
        if table != nxos.CHANNEL_TABLE or after is not None or observed_members != members | pending_detach:
            raise nxos.unreadable("agreement between configured and operational port-channel members")
        # An undo detaches the idle member before deleting the channel. The
        # currently attached member still needs all protections at preview.
        members = observed_members
    if row["status"] != "D" or row["layer"] != "S" or any(state != "D" for state in row["members"].values()):
        raise Rejected(["the affected port-channel is carrying traffic or has a non-idle member"],
                       reason_codes=["port_lag_active"])
    if table == nxos.CHANNEL_MEMBER_TABLE and before and row["protocol"] != "LACP":
        raise nxos.unreadable("port-channel LACP protocol")
    _idle_channel(access, device, snapshot, channel, members, key if table == nxos.CHANNEL_MEMBER_TABLE else None)


def _require_oob_management(access, snapshot):
    def uses_oob(read):
        peer = nxos.ssh_session_peer(read(QUERY_USERS))
        vrf = nxos.ssh_session_vrf(read(QUERY_SSH_SOCKETS % peer), peer)
        return vrf == "management" and nxos._interface_vrf(snapshot, "mgmt0") == vrf and not any(
            nxos._interface_vrf(snapshot, name) == vrf for name in snapshot.interfaces if nxos.SVI.fullmatch(name))

    if not access.with_interactive_reader(prompt_spec(snapshot.hostname), uses_oob):
        raise Rejected(["the port may carry a management SVI; an out-of-band SSH path could not be verified"],
                       reason_codes=["port_management_interface"])


def _protect_svi_ssh(access, snapshot, interface):
    block = snapshot.interfaces.get(interface)
    if block is None or nxos.l3_entry(snapshot, interface, block).attributes.get("admin-state") == "disabled":
        return
    networks = [(vrf or "default", network) for name, vrf, network in nxos.interface_networks(snapshot)
                if name == interface]
    configured = [line for line in snapshot.interface_lines(interface)
                  if line.startswith(("ip address ", "ipv6 address "))]
    if len(networks) != len(configured):
        raise nxos.unreadable("SVI subnets for the management SSH check")
    if not networks:
        return
    try:
        status = access.query("show interface " + _interface_command(interface))
    except AccessError as exc:
        raise nxos.unreadable("SVI operational state") from exc
    if not nxos.svi_operational(status, interface):
        return
    def session_uses_svi(read):
        peer = nxos.ssh_session_peer(read(QUERY_USERS))
        source = nxos.unmap_ipv4(peer)
        matching_vrfs = {vrf for vrf, network in networks if source.version == network.version
                         and source in network}
        if not matching_vrfs:
            return False
        # The inventory host/port may be translated by DNAT. Read the switch's socket context.
        session_vrf = nxos.ssh_session_vrf(read(QUERY_SSH_SOCKETS % peer), peer)
        return session_vrf in matching_vrfs

    try:
        carries_session = access.with_interactive_reader(prompt_spec(snapshot.hostname), session_uses_svi)
    except AccessError as exc:
        raise nxos.unreadable("current SSH session source or VRF") from exc
    if carries_session:
        raise Rejected(["SVI %s carries the Admin SSH session" % interface],
                       reason_codes=["port_management_interface"])


def state_prechecks(access, plan, snapshot_text):
    table, key = plan["table"], plan["key"]
    interface = key.split(":", 1)[0]
    if table in (nxos.L3_TABLE, nxos.RELAY_TABLE) and nxos.SVI.fullmatch(interface):
        _protect_svi_ssh(access, nxos.load(snapshot_text, plan["firmware"]), interface)
    if table == nxos.RELAY_TABLE:
        feature = nxos.feature_state(access.query("show feature | include ^dhcp"), "dhcp")
        if feature != "enabled" or {"no service dhcp", "no ip dhcp relay"}.intersection(
                nxos.load(snapshot_text, plan["firmware"]).lines):
            raise Rejected(["enable the DHCP feature and relay agent before managing relay addresses"],
                           reason_codes=["dhcp_feature_disabled"])
        # The check account must be able to read the relay table before installing a safeguard.
        if relay_readback(access, plan) != plan["predicted"]["before"]:
            raise nxos.unreadable("DHCP relay state before the change")
    elif table == nxos.L3_TABLE and nxos.ETHERNET.fullmatch(key):
        before, after = (plan["predicted"][side] for side in ("before", "after"))
        # any change of a physical port (mode, admin state, address, VRF) interrupts its traffic (nxos routing admin r3)
        if before != after:
            status = nxos.status_row(access.query("show interface %s status" % key), key)
            if status is None:
                raise nxos.unreadable("physical port status")
            if status["status"] not in ("notconnec", "notconnect", "disabled"):
                raise Rejected(["the physical port is in use"], reason_codes=["port_uplink"])
            if nxos.short_name(key) in nxos.trunk_ports(access.query(QUERY_TRUNKS)):
                raise Rejected(["the physical port is a trunk"], reason_codes=["port_uplink"])
            if nxos.learned_macs(access.query("show mac address-table interface %s" % key)):
                raise Rejected(["the physical port has learned MAC addresses"], reason_codes=["port_learned_mac"])
            if nxos.short_name(key) in nxos.lldp_ports(access.query(QUERY_LLDP)):
                raise Rejected(["the physical port has an LLDP neighbor"], reason_codes=["port_lldp_neighbor"])
    return []


def ports(access, table: str):
    return None


def batch_read_error(exc):
    if re.search(r"timed out|timeout", str(exc), re.IGNORECASE):
        return Rejected(["the NX-OS profile batch preflight read timed out"],
                        reason_codes=["nxos_l2_read_timeout"])
    return nxos.unreadable("profile batch preflight")


def batch_prechecks(access, device, plan, snapshot_text, earlier, *, undo=False):
    """Check current state, deferring only prerequisites supplied by an earlier verified step."""
    table, key = plan["table"], plan["key"]
    pending_vlans = {step["key"] for step in earlier if step["table"] == nxos.VLAN_TABLE and step["op"] == "create"}
    pending_ports = {nxos.short_name(step["key"]) for step in earlier
                     if step["table"] == nxos.MEMBERSHIP_TABLE
                     and key in ((step["predicted"]["before"] or {}).get("access-vlan"),
                                 (step["predicted"]["before"] or {}).get("native-vlan"))
                     and key not in ((step["predicted"]["after"] or {}).get("access-vlan"),
                                     (step["predicted"]["after"] or {}).get("native-vlan"))}
    pending_acls = {step["key"] for step in earlier if step["table"] == nxos.ACL_TABLE and step["op"] == "create"}
    interface = nxos.interface_target(table, key)
    try:
        existing = plan["predicted"]["before"] is not None or table == nxos.RELAY_TABLE
        if interface and existing and table != nxos.ACL_BINDING_TABLE:
            if nxos.ETHERNET.fullmatch(interface) or nxos.PORT_CHANNEL.fullmatch(interface):
                row = nxos.status_row(access.query(f"show interface {interface} status"), interface)
                if row is None:
                    raise nxos.unreadable("batch interface status")
                active = row["status"] == "connected"
                if not active and row["status"] not in ("notconnec", "notconnect", "disabled", "noOperMem"):
                    raise nxos.unreadable("batch interface status")
            else:
                status = access.query("show interface " + _interface_command(interface))
                if nxos.LOOPBACK.fullmatch(interface):
                    active = nxos.loopback_operational(status, interface)
                else:
                    active = nxos.svi_operational(status, interface)
            if active and plan.get("endpoint_impact") != key:
                raise Rejected(["the active interface %s requires endpoint_impact naming %s" % (interface, key)],
                               reason_codes=["endpoint_impact_required"])
        reasons = plan_prechecks(access, device, plan, snapshot_text, undo=undo,
                                 pending_vlans=pending_vlans, pending_ports=pending_ports, earlier=earlier)
        if reasons:
            raise Rejected(reasons)
        if table == nxos.ACL_BINDING_TABLE:
            observed = observe_acl(access, plan, pending_acls=pending_acls)
        elif table == nxos.VLAN_TABLE:
            observed = observe_vlan(access, plan, pending_ports=pending_ports)
        else:
            observed = observe(access, plan)
    except AccessError as exc:
        raise batch_read_error(exc) from None
    from netops_admin import engine
    if engine.observed_state(plan, observed) != engine.check_view(plan, plan["predicted"]["before"]):
        raise nxos.unreadable("agreement between the check account and the planned starting state")


# ---- the safeguard objects on the switch ----

KINDS = ("checkpoint", "job", "schedule", "file")
CREATED_AT = re.compile(r"^Created at [A-Z][a-z]{2}, ([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{1,2}) ([A-Z][a-z]{2}) "
                        r"([0-9]{4})\s*$")


def schedule(text: str, label: str):
    """The schedule L of show scheduler schedule name L: its time, whether it ran and the status of its job, or
    None when the switch does not know it ("Error: entry not found")."""
    if "entry not found" in text:
        return None
    names = SCHEDULE_NAME.findall(text)
    when = RUN_ONCE.search(text)
    last = LAST_EXECUTION.search(text)
    if names != [label] or when is None or last is None or when.group(1) not in MONTHS:
        raise Rejected(["the answer about scheduler schedule %s is not recognised" % label])
    month, day, hour, minute, second, year = when.groups()
    status = None
    for line in text.replace("\r", "").split("\n"):
        words = line.split()
        if words[:1] == [label] and len(words) >= 2:
            status = " ".join(words[1:])
    count = EXECUTION_COUNT.search(text)
    executed = last.group(1) != "Yet to be executed" or (count is not None and int(count.group(1)) > 0)
    return {"time": datetime.datetime(int(year), MONTHS.index(month) + 1, int(day), int(hour), int(minute),
                                      int(second)),
            "executed": executed, "status": status}


def _schedule(access, label):
    return schedule(_read(access, "show scheduler schedule name %s" % label), label)


def checkpoints(text: str) -> list:
    return CHECKPOINT_ROW.findall(text.replace("\r", ""))


def checkpoint_created(text: str, label: str):
    """The device time at which checkpoint L was created (show checkpoint summary user: "Created at Mon, 01:10:16
    16 Nov 2026"), or None when L is not listed or the time is not recognised."""
    current = None
    for line in text.replace("\r", "").split("\n"):
        row = CHECKPOINT_ROW.match(line)
        if row is not None:
            current = row.group(1)
            continue
        found = CREATED_AT.match(line.strip())
        if current == label and found is not None and found.group(5) in MONTHS:
            hour, minute, second, day, month, year = found.groups()
            return datetime.datetime(int(year), MONTHS.index(month) + 1, int(day), int(hour), int(minute),
                                     int(second))
    return None


def files(text: str) -> list:
    return FILE_ROW.findall(text.replace("\r", ""))


def objects(access, label) -> dict:
    """Which objects named L exist: scheduler job and schedule (running configuration), checkpoint and the bootflash
    file of the immediate return. The name alone never proves that an object is the own one (see _own)."""
    snapshot = nxos.load(access.query(QUERY_RUNNING), None)
    blocks = [block.header for block in snapshot.scheduler.get(label, [])]
    return {
        "job": "scheduler job name %s" % label in blocks,
        "schedule": "scheduler schedule name %s" % label in blocks,
        "checkpoint": label in checkpoints(access.query(QUERY_CHECKPOINTS)),
        "file": "%s-pred.cfg" % label in files(access.query(QUERY_FILES)),
    }


def leftovers(access) -> list:
    snapshot = nxos.load(access.query(QUERY_RUNNING), None)
    found = {"scheduler %s" % name for name in snapshot.safeguard_names()}
    found |= {"checkpoint %s" % name for name in checkpoints(access.query(QUERY_CHECKPOINTS))
              if name.startswith(nxos.SAFEGUARD_PREFIX)}
    found |= {"bootflash:%s" % name for name in files(access.query(QUERY_FILES))
              if name.startswith(nxos.SAFEGUARD_PREFIX)}
    return sorted(found)


def minutes(seconds: int) -> int:
    """M of `time start +M`: the real delay is in (M-1, M] minutes, so M-1 whole minutes cover safeguard_seconds."""
    return -(-int(seconds) // 60) + 1


def timer_seconds(device) -> float:
    """How long the job protects the change on the monotonic clock of Admin, counted from the moment before the
    installation started: `time start +M` runs at the next whole minute plus M-1 minutes after the device took the
    line, so at least M-1 minutes later, less the drift allowance of the device clock. execute.py takes the shorter
    of this and the lead the device itself reported (safeguard.lead_seconds)."""
    return (minutes(device.safeguard_seconds) - 1) * 60 * (1 - DRIFT_FRACTION)


def install_lines(label: str, seconds: int) -> list:
    return [
        "checkpoint %s" % label,
        "configure terminal",
        "scheduler job name %s" % label,
        "rollback running-config checkpoint %s atomic" % label,
        "exit",
        "scheduler schedule name %s" % label,
        "job name %s" % label,
        "time start +%d" % minutes(seconds),
        "end",
        "no checkpoint %s" % label,
        "checkpoint %s" % label,
        "copy running-config %s" % pred_file(label),
    ]


# what an accepted line of install_lines (1-based) proves the own session did: (object, now own, phase). An object
# is the own one only when the line that creates it was answered without an error in the own session, right after
# the name was read free of every object; the name derived from the change ID alone is never enough.
INSTALL_EFFECTS = {
    1: ("checkpoint", True, "placeholder checkpoint"),
    3: ("job", True, "job created"),
    6: ("schedule", True, "schedule created"),
    8: (None, None, "armed before the checkpoint holds the job"),
    10: ("checkpoint", False, "placeholder checkpoint removed"),
    11: ("checkpoint", True, "checkpoint holds the job and the schedule"),
    12: ("file", True, "installed"),
}


def _own(record) -> dict:
    own = (record.get("safeguard") or {}).get("own")
    return {kind: isinstance(own, dict) and own.get(kind) is True for kind in KINDS}


def install_safeguard(access, record, plan, device, spec, journal=None) -> list:
    """Install the safeguard (variant 3) and note, line by line, which objects the own session created.

    The name must be free of every object right before (a foreign object of the same name is left alone and the
    installation is not started). Each accepted creating line marks its object as own in record["safeguard"]["own"]
    and the journal saves it at once, so an interrupted installation is recognised by recover (its phase) and only
    own objects are ever removed. Verified afterwards: all four objects, an empty rollback patch (the checkpoint holds
    the job and the schedule), a pending schedule and its lead: the schedule time less the creation time of the
    checkpoint, both on the device clock (the device clock itself is never compared with Admin's)."""
    label = safeguard_label(record["change_id"])
    item = record["safeguard"]
    item["minutes"] = minutes(device.safeguard_seconds)
    item["own"] = {kind: False for kind in KINDS}
    item["phase"] = "name check"
    note = journal if journal is not None else (lambda: None)
    found = objects(access, label)
    if any(found.values()):
        return ["objects named %s exist before the installation (%s); they are not the own ones and are left alone"
                % (label, ", ".join(kind for kind in KINDS if found[kind]))]
    item["phase"] = "installing"
    note()

    def answered(number, _answer):
        effect = INSTALL_EFFECTS.get(number)
        if effect is None:
            return
        kind, own, phase = effect
        if kind is not None:
            item["own"][kind] = own
        item["phase"] = phase
        note()

    access.line_answered = answered
    try:
        access.apply(install_lines(label, device.safeguard_seconds), spec)
    finally:
        access.line_answered = None
    problems = []
    found = objects(access, label)
    missing = sorted(name for name, present in found.items() if not present)
    if missing:
        problems.append("safeguard objects are missing: %s" % ", ".join(missing))
    if "Rollback Patch is Empty" not in access.query("show diff rollback-patch running-config checkpoint %s"
                                                     % label):
        problems.append("the safeguard checkpoint does not hold the scheduler job and schedule")
    pending = _schedule(access, label)
    if pending is None or pending["executed"]:
        problems.append("the safeguard schedule is missing or has already run")
        return problems
    created = checkpoint_created(access.query(QUERY_CHECKPOINTS), label)
    if created is None:
        problems.append("the creation time of the safeguard checkpoint is not readable")
        return problems
    lead = (pending["time"] - created).total_seconds()
    # time start +M was taken before the checkpoint was made again, so the schedule runs at most M minutes and,
    # as measured, more than M-1 minutes less the few seconds of the installation after it
    if not (item["minutes"] - 2) * 60 < lead <= item["minutes"] * 60:
        problems.append("the safeguard schedule runs %d s after its checkpoint, not as time start +%d gives"
                        % (lead, item["minutes"]))
    item["device_time"] = pending["time"].strftime("%Y-%m-%d %H:%M:%S")
    item["lead_seconds"] = max(0.0, (lead - 1) * (1 - DRIFT_FRACTION))
    return problems


def _refused_in_progress(exc) -> bool:
    return IN_PROGRESS in str(exc)


def _cleanup(access, record, spec) -> None:
    """Remove the own objects only: the schedule and the job (a pending schedule first, so the job can no longer
    start; after the run the job first, as measured, again while the switch answers "schedule in progress"), then
    the checkpoint and the file; the checkpoint stays while a job or a schedule of the name exists."""
    label = safeguard_label(record["change_id"])
    own = _own(record)
    waited = 0
    while True:
        found = objects(access, label)
        item = _schedule(access, label) if found["schedule"] else None
        order = ("job", "schedule") if item is not None and item["executed"] else ("schedule", "job")
        try:
            for kind in order:
                if found[kind] and own[kind]:
                    access.apply(["configure terminal", "no scheduler %s name %s" % (kind, label), "end"], spec)
        except Exception as exc:
            if not _refused_in_progress(exc) or waited >= CLEANUP_LIMIT_SECONDS:
                raise
            PAUSE(CLEANUP_PAUSE_SECONDS)
            waited += CLEANUP_PAUSE_SECONDS
            continue
        break
    found = objects(access, label)
    if found["job"] or found["schedule"]:
        return
    if found["checkpoint"] and own["checkpoint"]:
        access.apply(["no checkpoint %s" % label], spec)
    if found["file"] and own["file"]:
        access.apply(["delete %s no-prompt" % pred_file(label)], spec)


def remove_safeguard(access, record, spec) -> bool:
    try:
        _cleanup(access, record, spec)
    except Exception:
        pass
    return safeguard_absent(access, record)


def _remaining(access, record) -> list:
    found = objects(access, safeguard_label(record["change_id"]))
    return [kind for kind in KINDS if found[kind]]


def manual_cleanup(label: str, remaining) -> str:
    return ("left on the switch: %s named %s. Check by hand that they are not someone else's, then: configure "
            "terminal / no scheduler schedule name %s / no scheduler job name %s / end / no checkpoint %s / delete "
            "%s no-prompt / copy running-config startup-config. A job that still answers 'schedule in progress' "
            "after its run is removed only by 'no feature scheduler', which creates a system checkpoint and evicts "
            "the oldest one (decision of the switch administrator); enable the feature again afterwards"
            % (", ".join(remaining), label, label, label, label, pred_file(label)))


def discard_installation(access, record, spec) -> tuple:
    """Remove the safeguard of a change that was never sent: an unverified or interrupted installation, in any
    phase. Only the objects the own session proved it created are removed; a pending schedule first, so a job that
    its checkpoint does not hold yet (the phase between time start and the second checkpoint, which blocks the
    scheduler when it runs, measured as variant 1) does not start when this removal succeeds before the minute of
    the job (after an interruption, only when recover runs in time); a job that already ran or a failed removal is
    left to the manual procedure. (True, short detail) when none of the name is left;
    else (False, short detail) and the manual procedure in record["safeguard"]["manual_cleanup"] (the journal; the
    audit log takes only short details)."""
    label = safeguard_label(record["change_id"])
    item = record.setdefault("safeguard", {})
    phase = item.get("phase")
    try:
        _cleanup(access, record, spec)
    except Exception:
        pass
    try:
        remaining = _remaining(access, record)
    except Exception as exc:
        item["manual_cleanup"] = manual_cleanup(label, list(KINDS))
        return False, "the state of the safeguard is not readable (%s); see safeguard.manual_cleanup" % (
            type(exc).__name__)
    if not remaining:
        return True, "installation phase %s; no object of the safeguard is left" % phase
    item["manual_cleanup"] = manual_cleanup(label, remaining)
    return False, "installation phase %s; left: %s; see safeguard.manual_cleanup" % (phase, ", ".join(remaining))


def remove_remaining(access, record, spec) -> bool:
    return discard_installation(access, record, spec)[0]


def safeguard_absent(access, record) -> bool:
    """No own object of the safeguard is left (an object of the name that the own session did not create is not the
    safeguard of this operation)."""
    try:
        found = objects(access, safeguard_label(record["change_id"]))
    except Exception:
        return False
    own = _own(record)
    return not any(found[kind] and own[kind] for kind in KINDS)


def safeguard_disarmed(access, record) -> bool:
    """The job can no longer run: its schedule is gone (job, checkpoint or file may remain)."""
    try:
        return _schedule(access, safeguard_label(record["change_id"])) is None
    except Exception:
        return False


def job_ran(access, label) -> bool:
    """The scheduler logfile holds the output of job L, or the rollback log names checkpoint L with an end time."""
    if re.search(r"^Job Name\s*:\s*%s\s" % re.escape(label), access.query(QUERY_SCHEDULER_LOG), re.MULTILINE):
        return True
    log = _read(access, QUERY_ROLLBACK_EXEC)
    return (re.search(r"^Checkpoint name\s*:\s*%s\s*$" % re.escape(label), log, re.MULTILINE) is not None
            and "End Time UTC" in log)


def safeguard_fired(access, record) -> bool:
    """The job can no longer change the configuration: its schedule is gone (removed by someone; the job never ran)
    or it ran to its end (the schedule reports an execution, no rollback is running, and the scheduler logfile or
    the rollback log shows the rollback to checkpoint L). Decided by reading the scheduler, never by the device
    clock; whether the configuration returned decides the snapshot. Unreadable is not ended: execute.py keeps asking
    until its wait limit on the monotonic clock of Admin."""
    label = safeguard_label(record["change_id"])
    try:
        item = _schedule(access, label)
        if item is None:
            return True
        if not item["executed"] or rollback_running(_read(access, QUERY_ROLLBACK_VERIFY)):
            return False
        return job_ran(access, label)
    except Exception:
        return False


def revert_now(access, record, spec) -> bool:
    """Return the change at once: configure replace with the own file saved right after the installation (it holds
    the job and the schedule, so the replace never deletes them). Sent while the job is pending (execute.py sends it
    only with REVERT_NOW_SECONDS of the own timer left) and after the job ran to its end (a line written late or a
    change of someone else after the timed return); never while a rollback is running. True when it was sent."""
    label = safeguard_label(record["change_id"])
    if not _own(record)["file"] or not objects(access, label)["file"]:
        return False
    item = _schedule(access, label)
    if rollback_running(_read(access, QUERY_ROLLBACK_VERIFY)):
        return False
    if item is not None and item["executed"] and not job_ran(access, label):
        return False
    access.apply(["configure replace %s" % pred_file(label)], spec)
    return True


def before_write(access, record, left, device):
    """None when the change may be written: the own schedule is still pending (read now) and, on the monotonic
    clock of Admin, enough of the timer is left for the write, the readback and the confirmation margin; else the
    reason (nothing is written then)."""
    needed = WRITE_BUDGET_SECONDS + READBACK_BUDGET_SECONDS + device.confirm_margin_seconds
    if left < needed:
        return "%d s of the safeguard left, %d s needed to write, read back and confirm" % (max(left, 0), needed)
    if not all(_own(record).values()):
        return "the safeguard is not proven the own one"
    try:
        item = _schedule(access, safeguard_label(record["change_id"]))
    except Exception as exc:
        return "the scheduler schedule is not readable (%s)" % type(exc).__name__
    if item is None or item["executed"]:
        return "the own scheduler job is no longer pending"
    return None


def line_allowed(left) -> bool:
    return left >= LINE_MARGIN_SECONDS


def persist(access, spec) -> bool:
    access.apply(["copy running-config startup-config"], spec)
    if access.query(QUERY_DIFF).strip():
        raise Rejected(["the running configuration still differs from the startup configuration after the save"])
    return True




SAVE_DIFF_HEADERS = ("*** Startup-config", "--- Running-config")
SAVE_DIFF_SEPARATOR = "***************"
SAVE_OLD_RANGE = re.compile(r"\*\*\* (\d+)(?:,(\d+))? \*\*\*\*")
SAVE_NEW_RANGE = re.compile(r"--- (\d+)(?:,(\d+))? ----")
# Preserve ordinary statements, including free-form descriptions, while withholding credential syntax and
# opaque payloads (for example, an indented key or certificate).
SAVE_PUBLIC = re.compile(
    r"(?:!?|end(?:-job)?|(?:no )?(?:shutdown|switchport|ip routing|ip domain-lookup)"
    r"|(?:description|remark) [^\t]+|(?:no )?(?:feature|hostname) [\w.-]+"
    r"|(?:interface|vrf context|vrf member|spanning-tree mode|switchport mode) [\w./-]+"
    r"|(?:ip address|ipv6 address|router-id) [\da-fA-F:./]+(?: secondary)?"
    r"|(?:ip route|ipv6 route|ip router ospf|router (?:ospf|bgp)|address-family|network|neighbor"
    r"|route-target|channel-group|spanning-tree (?:port type|priority)|vpc|mtu|speed|duplex)"
    r"(?: [\w.:/*-]+)+"
    r"|(?:vlan|switchport (?:access vlan|trunk (?:allowed|native) vlan)) (?:add |remove )?[\d,-]+"
    r"|(?:ntp (?:server|peer|source-interface)|logging (?:server|source-interface)"
    r"|ip (?:name-server|domain-name))(?: [\w.:/-]+)+"
    r"|(?:scheduler (?:job|schedule) name|job name) [\w.-]+"
    r"|rollback running-config checkpoint [\w.-]+ atomic)"
)
SAVE_SECRET = re.compile(
    r"(?i)(?:\b(?:password|passwd|passphrase|secret|token|community|key(?:-string)?|keychain|psk|enc"
    r"|encrypted|priv|auth|authentication|authpriv|cookie|localizedv2key)\b"
    r"|-----BEGIN|-----END)"
)


def _public_save_row(line, secrets):
    prefix, statement = line[:2], line[2:].strip()
    if not SAVE_SECRET.search(statement) and not any(secret in statement for secret in secrets) \
            and SAVE_PUBLIC.fullmatch(statement):
        return line
    return prefix + "[redacted]"


def _save_diff_unreadable():
    return Rejected(["NX-OS did not return a complete running/startup diff"],
                    reason_codes=["nxos_save_diff_unreadable"])


def _range_count(pattern, line):
    match = pattern.fullmatch(line)
    if not match:
        raise _save_diff_unreadable()
    start = int(match[1])
    end = int(match[2] or match[1])
    if end < start or (start == 0 and match[2] is not None):
        raise _save_diff_unreadable()
    return end - start + 1 if start else 0


def parse_save_diff(text, *, secrets=()):
    """Validate NX-OS context diff hunks before publishing their redacted lines."""
    normalized = text.replace("\r\n", "\n").strip("\n")
    digest = hashlib.sha256(normalized.encode()).hexdigest()
    if not normalized:
        return {"diff_sha256": digest, "diff": []}
    header, *hunks = normalized.split("\n" + SAVE_DIFF_SEPARATOR + "\n")
    if tuple(header.split("\n")) != SAVE_DIFF_HEADERS or not hunks or re.search(
            r"[\x00-\x08\x0b-\x1f\x7f\ufffd]", normalized):
        raise _save_diff_unreadable()
    public = list(SAVE_DIFF_HEADERS)
    for hunk in hunks:
        lines = hunk.split("\n")
        new_index = next((index for index, line in enumerate(lines[1:], 1) if SAVE_NEW_RANGE.fullmatch(line)), None)
        if new_index is None:
            raise _save_diff_unreadable()
        old_size = _range_count(SAVE_OLD_RANGE, lines[0])
        new_size = _range_count(SAVE_NEW_RANGE, lines[new_index])
        before, after = lines[1:new_index], lines[new_index + 1:]
        _validate_save_hunk(before, after, old_size, new_size)
        public.extend((SAVE_DIFF_SEPARATOR, lines[0], *(_public_save_row(line, secrets) for line in before),
                       lines[new_index], *(_public_save_row(line, secrets) for line in after)))
    return {"diff_sha256": digest, "diff": public}


def _validate_save_hunk(before, after, old_size, new_size):
    old_prefixes = ("  ", "- ", "! ") if after else ("  ", "- ")
    new_prefixes = ("  ", "+ ", "! ") if before else ("  ", "+ ")
    if (any(not line.startswith(old_prefixes) for line in before)
            or any(not line.startswith(new_prefixes) for line in after)):
        raise _save_diff_unreadable()
    old_context = [line for line in before if line.startswith("  ")]
    new_context = [line for line in after if line.startswith("  ")]
    # An insertion-only hunk omits the old body. A deletion-only hunk omits the new body.
    # The matching context in the populated body still accounts for the omitted range.
    if (old_size != len(before or new_context) or new_size != len(after or old_context)
            or (before and after and old_context != new_context)
            or len(old_context) + len(new_context) == len(before) + len(after)):
        raise _save_diff_unreadable()


def read_save_diff(access):
    try:
        status, text = access.query_status(QUERY_DIFF)
    except AccessError as exc:
        raise service_read_error(exc, saving=True) from None
    if status != 0:
        raise _save_diff_unreadable()
    credentials = (getattr(access, "credential", None), getattr(access, "check_credential", None))
    secrets = tuple(item.use() for item in credentials if getattr(item, "kind", None) == "password")
    return parse_save_diff(text, secrets=secrets)


ROUTE4_ROW = re.compile(r"^\s*(\S+), configured nh: (\S+)")
ROUTE6_ROW = re.compile(r"^\s*(\S+) -> (\S+), preference: ([0-9]+)\s*$")
INTERFACE4 = re.compile(r"^\s+Internet Address is (\S+)", re.MULTILINE)
INTERFACE6 = re.compile(r"^\s+([0-9A-Fa-f:]+/[0-9]{1,3}) +\[[A-Z]+\]\s*$", re.MULTILINE)


def route_readback(text, key):
    vrf, network = nxos.route_key(key)
    vrf = vrf or "default"
    heading = ('Static-route for VRF "%s"' if network.version == 4 else
               'IPv6 Configured Static Routes for VRF "%s"') % vrf
    if (not any(line.startswith(heading + "(") for line in text.splitlines())
            or (network.version == 4 and "IPv4 Unicast Static Routes:" not in text.splitlines())):
        raise nxos.unreadable("static route table")
    pattern = ROUTE4_ROW if network.version == 4 else ROUTE6_ROW
    found = []
    for line in text.splitlines():
        row = pattern.match(line)
        if row is not None and row[1] == str(network):
            try:
                hop = ipaddress.ip_interface(row[2])
                if hop.version != network.version or hop.network.prefixlen != hop.max_prefixlen:
                    raise ValueError
                found.append({"next-hop": str(hop.ip), **({"distance": row[3]} if network.version == 6 else {})})
            except ValueError:
                raise nxos.unreadable("static route next hop") from None
        elif line.lstrip().startswith(str(network) + (" " if network.version == 6 else ",")):
            raise nxos.unreadable("static route row")
    if len(found) > 1:
        raise nxos.unreadable("single-next-hop static route")
    return found[0] if found else None


def relay_state(text, key):
    rows = [line.split() for line in text.splitlines() if line.strip()]
    if (len(rows) < 2 or rows[0] != ["Interface", "Relay", "Address", "VRF", "Name"]
            or len(rows[1]) != 3 or any(set(word) != {"-"} for word in rows[1])):
        raise nxos.unreadable("DHCP relay address table")
    entries = {}
    for row in rows[2:]:
        if (len(row) not in (2, 3) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9./-]*", row[0])
                or (len(row) == 3 and not nxos.VRF.fullmatch(row[2]))):
            raise nxos.unreadable("DHCP relay address row")
        try:
            entry = row[0] + ":" + str(ipaddress.IPv4Address(row[1]))
        except ValueError:
            raise nxos.unreadable("DHCP relay IPv4 address") from None
        if entry in entries:
            raise nxos.unreadable("duplicate DHCP relay address row")
        entries[entry] = {"vrf": row[2]} if len(row) == 3 else {}
    return entries.get(key)


def relay_config_state(text, key, firmware):
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    required = {"feature dhcp", "service dhcp", "ip dhcp relay"}
    if (not lines or lines[0] != "!Command: show running-config dhcp" or nxos.firmware_of(text) != firmware
            or not required.issubset(lines)
            or any("--More--" in line or nxos.cli_error("\n" + line) for line in lines)):
        raise nxos.unreadable("DHCP running configuration")
    interface, server = key.split(":")
    found = []
    in_interface = False
    for line in lines:
        if not line.startswith(" "):
            in_interface = line == "interface " + interface
        elif in_interface and line.lstrip().startswith("ip dhcp relay address"):
            match = nxos.RELAY.fullmatch(line.strip())
            if match is None or (match[2] is not None and not nxos.VRF.fullmatch(match[2])):
                raise nxos.unreadable("configured DHCP relay address row")
            try:
                address = str(ipaddress.IPv4Address(match[1]))
            except ValueError:
                raise nxos.unreadable("configured DHCP relay IPv4 address") from None
            if address == server:
                found.append({"vrf": match[2]} if match[2] is not None else {})
    if len(found) > 1:
        raise nxos.unreadable("duplicate configured DHCP relay address")
    return found[0] if found else None


def relay_readback(access, plan):
    key = plan["key"]
    try:
        operational = relay_state(access.check_query("show ip dhcp relay address"), key)
        configured = relay_config_state(access.query("show running-config dhcp"), key, plan["firmware"])
    except AccessError:
        raise nxos.unreadable("DHCP relay readback") from None
    if operational != configured:
        raise nxos.unreadable("agreement between DHCP relay table and running configuration")
    return operational


def _configured_state(access, plan):
    snapshot = nxos.load(access.snapshot(), plan["firmware"])
    entry = snapshot.entries(plan["table"]).get(plan["key"])
    if entry is None:
        return None
    if entry.unsupported:
        raise nxos.unreadable("configured state")
    return dict(entry.attributes)




SERVICE_COMMANDS = {
    nxos.NTP_SERVER: "show ntp peers",
    nxos.NTP_SOURCE: "show ntp source-interface",
    nxos.SYSLOG_SERVER: "show logging server",
    nxos.SYSLOG_SOURCE: "show logging source-interface",
    nxos.DNS_SERVER: "show hosts",
    nxos.DNS_DOMAIN: "show hosts",
}
LOG_LEVELS = ("emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational", "debugging")


def _service_unreadable():
    return Rejected(["NX-OS service readback is incomplete or inconsistent"],
                    reason_codes=["nxos_service_readback_unreadable"])


def service_read_error(exc, *, saving=False):
    if re.search(r"timed out|timeout|did not finish within", str(exc), re.IGNORECASE):
        if saving:
            return Rejected(["the NX-OS save preflight read timed out"], reason_codes=["nxos_save_read_timeout"])
        return Rejected(["the NX-OS service read timed out"], reason_codes=["nxos_service_read_timeout"])
    return _save_diff_unreadable() if saving else _service_unreadable()


def _ntp_servers(text):
    if not text.strip():
        return set()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if (len(lines) < 4 or not re.fullmatch("-+", lines[0]) or not re.fullmatch("-+", lines[2])
            or lines[1].split() != ["Peer", "IP", "Address", "Serv/Peer"]):
        raise _service_unreadable()
    servers = set()
    for line in lines[3:]:
        match = re.fullmatch(r"(\S+)\s+(Server|Peer)(?:\s+\((?:configured|dynamic)\))?", line)
        if not match:
            raise _service_unreadable()
        address = nxos.service_address(match[1])
        if address and match[2] == "Server":
            servers.add(address)
    return servers


def _logging_servers(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) == 1 and re.fullmatch(r"Logging server:\s+disabled", lines[0]):
        return {}
    if not lines or not re.fullmatch(r"Logging server:\s+enabled", lines[0]):
        raise _service_unreadable()
    state, result = None, {}
    expected = {"severity", "facility", "VRF", "port"}
    for line in lines[1:]:
        heading = re.fullmatch(r"\{([A-Za-z0-9.:-]+)\}", line)
        if heading:
            host = nxos.service_address(heading[1]) or heading[1]
            if (state is not None and set(state) != expected) or host in result:
                raise _service_unreadable()
            state = result[host] = {}
        elif line != "This server is temporarily unreachable":
            field = re.fullmatch(r"server (severity|facility|VRF|port):\s+(\S+)", line)
            if not field or state is None or field[1] in state:
                raise _service_unreadable()
            state[field[1]] = field[2]
    if state is None or set(state) != expected:
        raise _service_unreadable()
    return result


def _source_interface(table, text):
    line = text.strip()
    if table == nxos.NTP_SOURCE:
        if line == "No Source interface configured":
            return {}
        source = re.fullmatch(r"Source interface\s+(\S+)", line)
    else:
        if re.fullmatch(r"Logging source-interface\s*:\s*disabled", line):
            return {}
        source = re.fullmatch(r"Logging source-interface\s*:\s*enabled \(Interface: (\S+)\)", line)
    if not source or not nxos.SERVICE_INTERFACE.fullmatch(source[1]):
        raise _service_unreadable()
    return {"source-interface": source[1]}


def _dns_hosts(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or not re.fullmatch(r"DNS lookup (?:enabled|disabled)", lines[0]):
        raise _service_unreadable()
    domains, addresses = {}, {}
    context, route, saw_config = "default", None, False
    for line in lines[1:]:
        if re.fullmatch(r"Host\s+Address", line):
            if saw_config:
                return domains, addresses
            break
        vrf = re.fullmatch(r"Vrf Name: (\S+)(?:\s+Default domain is (\S+))?", line)
        other = re.fullmatch(r"(\S+)\s+(\S+)\s+(name-server\(s\)|domain-name)\s+(.+)", line)
        if vrf:
            context, route = vrf[1], None
            if vrf[2]:
                domains[context] = {"domain": vrf[2]}
        elif other:
            saw_config = True
            context, route = other[1], other[2]
            if other[3] == "domain-name":
                domains[context] = {"domain": other[4], "vrf": route}
            else:
                _dns_host_addresses(addresses, context, route, other[4])
        elif line.startswith("Name servers are"):
            saw_config = True
            route = None
            values = line[len("Name servers are"):].strip()
            if values != "255.255.255.255":
                _dns_host_addresses(addresses, context, route, values)
        elif route and nxos.service_address(line):
            _dns_host_addresses(addresses, context, route, line)
        elif (not re.fullmatch(r"Name/address lookup (?:uses|does not use) domain service", line)
              and not re.fullmatch(r"Vrf\s+Use-vrf\s+Token\s+Config", line)):
            raise _service_unreadable()
    raise _service_unreadable()


def _dns_host_addresses(addresses, context, route, values):
    for value in values.split():
        address = nxos.service_address(value)
        if address is None:
            raise _service_unreadable()
        key = address if context == "default" else context + "/" + address
        entry = {"vrf": route} if route and route != "default" else {}
        if key in addresses and addresses[key] != entry:
            raise _service_unreadable()
        addresses[key] = entry


def observe_service(access, plan):
    table, key = plan["table"], plan["key"]
    try:
        configured = _configured_state(access, plan)
        if table in (nxos.DNS_SERVER, nxos.DNS_DOMAIN):
            # NX-OS network-operator cannot run show hosts. The write credential supplies a separate
            # operational read, which must agree with the running-config view before and after a write.
            status, text = access.query_status(SERVICE_COMMANDS[table])
        else:
            status, text = access.check_query_status(SERVICE_COMMANDS[table])
    except AccessError as exc:
        raise service_read_error(exc) from None
    except SnapshotRejected:
        raise _service_unreadable() from None
    if status or re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufffd]|--More--", text):
        raise _service_unreadable()
    if table == nxos.NTP_SERVER:
        present = key in _ntp_servers(text)
        if present != (configured is not None):
            raise _service_unreadable()
        observed = configured
    elif table in nxos.SERVICE_SOURCE_PREFIX:
        configured = configured or {}
        observed = _source_interface(table, text)
    elif table == nxos.SYSLOG_SERVER:
        entry = _logging_servers(text).get(key)
        if entry is None:
            observed = None
        elif entry["severity"] in LOG_LEVELS:
            observed = {"severity": str(LOG_LEVELS.index(entry["severity"]))}
            if entry["VRF"] != "default":
                observed["vrf"] = entry["VRF"]
        else:
            raise _service_unreadable()
        if configured is not None:
            configured = {"severity": "5", **configured}
    else:
        domains, addresses = _dns_hosts(text)
        if table == nxos.DNS_DOMAIN:
            configured = configured or {}
            observed = domains.get(key, {})
        else:
            observed = addresses.get(key)
    if observed != configured:
        raise _service_unreadable()
    return configured


def _interface_command(key):
    for pattern, prefix in ((nxos.SVI, "vlan "), (nxos.LOOPBACK, "loopback ")):
        match = pattern.fullmatch(key)
        if match:
            return prefix + match[1]
    return key


def _acl_read_error(exc):
    if re.search(r"timed out|timeout", str(exc), re.IGNORECASE):
        return Rejected(["the NX-OS ACL read timed out"], reason_codes=["nxos_acl_read_timeout"])
    return nxos.acl_unreadable("readback or preflight")


def acl_plan_prechecks(access, plan, snapshot_text):
    snapshot = nxos.load(snapshot_text, plan["firmware"])
    table, key = plan["table"], plan["key"]
    bindings = nxos.acl_references(snapshot, key) if table == nxos.ACL_TABLE else {key}
    if not bindings:
        return
    try:
        _require_oob_management(access, snapshot)
        for interface in sorted({binding.split(":")[0] for binding in bindings}):
            message = "ACL changes on active interface %s require endpoint_impact naming %s" % (interface, key)
            impact = plan.get("endpoint_impact") == key
            if nxos.SVI.fullmatch(interface):
                state = access.query("show interface " + _interface_command(interface))
                if nxos.svi_operational(state, interface) and not impact:
                    raise Rejected([message], reason_codes=["endpoint_impact_required"])
                continue
            short = nxos.short_name(interface)
            routed = nxos.acl_port_is_routed(snapshot, interface)
            status = nxos.status_row(access.query(f"show interface {interface} status"), interface)
            if status is None:
                raise nxos.acl_unreadable("port status")
            active = status["status"] == "connected"
            if status["status"] not in ("connected", "notconnec", "notconnect", "disabled") or short in nxos.trunk_ports(
                    access.query(QUERY_TRUNKS)):
                raise Rejected(["the ACL port has an unsupported state or is an uplink"], reason_codes=["port_uplink"])
            if (status["vlan"] == "routed") != routed:
                raise nxos.acl_unreadable("port mode in the running configuration")
            if not routed and not status["vlan"].isdigit():
                raise nxos.acl_unreadable("access port VLAN")
            if short in nxos.lldp_ports(access.query(QUERY_LLDP)):
                raise Rejected(["the ACL port has an LLDP neighbor"], reason_codes=["port_lldp_neighbor"])
            if short in nxos.cdp_ports(access.query("show cdp neighbors")):
                raise Rejected(["the ACL port has a CDP neighbor"], reason_codes=["port_cdp_neighbor"])
            if active and not impact:
                raise Rejected([message], reason_codes=["endpoint_impact_required"])
            if nxos.learned_macs(access.query(f"show mac address-table interface {interface}")) and not active:
                raise Rejected(["the ACL port has a learned MAC address"], reason_codes=["port_learned_mac"])
    except AccessError as exc:
        raise _acl_read_error(exc) from None


def _acl_check_query(access, command):
    read_status = getattr(access, "check_query_status", None)
    status, text = read_status(command) if read_status else (0, access.check_query(command))
    if status or nxos.cli_error(text):
        raise nxos.acl_unreadable("query")
    return text


ACL_SUMMARY_INTERFACE = re.compile(r"([A-Za-z][\w./-]*) - (ingress|egress) \([A-Za-z0-9 -]+\)")
ACL_ACTIVE_LABEL = "Active on interfaces:"


def acl_summary(text, family, name):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    if (len(lines) < 4 or lines[0] != f"{family.upper()} ACL {name}"
            or lines[2] != "Configured on interfaces:" or lines.count(ACL_ACTIVE_LABEL) != 1):
        raise nxos.acl_unreadable("summary")
    count = re.fullmatch(r"Total ACEs Configured: ([0-9]+)", lines[1])
    boundary = lines.index(ACL_ACTIVE_LABEL)
    if count is None or boundary < 3:
        raise nxos.acl_unreadable("summary")

    def interfaces(rows):
        matches = [ACL_SUMMARY_INTERFACE.fullmatch(row) for row in rows]
        if any(match is None for match in matches):
            raise nxos.acl_unreadable("summary interfaces")
        return {(match[1], "in" if match[2] == "ingress" else "out") for match in matches}

    configured = interfaces(lines[3:boundary])
    active = interfaces(lines[boundary + 1:])
    if not active <= configured:
        raise nxos.acl_unreadable("agreement between configured and active interfaces")
    return int(count[1]), configured


def _read_acl(access, family, name):
    cli = nxos.ACL_FAMILIES[family]
    command = f"show {cli} access-lists {name}"
    summary = acl_summary(_acl_check_query(access, command + " summary"), family, name)
    text = _acl_check_query(access, command)
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if not lines and summary is None:
        return None, set()
    header = ("IP" if family == "ipv4" else "IPv6") + " access list " + name
    if not lines or lines[0] != header or summary is None or any(not line[0].isspace() for line in lines[1:]):
        raise nxos.acl_unreadable("definition")
    try:
        rules = nxos.acl_rules(",".join(lines[1:]), family)
    except Rejected:
        raise nxos.acl_unreadable("entries") from None
    sequence = [int(line.split()[0]) for line in lines[1:]]
    count, configured = summary
    if len(rules) != count or sequence != list(rules):
        raise nxos.acl_unreadable("rule count or order")
    return ({"rules": ", ".join(rules.values())} if rules else {}), configured


def _read_acl_binding(access, plan, interface, family, direction, *, pending_acls=()):
    command = "show running-config interface " + _interface_command(interface)
    text = access.query(command)
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    header = f"interface {interface}"
    if (not lines or not lines[0].startswith("!Command: show running-config interface ")
            or sum(line == header for line in lines) != 1 or nxos.firmware_of(text) != plan["firmware"]
            or not text.replace("\r", "").endswith("\n\n") or nxos.cli_error(text)):
        raise nxos.acl_unreadable("interface configuration")
    body = lines[lines.index(header) + 1:]
    if any(not line.startswith(nxos.INDENT) for line in body):
        raise nxos.acl_unreadable("interface configuration")
    state = nxos.acl_binding_state([line.strip() for line in body], family, direction)
    names = {side["acl"] for side in (state, *plan.get("predicted", {}).values()) if side}
    for name in sorted(names):
        definition, configured = _read_acl(access, family, name)
        if definition is None and state.get("acl") != name and family + ":" + name in pending_acls:
            continue
        if not definition or ((interface, direction) in configured) != (state.get("acl") == name):
            raise nxos.acl_unreadable("agreement between the interface and the check account's ACL summary")
    return state


def observe_acl(access, plan, *, pending_acls=()):
    try:
        if plan["table"] == nxos.ACL_TABLE:
            return _read_acl(access, *plan["key"].split(":"))[0]
        return _read_acl_binding(access, plan, *plan["key"].split(":"), pending_acls=pending_acls)
    except AccessError as exc:
        raise _acl_read_error(exc) from None


def observe_state(access, plan):
    key, table = plan["key"], plan["table"]
    if table == nxos.RELAY_TABLE:
        return relay_readback(access, plan)
    state = _configured_state(access, plan)
    if table == nxos.ROUTE_TABLE:
        vrf, network = nxos.route_key(key)
        family = "ip" if network.version == 4 else "ipv6"
        seen = route_readback(access.check_query("show %s static-route vrf %s" % (
            family, vrf or "default")), key)
        if seen is not None and state is not None and network.version == 4:
            # NX-OS configured-route CLI has no preference column for IPv4.
            seen["distance"] = state["distance"]
        return seen

    interface = _interface_command(key)
    command = "show interface " + interface
    text = access.check_query(command)
    if state is None and "Syntax error while parsing '%s'" % command in text:
        return None
    if not re.search(r"^%s is " % re.escape(key), text, re.MULTILINE) or state is None:
        raise nxos.unreadable("interface")
    if nxos.ETHERNET.fullmatch(key):
        status = nxos.status_row(access.check_query("show interface %s status" % key), key)
        if status is None or not status["status"] or not status["vlan"]:
            raise nxos.unreadable("physical port status")
        if (status["vlan"] == "routed") != (state.get("mode") == "routed"):
            raise nxos.unreadable("agreement between physical port status and configured mode")
        admin = re.findall(r"^admin state is (up|down),.*$", text, re.MULTILINE)
        disabled = state.get("admin-state") == "disabled"
        if admin != (["down"] if disabled else ["up"]) or (status["status"] == "disabled") != disabled:
            raise nxos.unreadable("agreement between physical port status and configured admin state")
    addresses = INTERFACE4.findall(text)
    if len(addresses) > 1:
        raise nxos.unreadable("IPv4 interface address")
    state.pop("ipv4-address", None)
    if addresses:
        state["ipv4-address"] = nxos.canonical_address("ipv4-address", addresses[0])
    if "ipv6-address" in state:
        answer = access.check_query("show ipv6 interface " + interface)
        if not re.search(r"^%s, Interface status:" % re.escape(key), answer, re.MULTILINE):
            raise nxos.unreadable("IPv6 interface")
        addresses = INTERFACE6.findall(answer)
        if len(addresses) != 1:
            raise nxos.unreadable("IPv6 interface address")
        state["ipv6-address"] = nxos.canonical_address("ipv6-address", addresses[0])
    return state


def observe_vlan(access, plan, *, pending_ports=()):
    key = plan["key"]
    shown = nxos.vlan_status(access.check_query("show vlan id %s" % key), key)
    if shown is None:
        return None
    if shown["status"] != "active" or set(shown["ports"]) - set(pending_ports):
        raise nxos.unreadable("unused active VLAN %s" % key)
    return {} if shown["name"] == nxos.vlan_name(key) else {"name": shown["name"]}


def observe(access, plan):
    if plan["table"] in nxos.ACL_TABLES:
        return observe_acl(access, plan)
    if plan["table"] in nxos.SERVICE_TABLES:
        return observe_service(access, plan)
    if plan["table"] in nxos.STATE_TABLES:
        return observe_state(access, plan)
    key = plan["key"]
    table = plan["table"]
    if table == nxos.BOUNCE_TABLE:
        return {"admin-state": "disabled"} if interface_operational(access, key)["admin"] == "down" else {}
    if table == nxos.CHANNEL_TABLE:
        row = _channel_summary(access).get(key)
        if row is None:
            return None
        shown = nxos.switchport(access.check_query("show interface %s switchport" % key), key)
        if row["layer"] != "S" or shown["switchport"] != "Enabled" or shown["mode"] not in ("access", "trunk"):
            raise nxos.unreadable("Layer 2 port-channel mode")
        return {"mode": shown["mode"]}
    if table == nxos.CHANNEL_MEMBER_TABLE:
        for row in _channel_summary(access).values():
            if key in row["members"]:
                if row["protocol"] != "LACP":
                    raise nxos.unreadable("LACP member protocol")
                return {"group": row["group"]}
        return {}
    if table in nxos.VPC_TABLES:
        topology = _vpc_summary(access)
        if table == nxos.VPC_DOMAIN_TABLE:
            if topology["domain"] is None:
                return None
            if topology["domain"] != key:
                raise nxos.unreadable("vPC domain identity")
            return _keepalive(access)
        short = nxos.short_name(key)
        if table == nxos.VPC_PEER_LINK_TABLE:
            return {"peer-link": "enabled"} if topology["peer_link"] == short else {}
        group = topology["assignments"].get(short)
        return {"vpc-id": group} if group is not None else {}
    if plan["table"] == nxos.VLAN_TABLE:
        return observe_vlan(access, plan)
    if plan["table"] == nxos.MEMBERSHIP_TABLE:
        return nxos.membership_status(access.check_query("show interface %s switchport" % key), key)
    description = nxos.description_row(access.check_query(QUERY_DESCRIPTIONS), key)
    status = nxos.status_row(access.check_query("show interface %s status" % key), key)
    if description is None or status is None:
        return None
    state = {"description": description} if description else {}
    if status["status"] == "disabled":
        state["admin-state"] = "disabled"
    return state


def foreign_sessions(access, device) -> int:
    return nxos.users(access.query(QUERY_USERS))[1]


def request(action, device, port, reason, user_request, request_id, endpoint_impact=None):
    from netops_admin.request import parse_request

    body = {"device": device, "table": TABLES[action], "op": "update", "key": str(port), "reason": reason,
            "user_request": user_request, "request_id": request_id, "changes": {"admin-state": "disabled"}}
    if endpoint_impact is not None:
        body["endpoint_impact"] = endpoint_impact
    return parse_request(json.dumps(body).encode("utf-8"))


def preview(runtime, device, action, cycle_request):
    from netops_admin import execute

    try:
        result, refused = execute._preview(runtime, device, cycle_request, action=action)
    except Rejected as exc:
        if not isinstance(exc, execute.BudgetExhausted):
            execute._count_rejection(runtime)
        raise
    if refused:
        execute._count_rejection(runtime)
    if "commands" in result:
        result = dict(result, operation=action, hold_seconds=HOLD_SECONDS)
    return result


def apply(runtime, device, action, cycle_request, *, expected_plan_sha256=None):
    from netops_admin import execute

    try:
        expected = execute._expected_plan(cycle_request, expected_plan_sha256)
    except Rejected:
        execute._count_rejection(runtime)
        raise
    return execute._apply_counted(runtime, device, cycle_request, expected_plan=expected, action=action)


def run_bounce(runtime, adapter, access, record, plan, device, due):
    from netops_admin import audit_gate, engine, execute

    step, settle, finish = execute._step, execute._settle_after_expiry, execute._finish
    key, spec = plan["key"], execute._spec(record)
    remaining = lambda: due - runtime.monotonic()
    deadline = execute._Deadline(runtime, remaining(), "bounce safeguard expired")
    try:
        original = deadline.read(access, interface_operational, key)
        if original != {"admin": "up", "link": plan["cycle_state"]["link"]}:
            raise nxos.unreadable("port state since preview")
    except Exception as exc:
        step(runtime, record, "port_state_unreadable", type(exc).__name__)
        return settle(runtime, access, record, plan, "bounce preflight changed", due)
    refused = before_write(access, record, remaining() - HOLD_SECONDS - LINK_WAIT_SECONDS, device)
    if refused is not None:
        step(runtime, record, "change_not_written", refused)
        return settle(runtime, access, record, plan, "no time left to write", due)
    record["cycle"] = {"before": original}
    step(runtime, record, "change_start")
    failure = None
    access.line_guard = lambda: line_allowed(remaining())
    try:
        access.apply(plan["commands"], spec)
        disabled = deadline.read(access, interface_operational, key)
        record["cycle"]["off"] = disabled
        if disabled != {"admin": "down", "link": "down"}:
            raise nxos.unreadable("port shutdown readback")
        step(runtime, record, "port_off")
        runtime.sleep(HOLD_SECONDS)
    except Exception as exc:
        failure = "bounce shutdown unverified"
        step(runtime, record, "change_failed", type(exc).__name__)
    finally:
        try:
            # The shutdown may have succeeded even if its SSH session failed. Send the inverse in a fresh session.
            access.apply(plan["inverse"], spec)
            step(runtime, record, "port_restore_sent")
        except Exception as exc:
            failure = "bounce restore unverified"
            step(runtime, record, "port_restore_failed", type(exc).__name__)
        finally:
            access.line_guard = None
    if failure is not None:
        return settle(runtime, access, record, plan, failure, due)
    try:
        until = min(runtime.monotonic() + LINK_WAIT_SECONDS, due - device.confirm_margin_seconds)
        link_deadline = execute._Deadline(runtime, until - runtime.monotonic(), "bounce link readback expired")
        state = link_deadline.read(access, interface_operational, key)
        while state["admin"] == "up" and original["link"] == "up" and state["link"] != "up":
            if link_deadline.left() <= 3:
                break
            runtime.sleep(2)
            state = link_deadline.read(access, interface_operational, key)
        record["cycle"]["after"] = state
        if state["admin"] != "up":
            raise nxos.unreadable("restored administrative state")
    except Exception as exc:
        step(runtime, record, "postcheck_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "bounce readback unverified", due)
    if original["link"] == "up" and state["link"] != "up":
        failure = "link not up after the bounce"
        step(runtime, record, "postcheck_failed", failure)
        return settle(runtime, access, record, plan, failure, due)
    try:
        step(runtime, record, "port_restored", state["link"])
        text = deadline.read(access, lambda reader: reader.snapshot())
        if (accounts_check(access, device, text) != record["accounts"]
                or engine.verify(plan, text.encode(), expect="before")["result"] != "match"):
            raise nxos.unreadable("restored configuration")
        record["audit_coverage"] = audit_gate.evaluate("nxos", text, record["audit_policy"], plan["table"],
                                                       record["audit_before"])
        step(runtime, record, "postcheck_passed")
    except Exception as exc:
        step(runtime, record, "postcheck_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "bounce readback unverified", due)
    if remaining() < device.confirm_margin_seconds:
        return settle(runtime, access, record, plan, "no time left to confirm", due)
    step(runtime, record, "confirm_start")
    if not remove_safeguard(access, record, spec):
        return settle(runtime, access, record, plan, "confirmation unverified", due)
    try:
        result = engine.verify(plan, access.snapshot().encode(), expect="before")
    except Exception:
        return finish(runtime, record, "unknown", "final check unavailable")
    if result["result"] != "match":
        return finish(runtime, record, "unknown", "foreign change after the safeguard was removed", result["differences"])
    # The preflight required running and startup to agree. The inverse restored that configuration.
    if not execute._persist(runtime, adapter, access, record):
        return finish(runtime, record, "confirmed", "not persisted")
    return finish(runtime, record, "confirmed")


def recover_bounce(runtime, adapter, access, record, plan, restored):
    from netops_admin import execute

    if not restored:
        return execute._finish(runtime, record, "unknown", "interrupted; bounce configuration differs")
    try:
        state = interface_operational(access, plan["key"])
    except (AccessError, Rejected):
        return execute._finish(runtime, record, "unknown", "interrupted; bounce link unreadable")
    if state["admin"] != "up" or (plan["cycle_state"]["link"] == "up" and (
            record.get("cycle", {}).get("after", {}).get("link") != "up" or state["link"] != "up")):
        return execute._finish(runtime, record, "unknown", "interrupted; bounce link restoration unverified")
    saved = execute._persist(runtime, adapter, access, record)
    return execute._finish(runtime, record, "confirmed", "confirmed before the interruption" if saved else "not persisted")


# ---- 1.0.12 nxos targeted clear: targeted clear of counters, MAC and ARP/ND entries (nxos_clear) ----

def clear_device_prechecks(access, device, snapshot_text) -> str:
    """What a clear needs from the switch: the running version (for firmware_support, never a block). The safeguard
    preconditions of a configuration change (feature scheduler, no unsaved configuration, no open session) do not
    apply: a clear writes no configuration and has no timed return."""
    try:
        return nxos.nxos_version(access.query(QUERY_VERSION))
    except AccessError:
        raise Rejected(["the NX-OS version could not be read before the clear"],
                       reason_codes=["clear_readback_unreadable"]) from None


def observe_clear(access, table, target):
    try:
        text = access.check_query(target.read)
    except AccessError:
        raise Rejected(["the check account could not read the NX-OS clear target"],
                       reason_codes=["clear_readback_unreadable"]) from None
    return nxos_clear.observation(table, target, text)


def _refuse_clear(why):
    raise Rejected(["the selected clear scope includes a protected object: " + why],
                   reason_codes=["clear_protected_target"])


def _lldp_neighbors(access) -> set:
    """Ports with an LLDP neighbor; a switch with `feature lldp` disabled (measured on the switch-pair nodes: `show lldp
    neighbors` is a syntax error there) has none; an unknown feature state is unreadable."""
    state = nxos.feature_state(access.query(QUERY_FEATURE), "lldp")
    if state == "disabled":
        return set()
    if state != "enabled":
        raise nxos.unreadable("LLDP feature state")
    return nxos.lldp_ports(access.query(QUERY_LLDP))


def clear_prechecks(access, device, table, target, before, snapshot_text="") -> list:
    """A read that fails or times out refuses the clear with its own code (nothing was sent)."""
    try:
        return _clear_prechecks(access, device, table, target, before, snapshot_text)
    except AccessError:
        raise Rejected(["a read before the NX-OS clear failed or timed out"],
                       reason_codes=["clear_readback_unreadable"]) from None


def _clear_prechecks(access, device, table, target, before, snapshot_text="") -> list:
    """The protections of the port path apply to the clear scope and to every learned entry it removes: protected
    interfaces and VLANs, management interfaces and the management VRF, trunks, port-channels, peer-links and other
    non-Ethernet ports, ports with an LLDP or CDP neighbor (uplinks), and an SVI that carries the Admin SSH session.
    An unreadable answer refuses the clear."""
    protected = device.protected
    interfaces = {nxos_clear.ethernet(name) or name.casefold()
                  for name in (*protected.get("interface", ()), *protected.get("ports", ()))}
    vlans = {str(name) for name in protected.get("vlan", ())}
    if target.key.casefold() in {str(name).casefold() for name in protected.get(table, ())}:
        _refuse_clear("%s is protected" % target.key)
    if target.vrf is not None and target.vrf.casefold() == "management":
        _refuse_clear("VRF management carries the management interface")
    learned = [entry for entry in before.get("entries", ()) if entry["dynamic"]]
    ports, svis, mgmt = set(), set(), False
    if table == "port-counters":
        ports.add(nxos.short_name(target.value))
    for entry in learned:
        if table == "mac-address-table":
            ports.add(entry["port"])
            if entry["vlan"] in vlans:
                _refuse_clear("a learned entry is in the protected VLAN %s" % entry["vlan"])
            if entry["vlan"].isdigit():
                svis.add("Vlan" + entry["vlan"])
            if entry["flags"].strip("*") or not nxos.SHORT_PORT.fullmatch(entry["port"]) or not entry["port"].startswith("Eth"):
                _refuse_clear("a learned entry is not on a physical Ethernet port (port-channel, peer-link or "
                              "overlay)")
        else:
            name = entry["interface"]
            mgmt = mgmt or nxos.MANAGEMENT.fullmatch(name) is not None
            match = nxos.SVI.fullmatch(name)
            if match:
                svis.add(name)
                if match[1] in vlans:
                    _refuse_clear("a learned entry is on the protected interface %s" % name)
            elif name.startswith(("Ethernet", "port-channel", "Eth", "Po")):
                ports.add(nxos.short_name(name))
    if mgmt:
        _refuse_clear("a learned entry is on the management interface")
    learned_interfaces = {entry["interface"] for entry in learned if "interface" in entry}
    named = sorted(name for name in ports | learned_interfaces
                   if (nxos_clear.ethernet(name) or name.casefold()) in interfaces)
    if named:
        _refuse_clear("interface %s is protected" % ",".join(named))
    if ports:
        uplinks = sorted(ports & (nxos.trunk_ports(access.query(QUERY_TRUNKS)) | _lldp_neighbors(access)
                                  | nxos.cdp_ports(access.query("show cdp neighbors"))))
        if uplinks:
            _refuse_clear("port %s is a trunk or has an LLDP or CDP neighbor (uplink or managed device)"
                          % ",".join(uplinks))
        if any(port.startswith("Po") for port in ports):
            _refuse_clear("a port-channel is not cleared")
    if svis and snapshot_text:
        snapshot = nxos.load(snapshot_text, None)
        for svi in sorted(svis):
            _protect_svi_ssh(access, snapshot, svi)
    return ["scope: %s; not protected, no trunk, LLDP or CDP neighbor, no management path"
            % (", ".join(sorted(ports | svis)) or target.key)]
