"""Cisco IOS and IOS XE execution adapter (measured on IOSv 15.9(3)M12, IOSvL2 15.2(20200924:215240), IOL XE 17.18.2
and IOL-L2 XE 17.18.2, ref/mereni-c4c5).

Safeguard first, as execute.py needs it: ``configure terminal revert timer N`` followed by ``end`` saves the running
configuration to a new archive file and starts an absolute timer of N minutes (the granularity is one minute, so
``safeguard_seconds`` is rounded up). The change then runs line by line through ``configure terminal`` in an
interactive session: an SSH exec command of IOS has exit status 0 even when IOS refuses it and takes one line only,
so it is never used for configuration. Confirmation is ``configure confirm``; an expired timer replaces the WHOLE
running configuration with the archive (IOS XE at once, IOS within about 7 seconds, during which the timer is still
shown). The timer belongs to the device, not to the session: any privilege-15 session can confirm, extend or start
the return, so a pending timer of anyone refuses the operation, and ``write memory`` runs only when no timer is
pending (during a pending timer it saves the unconfirmed state without a warning).

The state of the safeguard comes from ``show archive config rollback timer`` (the timer of the device: time
configured, minutes, user) and ``show archive`` (the archive taken at the start); the log lines ARCHIVE_DIFF-5-
ROLLBK_CNFMD_CHG_* add evidence when they are still in the buffer (IOL keeps 4096 bytes, which a few SSH logins
overwrite).

Admin never reads the device clock (the clock of the measured IOSv was hours off and drifted). Its own timer is the
one whose installation the output of its own session proves (``Backing up current running config to <archive>``,
not ``already activated``) and whose ``Time configured``, user and minutes it recorded right after; a timer of the
same account without that proof is never confirmed, returned or otherwise touched. The time left is counted on the
monotonic clock of Admin from the moment before the timer was requested (TIMER_WATCH in execute.py); before the
change is written the own timer must still be pending with enough time left, and every configuration line is sent
only while some time is left. A failed write or readback of a normal operation is returned at once with ``configure
revert now`` from the own session; Admin waits for the expiry (by reading the timer, never the clock) only where
that fails, for the enrollment self-test (left unconfirmed on purpose) and for ``admin recover``. ``configure
confirm`` and ``configure revert now`` are sent only after ``show archive config rollback timer`` in the same
interactive session, right before them, still shows the own timer; the timer is global and has no owner, so this
narrows the gap between the check and the command to a fraction of a second but cannot close it.
"""
from __future__ import annotations

import datetime
import hashlib
import re

from netops_admin import ios
from netops_admin.errors import Rejected
from netops_admin.exec_fortios import PromptSpec

# the safeguard is watched on the monotonic clock of Admin, not on the device clock (execute.py: TIMER_WATCH)
TIMER_WATCH = True
FIRE_AT_TEXT = "device revert timer"
# The shortest timer is 2 minutes (the device has whole minutes, 1-120). Measured (ref/mereni-c4c5/ops.log, max of
# 4 nodes): "configure terminal revert timer" 5.8 s, PTY login 1.6 s (2.9 s with the IOSv banner), an exec read
# 1.1 s, show running-config 6.1 s, a configuration line 1.0 s, configure confirm 0.2 s. Until the change is written
# Admin spends about 13 s (install 9 s, three timer and archive reads); then it needs WRITE_BUDGET_SECONDS for the
# write session, READBACK_BUDGET_SECONDS for the snapshot, the check account and the final snapshot, and
# confirm_margin_seconds (15-45 s) to confirm. One minute (58.8 s with the drift allowance) leaves too little even
# with the smallest margin (13 + 20 + 20 + 15 = 68 s); two minutes leave 117.6 s.
MIN_MINUTES = 2
# the measured IOSv clock drifted by 35 s in 34 minutes (1.7 %); the timer runs on the device clock, so Admin
# counts it 2 % shorter
DRIFT_FRACTION = 0.02
# a write session: login 2.9 s + at most 5 lines of 1.0 s, about 8 s measured
WRITE_BUDGET_SECONDS = 20
# snapshot 6.1 s + check account 1.1 s + final snapshot 6.1 s, about 13 s measured
READBACK_BUDGET_SECONDS = 20
# a configuration line takes at most 1.0 s (measured); a line is sent only while this much of the timer is left
LINE_MARGIN_SECONDS = 10
REVERT_NOW = "configure revert now"
BACKING_UP = re.compile(r"Rollback Confirmed Change: Backing up current running config to (\S+)")
ROLLING_TO = re.compile(r"Rollback Confirmed Change: rolling to:\s*(\S+)")
QUERY_TIMER = "show archive config rollback timer"
QUERY_ARCHIVE = "show archive"
QUERY_VERSION = "show version"
QUERY_PRIVILEGE = "show privilege"
QUERY_UNSAVED = "show archive config differences nvram:startup-config system:running-config"
QUERY_LLDP = "show lldp neighbors"
QUERY_CDP = "show cdp neighbors"
QUERY_USERS = "show users"
QUERY_TCP = "show tcp brief"
QUERY_ADDRESSES = "show ip interface brief"
QUERY_LOG = "show logging | include ROLLBK_CNFMD_CHG"
QUERY_DESCRIPTIONS = "show interfaces description"
ABSOLUTE = "absolute timer"
SAFEGUARD_PREFIX = "netops-"
# the check of doctor: the check account reads the interface description table and must not have privilege 15
IDENTITY_KEY = "description table"
# the device ends an expired timer itself; the log proves it only while the lines are in the buffer, so a return is
# accepted on the running configuration equal to the state before (engine.verify), never on the log alone
FIRING_OBSERVED = False
HOSTNAME = re.compile(r"^hostname (\S+)\s*$", re.MULTILINE)
ACCOUNT_LINES = ("username ", "enable ", "aaa ", "no aaa ")


def parse_clock(text: str) -> tuple:
    """Device time of show clock as a naive datetime in the zone of the device, and the zone name.

    Kept to read the measured answers only: the executor never reads the device clock (the clock of the lab IOSv was
    hours off and drifted; the safeguard is watched on the monotonic clock of Admin and by reading the timer)."""
    match = ios.CLOCK.search(text)
    if match is None or match.group(5) not in ios.MONTHS:
        raise Rejected(["the device clock is not readable"])
    hour, minute, second, zone, month, day, year = match.groups()
    return datetime.datetime(int(year), ios.MONTHS.index(month) + 1, int(day), int(hour), int(minute),
                             int(second)), zone


def parse_timer(text: str):
    """None for "%No Rollback Confirmed Change pending", else the pending revert timer of the device."""
    stripped = text.strip()
    if stripped == ios.NO_PENDING:
        return None
    found = {name: pattern.search(text) for name, pattern in ios.TIMER.items()}
    if any(match is None for match in found.values()):
        raise Rejected(["the revert timer answer (show archive config rollback timer) is not recognised"])
    clock_text, zone, _weekday, month, day, year = found["configured"].group(1).split()
    if month not in ios.MONTHS:
        raise Rejected(["the revert timer answer names no known month"])
    hour, minute, second = (int(part) for part in clock_text.split(":"))
    return {"configured": datetime.datetime(int(year), ios.MONTHS.index(month) + 1, int(day), hour, minute, second),
            "zone": zone, "type": found["type"].group(1), "minutes": int(found["minutes"].group(1)),
            "user": found["user"].group(1)}


def prompt_spec(hostname: str) -> PromptSpec:
    # measured prompts: "d-iosv#", "d-iosv(config)#", "d-iosv(config-if)#"; the read-only account has "d-iosv>"
    return PromptSpec(anchor=("\n%s" % hostname).encode("ascii"), ends=(b"#", b">"), continuation=None,
                      error=ios.cli_error)


def safeguard_label(change_id: str) -> str:
    # IOS gives the revert timer no name; the label only names the operation in the journal and the audit log, the
    # identity of the safeguard is the archive file and the time configured of the timer (record["safeguard"])
    return SAFEGUARD_PREFIX + change_id[:12]


def hostname(access, snapshot_text: str) -> str:
    found = HOSTNAME.findall(snapshot_text.replace("\r", ""))
    if len(found) != 1:
        raise Rejected(["the running configuration does not name one hostname"])
    return found[0]


def _query(access, command: str, what: str) -> str:
    text = access.query(command)
    if ios.refused(text):
        raise Rejected(["the device refused %s (%s)" % (command, what)])
    return text


def _login(access):
    login = getattr(getattr(access, "credential", None), "login", None)
    if not login:
        raise Rejected(["the login of the write account is not known"])
    return login


def accounts_check(access, device, snapshot_text) -> str:
    snapshot = ios.load(snapshot_text, device.firmware)
    present = sorted({line.split()[1] for line in snapshot.lines
                      if line.startswith("username ") and len(line.split()) >= 2})
    if present != sorted(device.accounts):
        raise Rejected(["the device accounts differ from the expected list (%d present, %d expected)"
                        % (len(present), len(device.accounts))])
    lines = sorted(line for line in snapshot.lines if line.startswith(ACCOUNT_LINES))
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def pending(access):
    return parse_timer(_query(access, QUERY_TIMER, "revert timer"))


def prechecks(access, device, snapshot_text, spec) -> list:
    reasons = []
    level = ios.privilege(_query(access, QUERY_PRIVILEGE, "privilege"))
    if level != 15:
        raise Rejected(["the write account logs in with privilege %d; Admin needs privilege 15 at login (username "
                        "... privilege 15) and never sends enable" % level], reason_codes=["write_account_privilege"])
    running = ios.version(_query(access, QUERY_VERSION, "version"))
    if running["version"] != device.firmware:
        reasons.append("the device runs %s, not the configured %s" % (running["version"], device.firmware))
    if running["xe"] != (device.platform == "iosxe"):
        reasons.append("the device runs %s, not the configured platform %s"
                       % ("IOS XE" if running["xe"] else "IOS", device.platform))
    found = pending(access)
    if found is not None:
        raise Rejected(["a revert timer of %s is pending on the device (configured %s %s, %d min); the timer is "
                        "global, so Admin neither starts its own nor confirms it"
                        % (found["user"], found["configured"].strftime("%H:%M:%S"), found["zone"], found["minutes"])],
                       reason_codes=["rollback_timer_pending"])
    ios.archive(_query(access, QUERY_ARCHIVE, "archive"))
    differing = ios.unsaved(_query(access, QUERY_UNSAVED, "startup and running configuration"))
    if differing:
        reasons.append("the device has unsaved configuration changes of someone else (%d lines differ between "
                       "startup-config and running-config); Admin saves the configuration after its change"
                       % len(differing))
    return reasons


def _management(access, snapshot) -> tuple:
    """Interfaces that carry the SSH sessions of the device (show tcp brief, show ip interface brief) and the VLANs
    of such interfaces (an SVI VlanN); IOS accepts every change on them, so Admin refuses them."""
    addresses = ios.session_addresses(_query(access, QUERY_TCP, "TCP connections"))
    interfaces = dict(snapshot.addresses())
    interfaces.update(ios.ip_interfaces(_query(access, QUERY_ADDRESSES, "interface addresses")))
    found = {interfaces[address] for address in addresses if address in interfaces}
    if not found:
        raise Rejected(["the management interface (the local address of the SSH session) cannot be identified; "
                        "the change is refused"], reason_codes=["port_usage_unreadable"])
    vlans = {name[len("Vlan"):] for name in found if re.fullmatch(r"Vlan[0-9]+", name)}
    return found, vlans


def plan_prechecks(access, device, plan, snapshot_text="") -> list:
    key, table = plan["key"], plan["table"]
    if table not in ("interface", "vlan-membership"):
        return []
    snapshot = ios.load(snapshot_text, device.firmware)
    if key not in snapshot.interfaces:
        raise Rejected(ios.absent(snapshot, table, key))
    management, management_vlans = _management(access, snapshot)
    if key in management:
        raise Rejected(["interface %s carries the management address; Admin never changes it" % key],
                       reason_codes=["port_management_interface"])
    switch = ios.version(_query(access, QUERY_VERSION, "version"))["switch"]
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    shown = None
    if switch:
        shown = ios.switchport(access.query("show interfaces %s switchport" % key), key)
        if shown is None:
            raise Rejected(["the switch does not report interface %s" % key], reason_codes=["port_usage_unreadable"])
        if shown["access-vlan"] in management_vlans:
            raise Rejected(["port %s is in the management VLAN %s; Admin never changes it"
                            % (key, shown["access-vlan"])], reason_codes=["port_management_vlan"])
    if table == "vlan-membership":
        if not switch:
            raise Rejected(["the device is a router (image without switchport); an access VLAN cannot be set"],
                           reason_codes=["port_routed"])
        wanted = str((after or {}).get("access-vlan", ios.DEFAULT_VLAN))
        if wanted in management_vlans:
            raise Rejected(["VLAN %s is the management VLAN; Admin never puts a port into it" % wanted],
                           reason_codes=["port_management_vlan"])
        if not ios.vlan_exists(_query(access, "show vlan id %s" % wanted, "VLAN"), wanted):
            raise Rejected(["VLAN %s does not exist on the switch; IOS would create it and a rollback would not "
                            "remove a VLAN of the normal range, so the change is refused" % wanted],
                           reason_codes=["vlan_missing"])
        plan["prechecks"].append("VLAN %s exists" % wanted)
    plan["prechecks"].append("interface %s does not carry the management address (%s)"
                             % (key, ", ".join(sorted(management))))
    if table == "interface" and not ios.disruptive(table, before, after):
        return []
    if switch and shown["mode"] != "static access":
        raise Rejected(["port %s is in %s mode, not static access; it is treated as an uplink" % (key, shown["mode"])],
                       reason_codes=["port_uplink"])
    if ios.short_name(key) in ios.lldp_ports(_query(access, QUERY_LLDP, "LLDP neighbors")):
        raise Rejected(["port %s has an LLDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    if ios.cdp_name(key) in ios.cdp_ports(_query(access, QUERY_CDP, "CDP neighbors")):
        raise Rejected(["port %s has a CDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    if switch:
        if ios.learned_macs(_query(access, "show mac address-table interface %s" % key, "MAC table"), key):
            raise Rejected(["port %s has learned MAC addresses; changing a port in use is refused" % key],
                           reason_codes=["port_learned_mac"])
        plan["prechecks"].append("port %s is a static access port without LLDP/CDP neighbor and learned MAC address"
                                 % key)
    else:
        plan["prechecks"].append("interface %s has no IPv4 address and no LLDP/CDP neighbor" % key)
    return []


def ports(access, table: str):
    return None


def leftovers(access) -> list:
    found = pending(access)
    if found is None or found["user"] != _login(access):
        return []
    return ["revert timer of %s configured %s %s" % (found["user"], found["configured"].strftime("%Y-%m-%d %H:%M:%S"),
                                                     found["zone"])]


def _minutes(seconds: int) -> int:
    return max(MIN_MINUTES, -(-seconds // 60))


def timer_seconds(device) -> float:
    """How long the own timer protects the change on the monotonic clock of Admin, counted from the moment before
    it was requested: its minutes less the drift allowance of the device clock."""
    return _minutes(device.safeguard_seconds) * 60 * (1 - DRIFT_FRACTION)


def _answers(access) -> list:
    return list(getattr(access, "last_answers", ()) or ())


def install_safeguard(access, record, plan, device, spec) -> list:
    """Start the own revert timer and prove that it is the own one.

    The proof is the answer of the own session: "Backing up current running config to <archive>" without "already
    activated" (the device refuses a second timer), the new most recent archive of show archive with that name, and
    the pending timer of the write account with the requested minutes. Only then item["verified"] is set, and only
    such a timer is ever confirmed or returned by Admin. A refused installation is marked item["install"] =
    "refused" (nothing was changed); any other problem leaves the timer alone (execute.py records unknown)."""
    minutes = _minutes(device.safeguard_seconds)
    item = record["safeguard"]
    item["seconds"] = device.safeguard_seconds
    item["minutes"] = minutes
    before = ios.archive(_query(access, QUERY_ARCHIVE, "archive"))["recent"]
    try:
        access.apply(["configure terminal revert timer %d" % minutes, "end"], spec)
        failure = None
    except Exception as exc:
        failure = exc
    answers = _answers(access)
    first = answers[0] if answers else ""
    if any(line.strip().startswith(ios.ALREADY_ACTIVE) for line in first.replace("\r", "").split("\n")):
        item["install"] = "refused"
        return ["the device refused the revert timer: %s (a timer of someone else is pending)" % ios.ALREADY_ACTIVE]
    backed_up = BACKING_UP.search(first)
    if backed_up is not None:
        item["archive"] = backed_up.group(1)
    if failure is not None:
        return ["safeguard installation failed (%s)" % type(failure).__name__]
    if backed_up is None:
        return ["the own session did not report the archive of the revert timer (Backing up ... to <archive>)"]
    found = pending(access)
    recent = ios.archive(_query(access, QUERY_ARCHIVE, "archive"))["recent"]
    if found is None:
        return ["no revert timer is pending after configure terminal revert timer"]
    if found["user"] != _login(access) or found["type"] != ABSOLUTE or found["minutes"] != minutes:
        return ["the pending revert timer is not the absolute %d-minute timer of the write account" % minutes]
    if recent != item["archive"] or recent == before:
        return ["the most recent archive is not the one the own session saved for the revert timer"]
    item["configured"] = found["configured"].strftime("%Y-%m-%d %H:%M:%S")
    item["zone"] = found["zone"]
    item["verified"] = True
    return []


def _owned(access, record, found) -> bool:
    """The pending timer is the own one: its installation was proven by the own session (item["verified"]) and it
    still has the recorded time configured, minutes and user. Account and time alone are never enough."""
    item = record.get("safeguard") or {}
    if found is None or item.get("verified") is not True or found["user"] != _login(access):
        return False
    return (found["configured"].strftime("%Y-%m-%d %H:%M:%S") == item.get("configured")
            and found["minutes"] == item.get("minutes") and found["type"] == ABSOLUTE)


def before_write(access, record, left, device):
    """None when the change may be written: the own timer is still pending (read now) and, on the monotonic clock
    of Admin, enough of it is left for the write, the readback and the confirmation margin; else the reason."""
    needed = WRITE_BUDGET_SECONDS + READBACK_BUDGET_SECONDS + device.confirm_margin_seconds
    if left < needed:
        return "%d s of the safeguard left, %d s needed to write, read back and confirm" % (max(left, 0), needed)
    try:
        found = pending(access)
    except Exception as exc:
        return "the revert timer is not readable (%s)" % type(exc).__name__
    if not _owned(access, record, found):
        return "the own revert timer is no longer pending"
    return None


def line_allowed(left) -> bool:
    return left >= LINE_MARGIN_SECONDS


def safeguard_state(access, record) -> str:
    """armed (the own timer is pending), fired or disarmed (the log names the return to the own archive or the
    confirmation after its start), or absent (no own timer and no log evidence: confirmed, returned or never
    started, and the log lines may be out of the buffer)."""
    found = pending(access)
    if _owned(access, record, found):
        return "armed"
    archive = (record.get("safeguard") or {}).get("archive")
    if archive:
        try:
            outcome = ios.archive_outcome(ios.archive_events(access.query(QUERY_LOG)), archive, _login(access))
        except Exception:
            outcome = None
        if outcome == "fired":
            return "fired"
        if outcome == "confirmed":
            return "disarmed"
    return "absent"


def _session_timer(answer: str):
    """The revert timer from the answer of show archive config rollback timer in the interactive session (the
    first row is the echo of the command, the last one the prompt)."""
    rows = [row.strip() for row in answer.replace("\r", "").split("\n")[1:]]
    if ios.NO_PENDING in rows:
        return None
    return parse_timer(answer)


def _send_owned(access, record, command: str, spec) -> tuple:
    """Send configure confirm or configure revert now only while the own timer is pending, read in the same
    interactive session right before the command (show archive config rollback timer); a timer that is gone or
    not the own one there leaves the command unsent. The timer is global and has no owner, so the read and the
    command are still not atomic (docs/admin-configuration.md). (sent, answer of the command)."""
    previous, sent = access.line_guard, []

    def guard():
        if previous is not None and not previous():
            return False
        answers = _answers(access)
        if not answers:
            return True
        try:
            owned = _owned(access, record, _session_timer(answers[0]))
        except Exception:
            owned = False
        sent.append(owned)
        return owned

    access.line_guard = guard
    try:
        access.apply([QUERY_TIMER, command], spec)
    except Exception:
        pass
    finally:
        access.line_guard = previous
    if sent != [True]:
        return False, ""
    answers = _answers(access)
    return True, answers[1] if len(answers) > 1 else ""


def remove_safeguard(access, record, spec) -> bool:
    """Confirm the own timer. A timer that is not proven own is never confirmed (False while it is pending); the
    timer is read again in the session of configure confirm right before it."""
    try:
        found = pending(access)
        if found is None:
            return True
        if not _owned(access, record, found):
            return False
        if not _send_owned(access, record, "configure confirm", spec)[0]:
            # the own timer was not shown in the session: decided like the read above (gone: True, another: False)
            return pending(access) is None
    except Exception:
        pass
    return safeguard_absent(access, record)


def safeguard_absent(access, record) -> bool:
    try:
        return not _owned(access, record, pending(access))
    except Exception:
        return False


remove_remaining = remove_safeguard


def revert_now(access, record, spec) -> bool:
    """Return the configuration to the own archive at once (configure revert now) after a failed write or
    readback. Sent only while the own timer is pending, read again in the same session right before the command;
    True when the own timer is gone afterwards (the answer "rolling to:<own archive>", or an expiry in between),
    False when the command was not sent or the timer is still pending; then execute.py waits for the expiry."""
    try:
        if not _owned(access, record, pending(access)):
            return False
        sent, answer = _send_owned(access, record, REVERT_NOW, spec)
        if not sent:
            return False
        rolled = ROLLING_TO.search(answer)
        if rolled is not None and rolled.group(1) != record["safeguard"].get("archive"):
            return False
        return pending(access) is None
    except Exception:
        return False


def safeguard_disarmed(access, record) -> bool:
    try:
        return safeguard_state(access, record) == "disarmed"
    except Exception:
        return False


def safeguard_fired(access, record) -> bool:
    """The own timer is no longer pending: IOS ended it (or someone confirmed or returned it). Whether the
    configuration returned is decided by the running configuration against the state before, not by this answer.
    Unreadable is not ended: execute.py keeps asking until its wait limit on the monotonic clock of Admin."""
    try:
        return safeguard_state(access, record) != "armed"
    except Exception:
        return False


def persist(access, spec) -> bool:
    if pending(access) is not None:
        raise Rejected(["write memory is refused while a revert timer is pending: it would save the unconfirmed "
                        "configuration"])
    access.apply(["write memory"], spec)
    return True


def observe(access, plan):
    key = plan["key"]
    if key == IDENTITY_KEY:
        level = ios.privilege(access.check_query(QUERY_PRIVILEGE))
        if level >= 15:
            raise Rejected(["the check account has privilege %d; it must not be able to configure" % level])
        columns, rows = ios.table_rows(access.check_query(QUERY_DESCRIPTIONS), "Interface")
        return None if columns is None or not rows else {}
    if plan["table"] == "vlan-membership":
        shown = ios.switchport(access.check_query("show interfaces %s switchport" % key), key)
        if shown is None or shown["access-vlan"] is None:
            return None
        return {"access-vlan": shown["access-vlan"]}
    row = ios.description_row(access.check_query(QUERY_DESCRIPTIONS), key)
    if row is None:
        return None
    state = {"description": row["description"]} if row["description"] else {}
    if row["status"] == "admin down":
        state["admin-state"] = "disabled"
    return state


def foreign_sessions(access, device) -> int:
    return ios.users(_query(access, QUERY_USERS, "sessions"))[1]
