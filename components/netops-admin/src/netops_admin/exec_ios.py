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
import ipaddress
import re

from netops_admin import ios, ios_acl, ios_save
from netops_admin.access import AccessError
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
EXEC_BANNER_LOST = "exec_banner_lost"
EXEC_BANNER_LOST_REASON = ("The exec banner is missing after the IOS rollback. Restore the banner manually, "
                           "unblock the device, then retry the operation or enrollment.")
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
    snapshot.platform = device.platform
    present = sorted({line.split()[1] for line in snapshot.lines
                      if line.startswith("username ") and len(line.split()) >= 2})
    if present != sorted(device.accounts):
        raise Rejected(["the device accounts differ from the expected list (%d present, %d expected)"
                        % (len(present), len(device.accounts))])
    lines = sorted(line for line in snapshot.lines if line.startswith(ACCOUNT_LINES))
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def pending(access):
    return parse_timer(_query(access, QUERY_TIMER, "revert timer"))


def _identity_prechecks(access, device, *, controller=False) -> tuple[list, dict]:
    reasons = []
    level = ios.privilege(_query(access, QUERY_PRIVILEGE, "privilege"))
    if level != 15:
        raise Rejected(["the write account logs in with privilege %d; Admin needs privilege 15 at login (username "
                        "... privilege 15) and never sends enable" % level], reason_codes=["write_account_privilege"])
    version_output = _query(access, QUERY_VERSION, "version")
    if controller and not ios.C9800_VERSION_LINE.search(version_output):
        raise Rejected(["the write account did not identify a Catalyst 9800 controller"],
                       reason_codes=["clear_scope_unverified"])
    running = ios.version(version_output)
    if running["version"] != device.firmware:
        reasons.append("the device runs %s, not the configured %s; update firmware in the Admin configuration"
                       % (running["version"], device.firmware))
    if running["xe"] != (device.platform == "iosxe"):
        reasons.append("the device runs %s, not the configured platform %s"
                       % ("IOS XE" if running["xe"] else "IOS", device.platform))
    return reasons, running


def prechecks(access, device, snapshot_text, spec, *, saving=False, allow_unsaved=False) -> list:
    try:
        reasons, _ = _identity_prechecks(access, device)
        found = pending(access)
        if found is None and not saving:
            ios.archive(_query(access, QUERY_ARCHIVE, "archive"))
    except Rejected as exc:
        if (saving or allow_unsaved) and exc.reason_codes == ["unspecified_refusal"]:
            code = ios_save.UNREADABLE if saving else "ios_service_read_unreadable"
            raise Rejected(exc.reasons, reason_codes=[code]) from None
        raise
    if found is not None:
        raise Rejected(["a revert timer of %s is pending on the device (configured %s %s, %d min); the timer is "
                        "global, so Admin neither starts its own nor confirms it"
                        % (found["user"], found["configured"].strftime("%H:%M:%S"), found["zone"], found["minutes"])],
                       reason_codes=["rollback_timer_pending"])
    if saving:
        return reasons
    if allow_unsaved:
        return reasons
    differing = ios.unsaved(_query(access, QUERY_UNSAVED, "startup and running configuration"))
    if differing:
        reasons.append("the device has unsaved configuration changes of someone else (%d lines differ between "
                       "startup-config and running-config); Admin saves the configuration after its change"
                       % len(differing))
    return reasons


def clear_prechecks(access, device, target, snapshot_text):
    try:
        reasons, identity = _identity_prechecks(access, device, controller=target.table == ios.WIRELESS_CLIENT)
        if reasons:
            raise Rejected(reasons, reason_codes=["clear_scope_unverified"])
        if target.table == "neighbor-discovery" and identity["xe"] and identity["image"].startswith(
                ("X86_64BI_LINUX-", "X86_64BI_LINUX_L2-")):
            raise Rejected(["per-address IPv6 neighbor clear has no verified command on the IOS XE IOL image"],
                           reason_codes=["iosxe_iol_nd_clear_unsupported"])
        if (target.table == "fdb" and target.port is not None and identity["xe"]
                and identity["image"].startswith("X86_64BI_LINUX_L2-")):
            raise Rejected(["port-scoped MAC clear does not remove MAC entries on IOS XE IOL-L2; select a MAC address"],
                           reason_codes=["iosxe_iol_mac_port_clear_unsupported"])
        observed = observe_clear(access, target)
        _protect_clear(access, device, target, observed, snapshot_text)
    except AccessError as exc:
        raise clear_access_error(exc, target) from None
    return observed


def observe_clear(access, target):
    try:
        rc, text = access.check_query_status(target.read)
        if rc != 0:
            raise ios.clear_unreadable()
        observed = ios.clear_observation(target, text)
        if target.table == "fdb" and not (observed["entries"] or observed["other_entries"]):
            rc, counts = access.check_query_status("show mac address-table count")
            if rc != 0 or not ios.clear_fdb_is_empty(counts):
                raise ios.clear_unreadable()
    except AccessError as exc:
        raise clear_access_error(exc, target) from None
    return observed


def clear_access_error(error, target=None):
    if re.search(r"timed? out|timeout", str(error), re.I):
        if target is not None and target.table == ios.WIRELESS_CLIENT:
            return Rejected(["the Catalyst 9800 client read timed out"],
                            reason_codes=["wireless_client_read_timeout"])
        return Rejected(["the IOS operational clear read timed out"], reason_codes=["clear_read_timeout"])
    return ios.clear_unreadable()


def _protect_clear(access, device, target, observed, snapshot_text):
    if target.table == ios.WIRELESS_CLIENT:
        protected = {ios.clear_mac_address(value) for value in device.protected.get(target.table, ())}
        if target.key in protected:
            raise _clear_protected()
        return
    snapshot = ios.load(snapshot_text, device.firmware)
    policy = device.audit_policy or {}
    protected = device.protected
    protected_keys = protected.get(target.table, ())
    protected_vrfs = {name.casefold() for name in protected.get("vrf", ())}
    if (target.key.casefold() in {value.casefold() for value in protected_keys} or
            target.vrf and (target.vrf.casefold() in protected_vrfs or ios.MANAGEMENT_VRF_NAME.search(target.vrf))):
        raise _clear_protected()
    entries = observed.get("entries", ())
    if target.table == "fdb":
        protected_macs = {ios.clear_mac_address(value) for value in protected_keys}
        if any(row["address"] in protected_macs for row in entries):
            raise _clear_protected()
    ports = {row["port"] for row in entries if row["dynamic"]}
    if target.port:
        ports.add(target.port)
    if not ports:
        return
    if not ports <= snapshot.interfaces.keys():
        raise Rejected(["the interface for the clear scope could not be identified"],
                       reason_codes=["clear_scope_unverified"])
    try:
        management_ports, management_vlans = _management(access, snapshot)
        peers = ios.session_peers(_query(access, QUERY_TCP, "TCP connections")) if target.table == "iparp" else set()
    except Rejected:
        raise Rejected(["the management interfaces or peers for the clear scope could not be identified"],
                       reason_codes=["clear_scope_unverified"]) from None
    management_ports = {ios.clear_interface(name) for name in management_ports}
    protected_ports = {ios.clear_interface(name) for name in
                       (*protected.get("interface", ()), *protected.get("l3-interface", ()),
                        *policy.get("protected_ports", ()))}
    if target.table == "port-counters":
        protected_ports.update(ios.clear_interface(name) for name in protected_keys)
    elif target.table == "fdb":
        protected_ports.update(ios.clear_interface(key[5:]) for key in protected_keys if key.startswith("port:"))
    blocked_ports = {name.casefold() for name in protected_ports | management_ports}
    management_vlans.update(_inventory_management_vlans(device))
    scoped_ports = {port.casefold() for port in ports}
    if (target.key in peers or any(
        port in blocked_ports or port.split(".")[0] in blocked_ports
        or any(name.startswith(port + ".") for name in blocked_ports) for port in scoped_ports
    ) or any(
        ios.SVI.fullmatch(port) and ios.SVI.fullmatch(port)[1] in management_vlans
        or snapshot.management_vrf(port) for port in ports
    )):
        raise _clear_protected()
    if target.table != "fdb":
        return
    if any(row["vlan"] in management_vlans for row in entries):
        raise _clear_protected()
    try:
        lldp = ios.lldp_ports(_read(access, QUERY_LLDP, "LLDP neighbors"))
        cdp = ios.cdp_ports(_read(access, QUERY_CDP, "CDP neighbors"))
        for port in sorted(ports):
            if (not ios.ETHERNET.fullmatch(port) or ios.short_name(port) in lldp or ios.cdp_name(port) in cdp or
                    any(ios.LAG.match(line) for line in snapshot.interface_lines(port))):
                raise _clear_protected()
            _member_switchport(access, port, management_vlans)
    except Rejected as exc:
        if exc.reason_codes == ["port_usage_unreadable"]:
            raise Rejected(["the MAC scope could not be verified as an access port"],
                           reason_codes=["clear_scope_unverified"]) from None
        raise _clear_protected() from None


def _clear_protected():
    return Rejected(["the selected IOS clear scope includes a protected interface, VLAN, VRF or peer"],
                    reason_codes=["clear_protected_target"])


COUNTERS_CONFIRM = b'Clear "show interface" counters on this interface [confirm]'
COUNTERS_AGE = re.compile(r"([0-9]+):([0-5][0-9]):([0-5][0-9])")
ND_DELETE_REFUSED = "% Failed to delete ND entry"


def write_clear(access, spec, target, plan):
    # A moving MAC or a changed set of learned entries invalidates the approved target immediately before the write.
    current = observe_clear(access, target)
    before = plan["predicted"]["before"]
    if ((target.table == "port-counters" and current["link"] != before["link"]) or
            (target.table != "port-counters" and
             [ios.clear_entry_identity(row) for row in current["entries"]] !=
             [ios.clear_entry_identity(row) for row in before["entries"]])):
        raise Rejected(["the IOS operational clear scope changed before the write"], reason_codes=["clear_scope_unverified"])
    if target.table == "port-counters":
        accepted = access.apply([("ask", target.write, COUNTERS_CONFIRM), ""], spec)
        return int(accepted == 2), current
    try:
        return access.apply([target.write], spec), current
    except AccessError:
        if target.table == "neighbor-discovery" and any(
            line.strip() == ND_DELETE_REFUSED for answer in access.last_answers for line in answer.splitlines()
        ):
            raise Rejected(["the device refused to delete the selected IPv6 neighbor"],
                           reason_codes=["clear_command_refused"]) from None
        raise


def clear_readback(target, before, observed, *, platform):
    if target.table == "port-counters":
        previous, current = before["last_clearing"], observed["last_clearing"]
        if platform == "ios" and (not COUNTERS_AGE.fullmatch(current) or (
                previous != "never" and not COUNTERS_AGE.fullmatch(previous)
                and not re.fullmatch(r"[1-9][0-9]*(?:y[0-9]+w|w[0-9]+d|d[0-9]+h)", previous))):
            return False, observed
        prior = ios.clear_counter_age(previous)
        recent = ios.clear_counter_age(current)
        # Busy ports can have packets as soon as the command returns. An unchanged timer is no evidence.
        return recent is not None and prior is not None and recent <= 30 and recent < prior, observed
    other_rows = {frozenset(row.items()) for row in observed["other_entries"]}
    retained = all(frozenset(row.items()) in other_rows for row in before["other_entries"])
    if target.table == "iparp" and len(observed["entries"]) == 1:
        # IOS can refresh the entry by probing the neighbor, whose reply starts its age at zero again.
        old, new = before["entries"][0], observed["entries"][0]
        if new["age"] == 0 and old["age"] > 0 and ios.clear_entry_identity(old) == ios.clear_entry_identity(new):
            if platform == "iosxe":
                # Ordinary ARP traffic can also reset the age of an unchanged binding.
                return False, dict(observed, age_reset=True)
            return retained, dict(observed, refreshed=True)
    return retained and not observed["entries"], observed


def _management(access, snapshot, *, require_all=False) -> tuple:
    """Interfaces that carry the SSH sessions of the device (show tcp brief, show ip interface brief) and the VLANs
    of such interfaces (an SVI VlanN); IOS accepts every change on them, so Admin refuses them."""
    addresses = ios.session_addresses(_query(access, QUERY_TCP, "TCP connections"))
    interfaces = dict(snapshot.addresses())
    interfaces.update(ios.ip_interfaces(_query(access, QUERY_ADDRESSES, "interface addresses")))
    found = {interfaces[address] for address in addresses if address in interfaces}
    if not found or (require_all and not addresses <= interfaces.keys()):
        raise Rejected(["the management interface (the local address of the SSH session) cannot be identified; "
                        "the change is refused"], reason_codes=["port_usage_unreadable"])
    vlans = {name[len("Vlan"):] for name in found if re.fullmatch(r"Vlan[0-9]+", name)}
    return found, vlans


def _inventory_management_vlans(device) -> set[str]:
    policy = getattr(device, "audit_policy", None) or {}
    protected = device.protected or {}
    return {str(vlan) for vlan in (*policy.get("management_vlans", ()), *protected.get("vlan", ()))}


def _read(access, command: str, what: str) -> str:
    """A read of the G62 usage checks: a refused read is an unreadable usage (port_usage_unreadable)."""
    text = access.query(command)
    if ios.refused(text):
        raise ios.unreadable(what)
    return text


def _in_use_prechecks(access, snapshot, plan, management_vlans, undo) -> None:
    """1.0.12 G62 (IOS): an L3 interface that carries traffic of connected devices is not changed blindly.

    A new subinterface or SVI only adds a VLAN tag or a gateway address. Disruptive changes to an existing VLAN with
    learned MACs or a subinterface with a known neighbor are refused. An active parent without discovery neighbors
    needs explicit endpoint impact for the subinterface. Undo returns the state before."""
    key = plan["key"]
    svi, parent = ios.SVI.match(key), ios.SUBINTERFACE.match(key)
    if svi is not None:
        if not any(ios.SVI.fullmatch(name) for name in snapshot.interfaces):
            if snapshot.has_vlan_database:
                default_vlan = snapshot.vlans.get("1")
                if default_vlan is None or default_vlan.unsupported:
                    raise ios.unreadable("VLAN database for SVI support")
            else:
                # Implicit switchport modes can leave no switchport or VLAN allocation lines in running-config.
                listing = access.query("show vlan id 1")
                try:
                    if ios.refused(listing):
                        listing = access.query("show vlan brief")
                        if ios.refused(listing):
                            active = None
                        else:
                            active = ios.vlan_database(listing)["1"][1] == "active"
                    else:
                        active = ios.vlan_exists(listing, "1")
                except Rejected:
                    raise ios.unreadable("VLAN database for SVI support") from None
                if active is None:
                    raise Rejected(["the device did not establish support for SVIs (interface Vlan); %s cannot be changed"
                                    % key], reason_codes=["port_unsupported_interface"])
                if not active:
                    raise ios.unreadable("VLAN database for SVI support")
        if svi.group(1) in management_vlans:
            raise Rejected(["VLAN %s carries the management address; Admin never changes its SVI" % svi.group(1)],
                           reason_codes=["port_management_vlan"])
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    if before is None or undo:
        if before is None and (svi is not None or parent is not None):
            plan["prechecks"].append("%s is a new object; existing traffic of the port or VLAN is not changed" % key)
        return
    disruptive = after is None or any((before.get(name) != after.get(name))
                                      for name in ("ipv4-address", "ipv6-address", "admin-state", "vrf"))
    if not disruptive:
        return
    if parent is not None:
        port = parent.group(1)
        lldp = ios.lldp_ports(_read(access, QUERY_LLDP, "LLDP neighbor list"))
        cdp = ios.cdp_ports(_read(access, QUERY_CDP, "CDP neighbor list"))
        if ios.short_name(port) in lldp or ios.cdp_name(port) in cdp:
            raise Rejected(["the parent port %s of %s has an LLDP/CDP neighbor; changing an existing subinterface of a "
                            "connected port is refused" % (port, key)], reason_codes=["port_lldp_neighbor"])
        row = ios.description_row(access.query(QUERY_DESCRIPTIONS), port, include_protocol=True, require_table=True)
        if row is None or row["status"] not in ("up", "down", "admin down") or row["protocol"] not in ("up", "down"):
            raise ios.unreadable("link status of the parent port %s" % port)
        active = row["status"] == row["protocol"] == "up"
        if active and plan.get("endpoint_impact") != key:
            raise Rejected(["the parent port %s of %s is up/up; changing the existing subinterface requires "
                            "endpoint_impact naming %s" % (port, key, key)], reason_codes=["endpoint_impact_required"])
        plan["prechecks"].append("the parent port %s of %s is %s/%s and has no LLDP/CDP neighbor"
                                 % (port, key, row["status"], row["protocol"]))
    if svi is not None:
        macs = ios.vlan_macs(_read(access, "show mac address-table vlan " + svi.group(1), "MAC address table"),
                             svi.group(1))
        if macs:
            raise Rejected(["VLAN %s has %d learned MAC addresses; changing its SVI %s in use is refused"
                            % (svi.group(1), macs, key)], reason_codes=["port_learned_mac"])
        plan["prechecks"].append("VLAN %s of %s has no learned MAC address" % (svi.group(1), key))


def _state_prechecks(access, device, plan, snapshot_text, undo=False) -> list:
    """1.0.12 G80: a static route or an L3 interface never touches the management path: the management interface
    (local address of the SSH session) and its subinterfaces are refused, and in the VRF of the management interface
    a destination or an interface address may not overlap the management subnet or the SSH client address. A default
    route through the management interface does not refuse other routes (G19 lesson); default routes themselves are
    refused by the plan."""
    key, table = plan["key"], plan["table"]
    snapshot = ios.load(snapshot_text, device.firmware)
    snapshot.platform = device.platform
    management, management_vlans = _management(access, snapshot)
    peers = ios.session_peers(_query(access, QUERY_TCP, "TCP connections"))
    vrfs = {ios.vrf_of(snapshot, name) for name in management}
    guarded = [network for name, _vrf, network in ios.interface_networks(snapshot) if name in management]
    guarded += [ipaddress.ip_network(peer) for peer in sorted(peers)]
    names = []
    for side in (plan["predicted"]["before"], plan["predicted"]["after"]):
        if side is None:
            continue
        if table == ios.ROUTE_TABLE:
            vrf, network = ios.route_key(key)
            names.append((vrf, network))
        else:
            vrf = side.get("vrf")
            names += [(vrf, ipaddress.ip_interface("/".join(side[name].split())).network)
                      for name in ("ipv4-address", "ipv6-address") if name in side]
    if table == ios.L3_TABLE:
        parent = ios.SUBINTERFACE.match(key)
        if key in management or (parent is not None and parent.group(1) in management):
            raise Rejected(["interface %s is or belongs to the management interface; Admin never changes it" % key],
                           reason_codes=["port_management_interface"])
        if device.platform == "ios":
            _in_use_prechecks(access, snapshot, plan, management_vlans, undo)
    for vrf, network in names:
        hit = [str(other) for other in guarded if vrf in vrfs and other.version == network.version
               and other.overlaps(network)]
        if hit:
            raise Rejected(["%s overlaps the management path (%s); Admin never changes it" % (network, ", ".join(hit))],
                           reason_codes=["port_management_interface"])
    plan["prechecks"].append("%s does not touch the management interface (%s), its subnet or the SSH client"
                             % (key, ", ".join(sorted(management))))
    return []


def _loopback_management_egress(access, snapshot, tcp, management):
    loopbacks = {name for name in management if re.fullmatch(r"Loopback[0-9]+", name)}
    if not loopbacks:
        return set()
    addresses = snapshot.addresses()
    addresses.update(ios.ip_interfaces(_query(access, QUERY_ADDRESSES, "interface addresses")))
    paths = {(ios.vrf_of(snapshot, addresses[local]), peer)
             for local, peer in ios.session_pairs(tcp) if addresses.get(local) in loopbacks}
    if not paths:
        raise ios.unreadable("routes to the loopback SSH peers")
    egress = set()
    for vrf, peer in sorted(paths, key=lambda path: (path[0] or "", path[1])):
        if vrf is not None and not ios.VRF_NAME.fullmatch(vrf):
            raise ios.unreadable("the VRF of the loopback SSH peer")
        scope = " vrf " + vrf if vrf else ""
        answer = _query(access, "show ip cef%s %s detail" % (scope, peer), "route to the loopback SSH peer")
        ports = ios.cef_egress(answer, peer)
        if not ports <= snapshot.interfaces.keys():
            raise ios.unreadable("routed interfaces to the loopback SSH peer")
        egress.update(ports)
    return egress


def _acl_checks(access, device, plan, snapshot_text, pending_interfaces=()) -> list:
    """1.0.12 G64: an ACL rule list or an interface attachment never cuts the management path blindly.

    The interfaces concerned are those the ACL is attached to (or the attachment itself). An interface that carries
    the SSH sessions (or is in a management VRF) takes the change only when the inbound ACL still permits SSH from
    every client of the open sessions to the management address (the return traffic of an outbound ACL is checked with
    an unknown port); IPv6 cannot be judged there (show tcp brief lists IPv4 only) and is refused. A name that is
    also used elsewhere (VTY access-class, route-map, NAT, QoS) and an interface that is up need endpoint_impact
    naming the request key. A switchport (port ACL, L2 path) is refused."""
    key, table = plan["key"], plan["table"]
    snapshot = ios.load(snapshot_text, device.firmware)
    snapshot.platform = device.platform
    after = plan["predicted"]["after"]
    if table == ios_acl.ACL:
        family = key.split(":", 1)[0]
        attachments, others = ios_acl.references(snapshot, key)
        interfaces = {interface: {direction for name, direction in attachments if name == interface}
                      for interface, _ in attachments}
        rules_after = (after or {}).get("rules")
        wanted = {(interface, direction): rules_after for interface, direction in attachments}
    else:
        interface, family, direction = key.rsplit(":", 2)
        others, interfaces = [], {interface: {direction}}
        wanted = {(interface, direction): ios_acl.acl_rules(snapshot, family, after["acl"]) if after else None}
    if not interfaces and not others:
        plan["prechecks"].append("%s is not attached to an interface and not used elsewhere" % key)
        return []
    xe = device.platform == "iosxe"
    management, management_vlans = _management(access, snapshot, require_all=xe)
    tcp = _query(access, QUERY_TCP, "TCP connections")
    peers, locals_ = ios.session_peers(tcp), ios.session_addresses(tcp)
    if not peers or not locals_:
        raise ios.unreadable("SSH sessions of the management path")
    if xe:
        management.update(_loopback_management_egress(access, snapshot, tcp, management))
        management_vlans.update(_inventory_management_vlans(device))
    impact = plan.get("endpoint_impact") == key
    needs_impact = bool(others)
    for interface in sorted(interfaces):
        carrying = (interface in management or snapshot.management_vrf(interface)
                    or (ios.SVI.fullmatch(interface) and ios.SVI.fullmatch(interface).group(1) in management_vlans))
        if xe and (svi := ios.SVI.fullmatch(interface)) and svi[1] in management_vlans:
            raise ios_acl.refuse("the ACL SVI carries a management VLAN", "port_management_vlan")
        if xe and any(name == interface or name.startswith(interface + ".") or interface.startswith(name + ".")
                      for name in management):
            raise ios_acl.refuse("the ACL interface carries the management SSH path", "port_management_interface")
        for direction in sorted(interfaces[interface]):
            rules_text = wanted[(interface, direction)]
            if carrying and rules_text is not None:
                if family != "ipv4":
                    raise ios_acl.refuse("%s carries the management path; an IPv6 ACL cannot be checked against the "
                                         "open SSH sessions there" % interface, "port_management_interface")
                if not ios_acl.permits_ssh(rules_text, peers, locals_, direction):
                    raise ios_acl.refuse("the ACL would not permit SSH from every client of the open sessions on %s %s"
                                         % (interface, direction), "port_management_interface")
                plan["prechecks"].append("the ACL on %s %s keeps SSH of the open sessions permitted" % (interface, direction))
        if interface in pending_interfaces:
            needs_impact = needs_impact or pending_interfaces[interface].get("admin-state") != "disabled"
            continue
        try:
            if ios.ETHERNET.fullmatch(interface):
                shown = ios.switchport(access.query("show interfaces %s switchport" % interface), interface)
            else:
                shown = None
            row = ios.description_row(access.query(QUERY_DESCRIPTIONS), interface, include_protocol=True,
                                      require_table=True)
        except Rejected:
            if xe:
                raise ios_acl.refuse("the ACL interface state is unreadable", "ios_acl_readback_unreadable") from None
            raise
        if shown is not None and shown["mode"] != "routed":
            raise ios_acl.refuse("%s is a switchport; ACLs of Layer 2 ports are not supported" % interface,
                                 "port_unsupported_interface")
        statuses = ("up", "down", "admin down", "deleted") if xe else ("up", "down", "admin down")
        if row is None or row["status"] not in statuses or row["protocol"] not in ("up", "down"):
            if xe:
                raise ios_acl.refuse("the ACL interface state is unreadable", "ios_acl_readback_unreadable")
            raise ios.unreadable("link status of %s" % interface)
        active = "up" in (row["status"], row["protocol"]) if xe else row["status"] == row["protocol"] == "up"
        needs_impact |= active
        if xe:
            plan["prechecks"].append("%s is %s/%s and is outside the management path" %
                                     (interface, row["status"], row["protocol"]))
    if others and "vty" in others:
        if family != "ipv4":
            raise ios_acl.refuse("the ACL is the access-class of a VTY line; an IPv6 ACL cannot be checked against the "
                                 "open SSH sessions", "port_management_interface")
        if after is None or "rules" not in after or not ios_acl.permits_ssh(after["rules"], peers, locals_, "in"):
            raise ios_acl.refuse("the ACL is the access-class of a VTY line and would not permit SSH from every client "
                                 "of the open sessions", "port_management_interface")
        plan["prechecks"].append("the VTY access-class keeps SSH of the open sessions permitted")
    if needs_impact and not impact:
        raise ios_acl.refuse("the ACL change reaches an interface that is up or a name that is used elsewhere; it "
                             "requires endpoint_impact naming %s" % key, "endpoint_impact_required")
    plan["prechecks"].append("%s: management path (%s) checked, switchports refused, endpoint impact %s"
                             % (key, ", ".join(sorted(management)), "accepted" if needs_impact else "not needed"))
    return []


def _acl_guarded(call, *args):
    """A failed or timed out read of the ACL checks is its own refusal (not unspecified_refusal; a timeout is no verdict)."""
    from netops_admin.access import AccessError
    try:
        return call(*args)
    except AccessError as exc:
        if "timeout" in str(exc).lower() or "timed out" in str(exc).lower():
            raise ios_acl.refuse("the ACL preflight or readback timed out", "ios_acl_read_timeout") from None
        raise ios_acl.refuse("the ACL preflight or readback could not read the device",
                             "ios_acl_readback_unreadable") from None


def _acl_prechecks(access, device, plan, snapshot_text, pending_interfaces) -> list:
    return _acl_guarded(_acl_checks, access, device, plan, snapshot_text, pending_interfaces)


def _member_switchport(access, name, management_vlans, *, implicit_group=False):
    command = "show interfaces %s switchport" % name
    answer = access.query(command)
    if ios.refused(answer):
        raise Rejected(["the device does not report switchport capability for %s" % name],
                       reason_codes=["port_routed"] if not implicit_group else ["port_usage_unreadable"])
    try:
        shown = ios.switchport_membership(answer, name, allow_unassigned=implicit_group)
        operational = re.findall(r"^Operational Mode: ([^\n]+)$", answer.replace("\r", ""), re.MULTILINE)
        if len(operational) != 1:
            raise ios.unreadable(command)
    except (Rejected, ValueError):
        raise ios.unreadable(command) from None
    if shown is None:
        raise Rejected(["%s is a routed port" % name], reason_codes=["port_routed"])
    if {shown["access-vlan"], shown["voice-vlan"]} & management_vlans:
        raise Rejected(["%s carries a management VLAN" % name], reason_codes=["port_management_vlan"])
    if shown["mode"] == "trunk" and (
            {str(vlan) for vlan in ios.vlan_numbers(shown["allowed-vlans"])} | {shown["native-vlan"]}
    ) & management_vlans:
        raise Rejected(["%s carries a management VLAN" % name], reason_codes=["port_management_vlan"])
    if (implicit_group and shown["mode"] == "dynamic auto" and operational == ["down"]
            and shown["access-vlan"] is None and shown["voice-vlan"] == "none"):
        # IOL-L2 reports an unconfigured port-channel this way even after an access port joins it.
        # Check all its members' modes and VLANs before treating this as an access-only bundle.
        return shown
    if shown["mode"] != "access" or operational[0].startswith(("trunk", "dynamic ")):
        raise Rejected(["%s is a trunk or may negotiate trunking" % name], reason_codes=["port_uplink"])
    if (shown["access-vlan"] is None or not re.fullmatch(r"(?:[0-9]+|none|dot1p|untagged)", shown["voice-vlan"])
            or not re.fullmatch(r"static access|down(?: \(suspended member of bundle Po[0-9]+\))?", operational[0])):
        raise ios.unreadable(command)
    return shown


def _member_prechecks(access, device, plan, snapshot_text) -> list:
    """Refuse membership changes that could involve an uplink or a management path."""
    key = plan["key"]
    snapshot = ios.load(snapshot_text, device.firmware)
    snapshot.platform = device.platform
    management, management_vlans = _management(access, snapshot, require_all=True)
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    groups = ios.member_groups(before, after)
    touched = [key] + [ios.PORT_CHANNEL + group for group in groups]
    guarded = [name for name in management if any(name == item or name.startswith(item + ".") for item in touched)]
    if guarded:
        raise Rejected(["%s carries the management address; Admin never changes it" % ", ".join(sorted(guarded))],
                       reason_codes=["port_management_interface"])
    physical = _member_switchport(access, key, management_vlans)
    lacp = ios.etherchannel_port(_query(access, "show interfaces %s etherchannel" % key, "EtherChannel"), key)
    if lacp is not None and lacp["protocol"] != "LACP":
        raise ios.unreadable("LACP protocol of " + key)
    if before != (None if lacp is None else {attr: lacp[attr] for attr in ("channel-group", "mode")}):
        raise ios.unreadable("EtherChannel membership of " + key)
    # IOS XE prints "Down Not-in-Bndl" for a port without a link; IOS 15.2 prints "Up Mstr Not-in-Bndl" (measured G63),
    # so the bundle state decides: only a port that is not part of a bundle is changed
    if lacp is not None and "Not-in-Bndl" not in lacp["state"].split():
        raise Rejected(["port %s is %s in channel-group %s; a port-channel member in use is not changed"
                        % (key, lacp["state"], lacp["channel-group"])], reason_codes=["port_lag_active"])
    descriptions = _query(access, QUERY_DESCRIPTIONS, "interface link states")
    row = ios.description_row(descriptions, key, include_protocol=True)
    if (row is None or row["status"] not in ("up", "down", "admin down")
            or row["protocol"] not in ("up", "down")):
        raise ios.unreadable("link state of " + key)
    if row["status"] == "up" or row["protocol"] == "up":
        raise Rejected(["%s has an active link" % key],
                       reason_codes=["port_uplink"] if lacp is None else ["port_lag_active"])
    predicted_vlan = physical["access-vlan"]
    for line in plan["commands"]:
        match = ios.MEMBER_ACCESS.fullmatch(line)
        if match or line == "no switchport access vlan":
            predicted_vlan = match.group(1) if match else ios.DEFAULT_VLAN
            if predicted_vlan in management_vlans:
                raise Rejected(["the port would enter a management VLAN"], reason_codes=["port_management_vlan"])
            if (predicted_vlan != ios.DEFAULT_VLAN
                    and not ios.vlan_exists(_query(access, "show vlan id " + predicted_vlan, "VLAN"), predicted_vlan)):
                raise ios.unreadable("active access VLAN " + predicted_vlan)
    for group in groups:
        command = "show etherchannel %s summary" % group
        answer = access.query(command)
        if ios.refused(answer):
            raise Rejected(["the device does not accept channel-group %s" % group])
        if (not re.search(r"^Number of channel-groups in use:\s*[0-9]+\s*$", answer, re.MULTILINE)
                or not re.search(r"^Group\s+Port-channel\s+Protocol\s+Ports\s*$", answer, re.MULTILINE)):
            raise ios.unreadable(command)
        name = ios.PORT_CHANNEL + group
        if name not in snapshot.interfaces:
            if ios.DEFAULT_VLAN in management_vlans:
                raise Rejected(["the default VLAN of a new port-channel carries management"],
                               reason_codes=["port_management_vlan"])
            continue
        group_state = _member_switchport(access, name, management_vlans,
                                         implicit_group=not snapshot.interface_lines(name))
        if group_state["mode"] == "dynamic auto":
            if ios.DEFAULT_VLAN in management_vlans:
                raise Rejected(["the default VLAN of %s carries management" % name],
                               reason_codes=["port_management_vlan"])
            for member in sorted(set(ios.group_members(snapshot, group)) - {key}):
                if not ios.ETHERNET.fullmatch(member):
                    raise ios.unreadable("port-channel member " + member)
                _member_switchport(access, member, management_vlans)
                row = ios.description_row(descriptions, member, include_protocol=True)
                if row is None or row["status"] not in ("down", "admin down") or row["protocol"] != "down":
                    raise ios.unreadable("down link state of " + member)
        if (after and after["channel-group"] == group and (not before or before["channel-group"] != group)
                and group_state["mode"] == "access" and predicted_vlan != group_state["access-vlan"]):
            raise ios.unreadable("compatible access VLAN of " + name)
    require_complete = device.platform == "ios"
    if ios.short_name(key) in ios.lldp_ports(_query(access, QUERY_LLDP, "LLDP neighbors"), require_complete=require_complete):
        raise Rejected(["port %s has an LLDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    if ios.cdp_name(key) in ios.cdp_ports(_query(access, QUERY_CDP, "CDP neighbors"), require_complete=require_complete):
        raise Rejected(["port %s has a CDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    if ios.learned_macs(_query(access, "show mac address-table interface %s" % key, "MAC table"), key,
                        require_complete=require_complete):
        raise Rejected(["port %s has learned MAC addresses; changing a port in use is refused" % key],
                       reason_codes=["port_learned_mac"])
    plan["prechecks"].append("port %s is a free Layer 2 port (no LLDP/CDP neighbor, no learned MAC address, %s) and "
                             "%s does not carry the management address (%s)"
                             % (key, "not in a port-channel" if lacp is None else "down in channel-group %s"
                                % lacp["channel-group"], ", ".join(touched), ", ".join(sorted(management))))
    return []


def _port_read(read, command, what, code="port_usage_unreadable", *, xe=False):
    try:
        text = read(command)
    except (AccessError, TimeoutError) as exc:
        if xe and (isinstance(exc, TimeoutError) or any(
                marker in str(exc).lower() for marker in ("timeout", "timed out", "did not finish within"))):
            raise Rejected(["IOS %s timed out" % what], reason_codes=["ios_port_read_timeout"]) from None
        raise Rejected(["the %s is unavailable" % what], reason_codes=[code]) from None
    if not text.strip() or "--More--" in text or "\x08" in text:
        raise Rejected(["the %s is incomplete" % what], reason_codes=[code])
    return text


def poe_answer(access, key: str, *, check=False) -> dict:
    """1.0.12 G61: the row of port N in show power inline N (Cisco Catalyst manual layout: Interface, Admin, Oper, Power,
    Device, Class, Max). The write account reads it before a PoE change; the check account (operational commands only,
    `netops-ro` does not read the configuration) reads it for the readback. A switch without PoE refuses the command
    (measured on IOSvL2: 'Line has invalid autocommand'); a port without a row has no PoE: poe_not_capable."""
    command = "show power inline %s" % key
    xe = getattr(getattr(access, "device", access), "platform", None) == "iosxe"
    text = _port_read(access.check_query if check else access.query, command, "PoE state of " + key,
                      "poe_state_unreadable", xe=xe)
    try:
        row = ios.poe_row(text, key)
    except Rejected:
        raise Rejected(["the PoE answer about %s is not recognised" % key], reason_codes=["poe_state_unreadable"]) from None
    if row is None and check:
        raise Rejected(["the PoE answer of the check account about %s lists no port row" % key],
                       reason_codes=["poe_state_unreadable"])
    if row is None:
        raise Rejected(["port %s has no PoE: the switch gives no show power inline row for it" % key],
                       reason_codes=["poe_not_capable"])
    return row


def link_state(access, key: str) -> str:
    """1.0.12 G61: the Status column of show interfaces N status of the check account."""
    xe = getattr(getattr(access, "device", access), "platform", None) == "iosxe"
    text = _port_read(access.check_query, "show interfaces %s status" % key, "link status of " + key, xe=xe)
    status = ios.status_row(text, key)
    if status is None:
        raise ios.unreadable("link status of " + key)
    return status


def _port_action_prechecks(access, device, plan, snapshot_text) -> list:
    """1.0.12 G61: port bounce (IOS-C021), PoE change (IOS-M023) and PoE cycle (IOS-M024) of one Ethernet port with the
    protections of G60: the management interface and VLAN and a port-channel member are never changed; a trunk or
    dynamic port, an LLDP/CDP neighbor, learned MAC addresses or a connected bounce port need endpoint_impact naming the
    port. A switch is recognised by the answer of show interfaces N switchport, not by the name of its image."""
    key, table = plan["key"], plan["table"]
    snapshot = ios.load(snapshot_text, device.firmware)
    snapshot.platform = device.platform
    if key not in snapshot.interfaces:
        raise Rejected(ios.absent(snapshot, table, key))
    xe = device.platform == "iosxe"
    management, management_vlans = _management(access, snapshot, require_all=xe)
    if xe:
        management_vlans.update(_inventory_management_vlans(device))
    if key in management:
        raise Rejected(["interface %s carries the management address; Admin never changes it" % key],
                       reason_codes=["port_management_interface"])
    cycle, impact = xe or table in ios.ACTION_TABLES, plan.get("endpoint_impact") == key
    poe = poe_answer(access, key) if table in ios.POE_TABLES else None  # a port without PoE is refused first
    answer = _port_read(access.query, "show interfaces %s switchport" % key, "switchport state of " + key, xe=xe)
    shown = None
    if xe and ios.refused(answer):
        raise Rejected(["port %s does not report an enabled switchport" % key], reason_codes=["port_routed"])
    if not ios.refused(answer):
        try:
            shown = ios.switchport(answer, key)
            membership = None if shown is None or shown["mode"] == "routed" else ios.switchport_membership(answer, key)
        except Rejected:
            raise ios.unreadable("switchport state of " + key) from None
        if shown is not None and shown["mode"] == "routed":
            raise Rejected(["port %s is a routed port, not a switch port" % key], reason_codes=["port_routed"])
        names = {membership["access-vlan"], membership["voice-vlan"]}
        operational = ios.switchport_operational_mode(answer, key, xe=xe)
        if membership["mode"] == "trunk" or operational == "trunk":
            names |= {str(vlan) for vlan in ios.vlan_numbers(membership["allowed-vlans"])} | {membership["native-vlan"]}
        if names & management_vlans:
            raise Rejected(["port %s carries a management VLAN" % key], reason_codes=["port_management_vlan"])
    uplink = shown is not None and (shown["mode"] != "static access" or (xe and operational == "trunk"))
    if uplink and not impact and not xe:
        raise Rejected(["port %s is treated as an uplink" % key], reason_codes=["port_uplink"])
    status = link_state(access, key)
    if table == ios.BOUNCE_TABLE and status == "disabled":
        raise Rejected(["port %s is administratively disabled; a bounce needs it enabled" % key],
                       reason_codes=["port_disabled"])
    if xe and table == ios.BOUNCE_TABLE and status not in ("connected", "notconnect"):
        raise ios.unreadable("operational link status of " + key)
    if xe and not impact and (status == "connected" or (poe is not None and poe["oper"] == "on")):
        raise Rejected(["port %s is active; the operation requires endpoint_impact naming the port" % key],
                       reason_codes=["endpoint_impact_required"])
    if uplink and not impact:
        raise Rejected(["port %s is treated as an uplink" % key], reason_codes=["port_uplink"])
    state = {"link": status}
    if table in ios.POE_TABLES:
        if xe:
            if poe_answer(access, key, check=True) != poe:
                raise Rejected(["the two accounts disagree about the PoE state of %s" % key],
                               reason_codes=["poe_state_unreadable"])
            state["poe"] = poe["oper"]
        plan["prechecks"].append("port %s has PoE: Admin %s, Oper %s" % (key, poe["admin"], poe["oper"]))
        if table == ios.POE_CYCLE_TABLE:
            if poe["admin"] == "off":
                raise Rejected(["PoE of port %s is configured never; a cycle needs it enabled" % key],
                               reason_codes=["poe_disabled"])
            if poe["oper"] != "on":
                raise Rejected(["port %s has no powered device to restart (Oper %s)" % (key, poe["oper"])],
                               reason_codes=["poe_device_not_powered"])
            state["poe"] = poe["oper"]
    lldp = ios.short_name(key) in ios.lldp_ports(_port_read(access.query, QUERY_LLDP, "LLDP neighbors", xe=xe))
    cdp = ios.cdp_name(key) in ios.cdp_ports(_port_read(access.query, QUERY_CDP, "CDP neighbors", xe=xe))
    macs = 0 if shown is None else ios.learned_macs(
        _port_read(access.query, "show mac address-table interface %s" % key, "MAC address table", xe=xe), key)
    if cycle:
        state.update(lldp=str(lldp or cdp), learned_macs=str(macs))
        plan["cycle_state"] = state
    if (lldp or cdp) and not impact:
        raise Rejected(["port %s has an LLDP/CDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    if macs and not impact:
        raise Rejected(["port %s has learned MAC addresses; changing a port in use is refused" % key],
                       reason_codes=["port_learned_mac"])
    if table == ios.BOUNCE_TABLE and status == "connected" and not impact:
        raise Rejected(["port %s has an active link; a bounce requires endpoint_impact naming the port" % key],
                       reason_codes=["endpoint_impact_required"])
    plan["prechecks"].append(("endpoint impact explicitly accepted on %s (MACs %d, LLDP/CDP neighbor %s); traffic, phone "
                              "or AP connectivity may be interrupted" % (key, macs, lldp or cdp)) if impact else
                             "port %s is a free port (no LLDP/CDP neighbor, no learned MAC address) and does not carry "
                             "the management address (%s); link %s" % (key, ", ".join(sorted(management)), status))
    return []


def dhcp_read_failure(exc):
    if isinstance(exc, TimeoutError) or any(word in str(exc).lower() for word in ("timeout", "timed out")):
        return Rejected(["IOS DHCP read timed out"], reason_codes=["ios_dhcp_read_timeout"])
    return ios.dhcp_unreadable()


def _dhcp_read(read, command):
    try:
        text = read(command)
    except (AccessError, TimeoutError) as exc:
        raise dhcp_read_failure(exc) from None
    if ios.refused(text) or "--More--" in text:
        raise ios.dhcp_unreadable()
    return text


def _dhcp_prechecks(access, device, plan, snapshot_text, pending_interfaces=()):
    table, key = plan["table"], plan["key"]
    snapshot = ios.load(snapshot_text, device.firmware)
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    try:
        management, _ = _management(access, snapshot, require_all=True)
    except Rejected as exc:
        if exc.reason_codes != ["unspecified_refusal"]:
            raise
        raise ios.dhcp_unreadable() from None
    except (AccessError, TimeoutError) as exc:
        raise dhcp_read_failure(exc) from None

    if table == ios.DHCP_RELAY:
        interface = ios.dhcp_interface(key)
        if ({interface, interface.split(".", 1)[0]} & management
                or any(name.startswith(interface + ".") for name in management)):
            raise Rejected(["the relay interface is on the management path"],
                           reason_codes=["port_management_interface"])
        if interface not in pending_interfaces:
            state = _dhcp_read(access.check_query, "show ip interface " + interface)
            helpers = ios.dhcp_relay_entries(interface, snapshot.interfaces[interface].children)
            if ios.dhcp_relay_active(state, interface, helpers):
                if device.platform == "iosxe":
                    _dhcp_impact(plan, "the DHCP relay changes on an active interface")
                elif after is None and len(helpers) == 1 and ios.SVI.fullmatch(interface):
                    _dhcp_impact(plan, "this is the last DHCP helper on an active interface")
    else:
        configured = [(name, network) for name, _, network in ios.interface_networks(snapshot)
                      if name in management and network.version == 4]
        networks = {network for _, network in configured}
        for interface in sorted(management - {name for name, _ in configured}):
            state = ios.ip_interface_state(_dhcp_read(access.query, "show ip interface " + interface), interface)
            if "ipv4-address" not in state:
                raise ios.dhcp_unreadable()
            networks.add(ipaddress.IPv4Interface(state["ipv4-address"].replace(" ", "/")).network)
        if table == ios.DHCP_EXCLUSION:
            low, high = ios.dhcp_exclusion_range(key)
            affected = list(ipaddress.summarize_address_range(low, high))
        else:
            field = "host" if table == ios.DHCP_RESERVATION else "network"
            affected = [ipaddress.IPv4Interface(tuple(state[field].split())).network
                        for state in plan["predicted"].values() if state is not None]
        if any(left.overlaps(right) for left in networks for right in affected):
            raise Rejected(["the DHCP scope overlaps the management subnet"],
                           reason_codes=["port_management_interface"])
        if table == ios.DHCP_POOL and before is not None:
            state = _dhcp_read(access.query, "show ip dhcp pool " + key)
            pools = re.findall(r"^Pool (\S+)\s*:\s*$", state, re.MULTILINE)
            leases = re.findall(r"^\s*Leased addresses\s*:\s*([0-9]+)\s*$", state, re.MULTILINE)
            if pools != [key] or len(leases) != 1:
                raise ios.dhcp_unreadable()
            if int(leases[0]) > 0:
                _dhcp_impact(plan, "the DHCP pool has active leases")
    plan["prechecks"].append("DHCP change is outside the management path")
    return []


def _dhcp_impact(plan, reason):
    key = plan["key"]
    if plan.get("endpoint_impact") != key:
        raise Rejected(["%s; approve endpoint_impact naming %s" % (reason, key)],
                       reason_codes=["endpoint_impact_required"])
    plan["prechecks"].append("DHCP impact accepted for %s: %s" % (key, reason))


def plan_prechecks(access, device, plan, snapshot_text="", undo=False, *, pending_vlans=(), removed_vlans=(),
                   pending_interfaces=(), batch_step=False) -> list:
    key, table = plan["key"], plan["table"]
    if table in ios.PORT_ACTION_TABLES:
        try:
            return _port_action_prechecks(access, device, plan, snapshot_text)
        except Rejected:
            raise
        except Exception:
            # a failed or timed-out read is an unreadable port state, never an unspecified refusal
            raise ios.unreadable("state of port %s (the read failed)" % key) from None
    if table in ios_acl.TABLES:
        return _acl_prechecks(access, device, plan, snapshot_text, pending_interfaces)
    if table in ios.DHCP_TABLES:
        return _dhcp_prechecks(access, device, plan, snapshot_text, pending_interfaces)
    if table in ios.ios_services.TABLES:
        before, after = plan["predicted"]["before"], plan["predicted"]["after"]
        if table == ios.ios_services.SYSTEM and (sources := ios.ios_services.sources(before, after)):
            try:
                management, _ = _management(access, ios.load(snapshot_text, device.firmware), require_all=True)
            except AccessError as exc:
                code = ("ios_service_read_timeout" if re.search(r"timeout|timed out|within", str(exc), re.I)
                        else "ios_service_read_unreadable")
                raise Rejected(["the IOS service source could not be checked"], reason_codes=[code]) from None
            except Rejected as exc:
                if exc.reason_codes == ["unspecified_refusal"]:
                    raise ios.unreadable("service source management paths") from None
                raise
            if any(source in management or source.split(".", 1)[0] in management for source in sources):
                raise Rejected(["a service source references the SSH management interface"],
                               reason_codes=["port_management_interface"])
        return []
    if table in ios.STATE_TABLES:
        return _state_prechecks(access, device, plan, snapshot_text, undo)
    if table == ios.MEMBER_TABLE:
        return _member_prechecks(access, device, plan, snapshot_text)
    if table not in ("interface", "vlan-membership"):
        return []
    snapshot = ios.load(snapshot_text, device.firmware)
    snapshot.platform = device.platform
    if key not in snapshot.interfaces:
        raise Rejected(ios.absent(snapshot, table, key))
    management, management_vlans = _management(access, snapshot)
    xe_batch = batch_step and device.platform == "iosxe"
    if xe_batch:
        management_vlans.update(_inventory_management_vlans(device))
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
        if shown["mode"] != "routed" and (table == "vlan-membership" or ios.disruptive(table, before, after)):
            answer = access.query("show interfaces %s switchport" % key)
            membership = ios.switchport_membership(answer, key)
            if membership is None:
                raise ios.unreadable("switchport membership of " + key)
            operational = ios.switchport_operational_mode(answer, key, xe=True) if xe_batch else None
            if membership["voice-vlan"] in management_vlans:
                raise Rejected(["port voice VLAN carries management"], reason_codes=["port_management_vlan"])
            if shown["mode"] == "trunk" or operational == "trunk":
                allowed = {str(value) for value in ios.vlan_numbers(membership["allowed-vlans"])}
                if allowed & management_vlans:
                    raise Rejected(["trunk carries a management VLAN"], reason_codes=["port_management_vlan"])
        if shown["access-vlan"] in management_vlans:
            raise Rejected(["port %s is in the management VLAN %s; Admin never changes it"
                            % (key, shown["access-vlan"])], reason_codes=["port_management_vlan"])
    if table == "vlan-membership":
        if not switch:
            raise Rejected(["the device is a router (image without switchport); an access VLAN cannot be set"],
                           reason_codes=["port_routed"])
        wanted = str((after or {}).get("access-vlan", ios.DEFAULT_VLAN))
        selected = {wanted}
        required = {str(after[attr]) for attr in ("native-vlan", "voice-vlan")
                    if after and attr in after and str(after[attr]).isdigit()}
        selected |= required
        # Retained allowed VLANs may be absent from vlan.dat; IOS all also
        # includes reserved VLANs. Validate only newly added ordinary VLANs.
        allowed = (after or {}).get("allowed-vlans", "all")
        if allowed != "all":
            allowed_set = {str(vid) for vid in ios.vlan_numbers(allowed)}
            previous = {str(vid) for vid in ios.vlan_numbers((before or {}).get("allowed-vlans", "all"))}
            selected |= allowed_set
            # An undo restores an earlier allowed list; a VLAN that was allowed while missing
            # (live: trunk 1-98,100-4094 without VLAN 100) must be restorable. Only the undo path
            # of execute (trusted `undo` flag) qualifies, never a user-chosen request_id.
            if not undo:
                required |= allowed_set - previous - ios.RESERVED_VLANS
        if selected & management_vlans:
            raise Rejected(["membership names a management VLAN"], reason_codes=["port_management_vlan"])
        if ({wanted} | required) & set(removed_vlans):
            raise Rejected(["membership names a VLAN deleted by an earlier batch step"], reason_codes=["vlan_missing"])
        for vid in sorted(required - {wanted} - set(pending_vlans), key=int):
            if vid in ios.RESERVED_VLANS or not ios.vlan_exists(_query(access, "show vlan id " + vid, "VLAN"), vid):
                raise Rejected(["selected VLAN %s does not exist or is reserved" % vid], reason_codes=["vlan_missing"])
        if wanted in management_vlans:
            raise Rejected(["VLAN %s is the management VLAN; Admin never puts a port into it" % wanted],
                           reason_codes=["port_management_vlan"])
        if wanted not in pending_vlans and not ios.vlan_exists(
                _query(access, "show vlan id %s" % wanted, "VLAN"), wanted):
            raise Rejected(["VLAN %s does not exist on the switch; IOS would create it and a rollback would not "
                            "remove a VLAN of the normal range, so the change is refused" % wanted],
                           reason_codes=["vlan_missing"])
        plan["prechecks"].append("VLAN %s exists" % wanted)
    plan["prechecks"].append("interface %s does not carry the management address (%s)"
                             % (key, ", ".join(sorted(management))))
    if table == "interface" and not ios.disruptive(table, before, after):
        return []
    impact = plan.get("endpoint_impact") == key
    if table == "vlan-membership" and (
            (before or {}).get("mode", "dynamic auto") != (after or {}).get("mode", "dynamic auto")
            or shown["mode"] == "trunk" or (after or {}).get("mode") == "trunk") and not impact:
        raise Rejected(["changing mode or trunk membership requires endpoint_impact naming %s; traffic may be interrupted" % key],
                       reason_codes=["endpoint_impact_required"])
    if switch and shown["mode"] != "static access" and not impact:
        raise Rejected(["port %s is in %s mode, not static access; it is treated as an uplink" % (key, shown["mode"])],
                       reason_codes=["port_uplink"])
    lldp = ios.lldp_ports(_query(access, QUERY_LLDP, "LLDP neighbors"))
    cdp = ios.cdp_ports(_query(access, QUERY_CDP, "CDP neighbors"))
    if not impact and ios.short_name(key) in lldp:
        raise Rejected(["port %s has an LLDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    if not impact and ios.cdp_name(key) in cdp:
        raise Rejected(["port %s has a CDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    if switch:
        macs = ios.learned_macs(_query(access, "show mac address-table interface %s" % key, "MAC table"), key)
        if macs and not impact:
            raise Rejected(["port %s has learned MAC addresses; changing a port in use is refused" % key],
                           reason_codes=["port_learned_mac"])
        plan["prechecks"].append(("endpoint impact explicitly accepted on %s (MACs %d, LLDP %s, CDP %s); traffic, phone or AP connectivity may be interrupted"
                                  % (key, macs, ios.short_name(key) in lldp, ios.cdp_name(key) in cdp)) if impact else
                                 "port %s is a static access port without LLDP/CDP neighbor and learned MAC address" % key)
    else:
        plan["prechecks"].append("interface %s has no IPv4 address and no LLDP/CDP neighbor" % key)
    return []


def batch_read_error(exc):
    if isinstance(exc, TimeoutError) or re.search(r"timeout|timed out|within", str(exc), re.I):
        return Rejected(["the IOS batch preflight read timed out"], reason_codes=["ios_batch_read_timeout"])
    return Rejected(["the IOS batch preflight read is incomplete or unrecognised"],
                    reason_codes=["ios_batch_read_unreadable"])


def _batch_active(access, interface):
    text = access.check_query(QUERY_DESCRIPTIONS)
    if "--More--" in text:
        raise batch_read_error(None)
    try:
        row = ios.description_row(text, interface, include_protocol=True, require_table=True)
    except Rejected:
        raise batch_read_error(None) from None
    if row is None or row["status"] not in ("up", "down", "admin down") or row["protocol"] not in ("up", "down"):
        raise batch_read_error(None)
    return row["status"] == "up" and (ios.ETHERNET.fullmatch(interface) is not None or row["protocol"] == "up")


def batch_prechecks(access, device, plan, snapshot_text, earlier, *, undo=False):
    """Defer operational reads only for objects created by preceding, verified steps."""
    from netops_admin import engine, exec_ios_vlan
    table, key = plan["table"], plan["key"]
    pending_vlans = {step["key"] for step in earlier if step["table"] == "vlan" and step["op"] == "create"}
    removed_vlans = {step["key"] for step in earlier if step["table"] == "vlan" and step["op"] == "delete"}
    pending_interfaces = {step["key"]: step["predicted"]["after"] for step in earlier
                          if step["table"] == ios.L3_TABLE and step["op"] == "create"}
    interface = ios.batch_interface(table, key)
    try:
        snapshot = ios.load(snapshot_text, device.firmware)
        if table == "vlan":
            # vlan.dat is outside the IOS archive. Restrict the timed batch to VLANs kept in running-config.
            text = _query(access, "show vtp status", "VLAN storage mode")
            mode = re.findall(r"^VTP Operating Mode\s*:\s*(\S+)\s*$", text, re.MULTILINE)
            version = re.findall(r"^VTP version running\s*:\s*(\d+)\s*$", text, re.MULTILINE)
            if len(mode) != 1 or len(version) != 1:
                raise batch_read_error(None)
            if (int(key) <= 1005 or mode != ["Transparent"] or version[0] not in ("1", "2")
                    or (plan["predicted"]["before"] is not None
                        and not any(block.header == "vlan " + key for block in snapshot.blocks))):
                raise Rejected(["an IOS batch needs an extended VLAN stored in running-config under VTP transparent"],
                               reason_codes=["action_unsupported"])
            reasons = exec_ios_vlan.plan_prechecks(access, device, plan, snapshot_text)
        else:
            if table == ios.L3_TABLE and plan["op"] == "create":
                # The approval must also allow the later removal of a newly active endpoint on undo.
                active = plan["predicted"]["after"].get("admin-state") != "disabled"
            elif interface in snapshot.interfaces and table != ios_acl.BINDING:
                active = (pending_interfaces[interface].get("admin-state") != "disabled"
                          if interface in pending_interfaces else _batch_active(access, interface))
            else:
                active = False
            if active and plan.get("endpoint_impact") != key:
                raise Rejected(["the active or enabled interface %s requires endpoint_impact naming %s"
                                % (interface, key)], reason_codes=["endpoint_impact_required"])
            reasons = plan_prechecks(access, device, plan, snapshot_text, undo=undo,
                                     pending_vlans=pending_vlans, removed_vlans=removed_vlans,
                                     pending_interfaces=pending_interfaces, batch_step=True)
        if reasons:
            raise Rejected(reasons)
        if interface in pending_interfaces:
            return
        seen = engine.observed_state(plan, observe(access, plan))
        if seen != engine.check_view(plan, plan["predicted"]["before"]):
            raise batch_read_error(None)
    except (AccessError, TimeoutError) as exc:
        raise batch_read_error(exc) from None
    except Rejected as exc:
        if exc.reason_codes == ["unspecified_refusal"]:
            raise batch_read_error(None) from None
        raise


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


def has_exec_banner(text, firmware) -> bool:
    return any(block.header.split()[:2] == ["banner", "exec"] for block in ios.load(text, firmware).blocks)


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


def _observe_state(access, plan):
    key = plan["key"]
    if plan["table"] == ios.ROUTE_TABLE:
        vrf, network = ios.route_key(key)
        command = ("show ip static route" if network.version == 4 else "show ipv6 static") + (" vrf " + vrf if vrf else "")
        return ios.static_route_state(access.check_query(command), key)
    row = ios.description_row(access.check_query(QUERY_DESCRIPTIONS), key, require_table=True)
    if row is None or row["status"] == "deleted":
        return None
    state = {"description": row["description"]} if row["description"] else {}
    if row["status"] == "admin down" and not ios.SUBINTERFACE.match(key):
        # a subinterface shows the admin state of its parent port (measured), it has no own admin-state
        state["admin-state"] = "disabled"
    four = ios.ip_interface_state(access.check_query("show ip interface " + key), key)
    six = ios.ipv6_interface_state(access.check_query("show ipv6 interface " + key), key)
    if "vrf" in four and "vrf" in six and four["vrf"] != six["vrf"]:
        raise Rejected(["show ip interface and show ipv6 interface %s name another VRF" % key])
    state.update(four)
    state.update(six)
    if ios.SUBINTERFACE.match(key):
        state.update(ios.encapsulation_state(access.check_query("show interfaces " + key), key))
    return state


def _observe_acl(access, plan):
    key = plan["key"]
    if plan["table"] == ios_acl.ACL:
        family, name = key.split(":", 1)
        return ios_acl.observe_acl(access.check_query(ios_acl.LISTING_COMMANDS[family] + " " + name), key,
                                   xe=plan.get("platform") == "iosxe")
    interface, family, _ = key.rsplit(":", 2)
    command = ("show ip interface " if family == "ipv4" else "show ipv6 interface ") + interface
    return ios_acl.observe_binding(access.check_query(command), key, xe=plan.get("platform") == "iosxe")


def observe(access, plan):
    key = plan["key"]
    if plan["table"] == "vlan":
        from netops_admin import exec_ios_vlan
        return exec_ios_vlan.observe(access, plan)
    if plan["table"] in ios_acl.TABLES:
        return _acl_guarded(_observe_acl, access, plan)
    if plan["table"] in ios.DHCP_TABLES:
        return _observe_dhcp(access, plan["table"], key)
    if plan["table"] in ios.ios_services.TABLES:
        return ios.ios_services.observe(access, plan["table"], key, ios.Entry)
    if plan["table"] in ios.STATE_TABLES:
        return _observe_state(access, plan)
    if plan["table"] == ios.MEMBER_TABLE:
        return ios.member_state(access.check_query("show interfaces %s etherchannel" % key), key)
    if plan["table"] == ios.BOUNCE_TABLE:
        return {"admin-state": "disabled"} if link_state(access, key) == "disabled" else {}
    if plan["table"] in ios.POE_TABLES:
        # show power inline N is an operational command: the check account reads the admin mode (auto, off, static)
        mode = {"off": "never", "static": "static", "auto": "auto"}[poe_answer(access, key, check=True)["admin"]]
        return {} if mode == "auto" else {"mode": mode}
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
        if plan["platform"] in ios.PLATFORMS:
            return ios.switchport_membership(access.check_query("show interfaces %s switchport" % key), key)
        return {"access-vlan": shown["access-vlan"]}
    row = ios.description_row(access.check_query(QUERY_DESCRIPTIONS), key)
    if row is None:
        return None
    state = {"description": row["description"]} if row["description"] else {}
    if row["status"] == "admin down":
        state["admin-state"] = "disabled"
    return state


def _observe_dhcp(access, table, key):
    # The check identity can see bindings and the relay's operational address
    # but cannot read configured options, exclusions or helper qualifiers.
    # Read the exact object through the configuration identity in a fresh query.
    if table == ios.DHCP_RELAY:
        command = "show running-config interface " + ios.dhcp_interface(key)
    elif table == ios.DHCP_EXCLUSION:
        line = ios.DHCP_EXCLUSION_LINE + key.replace("-", " ").replace(".", "[.]")
        command = "show running-config | include ^" + line + "$|^end$"
    else:
        command = "show running-config | section ^" + ios.DHCP_POOL_LINE + key + "$|^end$"
    return ios.dhcp_readback(_dhcp_read(access.query, command), table, key)


def foreign_sessions(access, device) -> int:
    return ios.users(_query(access, QUERY_USERS, "sessions"))[1]
