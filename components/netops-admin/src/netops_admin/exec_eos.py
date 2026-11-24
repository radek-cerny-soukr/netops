"""Arista EOS execution adapter (measured on cEOS 4.36.1F, private measurement record).

Safeguard first, as execute.py needs it: an empty configuration session with a commit timer is committed before the
change; its checkpoint holds the configuration before the change. The change itself runs line by line through
configure terminal in an interactive session (an ssh exec batch continues after an error and would run the rest).
Confirmation commits the session (configure session NAME commit, also from another connection) and deletes its
record; an expired timer returns the whole running configuration to that checkpoint, which only the log proves
(CONFIG_SESSION_COMMIT_TIMER_TIMEDOUT, CONFIG_SESSION_COMMIT_REVERTED), because the session disappears. While the
timer is pending EOS refuses another commit timer and the commit of any other session, and write memory would save
the unconfirmed state, so persist runs only after the confirmation.

Routing profiles stage the change itself in the timed configuration session.

The write account must log in with privilege 15 (aaa authorization exec default local and username... privilege
15): Admin reads the running configuration with one ssh exec command and never sends enable or an enable secret.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import re

from netops_admin import eos, eos_acl, eos_bgp, eos_clear, eos_dhcp, eos_l2, eos_l3, eos_routing, eos_services
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
QUERY_SSH_SESSIONS = "show users detail | json"
QUERY_SSH_STATUS = "show management ssh"
ADDRESSING = re.compile(r"^(?:(?:ip|ipv6) (?:address|virtual-router address) (?:virtual )?([^ ]+)"
                        r"|ipv6 enable$|ip unnumbered )")
SSHD_STATUS = re.compile(r"SSHD status for (?:VRF (\S+)|(\S+) VRF)(?:: | is )(enabled|disabled)")
FIRED = ("CONFIG_SESSION_COMMIT_TIMER_TIMEDOUT", "CONFIG_SESSION_COMMIT_REVERTED")
CONFIRMED = "CONFIG_SESSION_COMMIT_TIMER_COMPLETED"
FIRING_OBSERVED = True


def prompt_spec(hostname: str) -> PromptSpec:
    # measured prompts: "Arista cEOS 4.36.1F>", "Arista cEOS 4.36.1F#", "Arista cEOS 4.36.1F(config-if-Et10)#", "Arista cEOS 4.36.1F(config-s-netops-c7-)#"
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


def prechecks(access, device, snapshot_text, spec, *, saving=False) -> list:
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
    if not saving and access.query(QUERY_DIFFS).strip():
        reasons.append("the switch has unsaved configuration changes of someone else (show running-config diffs)")
    data = sessions(access)
    timer = data.get("commitTimerSessionName")
    foreign = sorted(name for name, item in data["sessions"].items()
                     if not name.startswith(eos.SESSION_PREFIX) and (item or {}).get("state") == "pending")
    if timer and (saving or not str(timer).startswith(eos.SESSION_PREFIX)):
        raise Rejected(["configuration session %s of someone else has a pending commit timer; EOS refuses "
                        "every other commit until it ends" % timer], reason_codes=["foreign_config_session"])
    if foreign:
        raise Rejected(["%d configuration sessions of someone else are open (pending)" % len(foreign)],
                       reason_codes=["foreign_config_session"])
    return reasons


def vlan_answer(access, vlan: str) -> str:
    """show vlan id N of the write account; a missing VLAN ends with exit status 1 (measured), which is an answer."""
    _status, text = access.query_status("show vlan id %s" % vlan)
    return text


def _vlan_plan_prechecks(access, plan) -> list:
    """eos switchport admin (E05/E19): the VLAN database of the switch agrees with the snapshot; a deleted VLAN carries no traffic."""
    key, op = plan["key"], plan["op"]
    exists = eos.vlan_exists(vlan_answer(access, key), key)
    if exists != (op != "create"):
        raise Rejected(["VLAN %s %s on the switch, unlike in the snapshot" % (key, "exists" if exists else
                                                                                 "does not exist")])
    if op == "delete":
        if eos.learned_macs(access.query("show mac address-table vlan %s" % key)):
            raise Rejected(["VLAN %s has learned MAC addresses; a VLAN in use is not deleted" % key],
                           reason_codes=["port_learned_mac"])
        plan["prechecks"].append("VLAN %s has no learned MAC address" % key)
    plan["prechecks"].append("the timed safeguard also returns the VLAN (EOS keeps VLANs in the running "
                             "configuration)")
    return []


def _interface_addressing(lines):
    vrf = next((line[4:] for line in lines if line.startswith("vrf ")), "default")
    entries = [match[1] for line in lines if (match := ADDRESSING.match(line))]
    addresses = set()
    for entry in entries:
        try:
            addresses.add(ipaddress.ip_interface(entry))
        except ValueError:
            # DHCP and unnumbered interfaces are addressed without a static prefix in the snapshot.
            continue
    return vrf, bool(entries), addresses


def _ip(value):
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    return getattr(parsed, "ipv4_mapped", None) or parsed


def _ssh_sources_by_account(access, *, query=None):
    try:
        sessions = _json((query or access.query)(QUERY_SSH_SESSIONS), "SSH sessions").get("vtys")
    except Rejected:
        raise
    except Exception:
        raise eos.unreadable("SSH sessions") from None
    if not isinstance(sessions, dict):
        raise eos.unreadable("SSH sessions")
    peers = {access.credential.login: set()}
    check = getattr(access, "check_credential", None)
    if check is not None:
        peers[check.login] = set()
    for session in sessions.values():
        if not isinstance(session, dict):
            raise eos.unreadable("SSH session")
        if (session.get("service") == "sshd" and session.get("state") == "established"
                and session.get("username") in peers):
            peer = _ip(session.get("remoteAddress"))
            if peer is None:
                raise eos.unreadable("SSH source address")
            peers[session["username"]].add(peer)
    return peers


def _ssh_sources(access, *, query=None):
    peers = _ssh_sources_by_account(access, query=query)
    return set().union(*peers.values()), bool(peers[access.credential.login])


def _ssh_vrfs(access, *, text=None):
    if text is None:
        try:
            text = access.query(QUERY_SSH_STATUS)
        except Exception:
            raise eos.unreadable("SSH status by VRF") from None
    enabled = set()
    found = False
    for line in text.splitlines():
        if line.startswith("SSHD status"):
            match = SSHD_STATUS.fullmatch(line.strip())
            if not match:
                raise eos.unreadable("SSH status by VRF")
            found = True
            if match[3] == "enabled":
                name = match[1] or match[2]
                enabled.add("default" if name == "Default" else name)
    if not found:
        raise eos.unreadable("SSH status by VRF")
    return enabled


def _management_svi(access, device, snapshot, vlan):
    svi_vrf, addressed, svi_addresses = _interface_addressing(snapshot.interface_lines("Vlan" + vlan))
    if not addressed:
        return False
    ssh_vrfs = _ssh_vrfs(access)
    if not ssh_vrfs:
        raise eos.unreadable("SSH status by VRF")
    mgmt_vrf, mgmt_addressed, mgmt_addresses = _interface_addressing(snapshot.interface_lines("Management0"))
    svi_ssh = svi_vrf in ssh_vrfs
    if svi_ssh and svi_vrf == "default" and (mgmt_vrf == "default" or not mgmt_addressed):
        return True
    targets = {device.address, device.check_address or device.address}
    target_ips = set()
    for target in targets:
        literal = _ip(target)
        candidates = {literal} if literal is not None else {_ip(address) for address in access.resolve_addresses(target)}
        if not candidates or None in candidates:
            raise eos.unreadable("SSH destination addresses")
        target_ips.update(candidates)
    svi_target = bool(target_ips & {address.ip for address in svi_addresses})
    if svi_ssh and svi_target:
        return True

    # A target on another interface in the SVI's VRF can still be reached via the SVI.
    data_targets = set()
    unknown_data_address = False
    if svi_ssh:
        for interface in snapshot.interfaces:
            vrf, configured, addresses = _interface_addressing(snapshot.interface_lines(interface))
            if vrf == svi_vrf:
                data_targets.update(target_ips & {address.ip for address in addresses})
                unknown_data_address |= configured and not addresses
    separate_management = mgmt_vrf != svi_vrf and mgmt_vrf in ssh_vrfs and mgmt_addressed
    exclusive_management = separate_management and not data_targets and not unknown_data_address
    if exclusive_management and target_ips <= {address.ip for address in mgmt_addresses}:
        return False
    if not svi_ssh and not svi_target:
        return False
    if not svi_ssh:
        raise eos.unreadable("SSH management path for VLAN %s" % vlan)

    peers, writer_seen = _ssh_sources(access)
    if any(peer in address.network for peer in peers for address in svi_addresses):
        return True
    if (exclusive_management and len(targets) == 1 and writer_seen
            and all(any(peer in address.network for address in mgmt_addresses) for peer in peers)):
        return False
    raise eos.unreadable("SSH management path for VLAN %s" % vlan)


def _cycle_management_precheck(access, device, key, snapshot_text):
    shown = eos.switchport(access.query("show interfaces %s switchport" % key), key)
    if shown["mode"] != "static access":
        raise Rejected(["port %s is not a static access port" % key], reason_codes=["port_uplink"])
    vlan = shown["access-vlan"]
    policy_vlans = {str(number) for number in (device.audit_policy or {}).get("management_vlans", ())}
    if vlan in policy_vlans or _management_svi(access, device, eos.load(snapshot_text, None), vlan):
        raise Rejected(["port %s carries VLAN %s on the management path" % (key, vlan)],
                       reason_codes=["port_management_vlan"])


def _cycle_prechecks(access, device, plan, snapshot_text, status):
    key = plan["key"]
    if not status:
        raise eos.unreadable("interface status")
    try:
        _cycle_management_precheck(access, device, key, snapshot_text)
    except Rejected as exc:
        if "unspecified_refusal" not in exc.reason_codes:
            raise
        raise eos.unreadable("switchport state") from None
    plan["cycle_state"] = {"link": status}


def plan_prechecks(access, device, plan, snapshot_text="", undo=False, pending_vlans=()) -> list:
    """Run prechecks for a new change or the trusted undo path of execute. pending_vlans are VLANs an earlier step
    of the same profile batch creates (the VLAN checks of this step then need no VLAN on the switch yet)."""
    key, table = plan["key"], plan["table"]
    if table == eos_bgp.TABLE:
        return _bgp_plan_prechecks(access, device, plan, snapshot_text)
    if table in eos_routing.TABLES:
        return _routing_plan_prechecks(access, device, plan, snapshot_text)
    if table in eos_dhcp.TABLES:
        return _dhcp_plan_prechecks(access, device, plan, snapshot_text)
    if table in eos_acl.TABLES:
        return _acl_plan_prechecks(access, device, plan, snapshot_text)
    if table in eos_l2.TABLES:
        return _l2_plan_prechecks(access, device, plan, eos.load(snapshot_text, None))
    if table in eos_l3.TABLES:
        return l3_plan_prechecks(access, device, plan, snapshot_text, undo=undo)
    if table in eos_services.TABLES:
        return []
    if table == eos.VLAN_TABLE:
        return _vlan_plan_prechecks(access, plan)
    if table not in ("interface", "vlan-membership", eos.BOUNCE_TABLE, eos.POE_TABLE):
        return []
    cycle = table in (eos.BOUNCE_TABLE, eos.POE_TABLE)
    try:
        status = eos.status_row(access.query("show interfaces %s status" % key), key)
        if cycle:
            _cycle_prechecks(access, device, plan, snapshot_text, status)
    except Rejected:
        raise
    except Exception:
        if cycle:
            raise eos.unreadable("cycle port status or switchport state") from None
        raise
    if status is None:
        raise Rejected(["the switch does not report interface %s" % key], reason_codes=["port_usage_unreadable"])
    plan["prechecks"].append("interface %s now: %s" % (key, status))
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    impact = plan.get("endpoint_impact") == key
    if table == "vlan-membership":
        for wanted in sorted(eos.required_vlans(before, after, undo), key=int):
            if wanted not in pending_vlans and not eos.vlan_exists(vlan_answer(access, wanted), wanted):
                raise Rejected(["VLAN %s does not exist on the switch; EOS would create it without an error, so the "
                                "change is refused" % wanted], reason_codes=["vlan_missing"])
        shown = eos.switchport(access.query("show interfaces %s switchport" % key), key)
        if (eos.trunk_change(before, after) or shown["mode"] != "static access") and not impact:
            if shown["mode"] != "static access" and not eos.trunk_change(before, after):
                raise Rejected(["port %s is in %s mode, not static access" % (key, shown["mode"])],
                               reason_codes=["port_uplink"])
            raise Rejected(["changing the mode or the membership of a trunk requires endpoint_impact naming %s; "
                            "traffic may be interrupted" % key], reason_codes=["endpoint_impact_required"])
        plan["prechecks"].append("checked VLANs required for this change; port %s is in %s mode" % (key, shown["mode"]))
    if table in ("interface", eos.POE_TABLE):
        _capability_prechecks(access, plan, before or {}, after or {})
    if not eos.disruptive(table, before, after):
        return []
    try:
        lldp = eos.short_name(key) in eos.lldp_ports(access.query(QUERY_LLDP))
    except Rejected:
        raise
    except Exception:
        if cycle:
            raise eos.unreadable("LLDP neighbor list") from None
        raise
    if lldp and not impact:
        raise Rejected(["port %s has an LLDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    try:
        macs = eos.learned_macs(access.query("show mac address-table interface %s" % key))
        if cycle and status == "connected" and lldp and macs:
            connected = eos.connected_ports(access.query("show interfaces status"))
            if eos.short_name(key) not in connected:
                raise eos.unreadable("connected interfaces")
            if len(connected) == 1:
                raise Rejected(["port %s is the only connected port and may carry the management path" % key],
                               reason_codes=["port_management_interface"])
    except Rejected:
        raise
    except Exception:
        if cycle:
            raise eos.unreadable("MAC address table or connected interfaces") from None
        raise
    if cycle:
        plan["cycle_state"].update(lldp=str(lldp), learned_macs=str(macs))
    if macs and not impact:
        raise Rejected(["port %s has learned MAC addresses; changing a port in use is refused" % key],
                       reason_codes=["port_learned_mac"])
    plan["prechecks"].append(("endpoint impact explicitly accepted on %s (MACs %d, LLDP neighbor %s); traffic, phone "
                              "or AP connectivity may be interrupted" % (key, macs, lldp)) if impact else
                             "port %s has no LLDP neighbor and no learned MAC address" % key)
    return []


def poe_answer(access, key: str) -> dict:
    """eos port maintenance (E06/E07): show poe interface N of the write account (Privileged EXEC in the Arista EOS manual); a switch
    without PoE hardware answers "% Unavailable command (not supported on this hardware platform)" (measured)."""
    try:
        status, text = access.query_status("show poe interface %s" % key)
    except Exception:
        raise Rejected(["the PoE answer about %s is unavailable" % key],
                       reason_codes=["poe_state_unreadable"]) from None
    if eos.poe_unavailable(status, text):
        raise Rejected(["port %s has no PoE: the switch answers that show poe is not supported on its hardware" % key],
                       reason_codes=["poe_not_capable"])
    if status != 0:
        raise Rejected(["the PoE answer about %s ended with an error" % key], reason_codes=["poe_state_unreadable"])
    return eos.poe_state(text, key)


def _capability_prechecks(access, plan, before, after) -> None:
    """eos port maintenance (E06/E07/E23): a new speed must be listed in show interfaces N hardware, a new MTU must not exceed the
    Ethernet MTU of the port, a PoE change needs a port with PoE whose state is readable; all before any write."""
    key = plan["key"]
    if plan["table"] == eos.POE_TABLE or after.get("poe") != before.get("poe"):
        state = poe_answer(access, key)
        if plan["table"] == eos.POE_TABLE:
            if state["configured"] != "enabled":
                raise Rejected(["PoE is disabled on port %s" % key], reason_codes=["poe_disabled"])
            if state["state"] != "powered":
                raise Rejected(["port %s has no powered device to restart" % key],
                               reason_codes=["poe_device_not_powered"])
            plan["cycle_state"].update(poe=state["state"])
        plan["prechecks"].append("port %s has PoE: PSE %s, %s" % (key, state["configured"], state["state"]))
    speed = after.get("speed")
    if speed not in (None, eos.SPEED_AUTO) and speed != before.get("speed"):
        speeds = eos.hardware_speeds(access.query("show interfaces %s hardware" % key), key)
        if not eos.speed_supported(speed, speeds):
            raise Rejected(["port %s does not list speed %s in show interfaces %s hardware (%s)"
                            % (key, speed, key, ",".join(sorted(speeds)))],
                           reason_codes=["port_capability_unsupported"])
        plan["prechecks"].append("port %s lists speed %s in its hardware capabilities" % (key, speed))
    mtu = after.get("mtu")
    if mtu is not None and mtu != before.get("mtu"):
        largest = eos.ethernet_mtu(access.query("show interfaces %s" % key), key)
        if int(mtu) > largest:
            raise Rejected(["port %s carries at most %d bytes (Ethernet MTU of show interfaces %s); EOS refuses mtu %s"
                            % (key, largest, key, mtu)], reason_codes=["port_capability_unsupported"])
        plan["prechecks"].append("mtu %s is within the Ethernet MTU %d of port %s" % (mtu, largest, key))


def link_state(access, key: str) -> str:
    """eos port maintenance (E08): the Status column of show interfaces N status of the check account."""
    return eos.link_state(access.check_query("show interfaces %s status" % key), key)


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
    staged = plan["commands"] if changes_in_session(plan) else []
    access.apply([f"configure session {label}", *staged, f"commit timer {_timer(device.safeguard_seconds)}"], spec)
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
        difference = (scheduled - planned).total_seconds()
        if staged:
            upper = clock(access) + datetime.timedelta(seconds=device.safeguard_seconds + TIMER_TOLERANCE_SECONDS)
            valid = difference >= -TIMER_TOLERANCE_SECONDS and scheduled <= upper
        else:
            valid = abs(difference) <= TIMER_TOLERANCE_SECONDS
        if not valid:
            problems.append("safeguard commit timer expires at another time than planned")
        record["safeguard"]["fire_at"] = scheduled.strftime("%Y-%m-%d %H:%M:%S")
    return problems


def changes_in_session(plan):
    return plan["table"] in eos_routing.TABLES | {eos_bgp.TABLE}


def discard_routing_session(access, record, spec):
    """Abort this operation's candidate or timed commit after a staging failure."""
    label = safeguard_label(record["change_id"])
    data = sessions(access)
    item = data["sessions"].get(label)
    if data.get("commitTimerSessionName") == label or (item and item.get("state") == "pending"):
        access.apply([f"configure session {label} abort"], spec)
    return safeguard_absent(access, record)


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


def cycle_timer_pending(access, record) -> bool:
    return sessions(access).get("commitTimerSessionName") == safeguard_label(record["change_id"])


def clean_confirmed_cycle(access, record, spec):
    label = safeguard_label(record["change_id"])
    try:
        data = sessions(access)
        if data.get("commitTimerSessionName") == label:
            return False
        if label in data["sessions"]:
            access.apply(["no configure session %s" % label], spec)
        return safeguard_absent(access, record)
    except Exception:
        return False


def safeguard_confirmed(access, record) -> bool:
    try:
        lines = log_lines(access, safeguard_label(record["change_id"]))
    except Exception:
        return False
    return any(CONFIRMED in line for line in lines)


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


def observe(access, plan, *, before=False):
    key = plan["key"]
    if plan["table"] == eos_bgp.TABLE:
        _, peer = eos_bgp.target(key)
        try:
            return eos_bgp.observe(_routing_json(access, f"show ip bgp neighbors {peer} | json"), key)
        except (KeyError, ValueError, TypeError, AttributeError):
            raise _routing_unreadable() from None
    if plan["table"] in eos_routing.TABLES:
        return _observe_routing(access, plan)
    if plan["table"] in eos_dhcp.TABLES:
        return _observe_dhcp(access, plan)
    if plan["table"] in eos_acl.TABLES:
        _acl_check_account(access, plan)
        observed, configured, active = _observe_acl(access, plan)
        links = plan.get("acl_attachment_links")
        if links is not None:
            bindings = {f"{interface}:{direction}" for interface, direction in configured}
            if plan["table"] == eos_acl.ACL and bindings != links.keys():
                return None
            active_slots = {f"{interface}:{direction}" for interface, direction in active}
            if not before and any(links[slot] and slot not in active_slots for slot in bindings):
                return None
        return observed
    if plan["table"] in eos_l2.TABLES:
        return _observe_l2(access, plan["table"], key)
    if plan["table"] in eos_l3.TABLES:
        return observe_l3(access, plan)
    if plan["table"] in eos_services.TABLES:
        return eos_services.observe(access, plan["table"], key)
    if plan["table"] == eos.VLAN_TABLE:
        return eos.vlan_state(access.check_query("show vlan id %s" % key), key)
    if plan["table"] == "vlan-membership":
        state = eos.membership(access.check_query("show interfaces %s switchport" % key), key)
        state.update(eos.dot1x_state(access.check_query("show dot1x interface %s" % key), key))
        return state
    if plan["table"] == eos.BOUNCE_TABLE:
        return {"admin-state": "disabled"} if link_state(access, key) == "disabled" else {}
    if plan["table"] == eos.POE_TABLE:
        # show poe is Privileged EXEC (Arista EOS manual): only the write account reads the PoE state of the port
        return {"admin-state": "disabled"} if poe_answer(access, key)["configured"] == "disabled" else {}
    row = eos.description_row(access.check_query("show interfaces %s description" % key), key)
    status = eos.status_row(access.check_query("show interfaces %s status" % key), key)
    if row is None or status is None:
        return None
    state = {"description": row["description"]} if row["description"] else {}
    if status == "disabled":
        state["admin-state"] = "disabled"
    return state


# ---- 1.0.12 eos port ownership (EP14): ordered profile batches under one commit timer ----
# One configuration session holds one commit timer for the whole batch (install_safeguard). The steps are written one
# by one and read back after each write; a failing step returns the written ones in reverse order, and the timer
# returns the whole configuration when that is not proven. Routing and BGP profiles stage their change in the session
# itself, so they are not part of a batch.
BATCH_REFUSED_TABLES = eos_routing.TABLES | {eos_bgp.TABLE}
BATCH_WRITE_MARGIN_SECONDS = 15
IDLE_STATUSES = ("notconnect", "disabled", "errdisabled", "inactive", "notconnec")


def batch_read_error(exc):
    if re.search(r"timed out|timeout", str(exc), re.IGNORECASE):
        return Rejected(["the EOS profile batch preflight read timed out"], reason_codes=["eos_l2_read_timeout"])
    return eos.unreadable("profile batch preflight")


def before_write(access, record, left, device):
    """A batch step is written only while its own commit timer is pending and has time left."""
    if left < BATCH_WRITE_MARGIN_SECONDS:
        return "no time left on the commit timer"
    if not cycle_timer_pending(access, record):
        return "the commit timer of the operation is not pending"
    return None


def _batch_active(access, interface):
    """True for an interface that carries traffic now (port connected, SVI up); None when it is no endpoint."""
    if eos.ETHERNET.fullmatch(interface) or interface.startswith("Port-Channel"):
        status = eos.status_row(access.query("show interfaces %s status" % interface), interface)
        if status is None or (status != "connected" and status not in IDLE_STATUSES):
            raise eos.unreadable("batch interface status")
        return status == "connected"
    if re.fullmatch(r"Vlan[1-9][0-9]{0,3}", interface):
        try:
            row = json.loads(access.query("show interfaces %s | json" % interface))["interfaces"][interface]
            if row["name"] != interface or row["lineProtocolStatus"] not in ("up", "down"):
                raise ValueError
        except (KeyError, ValueError, TypeError):
            raise eos.unreadable("batch SVI status") from None
        return row["lineProtocolStatus"] == "up"
    return None


def batch_prechecks(access, device, plan, snapshot_text, earlier, *, undo=False):
    """Check the current state for one step; only a VLAN an earlier verified step creates is accepted as missing."""
    from netops_admin import engine
    from netops_admin.access import AccessError
    table, key = plan["table"], plan["key"]
    if table in BATCH_REFUSED_TABLES:
        raise Rejected(["the EOS %s profile stages its change in the commit timer session and is not part of a "
                        "profile batch" % table], reason_codes=["action_unsupported"])
    pending_vlans = {step["key"] for step in earlier if step["table"] == eos.VLAN_TABLE and step["op"] == "create"}
    interface = eos.interface_target(table, key)
    try:
        if interface and plan["predicted"]["before"] is not None and _batch_active(access, interface) \
                and plan.get("endpoint_impact") != key:
            raise Rejected(["the active interface %s requires endpoint_impact naming %s" % (interface, key)],
                           reason_codes=["endpoint_impact_required"])
        reasons = plan_prechecks(access, device, plan, snapshot_text, undo=undo, pending_vlans=pending_vlans)
        if reasons:
            raise Rejected(reasons)
        observed = (observe(access, plan, before=True) if "acl_attachment_links" in plan else observe(access, plan))
        seen = engine.observed_state(plan, observed)
    except AccessError as exc:
        raise batch_read_error(exc) from None
    if seen != engine.check_view(plan, plan["predicted"]["before"]):
        raise eos.unreadable("agreement between the check account and the planned starting state")


def foreign_sessions(access, device) -> int:
    return eos.users(access.query(QUERY_USERS))[1]


# eos static routing. These profiles use the existing EOS session safeguard and a scoped second readback.
def _l3_unreadable(what):
    return Rejected(["the EOS %s is incomplete or unrecognised" % what],
                    reason_codes=["eos_l3_readback_unreadable"])


def _l3_query(access, command, *, check=False, status=False):
    from netops_admin.access import AccessError
    try:
        if status:
            return access.query_status(command)
        return (access.check_query if check else access.query)(command)
    except AccessError as exc:
        if "timeout" in str(exc).lower() or "timed out" in str(exc).lower():
            raise Rejected(["EOS %s timed out" % command], reason_codes=["eos_l3_read_timeout"]) from None
        raise _l3_unreadable(command) from None


def _l3_json(access, command):
    try:
        data = json.loads(_l3_query(access, command, check=True))
    except ValueError:
        raise _l3_unreadable(command) from None
    if not isinstance(data, dict):
        raise _l3_unreadable(command)
    return data


def _port_mode(text, key):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines == ["Name: " + eos.short_name(key), "Switchport: Disabled"]:
        return "routed", None
    if "Switchport: Enabled" not in lines:
        raise _l3_unreadable("switchport state")
    try:
        shown = eos.switchport(text, key)
    except Rejected:
        raise _l3_unreadable("switchport state") from None
    if shown["mode"] != "static access":
        raise Rejected(["the port is not static access"], reason_codes=["port_uplink"])
    return None, shown["access-vlan"]


def _l3_management(access, device, plan, snapshot):
    key, table = plan["key"], plan["table"]
    if table == eos_l3.VARP_MAC:
        return
    vrfs = _ssh_vrfs(access)
    if table == eos_l3.ROUTING:
        if key in vrfs:
            raise Rejected(["IPv4/IPv6 forwarding is on the SSH management path"],
                           reason_codes=["port_management_interface"])
        return
    before, after = plan["predicted"]["before"] or {}, plan["predicted"]["after"] or {}
    name = eos_l3.target(table, key)
    if table == eos_l3.ROUTE:
        vrf, network = eos_l3.route_key(key)
        vrf = vrf or "default"
        networks, ips = [network], []
    else:
        vrf = after.get("vrf") or eos_l3.interface_vrf(snapshot, name)
        _, _, addresses = _interface_addressing(snapshot.interface_lines(name))
        addresses.update(ipaddress.ip_interface(side[field]) for side in (before, after)
                         for field in ("ipv4-address", "ipv6-address") if field in side)
        ips = [address.ip for address in addresses]
        ips.extend(ipaddress.ip_address(side["virtual-ip"]) for side in (before, after) if "virtual-ip" in side)
        networks = [address.network for address in addresses]
    if vrf not in vrfs:
        return
    peers, writer_seen = _ssh_sources(access)
    targets = {_ip(value) for value in (device.address, device.check_address or device.address)}
    if not writer_seen or None in targets:
        raise eos.unreadable("SSH management addresses")
    management = set()
    for interface in snapshot.interfaces:
        mgmt_vrf, _, addresses = _interface_addressing(snapshot.interface_lines(interface))
        if mgmt_vrf != vrf:
            continue
        if eos.MANAGEMENT.fullmatch(interface) or any(address.ip in targets or
                                                     any(peer in address.network for peer in peers)
                                                     for address in addresses):
            if interface == name:
                raise Rejected(["the interface carries management SSH"], reason_codes=["port_management_interface"])
            management.update(address.network for address in addresses)
    if targets.intersection(ips) or any(
            candidate.version == other.version and candidate.overlaps(other)
            for candidate in networks for other in (*management, *(ipaddress.ip_network(p) for p in peers | targets))):
        raise Rejected(["the route or interface overlaps the SSH management path"],
                       reason_codes=["port_management_interface"])


def _l3_port_prechecks(access, device, plan, snapshot, management_vlans):
    key = plan["key"]
    before = plan["predicted"]["before"] or {}
    mode, vlan = _port_mode(_l3_query(access, "show interfaces %s switchport" % key), key)
    if mode != before.get("mode"):
        raise _l3_unreadable("switchport mode versus running configuration")
    after = plan["predicted"]["after"]
    if mode == "routed" and not after.get("mode"):
        vlan = eos.DEFAULT_VLAN
    if vlan and (vlan in management_vlans or (snapshot.interface_lines("Vlan" + vlan)
                                             and _management_svi(access, device, snapshot, vlan))):
        raise Rejected(["the access port carries a management VLAN"], reason_codes=["port_management_vlan"])
    text = _l3_query(access, "show interfaces %s status" % key)
    status = eos.status_row(text, key)
    if status is None:
        raise eos.unreadable("interface status")
    if eos.short_name(key) in eos.lldp_ports(_l3_query(access, QUERY_LLDP)):
        raise Rejected(["the Ethernet port has an LLDP neighbor"], reason_codes=["port_lldp_neighbor"])
    if eos.learned_macs(_l3_query(access, "show mac address-table interface " + key)):
        raise Rejected(["the Ethernet port has learned MAC addresses"], reason_codes=["port_learned_mac"])
    if status == "connected" and plan.get("endpoint_impact") != key:
        raise Rejected(["changing a connected Ethernet port requires endpoint_impact naming %s" % key],
                       reason_codes=["endpoint_impact_required"])


def _mac_rows(text, vid=None):
    """Read both EOS MAC table sections and check their reported row counts."""
    sections = eos.MAC_TOTAL.split(text)
    if len(sections) != 5 or sections[-1].strip():
        raise eos.unreadable("MAC address table")
    unicast, unicast_count, multicast, multicast_count, _ = sections
    columns = "Vlan Mac Address Type Ports"
    rows = []
    for section, count, heading, header in (
        (unicast, unicast_count, "Mac Address Table", columns + " Moves Last Move"),
        (multicast, multicast_count, "Multicast Mac Address Table", columns),
    ):
        lines = [line.strip() for line in section.splitlines() if line.strip(" \t-")]
        if len(lines) != int(count) + 2 or lines[0] != heading or " ".join(lines[1].split()) != header:
            raise eos.unreadable("MAC address table")
        for line in lines[2:]:
            fields = line.split()
            if (len(fields) < 4 or not fields[0].isdigit() or (vid is not None and fields[0] != vid)
                    or not re.fullmatch(r"[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}", fields[1], re.IGNORECASE)):
                raise eos.unreadable("MAC address table")
            rows.append(line)
    return rows


def _l3_vlan_macs(access, snapshot, vid, table, *, undo):
    text = _l3_query(access, "show mac address-table vlan " + vid)
    if undo:
        blocking = [row for row in _mac_rows(text, vid) if row.split()[2] != "DYNAMIC"]
        text, count = "\n".join(blocking), len(blocking)
    else:
        count = eos.learned_macs(text)
    if table != eos_l3.VARP or count != 1:
        return count
    mac = next((match[1] for block in snapshot.blocks if (match := eos_l3.MAC_LINE.fullmatch(block.header))), "")
    # EOS programs the configured global VARP MAC on the CPU before an SVI has a virtual address.
    # Exclude only that exact local entry. Any other address still counted above fails the guard.
    digits = mac.replace(":", "").replace(".", "")
    if not re.fullmatch(r"[a-fA-F0-9]{12}", digits):
        return count
    dotted = ".".join(digits[index:index + 4] for index in (0, 4, 8))
    local = r"^\s*" + vid + r"\s+" + re.escape(dotted) + r"\s+STATIC\s+Cpu[ \t]*$"
    return 0 if re.search(local, text, flags=re.MULTILINE | re.IGNORECASE) else count


def l3_plan_prechecks(access, device, plan, snapshot_text, *, undo):
    snapshot = eos.load(snapshot_text, plan["firmware"])
    table, key = plan["table"], plan["key"]
    name = eos_l3.target(table, key)
    vlan = eos_l3.SVI.fullmatch(name)
    management_vlans = {str(v) for v in (device.audit_policy or {}).get("management_vlans", ())}
    management_vlans.update(str(v) for v in (device.protected or {}).get("vlan", ()))
    _l3_management(access, device, plan, snapshot)
    if table == eos_l3.INTERFACE and eos.ETHERNET.fullmatch(name):
        _l3_port_prechecks(access, device, plan, snapshot, management_vlans)
    if vlan:
        vid = vlan[1]
        if vid in management_vlans:
            raise Rejected(["the SVI belongs to a management VLAN"], reason_codes=["port_management_vlan"])
        _status, answer = _l3_query(access, "show vlan id " + vid, status=True)
        try:
            exists = eos.vlan_exists(answer, vid)
        except Rejected:
            raise _l3_unreadable("VLAN state") from None
        if not exists:
            raise Rejected(["the VLAN of the SVI does not exist"], reason_codes=["vlan_missing"])
        if _l3_vlan_macs(access, snapshot, vid, table, undo=undo):
            raise Rejected(["the VLAN has learned MAC addresses"], reason_codes=["port_learned_mac"])
    plan["prechecks"].append("the EOS L3 change is outside the SSH management path")
    return []


def _l3_config_state(plan, lines):
    snapshot = eos.load("\n".join((eos.COMMAND_LINE, "! device: readback (EOS, EOS-%s)" % plan["firmware"],
                                    *lines, "end")), plan["firmware"])
    table, key = plan["table"], plan["key"]
    entry = eos_l3.entries(snapshot, table, eos.Entry, key=key).get(key)
    if entry is not None and entry.unsupported:
        raise _l3_unreadable("configuration readback")
    return None if entry is None else entry.attributes


def _l3_routing_state(access, key):
    command = "show vrf | json"
    data = _l3_json(access, command)
    try:
        protocols = data["vrfs"][key]["protocols"]
        values = {name: protocols[name]["routingState"] for name in eos_l3.ROUTING_COMMANDS}
        if any(value not in ("up", "down") for value in values.values()):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise _l3_unreadable(command) from None
    return {name: "enabled" for name, value in values.items() if value == "up"}


def _l3_varp_state(access, table, name):
    command = "show ip virtual-router | json"
    data = _l3_json(access, command)
    try:
        if not isinstance(data["virtualMacs"], list) or not isinstance(data["virtualRouters"], list):
            raise ValueError
        if table == eos_l3.VARP_MAC:
            mac, = [item["macAddress"] for item in data["virtualMacs"] if item["macType"] == "varp"]
            if mac == "00:00:00:00:00:00":
                return {}
            return eos_l3.canonical_changes({"mac-address": mac})
        routers = [item for item in data["virtualRouters"] if item["interface"] == name]
        if not routers:
            return None
        router, = routers
        vip, = router["virtualIps"]
        if vip["mask"] != 32:
            raise ValueError
        return eos_l3.canonical_changes({"virtual-ip": vip["ip"]})
    except (KeyError, TypeError, ValueError, Rejected):
        raise _l3_unreadable(command) from None


def observe_l3(access, plan):
    key, table = plan["key"], plan["table"]
    if table == eos_l3.ROUTING:
        return _l3_routing_state(access, key)
    if table in (eos_l3.VARP, eos_l3.VARP_MAC):
        return _l3_varp_state(access, table, eos_l3.target(table, key))
    if table == eos_l3.ROUTE:
        # The FIB omits an unresolved or inactive configured static route. Include EOS's end marker to
        # distinguish an empty configured route list from an incomplete reply.
        command = "show running-config | include ^ip route |^ipv6 route |^end$"
        lines = _l3_query(access, command).strip().splitlines()
        if not lines or lines[-1] != "end" or any(not line.startswith(("ip route ", "ipv6 route "))
                                                 for line in lines[:-1]):
            raise _l3_unreadable(command)
        return _l3_config_state(plan, lines[:-1])
    name = eos_l3.target(table, key)
    command = "show running-config interfaces " + name
    # show vrrp requires privilege 15 and its operational view can omit a configured instance in a
    # non-default VRF. Use the targeted configuration read from the privileged account.
    lines = _l3_query(access, command).rstrip().splitlines()
    if not lines:
        if table != eos_l3.INTERFACE or not eos_l3.SVI.fullmatch(name):
            raise _l3_unreadable(command)
        answer = _l3_query(access, "show interfaces %s | json" % name, check=True)
        if not re.search(r"^% Interface does not exist(?: at line [0-9]+)?$", answer, re.MULTILINE):
            raise _l3_unreadable("missing SVI")
        return None
    if lines[0] != "interface " + name or any(not line.startswith(eos.INDENT) for line in lines[1:]):
        raise _l3_unreadable(command)
    state = _l3_config_state(plan, lines)
    if table == eos_l3.INTERFACE and eos.ETHERNET.fullmatch(name):
        mode, _ = _port_mode(_l3_query(access, "show interfaces %s switchport" % name, check=True), name)
        if mode != state.get("mode"):
            raise _l3_unreadable("routed port mode")
    return state


def _acl_unreadable():
    return eos_acl.refuse("the EOS ACL readback is incomplete, inconsistent or unrecognised",
                          "eos_acl_readback_unreadable")


def _acl_query(access, command, *, check=False):
    from netops_admin.access import AccessError

    try:
        return (access.check_query if check else access.query)(command)
    except AccessError as exc:
        if "timeout" in str(exc).lower() or "timed out" in str(exc).lower():
            raise eos_acl.refuse("EOS ACL preflight or readback timed out", "eos_acl_read_timeout") from None
        raise _acl_unreadable() from None


def _acl_check_account(access, plan):
    """Keep the independent management login check when ACL inspection itself requires privilege 15."""
    try:
        version = eos.image_version(_acl_query(access, QUERY_VERSION, check=True))
    except Rejected as exc:
        if "eos_acl_read_timeout" in exc.reason_codes:
            raise
        raise _acl_unreadable() from None
    if version != plan["firmware"]:
        raise _acl_unreadable()


def _acl_json(access, family, selection):
    # EOS marks these commands Privileged EXEC and netops-ro refuses them on cEOS 4.36.1F.
    # A separate operating-state read complements the exec engine's full running-config verification.
    command = "show %s access-lists %s | json" % (eos_acl.FAMILIES[family], selection)
    try:
        data = json.loads(_acl_query(access, command))
        rows = data["aclList"]
        if not isinstance(rows, list) or type(data["phoneAclBypass"]) is not bool:
            raise ValueError
        names = set()
        for row in rows:
            name = row["name"]
            if (not isinstance(name, str) or not name or name in names
                    or row["type"] != ("Ip4Acl" if family == "ipv4" else "Ip6Acl")
                    or type(row["readonly"]) is not bool or type(row["standard"]) is not bool
                    or type(row["dynamic"]) is not bool):
                raise ValueError
            names.add(name)
        return rows
    except (KeyError, TypeError, ValueError):
        raise _acl_unreadable() from None


def _acl_attachments(row, mode):
    items = set()
    for direction, eos_direction in (("in", "Ingress"), ("out", "Egress")):
        values = row[mode + eos_direction + "Intfs"]
        if not isinstance(values, list):
            raise ValueError
        for item in values:
            interface = item["name"]
            pair = (interface, direction)
            if not isinstance(interface, str) or not interface or pair in items:
                raise ValueError
            items.add(pair)
    return items


def _observe_acl(access, plan):
    """Read configured ACLs or attachments, including inactive attachments on unused links."""
    try:
        if plan["table"] == eos_acl.BINDING:
            interface, family, direction = plan["key"].split(":")
            names = []
            target = (interface, direction)
            target_active = set()
            for row in _acl_json(access, family, "interface " + interface):
                configured = _acl_attachments(row, "configured")
                active = _acl_attachments(row, "active")
                if target in configured:
                    names.append(row["name"])
                    target_active = active & {target}
                if (not active <= configured or not any(i == interface for i, _ in configured)
                        or (target in configured and row["notFullySupportedByHardware"] is not False)):
                    raise ValueError
            if len(names) > 1:
                raise ValueError
            return ({"acl": names[0]} if names else {}), ({target} if names else set()), target_active

        family, name = plan["key"].split(":")
        rows = _acl_json(access, family, name)
        if not rows:
            return None, set(), set()
        row, = rows
        if row["name"] != name or any(row[field] for field in ("readonly", "standard", "dynamic", "countersEnabled")):
            raise ValueError
        sequence = row["sequence"]
        if (not isinstance(sequence, list) or type(row["sequenceLength"]) is not int
                or len(sequence) != row["sequenceLength"]):
            raise ValueError
        rules = []
        previous = 0
        for rule in sequence:
            number = rule["sequenceNumber"]
            if type(number) is not int or number <= previous or not isinstance(rule["text"], str) or "," in rule["text"]:
                raise ValueError
            parsed = eos_acl.rules(f"{number} {rule['text']}", family)[number]
            previous = number
            dst = rule["ruleFilter"]["dstPort"]
            if " eq " in parsed:
                if dst["oper"] != "eq" or dst["ports"] != [int(parsed.rsplit(" ", 1)[-1])]:
                    raise ValueError
            elif dst["oper"] != "any" or dst["ports"] != []:
                raise ValueError
            rules.append(parsed)
        configured = _acl_attachments(row, "configured")
        active = _acl_attachments(row, "active")
        if not active <= configured or (configured and row["notFullySupportedByHardware"] is not False):
            raise ValueError
        return ({"rules": ", ".join(rules)} if rules else {}), configured, active
    except (KeyError, TypeError, ValueError, Rejected) as exc:
        if isinstance(exc, Rejected) and "eos_acl_read_timeout" in exc.reason_codes:
            raise
        raise _acl_unreadable() from None


def _acl_route_interfaces(access, vrf, peer):
    protocol = "ip" if peer.version == 4 else "ipv6"
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", vrf):
        raise _acl_unreadable()
    answer = _acl_query(access, f"show {protocol} route vrf {vrf} {peer} | json")
    try:
        routes = json.loads(answer)["vrfs"][vrf]["routes"]
        if not isinstance(routes, dict):
            raise ValueError
        if not routes:
            return set()
        prefix, route = next(iter(routes.items()))
        if len(routes) != 1 or peer not in ipaddress.ip_network(prefix) or route["routeAction"] != "forward":
            raise ValueError
        hops = route["vias"]
        if not isinstance(hops, list) or not hops:
            raise ValueError
        interfaces = {hop["interface"] for hop in hops}
        if not all(isinstance(interface, str) and interface for interface in interfaces):
            raise ValueError
        return interfaces
    except (KeyError, ValueError, TypeError):
        raise _acl_unreadable() from None


def _acl_management_interfaces(access, device, snapshot):
    writer_target, check_target = device.address, device.check_address or device.address
    targets = {}
    for target in {writer_target, check_target}:
        literal = _ip(target)
        try:
            addresses = {literal} if literal is not None else {_ip(ip) for ip in access.resolve_addresses(target)}
        except OSError:
            raise _acl_unreadable() from None
        if not addresses or None in addresses:
            raise _acl_unreadable()
        targets[target] = addresses

    local = {}
    target_ips = set().union(*targets.values())
    for interface in snapshot.interfaces:
        vrf, _, addresses = _interface_addressing(snapshot.interface_lines(interface))
        for address in addresses:
            if (ip := _ip(str(address.ip))) in target_ips:
                local.setdefault(ip, set()).add((interface, vrf))
    paths = {interface for matches in local.values() for interface, _ in matches}

    # A hostname can have multiple destinations, and a target can be translated by DNAT.
    # Keep looking up live routes in the SSH-enabled VRFs for those targets.
    literals = {_ip(target) for target in targets}
    vrfs = {vrf for ip in literals for _, vrf in local.get(ip, ())}
    if len(literals & local.keys()) != len(targets):
        vrfs.update(_ssh_vrfs(access, text=_acl_query(access, QUERY_SSH_STATUS)))

    sessions = _ssh_sources_by_account(access, query=lambda command: _acl_query(access, command))
    writer_peers = sessions[access.credential.login]
    check = getattr(access, "check_credential", None)
    check_peers = sessions[check.login] if check is not None else set()
    check_ips = targets[check_target]
    # The independent version check has already connected from this client. If its
    # session is gone, reuse the writer's path only for the same single destination.
    shared_destination = check_ips == targets[writer_target] and len(check_ips) == 1
    if not vrfs or not writer_peers or (not check_peers and not shared_destination):
        raise _acl_unreadable()

    routes = {}
    for peer in writer_peers | check_peers:
        for vrf in sorted(vrfs):
            outgoing = _acl_route_interfaces(access, vrf, peer)
            if outgoing:
                routes.setdefault(peer, set()).add(vrf)
                paths.update(outgoing)
    for target, peers in ((writer_target, writer_peers), (check_target, check_peers)):
        if not peers:
            continue
        peer_vrfs = {}
        for peer in peers:
            if peer not in routes:
                raise _acl_unreadable()
            peer_vrfs.setdefault(peer.version, set()).update(routes[peer])
        for ip in targets[target]:
            reachable = peer_vrfs.get(ip.version, set())
            if not reachable or any(vrf not in reachable for _, vrf in local.get(ip, ())):
                raise _acl_unreadable()
    return paths


def _acl_svi_connected(access, interface):
    answer = _acl_query(access, f"show interfaces {interface} | json")
    try:
        row = json.loads(answer)["interfaces"][interface]
        status = row["lineProtocolStatus"]
        if row["name"] != interface or status not in ("up", "down"):
            raise ValueError
        return status == "up"
    except (KeyError, ValueError, TypeError):
        raise _acl_unreadable() from None


def _acl_routed_endpoint(access, snapshot, interface):
    lines = snapshot.interface_lines(interface)
    vrf, _, addresses = _interface_addressing(lines)
    if (not addresses or not re.fullmatch(r"[A-Za-z0-9_.-]+", vrf) or vrf.casefold() == "all"
            or any(line.startswith(("channel-group ", "ip ospf ", "ipv6 ospf ", "isis enable ")) for line in lines)):
        return False
    for block in snapshot.blocks:
        process = re.fullmatch(r"router ospf [0-9]+(?: vrf (\S+))?", block.header)
        if process and (process[1] or "default") == vrf:
            try:
                networks = eos_routing.process_networks(block)
            except ValueError:
                raise _acl_unreadable() from None
            if any(address.ip in network for network in networks for address in addresses):
                return False
    commands = {4: f"show ip arp vrf {vrf} interface {interface} | json",
                6: f"show ipv6 neighbors vrf {vrf} {interface} | json"}
    entries = []
    for family in sorted({address.version for address in addresses}):
        answer = _acl_query(access, commands[family])
        try:
            data = json.loads(answer)
            if not isinstance(data, dict) or data.get("notLearnedEntries", 0) != 0:
                raise ValueError
            entries.extend(eos_clear.neighbor_entries(data, f"ipV{family}Neighbors"))
        except (ValueError, Rejected):
            raise _acl_unreadable() from None
    macs, peers = set(), set()
    own = {address.ip for address in addresses}
    for entry in entries:
        peer = ipaddress.ip_address(entry["address"])
        if (entry["interface"] != interface or entry["port"] is not None or not entry["dynamic"]
                or peer in own or peer.is_multicast or peer.is_unspecified or peer.is_loopback
                or not any(peer in address.network or address.version == peer.version == 6 and peer.is_link_local
                           for address in addresses)):
            return False
        macs.add(eos_clear.mac(entry["mac"]))
        peers.add(peer)
    if len(macs) != 1 or None in macs:
        return False
    for line in snapshot.lines:
        route = eos_l3.ROUTE_LINE.fullmatch(line)
        if route and (route[2] or "default") == vrf:
            if any(eos_clear.ethernet(word) == interface or _ip(word) in peers for word in (route[4] or "").split()):
                return False
    bgp = eos_bgp.router(snapshot)
    return bgp is None or not any(len(words) >= 2 and words[0] == "neighbor" and _ip(words[1]) in peers
                                for line in bgp.children if (words := line.split()))


def _acl_interface_precheck(access, device, plan, interface, management, snapshot):
    mgmt_vlans = {str(vid) for vid in (device.audit_policy or {}).get("management_vlans", ())}
    mgmt_vlans.update(str(vid) for vid in (device.protected or {}).get("vlan", ()))
    if interface in management:
        raise eos_acl.refuse("the ACL interface carries management SSH", "port_management_interface")
    svi = eos_acl.SVI.fullmatch(interface)
    if svi:
        if svi[1] in mgmt_vlans:
            raise eos_acl.refuse("the ACL SVI carries a management VLAN", "port_management_vlan")
        # A configured SVI may carry traffic even if its own addresses are absent.
        if plan.get("endpoint_impact") != plan["key"]:
            raise eos_acl.refuse("an ACL change on an SVI requires endpoint_impact naming the request key",
                                 "endpoint_impact_required")
        return _acl_svi_connected(access, interface)

    mode, vlan = _port_mode(_acl_query(access, f"show interfaces {interface} switchport"), interface)
    if vlan and (vlan in mgmt_vlans or "Vlan" + vlan in management):
        raise eos_acl.refuse("the ACL interface carries a management VLAN", "port_management_vlan")
    status = eos.status_row(_acl_query(access, f"show interfaces {interface} status"), interface)
    if status not in {"connected", "notconnect", "disabled", "errdisabled"}:
        raise _acl_unreadable()
    short_name = eos.short_name(interface)
    if short_name in eos.lldp_ports(_acl_query(access, QUERY_LLDP)):
        raise eos_acl.refuse("the ACL interface has an LLDP neighbor", "port_lldp_neighbor")
    connected = status == "connected"
    if mode == "routed":
        rows = []
        single_endpoint = connected and _acl_routed_endpoint(access, snapshot, interface)
    else:
        rows = _mac_rows(_acl_query(access, "show mac address-table interface " + interface), vlan)
        single_endpoint = len(rows) == 1 and rows[0].split()[2:4] == ["DYNAMIC", short_name]
    if connected and not single_endpoint:
        raise eos_acl.refuse("the connected ACL interface has no proven single endpoint", "port_uplink")
    if (connected or rows) and plan.get("endpoint_impact") != plan["key"]:
        raise eos_acl.refuse("a connected ACL interface requires endpoint_impact naming the request key",
                             "endpoint_impact_required")
    return connected


def _acl_plan_prechecks(access, device, plan, snapshot_text):
    snapshot = eos.load(snapshot_text, plan["firmware"])
    _acl_check_account(access, plan)
    observed, configured, _ = _observe_acl(access, plan)
    if observed != plan["predicted"]["before"]:
        raise _acl_unreadable()
    if plan["table"] == eos_acl.BINDING:
        interface, _, direction = plan["key"].split(":")
        configured = {(interface, direction)}
    elif eos_acl.references(snapshot, plan["key"]) != configured:
        raise _acl_unreadable()
    links = {}
    if configured:
        try:
            management = _acl_management_interfaces(access, device, snapshot)
            for interface in sorted({interface for interface, _ in configured}):
                links[interface] = _acl_interface_precheck(access, device, plan, interface, management, snapshot)
                plan["prechecks"].append("ACL impact on %s checked against management, uplink and endpoint state" % interface)
        except Rejected as exc:
            if not {"unspecified_refusal", "eos_l3_readback_unreadable"} & set(exc.reason_codes):
                raise
            raise _acl_unreadable() from None
    plan["acl_attachment_links"] = {f"{interface}:{direction}": links[interface]
                                    for interface, direction in sorted(configured)}
    return []


def _l2_unreadable(command):
    return Rejected(["EOS %s is incomplete or unrecognised" % command],
                    reason_codes=["eos_l2_readback_unreadable"])


def _l2_read(access, command, *, status=False, check=False):
    from netops_admin.access import AccessError

    try:
        if check:
            rc, text = access.check_query_status(command)
            if rc and not status:
                raise _l2_unreadable(command)
            answer = (rc, text) if status else text
        else:
            answer = access.query_status(command) if status else access.query(command)
    except AccessError as exc:
        if "timeout" in str(exc).lower() or "timed out" in str(exc).lower():
            raise Rejected(["EOS %s timed out" % command], reason_codes=["eos_l2_read_timeout"]) from None
        raise _l2_unreadable(command) from None
    text = answer[1] if status else answer
    if "--More--" in text or "\ufffd" in text:
        raise _l2_unreadable(command)
    return answer


def _l2_json(text, command):
    try:
        data = json.loads(text)
    except ValueError:
        raise _l2_unreadable(command) from None
    if not isinstance(data, dict):
        raise _l2_unreadable(command)
    return data


def _l2_interface(access, name, *, check=False):
    command = "show interfaces %s | json" % name
    rc, text = _l2_read(access, command, status=True, check=check)
    lines = [line for line in text.splitlines() if line.strip() and line != "> " + command]
    if rc == 1 and len(lines) == 1 and re.fullmatch(r"% Interface does not exist(?: at line 1)?", lines[0]):
        return None
    if rc:
        raise _l2_unreadable(command)
    interfaces = _l2_json(text, command).get("interfaces")
    if not isinstance(interfaces, dict) or set(interfaces) != {name}:
        raise _l2_unreadable(command)
    info = interfaces[name]
    if not isinstance(info, dict) or info.get("name") != name or not isinstance(info.get("interfaceStatus"), str):
        raise _l2_unreadable(command)
    return info


def _l2_show_mlag(access, *, check=False):
    command = "show mlag | json"
    data = _l2_json(_l2_read(access, command, check=check), command)
    if any(not isinstance(data.get(field), str) for field in
           ("state", "localInterface", "peerAddress", "peerLink")):
        raise _l2_unreadable(command)
    return data


def _l2_show_mlag_interfaces(access, *, check=False):
    command = "show mlag interfaces | json"
    data = _l2_json(_l2_read(access, command, check=check), command).get("interfaces")
    if not isinstance(data, dict) or any(
            not ident.isdecimal() or not isinstance(entry, dict)
            or any(not isinstance(entry.get(field), str) for field in ("localInterface", "peerInterface", "status"))
            for ident, entry in data.items()):
        raise _l2_unreadable(command)
    return data


def _l2_mgmt_vlan(access, device, snapshot, vid):
    policy_vlans = {str(number) for number in (device.audit_policy or {}).get("management_vlans", ())}
    protected_vlans = set(device.protected.get("vlan", ()))
    protected_vlans.update(name[4:] for name in device.protected.get("interface", ()) if name.startswith("Vlan"))
    try:
        management = vid in policy_vlans | protected_vlans or _management_svi(access, device, snapshot, vid)
    except Rejected:
        raise
    except Exception:
        raise _l2_unreadable("management path for VLAN %s" % vid) from None
    if management:
        raise Rejected(["VLAN %s is protected or carries management" % vid], reason_codes=["port_management_vlan"])


def _l2_switchport(access, name, *, peer=False):
    command = "show interfaces %s switchport" % name
    text = _l2_read(access, command)
    if "Switchport: Disabled" in text.splitlines():
        raise Rejected(["%s is routed" % name], reason_codes=["port_routed"])
    if "Switchport: Enabled" not in text.splitlines():
        raise _l2_unreadable(command)
    try:
        shown = eos.membership(text, name)
    except Rejected:
        raise _l2_unreadable(command) from None
    if shown["mode"] != ("trunk" if peer else "access"):
        raise Rejected(["%s is not in the expected static switchport mode" % name], reason_codes=["port_uplink"])
    return shown


def _l2_no_endpoints(access, name, neighbors):
    if name in neighbors:
        raise Rejected(["%s has an LLDP neighbor" % name], reason_codes=["port_lldp_neighbor"])
    command = "show mac address-table interface " + name
    text = _l2_read(access, command)
    try:
        rows = _mac_rows(text)
    except Rejected:
        raise _l2_unreadable(command) from None
    if rows:
        raise Rejected(["%s has MAC table entries" % name], reason_codes=["port_learned_mac"])


def _l2_lldp_ports(access):
    command = "show lldp neighbors | json"
    rows = _l2_json(_l2_read(access, command), command).get("lldpNeighbors")
    if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("port"), str)
                                        for row in rows):
        raise _l2_unreadable(command)
    return {row["port"] for row in rows}


def _l2_stp_vlan_prechecks(access, device, snapshot, key):
    _l2_mgmt_vlan(access, device, snapshot, key)
    command = "show vlan id %s | json" % key
    rc, text = _l2_read(access, command, status=True)
    missing = eos.VLAN_MISSING.search(text)
    if rc == 1 and missing and missing[1] == key:
        raise Rejected(["VLAN %s does not exist" % key], reason_codes=["vlan_missing"])
    if rc:
        raise _l2_unreadable(command)
    vlans = _l2_json(text, command).get("vlans")
    vlan = vlans.get(key) if isinstance(vlans, dict) and set(vlans) == {key} else None
    ports = vlan.get("interfaces") if isinstance(vlan, dict) else None
    if not isinstance(ports, dict) or any(not isinstance(port, dict) for port in ports.values()):
        raise _l2_unreadable(command)
    # EOS lists the local CPU alongside physical switchports. The SVI was checked above.
    switchports = ports.keys() - {"Cpu"}
    if any(not re.fullmatch(eos_l2.ETHERNET, port) and not re.fullmatch(eos_l2.CHANNEL_NAME, port)
           for port in switchports):
        raise _l2_unreadable(command)
    channels = {port for port in switchports if port.startswith("Port-Channel")}
    affected = switchports.copy()
    for port in channels:
        affected.update(eos_l2.member_ports(snapshot, port.removeprefix("Port-Channel")))
    if eos_l2.protected_interfaces(device.protected) & {port.casefold() for port in affected}:
        raise Rejected(["the VLAN is carried by a protected interface"], reason_codes=["port_protected"])
    peer_link = eos_l2.peer_settings(snapshot).get("peer-link")
    if peer_link in affected or (peer_link and affected & eos_l2.member_ports(
            snapshot, peer_link.removeprefix("Port-Channel"))):
        raise Rejected(["the VLAN is carried by the MLAG peer link"], reason_codes=["port_uplink"])
    if affected and affected & _l2_lldp_ports(access):
        raise Rejected(["an interface carrying the VLAN has an LLDP neighbor"], reason_codes=["port_uplink"])
    for port in sorted(switchports):
        _l2_switchport(access, port)
        if port in channels:
            info = _l2_interface(access, port)
            if info is None or info["interfaceStatus"] not in {"connected", "disabled", "notconnect", "lowerlayerdown"}:
                raise _l2_unreadable("operational state of " + port)
            if info["interfaceStatus"] == "connected":
                raise Rejected(["the VLAN is carried by a connected Port-Channel"], reason_codes=["port_uplink"])


def _l2_plan_prechecks(access, device, plan, snapshot):
    table, key = plan["table"], plan["key"]
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    if table == eos_l2.STP_VLAN:
        _l2_stp_vlan_prechecks(access, device, snapshot, key)
        return []
    if table == eos_l2.CHANNEL and before is None:
        return []
    affected = eos_l2.affected_interfaces(snapshot, table, key, before, after)
    if table == eos_l2.MLAG_PEER and _l2_show_mlag(access)["state"] not in {"disabled", "inactive"}:
        raise Rejected(["the MLAG domain is active or negotiating"], reason_codes=["port_uplink"])
    if table == eos_l2.MLAG_PORT and after:
        id_state = _l2_show_mlag_interfaces(access).get(after["mlag-id"], {})
        if id_state.get("peerInterface") not in (None, "", "None", key):
            raise Rejected(["the peer uses this MLAG ID on another Port-Channel"],
                           reason_codes=["eos_l2_dependency"])
    peers = {side.get("peer-link") for side in (before, after) if side} if table == eos_l2.MLAG_PEER else set()
    neighbors = None
    for name in sorted(affected):
        if name.startswith("Vlan"):
            _l2_mgmt_vlan(access, device, snapshot, name[4:])
            continue
        info = _l2_interface(access, name)
        if info is None:
            raise _l2_unreadable("operational state of " + name)
        state = info["interfaceStatus"]
        if state == "connected":
            raise Rejected(["%s is connected" % name], reason_codes=["port_lag_active"])
        if state not in {"disabled", "notconnect", "lowerlayerdown"}:
            raise _l2_unreadable("operational state of " + name)
        # A peer-link must be a dedicated trunk. Physical members use the VLANs of its logical interface.
        if name in peers or not any(name in eos_l2.member_ports(snapshot, link.removeprefix("Port-Channel"))
                                    for link in peers if link):
            shown = _l2_switchport(access, name, peer=name in peers)
            if name in peers:
                allowed = eos.vlan_numbers(shown["allowed-vlans"])
                for vlan_name in snapshot.interfaces:
                    if re.fullmatch(eos_l2.VLAN_NAME, vlan_name) and int(vlan_name[4:]) in allowed:
                        _l2_mgmt_vlan(access, device, snapshot, vlan_name[4:])
                for vid in (device.audit_policy or {}).get("management_vlans", ()):
                    if int(vid) in allowed:
                        _l2_mgmt_vlan(access, device, snapshot, str(vid))
            else:
                _l2_mgmt_vlan(access, device, snapshot, shown["access-vlan"])
        if neighbors is None:
            neighbors = _l2_lldp_ports(access)
        _l2_no_endpoints(access, name, neighbors)
    return []


def _l2_channel_member(access, name):
    command = "show interfaces %s status | json" % name
    data = _l2_json(_l2_read(access, command, check=True), command)
    try:
        interfaces = data["interfaceStatuses"]
        if not isinstance(interfaces, dict) or set(interfaces) != {name}:
            raise ValueError
        vlan = interfaces[name]["vlanInformation"]
        model = vlan["interfaceForwardingModel"]
        if model == "bridged" and "vlanExplanation" not in vlan:
            return {}
        group = re.fullmatch(r"in Po([1-9][0-9]{0,5})", vlan["vlanExplanation"])
        if model != "dataLink" or not group:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise _l2_unreadable(command) from None

    command = "show port-channel dense | json"
    data = _l2_json(_l2_read(access, command, check=True), command)
    try:
        entry = data["portChannels"]["Port-Channel" + group[1]]
        port = entry["ports"][name]
        if port["intf"] != name:
            raise ValueError
        if entry["protocol"] == "static" and port["staticLag"] is True:
            return {"group": group[1], "mode": "on"}
        activity = port["lacpState"]["activity"]
        if entry["protocol"] != "lacp" or port["staticLag"] is not False or type(activity) is not bool:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise _l2_unreadable(command) from None
    return {"group": group[1], "mode": "active" if activity else "passive"}


def _l2_stp_port(access, name):
    command = "show spanning-tree interface %s detail | json" % name
    data = _l2_json(_l2_read(access, command, check=True), command)
    if data.get("interface") != name or data.get("spanningTreeInstances") != {}:
        raise _l2_unreadable(command)
    info = _l2_interface(access, name, check=True)
    if info is None or info["interfaceStatus"] not in {"disabled", "notconnect", "lowerlayerdown"}:
        raise _l2_unreadable("inactive STP interface " + name)
    # An unused port has no operational STP instance. The snapshot verifies its configured attributes;
    # the operator independently verifies the named port exists and remains inactive.
    return {}


def _l2_stp_vlan(access, key):
    command = "show spanning-tree vlan %s detail | json" % key
    data = _l2_json(_l2_read(access, command, check=True), command)
    try:
        instances = data["spanningTreeVlanInstances"]
        if not isinstance(instances, dict) or set(instances) != {key}:
            raise ValueError
        instance = instances[key]["spanningTreeVlanInstance"]
        bridge = instance["bridge"]
        priority, extension = bridge["priority"], bridge["systemIdExtension"]
        if (instance["protocol"] != "rapidPvst" or type(extension) is not int or extension != int(key)
                or type(priority) is not int):
            raise ValueError
        # The bridge identifier can carry the priority and VLAN in the same integer.
        if priority % 4096 == extension:
            priority -= extension
        if not 0 <= priority <= 61440 or priority % 4096:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise _l2_unreadable(command) from None
    return {"priority": str(priority)}


def _observe_l2(access, table, key):
    if table == eos_l2.CHANNEL:
        info = _l2_interface(access, key, check=True)
        if info is None:
            return None
        description = info.get("description")
        if not isinstance(description, str):
            raise _l2_unreadable("description of " + key)
        return {"description": description} if description else {}
    if table == eos_l2.MEMBER:
        return _l2_channel_member(access, key)
    if table == eos_l2.STP_PORT:
        return _l2_stp_port(access, key)
    if table == eos_l2.STP_VLAN:
        return _l2_stp_vlan(access, key)
    if table == eos_l2.MLAG_PEER:
        data = _l2_show_mlag(access, check=True)
        return {field: data[name] for field, name in (
            ("local-interface", "localInterface"), ("peer-address", "peerAddress"), ("peer-link", "peerLink"))
                if data[name] not in ("", "0.0.0.0")}
    rows = _l2_show_mlag_interfaces(access, check=True)
    ids = [ident for ident, row in rows.items() if row["localInterface"] == key]
    if len(ids) > 1:
        raise _l2_unreadable("ambiguous local MLAG ID for " + key)
    return {"mlag-id": ids[0]} if ids else {}


def _routing_unreadable():
    return eos_routing.refuse("EOS routing readback is incomplete or unrecognised", "eos_routing_readback_unreadable")


def _routing_query(access, command, *, check=True):
    from netops_admin.access import AccessError

    try:
        return (access.check_query if check else access.query)(command)
    except AccessError as exc:
        if "timeout" in str(exc).lower() or "timed out" in str(exc).lower():
            raise eos_routing.refuse("EOS routing preflight or readback timed out", "eos_routing_read_timeout") from None
        raise _routing_unreadable() from None


def _routing_dict(value):
    if not isinstance(value, dict):
        raise ValueError
    return value


def _routing_json(access, command):
    return _routing_dict(json.loads(_routing_query(access, command)))


def _routing_management_routes(access, device, snapshot):
    """Find the paths from each SSH management VRF to the live NetOps source."""
    try:
        peers, writer_seen = _ssh_sources(access, query=lambda cmd: _routing_query(access, cmd, check=False))
        vrfs = _ssh_vrfs(access, text=_routing_query(access, QUERY_SSH_STATUS, check=False))
    except Rejected as exc:
        if "eos_routing_read_timeout" in exc.reason_codes:
            raise
        raise _routing_unreadable() from None
    if not writer_seen or not vrfs:
        raise _routing_unreadable()
    targets = {_ip(device.address), _ip(device.check_address or device.address)} - {None}
    interfaces = {name for name in snapshot.interfaces
                  if any(ip.ip in targets for ip in _interface_addressing(snapshot.interface_lines(name))[2])}
    routes = []
    for peer in peers:
        matched = False
        protocol = "ip" if peer.version == 4 else "ipv6"
        for vrf in sorted(vrfs):
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", vrf):
                raise _routing_unreadable()
            try:
                answer = _routing_json(access, f"show {protocol} route vrf {vrf} {peer} | json")
                entries = _routing_dict(answer["vrfs"][vrf]["routes"])
                if not entries:
                    continue
                (prefix, route), = entries.items()
                via = route["vias"]
                egress = {hop["interface"] for hop in via}
                if (peer not in ipaddress.ip_network(prefix) or route["routeAction"] != "forward"
                        or not egress or not all(isinstance(port, str) and port for port in egress)
                        or not isinstance(route["routeType"], str) or not route["routeType"]):
                    raise ValueError
            except (KeyError, ValueError, TypeError):
                raise _routing_unreadable() from None
            matched = True
            interfaces.update(egress)
            routes.append((vrf, peer, route["routeType"].lower()))
        if not matched:
            raise _routing_unreadable()
    return interfaces, routes


def _routing_plan_prechecks(access, device, plan, snapshot_text):
    table, key = plan["table"], plan["key"]
    if table in eos_routing.OSPF_TABLES:
        snapshot = eos.load(snapshot_text, plan["firmware"])
        affected = eos_routing.affected_interfaces(snapshot, table, key)
        eos_routing.protect_interfaces(affected, device.protected or {},
                                       (device.audit_policy or {}).get("management_vlans", ()))
        management, routes = _routing_management_routes(access, device, snapshot)
        prefix = ipaddress.ip_network(key.partition(":")[2]) if table == eos_routing.OSPF_NETWORK else None
        if affected & management or any(
            vrf == "default" and (kind.startswith("ospf") or (prefix is not None and peer in prefix))
            for vrf, peer, kind in routes
        ):
            raise eos_routing.refuse("the OSPF change can affect the active SSH management path",
                                     "port_management_interface")
        plan["prechecks"].append("OSPF scope checked against the live routes to the NetOps SSH source")
    return []


def _bgp_plan_prechecks(access, device, plan, snapshot_text):
    snapshot = eos.load(snapshot_text, plan["firmware"])
    _, peer = eos_bgp.target(plan["key"])
    interface = eos_bgp.connected_interface(snapshot, peer)
    eos_routing.protect_interfaces({interface}, device.protected or {},
                                   (device.audit_policy or {}).get("management_vlans", ()))
    management, routes = _routing_management_routes(access, device, snapshot)
    if interface in management or any(vrf == "default" and (kind.startswith("bgp") or source == peer)
                                      for vrf, source, kind in routes):
        raise eos_routing.refuse("the BGP neighbor can affect the active SSH management path",
                                 "port_management_interface")
    plan["prechecks"].append("The BGP peer interface was checked against the live NetOps SSH paths")
    return []


def _ospf_instances(access, suffix=""):
    data = _routing_json(access, f"show ip ospf{suffix} | json")
    vrfs = _routing_dict(data["vrfs"])
    if "default" not in vrfs:
        return {}
    return _routing_dict(vrfs["default"]["instList"])


def _ospf_readback(access, plan):
    table, key = plan["table"], plan["key"]
    process, _, target = key.partition(":")
    if table == eos_routing.OSPF_PROCESS:
        instance = _ospf_instances(access).get(process)
        if instance is None:
            return None
        if instance["instanceId"] != int(process) or instance["shutDown"] is not False:
            raise ValueError
        # Process creation requires an explicit router ID. An auto-selected ID cannot be deleted by this profile.
        return {"router-id": str(ipaddress.IPv4Address(instance["routerId"]))}

    # The write snapshot names the targeted interface(s) and distinguishes a configured cost
    # from the automatic cost. Area, passive state and explicit cost come from the RO account.
    snapshot = eos.load(access.snapshot(), plan["firmware"])
    targets = eos_routing.affected_interfaces(snapshot, table, key)
    areas = set()
    seen = set()
    for interface in sorted(targets):
        instances = _ospf_instances(access, f" interface {interface}")
        if process not in instances:
            if table == eos_routing.OSPF_NETWORK and process in _ospf_instances(access):
                continue
            raise ValueError
        row = _routing_dict(instances[process]["interfaces"]).get(interface)
        if row is None and table == eos_routing.OSPF_NETWORK:
            continue
        if not isinstance(row, dict) or type(row["cost"]) is not int or type(row["passive"]) is not bool:
            raise ValueError
        area = eos_routing.area_id(row["area"])
        address = ipaddress.IPv4Address(row["interfaceAddress"])
        if address not in eos_routing.addresses(snapshot, interface):
            raise ValueError
        if table == eos_routing.OSPF_INTERFACE:
            explicit = any(eos_routing.COST.fullmatch(line) for line in snapshot.interface_lines(interface))
            result = {"cost": str(row["cost"])} if explicit else {}
            block = eos_routing.process_blocks(snapshot)[process]
            configured = any(eos_routing.owns(table, key, block.header, line) for line in block.children)
            if configured or row["passive"]:
                result["passive"] = "enabled" if row["passive"] else "disabled"
            return result
        if address in ipaddress.IPv4Network(target):
            seen.add(interface)
            areas.add(area)
    if (seen and seen != targets) or len(areas) > 1:
        raise ValueError
    return {"area": areas.pop()} if areas else None


def _prefix_list_readback(access, key):
    lists = _routing_dict(_routing_json(access, f"show ip prefix-list {key} | json")["ipPrefixLists"])
    if not lists:
        return None
    if set(lists) != {key}:
        raise ValueError
    value = lists[key]
    entries = value["ipPrefixEntries"]
    if not isinstance(entries, list) or not entries or value["ipRemarkEntries"] != []:
        raise ValueError
    rules = []
    for entry in entries:
        if type(entry["seqno"]) is not int or entry["ge"] != 0 or entry["le"] != 0:
            raise ValueError
        rules.append(f"{entry['seqno']} {entry['filterType']} {entry['prefix']}")
    return {"rules": eos_routing.rule_text(eos_routing.parse_rules(", ".join(rules)))}


def _route_map_readback(access, key):
    name, seq = key.rsplit(":", 1)
    maps = _routing_dict(_routing_json(access, f"show route-map {name} | json")["routeMaps"])
    if not maps:
        return None
    if set(maps) != {name}:
        raise ValueError
    entries = _routing_dict(maps[name]["entries"])
    if not entries:
        raise ValueError
    if seq not in entries:
        return None
    entry = entries[seq]
    rules = _routing_dict(entry["matchRules"])
    if (set(rules) - {"prefixList"} or entry["setRules"] != {} or entry["description"] != []
            or entry["subRouteMap"] != {"name": "", "invert": False} or entry["filterType"] not in ("permit", "deny")):
        raise ValueError
    result = {"action": entry["filterType"]}
    if "prefixList" in rules:
        if not isinstance(rules["prefixList"], str) or not re.fullmatch(eos_routing.NAME, rules["prefixList"]):
            raise ValueError
        result["prefix-list"] = rules["prefixList"]
    return result


def _observe_routing(access, plan):
    table, key = plan["table"], plan["key"]
    try:
        if table == eos_routing.PREFIX_LIST:
            return _prefix_list_readback(access, key)
        if table == eos_routing.ROUTE_MAP:
            return _route_map_readback(access, key)
        return _ospf_readback(access, plan)
    except (KeyError, ValueError, TypeError, AttributeError):
        raise _routing_unreadable() from None


def _dhcp_check_query(access, command):
    from netops_admin.access import AccessError

    try:
        text = access.check_query(command)
        if re.search(r"(?im)^% (?:Invalid input|Unrecognized command)", text):
            status, write_answer = access.query_status(command)
            if status and re.search(r"(?im)^% (?:Invalid input|Unrecognized command)", write_answer):
                raise eos_dhcp.refuse("the device does not provide this EOS DHCP capability",
                                      "eos_dhcp_unsupported")
        return text
    except (AccessError, TimeoutError) as exc:
        if isinstance(exc, TimeoutError) or re.search(r"timed out|timeout", str(exc), re.I):
            raise eos_dhcp.refuse("EOS DHCP read timed out", "eos_dhcp_read_timeout") from None
        raise eos_dhcp.refuse("EOS DHCP operational read failed") from None


def _observe_dhcp(access, plan):
    if plan["table"] == eos_dhcp.POOL:
        return eos_dhcp.operational_pool(_dhcp_check_query(access, eos_dhcp.SERVER_SHOW), plan["key"])
    return eos_dhcp.operational_relay(_dhcp_check_query(access, eos_dhcp.RELAY_SHOW), plan["key"])


def _dhcp_plan_prechecks(access, device, plan, snapshot_text):
    snapshot = eos.load(snapshot_text, plan["firmware"])
    if plan["table"] == eos_dhcp.POOL:
        interface, _ = eos_dhcp.pool_interface(snapshot, plan["key"])
    else:
        interface, _ = eos_dhcp.relay_key(plan["key"])
    management_vlans = {str(value) for value in (device.audit_policy or {}).get("management_vlans", ())}
    if interface[4:] in management_vlans:
        raise eos_dhcp.refuse("the DHCP SVI is a management VLAN", "port_management_vlan")
    try:
        management = _acl_management_interfaces(access, device, snapshot)
    except Rejected as exc:
        if "eos_acl_read_timeout" in exc.reason_codes:
            raise eos_dhcp.refuse("reading the EOS SSH management path timed out",
                                  "eos_dhcp_read_timeout") from None
        raise eos_dhcp.refuse("the EOS SSH management path cannot be verified") from None
    if interface in management:
        raise eos_dhcp.refuse("the DHCP SVI carries SSH management", "port_management_interface")
    return []


# ---- 1.0.12 eos targeted clear: targeted clear of counters, MAC, ARP/ND entries and BGP refresh (eos_clear) ----

def clear_device_prechecks(access, device, snapshot_text) -> str:
    """What a clear needs from the switch: the write account logs in with privilege 15 (the clear runs in exec mode)
    and the running version (for firmware_support, never a block). The safeguard preconditions of a configuration
    change (unsaved configuration, open sessions, commit timer) do not apply: a clear writes no configuration and has
    no timed return."""
    from netops_admin.access import AccessError

    try:
        level = eos.privilege(access.query(QUERY_PRIVILEGE))
        version = eos.image_version(access.query(QUERY_VERSION))
    except AccessError:
        raise Rejected(["the EOS privilege level or version could not be read before the clear"],
                       reason_codes=["clear_readback_unreadable"]) from None
    if level != 15:
        raise Rejected(["the write account logs in with privilege %d; Admin needs privilege 15 at login" % level],
                       reason_codes=["write_account_privilege"])
    return version


def observe_clear(access, table, target):
    from netops_admin.access import AccessError

    try:
        rc, text = access.check_query_status(target.read)
    except AccessError:
        raise Rejected(["the check account could not read the EOS clear target"],
                       reason_codes=["clear_readback_unreadable"]) from None
    if rc and table == eos_clear.BGP and "BGP inactive" in text:
        raise Rejected(["BGP is not running on the switch"], reason_codes=["clear_no_entry"])
    if rc and re.search(r"% Invalid input|does not exist", text):
        raise Rejected(["the EOS clear target does not exist (the interface or the VRF is unknown)"],
                       reason_codes=["clear_invalid_target"])
    if rc:
        raise eos_clear.unreadable()
    return eos_clear.observation(table, target, text)


def _refuse_clear(why):
    raise Rejected(["the selected clear scope includes a protected object: " + why],
                   reason_codes=["clear_protected_target"])


PROTECTION_CODES = frozenset({"port_uplink", "port_routed", "port_management_vlan", "port_protected",
                              "port_lldp_neighbor", "port_learned_mac", "port_lag_active"})
UNREADABLE_CODES = frozenset({"eos_l2_readback_unreadable", "eos_l2_read_timeout", "port_usage_unreadable"})


def _clear_guard(call, *args):
    """The protections of the port path judge the clear scope; their refusals become clear_protected_target and an
    unreadable or timed-out read becomes clear_readback_unreadable (nothing was sent)."""
    from netops_admin.access import AccessError

    try:
        return call(*args)
    except Rejected as exc:
        if PROTECTION_CODES.intersection(exc.reason_codes):
            _refuse_clear("; ".join(exc.reasons))
        if UNREADABLE_CODES.intersection(exc.reason_codes):
            raise Rejected(["a read before the EOS clear failed, timed out or was not recognised"],
                           reason_codes=["clear_readback_unreadable"]) from None
        raise
    except AccessError:
        raise Rejected(["a read before the EOS clear failed or timed out"],
                       reason_codes=["clear_readback_unreadable"]) from None


def clear_prechecks(access, device, table, target, before, snapshot_text="") -> list:
    return _clear_prechecks(access, device, table, target, before, snapshot_text)


def _clear_port(access, device, snapshot, guarded, port, neighbors):
    """A port that carries no management path, no uplink and no managed device: a protected interface, a port that is
    not a physical Ethernet port (port-channel, peer-link, overlay), an LLDP neighbor, a routed or trunk port, the
    port of a management or protected VLAN and a port-channel member all refuse."""
    if port.casefold() in guarded:
        _refuse_clear("interface %s is protected" % port)
    if not eos_clear.ethernet(port):
        _refuse_clear("%s is not a physical Ethernet port (port-channel, peer-link or overlay)" % port)
    if port in neighbors:
        _refuse_clear("port %s has an LLDP neighbor (uplink or managed device)" % port)
    shown = _clear_guard(_l2_switchport, access, port)
    _clear_guard(_l2_mgmt_vlan, access, device, snapshot, shown["access-vlan"])
    if _clear_guard(_l2_channel_member, access, port):
        _refuse_clear("port %s is a port-channel member" % port)


def _clear_prechecks(access, device, table, target, before, snapshot_text="") -> list:
    """The protections of the port path apply to the clear scope and to every learned entry it removes: protected
    interfaces and VLANs, the management interface and VRF, uplinks (LLDP neighbors, trunk, routed and port-channel
    ports), the VLAN of an SVI that carries the Admin SSH session. An unreadable answer refuses the clear."""
    protected = device.protected or {}
    guarded = eos_l2.protected_interfaces(protected)
    if target.key.casefold() in {str(name).casefold() for name in protected.get(table, ())}:
        _refuse_clear("%s is protected" % target.key)
    if target.vrf is not None and target.vrf.casefold() == "management":
        _refuse_clear("VRF management carries the management interface")
    snapshot = eos.load(snapshot_text, None)
    if table == eos_clear.BGP:
        try:
            connected = eos_bgp.connected_interface(snapshot, ipaddress.ip_address(target.value))
        except Rejected:
            connected = None
        if connected is not None:
            _clear_guard(eos_routing.protect_interfaces, {connected}, protected)
        return ["BGP neighbor %s is not protected and its connected interface is not protected" % target.value]
    neighbors = _clear_guard(_l2_lldp_ports, access)
    vlans = {str(number) for number in protected.get("vlan", ())}
    ports, svis = set(), set()
    if table == eos_clear.COUNTERS:
        ports.add(target.value)
    for entry in (item for item in before.get("entries", ()) if item["dynamic"]):
        if table == eos_clear.MAC:
            svis.add(entry["vlan"])
            ports.add(entry["port"])
            continue
        match = eos_clear.SVI.fullmatch(entry["interface"])
        if match is None:
            _refuse_clear("a learned entry is on %s, not on a VLAN interface" % entry["interface"])
        if entry["interface"].casefold() in guarded or match.group(1) in vlans:
            _refuse_clear("a learned entry is on the protected interface %s" % entry["interface"])
        svis.add(match.group(1))
        if entry["port"] is not None:
            ports.add(entry["port"])
    for vlan in sorted(svis):
        if vlan in vlans or "vlan" + vlan in guarded:
            _refuse_clear("a learned entry is in the protected VLAN %s" % vlan)
        _clear_guard(_l2_mgmt_vlan, access, device, snapshot, vlan)
    for port in sorted(ports):
        _clear_port(access, device, snapshot, guarded, port, neighbors)
    return ["scope: %s; no protected object, no uplink or management path"
            % (", ".join(sorted(ports) + ["Vlan" + vlan for vlan in sorted(svis)]) or target.key)]
