from __future__ import annotations

import datetime
import ipaddress
import re

from netops_admin import exos, exos_acl, exos_g44, exos_g46, exos_services, membership
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin.exec_fortios import PromptSpec

TIMER_TOLERANCE_SECONDS = 10
UNSAVED_MARKER = b"*"


def prompt_spec(hostname: str, others=()) -> PromptSpec:
    return PromptSpec(anchor=("%s." % hostname).encode("ascii"), ends=(b"# ", b"> "), continuation=None,
                      error=exos.cli_error, anchors=tuple((name + ".").encode("ascii") for name in others))


def plan_hostnames(plan, hostname):
    if plan["table"] != exos_services.NAME:
        return ()
    return tuple(sorted({side["sysname"] for side in plan["predicted"].values()} - {hostname}))


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


def prechecks(access, device, snapshot_text, spec, *, allow_unsaved=False) -> list:
    reasons = []
    running = exos.switch_field(exos.IMAGE_VERSION, access.query(exos.QUERY_VERSION), "software version")
    if running != device.firmware:
        reasons.append("the switch runs %s, not the configured %s; update firmware in the Admin configuration"
                       % (running, device.firmware))
    if not allow_unsaved and UNSAVED_MARKER in access.login_prefix(spec):
        reasons.append("the switch has unsaved configuration changes of someone else")
    return reasons


def plan_prechecks(access, device, plan, snapshot_text="", *, undo=False) -> list:
    if plan["table"] == exos_acl.BINDING:
        from netops_admin.exec_exos_acl import binding_prechecks
        binding_prechecks(access, device, plan, snapshot_text)
        return []
    before, after = plan["predicted"]["before"] or {}, plan["predicted"]["after"] or {}
    if plan["table"] in exos.DHCP_TABLES:
        _dhcp_prechecks(access, device, plan, snapshot_text, undo=undo)
    if plan["table"] in exos_g44.TABLES:
        _link_prechecks(access, device, plan, snapshot_text, undo=undo)
    if plan["table"] in exos_g46.TABLES:
        _routing_prechecks(access, device, plan, snapshot_text)
    if plan["table"] in ("ports", exos.BOUNCE_TABLE) and before.get("admin-state") != after.get("admin-state"):
        _port_prechecks(access, device, plan, snapshot_text)
    elif plan["table"] == "inline-power":
        _poe_prechecks(access, device, plan, snapshot_text)
    elif plan["table"] == "vlan" and exos.plan_kind(before or None, after or None) == "ports":
        _vlan_port_prechecks(plan, before, after)
    if exos.plan_kind(before or None, after or None) != "rename" and exos.l3_changed(
            plan["table"], plan["predicted"]["before"], plan["predicted"]["after"]):
        _l3_prechecks(access, device, plan, snapshot_text)
    return []


def observe_clear(access, table, target):
    try:
        text = access.check_query(target.read)
    except AccessError:
        raise Rejected(["the check account could not read the ExtremeXOS clear target"],
                       reason_codes=["clear_readback_unreadable"]) from None
    return exos.clear_observation(table, target, text)


# Review finding 1: counters that were 0 or small before the clear may count control traffic (ND, LLDP, ...) sent
# between the clear and the readback; a counter passes when it fell or stays within this tolerance.
CLEAR_COUNTER_TOLERANCE_PACKETS = 64
CLEAR_COUNTER_TOLERANCE_BYTES = CLEAR_COUNTER_TOLERANCE_PACKETS * 1522


def _refuse_clear(why):
    raise Rejected(["the selected clear scope includes a protected object: " + why],
                   reason_codes=["clear_protected_target"])


def _entry_ports(row) -> set:
    return {port.strip() for port in row["port"].split(",") if port.strip()}


def clear_prechecks(access, device, table, target, before, snapshot_text="") -> list:
    """the protections of the admin-state path apply to the clear scope and to every learned entry it
    removes: protected and policy ports, ports carrying a management VLAN (running configuration or the port_vlans
    allowlist of the audit policy), ports with an LLDP neighbor (uplinks), management and protected VLANs, the
    built-in Mgmt VLAN and the system VRs (VR-Mgmt, VR-Control). An unreadable answer refuses the clear."""
    policy = device.audit_policy or {}
    management = ({name.casefold() for name in policy.get("management_vlans", ())}
                  | {exos.MANAGEMENT_VLAN.casefold()})
    vlans = management | {name.casefold() for name in device.protected.get("vlan", ())}
    ports = set(device.protected.get("ports", ())) | set(policy.get("protected_ports", ()))
    for port, modes in (policy.get("port_vlans") or {}).items():
        if {name.casefold() for names in modes.values() for name in names} & management:
            ports.add(port)
    if target.key.casefold() in {value.casefold() for value in device.protected.get(table, ())}:
        _refuse_clear("%s is protected" % target.key)
    if target.vr is not None and target.vr.casefold() in {vr.casefold() for vr in exos.SYSTEM_VRS}:
        _refuse_clear("%s is a system VR" % target.vr)
    if target.scope == "vlan" and target.value.casefold() in vlans:
        _refuse_clear("VLAN %s is a management or protected VLAN" % target.value)
    learned = [row for row in before.get("entries", ()) if row["dynamic"]]
    for row in learned:
        if row["vlan"].casefold() in vlans:
            _refuse_clear("a learned entry is in the management or protected VLAN %s" % row["vlan"])
    touched = ({target.value} if target.scope == "port" else set()).union(*map(_entry_ports, learned))
    if not touched:
        return []
    named = sorted(touched & ports, key=exos.port_order)
    if named:
        _refuse_clear("port %s is protected or carries a management VLAN of the audit policy" % ",".join(named))
    snapshot = exos.Snapshot(snapshot_text, device.firmware)
    if not exos.vlan_module_closed(snapshot):
        raise Rejected(["the configuration ends inside its vlan module; VLAN membership of the cleared ports cannot"
                        " be read completely"], reason_codes=["port_usage_unreadable"])
    snapshot.inventory = frozenset(exos.switch_ports(access.query(exos.QUERY_PORTS)))
    members = sorted((port for port in touched if exos.management_vlan_member(snapshot, port, management)),
                     key=exos.port_order)
    if members:
        _refuse_clear("port %s is a member of a management VLAN" % ",".join(members))
    uplinks = sorted(touched & exos.lldp_ports(access.query(exos.QUERY_LLDP)), key=exos.port_order)
    if uplinks:
        _refuse_clear("port %s has an LLDP neighbor (uplink or managed device)" % ",".join(uplinks))
    return ["port %s: not protected, no management VLAN, no LLDP neighbor"
            % ",".join(sorted(touched, key=exos.port_order))]


def _counter_cleared(name, before, after) -> bool:
    limit = CLEAR_COUNTER_TOLERANCE_BYTES if name.endswith("bytes") else CLEAR_COUNTER_TOLERANCE_PACKETS
    return after < before or after <= limit


def _static_entry(entry) -> bool:
    return not entry["dynamic"] and bool(re.fullmatch(exos.CLEAR_MAC, entry["mac"]))


def _entry_order(entry):
    return tuple(sorted(entry.items()))


def clear_readback(plan, observed):
    """Review finding 1: verify what the clear guarantees, not an idle table. The selected learned entries are gone
    or learned again by live traffic (marked `relearned`), every static entry stays, and the readback stays in the
    scope of the target. Counters fall or stay within a small tolerance for control traffic.
    Returns (matches, readback)."""
    before = plan["predicted"]["before"]
    if plan["table"] == "port-counters":
        return (observed["port"] == before["port"] and observed["link"] == before["link"] and
                all(_counter_cleared(name, value, observed["counters"][name])
                    for name, value in before["counters"].items())), observed
    scope = all(observed[name] == before[name] for name in ("scope", "target", "vr"))
    kept = sorted(filter(_static_entry, before["entries"]), key=_entry_order)
    seen = sorted(filter(_static_entry, observed["entries"]), key=_entry_order)
    entries = []
    for entry in observed["entries"]:
        if entry["dynamic"]:
            entry = dict(entry, relearned=True)
        elif not _static_entry(entry):
            entry = dict(entry, relearned=False, status="incomplete")
        entries.append(entry)
    return scope and seen == kept, dict(observed, entries=entries)


def _l3_prechecks(access, device, plan, snapshot_text) -> None:
    """1.0.12 switch ip routing: a static route or a VLAN subnet never carries or takes the path of a session client. The VR of a
    session comes from the route tables of the check account (every origin, dynamic routes included; review finding
    2), read only when the plan holds a client address."""
    snapshot = exos.Snapshot(snapshot_text, device.firmware)
    try:
        clients = exos.session_addresses(access.query(exos.QUERY_SESSIONS))
    except (AccessError, Rejected) as exc:
        raise Rejected(["the session list cannot be read, so the session clients are unknown: %s" % exc],
                       reason_codes=["port_management_interface"]) from None
    tables = {}

    def route_rows(vr, version):
        if (vr, version) not in tables:
            try:
                text = access.check_query("show iproute%s vr %s" % (" ipv6" if version == 6 else "", vr))
                tables[vr, version] = exos.route_rows(text, version)
            except (AccessError, Rejected) as exc:
                raise Rejected(["the route table of %s cannot be read, so the VR of the session is unknown: %s"
                                % (vr, exc)], reason_codes=["port_management_interface"]) from None
        return tables[vr, version]

    reasons = exos.management_refusals(snapshot, plan["table"], plan["key"], plan["predicted"]["before"],
                                       plan["predicted"]["after"], clients, route_rows)
    if reasons:
        raise Rejected(reasons, reason_codes=["port_management_interface"])
    plan["prechecks"].append("%s does not carry or take the path of the session clients (%s)"
                             % (plan["key"], ", ".join(sorted({str(client) for client in clients}))))


def _vlan_port_prechecks(plan, before, after) -> None:
    """1.0.12 switch rest: every port named by a VLAN port plan is reported by the switch."""
    named = set()
    for state in (before, after):
        for attribute in exos.PORT_ATTRIBUTES:
            named.update((state.get(attribute) or "").split())
    missing = sorted(named.difference(plan["ports"]), key=exos.port_order)
    if missing:
        raise Rejected(["port %s is not reported by the switch" % ",".join(missing)])
    plan["prechecks"].append("ports %s are reported by the switch" % ",".join(sorted(named, key=exos.port_order)))


def _sides(plan) -> set:
    return set(plan["predicted"]["before"] or {}) | set(plan["predicted"]["after"] or {})


def _management_path(access, snapshot, scope, vlan_names, *, whole_vlan=False, routing_origins=()) -> None:
    """Find each SSH client's return path before allowing a potentially disruptive port change."""
    route_tables = {}
    known_vlans = {vlan.casefold() for vlan in snapshot.vlans} | {"default", exos.MANAGEMENT_VLAN.casefold()}
    try:
        clients = exos.session_addresses(access.query(exos.QUERY_SESSIONS))
        for client in clients:
            reachable = False
            family = " ipv6" if client.version == 6 else ""
            for vr in exos.routing_vrs(snapshot):
                if not exos.VR_NAME.fullmatch(vr):
                    raise ValueError("unrecognised virtual router name")
                table = (vr, client.version)
                if table not in route_tables:
                    route_tables[table] = exos.route_rows(access.check_query(f"show iproute{family} vr {vr}"),
                                                         client.version)
                matches = [row for row in route_tables[table] if row.active_unicast and client in row.network]
                if not matches:
                    continue
                reachable = True
                length = max(row.network.prefixlen for row in matches)
                for row in matches:
                    if row.network.prefixlen != length:
                        continue
                    if row.origin in routing_origins:
                        raise ValueError("the SSH return path is learned by the affected protocol")
                    vlan = row.vlan.casefold()
                    if vlan not in known_vlans:
                        raise ValueError("unknown egress VLAN")
                    if vlan not in vlan_names:
                        continue
                    if whole_vlan:
                        raise ValueError("the affected VLAN carries the SSH return path")
                    gateway = client if row.origin == "d" else ipaddress.ip_address(row.gateway.split("%")[0])
                    table_name = "iparp" if client.version == 4 else "neighbor-discovery"
                    target = exos.clear_target(table_name, str(gateway), {"vr": vr})
                    entries = exos.clear_observation(table_name, target, access.check_query(target.read))["entries"]
                    ports = {entry["port"] for entry in entries if entry["vlan"].casefold() == row.vlan.casefold()
                             and re.fullmatch(exos.CLEAR_MAC, entry["mac"])}
                    if (not ports or not all(membership.PORT_NUMBER.fullmatch(port) for port in ports)
                            or scope.intersection(ports)):
                        raise ValueError("management next hop uses an affected port or is unresolved")
            if not reachable:
                raise ValueError("no active route to an SSH client")
    except (AccessError, TimeoutError, Rejected, ValueError) as exc:
        if routing_origins and isinstance(exc, (AccessError, TimeoutError)):
            _routing_read_failure(exc)
        raise Rejected(["the SSH management path may use an affected port or could not be determined"],
                       reason_codes=["port_management_interface"]) from None


def _port_membership(device, plan, snapshot_text):
    key = plan["key"]
    snapshot = exos.Snapshot(snapshot_text, device.firmware)
    if not exos.vlan_module_closed(snapshot):
        raise Rejected(["the configuration ends inside its vlan module; VLAN membership of port %s cannot be read "
                        "completely" % key], reason_codes=["port_usage_unreadable"])
    if "ports" in plan:
        snapshot.inventory = frozenset(plan["ports"])
    policy = device.audit_policy or {}
    vlans = {name.casefold() for name in policy.get("management_vlans", ())} | {exos.MANAGEMENT_VLAN.casefold()}
    lag = next((group for group in membership.lag_groups(snapshot) if key in group), set())
    scope = lag or {key}
    if lag and (lag.intersection(device.protected.get("ports", ())) or lag.intersection(policy.get("protected_ports", ()))):
        raise Rejected(["a port in the affected link aggregation is protected"], reason_codes=["port_protected"])
    _vlans, members, _descriptions = membership.model(snapshot)
    names = {name.casefold() for port in scope for names in members.get(port, {}).values() for name in names}
    for port in scope:
        modes = policy.get("port_vlans", {}).get(port, {})
        names.update(name.casefold() for allowed in modes.values() for name in allowed)
    if names & vlans:
        raise Rejected(["port %s is a member of a management VLAN of the audit policy" % key],
                       reason_codes=["port_management_vlan"])
    return snapshot, lag, members, names


def _port_prechecks(access, device, plan, snapshot_text) -> None:
    key = plan["key"]
    impact = plan.get("endpoint_impact") == key
    try:
        shown = exos.port_configuration(access.query("show ports %s configuration no-refresh" % key), key)
    except AccessError:
        raise Rejected(["the port configuration could not be read"], reason_codes=["port_usage_unreadable"]) from None
    if shown is None or shown["link_state"] not in exos.LINK_STATES.values():
        raise Rejected(["the affected port and link state could not be read"], reason_codes=["port_usage_unreadable"])
    plan["prechecks"].append("port %s now: port state %s, link state %s"
                             % (key, shown["port_state"], shown["link_state"]))
    # Data port admin state changes check membership in either direction.
    snapshot, lag, members, names = _port_membership(device, plan, snapshot_text)
    scope = lag or {key}
    try:
        lldp = exos.lldp_ports(access.query(exos.QUERY_LLDP))
        if key in lldp and not impact:
            raise Rejected(["port %s has an LLDP neighbor (uplink or managed device); changing its admin state is refused" % key],
                           reason_codes=["port_lldp_neighbor"])
        fdb = exos.fdb_ports(access.query(exos.QUERY_FDB))
    except AccessError:
        raise Rejected(["LLDP neighbors or the forwarding database could not be read"],
                       reason_codes=["port_usage_unreadable"]) from None
    if impact:
        _management_path(access, snapshot, scope, names)
        plan["port_impact"] = {
            "tagged_vlans": ", ".join(sorted({name for port in scope for name in members.get(port, {}).get("tagged", ())})),
            "lag_ports": ", ".join(sorted(lag, key=exos.port_order)),
            "link": shown["link_state"],
            "lldp": ", ".join(sorted(lldp & scope, key=exos.port_order)),
            "learned_macs": ", ".join(sorted(fdb & scope, key=exos.port_order)),
        }
    elif key in fdb:
        raise Rejected(["port %s has learned MAC addresses; changing the admin state of a port in use is refused" % key],
                       reason_codes=["port_learned_mac"])
    elif shown["link_state"] in ("active", "loopback"):
        raise Rejected(["port %s has an active link; preview its impact before changing its admin state" % key],
                       reason_codes=["port_uplink"])
    else:
        plan["prechecks"].append("port %s has no LLDP neighbor and no learned MAC address" % key)


def poe_state(access, key: str, check=False) -> dict:
    """Configured admin state and inline power state of a port, read by the check account or the write account."""
    query = access.check_query if check else access.query
    return exos.poe_detail(query("show inline-power info detail ports %s" % key), key)


def data_admin_state(access, key: str) -> str:
    shown = exos.shown_port(access.check_query("show ports %s information detail" % key), key, admin_state=True)
    if shown is None:
        raise Rejected(["the check account did not find the selected port"], reason_codes=["port_usage_unreadable"])
    return shown.get("admin-state", "enabled")


def _poe_prechecks(access, device, plan, snapshot_text) -> None:
    key = plan["key"]
    command = "show inline-power info ports %s" % key
    try:
        rc, text = access.query_status(command)
    except AccessError:
        raise Rejected(["the inline-power port state could not be read"],
                       reason_codes=["poe_state_unreadable"]) from None
    if exos.poe_not_capable_answer(rc, text, key):
        raise exos.NotInlinePower(["port %s is not inline-power capable" % key], reason_codes=["poe_not_capable"])
    if rc != 0:
        raise AccessError("query ended with exit status %s" % rc)
    row = exos.poe_info(text, key)
    if row["state"] == "disabled" and not (plan["predicted"]["before"] or {}).get("admin-state"):
        raise Rejected(["inline power of port %s is disabled (not delivering and not searching); a cycle is refused"
                        % key], reason_codes=["poe_disabled"])
    if (plan["predicted"]["after"] or {}).get("admin-state") == "disabled":
        snapshot, lag, _members, names = _port_membership(device, plan, snapshot_text)
        if lag:
            raise Rejected(["port %s belongs to a link aggregation; interrupting inline power is refused" % key],
                           reason_codes=["port_lag_member"])
        _management_path(access, snapshot, {key}, names)
    plan["prechecks"].append("port %s inline power before the cycle: %s, class %s, %s W, fault %s"
                             % (key, row["state"], row["class"], row["power_watts"], row["fault"]))


def ports(access, table: str, changes=None):
    grouped = table == "vlan" and changes is not None and exos.names_vlan_ports(changes)
    if not grouped and table not in (*exos.PORT_TABLES, *exos_g44.TABLES, *exos.DHCP_TABLES, exos_acl.BINDING, "vlan-membership"):
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
    if plan["table"] == exos_acl.BINDING:
        from netops_admin.exec_exos_acl import observe_binding
        return observe_binding(access, plan)
    if plan["table"] in exos.DHCP_TABLES:
        _dhcp_vlan(access, plan["key"])
        return _read_exos_dhcp(access, plan["table"], plan["key"])
    if plan["table"] in exos_services.TABLES:
        return exos_services.observe(access, plan["table"], plan["key"])
    if plan["table"] in exos_g46.TABLES:
        return _observe_routing(access, plan)
    if plan["table"] in exos_g44.TABLES:
        return _observe_link(access, plan)
    if plan["table"] == "vlan-membership":
        text = access.check_query("show ports %s vlan" % plan["key"])
        alias = None
        if membership.label(text) is not None:
            port = exos.shown_port(access.check_query("show ports %s information detail" % plan["key"]), plan["key"])
            alias = (port or {}).get("display-string")
        return membership.shown(text, plan["key"], alias)
    if plan["table"] == exos.BOUNCE_TABLE:
        return {"admin-state": "disabled"} if data_admin_state(access, plan["key"]) == "disabled" else {}
    if plan["table"] == "ports":
        return exos.shown_port(access.check_query("show ports %s information detail" % plan["key"]), plan["key"],
                               admin_state="admin-state" in _sides(plan),
                               description="description-string" in _sides(plan))
    if plan["table"] == "inline-power":
        state = poe_state(access, plan["key"], check=True)
        return {"admin-state": "disabled"} if state["configured"] == "disabled" else {}
    if plan["table"] == exos.ROUTE_TABLE:
        # 1.0.12 switch ip routing: the routes of the VR of the key (the list must be complete)
        vr, network = exos.route_key(plan["key"])
        text = access.check_query("show iproute%s vr %s" % (" ipv6" if network.version == 6 else "", vr))
        return exos.shown_route(text, plan["key"])
    if plan["table"] == exos.VRRP_TABLE:
        vlan, _vrid = exos.vrrp_key(plan["key"])
        state = exos.shown_vrrp(access.check_query("show vrrp vlan %s" % vlan), plan["key"])
        if state is None and not exos.vrrp_absent_from_list(access.check_query("show vrrp"), plan["key"]):
            raise Rejected(["the check account cannot establish the VRRP state"])
        return state
    predicted = plan.get("predicted") or {}
    kind = exos.plan_kind(predicted.get("before"), predicted.get("after"))
    if kind == "rename":
        # 1.0.12 switch rest: exactly one of the two names exists, before and after the rename
        names = (plan["predicted"]["before"][exos.RENAME], plan["predicted"]["after"][exos.RENAME])
        found = {name: state for name in names for state in [_shown_vlan(access, name, include_l3=False)]
                 if state is not None}
        if len(found) != 1:
            raise Rejected(["the check account sees %s of the VLAN names %s" % ("both" if found else "neither",
                                                                                 " and ".join(names))])
        name, state = found.popitem()
        state[exos.RENAME] = name
        return state
    # Review finding 5: a plan with IP attributes reads the forwarding rows strictly
    strict = exos.touches_l3("vlan", predicted.get("before"), predicted.get("after"))
    return _shown_vlan(access, plan["key"], ports=kind == "ports", strict_l3=strict,
                       include_l3=strict or plan.get("op") != "update")


def _shown_vlan(access, key, ports=False, strict_l3=False, include_l3=True):
    text = access.check_query("show vlan %s" % key)
    try:
        state = exos.shown_vlan(text, key, strict_l3=strict_l3, include_l3=include_l3)
    except Rejected:
        if "A number within the range of 1-4094 is expected." not in text:
            raise
        if exos.vlan_absent_from_list(access.check_query("show vlan"), key):
            return None
        raise Rejected(["the check account cannot establish the VLAN state"]) from None
    if state is not None and ports:
        state.update(exos.shown_vlan_ports(text))
    return state


def _routing_read_failure(exc):
    if isinstance(exc, TimeoutError) or any(
            phrase in str(exc).lower() for phrase in ("timeout", "timed out", "did not finish within")):
        raise Rejected(["the EXOS routing preflight or readback timed out"],
                       reason_codes=["exos_routing_read_timeout"]) from None
    exos_g46.read_error("the EXOS routing state could not be read")


def _routing_query(access, command, *, absent=None, admin=False, statuses=(0,)):
    try:
        query = access.query_status if admin else access.check_query_status
        rc, text = query(command)
    except (AccessError, TimeoutError) as exc:
        _routing_read_failure(exc)
    if absent is not None and re.fullmatch(absent, text.strip()):
        return None
    if re.search(r"(?im)^(?:%%|Error:).*licen[cs]", text):
        exos_g46.refuse("the switch license does not allow this routing feature")
    if rc not in statuses or not text.strip() or re.search(r"(?im)^(?:%%|Error:)|--More--|Press <SPACE>", text):
        exos_g46.read_error("the requested EXOS routing state could not be read")
    return text


def _routing_prechecks(access, device, plan, snapshot_text):
    table, key = plan["table"], plan["key"]
    snapshot = exos.load(snapshot_text, plan["firmware"])
    protected = dict(device.protected)
    policy = device.audit_policy or {}
    protected["vlan"] = set(protected.get("vlan", ())) | set(policy.get("management_vlans", ()))
    protected["ports"] = set(protected.get("ports", ())) | set(policy.get("protected_ports", ()))
    vlans = exos.routing_scope(snapshot, table, key, protected)
    if vlans:
        origins = ("be", "bg", "bi", "mb", "mbe", "mbi") if table == exos_g46.PEER else (
            "mo", "o", "o1", "o2", "oa", "oe", "oiv", "or")
        _management_path(access, snapshot, set(), {name.casefold() for name in vlans}, whole_vlan=True,
                         routing_origins=origins)
    if table == exos_g46.BGP:
        enabled, _asn = exos_g46.bgp_status(_routing_query(access, "show bgp"))
        if enabled or exos_g46.bgp_peers(_routing_query(access, "show bgp neighbor")):
            exos_g46.refuse("the local AS can only change while BGP is disabled and has no neighbors")
    if table == exos_g46.PEER:
        before = plan["predicted"]["before"] or {}
        after = plan["predicted"]["after"] or {}
        # Check the files used by the forward and inverse commands. A file can exist without any current binding.
        names = {state[attr] for attr in exos_g46.POLICIES if before.get(attr) != after.get(attr)
                 for state in (before, after) if attr in state}
        for name in sorted(names):
            missing = rf"Error:\s+Policy {re.escape(name)} does not exist on file"
            result = _routing_query(access, f"check policy {name}", absent=missing, admin=True)
            if result is None:
                exos_g46.refuse("a BGP route policy file required by the change or undo is missing")
            if not re.search(r"(?m)^Policy file check successful\.\s*$", result):
                exos_g46.read_error("the BGP route policy file could not be validated")


def _observe_routing(access, plan):
    table, key = plan["table"], plan["key"]
    proto = exos_g46.protocol(table, key)
    if table == exos_g46.OSPF:
        return exos_g46.ospf_status(_routing_query(access, f"show {proto}"), proto)
    if table == exos_g46.AREA:
        area = key.split(":", 1)[1]
        command = f"show {proto} area"
        areas = exos_g46.ospf_areas(_routing_query(access, command), proto)
        if area in areas:
            if areas[area] != "NORM":
                exos_g46.refuse("the existing OSPF area is not a normal area")
            return {}
        # EXOS 33.6 returns a CLI parser error when a specific area is absent. The independently parsed
        # inventory must also exclude it before accepting that error as an absence.
        missing = rf"(?:\x07)?%% Unrecognized command:\s+\"{re.escape(command)} {re.escape(area)}\"\s+%% Invalid input detected\."
        if _routing_query(access, f"{command} {area}", absent=missing) is not None:
            exos_g46.read_error("the OSPF area inventory and detailed state differ")
        return None
    if table == exos_g46.INTERFACE:
        vlan = key.split(":", 1)[1]
        # EXOS 33.6 emits status 250 with a complete detail answer for a VLAN with OSPF disabled.
        text = _routing_query(access, f"show {proto} interfaces vlan {vlan}", statuses=(0, 250))
        return exos_g46.ospf_interface(text, proto, vlan)
    if table == exos_g46.BGP:
        _enabled, asn = exos_g46.bgp_status(_routing_query(access, "show bgp"))
        return {"local-as": asn} if asn != "0" else {}
    peers = exos_g46.bgp_peers(_routing_query(access, "show bgp neighbor"))
    if key not in peers:
        return None
    return exos_g46.bgp_peer(_routing_query(access, f"show bgp neighbor {key}"), key, peers[key])


def foreign_sessions(access, device) -> int:
    return exos.foreign_sessions(access.query(exos.QUERY_SESSIONS))


def _link_prechecks(access, device, plan, snapshot_text, *, undo=False):
    table, key = plan["table"], plan["key"]
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    snapshot = exos.load(snapshot_text, plan["firmware"])
    snapshot.inventory = frozenset(plan["ports"])
    policy = device.audit_policy or {}
    if not exos.vlan_module_closed(snapshot):
        exos_g44.read_error("the VLAN module ended before the port scope could be evaluated")
    protected = dict(device.protected)
    protected["ports"] = set(protected.get("ports", ())) | set(policy.get("protected_ports", ()))
    try:
        scope = exos_g44.validate(snapshot, table, key, before, after, protected, exos.Entry)
        _vlans, members, _descriptions = membership.model(snapshot)
        vlan_names = {name.casefold() for port in scope for names in members.get(port, {}).values() for name in names}
        for port in scope:
            allowed = policy.get("port_vlans", {}).get(port, {})
            vlan_names.update(name.casefold() for names in allowed.values() for name in names)
        if table == exos_g44.STPD:
            vlan_names = exos_g44.stpd_scope_vlans(snapshot, key, vlan_names)
        if vlan_names.intersection(name.casefold() for name in policy.get("management_vlans", ())):
            exos_g44.refuse("an affected port is a member of a management VLAN in the audit policy", "port_management_vlan")
        if table == exos_g44.STPD:
            reported = exos_g44.stpd_ports(access.check_query(f"show stpd {key}"), key, snapshot)
            if not reported <= scope:
                exos_g44.read_error("the operational STP domain includes ports absent from the configured scope")
        else:
            _link_mlag_prechecks(access, snapshot, table, key, scope, vlan_names, undo and after is None)
        if table == exos_g44.ELRP:
            state = re.findall(r"^ELRP Standalone Client:[ \t]+(Enabled|Disabled)[ \t]*$",
                               access.check_query("show elrp"), re.M)
            if len(state) != 1:
                exos_g44.read_error("the standalone ELRP client state is incomplete")
            if state[0] == "Disabled":
                exos_g44.refuse("the standalone ELRP client must already be enabled")
        if scope or vlan_names:
            _management_path(access, snapshot, scope, vlan_names, whole_vlan=table == exos_g44.STPD)
        if scope and table not in (exos_g44.PEER, exos_g44.STPD):
            lldp = exos.lldp_ports(access.query(exos.QUERY_LLDP))
            fdb = exos.fdb_ports(access.query(exos.QUERY_FDB))
            if scope & lldp:
                exos_g44.refuse("an affected port has an LLDP neighbor", "port_lldp_neighbor")
            if scope & fdb:
                exos_g44.refuse("an affected port has learned MAC addresses", "port_learned_mac")
            for port in sorted(scope, key=exos.port_order):
                text = access.check_query(f"show ports {port} information detail")
                identity = exos.PORT_HEADER.search(text)
                link = re.findall(r"^[ \t]*Link State:[ \t]+([^\n]+)", text, re.M)
                if (identity is None or identity.group(1) != port or len(link) != 1
                        or not exos.PORT_DETAIL_END.search(text)):
                    exos_g44.read_error("an affected port's link state cannot be established")
                if link[0].strip().casefold() != "ready":
                    exos_g44.refuse("an affected port is active or unavailable", "port_uplink")
        plan["prechecks"].append("affected ports and management path checked against the live switch")
    except AccessError:
        exos_g44.read_error("the EXOS link scope could not be read")


def _link_mlag_prechecks(access, snapshot, table, key, scope, vlan_names, deleting_created_peer):
    peers = exos_g44.peers_readback(access.check_query("show mlag peer"))
    bindings = exos_g44.bindings_readback(access.check_query("show mlag ports"))
    if set(peers) != set(snapshot.entries(exos_g44.PEER)) or set(bindings) != set(snapshot.entries(exos_g44.BINDING)):
        exos_g44.read_error("the operational MLAG inventory differs from the configuration")
    if (scope if table != exos_g44.BINDING else scope - {key}).intersection(bindings):
        exos_g44.refuse("the change overlaps an operational MLAG binding")
    if table == exos_g44.PEER and key in peers:
        _, status, _, count = peers[key]
        if count or any(binding["peer"].casefold() == key.casefold() for binding in bindings.values()):
            exos_g44.refuse("the existing MLAG peer has operational port bindings")
        if status.casefold() == "up" and not deleting_created_peer:
            exos_g44.refuse("the existing MLAG peer checkpoint is active")
    isc_vlans = set().union(*(peer[2] for name, peer in peers.items() if table != exos_g44.PEER or name != key))
    if vlan_names & isc_vlans:
        exos_g44.refuse("the change overlaps an operational MLAG ISC or alternate path")


def _configured_link(access, plan):
    table, key = plan["table"], plan["key"]
    module = exos_g44.MODULE[table]
    command = "show configuration " + ("mlag" if module == "vsm" else module)
    # The independent account cannot read configuration. This targeted read
    # distinguishes command defaults from explicit values with the same effect.
    text = access.query(command)
    if module != "vlan":
        text = "# Module vlan configuration.\n" + text
    snapshot = exos.load(text, plan["firmware"])
    snapshot.inventory = frozenset(plan["ports"])
    entry = snapshot.entries(table).get(key)
    if entry is not None and entry.unsupported:
        exos_g44.read_error("the configured link state contains settings outside the profile")
    return None if entry is None else entry.attributes


def _observe_link(access, plan):
    table, key = plan["table"], plan["key"]
    try:
        if table == exos_g44.LINK:
            return exos_g44.link_readback(access.check_query(f"show ports {key} configuration no-refresh"),
                                         access.check_query(f"show ports {key} information detail"), key)
        if table == exos_g44.JUMBO:
            return _configured_link(access, plan) or {}
        if table == exos_g44.ELRP:
            return exos_g44.elrp_readback(access.check_query("show elrp"), key, frozenset(plan["ports"]))
        if table == exos_g44.LAG:
            return exos_g44.sharing_readback(access.check_query("show sharing"), key, _configured_link(access, plan))
        if table == exos_g44.STPD:
            return exos_g44.stpd_readback(access.check_query(f"show stpd {key}"), key)
        if table == exos_g44.STP_PORT:
            domain, port = key.split(":", 1)
            command = f"show stpd {domain} ports {port}"
            return exos_g44.stp_port_readback(access.check_query(command), access.check_query(command + " detail"),
                                             key, _configured_link(access, plan) or {})
        if table == exos_g44.BINDING:
            return exos_g44.bindings_readback(access.check_query("show mlag ports")).get(key)
        peers = exos_g44.peers_readback(access.check_query("show mlag peer"))
        return peers[key][0] if key in peers else None
    except AccessError:
        exos_g44.read_error("the EXOS link state could not be read")


_DHCP_UNREADABLE = "exos_dhcp_readback_unreadable"


def _dhcp_query(access, command, *, vlan_status=False):
    try:
        rc, text = access.check_query_status(command)
    except AccessError as exc:
        code = "exos_dhcp_read_timeout" if re.search(r"timed out|timeout", str(exc), re.I) else _DHCP_UNREADABLE
        raise exos.dhcp_refusal("the check account could not read EXOS DHCP state", code) from None
    # Both lab families can return 250 for a complete show vlan response. Only
    # this query accepts it, and its VLAN identity and complete ports block are parsed below.
    if (rc and not (vlan_status and rc == 250)) or re.search(
            r"(?im)^\s*(?:%%|Error:|Permission denied|Access denied|Ambiguous command)", text):
        if re.search(r"(?im)^(?:%% (?:Invalid input|Unrecognized command)|Error:.*(?:not supported|license))", text):
            raise exos.dhcp_refusal("the switch did not accept the DHCP operational command",
                                    "exos_dhcp_unsupported")
        raise exos.dhcp_refusal("the check account could not read EXOS DHCP state", _DHCP_UNREADABLE)
    return text.strip()


def _dhcp_fields(lines):
    fields = {}
    for line in lines:
        label, separator, value = line.partition(":")
        label = label.strip()
        if not separator or not label or label in fields:
            raise exos.dhcp_refusal("the DHCP operational answer is incomplete or ambiguous", _DHCP_UNREADABLE)
        fields[label] = value.strip()
    return fields


def _dhcp_ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        raise exos.dhcp_refusal("the DHCP operational answer has an invalid IPv4 address", _DHCP_UNREADABLE) from None


def _relay_readback(text, vlan):
    lines = [line for line in text.splitlines() if line.strip()]
    header = re.fullmatch(r'DHCPv4 BOOTP Relay\s*:\s*(Enabled|Disabled) on virtual router "VR-Default"'
                          r'(, but enabled on some VLANs)?', lines[0]) if lines else None
    if header is None:
        raise exos.dhcp_refusal("the IPv4 relay VR header is missing or outside the profile", _DHCP_UNREADABLE)
    if header[1] == "Enabled":
        raise exos.dhcp_refusal("VR-wide IPv4 relay is outside the VLAN profile", "exos_dhcp_conflict")
    if len(lines) == 1 and not header[2]:
        return {}
    identity = f'VLAN "{vlan}":'
    if lines.count(identity) != 1:
        raise exos.dhcp_refusal("the IPv4 relay answer does not identify the selected VLAN", _DHCP_UNREADABLE)
    index = lines.index(identity)
    vr = _dhcp_fields(lines[1:index - 2])
    if (index < 4 or not re.fullmatch(r"VLAN\s+DHCPv4 BOOTP Relay", lines[index - 2])
            or not re.fullmatch(r"-+\s+-+", lines[index - 1])
            or "BOOTP Relay Servers" not in vr):
        raise exos.dhcp_refusal("the IPv4 relay answer lacks its complete VLAN section", _DHCP_UNREADABLE)
    fields = _dhcp_fields(lines[index + 1:])
    if fields == {"BOOTP Relay": "Disabled"}:
        return {}
    if vr["BOOTP Relay Servers"]:
        raise exos.dhcp_refusal("the VLAN could inherit VR-wide IPv4 relay targets", "exos_dhcp_conflict")
    if (fields.get("BOOTP Relay") != "Enabled"
            or not {"BOOTP Relay Servers", "DHCP Relay Agent Information Option", "DHCP Relay Agent Information Check",
                    "DHCP Relay Agent Information Policy"} <= fields.keys()):
        raise exos.dhcp_refusal("the IPv4 relay state or target is incomplete", _DHCP_UNREADABLE)
    return {"server-ip": _dhcp_ipv4(fields["BOOTP Relay Servers"])}


def _pool_readback(text):
    fields = _dhcp_fields(text.splitlines())
    first, sep, last = fields.pop("DHCP Address Range", "").partition("->")
    lease = fields.pop("DHCP Lease Timer", "")
    netlogin = fields.pop("Netlogin Lease Timer", "")
    ports = fields.pop("Ports DHCP Enabled", "")
    if not sep or not netlogin or not ports:
        raise exos.dhcp_refusal("the DHCP pool answer is incomplete", _DHCP_UNREADABLE)
    state = {"range-start": _dhcp_ipv4(first), "range-end": _dhcp_ipv4(last)}
    if lease != "Not configured (Default = 7200 seconds)":
        explicit = re.fullmatch(r"([0-9]+) seconds", lease)
        if explicit is None:
            raise exos.dhcp_refusal("the DHCP lease answer is incomplete", _DHCP_UNREADABLE)
        state["lease-seconds"] = explicit[1]
    if ports != "No ports enabled":
        try:
            found = membership.ports(re.sub(r"\s*,\s*|\s+", ",", ports))
        except ValueError:
            raise exos.dhcp_refusal("the DHCP port list is incomplete", _DHCP_UNREADABLE) from None
        if not found:
            raise exos.dhcp_refusal("the DHCP port list is empty", _DHCP_UNREADABLE)
        state["ports"] = " ".join(sorted(found))
    for label, attribute in (("Default Gateway", "default-gateway"), ("Primary DNS Server", "primary-dns"),
                             ("Secondary DNS Server", "secondary-dns")):
        if label in fields:
            state[attribute] = _dhcp_ipv4(fields.pop(label))
    if fields:
        raise exos.dhcp_refusal("the DHCP pool answer contains options outside the profile", _DHCP_UNREADABLE)
    return state


def _read_exos_dhcp(access, table, vlan):
    if table == exos.DHCP_RELAY:
        return _relay_readback(_dhcp_query(access, f"show bootprelay configuration ipv4 vlan {vlan}"), vlan)
    config = _dhcp_query(access, f"show vlan {vlan} dhcp-config")
    if config:
        return _pool_readback(config)
    if _dhcp_query(access, f"show dhcp-server vlan {vlan}"):
        raise exos.dhcp_refusal("the two DHCP server reads disagree", _DHCP_UNREADABLE)
    return {}


def _dhcp_vlan(access, vlan):
    text = _dhcp_query(access, f"show vlan {vlan}", vlan_status=True)
    if not re.search(r"(?m)^\s*Virtual router:\s+VR-Default\s*$", text):
        raise exos.dhcp_refusal("the VLAN's virtual router cannot be established or is outside VR-Default")
    try:
        attributes = exos.shown_vlan(text, vlan, include_l3=False)
        ports = exos.shown_vlan_ports(text)
    except Rejected:
        raise exos.dhcp_refusal("the VLAN identity or membership answer is incomplete", _DHCP_UNREADABLE) from None
    active = re.search(r"(?m)^\s*Ports:\s+(\d+)\.\s*\(Number of active ports=(\d+)\)", text)
    if attributes is None or active is None or int(active[2]) > int(active[1]):
        raise exos.dhcp_refusal("the VLAN's active port count is incomplete", _DHCP_UNREADABLE)
    return set(" ".join(ports.values()).split()), int(active[2])


def _dhcp_prechecks(access, device, plan, snapshot_text, *, undo):
    vlan, table = plan["key"], plan["table"]
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    snapshot = exos.load(snapshot_text, device.firmware)
    snapshot.inventory = frozenset(plan["ports"])
    observed_ports, active_ports = _dhcp_vlan(access, vlan)
    if observed_ports != exos.dhcp_vlan_ports(snapshot, vlan):
        raise exos.dhcp_refusal("configured and operational VLAN membership disagree", _DHCP_UNREADABLE)
    policy = device.audit_policy or {}
    if observed_ports.intersection(policy.get("protected_ports", ())):
        raise exos.dhcp_refusal("the VLAN contains a port protected by the audit policy", "port_protected")
    management = {name.casefold() for name in policy.get("management_vlans", ())}
    impact = plan.get("endpoint_impact") == vlan
    if vlan.casefold() in management and not (impact or undo):
        raise exos.dhcp_refusal("endpoint_impact must name the management VLAN", "endpoint_impact_required")
    if _read_exos_dhcp(access, table, vlan) != before:
        raise exos.dhcp_refusal("configured and operational DHCP state disagree", _DHCP_UNREADABLE)
    peer = exos.DHCP_SERVER if table == exos.DHCP_RELAY else exos.DHCP_RELAY
    if _read_exos_dhcp(access, peer, vlan):
        raise exos.dhcp_refusal("the VLAN already has a conflicting DHCP server or relay", "exos_dhcp_conflict")
    new_ports = set(after.get("ports", "").split()) - set(before.get("ports", "").split())
    if table == exos.DHCP_SERVER and active_ports and (new_ports or (not before and after)):
        raise exos.dhcp_refusal("new DHCP service requires an inactive VLAN to exclude another DHCP server",
                                "exos_dhcp_conflict")
    if active_ports and not (impact or undo):
        try:
            _management_path(access, snapshot, set(), {vlan.casefold()}, whole_vlan=True)
        except Rejected:
            raise exos.dhcp_refusal("endpoint_impact must name the VLAN if it may carry an SSH management path",
                                    "endpoint_impact_required") from None
    plan["prechecks"].append("VLAN membership and DHCP state checked by the read-only account")
