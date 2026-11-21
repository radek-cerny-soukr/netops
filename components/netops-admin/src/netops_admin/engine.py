from __future__ import annotations

import hashlib
import json
import re

from netops_admin import (
    __version__, eos, eos_save, exos, exos_acl, exos_g44, exos_save, exos_services, fortiadc, fortiadc_plan, fortios,
    ios, ios_save, junos, junos_clear, junos_g140, membership, nxos, ruckus,
)
from netops_admin import eos_clear, fortios_lease, nxos_clear
from netops_admin.errors import SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected, SnapshotRejected
from netops_admin.profiles import LIST_TYPES, find_profile, firmware_support
from netops_core import tested
from netops_admin.request import BATCH, FORTIOS_POLICY_LIST_FIELDS, MAX_BATCH_STEPS, ProfileBatch, canonical_value, list_items

PLAN_FORMAT = "netops-admin-plan/1"
ADAPTERS = {"fortios": fortios, "exos": exos, "eos": eos, "ios": ios, "iosxe": ios, "fortiadc": fortiadc_plan, "nxos": nxos,
            "junos": junos, "ruckus": ruckus}
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
PORT_TABLES = exos.PORT_TABLES
# platforms whose port changes accept endpoint_impact (1.0.12 G60/G78 IOS and IOS XE, G122 EOS)
IMPACT_PLATFORMS = ios.PLATFORMS + ("eos", "junos", "nxos")
# 1.0.12 G138: the Junos tables that accept endpoint_impact (a port in use: bounce, PoE, speed and MTU)
JUNOS_IMPACT_TABLES = ("interface", junos.POE_TABLE, junos.POE_CYCLE_TABLE, junos.BOUNCE_TABLE, *junos_g140.TABLES, *junos.routing.BGP_TABLES,
                       *junos.fltr.TABLES, *junos.srx.TABLES, *junos.dhcp.TABLES)
REFERENCE_TEXT_ATTRIBUTES = {"vlan-membership": ("untagged",), "firewall policy": ("schedule",),
                             fortios.ADDRESS_TABLE: ("interface",)}


def adapter_for(platform: str):
    adapter = ADAPTERS.get(platform)
    if adapter is None:
        raise Rejected(["unknown platform %r" % platform])
    return adapter


def decode_snapshot(raw: bytes) -> str:
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise SnapshotRejected(["snapshot is larger than %d bytes" % MAX_SNAPSHOT_BYTES], SNAPSHOT_UNREADABLE)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise SnapshotRejected(["snapshot is not UTF-8"], SNAPSHOT_UNREADABLE) from None


def _preserve_configured_default(profile, name):
    return profile.platform == "junos" and profile.table == "vlan-membership" and name == "access-vlan"


def normalize(profile, attributes: dict):
    state, unsupported = {}, []
    for name, value in attributes.items():
        if name in profile.volatile:
            continue
        if name in profile.fixed:
            if value != profile.fixed[name]:
                unsupported.append("%s %s" % (name, value))
            continue
        attribute = profile.attributes.get(name)
        if attribute is None:
            if ((profile.platform == "junos" and profile.table == "vlan" and name == "l3-interface")
                    or (profile.platform == "ruckus" and name in ruckus.SECURITY_FIELDS)):
                # Read-only state is compared without making it a writable profile attribute.
                state[name] = value
            else:
                unsupported.append(name)
            continue
        if attribute.default is not None and value == attribute.default and not _preserve_configured_default(profile, name):
            continue
        quoted_fortios_list = profile.platform == "fortios" and (
            (profile.table == fortios.GROUP_TABLE and name == "member") or
            (profile.table == fortios.POLICY_TABLE and name in FORTIOS_POLICY_LIST_FIELDS)
            or (profile.table == fortios.SWITCH_PORT and name in fortios.FORTIOS_PORT_VLAN_LISTS)
        )
        if attribute.type == "name-list" and not quoted_fortios_list:
            value = " ".join(sorted(value.split()))
        if attribute.type in ("mac-address", "mac-address-list"):
            value = value.lower()
        state[name] = value
    return state, unsupported


def full_state(profile, attributes: dict, *, opaque=False) -> dict:
    """The whole existing state of an object of an isolated update: profile attributes normalized, a fixed attribute
    with its fixed value dropped, any other value (outside the profile, or a fixed attribute with another value such
    as role lan of a VLAN) kept as it is, so the readback compares it unchanged."""
    state = {}
    for name, value in attributes.items():
        if name in profile.volatile:
            continue
        if name in profile.fixed and value != profile.fixed[name]:
            state[name] = _digest(value) if opaque else value
        elif name in profile.attributes or name in profile.fixed:
            known, _unknown = normalize(profile, {name: value})
            state.update(known)
        else:
            state[name] = _digest(value) if opaque else value
    return state


def is_isolated_plan(profile, plan) -> bool:
    if not profile.isolated_update or plan["op"] != "update":
        return False
    before = plan["predicted"]["before"] or {}
    return any(name not in profile.attributes and name not in profile.volatile
               and (name not in profile.fixed or before[name] != profile.fixed[name])
               for name in before)


def check_view(plan, state):
    """The part of an object state that the check account can read; the comparison of the check account takes it from
    both the observed and the predicted state (G122 r2: EOS hides a phone VLAN outside trunk phone mode and 802.1X that
    is not enforced; every other platform reads the whole state)."""
    from netops_admin import schema_runtime
    if state is None or schema_runtime.is_plan(plan):
        return state
    if plan.get("platform") == "eos":
        return eos.check_view(plan["table"], state)
    if plan.get("platform") == "junos":
        return junos.check_view(plan["table"], state)
    if plan.get("platform") == "nxos" and plan["table"] in nxos.LINK_TABLES:
        return nxos.link_check_view(plan["table"], state)
    if plan.get("platform") == "fortios" and (plan["table"] == fortios.SWITCH_BOUNCE or (
            plan["table"] == fortios.SWITCH_PORT and "state_schema" not in plan)):
        return {name: value for name, value in state.items() if name in fortios.SWITCH_BASE_FIELDS}
    if (plan.get("platform"), plan["table"]) == ("fortios", fortios.SWITCH_POE_CYCLE):
        return {name: value for name, value in state.items() if name in fortios.SWITCH_CYCLE_FIELDS}
    if (plan.get("platform"), plan["table"]) == ("exos", exos_g44.ELRP):
        return {"action": "L", **state}
    if plan.get("platform") in ios.PLATFORMS and plan["table"] in ios.POE_TABLES:
        # 1.0.12 G61: show power inline of the check account names the admin mode; the maximum it prints is the default
        # of the hardware unless it is set, so the maximum is verified in the running configuration only
        return {name: value for name, value in state.items() if name != "max-milliwatts"}
    return state


def observed_state(plan, attributes):
    from netops_admin import schema_runtime
    if schema_runtime.is_plan(plan):
        return attributes
    if attributes is None:
        return None
    if (plan["platform"], plan["table"]) == ("exos", exos_g44.ELRP):
        return attributes  # The independent parser supplies the port list, interval and action.
    attributes = check_view(plan, attributes)
    profile = find_profile(plan["platform"], plan["table"], plan["firmware"])
    if "policy_move_sha256" in plan:
        return normalize(profile, {name: value for name, value in attributes.items() if name in profile.attributes})[0]
    if is_isolated_plan(profile, plan):
        return full_state(profile, attributes, opaque="policy_order" in plan)
    state, unknown = normalize(profile, attributes)
    if tracks_policy_uuid(plan):
        value = attributes.get("uuid")
        if fortios.valid_policy_uuid(value):
            state["uuid"] = value.lower()
    if unknown:
        raise Rejected(["the check account sees configuration outside the profile: %s" % ", ".join(sorted(unknown))])
    return state


def tracks_policy_uuid(plan):
    return "policy_order" in plan and (
        "policy_uuid_generated" in plan or any("uuid" in (state or {}) for state in plan["predicted"].values()))


def observed_side(plan, snapshot_raw: bytes):
    """The side of the plan ("after" or "before") the snapshot matches exactly, or None.

    1.0.12 G07: a block after an unknown result is lifted over MCP only when the device was read on one side; the
    side is reported, it never confirms or reverts the operation."""
    for side in ("after", "before"):
        if verify(plan, snapshot_raw, expect=side)["result"] == "match":
            return side
    return None


def _find_entry(entries: dict, key: str):
    if key in entries:
        return entries[key]
    if any(name.casefold() == key.casefold() for name in entries):
        raise Rejected(["key %r differs only in letter case from an existing object" % key])
    return None


def _entry_state(snapshot, profile, entry):
    lists = [name for name, attribute in profile.attributes.items() if attribute.type in LIST_TYPES]
    attributes, unsupported = snapshot.entry_state(entry, lists)
    if profile.platform == "fortios" and profile.table in (fortios.SWITCH_BOUNCE, fortios.SWITCH_POE_CYCLE):
        attributes = {name: value for name, value in attributes.items() if name in profile.attributes}
    state, unknown = normalize(profile, attributes)
    return state, unsupported + unknown


def canonical_changes(profile, changes):
    canonical, reasons = {}, []
    for name, value in sorted(changes.items()):
        attribute = profile.attributes.get(name)
        if attribute is None:
            reasons.append("attribute %s is not in the profile" % name)
            continue
        if value is None:
            if not attribute.unset:
                reasons.append("attribute %s cannot be removed" % name)
            else:
                canonical[name] = None
            continue
        if (profile.platform, profile.table, name) == ("exos", exos_acl.POLICY, exos_acl.CONTENT):
            canonical[name] = exos_acl.content(value)
            continue
        try:
            canonical[name] = canonical_value(attribute, value, profile.platform)
        except Rejected as exc:
            reasons.extend(exc.reasons)
            continue
        if canonical[name] in profile.reserved_values.get(name, ()):
            reasons.append("attribute %s: value %s is reserved on this platform" % (name, canonical[name]))
    if reasons:
        raise Rejected(reasons)
    return canonical


def _check_value_requirements(profile, changes):
    for name, values in sorted((profile.value_requires or {}).items()):
        needed = values.get(changes.get(name)) if isinstance(changes.get(name), str) else None
        if needed and any(other not in changes for other in needed):
            raise Rejected(["%s %s needs %s in the same request" % (name, changes[name], ", ".join(needed))])


def _check_create_values(profile, changes):
    missing = [name for name, attribute in sorted(profile.attributes.items())
               if attribute.required_on_create and changes.get(name) is None]
    if missing:
        raise Rejected(["create needs %s" % ", ".join(missing)])
    wrong = sorted(name for name, wanted in (profile.create_values or {}).items() if changes.get(name) != wanted)
    if wrong:
        raise Rejected(["create needs %s" % ", ".join("%s %s" % (name, profile.create_values[name]) for name in wrong)])


def _without_defaults(profile, values: dict) -> dict:
    return {
        name: value for name, value in values.items()
        if value is not None and value != profile.attributes[name].default
    }


def _referenced(profile, state) -> set:
    names = set()
    for name, value in (state or {}).items():
        attribute = profile.attributes.get(name)
        if attribute is not None and (attribute.type == "name-list"
                                      or name in REFERENCE_TEXT_ATTRIBUTES.get(profile.table, ())):
            if (profile.platform, profile.table, name) == ("fortios", fortios.POLICY_TABLE, "schedule"):
                names.add(str(value))
            else:
                names.update(list_items(attribute, str(value), profile.platform))
    return names


def _linked(snapshot, profile, key, before, after, guarded) -> set:
    if profile.platform == "fortios" and profile.table == "firewall addrgrp":
        return fortios.containing_groups(snapshot.entries("firewall addrgrp"), key)
    if profile.platform == "junos" and profile.table == "vlan" and before and after and before["name"] != after["name"]:
        return snapshot.rename_ports(before["name"], guarded)
    if profile.platform != "exos" or profile.table not in ("ports", "vlan", "vrrp"):
        return set()
    _vlans, members, _descriptions = membership.model(snapshot)
    if profile.table == "ports":
        modes = members.get(key, {})
        return set(modes.get("tagged", ())) | set(modes.get("untagged", ()))
    # 1.0.12 G45 r2 (479-rv finding 3): a VRRP instance changes its VLAN, so the member ports of the VLAN are its links
    folded = (key.split(":", 1)[0] if profile.table == "vrrp" else key).casefold()
    return {port for port, modes in members.items()
            if any(name.casefold() == folded for names in modes.values() for name in names)}


def _protected_references(snapshot, profile, protected, key, before, after) -> list:
    guarded = {name.casefold() for names in (protected or {}).values() for name in names}
    if not guarded and (profile.platform, profile.table) != ("junos", "vlan"):
        return []
    try:
        names = _referenced(profile, before) | _referenced(profile, after) | _linked(
            snapshot, profile, key, before, after, guarded)
        if profile.platform == "fortios" and profile.table in ("firewall addrgrp", "firewall policy"):
            names |= fortios.member_closure(snapshot.entries("firewall addrgrp"), names)
    except Rejected as exc:
        raise Rejected(["the references of the object to protected names cannot be evaluated: %s"
                        % "; ".join(exc.reasons)]) from None
    return sorted(name for name in names if name.casefold() in guarded)


def _digest(value) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("ascii")).hexdigest()


# 1.0.10 B4c: plan_sha256 binds the plan to its target - the configured device alias, the platform and the
# firmware - besides the commands, the inverse and the predicted states, so an identical change previewed for
# another device or another firmware has another plan_sha256. FortiOS and EOS read the firmware from the fresh
# snapshot; ExtremeXOS, IOS and IOS XE have no full version in their snapshot and use the configured version, which
# the prechecks verify against the live `show version` before any write.
PLAN_DIGEST_SINCE = (1, 0, 10)


# 1.0.12 G00-1: a firmware outside the tested versions of the profile is not refused; the plan carries
# firmware_support and the digest binds its status, so approving the plan_sha256 approves the warning too
# (decision Q1 a). A tested plan has no such key in its digest: its plan_sha256 is the one of 1.0.10 and 1.0.11.
def plan_digest(plan) -> str:
    if "batch_steps" in plan:
        return _digest({
            "device": plan["device"], "platform": plan["platform"], "firmware": plan["firmware"],
            "request": plan["request_sha256"],
            **({"snapshots": plan["batch_snapshots"]} if "batch_snapshots" in plan else {}),
            "steps": [(step["table"], step["op"], step["key"], step["plan_sha256"], step["rest_sha256"])
                      for step in plan["batch_steps"]],
        })
    bound = {"device": plan["device"], "platform": plan["platform"], "firmware": plan["firmware"],
             "commands": plan["commands"], "inverse": plan["inverse"],
             "before": plan["predicted"]["before"], "after": plan["predicted"]["after"]}
    if plan["platform"] == "junos" and plan["table"] in junos_g140.TABLES:
        bound.update(table=plan["table"], key=plan["key"], rest_sha256=plan["rest_sha256"])
        for metadata in ("junos_lag_capacity", "junos_rstp_root"):
            if metadata in plan:
                bound[metadata] = plan[metadata]
    if "member_digests" in plan:
        bound["member_digests"] = plan["member_digests"]
        bound["member_rest_before"] = plan["rest_sha256"]
    if plan.get("state_schema") == fortios.SWITCH_PORT_STATE_SCHEMA:
        bound["state_schema"] = plan["state_schema"]
    if "batch_volatile" in plan:
        bound["batch_volatile"] = plan["batch_volatile"]
    if plan.get("ios_batch_step"):
        bound.update(table=plan["table"], key=plan["key"], ios_batch_step=True, rest_sha256=plan["rest_sha256"])
    if ((plan["platform"] in ios.PLATFORMS and plan["table"] in ios.ios_services.TABLES)
            or (plan["platform"] == "iosxe" and plan["table"] in ios.ios_acl.TABLES)
            or (plan["platform"] == "exos" and plan["table"] in (
                *exos_g44.TABLES, *exos.DHCP_TABLES, *exos_services.TABLES, *exos.exos_g46.TABLES, *exos_acl.TABLES))
            or (plan["platform"] == "nxos" and plan["table"] in (*nxos.LINK_TABLES, *nxos.ACL_TABLES,
                                                               *nxos.SERVICE_TABLES))
            or (plan["platform"] == "fortios" and plan["table"] in fortios.SWITCH_PORT_TABLES)
            or (plan["platform"] == "eos" and plan["table"] in eos.eos_l2.TABLES | eos.eos_services.TABLES
                | {eos.eos_bgp.TABLE})
            or (plan["platform"] == "fortios" and plan["table"] == fortios.PHASE2_TABLE)):
        bound.update(table=plan["table"], key=plan["key"], rest_sha256=plan["rest_sha256"])
    if plan["op"] in ("clear", "save"):
        bound.update(table=plan["table"], op=plan["op"], snapshot_sha256=plan["snapshot_sha256"])
        if plan["table"] == "port-counters" and plan["platform"] != "junos":
            # Active counters can advance between preview and apply. The target, link state and configuration bind.
            volatile = ("counters", "last_clearing") if plan["platform"] in ios.PLATFORMS else ("counters",)
            bound["before"] = {key: value for key, value in bound["before"].items() if key not in volatile}
        elif plan["op"] == "clear" and plan["platform"] in ios.PLATFORMS:
            # Bind the selected identities. Use a fresh view of unrelated rows for the after-write comparison.
            for side in ("before", "after"):
                bound[side] = {"entries": [ios.clear_entry_identity(row) for row in bound[side].get("entries", ())]}
        if plan["op"] == "clear" and plan["platform"] in ("nxos", "eos"):
            stabilize = nxos_clear.stable if plan["platform"] == "nxos" else eos_clear.stable
            bound["before"], bound["after"] = stabilize(bound["before"]), stabilize(bound["after"])
        elif plan["platform"] == "junos":
            # 1.0.12 G146: counters, time stamps, TTE and message counters change by themselves; the object binds
            bound["before"] = junos_clear.stable(plan["table"], bound["before"])
            bound["after"] = junos_clear.stable(plan["table"], bound["after"])
        elif plan["op"] == "clear" and plan["platform"] == "fortios":
            bound.update(key=plan["key"], request_sha256=plan["request_sha256"])
    if plan["op"] == "save":
        bound["request_sha256"] = plan["request_sha256"]
        if plan["platform"] == "exos":
            bound.update(key=plan["key"], rest_sha256=plan["rest_sha256"])
    if "cycle_state" in plan:
        bound["cycle_state"] = plan["cycle_state"]
    if "acl_attachment_links" in plan:
        bound["acl_attachment_links"] = plan["acl_attachment_links"]
    if "exos_acl_file_sha256" in plan:
        bound["exos_acl_file_sha256"] = plan["exos_acl_file_sha256"]
    if "fortiadc_ha_role" in plan:
        bound["fortiadc_ha_role"] = plan["fortiadc_ha_role"]
    if "link_before" in plan:
        bound["link_before"] = plan["link_before"]
    if "state_schema" in plan:
        bound["state_schema"] = plan["state_schema"]
    if "endpoint_impact" in plan:
        bound["endpoint_impact"] = plan["endpoint_impact"]
    if "policy_order" in plan:
        bound.update(table=plan["table"], key=plan["key"], op=plan["op"],
                     policy_order=plan["policy_order"], rest_sha256=plan["rest_sha256"],
                     inverse_identity_changes=plan["inverse_identity_changes"])
        if "policy_move_sha256" in plan:
            bound["policy_move_sha256"] = plan["policy_move_sha256"]
        if "policy_uuid_generated" in plan:
            bound["policy_uuid_generated"] = plan["policy_uuid_generated"]
    if "port_impact" in plan:
        bound["port_impact"] = plan["port_impact"]
    if "cycle_action" in plan:
        bound["cycle_action"] = plan["cycle_action"]
    status = (plan.get("firmware_support") or {}).get("status", tested.TESTED)
    if status != tested.TESTED:
        bound["firmware_support"] = status
    return _digest(bound)


def firmware_prechecks(profile, support) -> list:
    firmware = support["device_version"]
    if not support["tested_versions"]:
        return [support["message"]]
    if not profile.measured:
        return ["firmware %s is named by this profile, but the profile is NOT MEASURED on a device"
                " (simulation only)" % firmware]
    if tested.is_tested(support):
        return ["firmware %s is measured for this profile" % firmware]
    return ["firmware %s is not among the tested versions of this profile (tested: %s); the change runs with the"
            " same safeguard, postcheck and undo" % (firmware, ", ".join(support["tested_versions"]))]


def _legacy_plan_digest(plan) -> str | None:
    # Journal records written by Admin 1.0.x before 1.0.10 carry the content-only digest; they stay readable for
    # verify, recovery and undo. A preview hash of such a version never matches a fresh plan of this one.
    # A plan stamped with the running version always needs the bound digest.
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:[^0-9].*)?", plan["admin_version"])
    if (plan["admin_version"] == __version__ or "policy_order" in plan or match is None
            or tuple(int(part) for part in match.groups()[:2]) != (1, 0)
            or tuple(int(part) for part in match.groups()) >= PLAN_DIGEST_SINCE):
        return None
    return _digest({"commands": plan["commands"], "inverse": plan["inverse"],
                    "before": plan["predicted"]["before"], "after": plan["predicted"]["after"]})


def build_plan(platform: str, snapshot_raw: bytes, request, firmware: str | None = None,
               protected: dict | None = None, enrollment_probe=False, ports=None, undo=False,
               device: str | None = None, undo_plan=None, batch_step=False, manual_policy_uuid=False,
               batch_volatile=()) -> dict:
    from netops_admin.schema_request import Transaction
    if isinstance(request, Transaction):
        raise Rejected(["schema transaction planning requires schema-plan with a pinned library and calibration"])
    if isinstance(request, ProfileBatch):
        plan, _ = build_batch(platform, snapshot_raw, request, firmware, protected, device=device)
        return plan
    if request.op in ("clear", "save"):
        raise Rejected([f"{request.op} needs a live preview of the operational state"])
    adapter = adapter_for(platform)
    snapshot = adapter.load(decode_snapshot(snapshot_raw), firmware)
    if platform in ios.PLATFORMS:
        snapshot.platform = platform
    if ports is not None:
        if platform != "exos":
            raise Rejected(["a port list applies only to ExtremeXOS"])
        snapshot.inventory = frozenset(ports)
    profile = find_profile(platform, request.table, snapshot.firmware)
    if platform == "fortios":
        refusal = fortios.webhook_refusal(profile, snapshot.firmware)
        if refusal is not None:
            raise Rejected([refusal], reason_codes=[fortios.NO_REST_INVERSE])
    unmeasured_operation = platform == "junos" and (
        (profile.table == "interface" and bool({"speed", "auto-negotiation"} & request.changes.keys()))
        or (profile.table == junos.ROUTE_TABLE and ":" in request.key)
    )
    if platform == "fortios" and profile.table == fortios.SWITCH_PORT:
        unmeasured_operation = bool({"poe-status", "allowed-vlans-all"} & request.changes.keys())
    support = firmware_support(profile, snapshot.firmware, unmeasured_operation=unmeasured_operation)
    key, op = request.key, request.op
    policy = platform == "fortios" and profile.table == fortios.POLICY_TABLE
    if key.casefold().startswith("netops-enroll-") and not enrollment_probe:
        raise Rejected(["the enrollment object namespace is reserved"])
    nxos_state = platform == "nxos" and profile.table in nxos.STATE_TABLES + nxos.L2_STATE_TABLES
    nxos_link = platform == "nxos" and profile.table in nxos.LINK_TABLES
    nxos_service = platform == "nxos" and profile.table in nxos.SERVICE_TABLES
    eos_state = platform == "eos" and profile.table in eos.eos_l3.TABLES
    eos_acl_state = platform == "eos" and profile.table in eos.eos_acl.TABLES
    eos_l2_state = platform == "eos" and profile.table in eos.eos_l2.TABLES
    ios_acl_state = platform in ios.PLATFORMS and profile.table in ios.ios_acl.TABLES
    eos_routing_state = platform == "eos" and profile.table in eos.eos_routing.TABLES
    eos_bgp_state = platform == "eos" and profile.table == eos.eos_bgp.TABLE
    eos_dhcp_state = platform == "eos" and profile.table in eos.eos_dhcp.TABLES
    eos_service_state = platform == "eos" and profile.table in eos.eos_services.TABLES
    ios_service_state = platform in ios.PLATFORMS and profile.table in ios.ios_services.TABLES
    g140 = platform == "junos" and profile.table in junos_g140.TABLES
    exos_routing = platform == "exos" and profile.table in exos.exos_g46.TABLES
    exos_bgp_peer = exos_routing and profile.table == exos.exos_g46.PEER
    exos_acl_binding = platform == "exos" and profile.table == exos_acl.BINDING
    exos_service = platform == "exos" and profile.table in exos_services.TABLES
    scoped_state = (nxos_state or nxos_link or nxos_service
                    or eos_state or eos_acl_state or eos_l2_state or eos_routing_state
                    or eos_bgp_state or eos_dhcp_state or eos_service_state or g140 or exos_service or exos_routing
                    or ios_acl_state or ios_service_state)
    lag_capacity = rstp_root = None
    checks = firmware_prechecks(profile, support)
    if op not in profile.ops and not (undo and op in profile.undo_ops):
        raise Rejected(["operation %s is not enabled in the profile" % op])
    if not profile.key_pattern.fullmatch(key):
        raise Rejected(["key %r does not match %s" % (key, profile.key_pattern.pattern)])
    requested_changes = request.changes
    if platform == "fortios" and profile.table in fortios.NESTED:
        # 1.0.12 G20: "<interface>@<mac>" and "<zone>@<hostname>" name the object the way the operator knows it
        key, requested_changes = fortios.resolve_nested_key(snapshot, profile.table, key, op, request.changes)
    guarded = {name.casefold() for name in profile.protected_keys}
    guarded |= {name.casefold() for name in (protected or {}).get(profile.table, ())}
    if platform == "junos" and profile.table in ("interface", "vlan-membership"):
        protected_interfaces = {name.casefold() for name in (protected or {}).get("interface", ())}
        if {key.casefold(), key.casefold() + ".0"} & protected_interfaces:
            raise Rejected(["interface %r is protected" % key], reason_codes=["port_protected"])
    nxos_target = nxos.interface_target(profile.table, key) if platform == "nxos" else None
    if nxos_target and nxos.interface_protected(protected, nxos_target):
        raise Rejected(["interface %r is protected" % nxos_target], reason_codes=["port_protected"])
    eos_target = eos.interface_target(profile.table, key) if platform == "eos" else None
    if eos_target and eos.interface_protected(protected, eos_target):
        raise Rejected(["interface %r is protected" % eos_target], reason_codes=["port_protected"])
    nxos_physical = nxos_state and profile.table == nxos.L3_TABLE and nxos.ETHERNET.fullmatch(key)
    if nxos_physical or (platform == "nxos" and profile.table in (nxos.MEMBERSHIP_TABLE, nxos.BOUNCE_TABLE)):
        guarded |= {name.casefold() for name in (protected or {}).get("interface", ())}
    if profile.table == "inline-power" or (platform == "exos" and profile.table == exos.BOUNCE_TABLE):
        guarded |= {name.casefold() for name in (protected or {}).get("ports", ())}
    eos_action = ((platform == "eos" and profile.table in (eos.BOUNCE_TABLE, eos.POE_TABLE))
                  or (platform == "junos" and profile.table in (junos.POE_TABLE, *junos.CYCLE_TABLES)))
    if eos_action:
        # 1.0.12 G123/G138: a protected interface is protected for its bounce and PoE cycle (and Junos PoE) too
        guarded |= {name.casefold() for name in (protected or {}).get("interface", ())}
    ios_port_action = platform in ios.PLATFORMS and profile.table in ios.PORT_ACTION_TABLES
    if ios_port_action:
        # 1.0.12 G61: a protected interface is protected for its bounce and its PoE changes too
        guarded |= {name.casefold() for name in (protected or {}).get("interface", ())}
    if key.casefold() in guarded:
        raise Rejected(["object %r is protected" % key],
                       reason_codes=["port_protected"] if
                       (profile.table in PORT_TABLES or nxos_physical or nxos_link or eos_action or eos_l2_state or ios_port_action
                        or (ios_acl_state and profile.table == ios.ios_acl.BINDING))
                       else ["ios_acl_in_use"] if ios_acl_state else None)
    if platform == "exos" and profile.table == "vlan" and op == "create":
        exos.validate_vlan_name(key)
    if exos_routing:
        exos.exos_g46.require_module(snapshot, profile.table, key)
    checks.append("key is valid and not protected")
    entries = snapshot.entries(profile.table)
    if entries is None:
        raise Rejected(["snapshot holds no %s section; it cannot be evaluated" % profile.table])
    entry = _find_entry(entries, key)
    switch_port = platform == "fortios" and profile.table in fortios.SWITCH_PORT_TABLES
    if switch_port and entry is not None:
        fortios.protect_switch_port(key, entry, protected)
    phase2 = platform == "fortios" and profile.table == fortios.PHASE2_TABLE
    if phase2 and "copy-from" in requested_changes:
        if op != "create":
            raise fortios.ipsec_refused("copy-from is available when creating a Phase 2 selector")
        requested_changes = dict(requested_changes)
        source = requested_changes.pop("copy-from")
        requested_changes = fortios.phase2_copy(snapshot, profile, requested_changes, source)
    supplied, position = fortios.policy_position(op, requested_changes) if policy else (requested_changes, None)
    changes = canonical_changes(profile, supplied)
    if (platform, profile.table) == ("fortios", fortios.SWITCH_POE_CYCLE) and changes != {"poe-status": "disable"}:
        raise Rejected(["a FortiSwitch PoE cycle requires update with poe-status=disable"],
                       reason_codes=["action_unsupported"])
    if (platform == "ruckus" and profile.table == ruckus.TABLE and not undo
            and "passphrase-ref" in changes and changes["passphrase-ref"] is None):
        raise Rejected(["passphrase-ref must name a vault entry WLAN_PSK_<NAME>"])
    if platform == "junos" and profile.table in junos.G139_TABLES:
        changes = junos.l3_changes(profile.table, key, changes)
    exos_dhcp = platform == "exos" and profile.table in exos.DHCP_TABLES
    if exos_dhcp and changes.get("ports") == "":
        changes["ports"] = None
    if platform == "eos":
        changes = eos.canonical_changes(profile.table, key, changes)
    if nxos_state and profile.table in nxos.ACL_TABLES:
        changes = nxos.canonical_acl_changes(profile.table, key, changes)
    if platform == "junos" and profile.table in junos.routing.TABLES:
        changes = junos.routing.canonical_changes(profile.table, changes)
    if platform == "junos" and profile.table in junos.fltr.TABLES:
        changes = junos.fltr.canonical_changes(profile.table, key, changes)
    if platform == "junos" and profile.table in junos.srx.TABLES:
        junos.srx.split_key(profile.table, key)
        changes = junos.srx.canonical_changes(profile.table, changes)
    if platform == "junos" and profile.table in junos.dhcp.TABLES:
        changes = junos.dhcp.canonical_changes(profile.table, changes)
    if ios_acl_state:
        changes = ios.ios_acl.canonical_changes(profile.table, key, changes, xe=platform == "iosxe")
    if ios_service_state:
        changes = ios.ios_services.changes(changes)
        if profile.table == ios.ios_services.HOST and request.endpoint_impact is not None:
            raise Rejected(["static host changes do not take endpoint_impact"], reason_codes=["action_unsupported"])
    # 1.0.12 G43: an ExtremeXOS VLAN rename or a VLAN plan with its ports ("rename", "ports" or None)
    g43 = exos.vlan_change(profile, op, changes) if platform == "exos" else None
    reasons = []
    _check_value_requirements(profile, changes)

    if op == "create":
        if entry is not None or (not profile.table_scoped_key and snapshot.in_use(key)):
            raise Rejected(["name %r is already used in the configuration" % key])
        if profile.table_scoped_key:
            checks.append("key is unused in the table of the snapshot")
        else:
            checks.append("name is unused among the object names and references of the snapshot")
        _check_create_values(profile, changes)
        if profile.create_values:
            checks.append("new object is created with %s; change it with a separate update"
                          % ", ".join("%s %s" % item for item in sorted(profile.create_values.items())))
        if profile.create_position:
            checks.append("new object is placed after all existing objects")
        before = None
        after = _without_defaults(profile, changes)
        assign = {name: value for name, value in changes.items() if value is not None}
        if platform == "fortios" and profile.table == fortios.ADDRESS_TABLE and after.get("type") == fortios.INTERFACE_SUBNET:
            fortios.predict_interface_subnet(snapshot, key, after)
        if platform == "ruckus" and profile.table == ruckus.TABLE:
            security = (ruckus.restoration_security(undo_plan["predicted"]["before"])
                        if undo_plan else ruckus.CREATE_SECURITY)
            after.update(security)
            assign.update(security)
        if not scoped_state:
            commands = adapter.render_create(profile, key, assign)
            inverse = adapter.render_delete(profile, key)
    else:
        if entry is None and not profile.implicit_keys:
            raise Rejected(adapter.absent(snapshot, profile.table, key))
        if platform == "ruckus" and op == "delete" and profile.table == ruckus.TABLE:
            ruckus.require_restorable(snapshot, profile, entry)
        isolated = (op == "update" and profile.isolated_update and changes
                    and set(changes) <= set(profile.isolated_update))
        if policy and op == "move":
            attributes = fortios._shown_attributes(entry)
            before, unsupported = normalize(profile, {name: value for name, value in attributes.items()
                                                      if name in profile.attributes})
        elif isolated and entry is not None:
            lists = [name for name, attribute in profile.attributes.items() if attribute.type in LIST_TYPES]
            attributes, unsupported = snapshot.entry_state(entry, lists)
            before = full_state(profile, attributes, opaque=policy)
        else:
            before, unsupported = ({}, []) if entry is None else _entry_state(snapshot, profile, entry)
        if g43 == "rename" or (platform == "exos" and profile.table == "vlan" and op == "update"
                               and not snapshot.owns_vlan_l3(key) and set(exos.L3_ATTRIBUTES).isdisjoint(changes)):
            before, unsupported = exos.without_l3(before, unsupported, entry)
        if g43 == "rename":
            before[exos.RENAME] = entry.name
        elif g43 == "ports":
            before.update(exos.vlan_ports(snapshot, entry.name))
        if unsupported and exos_dhcp:
            raise exos.dhcp_refusal("the VLAN holds DHCP settings that cannot be independently verified",
                                    "exos_dhcp_readback_unreadable")
        if unsupported:
            if nxos_service:
                raise nxos.service_unrestorable()
            raise Rejected(["object %r holds configuration outside the profile: %s"
                            % (key, ", ".join(sorted(unsupported)))])
        checks.append("object exists and holds only profile attributes")
        references = [] if profile.table_scoped_key else snapshot.references(profile.table, key)
        if g43 == "ports":
            references = exos.references_without_members(snapshot, key)
        if op == "update":
            for name in changes:
                attribute = profile.attributes[name]
                if not attribute.update:
                    reasons.append("attribute %s cannot be updated" % name)
                elif references and not attribute.referenced_update:
                    reasons.append("attribute %s cannot change on a referenced object (%d references)"
                                   % (name, len(references)))
            if not changes:
                reasons.append("update names no attribute")
            if reasons:
                raise Rejected(reasons)
            after = dict(before)
            for name, value in changes.items():
                default = value == profile.attributes[name].default and not _preserve_configured_default(profile, name)
                if value is None or default:
                    after.pop(name, None)
                else:
                    after[name] = value
            if platform == "junos" and profile.table == "vlan-membership":
                junos.membership_target(before, after, undo)
            if platform in ios.PLATFORMS and profile.table in ios.POE_TABLES:
                after = ios.poe_after(profile.table, key, before, after, changes)
            # 1.0.12 G112: a passphrase reference is written but never read back, so it is not part of a stored state
            write_only = platform == "ruckus" and any(changes.get(name) is not None for name in ruckus.WRITE_ONLY)
            if platform == "ruckus":
                after = ruckus.settle(after)
            if after == before and not write_only:
                if profile.table == "inline-power" and platform not in ios.PLATFORMS:
                    if before.get("admin-state") == "disabled":
                        raise Rejected(["inline power of port %s is already configured disabled" % key],
                                       reason_codes=["poe_disabled"])
                    raise Rejected(["inline power of port %s is already configured enabled" % key])
                if profile.action == "port-bounce":
                    raise Rejected(["port %s is administratively disabled; a bounce needs it enabled" % key],
                                   reason_codes=["port_disabled"])
                if (platform, profile.action) == ("fortios", "poe-cycle"):
                    raise Rejected(["the FortiSwitch port has PoE disabled"], reason_codes=["poe_disabled"])
                raise Rejected(["update changes nothing"])
            checks.append("references allow the changed attributes")
            if not scoped_state:
                rendered = changes
                if ((platform == "eos" and profile.table == "vlan-membership")
                        or (platform == "exos" and profile.table in PORT_TABLES)):
                    # Skip requested values that already match the effective port state.
                    rendered = {name: value for name, value in changes.items() if before.get(name) != after.get(name)}
                if platform == "fortios" and (profile.table in (*fortios.ADDRESS_TABLES, *fortios.NAT_TABLES) or switch_port):
                    rendered = {name: value for name, value in changes.items() if before.get(name) != after.get(name)}
                if platform == "fortios" and profile.table == fortios.SWITCH_PORT:
                    # firmware status follows only the fields that really change the port (G17/G18)
                    support = firmware_support(profile, snapshot.firmware, unmeasured_operation=bool(
                        {"poe-status", "allowed-vlans-all"} & rendered.keys()))
                    checks[0] = firmware_prechecks(profile, support)[0]
                if policy:
                    required = {
                        dependency for name, value in changes.items() if before.get(name) != after.get(name)
                        for dependency in (profile.value_requires or {}).get(name, {}).get(value, ())
                    }
                    rendered = {name: value for name, value in changes.items()
                                if name in required or before.get(name) != after.get(name)}
                assign = {name: value for name, value in rendered.items() if value is not None}
                remove = sorted(name for name, value in rendered.items() if value is None)
                commands = adapter.render_update(profile, key, assign, remove)
                kept = set(rendered) | (ruckus.inverse_names(before, changes) if platform == "ruckus" else set())
                restore = {name: before[name] for name in kept if name in before}
                clear = set(rendered) - set(before)
                if (platform == "ruckus" and profile.table == ruckus.TABLE
                        and restore.get("authentication") == "open" and after.get("authentication") == "dot1x"):
                    clear.add("passphrase-ref")
                if switch_port:
                    for name in sorted(clear):
                        if profile.attributes[name].undo_to_default:
                            restore[name] = profile.attributes[name].default
                            clear.remove(name)
                inverse = adapter.render_update(profile, key, restore, sorted(clear))
                if (platform, profile.action) == ("fortios", "poe-cycle"):
                    commands = [fortios.switch_poe_reset(key)]
                    after = before
                if platform in ios.PLATFORMS and profile.table in ios.POE_TABLES:
                    # 1.0.12 G61: one "power inline" line replaces the earlier one; the inverse writes the earlier line
                    commands, inverse = ios.render_poe(key, after), ios.render_poe(key, before)
        elif op == "move":
            after = dict(before)
        else:
            if g43 == "ports":
                # a VLAN with ports is deleted only by a request that names exactly its current ports
                if any(changes.get(name, "") != before.get(name, "") for name in exos.PORT_ATTRIBUTES) \
                        or set(changes) - set(exos.PORT_ATTRIBUTES):
                    raise Rejected(["a delete that names ports must name exactly the current ports of the VLAN"])
            elif changes:
                raise Rejected(["delete takes no attribute changes"])
            if references:
                raise Rejected(["object %r is referenced in the configuration" % key])
            missing = [name for name, attribute in sorted(profile.attributes.items())
                       if attribute.required_on_create and not attribute.undo_to_default and name not in before]
            if missing:
                raise Rejected(["object %r cannot be recreated by the inverse: it has no %s"
                                % (key, ", ".join(missing))])
            if platform == "ios" and profile.table == ios.L3_TABLE:
                # Undo sends the saved state as a create request. Validate it before rendering the delete.
                if "create" not in profile.ops and "create" not in profile.undo_ops:
                    raise Rejected(["operation create is not enabled in the profile"])
                restoration = canonical_changes(profile, before)
                _check_value_requirements(profile, restoration)
                _check_create_values(profile, restoration)
                if _without_defaults(profile, restoration) != before:
                    raise Rejected(["object %r cannot be recreated with the same values by the inverse" % key])
            checks.append("object is not referenced and can be recreated")
            after = None
            if not scoped_state and not policy:
                commands = adapter.render_delete(profile, key)
                inverse = adapter.render_create(profile, key, before)

    generated_uuid = None
    if policy:
        if not fortios.valid_policy_id(key):
            raise Rejected(["the policy ID must be in 1..%d" % fortios.POLICYID_MAX])
        order, position = fortios.plan_policy_order(snapshot, key, op, position, undo_plan)
        if op == "delete":
            uuid = fortios.require_policy_uuid(entry.value("uuid"))
            restore = fortios.policy_restore_attributes(profile, before)
            restored = canonical_changes(profile, {
                name: list_items(profile.attributes[name], value, platform)
                if profile.attributes[name].type in LIST_TYPES else value for name, value in restore.items()
            })
            reasons.extend(fortios.policy_prechecks(snapshot, "create", None, restored, protected,
                                                    impact=getattr(request, "endpoint_impact", None)))
            commands = fortios.render_delete(profile, key)
            old_position = None if order["before"][-1] == key else fortios.position_at(order["before"], key)
            inverse = fortios.render_policy_create(profile, key, restored, old_position,
                                                   uuid=uuid if manual_policy_uuid else None)
            before["uuid"] = uuid
            if not manual_policy_uuid:
                generated_uuid = uuid
        elif op == "move":
            commands = fortios.render_move(key, position)
            inverse = fortios.render_move(key, fortios.position_at(order["before"], key))
        elif op == "create":
            uuid = None
            if undo_plan is not None and undo_plan["op"] == "delete":
                original = fortios.require_policy_uuid(undo_plan["predicted"]["before"].get("uuid"))
                if manual_policy_uuid:
                    uuid = after["uuid"] = original
                else:
                    generated_uuid = original
            commands = fortios.render_policy_create(profile, key, assign, position, uuid=uuid)

    if g140:
        junos_g140.prepare(snapshot, profile.table, key, before, after, op, undo,
                          getattr(request, "endpoint_impact", None))
        junos_g140.protect(snapshot, profile.table, key, before, after, protected)
        if profile.table == junos_g140.LAG:
            original_capacity = undo_plan.get("junos_lag_capacity") if undo_plan else None
            lag_capacity = junos_g140.capacity_plan(snapshot, key, after, original_capacity)
            if lag_capacity["before"] != lag_capacity["after"]:
                checks.append("Junos chassis aggregate device-count: %s → %s" %
                              (lag_capacity["before"] or "unset", lag_capacity["after"] or "unset"))
            reverse = {"before": lag_capacity["after"], "after": lag_capacity["before"]}
            commands = junos_g140.render(profile.table, key, before, after, lag_capacity)
            inverse = junos_g140.render(profile.table, key, after, before, reverse)
        else:
            original = undo_plan.get("junos_rstp_root") if undo_plan else None
            rstp_root, other_port_settings = junos_g140.rstp_layout(snapshot, profile.table, key, after, original)
            reverse = {"before": rstp_root["after"], "after": rstp_root["before"]}
            commands = junos_g140.render(profile.table, key, before, after, rstp=rstp_root,
                                         other_port_settings=other_port_settings)
            inverse = junos_g140.render(profile.table, key, after, before, rstp=reverse,
                                        other_port_settings=other_port_settings)
    touched = _protected_references(snapshot, profile, protected, key, before, after) if not g140 else []
    if touched:
        raise Rejected(["the object holds a reference to protected object %s before or after the change"
                        % ", ".join(repr(name) for name in touched)])
    group_impact = False
    if (platform == "fortios" and profile.table == fortios.GROUP_TABLE and op == "update"
            and fortios.group_members(before) != fortios.group_members(after)):
        # 1.0.12 G24 r2 (705-rv finding 1): the members of a group decide which traffic the policies that use it match
        guarded_policies, active_policies = fortios.group_policy_use(snapshot, key, protected)
        if guarded_policies:
            raise Rejected(["address group %r is used by protected firewall policy %s"
                            % (key, ", ".join(repr(name) for name in guarded_policies))])
        if active_policies:
            if getattr(request, "endpoint_impact", None) is None:
                raise Rejected(["address group %r is used by active firewall policy %s: changing its members changes"
                                " the traffic they match; endpoint_impact naming the group is required"
                                % (key, ", ".join(repr(name) for name in active_policies))],
                               reason_codes=["fortios_policy_impact_required"])
            group_impact = True
    if platform == "ruckus" and profile.table == ruckus.RELAY_TABLE and op == "update":
        commands = ruckus.render_relay_state(key, after)
        inverse = ruckus.render_relay_state(key, before)
    if platform == "exos" and profile.table == "vlan-membership":
        if key in (protected or {}).get("ports", []):
            raise Rejected(["the port is protected"])
        commands = membership.render(key, before, after)
        inverse = membership.render(key, after, before)
    if g43 is not None:
        # The stored states omit empty lists. Use the same classification for the digest as verification.
        g43 = exos.plan_kind(before, after)
    if g43 is not None:
        reasons.extend(exos.rename_prechecks(snapshot, profile, key, after[exos.RENAME], protected) if g43 == "rename"
                       else exos.port_prechecks(snapshot, key, before, after, protected))
        if reasons:
            raise Rejected(reasons)
        commands = exos.render_vlan(key, before, after)
        inverse = exos.render_vlan(after[exos.RENAME] if g43 == "rename" else key, after, before)
    if platform == "junos" and profile.table in junos.STATE_TABLES:
        # 1.0.12 G137: a Junos VLAN or port VLAN membership is rendered from its whole state before and after, in
        # the source that configures it (the port, an interface-range or a group); a rename moves the references
        restore = (undo_plan["inverse"]
                   if undo_plan and profile.table in (junos.srx.POLICY, *junos.srx.NAT) else None)
        commands = junos.render_state(snapshot, profile.table, key, before, after, restore,
                                      incremental_members=batch_step)
        inverse = junos.render_inverse(snapshot, profile.table, key, before, after, incremental_members=batch_step)
        checks.extend(junos.notes(snapshot, profile.table, op, key, before, after))
    if ios_service_state:
        services = ios.ios_services
        services.prechecks(snapshot, profile.table, before, after, protected,
                           impact=request.endpoint_impact is not None, undo=undo)
        commands = ["configure terminal", *services.render(profile.table, key, before, after), "end"]
        inverse = ["configure terminal", *services.render(profile.table, key, after, before), "end"]
        if platform == "iosxe":
            checks.append("This change affects running-config; startup-config requires a separately approved save")
    if platform in ios.PLATFORMS and profile.table in ios.STATE_TABLES:
        # Render from the before and after states so IOS can replace or remove just the changed settings.
        if profile.table == ios.L3_TABLE and ios.SUBINTERFACE.match(key) and ios.SUBINTERFACE.match(key).group(1).casefold() \
                in {name.casefold() for name in (protected or {}).get("interface", ())}:
            raise Rejected(["the parent port of subinterface %s is protected" % key], reason_codes=["port_protected"])
        if profile.table == ios.DHCP_RELAY:
            interface = ios.dhcp_interface(key)
            names = {interface.casefold(), interface.split(".", 1)[0].casefold()}
            if names & {name.casefold() for name in (protected or {}).get("interface", ())}:
                raise Rejected(["the relay interface or its parent is protected"], reason_codes=["port_protected"])
        commands = ios.render_state(profile.table, key, before, after)
        inverse = ios.render_state(profile.table, key, after, before)
    if platform in ios.PLATFORMS and profile.table == ios.MEMBER_TABLE:
        guarded_interfaces = {name.casefold() for name in (protected or {}).get("interface", ())}
        interfaces = [key] + [ios.PORT_CHANNEL + group for group in ios.member_groups(before, after)]
        if platform == "iosxe":
            interfaces += [ios.short_name(name) for name in interfaces]
        if any(name.casefold() in guarded_interfaces for name in interfaces):
            raise Rejected(["an interface affected by the membership change is protected"],
                           reason_codes=["port_protected"])
        journaled = undo_plan.get("member_digests") if undo_plan is not None else None
        if journaled is None:
            # Older records can safely undo a mode-only change. They cannot establish what a join or leave altered.
            if undo_plan is not None and not (before and after and before["channel-group"] == after["channel-group"]):
                raise Rejected(["the original plan did not record the port-channel and port configuration"])
            commands, inverse = ios.render_member(snapshot, key, before, after)
        else:
            if ios.member_scope_digest(snapshot, key, before, after) != journaled["scope_after"]:
                raise Rejected(["the affected EtherChannel configuration differs from the original readback"])
            commands, inverse = list(undo_plan["inverse"]), list(undo_plan["commands"])
    g44 = platform == "exos" and profile.table in exos_g44.TABLES
    if g44:
        scope = exos_g44.validate(snapshot, profile.table, key, before, after, protected, exos.Entry)
        checks.append("affected EXOS ports: " + (", ".join(sorted(scope, key=exos.port_order)) or "none"))
        if profile.table == exos_g44.JUMBO:
            checks.append("switch-wide frame size for every jumbo-enabled port")
        commands = exos_g44.render(profile.table, key, before, after)
        inverse = exos_g44.render(profile.table, key, after, before)
    if exos_routing:
        routing = exos.exos_g46
        undo_create = undo_plan is not None and undo_plan["op"] == "create" and after is None
        if exos_bgp_peer and before is not None and request.endpoint_impact != key and not undo_create:
            raise Rejected(["changing an existing ExtremeXOS BGP neighbor requires endpoint_impact naming the peer"],
                           reason_codes=["endpoint_impact_required"])
        routing.precheck(snapshot, profile.table, key, before, after, exos.Entry)
        exos.routing_scope(snapshot, profile.table, key, protected)
        commands = routing.render(profile.table, key, before, after)
        inverse = routing.render(profile.table, key, after, before)
    if platform == "exos" and g43 != "rename" and exos.touches_l3(profile.table, before, after):
        # 1.0.12 G45: a static route, a VRRP instance or the IP attributes of a VLAN are rendered from the whole
        # states before and after (measured order and side effects); IP routing has its own tested firmware
        reasons.extend(exos.g45_prechecks(snapshot, profile, op, key, before, after, protected))
        if reasons:
            raise Rejected(reasons)
        commands = exos.render_state(profile.table, key, before, after)
        inverse = exos.render_state(profile.table, key, after, before)
        if exos.l3_changed(profile.table, before, after):
            support = exos.l3_support(snapshot.firmware)
            checks[0] = firmware_prechecks(profile, support)[0]
    if exos_dhcp:
        exos.validate_dhcp(snapshot, profile.table, key, before, after, protected or {},
                           impact=request.endpoint_impact is not None, undo=undo)
        commands = exos.render_dhcp(profile.table, key, before, after)
        inverse = exos.render_dhcp(profile.table, key, after, before)
    if exos_service:
        exos_services.validate(snapshot, profile.table, key, before, after,
                               impact=request.endpoint_impact is not None,
                               undo=bool(undo_plan and snapshot.rest_digest(profile.table, key) == undo_plan["rest_sha256"]))
        commands = exos_services.render(profile.table, key, before, after)
        inverse = exos_services.render(profile.table, key, after, before)
        checks.append("The service change updates running configuration. Save is a separate operation.")
    if eos_routing_state:
        eos.eos_routing.prechecks(snapshot, profile.table, key, before, after, protected or {})
        commands = eos.eos_routing.render(profile.table, key, before, after)
        inverse = eos.eos_routing.render(profile.table, key, after, before)
    if eos_bgp_state:
        drop_router, new_router = eos.eos_bgp.prechecks(
            snapshot, key, before, after, protected, request.endpoint_impact, undo_plan,
        )
        commands = eos.eos_bgp.render(key, before, after, drop_parent=drop_router)
        inverse = eos.eos_bgp.render(key, after, before, drop_parent=new_router)
    if eos_dhcp_state:
        eos.eos_dhcp.prechecks(snapshot, profile.table, key, before, after, protected,
                              impact=request.endpoint_impact, undo=undo)
        if profile.table == eos.eos_dhcp.POOL and before is None:
            checks.append("EOS cannot verify whether an external DHCP server already serves the SVI's L2 network")
        drop_parent = profile.table == eos.eos_dhcp.POOL and after is None and eos.eos_dhcp.drop_created_parent(
            snapshot, key, undo_plan)
        new_parent = profile.table == eos.eos_dhcp.POOL and eos.eos_dhcp.SERVER not in snapshot.lines
        commands = eos.eos_dhcp.render(profile.table, key, before, after, drop_parent=drop_parent)
        inverse = eos.eos_dhcp.render(profile.table, key, after, before, drop_parent=new_parent)
    if ios_acl_state:
        ios.ios_acl.prechecks(snapshot, profile.table, key, before, after, protected)
        commands = ios.ios_acl.render(profile.table, key, before, after)
        inverse = ios.ios_acl.render(profile.table, key, after, before)
        if (platform == "ios" and profile.table == ios.ios_acl.ACL and key.startswith("ipv4:")
                and (ios.ios_acl.custom_numbers(before) or ios.ios_acl.custom_numbers(after))):
            checks.append("IOS 15.9 renumbers IPv4 ACL rules to 10, 20, 30, ... when the timed safeguard returns the "
                          "configuration (measured); an Admin undo restores the numbers exactly")
    if eos_acl_state:
        eos.eos_acl.prechecks(snapshot, profile.table, key, before, after, protected)
        commands = eos.eos_acl.render(profile.table, key, before, after)
        inverse = eos.eos_acl.render(profile.table, key, after, before)
    if eos_state:
        eos.eos_l3.prechecks(snapshot, profile.table, key, op, before, after, protected)
        commands = eos.eos_l3.render(profile.table, key, before, after)
        inverse = eos.eos_l3.render(profile.table, key, after, before)
    if eos_service_state:
        services = eos.eos_services
        services.prechecks(snapshot, profile.table, key, before, after, request.endpoint_impact,
                           undo_create=undo and undo_plan is not None and undo_plan["op"] == "create")
        commands = services.render(profile.table, key, before, after)
        inverse = services.render(profile.table, key, after, before)
    if eos_l2_state:
        eos.eos_l2.prechecks(snapshot, profile.table, key, before, after, protected or {})
        commands = eos.eos_l2.render(profile.table, key, before, after)
        inverse = eos.eos_l2.render(profile.table, key, after, before)
    if nxos_state:
        if (nxos_physical and not undo and before is not None and after is not None
                and before.get("mode") != after.get("mode") and "admin-state" not in changes):
            # A mode change resets Ethernet to the destination mode's administrative default.
            if after.get("mode") == "routed":
                after["admin-state"] = "disabled"
            else:
                after.pop("admin-state", None)
        if profile.table in nxos.ACL_TABLES:
            nxos.acl_prechecks(snapshot, profile.table, key, before, after, protected)
        commands = nxos.render_state(profile.table, key, before, after, snapshot)
        inverse = nxos.render_state(profile.table, key, after, before, snapshot)
    if nxos_link:
        nxos.link_prechecks(snapshot, profile.table, key, before, after, protected)
        commands = nxos.render_link(snapshot, profile.table, key, before, after)
        inverse = nxos.render_link(snapshot, profile.table, key, after, before)
    if nxos_service:
        checks.extend(nxos.service_prechecks(snapshot, profile.table, key, before, after, protected or {},
                                             request.endpoint_impact, undo=undo))
        commands = nxos.render_service(profile.table, key, before, after)
        inverse = nxos.render_service(profile.table, key, after, before)
    if platform == "fortios" and any("%%" in line for line in commands + inverse):
        raise Rejected(["automation placeholders cannot be restored as literal values by the timed safeguard"])
    if platform == "exos" and any(exos.EXPANDED in line for line in inverse):
        raise Rejected([exos.EXPANDED_REFUSAL])
    if (platform == "exos" and profile.table in PORT_TABLES
            and exos.touches_admin_state(snapshot, profile.table, key, after)):
        # the admin state and the inline-power cycle have their own tested versions (A5)
        support = exos.port_action_support(snapshot.firmware, profile.table)
        checks[0] = firmware_prechecks(profile, support)[0]
    if platform == "junos" and profile.table in junos.routing.TABLES:
        reasons.extend(junos.routing.prechecks(snapshot, profile.table, key, before, after, protected,
                                               getattr(request, "endpoint_impact", None), undo))
    elif platform == "junos" and profile.table in junos.fltr.TABLES:
        reasons.extend(junos.fltr.prechecks(snapshot, profile.table, key, before, after, protected,
                                            getattr(request, "endpoint_impact", None), undo))
    elif platform == "junos" and profile.table in junos.srx.TABLES:
        reasons.extend(junos.srx.prechecks(snapshot, profile.table, key, before, after, protected,
                                           getattr(request, "endpoint_impact", None), undo))
    elif platform == "junos" and profile.table in junos.dhcp.TABLES:
        reasons.extend(junos.dhcp.prechecks(snapshot, profile.table, key, before, after, protected,
                                            getattr(request, "endpoint_impact", None), undo))
    elif platform in ios.PLATFORMS and profile.table == ios.L3_TABLE:
        reasons.extend(ios.prechecks(snapshot, profile, op, key, after, before=before))
    elif platform == "exos":
        impact = getattr(request, "endpoint_impact", None) is not None
        if impact and not (exos_dhcp or exos_service or exos_bgp_peer or exos_acl_binding
                           or (profile.table in ("ports", exos.BOUNCE_TABLE)
                               and exos.touches_admin_state(snapshot, profile.table, key, after))):
            raise Rejected(["ExtremeXOS endpoint_impact applies to data port actions, DHCP, management services, "
                            "BGP neighbors and ACL attachments"])
        reasons.extend(exos.prechecks(snapshot, profile, op, key, after, endpoint_impact=impact))
    elif not g140:
        reasons.extend(adapter.prechecks(snapshot, profile, op, key, after,
                                         **({"undo": True} if undo and platform == "eos" else {}),
                                         **({"before": before, "changes": changes} if platform == "ruckus" else {})))
        if platform == "ruckus" and profile.table == ruckus.TABLE and op == "update":
            impact = getattr(request, "endpoint_impact", None)
            if ruckus.active_impact(before, after, changes) and impact is None:
                raise Rejected(["the WLAN broadcasts: changing its settings can cut clients"
                                " off, name the WLAN in endpoint_impact to accept it"],
                               reason_codes=["endpoint_impact_required"])
    if (platform == "fortios" and profile.table == fortios.DHCP_TABLE and not undo
            and getattr(request, "endpoint_impact", None) is None):
        # a reservation changes the address a client gets from an enabled DHCP server (checklist item 20b)
        raise Rejected(["changing a DHCP reservation affects an active DHCP server; endpoint_impact naming the request"
                        " key is required"], reason_codes=["endpoint_impact_required"])
    if policy:
        reasons.extend(fortios.policy_prechecks(snapshot, op, before, after, protected,
                                                impact=getattr(request, "endpoint_impact", None), order=order, key=key))
        support = fortios.policy_support(profile, snapshot, op, request.changes, before, after)
        checks[0] = firmware_prechecks(profile, support)[0]
    nat_object = platform == "fortios" and profile.table in fortios.NAT_TABLES
    if nat_object:
        reasons.extend(fortios.nat_prechecks(snapshot, profile.table, key, before, after, protected,
                                             request.endpoint_impact))
    if platform == "fortios" and profile.table in fortios.NETWORK_TABLES:
        reasons.extend(fortios.network_prechecks(snapshot, profile, op, key, before, after, protected))
    if platform == "fortios" and profile.table == fortios.DHCP_TABLE:
        reasons.extend(fortios.dhcp_protected(snapshot, key, protected))
    if phase2:
        fortios.phase2_prechecks(snapshot, op, key, after if after is not None else before,
                                 protected, request.endpoint_impact)
    switch_port_g18 = platform == "fortios" and profile.table == fortios.SWITCH_PORT
    if switch_port_g18:
        fortios.switch_vlan_prechecks(snapshot, key, before, after, protected)
    if platform == "fortios" and profile.table in fortios.ADDRESS_TABLES:
        reasons.extend(fortios.address_prechecks(snapshot, profile, op, key, before, after, changes))
        support = fortios.address_support(profile, snapshot.firmware, op, before, after)
        checks[0] = firmware_prechecks(profile, support)[0]
    if reasons:
        raise Rejected(reasons)
    if platform == "fortios" and not fortios.webhook_firmware(snapshot.firmware):
        fortios.check_cli_inverse(inverse)
    elif policy:
        fortios.rest_inverse(profile, op, key, inverse, "")
    document = {
        "format": PLAN_FORMAT,
        "safeguard_id": None,
        "admin_version": __version__,
        "platform": platform,
        "firmware": snapshot.firmware,
        "firmware_support": support,
        "table": profile.table,
        "op": op,
        "key": key,
        "device": device if device is not None else request.device,
        "request_id": request.request_id,
        "request_sha256": request.fingerprint(),
        "reason_characters": len(request.reason),
        "user_request_characters": len(request.user_request),
        "snapshot_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
        "rest_sha256": (_g43_rest(snapshot, key, before, after, "before") if g43 is not None
                        else snapshot.rest_digest(profile.table, key, **(
                            {"omit_empty_policy": True} if policy else {"switch_port_g18": True} if switch_port_g18
                            else _lag_scope(profile, before, after, before)),
                            **({"batch": True, "ignore_uuid": frozenset(tuple(item) for item in batch_volatile)}
                               if batch_step and platform == "fortios" else {}))),
        "prechecks": checks,
        "commands": commands,
        "inverse": inverse,
        "predicted": {"before": before, "after": after},
        "ignored_attributes": sorted(profile.volatile),
        "inverse_identity_changes": list(profile.inverse_identity_changes.get(op, ())),
        "rollback_evidence": profile.rollback_evidence,
        "plan_sha256": None,
    }
    if policy:
        document["policy_order"] = order
        if op == "move":
            document["policy_move_sha256"] = fortios.policy_move_digest(entry)
        if generated_uuid is not None:
            document["policy_uuid_generated"] = generated_uuid
            checks.append("FortiOS will assign a new UUID when recreating the firewall policy (original %s)"
                          % generated_uuid)
            if op == "delete":
                document["inverse_identity_changes"].append("uuid")
    if platform == "eos" and profile.table == "interface":
        document["state_schema"] = eos.INTERFACE_STATE_SCHEMA
    if platform == "exos" and profile.table == "ports":
        document["state_schema"] = exos.PORT_STATE_SCHEMA
    if platform == "junos" and profile.table == "interface":
        document["state_schema"] = junos.INTERFACE_STATE_SCHEMA
    if switch_port_g18:
        document["state_schema"] = fortios.SWITCH_PORT_STATE_SCHEMA
    if getattr(request, "endpoint_impact", None) is not None:
        ios_subinterface = platform == "ios" and profile.table == ios.L3_TABLE and ios.SUBINTERFACE.fullmatch(key)
        port_change = platform in IMPACT_PLATFORMS and (
            (profile.table in ("interface", "vlan-membership") and (platform != "junos" or profile.table == "interface"))
            or (platform == "nxos" and nxos.impact_table(profile.table))
            or (platform == "junos" and profile.table in JUNOS_IMPACT_TABLES)
            or (platform in ios.PLATFORMS and profile.table in ios.PORT_ACTION_TABLES)
            or (platform in ios.PLATFORMS and batch_step and profile.table in (ios.L3_TABLE, ios.MEMBER_TABLE))
            or (platform == "junos" and batch_step and profile.table in junos.BATCH_IMPACT_TABLES)
            or (platform == "eos" and (profile.table in (eos.BOUNCE_TABLE, eos.POE_TABLE)
                or (profile.table == eos.eos_l3.INTERFACE and eos.ETHERNET.fullmatch(key))
                or profile.table in eos.eos_acl.TABLES | eos.eos_dhcp.TABLES or eos_service_state or eos_bgp_state)))
        ios_dhcp_impact = platform in ios.PLATFORMS and profile.table in (ios.DHCP_POOL, ios.DHCP_RELAY)
        port_change = port_change or ios_acl_state or ios_dhcp_impact or ios_service_state
        junos_default_route = (platform == "junos" and profile.table == junos.ROUTE_TABLE
                               and junos.route_network(key).prefixlen == 0)
        ruckus_impact = platform == "ruckus" and profile.table == ruckus.TABLE and op == "update"
        fortios_dhcp = platform == "fortios" and profile.table == fortios.DHCP_TABLE
        if (not (ios_subinterface or port_change or junos_default_route or policy or fortios_dhcp or phase2 or nat_object
                 or switch_port or ruckus_impact or group_impact)
                and platform != "exos"):
            raise Rejected(["endpoint_impact is not supported for this platform, table or object"])
        document["endpoint_impact"] = key if fortios_dhcp else request.endpoint_impact
        if policy:
            document["prechecks"].append("Explicit endpoint impact accepted for firewall policy " + key)
        elif junos_default_route:
            document["prechecks"].append("Explicit endpoint impact accepted for the default route " + key)
        elif platform == "junos" and profile.table in junos.routing.BGP_TABLES:
            document["prechecks"].append("Explicit endpoint impact accepted for %s: routing may change" % key)
        elif platform == "junos" and profile.table in junos.fltr.TABLES:
            document["prechecks"].append("Explicit endpoint impact accepted for %s: traffic may be filtered" % key)
        elif platform == "junos" and profile.table in junos.srx.TABLES:
            document["prechecks"].append("Explicit impact accepted for %s: a security boundary changes" % key)
        elif platform == "junos" and profile.table in junos.dhcp.TABLES:
            document["prechecks"].append("Explicit endpoint impact accepted for %s: DHCP service may change" % key)
        elif eos_bgp_state or exos_bgp_peer:
            document["prechecks"].append("Explicit impact accepted for the BGP neighbor %s and its routes" % key)
        elif eos_service_state or nxos_service or ios_service_state or phase2:
            document["prechecks"].append("Explicit service impact accepted for %s" % key)
        elif ios_dhcp_impact:
            document["prechecks"].append("Explicit DHCP impact accepted for %s" % key)
        elif ruckus_impact:
            document["prechecks"].append("Explicit endpoint impact accepted for WLAN %s: connected clients may lose"
                                         " access" % key)
        elif group_impact:
            document["prechecks"].append("Explicit endpoint impact accepted for address group %s: the traffic of the"
                                         " active firewall policies that use it may change" % key)
        elif fortios_dhcp:
            document["prechecks"].append("Explicit impact accepted for the DHCP reservation %s: the address a client"
                                         " gets may change" % key)
        else:
            warning = ("the management service may be interrupted" if exos_service
                       else "connected clients, phones and APs may lose traffic")
            document["prechecks"].append("Explicit endpoint impact accepted for %s: %s" % (key, warning))
    if lag_capacity is not None:
        document["junos_lag_capacity"] = lag_capacity
    if rstp_root is not None:
        document["junos_rstp_root"] = rstp_root
    if platform in ios.PLATFORMS and profile.table == ios.MEMBER_TABLE:
        predicted_text = ios.member_snapshot_after(decode_snapshot(snapshot_raw), document)
        if batch_step:
            predicted_text = ios.batch_snapshot(predicted_text, snapshot.firmware, platform=platform)
        predicted_snapshot = ios.load(predicted_text, snapshot.firmware)
        document["member_digests"] = {
            "rest_after": ios.member_rest_digest(predicted_snapshot, key),
            "scope_before": ios.member_scope_digest(snapshot, key, before, after),
            "scope_after": ios.member_scope_digest(predicted_snapshot, key, before, after),
        }
        if journaled is not None and document["member_digests"]["scope_after"] != journaled["scope_before"]:
            raise Rejected(["the inverse will not restore the original EtherChannel configuration"])
    document["plan_sha256"] = plan_digest(document)
    if ports is not None:
        document["ports"] = sorted(snapshot.inventory, key=exos.port_order)
    return document


BATCH_PLATFORMS = ("nxos", "eos", "junos", "fortios", *ios.PLATFORMS)
BATCH_UNSUPPORTED = "profile batches are available on NX-OS, EOS, Junos, FortiOS, IOS and IOS XE"
BATCH_ROLLBACK = {
    "nxos": "timed NX-OS configuration return",
    "eos": "timed EOS configuration session commit timer",
    "junos": "Junos commit confirmed and complete configuration readback",
    "fortios": "FortiOS automation stitch with the inverse of every step in reverse order",
    **{platform: "IOS archive and timed configuration return" for platform in ios.PLATFORMS},
}
# 1.0.12 G24: the related FortiOS objects of one change (address -> group -> policy) are one batch. Only the tables
# whose plan, readback and return are measured on their own may be steps; a move or a NAT object is not one.
FORTIOS_BATCH_TABLES = (*fortios.ADDRESS_TABLES, fortios.POLICY_TABLE)


def build_batch(platform, snapshot_raw, request, firmware=None, protected=None, *, device=None, check=None,
                undo_plan=None, manual_policy_uuid=False):
    """Plan ordered profile changes against each preceding predicted configuration."""
    if platform not in BATCH_PLATFORMS:
        raise Rejected([BATCH_UNSUPPORTED], reason_codes=["action_unsupported"])
    adapter = adapter_for(platform)
    text = decode_snapshot(snapshot_raw)
    if platform == "fortios":
        _fortios_batch_allowed(request, _batch_firmware(platform, adapter, text, firmware))
    elif platform in ios.PLATFORMS:
        text = ios.batch_snapshot(text, firmware, platform=platform)
    start = text
    if platform == "junos" and undo_plan and verify(undo_plan, snapshot_raw, "after")["result"] != "match":
        raise Rejected(["the configuration differs from the state the undo was planned against"],
                       reason_codes=["plan_changed"])
    steps = []
    originals = list(reversed(undo_plan["batch_steps"])) if undo_plan else []
    seen_objects = set()
    for index, change in enumerate(request.changes):
        profile = find_profile(platform, change.table, _batch_firmware(platform, adapter, text, firmware))
        if platform in ("eos", "fortios", *ios.PLATFORMS):
            # one object, one step: a second step would be planned against a prediction the device does not confirm
            if (change.table, change.key) in seen_objects:
                raise Rejected(["batch step %d repeats %s %s" % (index + 1, change.table, change.key)],
                               reason_codes=["action_unsupported"])
            seen_objects.add((change.table, change.key))
        if profile.action is not None:
            raise Rejected(["profile batches require reversible configuration changes"],
                           reason_codes=["action_only_table"])
        if platform in ios.PLATFORMS:
            ios.batch_scope(change, protected)
        original = originals[index] if originals else None
        volatile = []
        if platform == "fortios":
            # the device names an object its step creates (uuid) and Admin cannot give an object it recreates its old
            # one: the rest of every other step ignores the identity of the objects the batch creates before it and
            # deletes after it, in the plan and in every readback
            volatile = ([[earlier.table, earlier.key] for earlier in request.changes[:index] if earlier.op == "create"]
                        + [[later.table, later.key] for later in request.changes[index + 1:] if later.op == "delete"])
        step = build_plan(platform, text.encode("utf-8"), change, firmware, protected,
                          undo=original is not None, undo_plan=original, device=device, batch_step=True,
                          batch_volatile=volatile, manual_policy_uuid=manual_policy_uuid)
        if platform == "fortios":
            step["batch_volatile"] = volatile
        if not step["commands"] or not step["inverse"]:
            raise Rejected(["batch step %d does not change the configuration" % (index + 1)],
                           reason_codes=["action_unsupported"])
        if original is not None and not _batch_step_restored(platform, original, text, "after"):
            raise Rejected(["the configuration differs from the state the undo was planned against"],
                           reason_codes=["plan_changed"])
        if check:
            check(step, text, steps)
        if platform in ios.PLATFORMS:
            step["ios_batch_step"] = True
        step["plan_sha256"] = plan_digest(step)
        text = _snapshot_after(platform, adapter, text, step)
        if platform in ios.PLATFORMS:
            text = ios.batch_snapshot(text, firmware, platform=platform)
        if original is not None and not _batch_step_restored(platform, original, text, "before"):
            raise Rejected(["the predicted undo does not restore the original configuration"],
                           reason_codes=["plan_changed"])
        steps.append(step)
    first = steps[0]
    support = next((step["firmware_support"] for step in steps if not tested.is_tested(step["firmware_support"])),
                   first["firmware_support"])
    plan = dict(first, table=BATCH, key=BATCH, op="update", firmware_support=support,
                request_sha256=request.fingerprint(), batch_steps=steps, ignored_attributes=[],
                inverse_identity_changes=[], rollback_evidence=BATCH_ROLLBACK[platform],
                prechecks=(["One exclusive candidate and one commit confirmed"] if platform == "junos"
                           else ["Each step is checked again on the device before it writes"]),
                predicted={side: {str(i): step["predicted"][side] for i, step in enumerate(steps, 1)}
                           for side in ("before", "after")},
                commands=_batch_commands(platform, steps, "commands"),
                inverse=_batch_commands(platform, reversed(steps), "inverse"))
    # the batch holds no field of its first step that is specific to one object (EOS interface state schema, ...)
    for field in ("endpoint_impact", "port_impact", "state_schema", "ports", "cycle_action", "member_digests",
                  "service_outage", "cycle_state", "acl_attachment_links", "link_before", "junos_lag_capacity",
                  "junos_rstp_root", "policy_order", "policy_move_sha256", "policy_uuid_generated", "ios_batch_step"):
        plan.pop(field, None)
    if platform == "fortios":
        # the one device safeguard script returns every step: all inverses together must fit its limit
        fortios.check_cli_inverse(plan["inverse"])
    if platform == "junos":
        plan["batch_snapshots"] = {side: junos.batch_snapshot_digest(junos.load(value, firmware))
                                   for side, value in (("before", start), ("after", text))}
        if plan["batch_snapshots"]["before"] == plan["batch_snapshots"]["after"]:
            raise Rejected(["the Junos batch does not change the configuration"], reason_codes=["action_unsupported"])
        if undo_plan and plan["batch_snapshots"]["after"] != undo_plan["batch_snapshots"]["before"]:
            raise Rejected(["the predicted undo does not restore the original configuration"],
                           reason_codes=["plan_changed"])
    plan["plan_sha256"] = plan_digest(plan)
    return plan, text


def _batch_firmware(platform, adapter, text, firmware):
    if firmware:
        return firmware
    return fortios.load(text, None).firmware if platform == "fortios" else adapter.firmware_of(text)


def _fortios_batch_allowed(request, firmware):
    if fortios.webhook_firmware(firmware):
        # the safeguard of FortiOS 8.0.1 and later is one REST request for one object; it cannot return a batch
        raise Rejected(["a FortiOS profile batch needs the cli-script safeguard; firmware %s keeps the webhook"
                        " safeguard of one object" % firmware], reason_codes=["action_unsupported"])
    if sum(change.table == fortios.POLICY_TABLE for change in request.changes) > 1:
        # the check account cannot see the first policy before it is written, so the second one has no verifiable order
        raise Rejected(["a FortiOS batch holds at most one firewall policy"], reason_codes=["action_unsupported"])
    for index, change in enumerate(request.changes, 1):
        if change.table not in FORTIOS_BATCH_TABLES or change.op not in ("create", "update", "delete"):
            raise Rejected(["batch step %d: a FortiOS batch holds %s changes" % (index, ", ".join(FORTIOS_BATCH_TABLES))],
                           reason_codes=["action_unsupported"])


def _snapshot_after(platform, adapter, text, step):
    if platform == "fortios":
        from netops_admin import prediction
        return prediction.snapshot_after(text, step)
    return adapter.snapshot_after(text, step)


def _batch_commands(platform, steps, field):
    if platform == "junos":
        return junos.batch_commands(steps, field)
    return [line for step in steps for line in step[field]]


def _batch_step_restored(platform, step, text, side):
    result = verify(step, text.encode("utf-8"), side)
    if platform == "fortios" and "policy_uuid_generated" in step and result["result"] != "match":
        # the device gives a recreated firewall policy a new UUID that the predicted configuration cannot hold
        result["differences"] = [item for item in result["differences"]
                                 if not item.startswith(("a FortiOS-assigned firewall policy UUID", "uuid: expected"))]
        return not result["differences"]
    return result["object_matches"] if platform == "junos" else result["result"] == "match"


def build_save_plan(device, snapshot_text, request, before):
    platform = device.platform
    save = ios_save if platform in ios.PLATFORMS else eos_save
    snapshot = adapter_for(platform).load(snapshot_text, device.firmware)
    profile = find_profile(platform, save.TABLE, snapshot.firmware)
    support = firmware_support(profile, snapshot.firmware)
    if platform in ios.PLATFORMS:
        snapshot_hash = before["running_sha256"]
    else:
        snapshot_hash = (nxos.save_snapshot_digest(snapshot_text) if platform == "nxos"
                         else hashlib.sha256(snapshot_text.encode("utf-8")).hexdigest())
    checks = firmware_prechecks(profile, support)
    checks.append("Approve the plan_sha256 for the entire running/startup diff" if before["diff"]
                  else "Running and startup configuration are identical")
    plan = {
        "format": PLAN_FORMAT, "admin_version": __version__, "platform": platform, "firmware": snapshot.firmware,
        "firmware_support": support, "table": save.TABLE, "op": "save", "key": save.TABLE,
        "device": device.name, "request_id": request.request_id, "request_sha256": request.fingerprint(),
        "reason_characters": len(request.reason), "user_request_characters": len(request.user_request),
        "snapshot_sha256": snapshot_hash, "rest_sha256": snapshot_hash,
        "prechecks": checks, "commands": [save.COMMAND], "inverse": [],
        "predicted": {"before": before, "after": ios_save.after(before) if platform in ios.PLATFORMS else eos_save.parse_diff("")},
        "ignored_attributes": [], "inverse_identity_changes": [], "rollback_evidence": save.NO_UNDO,
        "safeguard_id": None,
    }
    plan["plan_sha256"] = plan_digest(plan)
    return plan


def build_clear_plan(device, snapshot_text, request, target, before, *, firmware=None, model=None,
                     checksum=None) -> dict:
    if device.platform == "fortios" and request.table == fortios.SESSION_TABLE:
        if request.endpoint_impact != target.key:
            raise Rejected(["session clear requires endpoint_impact naming the request key"],
                           reason_codes=["endpoint_impact_required"])
        if not before["entries"]:
            raise Rejected(["the FortiOS filter matches no active forwarded session"], reason_codes=["clear_no_entry"])
        after = dict(before, entries=[])
        commands = [*target.commands(firmware), fortios.SESSION_CLEAR, fortios.SESSION_FILTER + " clear"]
        snapshot_hash = checksum
        support = tested.support("fortios", firmware, fortios.SESSION_FIRMWARE, model=model,
                                 function="this session clear")
        checks = ["The check account verified the positive filter, forwarded sessions and an empty expectation table",
                  "The write session must verify the same filter and session identifiers immediately before clear"]
        scope = [f"{len(before['entries'])} forwarded session(s) matched by {target.key} will be interrupted"]
        rollback = "Cleared FortiOS sessions cannot be restored by Admin. Clients can open new sessions."
    elif device.platform == "fortios" and request.table == fortios.IPSEC_TUNNEL:
        snapshot = fortios.load(snapshot_text, device.firmware)
        firmware = snapshot.firmware
        after = dict(before, up=True)
        commands = fortios.ipsec_recovery_commands(before)
        snapshot_hash = snapshot.rest_digest(fortios.PHASE2_TABLE, "")
        support = tested.support("fortios", firmware, fortios.IPSEC_FIRMWARE, function="IPsec selector recovery")
        checks = ["the protected management interface and targeted static Phase 2 were checked"]
        scope = ["Phase 2 %s on %s: %s" % (target[0], target[1],
                 "interrupt and restore this selector" if before["up"] else "bring up this selector")]
        rollback = "IPsec selector recovery changes runtime state and has no Admin undo."
    elif device.platform == "junos":
        after, scope = junos_clear.prediction(request.table, target, before)
        commands = [target.write]
        firmware = device.firmware
        snapshot_hash = hashlib.sha256(snapshot_text.encode("utf-8")).hexdigest()
        support = tested.support("junos", firmware, junos_clear.FIRMWARE, function="this clear operation")
        checks = ["target read with the check account"]
        rollback = "Cleared counters, learned entries and BGP refreshes cannot be restored by Admin."
    elif device.platform == "fortiadc":
        if not before["entries"]:
            raise Rejected(["the selected FortiADC scope has no active entry to clear"], reason_codes=["clear_no_entry"])
        after = dict(before, entries=[])
        scope = ["virtual server %s%s: %d active entries will be cleared" %
                 (target.key, " from " + target.source_ip if target.source_ip else "", len(before["entries"]))]
        commands = target.commands
        snapshot_hash = fortiadc.clear_snapshot_digest(snapshot_text)
        support = tested.support("fortiadc", firmware, fortiadc.CLEAR_FIRMWARE, function="this clear operation")
        checks = ["operational scope verified from an unfiltered FortiADC listing"]
        rollback = "Released WAF blocks and cleared SLB entries cannot be restored by Admin."
    elif device.platform == "eos":
        after, scope, command = eos_clear.prediction(request.table, target, before)
        commands = [command]
        snapshot_hash = eos_clear.config_digest(snapshot_text)
        support = tested.support("eos", firmware, eos_clear.FIRMWARE, function="this clear operation")
        checks = ["target read with the check account"]
        rollback = "Cleared counters, cache entries and the earlier BGP exchange cannot be restored by Admin."
    elif device.platform == "fortios":
        if request.endpoint_impact != target.key:
            raise Rejected(["lease release requires endpoint_impact naming the request key"],
                           reason_codes=["endpoint_impact_required"])
        snapshot = fortios.Snapshot(snapshot_text)
        guarded = fortios.protected_interfaces(snapshot, device.protected)
        before = fortios_lease.state(before, target)
        after, scope = fortios_lease.prediction(target, before, guarded)
        commands = [target.write]
        firmware = snapshot.firmware
        snapshot_hash = fortios_lease.config_digest(snapshot)
        support = tested.support("fortios", firmware, fortios_lease.FIRMWARE, function="this clear operation")
        checks = ["lease read with the check account from the unfiltered lease list of every interface"]
        rollback = "A released DHCP lease cannot be restored by Admin; the client asks for a new lease."
    elif device.platform == "nxos":
        after, scope = nxos_clear.prediction(request.table, target, before)
        commands = [target.write]
        snapshot_hash = nxos_clear.config_digest(snapshot_text)
        support = tested.support("nxos", firmware, nxos_clear.FIRMWARE, function="this clear operation")
        checks = ["target read with the check account"]
        rollback = "Cleared counters and cache entries cannot be restored by Admin."
    elif device.platform in ios.PLATFORMS:
        after, scope = _ios_clear_prediction(target, before)
        if device.platform == "iosxe" and ios.clear_active(target, before) and request.endpoint_impact is None:
            raise Rejected(["the active IOS XE clear requires endpoint_impact naming the request key"],
                           reason_codes=["endpoint_impact_required"])
        commands = [target.write]
        firmware = device.firmware
        snapshot_hash = ios.clear_snapshot_digest(snapshot_text)
        versions = (ios.WIRELESS_FIRMWARE if request.table == ios.WIRELESS_CLIENT
                    else ios.CLEAR_FIRMWARE[request.table])
        if versions:
            support = tested.support(device.platform, firmware, versions, function="this clear operation")
        else:
            support = {"status": tested.UNTESTED, "platform": device.platform, "device_version": firmware,
                       "model": None, "tested_versions": [],
                       "message": "This IOS IPv6 neighbor clear has no successful live verification on record."}
        checks = ["IOS clear scope verified with the check account"]
        rollback = ("The client can reconnect. The previous wireless association cannot be restored by Admin."
                    if request.table == ios.WIRELESS_CLIENT
                    else "Cleared counters and cache entries cannot be restored by Admin.")
    else:
        after, scope = _exos_clear_prediction(request, target, before)
        commands = [target.write]
        firmware = device.firmware
        snapshot_hash = hashlib.sha256(snapshot_text.encode("utf-8")).hexdigest()
        support = tested.support("exos", firmware, exos.CLEAR_FIRMWARE, function="this clear operation")
        checks = ["target read with the check account"]
        rollback = "Cleared counters and cache entries cannot be restored by Admin."
    plan = {
        "format": PLAN_FORMAT, "admin_version": __version__, "platform": device.platform, "firmware": firmware,
        "firmware_support": support, "table": request.table, "op": "clear", "key": request.key if device.platform == "fortios" else target.key,
        "device": device.name,
        "request_id": request.request_id, "request_sha256": request.fingerprint(),
        "reason_characters": len(request.reason), "user_request_characters": len(request.user_request),
        "snapshot_sha256": snapshot_hash, "rest_sha256": snapshot_hash,
        "prechecks": [*checks, *scope], "commands": commands, "inverse": [],
        "predicted": {"before": before, "after": after}, "ignored_attributes": [], "inverse_identity_changes": [],
        "rollback_evidence": rollback, "safeguard_id": None,
    }
    if device.platform == "fortios":
        plan["endpoint_impact"] = request.endpoint_impact
    if device.platform in ios.PLATFORMS and request.endpoint_impact is not None:
        plan["endpoint_impact"] = target.key
    plan["plan_sha256"] = plan_digest(plan)
    return plan


def _ios_clear_prediction(target, before):
    if target.table == ios.WIRELESS_CLIENT:
        if len(before["entries"]) != 1:
            raise Rejected(["the selected wireless client is absent"], reason_codes=["clear_no_entry"])
        return dict(before, entries=[]), [f"Disconnect only the wireless client {target.key}"]
    if target.table == "port-counters":
        return (dict(before, counters=dict.fromkeys(ios.CLEAR_COUNTER_NAMES, 0), last_clearing="00:00:00"),
                ["interface %s: show interfaces counters will be reset" % target.port])
    entries = before["entries"]
    if not entries or not any(row["dynamic"] for row in entries):
        raise Rejected(["the selected IOS scope has no dynamic entry to clear"], reason_codes=["clear_no_entry"])
    if target.table != "fdb" or target.port is None:
        if len(entries) != 1:
            raise Rejected(["the selected IOS address matches multiple entries"], reason_codes=["clear_ambiguous_entry"])
    return (dict(before, entries=[]),
            ["%s %s%s: %d dynamic entries in scope" % (target.table, target.key,
             " in VRF " + target.vrf if target.vrf else "", len(entries))])


def _exos_clear_prediction(request, target, before):
    if request.table == "port-counters":
        after = dict(before, counters=dict.fromkeys(exos.CLEAR_COUNTER_NAMES, 0))
    else:
        entries = before["entries"]
        dynamic = [entry for entry in entries if entry["dynamic"]]
        if not dynamic:
            raise Rejected(["the selected scope has no learned entry to clear"], reason_codes=["clear_no_entry"])
        if target.scope in ("mac", "ip") and len(dynamic) != 1:
            raise Rejected(["the selected address matches multiple learned entries"], reason_codes=["clear_ambiguous_entry"])
        # EXOS 33.6.1.14 also evicts a static IPv6 neighbor at the selected address (G50 live measurement).
        if request.table == "neighbor-discovery" and len(entries) != 1:
            raise Rejected(["the selected IPv6 address has other entries that clear could evict"],
                           reason_codes=["clear_ambiguous_entry"])
        after = dict(before, entries=[entry for entry in entries if not entry["dynamic"]])
    if request.table == "port-counters":
        scope = ["port %s: all %d traffic counters are reset" % (target.value, len(exos.CLEAR_COUNTER_NAMES))]
    else:
        # 501-rv: the preview names how many learned entries the clear removes (a VLAN scope can be large)
        scope = ["%s %s: %d learned (dynamic) entries will be cleared, %d other entries stay"
                 % (request.table, target.key, len(dynamic), len(entries) - len(dynamic))]
    return after, scope


PLAN_FIELDS = frozenset((
    "format", "admin_version", "platform", "firmware", "table", "op", "key", "device", "request_id",
    "request_sha256", "reason_characters", "user_request_characters", "snapshot_sha256", "rest_sha256",
    "prechecks", "commands", "inverse", "predicted", "ignored_attributes", "inverse_identity_changes",
    "rollback_evidence", "plan_sha256", "safeguard_id",
))
PLAN_OPS = ("create", "update", "delete", "move", "clear", "save")
CLEAR_TABLES = {"exos": exos.CLEAR_TABLES, "fortiadc": fortiadc.CLEAR_TABLES,
                "junos": junos_clear.TABLES, "nxos": nxos_clear.TABLES, "eos": eos_clear.TABLES,
                "fortios": (fortios.SESSION_TABLE, fortios.IPSEC_TUNNEL, fortios_lease.TABLE),
                "ios": ios.CLEAR_TABLES, "iosxe": (*ios.CLEAR_TABLES, ios.WIRELESS_CLIENT)}
PLAN_TEXTS = ("format", "admin_version", "table", "key", "request_sha256", "snapshot_sha256", "rest_sha256",
              "plan_sha256", "rollback_evidence")
PLAN_OPTIONAL_TEXTS = ("firmware", "device", "request_id", "safeguard_id")
PLAN_COUNTS = ("reason_characters", "user_request_characters")
PLAN_TEXT_LISTS = ("prechecks", "commands", "inverse", "ignored_attributes", "inverse_identity_changes")


def _texts(value) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _typed(plan) -> bool:
    return (plan["platform"] in tuple(ADAPTERS) and plan["op"] in PLAN_OPS
            and all(isinstance(plan[name], str) for name in PLAN_TEXTS)
            and all(plan[name] is None or isinstance(plan[name], str) for name in PLAN_OPTIONAL_TEXTS)
            and all(isinstance(plan[name], int) and not isinstance(plan[name], bool) and plan[name] >= 0
                    for name in PLAN_COUNTS)
            and all(_texts(plan[name]) for name in PLAN_TEXT_LISTS)
            and all(side is None or isinstance(side, dict) for side in plan["predicted"].values()))


def _read_plan(plan) -> dict:
    from netops_admin import schema_runtime
    if schema_runtime.is_plan(plan):
        return schema_runtime.read_plan(plan)
    # Older plans may omit firmware_support. FortiADC virtual-server prechecks set service_outage.
    if (not isinstance(plan, dict)
            or set(plan) - {"ports", "firmware_support", "endpoint_impact", "port_impact", "cycle_action", "member_digests",
                            "service_outage", "cycle_state", "state_schema", "acl_attachment_links", "link_before",
                            "junos_lag_capacity", "junos_rstp_root", "exos_acl_file_sha256", "batch_steps",
                            "batch_snapshots", "fortiadc_ha_role", "policy_order", "policy_move_sha256",
                            "policy_uuid_generated", "batch_volatile", "ios_batch_step"} != PLAN_FIELDS
            or plan.get("format") != PLAN_FORMAT):
        raise Rejected(["plan is not a %s document" % PLAN_FORMAT])
    if "exos_acl_file_sha256" in plan and (
            (plan.get("platform"), plan.get("table")) != ("exos", exos_acl.BINDING)
            or not isinstance(plan["exos_acl_file_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", plan["exos_acl_file_sha256"])):
        raise Rejected(["plan holds an invalid ExtremeXOS ACL file digest"])
    if "batch_volatile" in plan and (
            plan.get("platform") != "fortios" or not isinstance(plan["batch_volatile"], list)
            or any(not isinstance(item, list) or len(item) != 2 or not _texts(item) for item in plan["batch_volatile"])):
        raise Rejected(["plan holds invalid objects of a FortiOS batch whose identity the rest ignores"])
    if "ios_batch_step" in plan and (plan["platform"] not in ios.PLATFORMS or plan["ios_batch_step"] is not True
                                    or plan["table"] not in ios.BATCH_TABLES):
        raise Rejected(["plan holds an invalid IOS batch step"])
    if "service_outage" in plan and (plan.get("platform") != "fortiadc" or not _texts(plan["service_outage"])):
        raise Rejected(["plan holds an invalid service outage"])
    if "fortiadc_ha_role" in plan and (plan["platform"], plan["fortiadc_ha_role"]) != ("fortiadc", "primary"):
        raise Rejected(["plan holds an invalid FortiADC HA role"])
    exos_impact = plan["platform"] == "exos" and plan["table"] in (
        "ports", exos.BOUNCE_TABLE, *exos.DHCP_TABLES, *exos_services.TABLES)
    exos_endpoint_impact = exos_impact or (plan["platform"] == "exos"
                                          and plan["table"] in (exos.exos_g46.PEER, exos_acl.BINDING))
    ruckus_impact = plan["platform"] == "ruckus" and plan["table"] == ruckus.TABLE and plan["op"] == "update"
    policy = (plan["platform"], plan["table"]) == ("fortios", fortios.POLICY_TABLE)
    if "policy_order" in plan:
        order = plan["policy_order"]
        if (not policy or not isinstance(order, dict) or set(order) != {"before", "after"}
                or any(not _texts(ids) or not all(fortios.valid_policy_id(item) for item in ids)
                       or len(set(ids)) != len(ids) for ids in order.values())):
            raise Rejected(["plan holds an invalid firewall policy order"])
    move_hash = plan.get("policy_move_sha256")
    if (plan["op"] == "move") != ("policy_move_sha256" in plan) or (
            plan["op"] == "move" and (not policy or "policy_order" not in plan
                                    or not isinstance(move_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", move_hash))):
        raise Rejected(["plan holds an invalid move operation"])
    if "policy_uuid_generated" in plan and (
            "policy_order" not in plan or plan["op"] not in ("create", "delete")
            or not fortios.valid_policy_uuid(plan["policy_uuid_generated"])):
        raise Rejected(["plan holds an invalid original UUID for firewall policy recreation"])
    fortios_clear = (plan["platform"], plan["table"], plan["op"]) == ("fortios", fortios.SESSION_TABLE, "clear")
    if fortios_clear and "endpoint_impact" not in plan:
        raise Rejected(["plan holds no endpoint impact confirmation for the FortiOS session clear"])
    fortios_impact = plan["platform"] == "fortios" and plan["table"] in (
        fortios.DHCP_TABLE, fortios.PHASE2_TABLE, fortios.GROUP_TABLE, fortios.IPSEC_TUNNEL, fortios_lease.TABLE,
        *fortios.NAT_TABLES, *fortios.SWITCH_PORT_TABLES)
    if "endpoint_impact" in plan and (
            (plan["platform"] not in IMPACT_PLATFORMS and not (exos_endpoint_impact or policy or fortios_clear
                                                             or fortios_impact or ruckus_impact))
            or (plan["platform"] == "nxos" and
                not nxos.impact_table(plan["table"]))
            or plan["endpoint_impact"] != plan["key"]):
        raise Rejected(["plan holds an invalid endpoint impact confirmation"])
    if "port_impact" in plan:
        impact = plan["port_impact"]
        nxos_impact = (plan["platform"] == "nxos" and
                       plan["table"] in ("interface", nxos.MEMBERSHIP_TABLE, nxos.BOUNCE_TABLE))
        fields = ({"link", "mode", "vlan", "learned_macs"} if nxos_impact
                  else {"tagged_vlans", "lag_ports", "link", "lldp", "learned_macs"})
        if (not (exos_impact or nxos_impact) or "endpoint_impact" not in plan or not isinstance(impact, dict)
                or set(impact) != fields
                or not all(isinstance(value, str) for value in impact.values())):
            raise Rejected(["plan holds invalid port impact"])
    if "cycle_action" in plan and (plan["platform"] != "exos" or plan["op"] != "update" or
            {"inline-power": "poe-cycle", exos.BOUNCE_TABLE: "port-bounce"}.get(plan["table"]) != plan["cycle_action"]):
        raise Rejected(["plan holds an invalid ExtremeXOS cycle action"])
    predicted = plan["predicted"]
    if not isinstance(predicted, dict) or set(predicted) != {"before", "after"}:
        raise Rejected(["plan has no prediction"])
    if not _typed(plan) or ("firmware_support" in plan and not tested.valid(plan["firmware_support"])):
        raise Rejected(["plan holds a value of the wrong type"])
    atomic_batch = plan["platform"] == "junos" and "batch_steps" in plan
    if atomic_batch or "batch_snapshots" in plan:
        digests = plan.get("batch_snapshots")
        if (not atomic_batch or not isinstance(digests, dict) or set(digests) != {"before", "after"}
                or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                       for value in digests.values()) or digests["before"] == digests["after"]):
            raise Rejected(["plan holds invalid Junos batch snapshots"])
    if "batch_steps" in plan:
        steps = plan["batch_steps"]
        if (plan["platform"] not in BATCH_PLATFORMS or plan["table"] != BATCH or plan["key"] != BATCH or plan["op"] != "update"
                or not isinstance(steps, list) or not 2 <= len(steps) <= MAX_BATCH_STEPS
                or any(not isinstance(step, dict) or "batch_steps" in step for step in steps)):
            raise Rejected(["plan holds an invalid profile batch"])
        for step in steps:
            _read_plan(step)
            if (step["format"] != PLAN_FORMAT or step["op"] not in ("create", "update", "delete")
                    or not step["commands"] or not step["inverse"] or step["safeguard_id"] is not None
                    or (plan["platform"] in ios.PLATFORMS and not step.get("ios_batch_step"))
                    or any(step[field] != plan[field] for field in ("device", "platform", "firmware"))):
                raise Rejected(["plan holds an invalid profile batch step"])
        if (plan["commands"] != _batch_commands(plan["platform"], steps, "commands")
                or plan["inverse"] != _batch_commands(plan["platform"], reversed(steps), "inverse")
                or any(predicted[side] != {str(i): step["predicted"][side] for i, step in enumerate(steps, 1)}
                       for side in predicted)):
            raise Rejected(["plan holds inconsistent profile batch steps"])
    if plan["op"] == "clear" and (plan["table"] not in CLEAR_TABLES.get(plan["platform"], ())
                                  or plan["inverse"] or plan["safeguard_id"] is not None
                                  or any(side is None for side in predicted.values())):
        raise Rejected(["plan holds an invalid clear operation"])
    if plan["table"] == ios.WIRELESS_CLIENT and (
            plan["platform"] != "iosxe" or plan["op"] != "clear"
            or plan.get("endpoint_impact") != plan["key"]
            or plan["commands"] != [ios.clear_target(ios.WIRELESS_CLIENT, plan["key"], {}).write]):
        raise Rejected(["plan holds an invalid wireless client clear"])
    if plan["op"] == "save" and plan["platform"] in ("eos", "nxos") and not eos_save.valid_plan(plan):
        raise Rejected(["plan holds an invalid save operation"])
    if plan["op"] == "save" and plan["platform"] in ios.PLATFORMS and not ios_save.valid_plan(plan):
        raise Rejected(["plan holds an invalid IOS save operation"])
    if plan["op"] == "save" and plan["platform"] not in ("eos", "nxos", *ios.PLATFORMS) and (
            plan["platform"] != "exos" or plan["table"] != exos_save.TABLE
            or plan["key"] != exos_save.TABLE or plan["commands"] != [exos_save.COMMAND]
            or plan["inverse"] or plan["safeguard_id"] is not None
            or any(side is None for side in predicted.values())):
        raise Rejected(["plan holds an invalid ExtremeXOS save operation"])
    if plan["op"] == "clear" and plan["platform"] in ios.PLATFORMS and plan["table"] != "port-counters":
        if any(not isinstance(side.get(field), list) or not all(isinstance(row, dict) for row in side[field])
               for side in predicted.values() for field in ("entries", "other_entries")):
            raise Rejected(["plan holds invalid IOS clear entries"])
    state_schemas = {("eos", "interface"): eos.INTERFACE_STATE_SCHEMA, ("exos", "ports"): exos.PORT_STATE_SCHEMA,
                     ("junos", "interface"): junos.INTERFACE_STATE_SCHEMA,
                     ("fortios", fortios.SWITCH_PORT): fortios.SWITCH_PORT_STATE_SCHEMA}
    if "state_schema" in plan and (type(plan["state_schema"]) not in (int, str)
                                   or state_schemas.get((plan["platform"], plan["table"])) != plan["state_schema"]):
        raise Rejected(["plan holds an unsupported interface state schema"])
    if "link_before" in plan and (plan["platform"] != "junos" or plan["table"] != "interface"
                                  or plan["link_before"] not in ("up", "down")
                                  or "speed" not in (predicted["before"] or {})
                                  or "speed" in (predicted["after"] or {})):
        raise Rejected(["plan holds an invalid link state before speed removal"])
    if "ports" in plan and (plan["platform"] != "exos" or not isinstance(plan["ports"], list)
                            or not all(isinstance(port, str) for port in plan["ports"])):
        raise Rejected(["plan holds an invalid port list"])
    if "cycle_state" in plan:
        state = plan["cycle_state"]
        switch_cycle = plan["platform"] == "fortios" and plan["table"] in fortios.SWITCH_PORT_TABLES
        fields = {"link", "admin"} if switch_cycle else {"link", "lldp", "learned_macs"}
        xe_inline_power = plan["platform"] == "iosxe" and plan["table"] == ios.POE_TABLE
        if xe_inline_power or plan["table"] in (eos.POE_TABLE, junos.POE_CYCLE_TABLE, ios.POE_CYCLE_TABLE):
            fields.add("poe")
        if (plan["platform"], plan["table"]) == ("fortios", fortios.SWITCH_POE_CYCLE):
            fields.add("poe")
        if (not ((plan["platform"] == "eos" and plan["table"] in (eos.BOUNCE_TABLE, eos.POE_TABLE))
                 or (plan["platform"] == "junos" and plan["table"] in junos.CYCLE_TABLES)
                 or xe_inline_power or (plan["platform"] in ios.PLATFORMS and plan["table"] in ios.ACTION_TABLES)
                 or (plan["platform"] == "nxos" and plan["table"] == nxos.BOUNCE_TABLE) or switch_cycle)
                or not isinstance(state, dict) or set(state) != fields
                or not all(isinstance(value, str) for value in state.values())):
            raise Rejected(["plan holds invalid cycle state"])
    if "acl_attachment_links" in plan:
        links = plan["acl_attachment_links"]
        if (plan["platform"] != "eos" or plan["table"] not in eos.eos_acl.TABLES
                or not isinstance(links, dict)
                or any(type(link) is not bool or not isinstance(slot, str)
                       or not re.fullmatch(r"(?:Ethernet[0-9/]+|Vlan[0-9]+):(?:in|out)", slot)
                       for slot, link in links.items())):
            raise Rejected(["plan holds invalid EOS ACL attachment state"])
    junos_lag = plan["platform"] == "junos" and plan["table"] == junos_g140.LAG
    if junos_lag or "junos_lag_capacity" in plan:
        capacity = plan.get("junos_lag_capacity")
        if (not junos_lag or not isinstance(capacity, dict) or set(capacity) != {"before", "after"}
                or any(value is not None and (not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value))
                       for value in capacity.values())):
            raise Rejected(["plan holds invalid Junos LAG capacity"])
    rstp = plan["platform"] == "junos" and plan["table"] in (junos_g140.RSTP, junos_g140.RSTP_PORT)
    if rstp or "junos_rstp_root" in plan:
        layout = plan.get("junos_rstp_root")
        if (not rstp or not isinstance(layout, dict) or set(layout) != {"before", "after"}
                or any(value not in ("absent", "empty", "configured") for value in layout.values())):
            raise Rejected(["plan holds invalid Junos RSTP configuration hierarchy"])
    if "member_digests" in plan:
        digests = plan["member_digests"]
        if (plan["platform"] not in ios.PLATFORMS or plan["table"] != ios.MEMBER_TABLE or not isinstance(digests, dict)
                or set(digests) != {"rest_after", "scope_before", "scope_after"}
                or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                       for value in digests.values())):
            raise Rejected(["plan holds invalid EtherChannel digests"])
    if plan["plan_sha256"] not in (plan_digest(plan), _legacy_plan_digest(plan)):
        raise Rejected(["plan content does not match its plan_sha256"])
    return plan


def verify(plan, snapshot_raw: bytes, expect: str = "after") -> dict:
    from netops_admin import schema_runtime
    if schema_runtime.is_plan(plan):
        return schema_runtime.verify(plan, snapshot_raw, expect)
    plan = _read_plan(plan)
    if plan["op"] in ("clear", "save"):
        raise Rejected([f"{plan['op']} verification requires a live operational readback"])
    if expect not in ("before", "after"):
        raise Rejected(["expect must be before or after"])
    if "batch_snapshots" in plan:
        snapshot = junos.load(decode_snapshot(snapshot_raw), plan["firmware"])
        matches = junos.batch_snapshot_digest(snapshot) == plan["batch_snapshots"][expect]
        return {"result": "match" if matches else "mismatch", "object_matches": matches, "rest_matches": matches,
                "expect": expect, "key": plan["key"], "plan_sha256": plan["plan_sha256"],
                "snapshot_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
                "differences": [] if matches else ["configuration differs from the planned Junos batch state"]}
    if "batch_steps" in plan:
        # Each boundary verifies its object and the rest of the snapshot. The last step's rest
        # includes the effects of all preceding steps, as verified after each write.
        step = plan["batch_steps"][0 if expect == "before" else -1]
        verdict = verify(dict(step, safeguard_id=plan["safeguard_id"]), snapshot_raw, expect)
        return dict(verdict, key=plan["key"], plan_sha256=plan["plan_sha256"],
                    object_matches=verdict["result"] == "match")
    adapter = adapter_for(plan["platform"])
    text = decode_snapshot(snapshot_raw)
    if plan.get("ios_batch_step"):
        text = ios.batch_snapshot(text, plan["firmware"], platform=plan["platform"])
    snapshot = adapter.load(text, plan["firmware"])
    if plan["platform"] in ios.PLATFORMS:
        snapshot.platform = plan["platform"]
    if "ports" in plan:
        snapshot.inventory = frozenset(plan["ports"])
    profile = find_profile(plan["platform"], plan["table"], snapshot.firmware)
    if plan["platform"] == "exos" and profile.table in exos.exos_g46.TABLES:
        exos.exos_g46.require_module(snapshot, profile.table, plan["key"])
    entries = snapshot.entries(profile.table)
    if entries is None:
        raise SnapshotRejected(["snapshot holds no %s section" % profile.table], SNAPSHOT_INCOMPLETE)
    differences = []
    g43 = exos.plan_kind(plan["predicted"]["before"], plan["predicted"]["after"]) if plan["platform"] == "exos" else None
    if g43 is not None:
        return _g43_verify(plan, snapshot, profile, entries, expect, snapshot_raw, g43)
    entry = _find_entry(entries, plan["key"])
    actual = {} if profile.implicit_keys else None
    if entry is not None and "policy_move_sha256" in plan:
        actual = observed_state(plan, fortios._shown_attributes(entry))
        if fortios.policy_move_digest(entry) != plan["policy_move_sha256"]:
            differences.append("the moved firewall policy configuration changed")
    elif entry is not None and is_isolated_plan(profile, plan):
        lists = [name for name, attribute in profile.attributes.items() if attribute.type in LIST_TYPES]
        attributes, unsupported = snapshot.entry_state(entry, lists)
        actual = full_state(profile, attributes, opaque="policy_order" in plan)
        differences.extend("object holds configuration outside the profile: %s" % item for item in unsupported)
    elif entry is not None:
        actual, unsupported = _entry_state(snapshot, profile, entry)
        if plan["platform"] == "exos" and profile.table == "vlan" and _preserves_exos_vlan_l3(plan, snapshot):
            actual, unsupported = exos.without_l3(actual, unsupported, entry)
        differences.extend("object holds configuration outside the profile: %s" % item for item in unsupported)
    legacy_exos_port = plan["platform"] == "exos" and profile.table == "ports" and "state_schema" not in plan
    if legacy_exos_port and actual is not None:
        actual.pop("description-string", None)
    if plan["platform"] == "fortios" and plan["table"] == fortios.SWITCH_PORT:
        actual = check_view(plan, actual)
    wanted = plan["predicted"][expect]
    warnings = []
    if tracks_policy_uuid(plan) and entry is not None and actual is not None:
        value = entry.value("uuid")
        if fortios.valid_policy_uuid(value):
            actual["uuid"] = value.lower()
    original_uuid = plan.get("policy_uuid_generated")
    if original_uuid is not None and wanted is not None:
        new_uuid = (actual or {}).get("uuid")
        if new_uuid is None or (plan["op"] == "create" and new_uuid == original_uuid):
            differences.append("a FortiOS-assigned firewall policy UUID could not be verified")
        elif new_uuid != original_uuid:
            wanted = {**wanted, "uuid": new_uuid}
            warnings.append({"code": "uuid_changed", "original_uuid": original_uuid, "new_uuid": new_uuid})
    if ("policy_order" in plan and plan["op"] == "delete" and expect == "before"
            and not tracks_policy_uuid(plan)):
        differences.append("the original firewall policy UUID was not recorded")
    legacy_ruckus = plan["platform"] == "ruckus" and profile.table == ruckus.TABLE and all(
        ruckus.SECURITY_FIELDS.keys().isdisjoint(side or {}) for side in plan["predicted"].values()
    )
    if legacy_ruckus and wanted is not None:
        if plan["op"] == "create":
            wanted = {**wanted, **ruckus.CREATE_SECURITY}
        elif actual is not None:
            actual = {name: value for name, value in actual.items() if name not in ruckus.SECURITY_FIELDS}
    if plan["platform"] == "ruckus" and plan["op"] == "delete" and profile.table == ruckus.TABLE:
        try:
            if expect == "after":
                ruckus.require_group_membership(snapshot.group_memberships, plan["key"], present=False)
            elif entry is not None and not legacy_ruckus:
                ruckus.require_restorable(snapshot, profile, entry)
        except Rejected as exc:
            differences.extend(exc.reasons)
    if (plan["platform"] == "ios" and profile.table == ios.ios_acl.ACL and plan["key"].startswith("ipv4:")
            and expect == "before" and actual and wanted and actual != wanted
            and ios.ios_acl.same_order(actual, wanted)):
        # IOSv 15.9 returns the rules in order but can change the sequence numbers used for future edits.
        differences.append("IPv4 ACL rule sequence numbers differ from the original configuration")
        actual = wanted
    if (actual is None) != (wanted is None):
        differences.append("object %s, expected %s"
                           % ("absent" if actual is None else "present", "absent" if wanted is None else "present"))
    elif actual is not None:
        for name in sorted(set(actual) | set(wanted)):
            if actual.get(name) != wanted.get(name):
                differences.append("%s: expected %r, found %r" % (name, wanted.get(name), actual.get(name)))
    if "policy_order" in plan:
        found = snapshot.policy_order()
        if found != plan["policy_order"][expect]:
            differences.append("the firewall policy order differs from the planned order")
    elif (plan["op"] == "create" and (profile.create_position == "last" or
          (plan["platform"], profile.table) == ("fortios", fortios.POLICY_TABLE)) and expect == "after"
            and entry is not None and list(entries)[-1] != plan["key"]):
        differences.append("new object is not placed after all existing objects")
    if "junos_lag_capacity" in plan and junos_g140.capacity(snapshot) != plan["junos_lag_capacity"][expect]:
        differences.append("Junos aggregate device-count differs from the planned value")
    if "junos_rstp_root" in plan and junos_g140.rstp_root(snapshot) != plan["junos_rstp_root"][expect]:
        differences.append("Junos RSTP hierarchy differs from the planned state")
    if (plan["platform"], plan["table"]) == ("eos", eos.eos_dhcp.POOL):
        if not eos.eos_dhcp.pool_parent_matches(snapshot, plan, expect):
            differences.append("the EOS DHCP server configuration section differs from the planned state")
    if (plan["platform"], plan["table"]) == ("eos", eos.eos_bgp.TABLE):
        if not eos.eos_bgp.parent_matches(snapshot, plan, expect):
            differences.append("the EOS BGP router section differs from the planned state")
    if plan["platform"] == "junos" and profile.table in junos.srx.NAT and not junos.srx.nat_order_matches(
            snapshot, plan, expect):
        differences.append("the SRX NAT rule is outside its planned evaluation order")
    object_matches = not differences
    rest_options = {"port_description": False} if legacy_exos_port else {}
    if legacy_ruckus:
        rest_options["legacy"] = True
    if plan.get("state_schema") == fortios.SWITCH_PORT_STATE_SCHEMA:
        rest_options["switch_port_g18"] = True
    rest_options.update(_lag_scope(profile, plan["predicted"]["before"], plan["predicted"]["after"], wanted))
    if "policy_order" in plan:
        rest_options["omit_empty_policy"] = True
    if "batch_volatile" in plan:
        rest_options["batch"] = True
        rest_options["ignore_uuid"] = frozenset(tuple(item) for item in plan["batch_volatile"])
    try:
        rest_digest = snapshot.rest_digest(profile.table, plan["key"], plan.get("safeguard_id"), **rest_options)
    except Rejected:
        if not rest_options.get("scope"):
            raise
        rest_digest = None
    expected_rest = plan["rest_sha256"]
    if plan["platform"] in ios.PLATFORMS and profile.table == ios.MEMBER_TABLE:
        if "member_digests" not in plan:
            expected_rest = None
        elif expect == "after":
            expected_rest = plan["member_digests"]["rest_after"]
    rest_matches = rest_digest == expected_rest
    if not rest_matches and plan["platform"] == "fortios" and "policy_order" not in plan:
        # Previously journaled plans could include an empty addrgrp section in the digest.
        rest_matches = snapshot.rest_digest(profile.table, plan["key"], plan.get("safeguard_id"),
                                            include_empty_group=True, **rest_options) == expected_rest
    if not rest_matches:
        differences.append("configuration outside the planned object changed")
    return {
        "result": "match" if not differences else "mismatch",
        "object_matches": object_matches,
        "rest_matches": rest_matches,
        "expect": expect,
        "key": plan["key"],
        "plan_sha256": plan["plan_sha256"],
        "snapshot_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
        "differences": differences,
        **({"warnings": warnings} if warnings else {}),
    }


def _lag_scope(profile, before, after, expected):
    if (profile.platform, profile.table) == ("exos", exos_g44.LAG):
        old, new = exos_g44.lag_members(before), exos_g44.lag_members(after)
        return {"scope": old | new, "expected": expected, "require_default": old != new}
    return {}


def _g43_rest(snapshot, key, before, after, expect, safeguard_id=None) -> str:
    kind = exos.plan_kind(before, after)
    state = after if expect == "after" else before
    name = (state or {}).get(exos.RENAME, key) if kind == "rename" else key
    return exos.g43_rest_digest(snapshot, kind, name, exos.touched_untagged(before, after), safeguard_id)


def _preserves_exos_vlan_l3(plan, snapshot) -> bool:
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    return (plan["op"] == "update" and not snapshot.owns_vlan_l3(plan["key"])
            and not exos.touches_l3("vlan", before, after))


def _g43_verify(plan, snapshot, profile, entries, expect, snapshot_raw, kind) -> dict:
    """verify of a G43 VLAN plan: a rename looks the VLAN up by its name on the expected side and needs the other
    name absent; a port plan compares the ports of the VLAN and the native VLAN of every untagged port it moves."""
    before, after, key = plan["predicted"]["before"], plan["predicted"]["after"], plan["key"]
    wanted = plan["predicted"][expect]
    differences = []
    if kind == "rename":
        name, other = (after[exos.RENAME], before[exos.RENAME]) if expect == "after" else (before[exos.RENAME], after[exos.RENAME])
        if _find_entry(entries, other) is not None:
            differences.append("VLAN %s still exists" % other)
    else:
        name = key
    entry = _find_entry(entries, name)
    actual = None
    if entry is not None:
        actual, unsupported = _entry_state(snapshot, profile, entry)
        if kind == "rename" or _preserves_exos_vlan_l3(plan, snapshot):
            actual, unsupported = exos.without_l3(actual, unsupported, entry)
        differences.extend("object holds configuration outside the profile: %s" % item for item in unsupported)
        if kind == "rename":
            actual[exos.RENAME] = entry.name
        else:
            actual.update(exos.vlan_ports(snapshot, entry.name))
    if (actual is None) != (wanted is None):
        differences.append("object %s, expected %s"
                           % ("absent" if actual is None else "present", "absent" if wanted is None else "present"))
    elif actual is not None:
        for attribute in sorted(set(actual) | set(wanted)):
            if actual.get(attribute) != wanted.get(attribute):
                differences.append("%s: expected %r, found %r" % (attribute, wanted.get(attribute), actual.get(attribute)))
    if kind == "ports":
        differences.extend(exos.native_differences(snapshot, key, exos.touched_untagged(before, after), wanted))
    object_matches = not differences
    rest_matches = _g43_rest(snapshot, key, before, after, expect, plan.get("safeguard_id")) == plan["rest_sha256"]
    if not rest_matches:
        differences.append("configuration outside the planned object changed")
    return {
        "result": "match" if not differences else "mismatch",
        "object_matches": object_matches,
        "rest_matches": rest_matches,
        "expect": expect,
        "key": plan["key"],
        "plan_sha256": plan["plan_sha256"],
        "snapshot_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
        "differences": differences,
    }
