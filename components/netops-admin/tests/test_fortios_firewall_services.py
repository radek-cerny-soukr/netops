"""FIREWALL-SERVICES through Admin preview/apply/undo with the captured FortiOS 7.6.8 replies."""
from pathlib import Path

import pytest

from fake_fortios import DeviceRefused, quoted
from netops_admin import engine, execute, fortios, profiles
from netops_admin.config import _device
from netops_admin.errors import Rejected
from test_execute import make_runtime, request
from test_firewall_policy import FakeFortiOS

FIXTURES = Path(__file__).parent / "fixtures" / "fortios_7_6_8_firewall_services"
VIP, POOL, POLICY = "firewall vip", "firewall ippool", "firewall policy"
VIP_KEY, POOL_KEY, POLICY_ID = "netops-firewall-services-679-vip", "netops-firewall-services-679-pool", "230679"
SUPPORTED = {
    "antivirus profile": "default", "webfilter profile": "default", "ips sensor": "default",
    "application list": "default", "dnsfilter profile": "default", "firewall ssl-ssh-profile": "certificate-inspection",
}
BASE_POLICY = {
    "name": "netops-firewall-services-679", "action": "accept", "status": "disable", "srcintf": ["host01"],
    "dstintf": ["host01"], "srcaddr": ["all"], "dstaddr": [VIP_KEY], "schedule": "always",
    "service": ["ALL_TCP"], "logtraffic": "all",
}


def capture(label):
    return (FIXTURES / f"{label}.txt").read_text()


def measured(label, table, key):
    node = fortios.parse_snapshot(capture(label)).section(table).entries[key]
    return {name: attr.value() for name, attr in node.attrs.items()}


class LabCLI(FakeFortiOS):
    def __init__(self):
        super().__init__()
        self.interfaces.append("host01")
        self.services["ALL_TCP"] = {}
        self.aliases = {VIP: (VIP_KEY, "vip"), POOL: (POOL_KEY, "pool")}
        self.tables = {VIP: {}, POOL: {}}
        self.override = {}
        self.policy_hidden.update(nat="disable", ippool="disable", **{"utm-status": "disable"})
        self.snapshot_extra.extend(
            line for section, name in SUPPORTED.items()
            for line in ("config " + section, "    edit " + quoted(name), "    next", "end")
        )
        self.snapshot_extra.extend(("config user group", '    edit "Guest-group"', "    next", "end",
                                    "config user local", '    edit "guest"', "    next", "end"))

    def _run(self, lines, automatic=False):
        table = lines[0].strip().removeprefix("config ")
        if table not in self.tables:
            return super()._run(lines, automatic)
        target = self.tables[table]
        key = None
        for number, line in enumerate(lines, 1):
            words = fortios.l1_fortios.tokenize(line.strip())
            action = words[0]
            if action == "edit":
                key = words[1]
                target.setdefault(key, {"uuid": self._uuid()} if table == VIP else {})
            elif action == "set":
                field, value = words[1:]
                if field in ("extport", "mappedport", "protocol") and target[key].get("portforward") != "enable":
                    raise DeviceRefused(number - 1)
                target[key][field] = value
            elif action == "unset":
                target[key].pop(words[1], None)
            elif action == "delete":
                target.pop(words[1])
        return len(lines)

    def _show(self, table, key, fields):
        fixture_key, label = self.aliases[table]
        facts = dict(fields)
        sample = measured(label, table, fixture_key)
        if facts.get("protocol") == "tcp":
            facts.pop("protocol")
        comparable = {**facts, **({"uuid": sample["uuid"]} if "uuid" in sample else {})}
        if key == fixture_key and comparable == sample:
            text = capture(label)
            return text.replace(sample["uuid"], fields["uuid"]) if "uuid" in sample else text
        attrs = [f"        set {name} {quoted(value)}" for name, value in facts.items()
                 if (name, value) not in {("arp-reply", "enable"), ("protocol", "tcp"), ("portforward", "disable")}]
        return "\n".join(["config " + table, "    edit " + quoted(key), *attrs, "    next", "end", ""])

    def snapshot(self):
        base = super().snapshot()
        return base + "".join(
            self._show(table, key, fields) for table, rows in self.tables.items() for key, fields in rows.items()
        )

    def check_query_status(self, command):
        if command in self.override:
            return self.override[command]
        text = self.check_query(command)
        return int("entry is not found in table" in text), text

    def check_query(self, command):
        if command.startswith("show firewall internet-service-name "):
            name = fortios.l1_fortios.tokenize(command)[-1]
            return capture("internet-service") if name == "Google-Gmail" else capture("policy-absent")
        for table in self.tables:
            if command.startswith("show " + table + " "):
                key = fortios.l1_fortios.tokenize(command)[-1]
                row = self.tables[table].get(key)
                return capture(self.aliases[table][1] + "-absent") if row is None else self._show(table, key, row)
        if command == f'show {POLICY} "{POLICY_ID}"':
            if POLICY_ID not in self.policies:
                return capture("policy-absent")
            actual = {name: value for name, value in self.policies[POLICY_ID].items() if name != "uuid"}
            for label in ("policy", "policy-ipv6", "policy-internet"):
                expected = measured(label, POLICY, POLICY_ID)
                if actual == {name: value for name, value in expected.items() if name != "uuid"}:
                    return capture(label).replace(expected["uuid"], self.policies[POLICY_ID]["uuid"])
        return super().check_query(command)


def runtime(tmp_path, device, **kwargs):
    kwargs.setdefault("protected", {"interface": ["wan1"]})
    kwargs.setdefault("opt_in", (VIP, POOL, POLICY))
    return make_runtime(tmp_path, device, **kwargs)


def ask(label, table, key, op, changes, *, impact=False):
    return request(table=table, key=key, op=op, changes=changes, request_id=label,
                   **({"endpoint_impact": key} if impact else {}))


def approved(rt, device, req):
    original, writes = device.snapshot(), len(device.applied_blocks)
    preview = execute.preview(rt, "lab", req)
    assert preview["result"] == "ready", preview
    assert device.snapshot() == original and len(device.applied_blocks) == writes
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    return record


def undo(rt, device, record):
    original, writes = device.snapshot(), len(device.applied_blocks)
    reason = "restore measured lab snapshot"
    preview = execute.preview_undo(rt, record["change_id"], reason, issue=True)
    assert preview["result"] == "ready", preview
    assert device.snapshot() == original and len(device.applied_blocks) == writes
    restored = execute.undo(rt, record["change_id"], reason, preview["plan_sha256"])
    assert restored["result"] == "confirmed", restored
    return restored


@pytest.mark.parametrize(("table", "key", "label"), [(VIP, VIP_KEY, "vip"), (POOL, POOL_KEY, "pool")])
def test_nat_object_roundtrip_requires_approved_preview(tmp_path, table, key, label):
    device = LabCLI()
    rt = runtime(tmp_path, device)
    original = device.snapshot()
    values = measured(label, table, key)
    values.pop("uuid", None)
    req = ask(f"firewall-services-add-{label}", table, key, "create", values)
    with pytest.raises(Rejected) as rejected:
        execute.apply(rt, "lab", req)
    assert rejected.value.reason_codes == ["fortios_nat_preview_required"]
    assert device.applied_blocks == []
    record = approved(rt, device, req)
    assert record["plan"]["predicted"]["after"] == values
    assert f'config {table}' in record["plan"]["commands"]
    changed = approved(rt, device, ask(f"firewall-services-update-{label}", table, key, "update",
                                      {"comment" if table == VIP else "comments": "lab note"}))
    undo(rt, device, changed)
    undo(rt, device, record)
    assert device.snapshot() == original and not (device.actions or device.triggers or device.stitches)


@pytest.mark.parametrize("failure", ["truncated", "denied", "absence-prefix", "timeout"])
def test_nat_preflight_does_not_treat_unreadable_as_absence(tmp_path, failure):
    device = LabCLI()
    rt = runtime(tmp_path, device)
    query = f'show {VIP} "{VIP_KEY}"'
    replies = {
        "truncated": (0, capture("vip").rsplit("end", 1)[0]),
        "denied": (1, (FIXTURES.parent / "fortios_7_6_8_firewall_cleanup" / "execute-refused.txt").read_text()),
        "absence-prefix": (1, capture("vip-absent") + "Unknown action 0\n"),
    }
    if failure == "timeout":
        device.check_query_status = lambda _: (_ for _ in ()).throw(TimeoutError())
    else:
        device.override[query] = replies[failure]
    values = measured("vip", VIP, VIP_KEY)
    values.pop("uuid")
    preview = execute.preview(rt, "lab", ask("firewall-services-preflight", VIP, VIP_KEY, "create", values))
    assert preview["result"] == "rejected", preview
    assert preview["reason_codes"] == [f"fortios_nat_read_{'timeout' if failure == 'timeout' else 'unreadable'}"]
    assert device.applied_blocks == []


def test_nat_protected_interface_and_arp_impact(tmp_path):
    device = LabCLI()
    rt = runtime(tmp_path, device)
    values = measured("vip", VIP, VIP_KEY)
    values.pop("uuid")
    protected = ask("firewall-services-protected", VIP, VIP_KEY, "create", {**values, "extintf": "wan1"})
    assert execute.preview(rt, "lab", protected)["reason_codes"] == ["fortios_nat_protected"]
    values.pop("arp-reply")
    missing = ask("firewall-services-no-impact", VIP, VIP_KEY, "create", values)
    assert execute.preview(rt, "lab", missing)["reason_codes"] == ["fortios_nat_impact_required"]
    approved_req = ask("firewall-services-with-impact", VIP, VIP_KEY, "create", values, impact=True)
    record = approved(rt, device, approved_req)
    assert record["plan"]["endpoint_impact"] == VIP_KEY
    undo(rt, device, record)


def test_nat_profile_configuration_requires_protected_interface():
    definition = {"platform": "fortios", "address": "192.0.2.1", "port": 22, "vault": "/x",
                  "host_key_fingerprint": "SHA256:" + "A" * 43, "credential": "rw",
                  "check_credential": "ro", "opt_in": [VIP, POOL]}
    with pytest.raises(Rejected, match="protected system interface"):
        _device("firewall-services-lab", definition)
    assert _device("firewall-services-lab", {**definition, "protected": {"interface": ["wan1"]}}).opt_in == (VIP, POOL)


def seed_nat(device):
    device.tables[VIP][VIP_KEY] = measured("vip", VIP, VIP_KEY)
    device.tables[POOL][POOL_KEY] = measured("pool", POOL, POOL_KEY)


def test_policy_uses_measured_nat_and_security_profiles_and_reverses_update(tmp_path):
    device = LabCLI()
    seed_nat(device)
    rt = runtime(tmp_path, device)
    original = device.snapshot()
    created = approved(rt, device, ask("firewall-services-initial-policy", POLICY, POLICY_ID, "create", BASE_POLICY))
    recorded = measured("policy", POLICY, POLICY_ID)
    changes = {name: value for name, value in recorded.items() if name in fortios.G23_POLICY_FIELDS | {"nat", "utm-status"}}
    changes["poolname"] = [changes["poolname"]]
    req = ask("firewall-services-policy-profile-change", POLICY, POLICY_ID, "update", changes)
    updated = approved(rt, device, req)
    commands = [line.strip().split()[1] for line in updated["plan"]["commands"] if line.strip().startswith("set ")]
    assert commands.index("nat") < commands.index("ippool") < commands.index("poolname")
    assert commands.index("utm-status") < commands.index("av-profile")
    assert engine.observed_state(updated["plan"], fortios.shown_object(capture("policy"), POLICY, POLICY_ID)) == (
        updated["plan"]["predicted"]["after"]
    )
    undone = undo(rt, device, updated)
    inverse = [line.strip() for line in undone["plan"]["commands"]]
    assert inverse.index("unset poolname") < inverse.index("unset ippool") < inverse.index("unset nat")
    assert inverse.index("unset av-profile") < inverse.index("unset utm-status")
    undo(rt, device, created)
    assert device.snapshot() == original


def test_policy_explicit_disables_remove_dependent_settings_first(tmp_path):
    device = LabCLI()
    seed_nat(device)
    device.policies[POLICY_ID] = measured("policy", POLICY, POLICY_ID)
    rt = runtime(tmp_path, device)
    fields = {name: None for name in fortios.POLICY_PROFILES}
    fields.update({"ippool": "disable", "poolname": None, "nat": "disable", "utm-status": "disable"})
    req = ask("firewall-services-disable-profile-contexts", POLICY, POLICY_ID, "update", fields)
    changed = approved(rt, device, req)
    commands = [line.strip() for line in changed["plan"]["commands"]]
    assert commands.index("unset poolname") < commands.index("unset ippool") < commands.index("unset nat")
    assert commands.index("unset ssl-ssh-profile") < commands.index("unset utm-status")
    undo(rt, device, changed)
    assert engine.verify(changed["plan"], device.snapshot().encode(), expect="before")["result"] == "match"


def test_policy_vip_group_is_destination_only_and_impact_is_required(tmp_path):
    device = LabCLI()
    seed_nat(device)
    group = "example-vip-group"
    # Fortinet's VIP-group example uses an explicit interface and member list; see PROVENANCE.
    device.snapshot_extra.extend(["config firewall vipgrp", f'    edit "{group}"', '        set interface "host01"',
                                  f'        set member "{VIP_KEY}"', "    next", "end"])
    rt = runtime(tmp_path, device)
    changes = {**BASE_POLICY, "dstaddr": [group], "status": "enable"}
    req = ask("firewall-services-group-need-impact", POLICY, POLICY_ID, "create", changes)
    assert execute.preview(rt, "lab", req)["reason_codes"] == ["fortios_policy_impact_required"]
    req = ask("firewall-services-group-active", POLICY, POLICY_ID, "create", changes, impact=True)
    preview = execute.preview(rt, "lab", req)
    assert preview["firmware_support"]["status"] == "untested"
    assert preview["firmware_support"]["tested_versions"] == []
    created = approved(rt, device, req)
    cmd = [line.strip() for line in created["plan"]["commands"]]
    assert cmd.index('set srcintf "host01"') < cmd.index(f'set dstaddr "{group}"')
    assert created["plan"]["predicted"]["after"]["dstaddr"] == group
    undo(rt, device, created)
    invalid = ask("firewall-services-group-source", POLICY, POLICY_ID, "create", {**BASE_POLICY, "srcaddr": [group]})
    assert execute.preview(rt, "lab", invalid)["result"] == "rejected"


@pytest.mark.parametrize("changes", [
    {"ippool": "enable", "poolname": [POOL_KEY]},
    {"nat": "enable", "poolname": [POOL_KEY]},
    {"utm-status": "enable", "av-profile": "profile-not-found"},
    {"dnsfilter-profile": "default"},
    {"srcaddr6": ["all"]},
    {"internet-service": "enable", "internet-service-name": ["Google-Gmail"]},
    {"dstaddr": ["missing-vip"]},
])
def test_inconsistent_policy_is_refused_without_writes(tmp_path, changes):
    device = LabCLI()
    seed_nat(device)
    rt = runtime(tmp_path, device)
    req = ask("firewall-services-inconsistent", POLICY, POLICY_ID, "create", {**BASE_POLICY, **changes})
    assert execute.preview(rt, "lab", req)["result"] == "rejected"
    assert device.applied_blocks == []


def test_untested_nat_firmware_warns_and_retains_webhook_inverse():
    device = LabCLI()
    device.firmware = ("8.0.3", "0300")
    values = measured("vip", VIP, VIP_KEY)
    values.pop("uuid")
    req = ask("firewall-services-untested", VIP, VIP_KEY, "create", values)
    plan = engine.build_plan("fortios", device.snapshot().encode(), req)
    assert plan["firmware_support"]["status"] == "untested"
    profile = profiles.find_profile("fortios", VIP, plan["firmware"])
    result = fortios.rest_inverse(
        profile, "create", VIP_KEY, plan["inverse"], "https://192.0.2.1"
    )
    assert result == {"method": "delete", "uri": f"https://192.0.2.1/api/v2/cmdb/firewall/vip/{VIP_KEY}", "body": ""}
    inverse = fortios.render_create(profile, VIP_KEY, values)
    result = fortios.rest_inverse(profile, "delete", VIP_KEY, inverse, "https://192.0.2.1")
    assert '"mappedip":[{"range":"192.0.2.20"}]' in result["body"]
    assert '"extport":"43679"' in result["body"]


@pytest.mark.parametrize("label", ["policy-ipv6", "policy-internet"])
def test_policy_selector_modes_match_lab_cli_and_restore_ipv4(tmp_path, label):
    device = LabCLI()
    seed_nat(device)
    rt = runtime(tmp_path, device)
    original = approved(rt, device, ask("firewall-services-ipv4", POLICY, POLICY_ID, "create", BASE_POLICY))
    profile = profiles.find_profile("fortios", POLICY, "7.6.8 build3744")
    observed = measured(label, POLICY, POLICY_ID)
    changes = {name: None for name in ("srcaddr", "dstaddr", "service") if name not in observed}
    for name in fortios.POLICY_MATCH_FIELDS | {"groups", "users"}:
        if name in observed:
            field = profile.attributes[name]
            value = observed[name]
            changes[name] = fortios.list_items(field, value, "fortios") if field.type == "name-list" else value
    changed = approved(rt, device, ask("firewall-services-selectors", POLICY, POLICY_ID, "update", changes))
    assert engine.observed_state(changed["plan"], fortios.shown_object(capture(label), POLICY, POLICY_ID)) == (
        changed["plan"]["predicted"]["after"]
    )
    undo(rt, device, changed)
    assert engine.verify(changed["plan"], device.snapshot().encode(), expect="before")["result"] == "match"
    undo(rt, device, original)


def test_builtin_internet_service_has_to_exist_on_target(tmp_path):
    device = LabCLI()
    rt = runtime(tmp_path, device)
    ipv4_fields = set(BASE_POLICY) - {"dstaddr", "service"}
    changes = {name: BASE_POLICY[name] for name in ipv4_fields}
    changes.update({"internet-service": "enable", "internet-service-name": ["No-such-service"]})
    req = ask("firewall-services-missing-isdb", POLICY, POLICY_ID, "create", changes)
    preview = execute.preview(rt, "lab", req)
    assert preview["reason_codes"] == ["fortios_policy_internet_service_missing"]
    assert not device.applied_blocks


class ManagementAddressLab(LabCLI):
    def snapshot(self):
        text = super().snapshot()
        text = text.replace('    edit "wan1"\n    next', '''    edit "wan1"
        set ip 192.0.2.10 255.255.255.0
        set secondary-IP enable
        config secondaryip
            edit 1
                set ip 192.0.2.11 255.255.255.0
            next
        end
    next''', 1)
        return text.replace('    edit "port2"\n    next', '''    edit "port2"
        set ip 198.51.100.10 255.255.255.0
        set allowaccess ssh
        set secondary-IP enable
        config secondaryip
            edit 1
                set ip 198.51.100.11 255.255.255.0
            next
        end
    next''', 1)


@pytest.mark.parametrize("mapped", ["192.0.2.11", "198.51.100.10", "198.51.100.11"])
def test_vip_refuses_every_management_ipv4_address(tmp_path, mapped):
    device = ManagementAddressLab()
    values = measured("vip", VIP, VIP_KEY)
    values.pop("uuid")
    req = ask("firewall-services-management-ip", VIP, VIP_KEY, "create", {**values, "mappedip": mapped})
    preview = execute.preview(runtime(tmp_path, device), "lab", req)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_nat_protected"], preview
    assert not device.applied_blocks


@pytest.mark.parametrize(("group", "mapped"), [(False, "192.0.2.11"), (True, "198.51.100.9-198.51.100.11")])
def test_policy_refuses_management_ipv4_in_existing_vip(tmp_path, group, mapped):
    device = ManagementAddressLab()
    device.tables[VIP][VIP_KEY] = {**measured("vip", VIP, VIP_KEY), "mappedip": mapped}
    destination = VIP_KEY
    if group:
        destination = "netops-firewall-services-vip-group"
        device.snapshot_extra.extend(("config firewall vipgrp", f'    edit "{destination}"',
                                      '        set interface "host01"', f'        set member "{VIP_KEY}"',
                                      "    next", "end"))
    req = ask("firewall-services-policy-management-vip", POLICY, POLICY_ID, "create", {**BASE_POLICY, "dstaddr": [destination]})
    preview = execute.preview(runtime(tmp_path, device), "lab", req)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_nat_protected"], preview
    assert not device.applied_blocks
