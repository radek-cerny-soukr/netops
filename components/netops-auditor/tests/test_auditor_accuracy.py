import json
from pathlib import Path

from netops_auditor import l1_exos, l1_fortios, management
from netops_auditor.engine import evaluate, load_catalog
from test_cli import invoke, run_args, write_config

FIXTURES = Path(__file__).parent / "fixtures" / "accuracy"
EXOS_SAMPLE = (Path(__file__).resolve().parents[2] / "netops-admin" / "tests" / "golden" / "exos" / "33.7.1.6-patch1-11"
               / "X435-8P-4S" / "show-configuration" / "X435-8P-4S__normal-redacted-secrets.conf")
GLOBAL_RULES = (
    "fortios.crypto.static-key-ciphers",
    "fortios.crypto.strong-crypto-disabled",
    "fortios.mgmt.gui-legacy-tls",
    "fortios.mgmt.idle-timeout",
    "fortios.mgmt.lockout-threshold",
)


def text(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def mutate(source, old, new):
    assert source.count(old) == 1
    return source.replace(old, new)


def audit(platform, source, policy=None):
    parser = l1_fortios if platform == "fortios" else l1_exos
    rules = tuple(r for r in load_catalog(platform) if ".management." not in r.id or policy is not None)
    return evaluate(parser.parse(source), "tenant-example", "device-example", rules, policy)


def hits(platform, source, rule_ids, policy=None):
    findings, _states = audit(platform, source, policy)
    return sorted((f.rule_id, f.object_key) for f in findings if f.rule_id in rule_ids)


def by_rule(source, rule_id):
    findings, _states = audit("fortios", source)
    return {f.object_key: dict(f.evidence) for f in findings if f.rule_id == rule_id}


def test_ipv6_allowaccess_on_wan_is_reported_with_its_origin():
    found = by_rule(text("wan-access-ipv6.conf"), "fortios.mgmt.wan-admin-access")
    assert found == {"system interface/wan1/ipv6": {"interface": "wan1", "services": "https ssh", "origin": "ipv6"}}


def test_ipv6_plaintext_access_is_reported_on_any_interface():
    found = by_rule(text("wan-access-ipv6.conf"), "fortios.mgmt.plaintext-admin-access")
    assert found == {"system interface/internal/ipv6": {"interface": "internal", "services": "http", "origin": "ipv6"}}


def test_secondary_ip_allowaccess_is_reported_with_its_origin():
    source = text("wan-access-secondary-ip.conf")
    assert by_rule(source, "fortios.mgmt.wan-admin-access") == {
        "system interface/wan1/secondaryip/1": {"interface": "wan1", "services": "https telnet", "origin": "secondary-ipv4"}}
    assert by_rule(source, "fortios.mgmt.plaintext-admin-access") == {
        "system interface/wan1/secondaryip/1": {"interface": "wan1", "services": "telnet", "origin": "secondary-ipv4"}}


def test_primary_allowaccess_keeps_its_object_key_and_names_primary_ipv4():
    source = mutate(text("wan-access-ipv6.conf"), "        set allowaccess ping\n", "        set allowaccess ping ssh\n")
    found = by_rule(source, "fortios.mgmt.wan-admin-access")
    assert found["system interface/wan1"] == {"interface": "wan1", "services": "ssh", "origin": "primary-ipv4"}


def test_lan_interface_access_stays_out_of_the_wan_rule():
    source = mutate(text("wan-access-ipv6.conf"), "set ip6-allowaccess ping https ssh", "set ip6-allowaccess ping")
    assert by_rule(source, "fortios.mgmt.wan-admin-access") == {}


def test_missing_global_section_leaves_the_global_rules_not_evaluated():
    findings, states = audit("fortios", text("no-system-global.conf"))
    for rule_id in GLOBAL_RULES:
        assert states[rule_id] == ("not-evaluated", "section-missing: system global")
    assert not [f for f in findings if f.rule_id in GLOBAL_RULES]


def test_present_global_section_without_the_line_is_still_evaluated():
    source = mutate(text("with-system-global.conf"), "    set ssl-static-key-ciphers enable\n", "")
    findings, states = audit("fortios", source)
    assert states["fortios.crypto.static-key-ciphers"] == ("evaluated", "")
    assert [dict(f.evidence) for f in findings if f.rule_id == "fortios.crypto.static-key-ciphers"] == [{"setting": "unset"}]


def test_finding_does_not_become_gone_when_the_section_is_missing(tmp_path, capsys):
    store = tmp_path / "audit.sqlite"
    first = write_config(tmp_path, text("with-system-global.conf"), name="first.conf")
    second = write_config(tmp_path, text("no-system-global.conf"), name="second.conf")
    _code, out, _err = invoke(capsys, run_args(first, as_json=True, store=store))
    report = json.loads(out)
    first_rules = {f["rule_id"] for f in report["findings"]}
    assert "fortios.crypto.static-key-ciphers" in first_rules
    assert report["evaluation_complete"] is True
    code, out, _err = invoke(capsys, run_args(second, as_json=True, store=store))
    report = json.loads(out)
    assert report["gone"] == []
    assert report["evaluation_complete"] is False
    assert code != 0
    skipped = [item["rule_id"] for item in report["not_evaluated"]]
    assert "fortios.crypto.static-key-ciphers" in skipped
    assert set(skipped) <= first_rules
    assert report["rule_status"]["fortios.crypto.static-key-ciphers"]["reason"] == "section-missing: system global"


def test_factory_all_and_none_are_outside_the_address_policy():
    policy = management.load_policy(FIXTURES / "factory-addresses-policy.json", "fortios")
    assert hits("fortios", text("factory-addresses.conf"), {"fortios.management.address-policy"}, policy) == []


def test_same_name_with_another_subnet_is_still_checked():
    policy = management.load_policy(FIXTURES / "factory-addresses-policy.json", "fortios")
    source = mutate(text("factory-addresses.conf"), "set subnet 0.0.0.0 0.0.0.0", "set subnet 203.0.113.0 255.255.255.0")
    source = mutate(source, "set subnet 0.0.0.0 255.255.255.255", "set subnet 203.0.113.9 255.255.255.255")
    assert hits("fortios", source, {"fortios.management.address-policy"}, policy) == [
        ("fortios.management.address-policy", "firewall address/all"),
        ("fortios.management.address-policy", "firewall address/none"),
    ]


def test_vip_and_vip_group_references_are_not_dangling():
    assert hits("fortios", text("vip-references.conf"), {"fortios.ref.dangling"}) == []


def test_undefined_name_next_to_a_vip_is_still_dangling():
    source = mutate(text("vip-references.conf"), 'set dstaddr "web-vip" "web-vips"', 'set dstaddr "web-vip" "web-vip-typo"')
    assert hits("fortios", source, {"fortios.ref.dangling"}) == [
        ("fortios.ref.dangling", "firewall policy/7/dstaddr/web-vip-typo")]


def test_ipv6_address_name_in_an_ipv4_reference_is_still_dangling():
    source = mutate(text("vip-references.conf"), 'set dstaddr "web-vip" "web-vips"', 'set dstaddr "web-vip" "lan6-net"')
    assert hits("fortios", source, {"fortios.ref.dangling"}) == [
        ("fortios.ref.dangling", "firewall policy/7/dstaddr/lan6-net")]


VLAN_RULES = {"exos.management.vlan-empty", "exos.management.vlan-policy"}


def test_reserved_vlans_are_recognised_in_any_letter_case():
    policy = management.load_policy(FIXTURES / "exos-reserved-vlans-policy.json", "exos")
    assert hits("exos", text("exos-reserved-vlans.conf"), VLAN_RULES, policy) == []


def test_real_exos_sample_reports_no_reserved_vlan():
    policy = management.load_policy(FIXTURES / "exos-reserved-vlans-policy.json", "exos")
    found = hits("exos", EXOS_SAMPLE.read_text(encoding="utf-8"), VLAN_RULES, policy)
    assert [key for _rule, key in found if key.casefold() in ("vlan/default", "vlan/mgmt")] == []


def test_reserved_name_with_an_explicit_tag_outside_the_policy_is_reported():
    policy = management.load_policy(FIXTURES / "exos-reserved-vlans-policy.json", "exos")
    source = text("exos-reserved-vlans.conf") + "configure vlan default tag 200\n"
    assert hits("exos", source, VLAN_RULES, policy) == [("exos.management.vlan-policy", "vlan/default")]


def test_similar_names_get_no_exception():
    policy = management.load_policy(FIXTURES / "exos-reserved-vlans-policy.json", "exos")
    source = text("exos-reserved-vlans.conf") + "create vlan Defaults\ncreate vlan MGMT2 tag 300\n"
    assert hits("exos", source, VLAN_RULES, policy) == [
        ("exos.management.vlan-empty", "vlan/Defaults"),
        ("exos.management.vlan-empty", "vlan/MGMT2"),
        ("exos.management.vlan-policy", "vlan/Defaults"),
        ("exos.management.vlan-policy", "vlan/MGMT2"),
    ]
