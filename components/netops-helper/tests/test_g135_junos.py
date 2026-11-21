"""G135 public SSH reads over anonymized lab and Juniper CLI reference output."""
from dataclasses import replace
from pathlib import Path

import pytest

from netops_helper import engine
from netops_helper.auth import EgressPolicy, PolicyScopeError, TargetAuth
from netops_helper.query_catalog import READ_QUERIES
from netops_helper.query_catalog.junos import FILTER_BINDING_QUERY, SRX_QUERIES
from netops_helper.read_policy import render_read_query

FIXTURES = Path(__file__).parent / "fixtures"
VENDOR = FIXTURES / "docs/juniper_junos/g135"
LAB = FIXTURES / "real/juniper_junos_els/g135_vjunosswitch_26.2R1.7"
IDENTITY = FIXTURES / "real/juniper_junos_els/g132_vjunosswitch_26.2R1.7/version_ro.out"
JUNOS = "juniper_junos"
ELS = "juniper_junos_els"
SUFFIX = " | no-more"
POLICY_COUNT = 'show security policies detail | match "^[[:space:]]*Policy:" | count' + SUFFIX
FLOW = {"from_zone": "z1", "to_zone": "z2", "src": "192.0.2.1", "dst": "198.51.100.1",
        "src_port": "1", "dst_port": "21", "protocol": "6"}
INVENTORY = {"firewall_filters": ("test", "g135-no-such-filter"), "interfaces": ("lo0.0",),
             "config_access": ("read",), "security_zones": ("z1", "z2"),
             "addresses": (FLOW["src"], FLOW["dst"]), "flow_ports": ("1", "21"), "ip_protocols": ("6",),
             "lookup_prefixes": ("203.0.113.254/32", "2001:db8::/64")}


def target(profile):
    return TargetAuth(alias="lab", host="192.0.2.10", port=2256, login="fixture",
                      secret="fixture-do-not-return", ssh_platform=profile,
                      host_key_fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                      enabled_queries=tuple(READ_QUERIES[profile]), read_inventory=INVENTORY,
                      device_types=("firewall",) if profile == JUNOS else ("switch",),
                      egress=EgressPolicy(addresses=("192.0.2.10",)))


def replay(monkeypatch, command, output, profile=JUNOS, *, policy_count=(0, "Count: 2 lines\n")):
    calls = []

    def cli(auth, selected, actual, **kwargs):
        assert selected == profile
        calls.append(actual)
        if actual == "show version" + SUFFIX:
            identity = IDENTITY.read_text()
            return 0, identity if profile == ELS else identity.replace("Model: ex9214", "Model: srx345")
        if actual == POLICY_COUNT:
            return policy_count
        assert actual == command + SUFFIX
        return 0, output

    monkeypatch.setattr(engine, "_exec_read", cli)
    monkeypatch.setattr(engine, "record", lambda *a, **kw: None)
    return target(profile), calls


CASES = [
    (ELS, "firewall_filters", "show firewall", None, 4, ("filter", "ef_path")),
    (ELS, "firewall_filter", "show firewall filter test", {"filter": "test"}, 1, ("filter", "test")),
    (JUNOS, "security_policies", "show security policies detail", None, 2, ("action", "permit")),
    (JUNOS, "security_policy_hits", "show security policies hit-count", None, 3, ("hits", 40)),
    (JUNOS, "security_match_policies",
     "show security match-policies from-zone z1 to-zone z2 source-ip 192.0.2.1 destination-ip 198.51.100.1 "
     "source-port 1 destination-port 21 protocol 6", FLOW, 1, ("to_zone", "z2")),
    (JUNOS, "security_flow_sessions", "show security flow session source-prefix 203.0.113.254/32",
     {"prefix": "203.0.113.254/32"}, 1, ("translation", {})),
    (JUNOS, "security_source_nat_rules", "show security nat source rule all", None, 1, ("name", "r2")),
    (JUNOS, "security_destination_nat_rules", "show security nat destination rule all", None, 1, ("name", "r4")),
    (JUNOS, "chassis_cluster_status", "show chassis cluster status", None, 2, ("group", 0)),
    (JUNOS, "chassis_cluster_interfaces", "show chassis cluster interfaces", None, 10, ("status", "Down")),
    (JUNOS, "chassis_cluster_statistics", "show chassis cluster statistics", None, 20, ("kind", "control link")),
    (JUNOS, "ike_security_associations", "show security ike security-associations", None, 1, ("state", "up")),
    (JUNOS, "ipsec_security_associations", "show security ipsec security-associations detail", None, 1, ("name", "SPK_VPN1")),
    (JUNOS, "ipsec_statistics", "show security ipsec statistics", None, 3, ("section", "ESP Statistics")),
]


@pytest.mark.parametrize("profile,query,command,parameters,count,expected", CASES, ids=[row[1] for row in CASES])
def test_read_uses_vendor_output(monkeypatch, profile, query, command, parameters, count, expected):
    body = (VENDOR / f"{query}.out").read_text()
    auth, calls = replay(monkeypatch, command, body, profile)
    result = engine.ssh_read(auth, profile, query, parameters, 0, 16000)
    assert result["ok"] and result["status"] == "ok", result
    expected_calls = ["show version" + SUFFIX, command + SUFFIX]
    if query == "security_policies":
        expected_calls.append(POLICY_COUNT)
    assert calls == expected_calls
    parsed = result["diagnostics"]
    assert parsed["complete"] and result["normalized"]["coverage"]["complete"]
    assert len(parsed["records"]) == count
    assert parsed["records"][0][expected[0]] == expected[1]
    if profile == JUNOS:
        assert result["firmware_support"]["status"] == "untested"
        assert result["warnings"][0]["code"] == "firmware_untested"


@pytest.mark.parametrize("profile,query,command,parameters,count,expected", CASES, ids=[row[1] for row in CASES])
def test_incomplete_vendor_output(monkeypatch, profile, query, command, parameters, count, expected):
    # A fragment of the actual capture with no complete result record.
    lines = [line for line in (VENDOR / f"{query}.out").read_text().splitlines() if line.strip()]
    body = lines[0]
    if query == "security_policies":
        body = next(line for line in lines if line.startswith("Policy:"))
    if query in {"firewall_filter", "firewall_filters"}:
        body = (VENDOR / f"{query}.out").read_text().splitlines()[3]
    auth, _ = replay(monkeypatch, command, body + "\n", profile)
    result = engine.ssh_read(auth, profile, query, parameters, 0, 16000)
    assert result["status"] == "unparsed"
    assert not result["diagnostics"]["complete"]


@pytest.mark.parametrize("query,command,parameters,fixture,state", [
    ("firewall_filters", "show firewall", None, "firewall_refused", "permission_denied"),
    ("firewall_filter", "show firewall filter g135-no-such-filter", {"filter": "g135-no-such-filter"},
     "firewall_refused", "permission_denied"),
    (FILTER_BINDING_QUERY, "show configuration interfaces lo0 unit 0 family inet filter", {"interface": "lo0.0"},
     "bindings_refused", "permission_denied"),
    (FILTER_BINDING_QUERY, "show configuration interfaces lo0 unit 0 family inet filter", {"interface": "lo0.0"},
     "bindings_empty", "empty"),
])
def test_lab_refusal_and_empty_binding(monkeypatch, query, command, parameters, fixture, state):
    auth, _ = replay(monkeypatch, command, (LAB / f"{fixture}.out").read_text(), ELS)
    result = engine.ssh_read(auth, ELS, query, parameters, 0, 16000)
    assert result["status"] == state
    if state == "empty":
        assert result["diagnostics"] == {"records": [], "complete": True, "interface": "lo0.0"}
        assert result["firmware_support"]["status"] == "tested"
    else:
        assert not result["ok"]


def test_config_leaf_fails_closed_and_requires_enrollment(monkeypatch):
    command = "show configuration interfaces lo0 unit 0 family inet filter"
    auth, calls = replay(monkeypatch, command, "addresses {\n    unrelated-config;\n}\n", ELS)
    params = {"interface": "lo0.0"}
    with pytest.raises(PolicyScopeError):
        engine.ssh_read(replace(auth, read_inventory={"interfaces": ("lo0.0",)}),
                        ELS, FILTER_BINDING_QUERY, params, 0, 16000)
    assert not calls
    result = engine.ssh_read(auth, ELS, FILTER_BINDING_QUERY, params, 0, 16000)
    assert not result["ok"] and result["status"] == "unparsed"
    assert "unrelated-config" not in str(result)


def test_configured_filter_binding(monkeypatch):
    body = (VENDOR / "bindings_configured.out").read_text()
    auth, _ = replay(monkeypatch, "show configuration interfaces lo0 unit 0 family inet filter", body, ELS)
    result = engine.ssh_read(auth, ELS, FILTER_BINDING_QUERY, {"interface": "lo0.0"}, 0, 16000)
    assert result["status"] == "ok"
    assert result["diagnostics"]["records"] == [{"filter": "f_term", "direction": "input", "inactive": False}]


def test_source_nat_in_session(monkeypatch):
    body = (VENDOR / "security_flow_translated.out").read_text()
    auth, _ = replay(monkeypatch, "show security flow session source-prefix 192.0.2.11/32", body)
    auth = replace(auth, read_inventory={"lookup_prefixes": ("192.0.2.11/32",)})
    result = engine.ssh_read(auth, JUNOS, "security_flow_sessions", {"prefix": "192.0.2.11/32"}, 0, 16000)
    assert result["status"] == "ok"
    row, = result["diagnostics"]["records"]
    assert row["original"]["src"] == "192.0.2.11"
    assert row["translation"] == {"src": {"address": "203.0.113.145", "port": 8983}}


def test_query_scopes():
    assert not SRX_QUERIES.keys() & READ_QUERIES[ELS].keys()
    assert all(query.group == "firewall" for query in SRX_QUERIES.values())
    for query, params in [
        ("firewall_filter", {"filter": "regex"}),
        ("firewall_filter", {"filter": "test | count"}),
        (FILTER_BINDING_QUERY, {"interface": "lo0.1"}),
        ("security_match_policies", {**FLOW, "from_zone": "any"}),
        ("security_match_policies", {**FLOW, "protocol": "256"}),
        ("security_flow_sessions", {"prefix": "203.0.113.0/24"}),
    ]:
        with pytest.raises(ValueError):
            render_read_query(JUNOS, query, params, INVENTORY)
    assert render_read_query(JUNOS, "security_flow_sessions", {"prefix": "2001:db8::/64"}, INVENTORY)[1] == (
        "show security flow session source-prefix 2001:db8::/64" + SUFFIX
    )


def test_ipsec_key_fields_are_removed_before_cache_or_page(monkeypatch):
    body = (VENDOR / "ipsec_security_associations.out").read_text()
    body += "    Authentication key: example-sensitive-data here\n"
    auth, _ = replay(monkeypatch, "show security ipsec security-associations detail", body)
    result = engine.ssh_read(auth, JUNOS, "ipsec_security_associations", None, 0, 16000)
    assert result["diagnostics"]["complete"]
    assert "example-sensitive-data" not in str(result)
    assert "Authentication key: <REDACTED>" in result["untrusted_device_output"]


# Review 492-rv finding 1: every Sample Output of the Juniper `show security policies hit-count` reference page,
# byte for byte (see fixtures/docs/juniper_junos/g135_hit_count/PROVENANCE.md), read through engine.ssh_read
# with only the SSH transport replaced.
HIT_COUNT = FIXTURES / "docs/juniper_junos/g135_hit_count"
HIT_COUNT_COMMAND = "show security policies hit-count"
HIT_COUNT_CASES = {
    "default": [(1, "policy1", 40, None, None), (2, "policy2", 20, None, None), (3, "policy3", 80, None, None)],
    "ascending": [(2, "policy2", 20, None, None), (1, "policy1", 40, None, None), (3, "policy3", 80, None, None)],
    "descending_range": [(2, "policy2", 100, None, None), (1, "policy1", 90, None, None),
                         (3, "policy3", 80, None, None)],
    "zone_pair": [(2, "policy2", 20, None, None), (3, "policy3", 80, None, None)],
    "logical_system": [(1, "policy1", 5202, "Permit", None)],
    "detail_redirect": [(1, "policy1", 5202, "Permit", 0), (2, "policy2", 5202, "Reject", 3)],
    "detail_url_categories": [(1, "policy1", 5202, "Permit", 0)],
    "detail_dynamic_applications": [(1, "policy1", 5202, "Permit", 0)],
}


def hit_count_read(monkeypatch, body):
    auth, calls = replay(monkeypatch, HIT_COUNT_COMMAND, body)
    result = engine.ssh_read(auth, JUNOS, "security_policy_hits", None, 0, 16000)
    assert calls == ["show version" + SUFFIX, HIT_COUNT_COMMAND + SUFFIX]
    return result


def test_hit_count_provenance_matches_fixtures():
    import hashlib
    provenance = (HIT_COUNT / "PROVENANCE.md").read_text()
    assert "show-security-policies-hit-count.html" in provenance and "J-C7B534872022" in provenance
    for name in HIT_COUNT_CASES:
        digest = hashlib.sha256((HIT_COUNT / f"{name}.out").read_bytes()).hexdigest()
        assert f"| `{name}.out` |" in provenance and digest in provenance, name


@pytest.mark.parametrize("name", HIT_COUNT_CASES)
def test_hit_count_documented_layouts(monkeypatch, name):
    result = hit_count_read(monkeypatch, (HIT_COUNT / f"{name}.out").read_text())
    assert result["ok"] and result["status"] == "ok", result
    parsed = result["diagnostics"]
    assert parsed["complete"] and result["normalized"]["coverage"]["complete"]
    assert [(row["index"], row["name"], row["hits"], row["action"], row["redirect"])
            for row in parsed["records"]] == HIT_COUNT_CASES[name]
    new_layout = HIT_COUNT_CASES[name][0][3] is not None
    for row in parsed["records"]:
        assert row["logical_system"] == ("root-logical-system" if new_layout else None)
        assert (row["from_zone"], row["to_zone"]) in {("junos-global", "junos-global"), ("untrust", "trust"),
                                                      ("untrust", "vrtrust")}
    if name == "detail_url_categories":
        assert parsed["records"][0]["url_categories"] == [
            {"name": "Enhanced_Information_Technology", "count": 1000},
            {"name": "Enhanced_Collaboration_Office", "count": 2000}]
    if name == "detail_dynamic_applications":
        assert parsed["records"][0]["dynamic_applications"] == [
            {"name": "Junos:SSH", "count": 2234}, {"name": "Junos:HTTP", "count": 2502},
            {"name": "Junos:TWITTER", "count": 529}]


def hit_count_variant(name, old, new):
    text = (HIT_COUNT / f"{name}.out").read_text()
    assert old in text
    return text.replace(old, new, 1)


@pytest.mark.parametrize("body", [
    # Classic table without its footer: possibly cut off.
    pytest.param(hit_count_variant("default", "Number of policy: 3", ""), id="classic-no-footer"),
    pytest.param(hit_count_variant("default", "Number of policy: 3", "Number of policy: 4"), id="classic-footer-mismatch"),
    # 21.2+ table: a row without all heading columns (cut off before Action).
    pytest.param(hit_count_variant("detail_redirect", "Reject    3", ""), id="new-row-cut"),
    pytest.param(hit_count_variant("logical_system", "Permit    \n", "Permit\nunexpected trailer line\n"),
                 id="new-unknown-line"),
    pytest.param(hit_count_variant("logical_system", "Permit    \n", "Permit\n\nNumber of policy: 2\n"),
                 id="new-footer-mismatch"),
    pytest.param(hit_count_variant("detail_redirect", "2      junos-global", "1      junos-global"),
                 id="new-duplicate-index"),
    pytest.param("Logical system: root-logical-system\n", id="new-heading-missing"),
    pytest.param(hit_count_variant("detail_dynamic_applications", "Junos:SSH         2234", "Junos:SSH  many"),
                 id="detail-unknown-row"),
    pytest.param(hit_count_variant("detail_url_categories", "Name                                  Count\n", ""),
                 id="detail-heading-missing"),
])
def test_hit_count_unknown_or_cut_output_is_unparsed(monkeypatch, body):
    result = hit_count_read(monkeypatch, body)
    assert result["status"] == "unparsed", result
    assert not result["diagnostics"]["complete"] and not result["normalized"]["coverage"]["complete"]
    assert "incomplete_output" in result["normalized"]["warnings"]


def test_hit_count_footer_still_checked_on_new_layout(monkeypatch):
    body = (HIT_COUNT / "detail_redirect.out").read_text() + "\nNumber of policy: 2\n"
    result = hit_count_read(monkeypatch, body)
    assert result["status"] == "ok" and result["diagnostics"]["complete"]
    assert len(result["diagnostics"]["records"]) == 2


@pytest.mark.parametrize("count_response", [(0, "Count: 2 lines\n"), (1, "error: permission denied\n")])
def test_srx_policy_coverage_is_unverified_when_a_record_or_the_count_is_missing(monkeypatch, count_response):
    # Juniper's example contains two complete policies. Keep one complete record.
    body = (VENDOR / "security_policies.out").read_text().split("Policy: p2", 1)[0]
    auth, calls = replay(monkeypatch, "show security policies detail", body, policy_count=count_response)
    result = engine.ssh_read(auth, JUNOS, "security_policies", None, 0, 16000)
    assert result["ok"] and result["status"] == "unparsed"
    assert not result["diagnostics"]["complete"]
    assert len(result["diagnostics"]["records"]) == 1
    assert not result["normalized"]["coverage"]["complete"]
    assert calls[-1] == POLICY_COUNT
