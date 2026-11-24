"""U6 coverage and regression tests against the registered production catalog."""

import asyncio
from contextlib import closing
import json
from pathlib import Path
import sqlite3

import pytest

from netops_auditor import cli, collect, engine, l1_junos, mcp_server
from netops_auditor.platforms import AuditContext, SectionVisibility, SnapshotMetadata
from test_channel_events_on_failure import LOGIN
from test_multiplatform_collect import DEVICE, FIXTURES, TENANT, Transport, invoke


PLATFORM = "juniper-junos"
ALIAS = "juniper_junos_els"
RULES = {rule.id.removeprefix(PLATFORM + "."): rule for rule in engine.load_catalog(PLATFORM)}
R = Path(__file__).parent / "fixtures" / "rules"
J1 = FIXTURES / "junos_26_2R1_7"
INTENTS = {
    "mgmt.access-acl": {"management_prefixes": ["198.51.100.0/24"]},
    "aaa.external-login": {"external_aaa_required": True},
    "time.ntp-auth": {"ntp_auth_required": True},
    "logging.syslog-level": {"syslog_severity": "info"},
    "services.edge-discovery": {"ports": {"ge-0/0/1": {"role": "edge", "discovery_allowed": False}}},
    "l2.bpdu-guard": {"ports": {"ge-0/0/1": {"role": "edge"}}},
    "l2.default-vlan": {"ports": {"ge-0/0/1": {"role": "edge", "default_vlan_allowed": False}}},
    "l2.trunk-native": {"ports": {"ge-0/0/1": {"role": "trunk", "native_vlan": 20}}},
    "l2.dhcp-snooping": {"dhcp_snooping_vlans": [20], "trusted_dhcp_ports": []},
    "l2.storm-control": {"ports": {"ge-0/0/1": {"role": "edge", "storm_control_required": True}}},
    "ports.unused-up": {"ports": {"ge-0/0/1": {"role": "unused"}}},
}


def fixture(short_id, form):
    return (R / RULES[short_id].id / (form + ".conf")).read_bytes()


def replay(data, expanded=None):
    answers = {} if expanded is None else {collect.JUNOS_INHERITANCE: expanded}
    transport = Transport(collect.JUNOS_CONFIG, data, answers)
    snapshot, events = transport.collect(ALIAS)
    assert snapshot.metadata.complete
    return snapshot.metadata, events


def evaluate(short_id, metadata, *, verified=False, intent=None):
    rule = RULES[short_id]
    if verified:
        # The real restricted SSH profile intentionally lacks these attestations.
        sections = {section: SectionVisibility("visible", "verified-profile")
                    for section in l1_junos.SECTIONS}
        metadata = SnapshotMetadata(ALIAS, sections, complete=True, tree=metadata.tree)
    if intent is None:
        intent = INTENTS.get(short_id, {})
    findings, states = engine.evaluate(metadata.tree, TENANT, DEVICE, [rule],
                                       context=AuditContext(intent, metadata, live=True))
    return findings, states[rule.id]


@pytest.mark.parametrize("short_id", RULES)
@pytest.mark.parametrize("form", ["positive", "negative", "not-evaluated"])
def test_rule_fixtures(short_id, form):
    metadata, _ = replay(fixture(short_id, form))
    if form == "not-evaluated":
        assert metadata.tree.hidden
        assert all(metadata.visibility(section).reason == "access-denied" for section in metadata.tree.hidden)
    hits, status = evaluate(short_id, metadata, verified=True)
    assert bool(hits) == (form == "positive")
    assert status == (("evaluated", "") if form != "not-evaluated" else ("not-evaluated", "access-denied"))


@pytest.mark.parametrize("short_id", INTENTS)
def test_missing_intent_precedes_visibility(short_id):
    metadata, _ = replay(fixture(short_id, "not-evaluated"))
    assert evaluate(short_id, metadata, intent={}) == ((), ("evaluated", ""))


@pytest.mark.parametrize("short_id", ["mgmt.lockout", "time.no-ntp-source", "logging.no-syslog-target",
                                     "logging.syslog-level", "ports.unused-up"])
def test_content_does_not_prove_absence(short_id):
    metadata, _ = replay(fixture(short_id, "positive"))
    assert evaluate(short_id, metadata) == ((), ("not-evaluated", "visibility-unproven"))


def test_reserved_mask_without_root_password_path_does_not_prove_type():
    data = b"set system services ssh root-login allow\nset system root-authentication /* SECRET-DATA */;\n"
    metadata, _ = replay(data)
    assert evaluate("aaa.default-account", metadata) == ((), ("not-evaluated", "visibility-unproven"))


def test_ip_filter_term_order_and_separate_management_path():
    rule = "mgmt.access-acl"
    config = fixture(rule, "negative")
    config += b"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24\n"
    metadata, _ = replay(config)
    hits, status = evaluate(rule, metadata, verified=True)
    assert status == ("evaluated", "")
    assert [hit.object_key for hit in hits] == ["fxp0.0/inet"]


def test_ipv6_management_filter():
    rule = "mgmt.access-acl"
    data = b"""set system services ssh
set interfaces lo0 unit 0 family inet6 address 2001:db8::1/128
set interfaces lo0 unit 0 family inet6 filter input example-mgmt
set firewall family inet6 filter example-mgmt term permit from source-address 2001:db8:1::/64
set firewall family inet6 filter example-mgmt term permit from next-header tcp
set firewall family inet6 filter example-mgmt term permit from destination-port ssh
set firewall family inet6 filter example-mgmt term permit then accept
"""
    metadata, _ = replay(data)
    intent = {"management_prefixes": ["2001:db8:1::/64"]}
    assert evaluate(rule, metadata, verified=True, intent=intent) == ((), ("evaluated", ""))


def test_capture_trunk_native_and_inheritance():
    trunk = (J1 / "show-configuration-interfaces-ge-0-0-2-display-set__junos_vlan_admin-trunk-native.txt").read_bytes()
    metadata, _ = replay(trunk)
    hits, status = evaluate("l2.trunk-native", metadata,
                            intent={"ports": {"ge-0/0/2": {"role": "trunk", "native_vlan": 20}}})
    assert status == ("evaluated", "")
    assert [hit.object_key for hit in hits] == ["ge-0/0/2"]

    group = (J1 / "show-configuration-interfaces-ge-0-0-7-display-inheritance-display-set__junos_vlan_admin-group.txt").read_bytes()
    composite = (J1 / "show-configuration-display-set__junos_vlan_admin-composite.txt").read_bytes()
    config = composite + b"set interfaces ge-0/0/7 apply-groups test-inherited\n"
    unresolved, _ = replay(config)
    resolved, events = replay(config, group)
    assert "interfaces" in unresolved.tree.inheritance
    assert resolved.tree.matching("interfaces", "ge-0/0/7", "unit", "0", "family", "ethernet-switching")
    # The snapshot, its inheritance view and the session role read (proof of the full profile).
    assert [(event.request.split(" ", 1)[1], event.outcome) for event in events] == [
        (collect.JUNOS_CONFIG, "ok"), (collect.JUNOS_INHERITANCE, "ok"), ("show cli authorization", "ok")]
    assert "interfaces" not in resolved.tree.inheritance


@pytest.mark.parametrize(("family", "rule"), [("ntp", "time.no-ntp-source"), ("syslog", "logging.no-syslog-target")])
def test_captured_system_family_readback(family, rule):
    filename = f"show-configuration-system-{family}-display-set__junos_port_ownership.txt"
    metadata, _ = replay((J1 / filename).read_bytes())
    assert evaluate(rule, metadata) == ((), ("evaluated", ""))


def test_actual_ro_mask_leaves_independent_findings_available():
    data = (FIXTURES / "junos_junos_config/config_display_set_ro.out").read_bytes()
    metadata, _ = replay(data + b"set snmp community SECRET-DATA authorization read-only\n"
                          b"set system services telnet\n")
    assert metadata.visibility("system").reason == "access-denied"
    hits, status = evaluate("mgmt.telnet-enabled", metadata)
    assert status == ("evaluated", "")
    assert [hit.object_key for hit in hits] == ["telnet"]
    assert evaluate("aaa.default-account", metadata) == ((), ("not-evaluated", "access-denied"))


def test_cli_collect_mcp_and_offline_fingerprints(tmp_path, monkeypatch, capsys):
    short_id = "snmp.v1v2c-community"
    rule_id = RULES[short_id].id
    long_canary = "ExampleJunosCanaryPhrase"
    short_canary = "~J~"
    # Neither a quoted community credential nor a short private key field may survive serialization.
    data = fixture(short_id, "positive").replace(b"example community", long_canary.encode())
    data += (b"set system root-authentication encrypted-password " + short_canary.encode() + b"\n"
             + b"set interfaces ge-0/0/1 description example\n")
    transport = Transport(collect.JUNOS_CONFIG, data)
    transport.install(monkeypatch)
    assert invoke(tmp_path, transport, ALIAS) == 3
    out, err = capsys.readouterr()
    report = json.loads(out)
    hits = [hit for hit in report["findings"] if hit["rule_id"] == rule_id]
    assert len(hits) == 1 and hits[0]["object_key"] == "communities"
    assert report["rule_status"]["juniper-junos.logging.no-syslog-target"]["status"] == "not-evaluated"

    path = tmp_path / "display-set.conf"
    path.write_bytes(data)
    args = ["run", "--platform", PLATFORM, "--device", DEVICE, "--tenant", TENANT, "--config", str(path)]
    assert cli.main([*args, "--json"]) in (0, 3)
    offline = json.loads(capsys.readouterr().out)
    assert [hit["fingerprint"] for hit in offline["findings"] if hit["rule_id"] == rule_id] == [hits[0]["fingerprint"]]
    assert cli.main([*args, "--sarif"]) in (0, 3)
    sarif = capsys.readouterr().out

    storage = tmp_path / "audit.sqlite"
    with closing(sqlite3.connect(storage)) as connection:
        assert connection.execute("SELECT count(*) FROM runs").fetchone() == (1,)
        sql = "\n".join(connection.iterdump())
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", None)
    mcp_server.configure({
        mcp_server.STORE_VARIABLE: str(storage),
        mcp_server.TENANT_VARIABLE: TENANT,
        mcp_server.CATALOG_VARIABLE: PLATFORM,
    })

    async def read_mcp():
        from fastmcp import Client

        async with Client(mcp_server.mcp) as client:
            status = await client.call_tool("audit_status", {"device": DEVICE, "platform": PLATFORM})
            findings = await client.call_tool("findings_summary", {"device": DEVICE, "platform": PLATFORM,
                                                                   "rule_id": rule_id})
            return status.content[0].text, findings.content[0].text

    status, summary = asyncio.run(read_mcp())
    assert json.loads(summary)["items"][0]["fingerprint"] == hits[0]["fingerprint"]
    assert "incomplete" in status
    for canary in (long_canary, short_canary):
        assert canary not in out + err + json.dumps(offline) + sarif + sql + status + summary


# Review regressions. The base is the J1 composite capture
# with its apply-groups lines removed, so no inheritance stays unresolved; the added
# lines are derived for each case.
COMPOSITE = J1 / "show-configuration-display-set__junos_vlan_admin-composite.txt"


def composite(*, drop=()):
    lines = COMPOSITE.read_bytes().split(b"\n")
    return b"\n".join(line for line in lines if b" apply-groups " not in line
                       and not line.startswith(b"set apply-groups ") and line not in drop)


def full_account(extra):
    """The collecting account's super-user line lets a complete snapshot prove its families."""
    return composite() + b"set system login user %s class super-user\n" % LOGIN.encode() + extra


@pytest.mark.parametrize("extra", [b"", b"set system syslog host 192.0.2.10 any notice\n"
                                   b"set system ntp server 192.0.2.123\n"], ids=["absent", "present"])
def test_offline_file_never_proves_missing_ntp_or_syslog(tmp_path, capsys, extra):
    path = tmp_path / "display-set.conf"
    path.write_bytes(composite() + extra)
    assert cli.main(["run", "--platform", PLATFORM, "--device", DEVICE, "--tenant", TENANT,
                     "--config", str(path), "--json"]) in (0, 3)
    report = json.loads(capsys.readouterr().out)
    for short_id in ("time.no-ntp-source", "logging.no-syslog-target"):
        rule_id = RULES[short_id].id
        state = report["rule_status"][rule_id]
        expected = ("evaluated", "") if extra else ("not-evaluated", "visibility-unproven")
        assert (state["status"], state["reason"]) == expected
        assert not [hit for hit in report["findings"] if hit["rule_id"] == rule_id]


@pytest.mark.parametrize(("short_id", "port", "extra"), [
    ("l2.default-vlan", "ge-0/0/9",
     b"set vlans default vlan-id 1\nset interfaces ge-0/0/9 unit 0 family ethernet-switching\n"),
    ("ports.unused-up", "ge-0/0/11",
     b"set interfaces interface-range example-unused member-range ge-0/0/10 to ge-0/0/12\n"
     b"set interfaces interface-range example-unused disable\n"
     b"set interfaces ge-0/0/11 unit 0 family ethernet-switching\n"),
], ids=["member", "member-range"])
def test_interface_range_member_is_not_evaluated(short_id, port, extra):
    metadata, _ = replay(full_account(extra))
    role = {"l2.default-vlan": {"role": "edge", "default_vlan_allowed": False}, "ports.unused-up": {"role": "unused"}}
    intent = {"ports": {port: role[short_id]}}
    hits, status = evaluate(short_id, metadata, intent=intent)
    assert hits == () and status[0] == "not-evaluated"
    assert evaluate(short_id, metadata, verified=True, intent=intent) == (
        (), ("not-evaluated", "interface-range-unproven"))
    # A port outside the range keeps its evaluation.
    other = {"ports": {"ge-0/0/1": role[short_id]}}
    hits, status = evaluate(short_id, metadata, verified=True, intent=other)
    assert status == ("evaluated", "") and len(hits) == (short_id == "ports.unused-up")


MGMT_FILTER = b"""set interfaces fxp0 unit 0 family inet filter input example-mgmt
set firewall family inet filter example-mgmt term allow from source-address 192.0.2.0/24
set firewall family inet filter example-mgmt term allow from protocol tcp
set firewall family inet filter example-mgmt term allow from destination-port ssh
set firewall family inet filter example-mgmt term allow then accept
"""
LO0 = b"set interfaces lo0 unit 0 family inet address 192.0.2.6/32"


def test_in_band_irb_without_loopback_filter_is_not_evaluated():
    intent = {"management_prefixes": ["192.0.2.0/24"]}
    data = composite(drop=(LO0,)) + b"set system login user %s class super-user\n" % LOGIN.encode() + MGMT_FILTER
    metadata, _ = replay(data)
    assert metadata.tree.matching("interfaces", "irb", "unit", "10", "family", "inet", "address")
    hits, status = evaluate("mgmt.access-acl", metadata, intent=intent)
    assert hits == () and status[0] == "not-evaluated"
    assert evaluate("mgmt.access-acl", metadata, verified=True, intent=intent) == (
        (), ("not-evaluated", "in-band-management-unproven"))
    # The same filter on lo0 covers the in-band units.
    metadata, _ = replay(full_account(MGMT_FILTER + b"set interfaces lo0 unit 0 family inet filter input example-mgmt\n"))
    assert evaluate("mgmt.access-acl", metadata, verified=True, intent=intent) == ((), ("evaluated", ""))
