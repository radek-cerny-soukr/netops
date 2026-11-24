"""NX-OS catalog checks and read-only SSH-to-MCP replay."""
import asyncio
from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3

from fastmcp import Client
import pytest

from netops_auditor import cli, collect, engine, l1_cli, mcp_server, platforms
from netops_auditor.management import validate_intent
from test_multiplatform_collect import DEVICE, FIXTURES, TENANT, Transport, invoke, payload


CATALOG = "cisco-nxos"
ALIAS = "cisco_nxos"
RULES = {rule.id.removeprefix(CATALOG + "."): rule for rule in engine.load_catalog(CATALOG)}
FIXTURE_RULES = Path(__file__).parent / "fixtures" / "rules"
BASE = "version 9.3(12) Bios:version\nhostname example\ninterface mgmt0\n  description sample\n"
PORT = "Ethernet1/1"
EDGE = {PORT: {"role": "edge"}}
INTENT = {
    "mgmt.access-acl": {"management_prefixes": ["192.0.2.0/24"]},
    "aaa.external-login": {"external_aaa_required": True},
    "time.ntp-auth": {"ntp_auth_required": True},
    "logging.syslog-level": {"syslog_severity": "info"},
    "services.edge-discovery": {"ports": {PORT: {"role": "edge", "discovery_allowed": False}}},
    "l2.bpdu-guard": {"ports": EDGE},
    "l2.default-vlan": {"ports": {PORT: {"role": "edge", "default_vlan_allowed": False}}},
    "l2.trunk-native": {"ports": {PORT: {"role": "trunk", "native_vlan": 20}}},
    "l2.dhcp-snooping": {"dhcp_snooping_vlans": [20], "trusted_dhcp_ports": [PORT]},
    "l2.storm-control": {"ports": {PORT: {"role": "edge", "storm_control_required": True}}},
    "ports.unused-up": {"ports": {PORT: {"role": "unused"}}},
}
FULL = {
    "aaa.external-login": ("aaa",),
    "mgmt.access-acl": ("line vty", "ip access-list"),
    "time.no-ntp-source": ("ntp",),
    "logging.no-syslog-target": ("logging",),
    "l2.bpdu-guard": ("interface",),
    "l2.default-vlan": ("interface", "global"),
    "l2.trunk-native": ("interface",),
    "l2.dhcp-snooping": ("interface",),
    "l2.storm-control": ("interface",),
    "mgmt.telnet-enabled": ("feature",),
    "ports.unused-up": ("interface", "global"),
    "snmp.v1v2c-community": ("snmp",),
    "snmp.v3-auth-priv": ("snmp",),
}


def audit(name, body, *, intent=None, full=(), answers=None):
    transport = Transport(collect.RUNNING, body, answers)
    snapshot, _ = transport.collect(ALIAS)
    proven = dict.fromkeys(full, platforms.SectionVisibility(platforms.VISIBLE, "verified-profile"))
    metadata = replace(snapshot.metadata, sections={**snapshot.metadata.sections, **proven})
    policy = validate_intent(INTENT.get(name, {}) if intent is None else intent, CATALOG)
    rule = RULES[name]
    hits, states = engine.evaluate(metadata.tree, TENANT, DEVICE, (rule,),
                                   context=platforms.AuditContext(policy, metadata, True))
    return hits, states[rule.id]


def replay(name, text, **kwargs):
    return audit(name, ("!Command: show running-config\n" + BASE + text).encode(), **kwargs)


@pytest.mark.parametrize("name", sorted(RULES))
@pytest.mark.parametrize("case,wanted,verdict", [
    ("positive", engine.EVALUATED, True),
    ("negative", engine.EVALUATED, False),
    ("not-evaluated", engine.NOT_EVALUATED, False),
])
def test_rule_fixture(name, case, wanted, verdict):
    body = (FIXTURE_RULES / RULES[name].id / (case + ".conf")).read_bytes()
    full = FULL.get(name, ()) if case != "not-evaluated" else ()
    hits, (state, reason) = audit(name, body, full=full)
    assert (state, bool(hits)) == (wanted, verdict)
    assert bool(reason) == (wanted == engine.NOT_EVALUATED)


@pytest.mark.parametrize("name", sorted(INTENT))
def test_no_intent_never_requires_visibility(name):
    body = (FIXTURE_RULES / RULES[name].id / "positive.conf").read_bytes()
    assert audit(name, body, intent={}) == ((), (engine.EVALUATED, ""))


def test_unverified_config_keeps_l2_direct_finding_and_does_not_close_other_ports():
    name = "l2.bpdu-guard"
    hits, state = replay(name, "interface Ethernet1/1\n  spanning-tree bpduguard disable\n"
                               "interface Ethernet1/2\n  spanning-tree port type edge\n",
                         intent={"ports": {**EDGE, "Ethernet1/2": {"role": "edge"}}})
    assert [hit.object_key for hit in hits] == [PORT]
    assert state == (engine.NOT_EVALUATED, "visibility-unproven")


def test_ipv6_acl_sequence_deny_before_permit_and_direction():
    name = "mgmt.access-acl"
    body = ("line vty\n  ipv6 access-class EXAMPLE in\n  ipv6 access-class OTHER out\n"
            "ipv6 access-list EXAMPLE\n  30 deny ipv6 any any\n  10 permit ipv6 2001:db8::/32 any\n")
    intent = {"management_prefixes": ["2001:db8::/32"]}
    assert replay(name, body, intent=intent, full=("ipv6 access-list",)) == ((), (engine.EVALUATED, ""))
    assert replay(name, body, intent=intent)[1][0] == engine.NOT_EVALUATED


def test_implicit_http_uses_actual_listener_and_https_is_distinct():
    name = "mgmt.http-enabled"
    body = "feature nxapi\n"
    answers = {"show nxapi": b"NX-API is enabled\nHTTP Listen on port 80\nHTTPS Listen on port 443\n"}
    hits, state = replay(name, body, answers=answers)
    assert dict(hits[0].evidence) == {"port": 80}
    assert state == (engine.EVALUATED, "")
    answers["show nxapi"] = b"NX-API http server is disabled\nHTTPS Listen on port 443\n"
    assert replay(name, body, answers=answers) == ((), (engine.EVALUATED, ""))


def test_real_admin_ntp_vrf_and_no_local_clock_or_parallel_vrf_removal():
    config = FIXTURES / "nxos_nxos_services_admin" / "configured-ntp-config.txt"
    fragment = config.read_text()
    assert "use-vrf" in fragment
    name = "time.no-ntp-source"
    assert replay(name, fragment) == ((), (engine.EVALUATED, ""))
    hits, _ = replay(name, "ntp peer 192.0.2.10 use-vrf default\n"
                           "ntp peer 192.0.2.10 use-vrf management\n"
                           "no ntp peer 192.0.2.10 use-vrf default\n")
    assert not hits
    hits, _ = replay(name, "ntp master 5\nntp server 127.127.1.0\n", full=("ntp",))
    assert len(hits) == 1


def test_snmp_user_table_reads_implicit_des_and_effective_auto_user():
    name = "snmp.v3-auth-priv"
    answers = {"show snmp user": b"User Auth Priv(enforce) Groups aclfilter\n"
                                b"sample-auto md5 des(no) network-admin\n"
                                b"sample-auth sha no network-operator\n"
                                b"sample-private sha aes-128(yes) network-operator\n"}
    hits, state = replay(name, "", answers=answers)
    assert {tuple(h.evidence) for h in hits} == {
        (("count", 1), ("privacy", "des")), (("count", 1), ("privacy", "no-auth-priv"))}
    assert state == (engine.EVALUATED, "")
    assert "sample-" not in repr(hits)


def test_real_ro_refusal_never_yields_a_snapshot():
    denied = FIXTURES / "nxos_9_3_12" / "ro__show-running-config-denied.txt"
    with pytest.raises(collect.CollectError, match="permission-denied"):
        Transport(collect.RUNNING, denied.read_bytes()).collect(ALIAS)


@pytest.mark.parametrize("auxiliary", [b"% Authorization failed\n", None])
def test_missing_auxiliary_leaves_vty_and_snmp_direct_evidence(auxiliary):
    body = ("!Command: show running-config\n" + BASE +
            "line vty\n  exec-timeout 0\n"
            "snmp-server user example-user network-operator auth sha [redacted] priv [redacted]\n")
    transport = Transport(collect.RUNNING, body.encode(), {"show snmp user": auxiliary})
    snapshot, _ = transport.collect(ALIAS)
    names = ("mgmt.idle-timeout", "snmp.v3-auth-priv")
    hits, states = engine.evaluate(snapshot.metadata.tree, TENANT, DEVICE, tuple(RULES[n] for n in names),
                                   context=platforms.AuditContext(snapshot=snapshot.metadata, live=True))
    assert {hit.rule_id for hit in hits} == {RULES[name].id for name in names}
    assert states[RULES[names[1]].id][0] == engine.NOT_EVALUATED


def test_real_cli_parser_audit_store_and_mcp(tmp_path, monkeypatch, capsys):
    long_secret = "AuditNXOSCanaryValue"
    short_secret = "~J~"
    data = payload(ALIAS) + (
        "\nline vty\n  exec-timeout 0\nfeature telnet\n"
        "snmp-server community " + long_secret + " group network-operator\n"
        "snmp-server community " + short_secret + " use-acl EXAMPLE\n"
    ).encode()
    transport = Transport(collect.RUNNING, data)
    transport.install(monkeypatch)
    assert invoke(tmp_path, transport, ALIAS) == cli.EXIT_INCOMPLETE
    collected = capsys.readouterr()
    report = json.loads(collected.out)
    expected = {RULES[n].id for n in ("mgmt.telnet-enabled", "mgmt.idle-timeout", "snmp.v1v2c-community", "snmp.v3-auth-priv")}
    assert {hit["rule_id"] for hit in report["findings"]} == expected

    offline = tmp_path / "input.conf"
    offline.write_bytes(data)
    args = ["run", "--platform", CATALOG, "--device", DEVICE, "--tenant", TENANT, "--config", str(offline)]
    assert cli.main([*args, "--json"]) == cli.EXIT_INCOMPLETE
    file_result = capsys.readouterr()
    assert {hit["fingerprint"] for hit in json.loads(file_result.out)["findings"]} == {
        hit["fingerprint"] for hit in report["findings"]}
    assert cli.main([*args, "--sarif"]) == cli.EXIT_INCOMPLETE
    sarif = capsys.readouterr()
    tree = l1_cli.parse(data.decode())
    assert not tree.unterminated

    monkeypatch.setattr(mcp_server, "_CONFIGURATION", None)
    mcp_server.configure({
        mcp_server.STORE_VARIABLE: str(tmp_path / "audit.sqlite"),
        mcp_server.TENANT_VARIABLE: TENANT,
        mcp_server.CATALOG_VARIABLE: CATALOG,
    })

    async def findings():
        async with Client(mcp_server.mcp) as client:
            result = await client.call_tool("list_findings", {"device": DEVICE})
            return result.content[0].text

    mcp_json = asyncio.run(findings())
    assert {hit["rule_id"] for hit in json.loads(mcp_json)["findings"]} == expected
    with closing(sqlite3.connect(tmp_path / "audit.sqlite")) as db:
        storage = "\n".join(db.iterdump())
    for value in (long_secret, short_secret):
        assert value not in mcp_json + storage
        assert all(value not in result.out + result.err for result in (collected, file_result, sarif))


def test_snmp_user_modifiers_leave_auth_and_privacy_in_place():
    name = "snmp.v3-auth-priv"
    body = ("snmp-server user sample network-operator auth sha [redacted] priv [redacted] localizedkey\n"
            "snmp-server user sample enforcePriv\n")
    hits, state = replay(name, body, full=("snmp",))
    assert [dict(hit.evidence) for hit in hits] == [{"count": 1, "privacy": "des"}]
    assert state == (engine.EVALUATED, "")


def test_profile_can_prove_implicit_dhcp_global_default():
    name = "l2.dhcp-snooping"
    body = "feature dhcp\nip dhcp snooping vlan 20\n"
    assert replay(name, body)[1][0] == engine.NOT_EVALUATED
    hits, state = replay(name, body, full=("global",))
    assert [dict(hit.evidence) for hit in hits] == [{"count": 1, "state": "disabled"}]
    assert state == (engine.EVALUATED, "")


PROFILE = ("interface", "global")


def test_explicit_access_vlan_is_evaluated_and_bare_port_is_vlan_1_with_profile():
    name = "l2.default-vlan"
    vlan20 = "interface Ethernet1/1\n  switchport access vlan 20\n"
    assert replay(name, vlan20) == ((), (engine.EVALUATED, ""))
    assert replay(name, vlan20, full=PROFILE) == ((), (engine.EVALUATED, ""))
    bare = "interface Ethernet1/1\n"
    assert replay(name, bare) == ((), (engine.NOT_EVALUATED, "visibility-unproven"))
    hits, state = replay(name, bare, full=PROFILE)
    assert [(hit.object_key, dict(hit.evidence)) for hit in hits] == [(PORT, {"vlan": 1})]
    assert state == (engine.EVALUATED, "")


def test_system_default_switchport_matches_exact_tokens():
    name = "l2.default-vlan"
    hits, state = replay(name, "no system default switchport shutdown\ninterface Ethernet1/1\n", full=PROFILE)
    assert [dict(hit.evidence) for hit in hits] == [{"vlan": 1}]
    routed = "no system default switchport\nsystem default switchport shutdown\ninterface Ethernet1/1\n"
    assert replay(name, routed, full=PROFILE) == ((), (engine.EVALUATED, ""))
    unused = "no system default switchport shutdown\ninterface Ethernet1/1\n"
    hits, state = replay("ports.unused-up", unused, full=PROFILE)
    assert [dict(hit.evidence) for hit in hits] == [{"state": "admin-up"}]


def test_real_admin_baseline_access_ports():
    # Ethernet1/2 carries only "switchport access vlan 20"; the bare Ethernet1/48 is access, VLAN 1
    # (default) and not shut down in show-interface-Eth1-48-switchport/-status__baseline.txt.
    body = payload(ALIAS)
    edge = {"role": "edge", "default_vlan_allowed": False}
    name = "l2.default-vlan"
    assert audit(name, body, intent={"ports": {"Ethernet1/2": edge}}) == ((), (engine.EVALUATED, ""))
    ports = {"Ethernet1/1": edge, "Ethernet1/2": edge, "Ethernet1/48": edge}
    hits, state = audit(name, body, intent={"ports": ports})
    assert (hits, state) == ((), (engine.NOT_EVALUATED, "visibility-unproven"))
    hits, state = audit(name, body, intent={"ports": ports}, full=PROFILE)
    assert [(hit.object_key, dict(hit.evidence)) for hit in hits] == [("Ethernet1/48", {"vlan": 1})]
    assert state == (engine.EVALUATED, "")
    hits, state = audit("ports.unused-up", body, intent={"ports": {"Ethernet1/48": {"role": "unused"}}},
                        full=PROFILE)
    assert [(hit.object_key, dict(hit.evidence)) for hit in hits] == [("Ethernet1/48", {"state": "admin-up"})]
    assert state == (engine.EVALUATED, "")
