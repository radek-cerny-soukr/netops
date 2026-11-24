"""Arista EOS catalog fixtures and read-only transport, history and MCP regressions."""
import asyncio
import json
from pathlib import Path

import pytest
from fastmcp import Client

from netops_auditor import cli, collect, engine, l1_cli, mcp_server, platforms
from netops_auditor.management import validate_intent
from test_channel_events_on_failure import DEVICE, LOGIN, TENANT
from test_multiplatform_collect import EOS_SESSION_COMMAND, FIXTURES as ADMIN, Transport, invoke, payload, session


PLATFORM = "arista-eos"
ALIAS = "arista_eos"
RULES = {rule.id.removeprefix(PLATFORM + "."): rule for rule in engine.load_catalog(PLATFORM)}
FIXTURES = Path(__file__).parent / "fixtures" / "rules"
TRUNK = ADMIN / "eos_eos_switchport_admin/show-running-config-interfaces-Ethernet12__trunk-dot1x.txt"
DENIED = ADMIN / "eos_eos_mlag_admin/ro-running-config-denied.txt"
INTENTS = {
    "mgmt.access-acl": {"management_prefixes": ["192.0.2.0/24"]},
    "aaa.external-login": {"external_aaa_required": True},
    "time.ntp-auth": {"ntp_auth_required": True},
    "logging.syslog-level": {"syslog_severity": "info"},
    "services.edge-discovery": {"ports": {"Ethernet12": {"role": "edge", "discovery_allowed": False}}},
    "l2.bpdu-guard": {"ports": {"Ethernet12": {"role": "edge"}}},
    "l2.default-vlan": {"ports": {"Ethernet12": {"role": "edge", "default_vlan_allowed": False}}},
    "l2.trunk-native": {"ports": {"Ethernet12": {"role": "trunk", "native_vlan": 20}}},
    "l2.dhcp-snooping": {"dhcp_snooping_vlans": [21], "trusted_dhcp_ports": ["Ethernet12"]},
    "l2.storm-control": {"ports": {"Ethernet12": {"role": "edge", "storm_control_required": True}}},
    "ports.unused-up": {"ports": {"Ethernet12": {"role": "unused"}}},
}
VERIFIED = "verified-profile"
DEVICE_LINE = b"! device: switch-example (cEOSLab, EOS-4.36.1F-48405728.4361F (engineering build))\n"


def _fixture(rule, case):
    return (FIXTURES / rule.id / (case + ".conf")).read_bytes()


def _frame(body):
    return (b"! Command: show running-config\n" + DEVICE_LINE + b"!\nhostname switch-example\n!\n"
            + body + b"\n!\nend\n")


def _proof(answers=None):
    # The device's own report of the collecting session. A complete snapshot proves its
    # families only when `show users detail | json` lists this login's established SSH
    # session with the network-admin role (measured cEOS output, see test_multiplatform_collect).
    return {**(answers or {}), **session(ALIAS, login=LOGIN)}


def _evaluate(suffix, payload, *, intent=None, proof=False, auxiliary=b""):
    answers = {"show snmp user": auxiliary}
    transport = Transport(collect.RUNNING, payload, _proof(answers) if proof else answers)
    snapshot, _ = transport.collect(ALIAS)
    metadata = snapshot.metadata
    assert metadata.complete
    assert (metadata.visibility("interface").reason == VERIFIED) is proof
    context = platforms.AuditContext(validate_intent(intent if intent is not None else INTENTS.get(suffix, {}), PLATFORM),
                                     metadata, live=True)
    rule = RULES[suffix]
    findings, statuses = engine.evaluate(metadata.tree, TENANT, DEVICE, [rule], context=context)
    return findings, statuses[rule.id], transport.commands


@pytest.mark.parametrize("suffix", sorted(RULES))
@pytest.mark.parametrize("case", ("positive", "negative", "not-evaluated"))
def test_catalog_fixture(suffix, case):
    # Positive and negative fixtures are read by the proven account; the same
    # omissions read without that proof stay not-evaluated.
    findings, (status, reason), _ = _evaluate(
        suffix, _fixture(RULES[suffix], case), proof=case != "not-evaluated")
    assert bool(findings) == (case == "positive")
    assert status == (engine.NOT_EVALUATED if case == "not-evaluated" else engine.EVALUATED)
    assert bool(reason) == (case == "not-evaluated")
    for finding in findings:
        assert finding.as_dict()["rule_id"] == RULES[suffix].id
        assert "NETOPS_REDACTED" not in json.dumps(finding.as_dict())


@pytest.mark.parametrize("suffix", sorted(INTENTS))
def test_missing_intent_is_optional_even_for_a_positive_fixture(suffix):
    findings, status, _ = _evaluate(suffix, _fixture(RULES[suffix], "positive"), intent={})
    assert not findings
    assert status == (engine.EVALUATED, "")


@pytest.mark.parametrize(("body", "result"), [
    (b"   10 deny tcp any any eq ssh\n   20 permit ip any any", False),
    (b"   10 deny tcp 198.51.100.0/24 any eq ssh\n   20 permit tcp any any eq ssh", True),
    (b"   10 permit tcp any any eq 443\n   20 permit tcp 192.0.2.0/24 any eq ssh", False),
])
def test_ssh_acl_uses_source_order_and_ssh_service(body, result):
    config = _frame(b"management ssh\n   ip access-group example in\nip access-list example\n" + body)
    findings, state, _ = _evaluate("mgmt.access-acl", config, proof=True)
    assert state == (engine.EVALUATED, "")
    assert bool(findings) is result


def test_ssh_acl_honors_vrf_and_ipv6():
    body = _frame(b"management ssh\n   vrf default\n      shutdown\n   vrf example\n      no shutdown\n"
                  b"   ipv6 access-group example in vrf example\nipv6 access-list example\n"
                  b"   10 permit tcp any6 any6 eq 22")
    findings, _, _ = _evaluate("mgmt.access-acl", body, intent={"management_prefixes": ["2001:db8::/32"]})
    assert [finding.object_key for finding in findings] == ["example:ipv6"]


def test_scoped_telnet_direct_finding_survives_unproven_default():
    data = _frame(b"management telnet\n   vrf example\n      no shutdown")
    findings, status, _ = _evaluate("mgmt.telnet-enabled", data)
    assert [finding.object_key for finding in findings] == ["example"]
    assert status == (engine.NOT_EVALUATED, "telnet-scope-unproven")


def test_global_discovery_disabled_even_with_port_transmit():
    body = _fixture(RULES["services.edge-discovery"], "positive").replace(
        b"\ninterface Ethernet12", b"\nno lldp run\n!\ninterface Ethernet12", 1)
    findings, status, _ = _evaluate("services.edge-discovery", body, proof=True)
    assert not findings
    assert status == (engine.EVALUATED, "")


def test_unverified_interface_does_not_prove_absent_override():
    body = _fixture(RULES["l2.bpdu-guard"], "negative")
    findings, status, _ = _evaluate("l2.bpdu-guard", body)
    assert not findings
    assert status == (engine.NOT_EVALUATED, "effective-bpdu-guard-unproven")


def test_snmp_disabled_scope_cannot_expose_legacy_communities():
    body = _frame(b"no snmp-server vrf default\nsnmp-server community NETOPS_REDACTED ro")
    findings, status, _ = _evaluate("snmp.v1v2c-community", body, proof=True)
    assert not findings
    assert status == (engine.EVALUATED, "")
    findings, status, _ = _evaluate("snmp.v1v2c-community", body)
    assert not findings
    assert status == (engine.NOT_EVALUATED, "snmp-communities-or-scope-unproven")


def test_effective_snmp_user_from_auxiliary():
    body = _fixture(RULES["snmp.v3-auth-priv"], "not-evaluated")
    data = (b"User name: example-user\nSecurity model: v3\nAuthentication protocol: SHA\n"
            b"Privacy protocol: AES-128\nGroup name: example\n")
    findings, status, commands = _evaluate("snmp.v3-auth-priv", body, auxiliary=data, proof=True)
    assert commands == [collect.RUNNING, "show snmp user", EOS_SESSION_COMMAND]
    assert not findings
    assert status == (engine.EVALUATED, "")
    findings, status, _ = _evaluate("snmp.v3-auth-priv", body, auxiliary=b"% Authorization failed\n", proof=True)
    assert not findings
    assert status == (engine.NOT_EVALUATED, "permission-denied")


def test_baseline_and_trunk_capture_and_fingerprint_parity():
    snapshot, _ = Transport(collect.RUNNING, payload(ALIAS)).collect(ALIAS)
    assert snapshot.metadata.complete
    assert snapshot.metadata.visibility("aaa").reason == "content"
    baseline_findings, _ = engine.evaluate(snapshot.metadata.tree, TENANT, DEVICE, RULES.values())
    assert RULES["aaa.local-password-storage"].id not in {item.rule_id for item in baseline_findings}
    config = _frame(TRUNK.read_bytes())
    snapshot, _ = Transport(collect.RUNNING, config).collect(ALIAS)
    intent = validate_intent(INTENTS["l2.trunk-native"], PLATFORM)
    findings = []
    for tree, context in (
        (l1_cli.parse(config.decode()), platforms.AuditContext(intent)),
        (snapshot.metadata.tree, platforms.AuditContext(intent, snapshot.metadata, live=True)),
    ):
        hit, status = engine.evaluate(tree, TENANT, DEVICE, [RULES["l2.trunk-native"]], context=context)
        assert status[hit[0].rule_id] == (engine.EVALUATED, "")
        assert hit[0].object_key == "Ethernet12"
        assert dict(hit[0].evidence)["vlan"] == 3990
        findings.append(hit[0].fingerprint())
    assert findings[0] == findings[1]


def test_explicit_trunk_allow_list_can_disprove_policy_with_implicit_native():
    config = _frame(b"interface Ethernet12\n   switchport trunk allowed vlan 20\n   switchport mode trunk")
    cases = [(1, engine.EVALUATED), (20, engine.NOT_EVALUATED)]
    for expected, expected_status in cases:
        intent = {"ports": {"Ethernet12": {"role": "trunk", "native_vlan": expected}}}
        findings, (status, _), _ = _evaluate("l2.trunk-native", config, intent=intent)
        assert status == expected_status
        if findings:
            assert dict(findings[0].evidence) == {
                "reason": "expected-native-vlan-not-allowed", "expected_vlan": 1,
            }
        assert bool(findings) == (expected == 1)


def test_cli_parser_audit_store_and_filtered_mcp(tmp_path, monkeypatch, capsys):
    canary = b"FixtureCanaryPrivateValue"
    body = b"\n".join((
        b"username example-user role network-operator secret 0 " + canary,
        b"snmp-server vrf default", b"snmp-server community " + canary + b" ro",
        b"management ssh", b"   idle-timeout 0",
        b"interface Ethernet12", b"   shutdown",
    ))
    transport = Transport(collect.RUNNING, _frame(body))
    transport.install(monkeypatch)
    assert invoke(tmp_path, transport, ALIAS) == cli.EXIT_INCOMPLETE
    output = capsys.readouterr()
    assert canary.decode() not in output.out + output.err
    audit = json.loads(output.out)
    findings = {item["rule_id"] for item in audit["findings"]}
    assert findings == {RULES[suffix].id for suffix in
                        ("aaa.local-password-storage", "snmp.v1v2c-community", "mgmt.idle-timeout")}
    snapshot_store = tmp_path / "audit.sqlite"
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", None)
    mcp_server.configure({mcp_server.STORE_VARIABLE: str(snapshot_store),
                          mcp_server.TENANT_VARIABLE: TENANT, mcp_server.CATALOG_VARIABLE: PLATFORM})

    async def mcp_requests():
        async with Client(mcp_server.mcp) as client:
            status = await client.call_tool("audit_status", {"platform": PLATFORM, "device": DEVICE})
            summary = await client.call_tool("findings_summary", {"platform": PLATFORM, "device": DEVICE,
                "rule_id": RULES["snmp.v1v2c-community"].id})
            return (json.loads(status.content[0].text), json.loads(summary.content[0].text))

    status, summary = asyncio.run(mcp_requests())
    assert status["devices"][0]["coverage"]["counts"]["not_evaluated"] > 0
    assert summary["returned"] == 1
    assert canary.decode() not in json.dumps((status, summary))
    assert canary not in snapshot_store.read_bytes()

    # A real RO refusal never creates a new run for that device.
    transport.answers[collect.RUNNING] = DENIED.read_bytes()
    assert invoke(tmp_path, transport, ALIAS) != 0
    denied = capsys.readouterr()
    assert "command-unavailable" in denied.err + denied.out
    assert asyncio.run(mcp_requests())[0] == status


def test_cli_file_baseline_preserves_direct_offline_finding(tmp_path, capsys):
    path = tmp_path / "snapshot.conf"
    path.write_bytes(_fixture(RULES["mgmt.telnet-enabled"], "positive"))
    assert cli.main(["run", "--platform", PLATFORM, "--tenant", TENANT, "--device", DEVICE,
                     "--config", str(path), "--json"]) == 0
    assert RULES["mgmt.telnet-enabled"].id in capsys.readouterr().out


def test_real_capture_applies_eos_defaults_only_with_the_proven_account():
    # The 4.36.1F capture prints no NTP, syslog, SSH timer, lockout, LLDP or
    # shutdown line; the proof comes from the device's report of the collecting session.
    intent = {"ports": {"Ethernet15": {"role": "unused"},
                        "Ethernet14": {"role": "edge", "discovery_allowed": False}}}
    expected = {
        "mgmt.idle-timeout": "ssh", "mgmt.lockout": "local-login", "time.no-ntp-source": "client",
        "logging.no-syslog-target": "remote", "services.edge-discovery": "Ethernet14",
        "l2.bpdu-guard": "Ethernet14", "ports.unused-up": "Ethernet15",
    }
    for proof in (True, False):
        data = payload(ALIAS)
        snapshot, _ = Transport(collect.RUNNING, data, _proof() if proof else None).collect(ALIAS)
        assert snapshot.metadata.complete
        context = platforms.AuditContext(validate_intent(intent, PLATFORM), snapshot.metadata, live=True)
        findings, statuses = engine.evaluate(snapshot.metadata.tree, TENANT, DEVICE, RULES.values(),
                                             context=context)
        hits = {(item.rule_id.removeprefix(PLATFORM + "."), item.object_key) for item in findings}
        if proof:
            assert hits == set(expected.items())
            assert set(statuses.values()) == {(engine.EVALUATED, "")}
        else:
            for suffix in ("ports.unused-up", "services.edge-discovery"):
                assert statuses[RULES[suffix].id][0] == engine.NOT_EVALUATED


@pytest.mark.parametrize(("group", "server"), [("tacacs+", b"tacacs-server"), ("radius", b"radius-server")])
def test_builtin_login_group_uses_every_configured_server(group, server):
    login = b"aaa authentication login default group %s local" % group.encode()
    configured = _frame(server + b" host 192.0.2.10\n!\n" + login)
    findings, status, _ = _evaluate("aaa.external-login", configured, proof=True)
    assert not findings and status == (engine.EVALUATED, "")
    missing = _frame(login)
    findings, status, _ = _evaluate("aaa.external-login", missing, proof=True)
    assert status == (engine.EVALUATED, "")
    assert [dict(item.evidence)["reason"] for item in findings] == ["external-login-server-missing"]
    findings, status, _ = _evaluate("aaa.external-login", missing)
    assert not findings
    assert status == (engine.NOT_EVALUATED, "external-login-server-unproven")


def test_storm_control_default_is_reported_only_with_proof():
    body = _fixture(RULES["l2.storm-control"], "positive")
    findings, status, _ = _evaluate("l2.storm-control", body, proof=True)
    assert status == (engine.EVALUATED, "")
    assert [(item.object_key, dict(item.evidence)["reason"]) for item in findings] == [
        ("Ethernet12", "broadcast-storm-control-disabled")]
    findings, status, _ = _evaluate("l2.storm-control", body)
    assert not findings
    assert status == (engine.NOT_EVALUATED, "storm-control-limit-unproven")
