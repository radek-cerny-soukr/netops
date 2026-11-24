"""IOS rules exercised with redacted examples and the real Auditor entry points."""
import asyncio
from contextlib import closing
import json
from pathlib import Path
import sqlite3

import pytest

from netops_auditor import cli, collect, engine, l1_cli, platforms
from test_multiplatform_collect import FIXTURES, Transport, invoke, payload
from test_channel_events_on_failure import DEVICE, TENANT


KEY = "cisco-ios"
RULES = {item.id.removeprefix(KEY + "."): item for item in engine.load_catalog(KEY)}
R = Path(__file__).parent / "fixtures" / "rules"
PORT = "GigabitEthernet0/1"
V3_ROW = (b"User name: example-user\nEngine ID: 8000000903000000000001\n"
          b"storage-type: nonvolatile active\nAuthentication Protocol: SHA\n"
          b"Privacy Protocol: AES128\nGroup-name: MONITOR\n")

INTENTS = {
    "mgmt.access-acl": {"management_prefixes": ["192.0.2.0/24"]},
    "aaa.external-login": {"external_aaa_required": True},
    "time.ntp-auth": {"ntp_auth_required": True},
    "logging.syslog-level": {"syslog_severity": "info"},
    "services.edge-discovery": {"ports": {PORT: {"role": "edge", "discovery_allowed": False}}},
    "l2.bpdu-guard": {"ports": {PORT: {"role": "edge"}}},
    "l2.default-vlan": {"ports": {PORT: {"role": "edge", "default_vlan_allowed": False}}},
    "l2.trunk-native": {"ports": {PORT: {"role": "trunk", "native_vlan": 40}}},
    "l2.dhcp-snooping": {"dhcp_snooping_vlans": [20, 22, 30], "trusted_dhcp_ports": []},
    "l2.storm-control": {"ports": {PORT: {"role": "edge", "storm_control_required": True}}},
    "ports.unused-up": {"ports": {PORT: {"role": "unused"}}},
}


def framed(body):
    return ("Building configuration...\n\nCurrent configuration : 999 bytes\n!\n"
            "hostname router-example\n" + body).encode()


def evaluate(name, body, *, full=True, answers=None, intent=None, alias="cisco_xe"):
    replies = {} if full else {"show privilege": b"Current privilege level is 1\n",
                              "show parser view": b"% Authorization failed.\n"}
    replies.update(answers or {})
    transport = Transport(collect.RUNNING, body, replies)
    snapshot, _ = transport.collect(alias)
    assert snapshot.metadata.complete
    context = platforms.AuditContext(INTENTS.get(name, {}) if intent is None else intent,
                                     snapshot.metadata, live=True)
    rule = RULES[name]
    hits, statuses = engine.evaluate(snapshot.metadata.tree, TENANT, DEVICE, (rule,), context=context)
    return hits, statuses[rule.id]


@pytest.mark.parametrize("name", RULES)
@pytest.mark.parametrize("kind", ("positive", "negative", "not-evaluated"))
def test_rule_fixture(name, kind):
    path = R / RULES[name].id / (kind + ".conf")
    pending = kind == "not-evaluated"
    answers = {}
    if name == "snmp.v3-auth-priv":
        answers["show snmp user"] = b"% Authorization failed.\n" if pending else V3_ROW
    if name == "mgmt.ssh-v2" and pending:
        answers["show ip ssh"] = b"% Authorization failed.\n"
    hits, (status, reason) = evaluate(name, framed(path.read_text()), full=not pending, answers=answers)
    assert status == (engine.NOT_EVALUATED if pending else engine.EVALUATED)
    assert bool(reason) == pending
    assert bool(hits) == (kind == "positive")
    assert all(hit.rule_id == RULES[name].id for hit in hits)


@pytest.mark.parametrize("name", INTENTS)
def test_intent_is_optional_before_visibility(name):
    hits, state = evaluate(name, framed("version 17.18\nend\n"), full=False, intent={})
    assert not hits
    assert state == (engine.EVALUATED, "")


def test_weak_vty_retains_explicit_finding_without_inferring_absence():
    body = framed("version 17.18\nline vty 0 2\n transport input telnet\nline vty 1\n login local\n"
                  "line vty 2\n transport input ssh\nline vty 1\n transport input none\nend\n")
    hits, (state, _) = evaluate("mgmt.telnet-enabled", body, full=False)
    assert state == engine.NOT_EVALUATED
    assert [item.object_key for item in hits] == ["vty:0"]
    hits, (state, _) = evaluate("mgmt.access-acl", body, full=False)
    assert state == engine.NOT_EVALUATED
    assert not hits


def test_lockout_reports_missing_quiet_period_once_per_device():
    body = framed("version 15.9\nno aaa new-model\nline vty 0 4\n transport input ssh\n"
                  " login local\nline vty 5 15\n transport input ssh\n login local\nend\n")
    hits, state = evaluate("mgmt.lockout", body, alias="cisco_ios")
    assert state == (engine.EVALUATED, "")
    assert [(hit.object_key, dict(hit.evidence)) for hit in hits] == [("global", {"state": "missing"})]


@pytest.mark.parametrize(("full", "version", "expected"), (
    (True, "17.18", engine.EVALUATED),
    (False, "17.18", engine.NOT_EVALUATED),
    (True, "99.1", engine.NOT_EVALUATED),
))
def test_unused_port_omits_shutdown_in_running_config(full, version, expected):
    body = framed(f"version {version}\n!\ninterface {PORT}\n!\nend\n")
    hits, (state, reason) = evaluate("ports.unused-up", body, full=full)
    assert state == expected
    if expected == engine.EVALUATED:
        assert reason == ""
        assert [(hit.object_key, dict(hit.evidence)) for hit in hits] == [
            (PORT, {"state": "administratively-up"}),
        ]
    else:
        assert reason == "unproven: physical port administrative shutdown"
        assert not hits


@pytest.mark.parametrize(("capture", "alias", "port"), (
    ("ios_c45/iolxe-l2/show-running-config__exec.txt", "cisco_xe", "Ethernet2/0"),
    ("ios_c45/iosvl2/show-running-config__exec.txt", "cisco_ios", "GigabitEthernet1/1"),
))
def test_unused_port_on_historical_running_config(capture, alias, port):
    data = (FIXTURES / capture).read_bytes()
    intent = {"ports": {port: {"role": "unused"}}}
    hits, state = evaluate("ports.unused-up", data, intent=intent, alias=alias)
    assert state == (engine.EVALUATED, "")
    assert [(hit.object_key, dict(hit.evidence)) for hit in hits] == [(port, {"state": "administratively-up"})]


@pytest.mark.parametrize(("answer", "finding"), [(b"SSH Enabled - version 1.99\n", True),
    (b"SSH Enabled - version 2.0\n", False), (b"SSH Disabled - version 2.0\n", False)])
def test_ssh_operational_version(answer, finding):
    body = framed("version 17.18\nline vty 0 0\n transport input ssh\nend\n")
    hits, state = evaluate("mgmt.ssh-v2", body, answers={"show ip ssh": answer})
    assert state == (engine.EVALUATED, "")
    assert bool(hits) == finding


@pytest.mark.parametrize(("acl", "finding"), [
    (" 20 permit ip any any\n 10 deny ip any any", False),
    (" 10 permit tcp 192.0.2.0 0.0.0.255 any eq 22\n 20 permit tcp any any eq telnet", False),
    (" 10 deny ip 198.51.100.0 0.0.0.127 any\n 20 permit ip 198.51.100.0 0.0.0.255 any", True),
])
def test_extended_acl_uses_order_prefix_subtraction_and_enabled_transport(acl, finding):
    body = framed("version 17.18\nline vty 0\n transport input ssh\n access-class FILTER in\n"
                  "ip access-list extended FILTER\n" + acl + "\nend\n")
    hits, state = evaluate("mgmt.access-acl", body)
    assert state == (engine.EVALUATED, "")
    assert bool(hits) == finding


def test_numbered_acl_and_ipv6_scope():
    body = framed("version 17.18\nline vty 0\n transport input ssh\n access-class 12 in\n"
                  " ipv6 access-class V6 in\naccess-list 12 permit 192.0.2.0 0.0.0.255\n"
                  "ipv6 access-list V6\n permit ipv6 any any\nend\n")
    intent = {"management_prefixes": ["192.0.2.0/24", "2001:db8::/32"]}
    hits, state = evaluate("mgmt.access-acl", body, intent=intent)
    assert state == (engine.EVALUATED, "")
    assert [item.object_key for item in hits] == ["vty:0:ipv6"]


@pytest.mark.parametrize("path", (
    "ios_ios_static_routing/iosvl2/admin-show-running-config__baseline.txt",
    "ios_c45/iosvl2/show-running-config__exec.txt",
))
def test_iosv_l2_portfast_edges_with_global_and_port_overrides(path):
    data = (FIXTURES / path).read_bytes()
    tree = l1_cli.parse(data.decode())
    edge = next(cmd.parents[0][1] for cmd in tree.matching("spanning-tree", "portfast", "edge") if cmd.parents)
    intent = {"ports": {edge: {"role": "edge"}}}
    for global_cmd in (b"spanning-tree portfast bpduguard default", b"spanning-tree portfast edge bpduguard default"):
        body = data.replace(b"\nend", b"\n" + global_cmd + b"\nend", 1)
        hits, state = evaluate("l2.bpdu-guard", body, intent=intent, alias="cisco_ios")
        assert not hits
        assert state[0] == engine.EVALUATED
        body = body.replace(b" spanning-tree portfast edge\n", b" spanning-tree portfast disable\n", 1)
        hits, state = evaluate("l2.bpdu-guard", body, intent=intent, alias="cisco_ios")
        assert len(hits) == 1
        assert state[0] == engine.EVALUATED


@pytest.mark.parametrize("alias", ("cisco_ios", "cisco_xe"))
def test_historical_admin_bodies_use_same_catalog_for_both_variants(alias):
    hits, state = evaluate("mgmt.telnet-enabled", payload(alias), alias=alias)
    assert not hits
    assert state == (engine.EVALUATED, "")


def test_historical_ntp_external_and_xe_read_only_refusal():
    text = (FIXTURES / "ios_ios_system_services/iosv-changed.txt").read_text()
    assert l1_cli.parse(text).matching("ntp", "server")
    external = next(line for line in text.splitlines() if line.startswith("ntp server "))
    for body, count in ((external + "\nntp master 5", 0), ("ntp master 5", 1)):
        hits, state = evaluate("time.no-ntp-source", framed("version 15.9\n" + body + "\nend\n"),
                               alias="cisco_ios")
        assert len(hits) == count
        assert state == (engine.EVALUATED, "")
    denied = (FIXTURES / "iosxe_xe_access_control/ro-show-running-config__denied.txt").read_bytes()
    with pytest.raises(collect.CollectError, match="permission-denied"):
        Transport(collect.RUNNING, denied).collect("cisco_xe")


def test_cli_audit_store_and_mcp_keep_fingerprints_and_credentials_private(tmp_path, monkeypatch, capsys):
    from fastmcp import Client
    from netops_auditor import mcp_server

    canaries = ("ExampleCredentialCanary", "~Z~", "ExampleCommunityCanary", "ExampleNtpKeyCanary")
    insert = (f"username example-user password 7 {canaries[0]}\nenable password 0 {canaries[1]}\n"
              f"snmp-server community {canaries[2]} RO\nntp authentication-key 19 md5 {canaries[3]}\n"
              "line vty 0 4\n transport input telnet\nline vty 1 4\n transport input ssh\n")
    body = payload("cisco_ios").replace(b"\nend", b"\n" + insert.encode() + b"end", 1)
    transport = Transport(collect.RUNNING, body)
    transport.install(monkeypatch)
    live_rc = invoke(tmp_path, transport)
    live_out, live_err = capsys.readouterr()
    live = json.loads(live_out)
    assert live_rc in (0, 2, 3)
    direct = {RULES[name].id for name in ("mgmt.telnet-enabled", "aaa.local-password-storage", "snmp.v1v2c-community")}
    expected = {item["fingerprint"] for item in live["findings"] if item["rule_id"] in direct}
    assert len(expected) == 4

    offline = tmp_path / "input.conf"
    offline.write_bytes(body)
    arguments = ["run", "--platform", KEY, "--device", DEVICE, "--tenant", TENANT, "--config", str(offline)]
    cli.main([*arguments, "--json"])
    offline_out, offline_err = capsys.readouterr()
    findings = json.loads(offline_out)["findings"]
    assert {item["fingerprint"] for item in findings if item["rule_id"] in direct} == expected
    cli.main([*arguments, "--sarif"])
    sarif_out, sarif_err = capsys.readouterr()

    database = tmp_path / "audit.sqlite"
    with closing(sqlite3.connect(database)) as db:
        assert db.execute("SELECT count(*) FROM runs").fetchone() == (1,)
        dump = "\n".join(db.iterdump())
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", None)
    mcp_server.configure({mcp_server.STORE_VARIABLE: str(database), mcp_server.TENANT_VARIABLE: TENANT,
                          mcp_server.CATALOG_VARIABLE: KEY})

    async def read():
        async with Client(mcp_server.mcp) as client:
            result = await client.call_tool("list_findings", {"device": DEVICE})
            return result.content[0].text

    mcp_out = asyncio.run(read())
    assert {item["fingerprint"] for item in json.loads(mcp_out)["findings"] if item["rule_id"] in direct} == expected
    assert all(value not in output for value in canaries for output in (
        live_out, live_err, offline_out, offline_err, sarif_out, sarif_err, dump, mcp_out))


@pytest.mark.parametrize("privilege", (1, 15))
def test_observed_no_parser_view_still_requires_privilege_15(privilege):
    body = framed("version 17.18\nntp master 5\nend\n")
    answers = {"show privilege": f"Current privilege level is {privilege}\n".encode(),
               "show parser view": f"No view is active ! Currently in Privilege Level {privilege}\n".encode()}
    hits, status = evaluate("time.no-ntp-source", body, answers=answers)
    assert bool(hits) == (privilege == 15)
    assert status[0] == (engine.EVALUATED if privilege == 15 else engine.NOT_EVALUATED)


def test_disabled_snmp_agent_proves_v3_is_inactive():
    body = framed("version 17.18\nend\n")
    hits, status = evaluate("snmp.v3-auth-priv", body, full=False,
                            answers={"show snmp user": b"%SNMP agent not enabled\n"})
    assert not hits
    assert status == (engine.EVALUATED, "")


def test_supported_username_secret_types_are_not_reported():
    body = framed("version 17.18\nusername operator secret 9 SECRET-DATA\nend\n")
    hits, status = evaluate("aaa.local-password-storage", body)
    assert not hits
    assert status == (engine.EVALUATED, "")
