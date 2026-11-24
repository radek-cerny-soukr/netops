"""ExtremeXOS taxonomy checks through the catalog, engine and Auditor CLI."""
import asyncio
import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest
from fastmcp import Client

from netops_auditor import cli, engine, l1_exos, mcp_server, platforms
from test_channel_events_on_failure import DEVICE, TENANT, stored, write_inventory, write_vault
from test_multiplatform_collect import Transport, X440_SWITCH, EXOS_VERSION_ANSWER

FIXTURES = Path(__file__).parent / "fixtures"
HELPER = FIXTURES.parents[2] / "netops-helper/tests/fixtures/real"
EXAMPLE = FIXTURES / "exos_clean.conf"
INTENTS = {
    "mgmt.lockout": {"account_lockout_required": ["user01"]},
    "mgmt.access-acl": {"management_prefixes": ["192.0.2.0/24"]},
    "aaa.external-login": {"external_aaa_required": True},
    "time.ntp-auth": {"ntp_auth_required": True},
    "logging.syslog-level": {"syslog_severity": "warning"},
    "services.edge-discovery": {"ports": {"2": {"role": "edge", "discovery_allowed": False}}},
    "l2.bpdu-guard": {"ports": {"2": {"role": "edge"}}},
    "l2.default-vlan": {"ports": {"2": {"role": "edge", "default_vlan_allowed": False}}},
    "l2.dhcp-snooping": {"ports": {"1": {"role": "edge"}, "2": {"role": "edge"}},
                        "dhcp_snooping_vlans": [10], "trusted_dhcp_ports": ["1"]},
    "l2.storm-control": {"ports": {"2": {"role": "edge", "storm_control_required": True}}},
    "ports.unused-up": {"ports": {"2": {"role": "unused"}}},
}
IDS = tuple("exos." + key for key in (
    "mgmt.http-enabled", "mgmt.idle-timeout", "mgmt.lockout", "mgmt.access-acl",
    "aaa.external-login", "snmp.v1v2c-community", "snmp.v3-auth-priv", "time.ntp-auth",
    "logging.syslog-level", "services.edge-discovery", "l2.bpdu-guard", "l2.default-vlan",
    "l2.dhcp-snooping", "l2.storm-control", "ports.unused-up",
))
RULES = {rule.id: rule for rule in engine.load_catalog("exos")}
ACL = """
entry permit-management {
    if { source-address 192.0.2.0/24; }
    then { permit; }
}
entry deny-other {
    if {}
    then { deny; }
}
"""


def example(rule_id, case):
    return (FIXTURES / "rules" / rule_id / (case + ".conf")).read_text()


def audit(rule_id, body, *, auxiliary=None, live=True, verified=(), intent=None):
    sections = {key: platforms.SectionVisibility("visible", "verified-profile") for key in verified}
    snapshot = platforms.SnapshotMetadata("exos", sections=sections, auxiliary=auxiliary or {}, complete=True)
    context = platforms.AuditContext(INTENTS.get(rule_id.removeprefix("exos."), {}) if intent is None else intent,
                                     snapshot=snapshot, live=live)
    hits, states = engine.evaluate(l1_exos.parse(body), TENANT, DEVICE, [RULES[rule_id]], context=context)
    return hits, states[rule_id]


@pytest.mark.parametrize("rule_id", IDS)
@pytest.mark.parametrize("case", ("positive", "negative", "not-evaluated"))
def test_taxonomy_fixture(rule_id, case):
    supporting = {"ssh access-profile example-sources": ACL} if rule_id == "exos.mgmt.access-acl" else {}
    hits, status = audit(rule_id, example(rule_id, case), auxiliary=supporting)
    assert status[0] == ("not-evaluated" if case == "not-evaluated" else "evaluated")
    assert bool(status[1]) == (case == "not-evaluated")
    assert len(hits) == (case == "positive")
    assert "SECRET-DATA" not in json.dumps([item.as_dict() for item in hits])


@pytest.mark.parametrize("key", INTENTS)
def test_missing_intent_short_circuits_before_missing_sections(key):
    assert audit("exos." + key, "", intent={}) == ((), ("evaluated", ""))


def test_unknown_port_keeps_direct_finding_and_gap():
    rule_id = "exos.ports.unused-up"
    intent = {"ports": {"2": {"role": "unused"}, "5": {"role": "unused"}}}
    hits, status = audit(rule_id, example(rule_id, "positive").replace("disable ports all\n", ""), intent=intent)
    assert status[0] == "not-evaluated"
    assert [hit.object_key for hit in hits] == ["2"]


def test_discovery_default_requires_verified_port_scope():
    rule_id = "exos.services.edge-discovery"
    body = example(rule_id, "not-evaluated") + "# Module edp configuration.\nconfigure vr VR-Default add ports 1-4\n"
    assert audit(rule_id, body)[1][0] == "not-evaluated"
    assert audit(rule_id, body, verified=("edp",))[0][0].object_key == "2"


def test_acl_uses_first_match():
    rule_id = "exos.mgmt.access-acl"
    key = "ssh access-profile example-sources"
    body = example(rule_id, "negative")
    permit_all = "entry permit-all { if {} then { permit; } }\n"
    assert audit(rule_id, body, auxiliary={key: permit_all + ACL})[0][0].object_key == "ssh"
    assert not audit(rule_id, body, auxiliary={key: ACL + permit_all})[0]


def test_snmp_communities_aggregate_and_remain_private():
    rule_id = "exos.snmp.v1v2c-community"
    original = example(rule_id, "positive")
    first, _ = audit(rule_id, original.replace("SECRET-DATA", "CanaryCommunity"))
    second, _ = audit(rule_id, original.replace("SECRET-DATA", "DifferentCommunity"))
    assert len(first) == 1
    assert first[0].fingerprint() == second[0].fingerprint()
    assert "Canary" not in json.dumps(first[0].as_dict())


def test_removed_or_disabled_communities_leave_no_active_entry():
    rule_id = "exos.snmp.v1v2c-community"
    body = example(rule_id, "positive")
    body += "configure snmp delete community readonly SECRET-DATA\ndisable snmpv3 community sample-index\n"
    assert audit(rule_id, body, verified=("snmpMaster",)) == ((), ("evaluated", ""))
    assert audit(rule_id, body + "enable snmpv3 community sample-index\n")[0]


def test_no_sntp_regression_in_both_captured_ntp_views():
    rule_id = "exos.time.no-sntp-client"
    for filename in ("vm-ntp.out", "x440-ntp.out"):
        data = (HELPER / "exos/switch-health" / filename).read_text()
        assert "NTP                 : Disabled" in data
        assert "Authentication      : Disabled" in data
        assert engine.run(l1_exos.parse("# Module netTools configuration.\n"
                                        "configure sntp-client primary 192.0.2.1\n"),
                          TENANT, DEVICE, [RULES[rule_id]]) == ()


def test_enabled_sntp_proves_missing_ntp_authentication():
    rule_id = "exos.time.ntp-auth"
    body = "# Module netTools configuration.\nconfigure sntp-client primary 192.0.2.1\nenable sntp-client\n"
    hits, status = audit(rule_id, body)
    assert status == ("evaluated", "")
    assert hits[0].evidence == (("state", "sntp-only"),)
    assert audit(rule_id, body + "enable ntp vr VR-Default\n")[1][0] == "not-evaluated"


def test_ntp_server_uses_its_own_vr():
    rule_id = "exos.time.ntp-auth"
    body = example(rule_id, "negative")
    changed = body.replace("enable ntp\n", "enable ntp vr AuditVR\n").replace("key 5\n", "key 5 vr AuditVR\n")
    assert audit(rule_id, changed) == ((), ("evaluated", ""))
    assert audit(rule_id, changed.replace("vr AuditVR\n", "vr OtherVR\n", 1))[1][0] == "not-evaluated"


def test_lockout_readback_of_account_flags():
    rule_id = "exos.mgmt.lockout"
    body = example(rule_id, "not-evaluated")
    readback = ("  user01    None      None None   0 None       U       - ------\n"
                "Lockout Time Config: (U) Account remains locked until cleared.\n"
                "Flags: (l) Account lockout on login failures enabled\n")
    hits, status = audit(rule_id, body, auxiliary={"accounts password-policy": readback})
    assert status == ("evaluated", "")
    assert hits[0].object_key == "user01"
    assert audit(rule_id, body, auxiliary={
        "accounts password-policy": readback.replace("------", "--l---"),
    }) == ((), ("evaluated", ""))


def _inventory(tmp_path):
    path = write_inventory(tmp_path)
    payload = json.loads(path.read_text())
    payload["devices"][0]["platform"] = "exos"
    payload["devices"][0]["auditor"]["required_sections"] = ["vlan", "telnetd"]
    path.write_text(json.dumps(payload))
    return path


def _collect(tmp_path, database, *options):
    return cli.main(["collect", "--inventory", str(_inventory(tmp_path)), "--vault", str(write_vault(tmp_path)),
                     "--device", DEVICE, "--tenant", TENANT, "--store", str(database), "--json", *options])


def test_cli_to_parser_store_and_mcp(tmp_path, monkeypatch, capsys):
    # A collected dump is complete only up to its terminal module header (vpex on the measured
    # X440 and EXOS-VM layouts); the same text goes through the file channel.
    body = EXAMPLE.read_text() + example("exos.mgmt.http-enabled", "positive") + "#\n# Module vpex configuration.\n#\n"
    config = tmp_path / "switch.conf"
    config.write_text(body)
    database = tmp_path / "state.sqlite"
    # Terminal control output (here CR line ends) leaves a collected dump without its proof of end.
    transport = Transport("show configuration", body.replace("\n", "\r\n").encode())
    transport.install(monkeypatch)
    assert _collect(tmp_path, tmp_path / "crlf.sqlite") == cli.EXIT_INCOMPLETE
    crlf = json.loads(capsys.readouterr().out)
    assert [item["rule_id"] for item in crlf["findings"]] == ["exos.snapshot.incomplete"]
    assert crlf["findings"][0]["evidence"]["reason"] == "truncated"

    # The one-shot exec answer as the switch sends it.
    transport.answers["show configuration"] = body.encode()
    transport.answers.update({"show version": EXOS_VERSION_ANSWER, "show switch": X440_SWITCH})
    transport.commands.clear()
    assert _collect(tmp_path, database) == cli.EXIT_INCOMPLETE
    collected = json.loads(capsys.readouterr().out)
    assert transport.commands == ["show configuration", "show version", "show switch"]
    assert cli.main(["run", "--config", str(config), "--platform", "exos", "--tenant", TENANT,
                     "--device", DEVICE, "--json"]) == cli.EXIT_OK
    offline = json.loads(capsys.readouterr().out)
    assert offline["findings"] == collected["findings"]
    assert len(collected["findings"]) == 1

    monkeypatch.setattr(mcp_server, "_CONFIGURATION", None)
    mcp_server.configure({mcp_server.STORE_VARIABLE: str(database), mcp_server.TENANT_VARIABLE: TENANT,
                          mcp_server.CATALOG_VARIABLE: "exos"})

    async def request():
        async with Client(mcp_server.mcp) as client:
            status = await client.call_tool("audit_status", {"device": DEVICE, "platform": "exos"})
            summary = await client.call_tool("findings_summary", {
                "device": DEVICE, "platform": "exos", "rule_id": "exos.mgmt.http-enabled"})
            return json.loads(status.content[0].text), json.loads(summary.content[0].text)

    status, summary = asyncio.run(request())
    assert status["devices"][0]["coverage"]["counts"]["evaluated"] > 0
    assert summary["returned"] == 1
    assert "SECRET-DATA" not in json.dumps(summary)


def test_archived_vm_configuration_reaches_the_catalog():
    path = HELPER / "exos/switch-config-20261118/vm-running.out"
    tree = l1_exos.parse(path.read_text())
    assert {"vlan", "edp", "ntp", "thttpd", "snmpMaster"} <= set(tree.modules)
    assert not tree.unterminated_upm
    hits, states = engine.evaluate(tree, TENANT, DEVICE, tuple(RULES.values()),
                                   context=platforms.AuditContext(live=True))
    assert all(hit.rule_id in RULES for hit in hits)
    assert states["exos.mgmt.http-enabled"] == ("not-evaluated", "http-listener-unproven")


def test_ro_refusal_with_nonzero_exec_leaves_no_run(tmp_path, monkeypatch, capsys):
    body = (HELPER / "platform_baseline_20261117/x440-show_configuration.out").read_bytes()
    transport = Transport("show configuration", body)
    monkeypatch.setattr(transport, "run", lambda command, **kwargs: CompletedProcess(command, 254, body, b""))
    transport.install(monkeypatch)
    database = tmp_path / "state.sqlite"
    assert _collect(tmp_path, database) == cli.EXIT_ERROR
    assert "exit status 254" in capsys.readouterr().err
    runs, events = stored(database)
    assert not runs and events[0][1:] == ("failed", None)


def test_legacy_clean_and_native_vlan_identity():
    assert engine.run(l1_exos.parse(EXAMPLE.read_text()), TENANT, DEVICE, tuple(RULES.values())) == ()
    rule_id = "exos.management.port-native"
    policy = json.loads((FIXTURES / "rules" / rule_id / "positive.policy.json").read_text())
    hits = engine.run(l1_exos.parse(example(rule_id, "positive")), TENANT, DEVICE, [RULES[rule_id]], policy)
    assert hits and all(item.rule_id == rule_id and item.rule_version == 1 for item in hits)


# A complete EXOS dump read over SSH, with its software version, proves its modules; the rules
# then apply the defaults measured on 33.6.1.14 and 33.7.1.6 for settings the dump omits.
GOLDEN = FIXTURES.parents[2] / "netops-admin/tests/golden/exos/33.7.1.6-patch1-11/X440G2-12p-10G4"
# The capture of an interactive session starts with its paging notice; an exec read has none.
DUMP = (GOLDEN / "show-configuration/X440-G2-12p-10G4__normal-redacted-secrets.conf").read_bytes().split(b"\n", 1)[1]
VERSION = (GOLDEN / "show-version/X440-G2-12p-10G4__normal.conf").read_bytes()
# Derived: port 10 disabled in the printed form of the device (netops-admin
# tests/fixtures/exos_port_poe/x440__36-cfgvlan-dis.out, same release).
PORT_10_DISABLED = DUMP.replace(b"configure vr VR-Default add ports 1-16\n",
                                b"configure vr VR-Default add ports 1-16\ndisable port 10\n", 1)
DEFAULT_RULES = ("exos.mgmt.http-enabled", "exos.mgmt.idle-timeout", "exos.snmp.v1v2c-community",
                 "exos.snmp.v3-auth-priv")
EDGE = {"role": "edge", "discovery_allowed": False, "default_vlan_allowed": False, "storm_control_required": True}
INTENT = {"audit_intent": {
    "account_lockout_required": ["admin"], "management_prefixes": ["192.0.2.0/24"], "external_aaa_required": True,
    "ports": {"2": EDGE, "3": {"role": "unused"}, "10": {"role": "unused"}},
}}


def _proven_collect(tmp_path, monkeypatch, capsys, data=DUMP, version=VERSION, *options):
    transport = Transport("show configuration", data, {"show version": version, "show switch": X440_SWITCH})
    transport.install(monkeypatch)
    code = _collect(tmp_path, tmp_path / "state.sqlite", *options)
    assert transport.commands == ["show configuration", "show version"] + (["show switch"] if version else [])
    report = json.loads(capsys.readouterr().out)
    return code, report, {(item["rule_id"], item["object_key"]): item["evidence"] for item in report["findings"]}


def test_proven_dump_applies_measured_defaults(tmp_path, monkeypatch, capsys):
    code, report, found = _proven_collect(tmp_path, monkeypatch, capsys)
    assert {rule: report["rule_status"][rule]["status"] for rule in DEFAULT_RULES} == dict.fromkeys(
        DEFAULT_RULES, "evaluated")
    # HTTP is on by default; the idle timer is on and SNMP access is off by default.
    assert found[("exos.mgmt.http-enabled", "http")] == {"state": "enabled"}
    assert not [key for key in found if key[0] in DEFAULT_RULES[1:]]
    assert report["coverage"]["actionable_gaps"] == [] and report["evaluation_complete"]
    assert code == cli.EXIT_OK


def test_dump_without_a_known_version_keeps_the_defaults_unproven(tmp_path, monkeypatch, capsys):
    code, report, found = _proven_collect(tmp_path, monkeypatch, capsys, DUMP, b"")
    assert code == cli.EXIT_INCOMPLETE
    assert {rule: report["rule_status"][rule]["status"] for rule in DEFAULT_RULES} == dict.fromkeys(
        DEFAULT_RULES, "not-evaluated")
    assert not [key for key in found if key[0] in DEFAULT_RULES]


def test_proven_dump_applies_defaults_to_declared_intent(tmp_path, monkeypatch, capsys):
    policy = tmp_path / "intent.json"
    policy.write_text(json.dumps(INTENT))
    code, report, found = _proven_collect(tmp_path, monkeypatch, capsys, PORT_10_DISABLED, VERSION,
                                          "--policy", str(policy))
    expected = {
        ("exos.mgmt.lockout", "admin"): "disabled",
        ("exos.mgmt.access-acl", "ssh"): "no-filter",
        ("exos.aaa.external-login", "external-login"): "disabled",
        ("exos.services.edge-discovery", "2"): "edp-transmitting",
        ("exos.l2.default-vlan", "2"): "untagged-vlan-1",
        ("exos.l2.storm-control", "2"): "broadcast-unlimited",
        ("exos.ports.unused-up", "3"): "administratively-enabled",
    }
    assert {key: found[key]["state"] for key in expected if key in found} == expected
    # Port 10 is disabled with the singular form the device prints.
    assert ("exos.ports.unused-up", "10") not in found
    assert report["rule_status"]["exos.ports.unused-up"]["status"] == "evaluated"
    # STP domain membership through the default s0 auto-bind is not inferred.
    assert [gap["rule_id"] for gap in report["coverage"]["actionable_gaps"]] == ["exos.l2.bpdu-guard"]
    assert code == cli.EXIT_INCOMPLETE
