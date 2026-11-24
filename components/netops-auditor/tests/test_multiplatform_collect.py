"""Transport replays from the Admin redacted baseline captures after O3.

The IOSv/IOL XE ACL baselines are 15.9/17.x running-config captures, NX-OS is
9.3(12), EOS is 4.36.1F, and the Junos VLAN composite is from 26.2R1.7.
The alternate EOS header, privilege and auxiliary answers and injected failure
bytes are derived for this test. Junos mask examples are in junos_junos_config.
"""
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from types import ModuleType
import json
import sqlite3
import sys

import pytest

from netops_auditor import cli, collect, engine, platforms, query
from netops_auditor.store import Store
from test_channel_events_on_failure import (
    Credential, DEVICE, HOST, KEY_BLOB, KEY_PIN, LOGIN, TENANT, write_inventory, write_vault,
)

FIXTURES = Path(__file__).resolve().parents[2] / "netops-admin/tests/fixtures"
EXOS_CAPTURES = FIXTURES.parents[2] / "netops-helper/tests/fixtures/real/exos"
CAPTURES = {
    "cisco_ios": ("ios_ios_access_control/iosv/admin-show-running-config__baseline.txt", "interface"),
    "cisco_xe": ("ios_ios_access_control/iolxe/admin-show-running-config__bound.txt", "interface"),
    "cisco_nxos": ("nxos_9_3_12/show-running-config__baseline.txt", "interface"),
    "arista_eos": ("eos_4_36_1F/show-running-config__baseline.txt", "interface"),
    "juniper_junos_els": ("junos_26_2R1_7/show-configuration-display-set__junos_vlan_admin-composite.txt", "interfaces"),
}
CANARY = "AuditU0CanaryValue"
SHORT = "~Z~"


def payload(alias):
    return (FIXTURES / CAPTURES[alias][0]).read_bytes()


class Transport:
    def __init__(self, primary, body, answers=None):
        self.answers = {
            primary: body, "show privilege": b"Current privilege level is 15\n",
            "show parser view": b"Current view is 'root'\n", **(answers or {}),
        }
        self.commands = []
        self.rc = 0
        self.stderr = b""

    def scan(self, command, **kwargs):
        return CompletedProcess(command, 0, f"{HOST} ssh-ed25519 {KEY_BLOB}\n".encode(), b"")

    def run(self, command, **kwargs):
        assert "StrictHostKeyChecking=yes" in command
        strict_path = next(item.partition("=")[2] for item in command if item.startswith("UserKnownHostsFile="))
        assert Path(strict_path).read_text().endswith(KEY_BLOB + "\n")
        key = command[-1]
        self.commands.append(key)
        answer = self.answers.get(key, b"")
        if answer is None:
            raise TimeoutExpired(command, kwargs["timeout"])
        return CompletedProcess(command, self.rc, answer, self.stderr)

    def collect(self, alias, **kwargs):
        return collect.collect_ssh(
            DEVICE, platforms.catalog_key(alias), HOST, 22, kwargs.pop("credential", Credential()),
            kwargs.pop("pin", KEY_PIN),
            run=self.run, keyscan=self.scan, inventory_platform=alias, **kwargs,
        )

    def install(self, monkeypatch):
        scan, run_command = collect.hostkey.scan, collect.ssh.run_command
        monkeypatch.setattr(collect.hostkey, "scan", lambda *a, **kw: scan(*a, **dict(kw, run=self.scan)))
        monkeypatch.setattr(collect.ssh, "run_command", lambda *a, **kw: run_command(*a, **dict(kw, run=self.run)))


def _primary(alias):
    return collect.JUNOS_CONFIG if alias.startswith("juniper") else collect.RUNNING


@pytest.mark.parametrize("alias", CAPTURES)
def test_real_exec_framing_and_sections(alias):
    answer = payload(alias)
    # The composite contains a global apply-groups. Supply an expanded answer
    # derived by removing the apply-groups line from the captured composite.
    expanded = b"\n".join(line for line in answer.split(b"\n") if b" apply-groups " not in line
                           and not line.startswith(b"set apply-groups "))
    transport = Transport(_primary(alias), answer, {collect.JUNOS_INHERITANCE: expanded})
    snapshot, events = transport.collect(alias)
    assert snapshot.metadata.complete
    assert snapshot.metadata.inventory_platform == alias
    assert snapshot.metadata.visibility(CAPTURES[alias][1]).state == "visible"
    assert events[0].response_bytes == len(payload(alias))
    assert all(event.outcome == "ok" for event in events)
    assert all(command.startswith("show ") for command in transport.commands)
    if alias.startswith("cisco"):
        assert "show snmp user" in transport.commands


def test_eos_echo_and_exec_header():
    data = payload("arista_eos").replace(b"! Command: show running-config", b"! Command: show running-config at line 1", 1)
    snapshot, _ = Transport(collect.RUNNING, b"> show running-config\r\n" + data).collect("arista_eos")
    assert snapshot.metadata.complete


def test_pin_is_checked_before_ssh_transport():
    transport = Transport(collect.RUNNING, payload("cisco_ios"))
    with pytest.raises(collect.CollectError):
        transport.collect("cisco_ios", pin="SHA256:" + "A" * 43)
    assert transport.commands == []


@pytest.mark.parametrize(("suffix", "reason"), [(b"\n--Mo\x1b[7mre--\n", "pager"), (b"", "truncated")])
def test_pager_and_truncation(suffix, reason):
    data = payload("cisco_ios").split(b"\nend")[0] + suffix
    snapshot, events = Transport(collect.RUNNING, data).collect("cisco_ios")
    assert snapshot.metadata.integrity_reason == reason
    assert [event.outcome for event in events] == ["failed"]


def test_refusal_with_rc_zero_does_not_expose_cli_echo():
    transport = Transport(collect.RUNNING, ("Line has invalid autocommand " + CANARY + SHORT).encode())
    with pytest.raises(collect.CollectError, match="permission-denied") as error:
        transport.collect("cisco_ios")
    assert CANARY not in str(error.value) + repr(error.value.events)
    assert SHORT not in str(error.value) + repr(error.value.events)


@pytest.mark.parametrize(("rc", "stderr", "reason"), [
    (1, b"% Command authorization failed\n", "permission-denied"),
    (1, b"% Invalid input detected\n", "command-unavailable"),
    (1, b"Unrecognized diagnostic\n", "transport-error"),
    (255, b"operator@192.0.2.9: Permission denied (publickey,password).\n", "authentication-failed"),
    (255, b"Permission denied (publickey).\nConnection reset by peer\n", "transport-error"),
])
def test_exec_failure_reasons_use_the_command_or_final_ssh_diagnostic(rc, stderr, reason):
    transport = Transport(collect.RUNNING, b"")
    transport.rc = rc
    transport.stderr = CANARY.encode() + b"\n" + stderr
    with pytest.raises(collect.CollectError, match=reason) as error:
        transport.collect("cisco_ios")
    assert CANARY not in str(error.value) + repr(error.value.events)


def test_exec_auxiliary_authentication_failure_is_incomplete():
    visibility = collect._auxiliary_visibility("authentication-failed")
    assert visibility == platforms.SectionVisibility(platforms.INCOMPLETE, "authentication-failed")


def test_auxiliary_timeout_leaves_main_evidence_and_empty_auxiliary_is_valid():
    transport = Transport(collect.RUNNING, payload("cisco_ios"), {"show snmp user": None})
    snapshot, events = transport.collect("cisco_ios")
    assert snapshot.metadata.visibility("interface").state == "visible"
    assert snapshot.metadata.visibility("snmp users").reason == "timeout"
    assert any(event.outcome == "failed" for event in events)
    transport.answers["show snmp user"] = b""
    snapshot, _ = transport.collect("cisco_ios")
    assert snapshot.metadata.auxiliary["snmp users"] == ""
    assert snapshot.metadata.visibility("snmp users").state == "visible"


def test_byte_limit_at_transport_boundary():
    transport = Transport(collect.RUNNING, payload("cisco_ios"))
    with pytest.raises(collect.CollectError, match="output-limit"):
        transport.collect("cisco_ios", max_response_bytes=128)


def test_junos_masks_quotes_and_deactivation():
    data = (FIXTURES / "junos_junos_config/config_display_set_ro.out").read_bytes()
    data += b'set snmp description "ACCESS-DENIED"\nset snmp v3 key /* SECRET-DATA */;\n'
    data += b'set interfaces ge-0/0/1 description "two words"\ndeactivate interfaces ge-0/0/1\n'
    snapshot, _ = Transport(collect.JUNOS_CONFIG, data).collect("juniper_junos_els")
    assert snapshot.metadata.visibility("system").reason == "access-denied"
    tree = platforms.PLATFORMS["juniper-junos"].parser.parse(snapshot.text)
    assert not tree.matching("interfaces")
    assert tree.matching("snmp", "description")[0].tokens[-1] == "ACCESS-DENIED"
    assert tree.matching("snmp", "v3")[0].masked


def test_junos_unresolved_inheritance_keeps_direct_data():
    base = payload("juniper_junos_els")
    direct = b"\n".join(line for line in base.split(b"\n") if not line.startswith(b"set apply-groups "))
    data = direct + b"set interfaces ge-0/0/1 apply-groups sample\n"
    transport = Transport(collect.JUNOS_CONFIG, data, {collect.JUNOS_INHERITANCE: None})
    snapshot, _ = transport.collect("juniper_junos_els")
    assert snapshot.metadata.visibility("interfaces").reason == "inheritance-unresolved"
    assert snapshot.metadata.visibility("system").state == "visible"


def install_catalog(tmp_path, monkeypatch, platform, callback, status=None, *, applies=None, partial=False):
    spec = platforms.PLATFORMS[platform]
    qualified = "netops_auditor." + spec.checks_module
    name = "u0_test_check"
    engine.available_platforms()
    monkeypatch.setitem(sys.modules, qualified, ModuleType(qualified))
    monkeypatch.setattr(engine, "_CHECKS", dict(engine._CHECKS))
    monkeypatch.setattr(engine, "_AUDITOR", dict(engine._AUDITOR))
    monkeypatch.setattr(engine, "_STATUS", dict(engine._STATUS))
    engine.check(name, status=status, audit_context=True, applies=applies, partial=partial)(callback)
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    for file in engine.CATALOG_DIR.glob("*.json"):
        (catalog / file.name).write_bytes(file.read_bytes())
    identifier = platform + ".mgmt.u0-test"
    document = {"rules": [{"id": identifier, "version": 1, "check": name, "class": "fakt", "severity": "medium",
                           "title": "Test rule", "remediation": "Test remediation", "sections": [],
                           "evidence_fields": ["count"]}]}
    (catalog / (platform + ".json")).write_text(json.dumps(document))
    monkeypatch.setattr(engine, "CATALOG_DIR", catalog)
    return identifier


def sample_hit(tree, context):
    yield {"object_key": "management", "section": "interface", "line": 1, "evidence": {"count": 1}}


def invoke(tmp_path, transport, alias="cisco_ios", extra=()):
    inventory = write_inventory(tmp_path)
    document = json.loads(inventory.read_text())
    device = document["devices"][0]
    device["platform"] = alias
    device["auditor"]["required_sections"] = [CAPTURES[alias][1]]
    inventory.write_text(json.dumps(document))
    return cli.main(["collect", "--inventory", str(inventory), "--vault", str(write_vault(tmp_path)), "--tenant", TENANT,
                     "--device", DEVICE, "--store", str(tmp_path / "audit.sqlite"), "--json", *extra])


@pytest.mark.parametrize(("suffix", "reason"), [(b"--More--\n", "pager"), (b"", "truncated")])
def test_incomplete_exec_preserves_the_previous_finding(tmp_path, monkeypatch, capsys, suffix, reason):
    rule_id = "cisco-ios.time.no-ntp-source"
    data = payload("cisco_ios")
    transport = Transport(collect.RUNNING, data)
    transport.install(monkeypatch)
    assert invoke(tmp_path, transport) in (cli.EXIT_OK, cli.EXIT_INCOMPLETE)
    initial_report = json.loads(capsys.readouterr().out)
    assert initial_report["rule_status"][rule_id]["status"] == engine.EVALUATED
    initial, = [item for item in initial_report["findings"] if item["rule_id"] == rule_id]

    transport.answers[collect.RUNNING] = data.partition(b"\nend")[0] + b"\n" + suffix
    assert invoke(tmp_path, transport) == cli.EXIT_INCOMPLETE
    report = json.loads(capsys.readouterr().out)
    marker, = report["findings"]
    assert marker["rule_id"] == "cisco-ios.snapshot.incomplete"
    assert marker["evidence"]["reason"] == reason
    assert report["rule_status"][rule_id]["status"] == engine.NOT_EVALUATED
    assert any(item["fingerprint"] == initial["fingerprint"] for item in report["not_evaluated"])
    with Store(tmp_path / "audit.sqlite") as store:
        listing = query.list_findings(store, TENANT, DEVICE, now=datetime.now(timezone.utc))
    assert listing["gone"] == ()
    observed = {item["fingerprint"]: item["state"] for item in listing["findings"]}
    assert observed[initial["fingerprint"]] == engine.NOT_EVALUATED
    assert marker["fingerprint"] in observed


@pytest.mark.parametrize("alias", CAPTURES)
def test_collect_json_and_store_through_real_catalog(tmp_path, monkeypatch, capsys, alias):
    platform = platforms.catalog_key(alias)
    identifier = install_catalog(tmp_path, monkeypatch, platform, sample_hit)
    prefix = b'set system login user example authentication encrypted-password ' if alias.startswith("juniper") else b'username example secret 0 '
    data = payload(alias)
    line = prefix + CANARY.encode() + b"\n" + prefix + SHORT.encode() + b"\n"
    if alias.startswith(("juniper", "cisco_nxos")):
        data += line
    else:
        data = data.replace(b"\nend", b"\n" + line + b"end")
    transport = Transport(_primary(alias), data)
    transport.install(monkeypatch)
    assert invoke(tmp_path, transport, alias) == 0
    out, err = capsys.readouterr()
    report = json.loads(out)
    assert report["findings"][0]["rule_id"] == identifier
    offline = tmp_path / "input.conf"
    offline.write_bytes(data)
    assert cli.main(["run", "--platform", platform, "--device", DEVICE, "--tenant", TENANT, "--config", str(offline),
                     "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"][0]["fingerprint"] == report["findings"][0]["fingerprint"]
    assert cli.main(["run", "--platform", platform, "--device", DEVICE, "--tenant", TENANT, "--config", str(offline),
                     "--sarif"]) == 0
    sarif = capsys.readouterr().out
    with closing(sqlite3.connect(tmp_path / "audit.sqlite")) as db:
        assert db.execute("SELECT count(*) FROM runs").fetchone() == (1,)
        assert db.execute("SELECT count(*) FROM channel_events").fetchone() == (len(transport.commands),)
        storage = "\n".join(db.iterdump())
    serialized = ""
    if alias == "cisco_ios":
        import asyncio
        from fastmcp import Client
        from netops_auditor import mcp_server

        monkeypatch.setattr(mcp_server, "_CONFIGURATION", None)
        mcp_server.configure({
            mcp_server.STORE_VARIABLE: str(tmp_path / "audit.sqlite"),
            mcp_server.TENANT_VARIABLE: TENANT,
            mcp_server.CATALOG_VARIABLE: platform,
        })

        async def read_findings():
            async with Client(mcp_server.mcp) as client:
                result = await client.call_tool("list_findings", {"device": DEVICE})
                return result.content[0].text

        serialized = asyncio.run(read_findings())
        assert json.loads(serialized)["findings"][0]["fingerprint"] == report["findings"][0]["fingerprint"]
    for value in (CANARY, SHORT):
        assert value not in out + err + sarif + storage + serialized


def test_pinned_fortios_session_handles_split_pager(tmp_path, monkeypatch, capsys):
    import test_fortinet_ssh_collection as replay

    # Insert before the client's generic answer line (the last write of a command echo).
    before, marker, after = replay.FAKE_CLIENT.rpartition(
        '    sys.stdout.buffer.write(command + b"\\r\\r\\n" + body.replace(')
    assert marker and after.count("\n") == 2
    script = before + r"""
    if command == b"show":
        import time
        first, _, rest = body.partition(b"\n")
        sys.stdout.buffer.write(command + b"\r\n" + first + b"\r\n--Mo")
        sys.stdout.buffer.flush()
        time.sleep(0.005)
        sys.stdout.buffer.write(b"re--")
        sys.stdout.buffer.flush()
        assert sys.stdin.buffer.read(1) == b" "
        sys.stdout.buffer.write(b"\r\x1b[K" + rest.replace(b"\n", b"\r\n") + prompt)
        sys.stdout.buffer.flush()
        continue
""" + marker + after
    monkeypatch.setattr(replay, "FAKE_CLIENT", script)
    replay._fake_client(tmp_path, monkeypatch, replay.CONSOLE, replay.DUMP.encode())
    rc, events = replay._cli_collect(tmp_path, host_key=replay.PUBLIC_KEY)
    out, err = capsys.readouterr()
    assert rc == 0 and not err
    assert [row[1] for row in events] == ["ok"] * len(replay.fortios_audit.SSH_STEPS)
    assert "--More--" not in out


# Proof of the defaults a device does not print. The account lines below are
# derived for this test from the captures above; the session answers are the Admin
# captures with the measured account name replaced by the test login.
VERIFIED = "verified-profile"
EXOS_CLEAN = (Path(__file__).resolve().parent / "fixtures/exos_clean.conf").read_bytes()
EXOS_GOLDEN_ROOT = Path(__file__).resolve().parents[2] / "netops-admin/tests/golden/exos/33.7.1.6-patch1-11"
EXOS_GOLDEN = EXOS_GOLDEN_ROOT / "X440G2-12p-10G4"
EXOS_CAPTURE = (EXOS_GOLDEN / "show-configuration/X440-G2-12p-10G4__normal-redacted-secrets.conf").read_bytes()
# The X440-G2 capture comes from an interactive session and starts with its paging notice;
# an ssh exec read has no such line, so the dump below is the capture without it.
EXOS_DUMP = EXOS_CAPTURE.split(b"\n", 1)[1]
EXOS_VERSION_ANSWER = (EXOS_GOLDEN / "show-version/X440-G2-12p-10G4__normal.conf").read_bytes()
X435_GOLDEN = EXOS_GOLDEN_ROOT / "X435-8P-4S"
X435_DUMP = (X435_GOLDEN / "show-configuration/X435-8P-4S__normal-redacted-secrets.conf").read_bytes().split(b"\n", 1)[1]
X435_VERSION = (X435_GOLDEN / "show-version/X435-8P-4S__normal.conf").read_bytes()
X435_SWITCH = (EXOS_CAPTURES / "x435-8p-4s_33.7.1.6/switch.txt").read_bytes()
X440_SWITCH = (EXOS_CAPTURES / "x440g2-12p-10g4_33.7.1.6/switch.txt").read_bytes()
VM_DUMP = (EXOS_CAPTURES / "switch-config-20261118/vm-running.out").read_bytes().split(b"\n", 1)[1]
VM_VERSION = (EXOS_CAPTURES / "exosvm_33.6.1.14/version.txt").read_bytes()
VM_SWITCH = (EXOS_CAPTURES / "exosvm_33.6.1.14/switch.txt").read_bytes()
EXOS_SHOW = "show configuration"
EXOS_VERSION = "show version"
EXOS_SWITCH = "show switch"
FULL = {"cisco_nxos": "network-admin", "arista_eos": "network-admin", "juniper_junos_els": "super-user"}
READ_ONLY = {"cisco_nxos": "network-operator", "arista_eos": "network-operator", "juniper_junos_els": "read-only"}
NXOS_ACCOUNTS = (FIXTURES / "nxos_9_3_12/show-user-account.txt").read_bytes()
JUNOS_SUPER_USER = (FIXTURES / "junos_26_2R1_7/show-cli-authorization__admin-super-user.txt").read_bytes()
JUNOS_READ_ONLY = (FIXTURES / "junos_26_2R1_7/show-cli-authorization__ro-read-only.txt").read_bytes()
EOS_PRIVILEGE = {True: (FIXTURES / "eos_4_36_1F/show-privilege__after-enable.txt").read_bytes(),
                 False: (FIXTURES / "eos_4_36_1F/show-privilege__priv1.txt").read_bytes()}
EOS_SESSIONS = (FIXTURES / "eos_eos_port_maintenance/show-users-detail__ssh.json").read_bytes()
EOS_SESSION_COMMAND = "show users detail | json"
JUNOS_DENIED = (FIXTURES / "junos_junos_config/config_display_set_ro.out").read_bytes().split(b"\n")[5] + b"\n"


class MeasuredAdmin(Credential):
    login = "netops-admin"


def session(alias, full=True, login=LOGIN):
    """The device's answer about the role of the session that reads the snapshot."""
    if alias == "cisco_nxos":
        measured = b"netops-admin" if full else b"netops-ro"
        return {"show user-account": NXOS_ACCOUNTS.replace(b"user:%s\n" % measured, b"user:%s\n" % login.encode())}
    if alias == "arista_eos":
        role = FULL[alias] if full else READ_ONLY[alias]
        data = EOS_SESSIONS.replace(b"netops-admin", login.encode()).replace(b"network-admin", role.encode())
        return {"show privilege": EOS_PRIVILEGE[full], EOS_SESSION_COMMAND: data}
    if full:
        return {"show cli authorization": JUNOS_SUPER_USER.replace(b"'netops-admin'", b"'%s'" % login.encode())}
    return {"show cli authorization": JUNOS_READ_ONLY.replace(b"'netops-ro   '", b"'%s   '" % login.encode())}


def with_account(alias, role, login=LOGIN):
    data = payload(alias)
    if alias == "cisco_nxos":
        line = b"username %s password 5 SECRET-PASSWORD-SENTINEL  role %s\n" % (login.encode(), role.encode())
        return data.replace(b"\nhostname ", b"\n" + line + b"hostname ", 1)
    if alias == "arista_eos":
        line = b"username %s role %s secret sha512 <REDIGOVANO>\n" % (login.encode(), role.encode())
        return data.replace(b"\nno aaa root\n", b"\nno aaa root\n" + line, 1)
    return data.replace(b"\nset vlans ", b"\nset system login user %s class %s\nset vlans " % (login.encode(), role.encode()), 1)


def expanded(alias, data):
    # Junos: the capture with its apply-groups lines removed, so no inheritance stays unresolved.
    if alias.startswith("juniper"):
        data = b"\n".join(line for line in data.split(b"\n") if b" apply-groups " not in line
                          and not line.startswith(b"set apply-groups "))
    return data


def exec_collect(alias, data, answers=None, **kwargs):
    transport = Transport(_primary(alias), expanded(alias, data), session(alias) if answers is None else answers)
    return transport.collect(alias, **kwargs)[0]


def proven(metadata):
    return {name for name, item in metadata.sections.items() if item.reason == VERIFIED}


@pytest.mark.parametrize("alias", FULL)
def test_complete_snapshot_of_a_full_session_proves_every_family(alias):
    snapshot = exec_collect(alias, payload(alias))
    families = platforms.PLATFORMS[platforms.catalog_key(alias)].parser.SECTIONS
    assert snapshot.metadata.complete
    if alias.startswith("juniper"):
        # vlans is the last hierarchy: it shows the end of the output, but a cut inside it looks the same.
        assert families - {"vlans"} <= proven(snapshot.metadata)
        assert snapshot.metadata.visibility("vlans") == platforms.SectionVisibility("visible", "content")
    else:
        assert families <= proven(snapshot.metadata)
    assert snapshot.metadata.visibility("session role").reason == "auxiliary-output"


def _version_unknown(alias, data):
    if alias == "cisco_nxos":
        return data.replace(b"\nversion 9.3(12) ", b"\nversion unknown ", 1)
    if alias == "arista_eos":
        return data.replace(b"(cEOSLab, EOS-4.36.1F-48405728.4361F (engineering build))", b"(cEOSLab)", 1)
    return b"\n".join(line for line in data.split(b"\n") if not line.startswith(b"set version "))


def _routing_options_denied(data):
    # Finding 4: the routing-options lines of the full output replaced by the denied line of the RO capture.
    lines = data.split(b"\n")
    first = next(index for index, line in enumerate(lines) if line.startswith(b"set routing-options "))
    kept = [line for line in lines if not line.startswith(b"set routing-options ")]
    return b"\n".join(kept[:first]) + b"\n" + JUNOS_DENIED + b"\n".join(kept[first:])


@pytest.mark.parametrize("alias", FULL)
@pytest.mark.parametrize("case", ["read-only session", "full record but restricted session", "other session user",
                                  "no session answer", "unknown version"])
def test_strict_conditions_leave_the_families_unproven(alias, case):
    data, answers = payload(alias), session(alias)
    if case == "read-only session":
        answers = session(alias, full=False)
    elif case == "full record but restricted session":
        # Finding 3: a local record of a full role with the login, and a session with a restricted role.
        data, answers = with_account(alias, FULL[alias]), session(alias, full=False)
    elif case == "other session user":
        answers = session(alias, login="someone-else")
    elif case == "no session answer":
        answers = dict.fromkeys(session(alias), b"")
    else:
        assert case == "unknown version"
        data = _version_unknown(alias, data)
        assert data != payload(alias)
    snapshot = exec_collect(alias, data, answers)
    assert snapshot.metadata.complete
    assert proven(snapshot.metadata) == set()


def test_junos_hidden_path_leaves_the_families_unproven():
    # ACCESS-DENIED paths are Junos output, so this strict condition has only the Junos case.
    alias = "juniper_junos_els"
    answers = session(alias)
    # The full account record as well, so the denied line is the only reason left to refuse the proof.
    data = _routing_options_denied(expanded(alias, with_account(alias, FULL[alias])))
    assert JUNOS_DENIED in data and b"set routing-options router-id" not in data
    assert proven(exec_collect(alias, data.replace(JUNOS_DENIED, b""), answers).metadata)
    snapshot = exec_collect(alias, data, answers)
    assert snapshot.metadata.complete
    assert proven(snapshot.metadata) == set()


@pytest.mark.parametrize("ambiguous", [False, True], ids=["restricted", "another-session-with-full-role"])
def test_restricted_eos_role_at_privilege_15_has_no_proof(ambiguous):
    alias = "arista_eos"
    answers = session(alias, full=False)
    answers["show privilege"] = EOS_PRIVILEGE[True]
    if ambiguous:
        data = json.loads(answers[EOS_SESSION_COMMAND])
        row = next(iter(data["vtys"].values()))
        data["vtys"]["9999"] = {**row, "role": FULL[alias]}
        answers[EOS_SESSION_COMMAND] = json.dumps(data).encode()
    data = with_account(alias, FULL[alias])
    transport = Transport(_primary(alias), data, answers)
    snapshot, _ = transport.collect(alias)
    assert not proven(snapshot.metadata)
    assert transport.commands[-1] == EOS_SESSION_COMMAND


def test_nxos_output_cut_after_the_first_interface_block_is_not_proven():
    # Finding 1: the output ends after the first finished interface block; line vty and the rest are missing.
    data = with_account("cisco_nxos", FULL["cisco_nxos"])
    first = data.index(b"\ninterface ")
    cut = data[:data.index(b"\ninterface ", first + 1) + 1]
    assert b"\nline vty" not in cut and cut.endswith(b"\n")
    snapshot = exec_collect("cisco_nxos", cut)
    assert snapshot.metadata.complete
    assert proven(snapshot.metadata) == set()
    assert snapshot.metadata.visibility("line vty").reason != VERIFIED


def test_junos_output_cut_after_the_super_user_class_is_not_proven():
    # Finding 1: the measured account netops-admin reads; the output ends after its class line.
    data = expanded("juniper_junos_els", payload("juniper_junos_els"))
    line = b"set system login user netops-admin class super-user\n"
    cut = data[:data.index(line) + len(line)]
    snapshot = exec_collect("juniper_junos_els", cut, {"show cli authorization": JUNOS_SUPER_USER},
                            credential=MeasuredAdmin())
    assert snapshot.metadata.complete
    assert proven(snapshot.metadata) == set()
    assert snapshot.metadata.visibility("vlans").reason != VERIFIED
    full = exec_collect("juniper_junos_els", data, {"show cli authorization": JUNOS_SUPER_USER},
                        credential=MeasuredAdmin())
    assert "system" in proven(full.metadata)


def exos_collect(data, version=EXOS_VERSION_ANSWER, switch=X440_SWITCH):
    transport = Transport(EXOS_SHOW, data, {EXOS_VERSION: version, EXOS_SWITCH: switch})
    snapshot, events = transport.collect("exos")
    return snapshot, events, transport


def test_full_exos_dump_with_a_known_version_proves_each_finished_module():
    snapshot, events, transport = exos_collect(EXOS_DUMP)
    assert transport.commands == [EXOS_SHOW, EXOS_VERSION, EXOS_SWITCH]
    assert [event.outcome for event in events] == ["ok", "ok", "ok"]
    assert snapshot.metadata.complete and snapshot.metadata.inventory_platform == "exos"
    modules = platforms.PLATFORMS["exos"].parser.parse(EXOS_DUMP.decode()).modules
    assert modules[0] == "devmgr" and modules[-1] == "vpex"
    assert proven(snapshot.metadata) == set(modules) - {"vpex"} >= {"devmgr", "vlan", "aaa", "snmpMaster", "telnetd"}
    # vpex shows the end of the dump; a cut inside it would leave the same shape.
    assert snapshot.metadata.visibility("vpex").state == "unproven"
    assert snapshot.text == EXOS_DUMP.decode()


@pytest.mark.parametrize("model_in_version", [False, True])
def test_full_x435_dump_proves_modules_before_upm(model_in_version):
    version = X435_VERSION.replace(b"800979-00-09", b"800979-00-10").replace(b"33.7.1.6", b"33.6.1.14")
    if model_in_version:
        model_line = next(line for line in X435_SWITCH.splitlines() if line.startswith(b"System Type:"))
        version += model_line + b"\n"
    else:
        version = X435_VERSION
    snapshot, _, transport = exos_collect(X435_DUMP, version, X435_SWITCH)
    assert snapshot.metadata is not None and snapshot.metadata.complete
    assert transport.commands == ([EXOS_SHOW, EXOS_VERSION] if model_in_version
                                  else [EXOS_SHOW, EXOS_VERSION, EXOS_SWITCH])
    modules = platforms.PLATFORMS["exos"].parser.parse(X435_DUMP.decode()).modules
    assert modules[-1] == "upm"
    assert proven(snapshot.metadata) == set(modules[:-1])
    assert snapshot.metadata.visibility("upm").state == "unproven"


def test_exos_vm_dump_proves_modules_before_vpex():
    snapshot, _, _ = exos_collect(VM_DUMP, VM_VERSION, VM_SWITCH)
    assert snapshot.metadata.complete
    assert snapshot.metadata.tree.modules[-1] == "vpex"
    assert proven(snapshot.metadata) == set(snapshot.metadata.tree.modules[:-1])


def test_exos_vpex_comment_inside_upm_does_not_prove_the_end():
    upm = b"# Module upm configuration.\n#\n"
    prefix, header, _ = EXOS_DUMP.partition(upm)
    assert header == upm
    data = prefix + header + b"create upm profile audit-example\n# Module vpex configuration.\n.\n"
    snapshot, _, _ = exos_collect(data)
    assert snapshot.metadata is not None
    assert not proven(snapshot.metadata)
    assert snapshot.metadata.integrity_reason == "truncated"


# The real Image line names the release twice ("33.7.1.6 33.7.1.6-patch1-11"); both shortened to three parts.
EXOS_VERSION_UNREADABLE = EXOS_VERSION_ANSWER.replace(b"version 33.7.1.6 33.7.1.6-", b"version 33.7.1 33.7.1-")


@pytest.mark.parametrize("version", [b"", b"Switch          : 800614-00-22 0000Z-00002 Rev 22\n",
                                     EXOS_VERSION_UNREADABLE],
                         ids=["empty", "no-image-line", "unreadable-version"])
def test_exos_dump_without_a_known_version_is_not_proven(version):
    # Finding 2: the same complete dump, but the software version is not known.
    assert EXOS_VERSION_UNREADABLE != EXOS_VERSION_ANSWER
    snapshot, events, _ = exos_collect(EXOS_DUMP, version)
    assert snapshot.metadata.integrity_reason == "unknown-end-format"
    assert events[0].outcome == "ok"


def test_failed_exos_version_read_keeps_an_incomplete_snapshot():
    transport = Transport(EXOS_SHOW, X435_DUMP, {EXOS_VERSION: None})
    snapshot, events = transport.collect("exos")
    assert snapshot.metadata.integrity_reason == "unknown-end-format"
    assert snapshot.text == X435_DUMP.decode()
    assert [event.outcome for event in events] == ["ok", "failed"]


@pytest.mark.parametrize("data", [
    EXOS_CLEAN.split(b"disable telnet\n")[0],
    EXOS_DUMP.split(b"disable telnet\n")[0],
    EXOS_DUMP.split(b"#\n# Module vpex configuration.\n")[0],
    EXOS_DUMP + b"\n--More--\n",
    # A cut inside a quoted value on a line boundary: the dump no longer parses.
    EXOS_DUMP.split(b'configure snmp sysLocation "')[0] + b'configure snmp sysLocation "Exam\n',
], ids=["clean-before-disable-telnet", "capture-before-disable-telnet", "capture-before-vpex", "pager",
        "cut-inside-a-quoted-value"])
def test_exos_dump_without_its_end_is_not_proven(data):
    # Finding 1: a cut on a line boundary, or a pager mark, leaves the dump without proof.
    assert data.endswith(b"\n")
    snapshot, _, _ = exos_collect(data)
    assert snapshot.metadata is not None and not snapshot.metadata.complete
    assert not proven(snapshot.metadata)
    assert snapshot.metadata.integrity_reason == ("pager" if b"--More--" in data else "truncated")


@pytest.mark.parametrize("data", [
    EXOS_CAPTURE,
    EXOS_DUMP.split(b"# Module vlan configuration.\n", 1)[1],
    EXOS_DUMP.replace(b"configure sys-recovery-level switch reset\n",
                      b"configure sys-recovery-level switch reset\nError: Permission denied\n"),
    EXOS_DUMP.replace(b"configure sys-recovery-level switch reset\n", b"configure sys-recovery-level switch reset\x08\n"),
    EXOS_DUMP.rstrip(b"\n"),
], ids=["preamble", "no-devmgr-header", "error-line", "control-byte", "no-final-newline"])
def test_exos_dump_without_a_clean_frame_keeps_an_incomplete_snapshot(data):
    snapshot, _, _ = exos_collect(data)
    assert snapshot.text == data.decode()
    assert snapshot.metadata is not None and not snapshot.metadata.complete
    assert snapshot.metadata.integrity_reason == "truncated"


def test_refused_exos_read_takes_no_snapshot():
    transport = Transport(EXOS_SHOW, EXOS_DUMP, {EXOS_VERSION: EXOS_VERSION_ANSWER})
    transport.rc = 254
    with pytest.raises(collect.CollectError, match="exit status 254"):
        transport.collect("exos")
    assert transport.commands == [EXOS_SHOW]


def proof_status(tree, context):
    if context.visibility("snmpMaster").reason != VERIFIED:
        return engine.NOT_EVALUATED, context.visibility("snmpMaster").reason
    return engine.EVALUATED, ""


def proof_hit(tree, context):
    if context.visibility("snmpMaster").reason == VERIFIED:
        yield {"object_key": "default", "section": "snmpMaster", "line": 1, "evidence": {"count": 1}}


def invoke_exos(tmp_path):
    inventory = write_inventory(tmp_path)
    document = json.loads(inventory.read_text())
    document["devices"][0]["platform"] = "exos"
    document["devices"][0]["auditor"]["required_sections"] = ["vlan"]
    inventory.write_text(json.dumps(document))
    return cli.main(["collect", "--inventory", str(inventory), "--vault", str(write_vault(tmp_path)),
                     "--tenant", TENANT, "--device", DEVICE, "--store", str(tmp_path / "audit.sqlite"),
                     "--json"])


@pytest.mark.parametrize("version,switch", [
    (None, X435_SWITCH),
    (X435_VERSION, None),
    (X435_VERSION, b"System Type: X999-8P\n"),
])
def test_exos_unknown_end_leaves_all_rules_not_evaluated(tmp_path, monkeypatch, capsys, version, switch):
    transport = Transport(EXOS_SHOW, X435_DUMP, {EXOS_VERSION: version, EXOS_SWITCH: switch})
    transport.install(monkeypatch)
    assert invoke_exos(tmp_path) == cli.EXIT_INCOMPLETE
    report = json.loads(capsys.readouterr().out)
    marker, = report["findings"]
    assert marker["rule_id"] == "exos.snapshot.incomplete"
    assert marker["evidence"]["reason"] == "unknown-end-format"
    assert {report["rule_status"][rule.id]["status"] for rule in engine.load_catalog("exos")} == {engine.NOT_EVALUATED}


@pytest.mark.parametrize("suffix", [b"", b"--More--\n"], ids=["cut", "pager"])
def test_exos_cut_before_disable_telnet_marks_the_real_rule_not_evaluated(tmp_path, monkeypatch, capsys, suffix):
    data = EXOS_CLEAN.split(b"disable telnet\n")[0]
    assert data != EXOS_CLEAN and b"# Module telnetd configuration." in data
    transport = Transport(EXOS_SHOW, data + suffix, {EXOS_VERSION: EXOS_VERSION_ANSWER, EXOS_SWITCH: X440_SWITCH})
    transport.install(monkeypatch)
    code = invoke_exos(tmp_path)
    report = json.loads(capsys.readouterr().out)
    assert report["rule_status"]["exos.mgmt.telnet-enabled"]["status"] == engine.NOT_EVALUATED
    assert code == cli.EXIT_INCOMPLETE
    assert not report["evaluation_complete"]
    assert [item["rule_id"] for item in report["findings"]] == ["exos.snapshot.incomplete"]


def test_exos_ssh_collect_gives_rules_the_proof_and_offline_run_does_not(tmp_path, monkeypatch, capsys):
    identifier = install_catalog(tmp_path, monkeypatch, "exos", proof_hit, proof_status)
    transport = Transport(EXOS_SHOW, EXOS_DUMP, {EXOS_VERSION: EXOS_VERSION_ANSWER, EXOS_SWITCH: X440_SWITCH})
    transport.install(monkeypatch)
    assert invoke_exos(tmp_path) == 0
    report = json.loads(capsys.readouterr().out)
    assert [item["rule_id"] for item in report["findings"]] == [identifier]
    assert report["rule_status"][identifier]["status"] == engine.EVALUATED
    offline = tmp_path / "exos.conf"
    offline.write_bytes(EXOS_DUMP)
    assert cli.main(["run", "--platform", "exos", "--device", DEVICE, "--tenant", TENANT, "--config",
                     str(offline), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []
