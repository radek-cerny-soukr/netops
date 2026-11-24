import asyncio
import hashlib
import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops_auditor import cli, collect, engine, fortios_audit, l1_fortios, platforms
from test_cli import audit, clean_text, write_config
from test_channel_events_on_failure import (
    DEVICE, HOST, KEY_BLOB, KEY_PIN, TENANT, Credential, targeted, write_inventory, write_vault,
)


FIXTURES = Path(__file__).parent / "fixtures"
LEGACY = tuple("fortios.mgmt." + name for name in (
    "default-admin-account", "admin-no-trusthost", "netops-safeguard-leftover",
))


class Replay:
    def __init__(self, show, responses):
        self.answers = {"show": show, **responses}
        self.sent = []

    def run(self, command, **options):
        self.sent.append(command)
        if command in self.answers:
            answer = self.answers[command]
        elif command.startswith("show "):
            answer = targeted(self.answers["show"].encode(), command).decode()
        else:
            answer = ""
        return SimpleNamespace(rc=0, stdout=answer.encode(), stderr=b"")


def collect_replay(show, responses):
    session = Replay(show, responses)
    snapshot, events = collect.collect_ssh(DEVICE, "fortios", HOST, 22, Credential(), KEY_PIN, session=session)
    assert session.sent == [step.command for step in fortios_audit.SSH_STEPS]
    assert len(events) == len(session.sent)
    assert snapshot.sha256 == hashlib.sha256(snapshot.text.encode()).hexdigest()
    return snapshot, events


def evaluate_legacy(tree, metadata=None):
    rules = tuple(rule for rule in engine.load_catalog("fortios") if rule.id in LEGACY)
    context = platforms.AuditContext(snapshot=metadata, live=metadata is not None)
    return engine.evaluate(tree, TENANT, DEVICE, rules, context=context)


def table(text, section):
    return targeted(text.encode(), "show " + section).decode()


def fixture(name):
    return (FIXTURES / "fortios-taxonomy" / name).read_text()


def test_identical_headers_do_not_prove_the_ro_table():
    ro, full = fixture("ro.txt"), fixture("full-redacted.txt")
    assert {row for row in ro.splitlines() if row.startswith("config ")} == {
        row for row in full.splitlines() if row.startswith("config ")
    }
    for name in (fortios_audit.ADMIN, *fortios_audit.SAFEGUARDS[:3]):
        assert table(ro, name) != table(full, name)
    for text, verified in ((ro, False), (full, True)):
        readback = table(text, fortios_audit.ADMIN)
        snapshot, _ = collect_replay(text, {
            "show system admin": readback,
            "show full-configuration system admin": readback,
        })
        hits, states = evaluate_legacy(snapshot.metadata.tree, snapshot.metadata)
        if verified:
            assert all(states[key] == (engine.EVALUATED, "") for key in LEGACY)
            offline, _ = evaluate_legacy(l1_fortios.parse(text))
            assert {hit.fingerprint() for hit in hits} == {hit.fingerprint() for hit in offline}
            assert {hit.rule_id for hit in hits} == set(LEGACY)
        else:
            assert all(states[key] == (engine.NOT_EVALUATED, "admin-visibility-unproven") for key in LEGACY[:2])
            assert states[LEGACY[2]] == (engine.NOT_EVALUATED, "visibility-unproven")
            assert [hit.rule_id for hit in hits] == [LEGACY[2]]


def test_scope_mismatch_and_cli_refusal_leave_proven_safeguards():
    full = fixture("full-redacted.txt")
    snapshot, events = collect_replay(full, {
        "show system admin": table(fixture("ro.txt"), fortios_audit.ADMIN),
        "show full-configuration system api-user": "Permission denied\nCANARY-CLI-SECRET\n",
    })
    meta = snapshot.metadata
    assert meta.visibility(fortios_audit.ADMIN) == platforms.SectionVisibility(platforms.INCOMPLETE, "truncated")
    assert meta.visibility("system api-user") == platforms.SectionVisibility(platforms.HIDDEN, "permission-denied")
    assert any(event.outcome == "failed" and event.request.endswith("system api-user") for event in events)
    assert "CANARY-CLI-SECRET" not in repr((events, meta))
    hits, states = evaluate_legacy(meta.tree, meta)
    assert all(states[key] == (engine.NOT_EVALUATED, "admin-visibility-unproven") for key in LEGACY[:2])
    assert states[LEGACY[2]] == (engine.NOT_EVALUATED, "permission-denied")
    assert [hit.rule_id for hit in hits] == [LEGACY[2]]


def test_missing_admin_retains_the_legacy_reason():
    text = 'config system global\n    set hostname "fw-example"\nend\n'
    snapshot, _ = collect_replay(text, {"show system admin": "Permission denied\n"})
    _, states = evaluate_legacy(snapshot.metadata.tree, snapshot.metadata)
    assert all(states[key] == (engine.NOT_EVALUATED, "section-missing: system admin") for key in LEGACY[:2])


def test_offline_cli_preserves_missing_admin_section(tmp_path, capsys):
    full = clean_text()
    path = write_config(tmp_path, full.replace(table(full, fortios_audit.ADMIN), ""))
    code, out, err = audit(capsys, path, as_json=True)
    assert not err
    status = json.loads(out)["rule_status"][LEGACY[0]]
    assert (status["status"], status["reason"]) == ("not-evaluated", "section-missing: system admin")
    assert code == cli.EXIT_INCOMPLETE


def test_cli_store_and_mcp_cover_ro_gaps_and_visible_objects(tmp_path, monkeypatch, capsys):
    pytest.importorskip("fastmcp")
    from fastmcp import Client
    from netops_auditor import mcp_server

    path = write_inventory(tmp_path)
    inventory = json.loads(path.read_text())
    inventory["devices"][0]["host_key"] = "ssh-ed25519 " + KEY_BLOB
    path.write_text(json.dumps(inventory))
    replay = Replay(fixture("ro.txt"), {"show full-configuration system api-user": "Permission denied\n"})
    monkeypatch.setattr(collect, "fortinet_session", lambda *a, **kw: nullcontext(replay))
    db = tmp_path / "audit.sqlite"
    rc = cli.main(["collect", "--inventory", str(path), "--vault", str(write_vault(tmp_path)),
                   "--device", DEVICE, "--tenant", TENANT, "--store", str(db), "--json"])
    result, stderr = capsys.readouterr()
    assert rc == cli.EXIT_INCOMPLETE
    assert not stderr
    decoded = json.loads(result)
    assert decoded["rule_status"][LEGACY[0]]["reason"] == "admin-visibility-unproven"
    assert any(finding["rule_id"] == LEGACY[2] for finding in decoded["findings"])
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", None)
    mcp_server.configure({mcp_server.STORE_VARIABLE: str(db), mcp_server.TENANT_VARIABLE: TENANT,
                          mcp_server.CATALOG_VARIABLE: "fortios"})

    async def read_store():
        async with Client(mcp_server.mcp) as client:
            status = await client.call_tool("audit_status", {"platform": "fortios"})
            findings = await client.call_tool("findings_summary", {"device": DEVICE, "rule_id": LEGACY[2]})
            return json.loads(status.content[0].text), json.loads(findings.content[0].text)

    status, findings = asyncio.run(read_store())
    scope = status["devices"][0]["coverage"]
    assert scope["counts"]["not_evaluated"] >= 3
    assert findings["returned"] == 1
