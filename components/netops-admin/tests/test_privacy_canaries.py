from __future__ import annotations

import base64
import dataclasses
import json
import re
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import request_bytes
from fake_exos import FIRMWARE, FakeExos
from fake_fortios import FakeFortiOS
from test_execute import make_runtime as make_fortios_runtime
from test_execute_exos import make_runtime as make_exos_runtime

from netops_admin import cli, enrollment, execute, notify, readiness
from netops_admin.config import DEFAULT_LIMITS
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

SECRETS = {
    "fortios admin password": "SH2K7cAdm+Hash/q8Zr2Lw=",
    "fortios local user passwd": "K7cUsr+Passwd/T4g9Vx=",
    "fortios ipsec psksecret": "K7cPsk+Secret/Mn3Yh0=",
    "fortios certificate password": "K7cCrt+Pass/Rb5Wq1=",
    "fortios certificate private key": "K7cKey+Body/Jd8Pz6Ns=",
    "fortios snmp community": "K7cSnmp+Comm/Hx2Fe7=",
    "fortios radius secret": "K7cRad+Secret/Gw4Kt3=",
    "fortios tacacs key": "K7cTac+Key/Zq6Uc9=",
    "fortios wifi passphrase": "K7cWifi+Phrase/Lp1Ba5=",
    "fortios secret on the planned object": "K7cObj+Passwd/Sy7Rk2=",
    "exos account hash": "K7cExos+Acct/Dm7Hs2=",
    "exos radius shared-secret": "K7cExRad+Secret/Vn9Qe4=",
    "exos tacacs shared-secret": "K7cExTac+Secret/Cy3Jw8=",
    "exos snmp community": "K7cExSnmp+Comm/Tk5Rg1=",
    "vault password": "K7cVault+Password/Xe2Nf6=",
    "vault private key": "K7cVault+KeyBody/Wu4Ld0=",
    "free text": "K7cFree+Text/Pq3Mz8=",
}
ATTRIBUTE = "k7c attr Vb8Wn"
PORT_STRING = "K7cVb8Wn"
ATTRIBUTE_VALUES = {"text attribute": "Vb8Wn"}
TOPIC = "k7c_topic_0001"
LIMITS = dict(DEFAULT_LIMITS, changes_per_device_per_hour=100, changes_per_day=100, rejections_per_hour=100)

FORTIOS_SECTIONS = "".join((
    'config system admin\n    edit "netops-rw"\n        set password ENC %s\n    next\nend\n'
    % SECRETS["fortios admin password"],
    'config user local\n    edit "k7c-user"\n        set type password\n        set passwd ENC %s\n    next\nend\n'
    % SECRETS["fortios local user passwd"],
    'config vpn ipsec phase1-interface\n    edit "k7c-tunnel"\n        set psksecret ENC %s\n    next\nend\n'
    % SECRETS["fortios ipsec psksecret"],
    'config vpn certificate local\n    edit "k7c-cert"\n        set password ENC %s\n'
    '        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----\n%s\n-----END ENCRYPTED PRIVATE KEY-----"\n'
    '    next\nend\n' % (SECRETS["fortios certificate password"], SECRETS["fortios certificate private key"]),
    'config system snmp community\n    edit 1\n        set name "%s"\n    next\nend\n' % SECRETS["fortios snmp community"],
    'config user radius\n    edit "k7c-radius"\n        set server "192.0.2.50"\n        set secret ENC %s\n    next\nend\n'
    % SECRETS["fortios radius secret"],
    'config user tacacs+\n    edit "k7c-tacacs"\n        set server "192.0.2.51"\n        set key ENC %s\n    next\nend\n'
    % SECRETS["fortios tacacs key"],
    'config wireless-controller vap\n    edit "k7c-vap"\n        set passphrase ENC %s\n    next\nend\n'
    % SECRETS["fortios wifi passphrase"],
))
EXOS_LINES = "".join((
    'configure radius mgmt-access primary server 192.0.2.50 1812 client-ip 192.0.2.2 vr VR-Mgmt'
    ' shared-secret encrypted "%s"\n' % SECRETS["exos radius shared-secret"],
    'configure tacacs primary server 192.0.2.51 49 client-ip 192.0.2.2 vr VR-Mgmt'
    ' shared-secret encrypted "%s"\n' % SECRETS["exos tacacs shared-secret"],
    "configure snmpv3 add community %s name %s user v1v2c_ro\n"
    % (SECRETS["exos snmp community"], SECRETS["exos snmp community"]),
))
NOTIFICATION_HEADERS = {"Accept-Encoding", "Connection", "Content-Length", "Content-Type", "Host", "User-Agent",
                        "Title", "Priority", "Tags"}


class CanaryFortiOS(FakeFortiOS):
    def __init__(self):
        super().__init__()
        self.object_secret = False

    def snapshot(self):
        head, rest = super().snapshot().split("end\n", 1)
        if self.object_secret:
            rest = rest.replace('    edit "spare-host"\n', '    edit "spare-host"\n        set passwd ENC %s\n'
                                % SECRETS["fortios secret on the planned object"], 1)
        return head + "end\n" + FORTIOS_SECTIONS + rest

    def query(self, command):
        if command == "show system admin":
            return "config system admin\n" + "".join(
                '    edit "%s"\n        set comments "account"\n        set password ENC %s\n    next\n'
                % (name, SECRETS["fortios admin password"]) for name in self.admins) + "end\n"
        return super().query(command)


class CanaryExos(FakeExos):
    def __init__(self):
        super().__init__()
        self.account_hashes = {name: SECRETS["exos account hash"] for name in self.accounts}

    def snapshot(self):
        return super().snapshot().replace("#\n# Module vlan configuration.\n",
                                          EXOS_LINES + "#\n# Module vlan configuration.\n", 1)


def forms(value: str) -> set:
    raw = value.encode("utf-8")
    found = {value, value.rsplit("/", 1)[-1].rstrip("="), raw.hex(), raw.hex().upper(),
             urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value), json.dumps(value)[1:-1]}
    for shift in range(3):
        bits = (shift + len(raw)) * 8
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            text = encode(b"\0" * shift + raw).decode("ascii")
            found.add(text[-(-shift * 8 // 6):bits // 6])
    return found


def leaks(texts: dict, needles: dict) -> list:
    return sorted({(label, where) for where, text in texts.items() for label, value in needles.items()
                   if any(form in text for form in forms(value))})


def collected(tmp_path, *extra) -> dict:
    texts = {}
    for path in sorted(tmp_path.rglob("*")):
        if path.is_file() and "inputs" not in path.relative_to(tmp_path).parts:
            texts[str(path.relative_to(tmp_path))] = path.read_bytes().decode("utf-8", "replace")
    for name, text in extra:
        texts[name] = text
    return texts


class _Collector(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.captured.append({"path": self.path, "headers": dict(self.headers.items()),
                                     "body": body.decode("utf-8", "replace")})
        self.send_response(self.server.statuses.pop(0) if self.server.statuses else 200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def ntfy(tmp_path, monkeypatch):
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Collector)
    server.captured, server.statuses = [], []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    topic = tmp_path / "inputs" / "ntfy.env"
    topic.parent.mkdir(parents=True, exist_ok=True)
    topic.write_text("NTFY_TOPIC=%s\n" % TOPIC)
    try:
        yield server, notify.NtfyNotifier("http://127.0.0.1:%d" % server.server_address[1], str(topic), 5)
    finally:
        server.shutdown()
        server.server_close()


def notification_texts(server) -> str:
    return json.dumps(server.captured, sort_keys=True)


def assert_notifications_carry_only_operational_fields(server, device, runtime):
    records = {record["change_id"]: record for record in runtime.store.records()}
    assert server.captured
    for sent in server.captured:
        assert sent["path"] == "/" + TOPIC
        assert set(sent["headers"]) <= NOTIFICATION_HEADERS, sent["headers"]
        lines = sent["body"].split("\n")
        result = re.fullmatch(r"result: ([a-z-]+)", lines[0]).group(1)
        record = records[re.fullmatch(r"change: ([0-9a-f]{32})", lines[2]).group(1)]
        assert sent["headers"]["Title"] == "netops-admin %s %s" % (device, result)
        assert sent["headers"]["Priority"] == notify.PRIORITIES.get(result, "4")
        assert sent["headers"]["Tags"] == "netops"
        plan = record["plan"]
        assert lines[1] == "operation: %s %s %s" % (plan["op"], plan["table"], plan["key"])
        assert lines[3] == "request: %s" % record["request_id"]
        for line in lines[4:]:
            assert (line == "reason: %s" % record["reason"]
                    or re.fullmatch(r"other administrator sessions were active: [0-9]+", line)
                    or re.fullmatch(r"differences: [0-9]+", line)
                    or line == "the device is blocked until a person investigates it"), line


class Journal:
    def __init__(self):
        self.entries = []

    def keep(self, label, action):
        try:
            value = action()
        except Rejected as exc:
            self.entries.append(json.dumps([label, "rejected", exc.reasons, str(exc)]))
            return None
        self.entries.append(json.dumps([label, value], default=str))
        return value

    def text(self) -> str:
        return "\n".join(self.entries)


def fortios_request(**fields):
    fields.setdefault("reason", "reason %s" % SECRETS["free text"])
    fields.setdefault("user_request", "please %s" % SECRETS["free text"])
    fields.setdefault("changes", {"subnet": "192.0.2.30/32", "comment": ATTRIBUTE})
    return parse_request(request_bytes(**fields))


def exos_request(**fields):
    fields.setdefault("table", "vlan")
    fields.setdefault("key", "guest")
    fields.setdefault("changes", {"tag": 3999, "description": ATTRIBUTE})
    return fortios_request(**fields)


def enrolled(runtime, name, notifier, base):
    status = base / "export-status.json"

    def fresh():
        status.write_text(json.dumps({"updated_at": time.time(), "pending": 0, "audit_file": runtime.config.audit_file}))

    fresh()
    runtime.config = dataclasses.replace(runtime.config, export_status_file=str(status), limits=dict(LIMITS))
    runtime.notifier = notifier
    runtime.store.clear_enrollment(name)
    return fresh


def apply_with(device, runtime, name, request, hook):
    blocks = []

    def on_apply(fake, lines):
        blocks.append(lines)
        fake.fail_at_line = None
        if len(blocks) == 2:
            hook(fake, lines)

    device.on_apply = on_apply
    try:
        return execute.apply(runtime, name, request)
    finally:
        device.on_apply = None


def fortios_paths(base, notifier, journal):
    device = CanaryFortiOS()
    runtime = make_fortios_runtime(base, device)
    fresh = enrolled(runtime, "lab", notifier, base)
    keep = journal.keep
    device.foreign_session_users = ["k7c-other"]
    assert keep("enroll", lambda: enrollment.run(runtime, "lab", "192.0.2.254/32"))["enrollment"] == "valid"
    assert keep("doctor", lambda: readiness.doctor(runtime, "lab"))["firmware"]
    assert keep("preview", lambda: execute.preview(runtime, "lab", fortios_request(request_id="k7c-preview-1")))["result"] == "ready"
    created = keep("create", lambda: execute.apply(runtime, "lab", fortios_request(request_id="k7c-create-1")))
    assert created["result"] == "confirmed"
    keep("repeat", lambda: execute.apply(runtime, "lab", fortios_request(request_id="k7c-create-1")))
    keep("preview known", lambda: execute.preview(runtime, "lab", fortios_request(request_id="k7c-create-1")))
    updated = keep("update", lambda: execute.apply(runtime, "lab", fortios_request(
        op="update", key="spare-host", changes={"comment": ATTRIBUTE}, request_id="k7c-update-1")))
    assert updated["result"] == "confirmed"
    assert keep("undo", lambda: execute.undo(runtime, updated["change_id"], "undo %s" % SECRETS["free text"]))["result"] == "confirmed"
    assert keep("delete", lambda: execute.apply(runtime, "lab", fortios_request(
        op="delete", key="new-host", changes={}, request_id="k7c-delete-1")))["result"] == "confirmed"
    keep("referenced", lambda: execute.apply(runtime, "lab", fortios_request(
        op="delete", key="srv-web", changes={}, request_id="k7c-reject-1")))
    keep("name in use", lambda: execute.apply(runtime, "lab", fortios_request(key="srv-web", request_id="k7c-reject-2")))
    keep("protected", lambda: execute.preview(runtime, "lab", fortios_request(key="all", request_id="k7c-reject-3")))

    failed = keep("refused line", lambda: apply_with(device, runtime, "lab", fortios_request(
        key="k7c-host-2", request_id="k7c-fail-1"), lambda fake, lines: setattr(fake, "fail_at_line", 3)))
    device.fail_at_line = None
    assert failed["result"] == "reverted"
    fresh()
    lied = keep("check identity", lambda: apply_with(device, runtime, "lab", fortios_request(
        key="k7c-host-3", request_id="k7c-check-1"),
        lambda fake, lines: setattr(fake, "check_override", {"k7c-host-3": {"subnet": "192.0.2.98 255.255.255.255"}})))
    device.check_override = None
    assert lied["result"] == "reverted"
    device.drop_comment = True
    mismatch = keep("mismatch", lambda: execute.apply(runtime, "lab", fortios_request(
        op="update", key="spare-host", changes={"comment": ATTRIBUTE + " two"}, request_id="k7c-mismatch-1")))
    device.drop_comment = False
    assert mismatch["reason"] == "prediction mismatch" and mismatch["postcheck_differences"]
    fresh()
    foreign = keep("secret on the object", lambda: apply_with(device, runtime, "lab", fortios_request(
        op="update", key="spare-host", changes={"comment": ATTRIBUTE + " three"}, request_id="k7c-foreign-1"),
        lambda fake, lines: setattr(fake, "object_secret", True)))
    assert foreign["result"] in ("revert-failed", "reverted", "unknown") and foreign["differences"]
    keep("blocked apply", lambda: execute.apply(runtime, "lab", fortios_request(key="k7c-host-4", request_id="k7c-blocked-1")))
    keep("blocked preview", lambda: execute.preview(runtime, "lab", fortios_request(key="k7c-host-4", request_id="k7c-blocked-2")))
    keep("blocked doctor", lambda: readiness.doctor(runtime, "lab"))
    keep("unblock", lambda: execute.unblock(runtime, "lab", "checked %s" % SECRETS["free text"]))
    keep("outside the profile", lambda: execute.apply(runtime, "lab", fortios_request(
        op="update", key="spare-host", changes={"comment": "x"}, request_id="k7c-outside-1")))
    keep("outside the profile preview", lambda: execute.preview(runtime, "lab", fortios_request(
        op="update", key="spare-host", changes={"comment": "x"}, request_id="k7c-outside-2")))
    device.object_secret = False
    device.addresses["spare-host"]["comment"] = "unused"
    fresh()
    kept = keep("foreign value on the object", lambda: apply_with(device, runtime, "lab", fortios_request(
        op="update", key="spare-host", changes={"subnet": "192.0.2.77/32"}, request_id="k7c-foreign-2"),
        lambda fake, lines: fake.addresses["spare-host"].__setitem__("comment", ATTRIBUTE + " foreign")))
    assert kept["result"] == "revert-failed" and any("Vb8Wn" in item for item in kept["differences"])
    keep("unblock after the foreign value", lambda: execute.unblock(runtime, "lab", "checked"))
    device.addresses["spare-host"]["comment"] = "unused"
    fresh()
    return device, runtime, fresh


def fortios_failures(device, runtime, fresh, server, journal):
    keep = journal.keep
    server.statuses.append(500)
    undelivered = keep("undelivered", lambda: execute.apply(runtime, "lab", fortios_request(key="k7c-host-5", request_id="k7c-notify-1")))
    assert undelivered["notification"] == "failed"
    keep("refused while undelivered", lambda: execute.apply(runtime, "lab", fortios_request(key="k7c-host-6", request_id="k7c-notify-2")))
    assert keep("notify retry", lambda: execute.notify_retry(runtime, undelivered["change_id"]))["notification"] == "sent"

    def crash(fake, lines):
        fake._run(lines)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        apply_with(device, runtime, "lab", fortios_request(key="k7c-host-7", request_id="k7c-crash-1"), crash)
    keep("refused while running", lambda: execute.apply(runtime, "lab", fortios_request(key="k7c-host-8", request_id="k7c-crash-2")))
    settled = keep("recover", lambda: execute.recover(runtime, "lab"))
    assert [record["result"] for record in settled] == ["reverted"]
    fresh()
    lost = keep("unreadable after the change", lambda: apply_with(device, runtime, "lab", fortios_request(
        key="k7c-host-9", request_id="k7c-unreadable-1"), lambda fake, lines: setattr(fake, "unreadable", True)))
    device.unreadable = False
    assert lost["result"] == "unknown"
    keep("doctor while blocked", lambda: readiness.doctor(runtime, "lab"))
    device.stitches.clear()
    device.triggers.clear()
    device.actions.clear()
    device.addresses.pop("k7c-host-9", None)
    keep("unblock again", lambda: execute.unblock(runtime, "lab", "checked"))
    broken = runtime.store.requests / "k7c-broken-0001.json"
    broken.write_text("{\"request_id\": ")
    keep("unreadable journal", lambda: execute.apply(runtime, "lab", fortios_request(key="k7c-host-10", request_id="k7c-broken-0001")))
    keep("unreadable journal preview", lambda: execute.preview(runtime, "lab", fortios_request(key="k7c-host-10", request_id="k7c-broken-0001")))
    broken.unlink()
    keep("status", lambda: execute.refresh_delivery(runtime, runtime.store.operation(undelivered["change_id"])))
    device.unreadable = True
    keep("unreadable before the change", lambda: execute.apply(runtime, "lab", fortios_request(key="k7c-host-11", request_id="k7c-unreadable-2")))
    keep("unreadable doctor", lambda: readiness.doctor(runtime, "lab"))
    device.unreadable = False


def write_config(path, runtime, name, platform, **device):
    fields = {"platform": platform, "address": "192.0.2.1", "host_key_fingerprint": "SHA256:" + "A" * 43,
              "vault": str(path.parent / "vault.json"), "credential": "rw", "check_credential": "ro"}
    fields.update(device)
    path.write_text(json.dumps({"version": 1, "state_dir": runtime.config.state_dir,
                                "audit_file": runtime.config.audit_file, "devices": {name: fields}}))
    return str(path)


def test_fortios_secrets_reach_no_output_journal_audit_or_notification(tmp_path, ntfy, capsys):
    server, notifier = ntfy
    journal = Journal()
    device, runtime, fresh = fortios_paths(tmp_path / "fortios", notifier, journal)
    fortios_failures(device, runtime, fresh, server, journal)
    config = write_config(tmp_path / "inputs" / "admin.json", runtime, "lab", "fortios")
    changes = sorted(path.stem for path in runtime.store.operations.glob("*.json"))
    for change_id in changes:
        journal.entries.append(json.dumps(cli.main(["status", "--config", config, "--change-id", change_id])))
    journal.entries.append(json.dumps(cli.main(["status", "--config", config, "--request-id", "k7c-create-1"])))
    printed = capsys.readouterr()
    texts = collected(tmp_path, ("results", journal.text()), ("stdout", printed.out), ("stderr", printed.err),
                      ("notifications", notification_texts(server)))
    assert leaks(texts, SECRETS) == []
    audit_and_notifications = {name: text for name, text in texts.items()
                               if name in ("notifications",) or name.endswith("audit.jsonl")}
    assert len(audit_and_notifications) == 2
    assert leaks(audit_and_notifications, ATTRIBUTE_VALUES) == []
    assert ATTRIBUTE in texts["results"]
    assert_notifications_carry_only_operational_fields(server, "lab", runtime)
    assert any("other administrator sessions were active: 1" in sent["body"] for sent in server.captured)
    assert any("enrollment-preflight" in sent["headers"]["Title"] for sent in server.captured)


def test_exos_secrets_reach_no_output_journal_audit_or_notification(tmp_path, ntfy, capsys):
    server, notifier = ntfy
    journal = Journal()
    keep = journal.keep
    base = tmp_path / "exos"
    device = CanaryExos()
    runtime = make_exos_runtime(base, device)
    fresh = enrolled(runtime, "sw", notifier, base)
    assert keep("enroll", lambda: enrollment.run(runtime, "sw", "3998"))["enrollment"] == "valid"
    assert keep("doctor", lambda: readiness.doctor(runtime, "sw"))["firmware"]
    assert keep("preview", lambda: execute.preview(runtime, "sw", exos_request(request_id="k7c-preview-1")))["result"] == "ready"
    assert keep("create", lambda: execute.apply(runtime, "sw", exos_request(request_id="k7c-create-1")))["result"] == "confirmed"
    port = keep("display string", lambda: execute.apply(runtime, "sw", exos_request(
        table="ports", op="update", key="11", changes={"display-string": PORT_STRING}, request_id="k7c-port-1")))
    assert port["result"] == "confirmed"
    assert keep("undo", lambda: execute.undo(runtime, port["change_id"], "back"))["result"] == "confirmed"
    keep("protected", lambda: execute.apply(runtime, "sw", exos_request(op="delete", key="Default", changes={},
                                                                         request_id="k7c-reject-1")))
    keep("tag in use", lambda: execute.apply(runtime, "sw", exos_request(key="other", changes={"tag": 10},
                                                                          request_id="k7c-reject-2")))
    device.drop_description = True
    mismatch = keep("mismatch", lambda: execute.apply(runtime, "sw", exos_request(
        op="update", key="spare", changes={"description": ATTRIBUTE + " two"}, request_id="k7c-mismatch-1")))
    device.drop_description = False
    assert mismatch["reason"] == "prediction mismatch"
    fresh()
    failed = keep("refused line", lambda: apply_with(device, runtime, "sw", exos_request(
        key="guest2", changes={"tag": 3997}, request_id="k7c-fail-1"), lambda fake, steps: setattr(fake, "fail_at_line", 1)))
    device.fail_at_line = None
    assert failed["result"] == "reverted"
    device.unsaved = False
    fresh()
    lost = keep("unreadable after the change", lambda: apply_with(device, runtime, "sw", exos_request(
        key="guest3", changes={"tag": 3996}, request_id="k7c-unreadable-1"), lambda fake, steps: setattr(fake, "unreadable", True)))
    device.unreadable = False
    assert lost["result"] == "unknown"
    keep("blocked", lambda: execute.apply(runtime, "sw", exos_request(key="guest4", changes={"tag": 3995},
                                                                       request_id="k7c-blocked-1")))
    keep("doctor while blocked", lambda: readiness.doctor(runtime, "sw"))
    config = write_config(tmp_path / "inputs" / "admin.json", runtime, "sw", "exos", firmware=FIRMWARE,
                          accounts=["admin", "netops-rw"])
    for path in sorted(runtime.store.operations.glob("*.json")):
        journal.entries.append(json.dumps(cli.main(["status", "--config", config, "--change-id", path.stem])))
    printed = capsys.readouterr()
    texts = collected(tmp_path, ("results", journal.text()), ("stdout", printed.out), ("stderr", printed.err),
                      ("notifications", notification_texts(server)))
    assert leaks(texts, SECRETS) == []
    audit_and_notifications = {name: text for name, text in texts.items()
                               if name == "notifications" or name.endswith("audit.jsonl")}
    assert len(audit_and_notifications) == 2
    assert leaks(audit_and_notifications, ATTRIBUTE_VALUES) == []
    assert_notifications_carry_only_operational_fields(server, "sw", runtime)


def test_mcp_answers_carry_no_secret(tmp_path, ntfy, monkeypatch):
    fastmcp = pytest.importorskip("fastmcp")
    import asyncio

    from netops_admin import mcp_server

    server, notifier = ntfy
    device = CanaryFortiOS()
    base = tmp_path / "mcp"
    runtime = make_fortios_runtime(base, device)
    enrolled(runtime, "lab", notifier, base)
    enrollment.run(runtime, "lab", "192.0.2.254/32")
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", runtime.config)
    monkeypatch.setattr(mcp_server, "build_runtime", lambda config: runtime)

    def call(name, arguments):
        async def run():
            async with fastmcp.Client(mcp_server.mcp) as client:
                result = await client.call_tool(name, arguments, raise_on_error=False)
                return json.dumps([result.structured_content, [getattr(item, "text", "") for item in result.content]])
        return asyncio.run(run())

    def arguments(**fields):
        body = {"device": "lab", "table": "firewall address", "op": "create", "key": "k7c-mcp-host",
                "changes": {"subnet": "192.0.2.40/32", "comment": ATTRIBUTE}, "reason": SECRETS["free text"],
                "user_request": SECRETS["free text"], "request_id": "k7c-mcp-0001"}
        body.update(fields)
        return body

    answers = [call("admin_doctor", {"device": "lab"}), call("admin_preview", arguments()),
               call("admin_apply", arguments()), call("admin_status", {"request_id": "k7c-mcp-0001"})]
    device.drop_comment = True
    answers.append(call("admin_apply", arguments(op="update", key="spare-host", changes={"comment": ATTRIBUTE},
                                                 request_id="k7c-mcp-0002")))
    device.drop_comment = False
    answers.append(call("admin_apply", arguments(op="delete", key="srv-web", changes={}, request_id="k7c-mcp-0003")))
    device.object_secret = True
    answers.append(call("admin_preview", arguments(op="update", key="spare-host", changes={"comment": "x"},
                                                   request_id="k7c-mcp-0004")))
    answers.append(call("admin_apply", arguments(op="update", key="spare-host", changes={"comment": "x"},
                                                 request_id="k7c-mcp-0005")))
    device.unreadable = True
    answers.append(call("admin_doctor", {"device": "lab"}))
    answers.append(call("admin_apply", arguments(key="k7c-mcp-host2", request_id="k7c-mcp-0006")))
    assert '"confirmed"' in answers[2] and '"prediction mismatch"' in answers[4] and "passwd" in answers[7]
    texts = collected(tmp_path, ("answers", "\n".join(answers)), ("notifications", notification_texts(server)))
    assert leaks(texts, SECRETS) == []


def test_offline_plan_and_verify_print_no_secret(tmp_path, capsys):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    device = CanaryFortiOS()
    clean = inputs / "fortios.conf"
    clean.write_text(device.snapshot())
    device.object_secret = True
    dirty = inputs / "fortios-object-secret.conf"
    dirty.write_text(device.snapshot())
    broken = inputs / "fortios-broken.conf"
    text = clean.read_text()
    broken.write_text(text[:text.index(SECRETS["fortios certificate private key"]) + 4])
    exos = inputs / "exos.conf"
    exos.write_text(CanaryExos().snapshot())
    requests = {}
    for name, fields in {
        "update": {"op": "update", "key": "spare-host", "changes": {"comment": ATTRIBUTE}},
        "delete": {"op": "delete", "key": "srv-web", "changes": {}},
        "vlan": {"table": "vlan", "key": "guest", "changes": {"tag": 3999, "description": ATTRIBUTE}},
    }.items():
        requests[name] = inputs / ("%s.json" % name)
        requests[name].write_bytes(request_bytes(reason=SECRETS["free text"], user_request=SECRETS["free text"], **fields))
    outputs = []

    def run(*argv):
        code = cli.main([str(item) for item in argv])
        printed = capsys.readouterr()
        outputs.append(printed.out + printed.err)
        return code, printed.out

    code, plan = run("plan", "--platform", "fortios", "--snapshot", clean, "--request", requests["update"])
    assert code == 0
    (tmp_path / "plan.json").write_text(plan)
    assert run("plan", "--platform", "fortios", "--snapshot", dirty, "--request", requests["update"])[0] == cli.EXIT_REJECTED
    assert "passwd" in outputs[-1]
    assert run("plan", "--platform", "fortios", "--snapshot", clean, "--request", requests["delete"])[0] == cli.EXIT_REJECTED
    assert run("plan", "--platform", "fortios", "--snapshot", broken, "--request", requests["update"])[0] == cli.EXIT_REJECTED
    assert "snapshot is cut off" in outputs[-1]
    assert run("verify", "--plan", tmp_path / "plan.json", "--snapshot", dirty, "--expect", "before")[0] == cli.EXIT_MISMATCH
    assert run("verify", "--plan", tmp_path / "plan.json", "--snapshot", clean, "--expect", "before")[0] == 0
    assert run("plan", "--platform", "exos", "--firmware", FIRMWARE, "--snapshot", exos, "--request", requests["vlan"])[0] == 0
    assert run("plan", "--platform", "exos", "--snapshot", exos, "--request", requests["vlan"])[0] == cli.EXIT_REJECTED
    texts = collected(tmp_path, ("outputs", "\n".join(outputs)))
    assert leaks(texts, SECRETS) == []


def closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.mark.parametrize("mode", [0o600, 0o644])
def test_vault_secrets_stay_out_of_refusals_of_the_real_device_access(tmp_path, capsys, mode):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    vault = inputs / "vault.json"
    vault.write_text(json.dumps({"version": 2, "credentials": {
        "rw": {"kind": "password", "login": "netops-rw", "value": SECRETS["vault password"]},
        "ro": {"kind": "ssh-key", "login": "netops-check",
               "value": "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n"
                        % SECRETS["vault private key"]},
    }}))
    vault.chmod(mode)
    config = inputs / "admin.json"
    config.write_text(json.dumps({"version": 1, "state_dir": str(tmp_path / "state"),
                                  "audit_file": str(tmp_path / "audit" / "audit.jsonl"), "devices": {"lab": {
                                      "platform": "fortios", "address": "127.0.0.1", "port": closed_port(),
                                      "host_key_fingerprint": "SHA256:" + "A" * 43, "vault": str(vault),
                                      "credential": "rw", "check_credential": "ro"}}}))
    request = inputs / "request.json"
    request.write_bytes(request_bytes(reason=SECRETS["free text"], user_request=SECRETS["free text"]))
    outputs = []
    for argv in (["doctor", "--config", config, "--device", "lab"],
                 ["preview", "--config", config, "--device", "lab", "--request", request],
                 ["apply", "--config", config, "--device", "lab", "--request", request]):
        code = cli.main([str(item) for item in argv])
        printed = capsys.readouterr()
        outputs.append(printed.out + printed.err)
        assert code in (cli.EXIT_NOT_READY, cli.EXIT_REJECTED)
    assert "credentials" in outputs[0]
    texts = collected(tmp_path, ("outputs", "\n".join(outputs)))
    assert leaks(texts, SECRETS) == []


def test_the_detector_finds_every_encoding_of_a_canary():
    for value in SECRETS.values():
        raw = value.encode("utf-8")
        shown = [value, json.dumps({"value": value}), value.replace("/", "\\/"), raw.hex(), raw.hex().upper(),
                 urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value)]
        for shift in range(3):
            shown.append(base64.b64encode(b"ab"[:shift] + raw + b"tail").decode("ascii"))
            shown.append(base64.urlsafe_b64encode(b"xy"[:shift] + raw).decode("ascii"))
        for text in shown:
            assert leaks({"probe": "before %s after" % text}, {"canary": value}) == [("canary", "probe")], text
    assert leaks({"probe": "nothing here"}, SECRETS) == []
