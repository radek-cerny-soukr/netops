from __future__ import annotations

import json
import threading
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fake_fortios import FakeFortiOS
from test_execute import SECRET, make_runtime, request

from netops_admin import execute, notify
from netops_admin.errors import Rejected


def test_message_is_ascii_and_carries_no_free_text(tmp_path):
    device = FakeFortiOS()
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
    title, body = notify.message(record)
    assert title == "netops-admin lab confirmed"
    assert title.isascii()
    assert "create firewall address new-host" in body
    assert SECRET not in body and "new host" not in body


def test_topic_is_read_only_in_its_expected_shape(tmp_path):
    good = tmp_path / "good.env"
    good.write_text("OTHER=1\nNTFY_TOPIC=\"abcdefgh_12345\"\n")
    assert notify._topic(str(good)) == "abcdefgh_12345"
    bad = tmp_path / "bad.env"
    bad.write_text("NTFY_TOPIC=has spaces and ; semicolons\n")
    assert notify._topic(str(bad)) is None
    assert notify._topic(str(tmp_path / "missing.env")) is None


def test_notifier_reports_failure_without_raising(tmp_path, monkeypatch):
    topic = tmp_path / "topic.env"
    topic.write_text("NTFY_TOPIC=abcdefgh_12345\n")

    def unreachable(*args, **kwargs):
        raise notify.subprocess.TimeoutExpired(["fixture-worker"], 1)

    monkeypatch.setattr(notify.subprocess, "run", unreachable)
    sender = notify.NtfyNotifier("https://ntfy.example", str(topic), 1, x509_strict=False)
    assert sender({"device": "lab", "result": "confirmed"}) == "failed"
    assert not (sender._context().verify_flags & notify.ssl.VERIFY_X509_STRICT)
    assert notify.NtfyNotifier("https://ntfy.example", str(topic), 1)._context().verify_flags & notify.ssl.VERIFY_X509_STRICT


def test_failed_notification_does_not_change_the_result_and_is_retried_alone(tmp_path):
    device = FakeFortiOS()
    answers = ["failed", "sent"]
    runtime = make_runtime(tmp_path, device)
    runtime.notifier = lambda record: answers.pop(0)
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == "confirmed" and record["notification"] == "failed"
    blocks = len(device.applied_blocks)
    again = execute.notify_retry(runtime, record["change_id"])
    assert again["notification"] == "sent"
    assert len(device.applied_blocks) == blocks
    events = [json.loads(line) for line in (tmp_path / "audit" / "audit.jsonl").read_text().splitlines()]
    assert [event["notification"] for event in events if event["event"] == "delivery"] == ["failed", "sent"]


def test_audit_delivery_is_acknowledged_once_the_queue_is_empty_after_the_operation(tmp_path):
    device = FakeFortiOS()
    status = tmp_path / "export-status.json"
    status.write_text(json.dumps({"updated_at": time.time(), "pending": 1, "oldest_pending_age_seconds": 1}))
    runtime = make_runtime(tmp_path, device, export_status=str(status))
    record = execute.apply(runtime, "lab", request())
    assert record["audit_delivery"] == "pending"
    status.write_text(json.dumps({"updated_at": time.time() + 1, "pending": 0}))
    assert execute.refresh_delivery(runtime, record)["audit_delivery"] == "acknowledged"


def test_audit_delivery_is_acknowledged_when_the_status_names_this_audit_file(tmp_path):
    device = FakeFortiOS()
    status = tmp_path / "export-status.json"
    named = str(tmp_path / "audit" / "." / "audit.jsonl")
    status.write_text(json.dumps({"updated_at": time.time(), "pending": 1, "audit_file": named}))
    runtime = make_runtime(tmp_path, device, export_status=str(status))
    record = execute.apply(runtime, "lab", request())
    assert record["audit_delivery"] == "pending"
    status.write_text(json.dumps({"updated_at": time.time() + 1, "pending": 0, "audit_file": named}))
    assert execute.refresh_delivery(runtime, record)["audit_delivery"] == "acknowledged"


def test_status_of_another_audit_file_acknowledges_nothing_and_refuses_changes(tmp_path):
    device = FakeFortiOS()
    status = tmp_path / "export-status.json"
    own = str(tmp_path / "audit" / "audit.jsonl")
    status.write_text(json.dumps({"updated_at": time.time(), "pending": 1, "audit_file": own}))
    runtime = make_runtime(tmp_path, device, export_status=str(status))
    record = execute.apply(runtime, "lab", request())
    assert record["audit_delivery"] == "pending"
    blocks = len(device.applied_blocks)
    other = "/var/lib/netops-admin-audit/audit.jsonl"
    status.write_text(json.dumps({"updated_at": time.time() + 1, "pending": 0, "audit_file": other}))
    assert execute.refresh_delivery(runtime, record)["audit_delivery"] == "pending"
    assert runtime.store.operation(record["change_id"])["audit_delivery"] == "pending"
    events = [json.loads(line) for line in (tmp_path / "audit" / "audit.jsonl").read_text().splitlines()]
    assert "acknowledged" not in [event.get("audit_delivery") for event in events]
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(key="other-host", request_id="req-0002-example"))
    assert "another audit file" in caught.value.reasons[0]
    assert len(device.applied_blocks) == blocks


def test_message_names_the_block_for_every_blocking_result():
    from netops_admin import blocking

    for result in blocking.BLOCKING_RESULTS:
        _title, body = notify.message({"result": result, "reason": "interrupted", "plan": {}})
        assert "the device is blocked until a person investigates it" in body
    _title, body = notify.message({"result": "reverted", "reason": "interrupted", "plan": {}})
    assert "the device is blocked" not in body


def test_message_names_the_block_for_every_blocking_reason():
    for reason in execute.BLOCKING_REASONS:
        _title, body = notify.message({"result": "confirmed", "reason": reason, "plan": {}})
        assert "the device is blocked until a person investigates it" in body


class _Endpoint(BaseHTTPRequestHandler):
    def _answer(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.received.append((self.command, self.path, body))
        status, location = self.server.answers.pop(0) if self.server.answers else (200, None)
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self._answer()

    def do_GET(self):
        self._answer()

    def log_message(self, *args):
        pass


@pytest.fixture
def endpoints(tmp_path, monkeypatch):
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    servers = []
    for _ in range(2):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Endpoint)
        server.received, server.answers = [], []
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    topic = tmp_path / "topic.env"
    topic.write_text("NTFY_TOPIC=abcdefgh_12345\n")
    try:
        yield servers, str(topic)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def _sender(server, topic):
    return notify.NtfyNotifier("http://127.0.0.1:%d" % server.server_address[1], topic, 5)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirected_notification_is_failed_and_not_followed(endpoints, status):
    (first, second), topic = endpoints
    first.answers.append((status, "http://127.0.0.1:%d/elsewhere" % second.server_address[1]))
    assert _sender(first, topic)({"device": "lab", "result": "confirmed"}) == "failed"
    assert [(method, path) for method, path, _body in first.received] == [("POST", "/abcdefgh_12345")]
    assert second.received == []


def test_a_direct_answer_is_sent_with_its_body(endpoints):
    (first, second), topic = endpoints
    assert _sender(first, topic)({"device": "lab", "result": "confirmed"}) == "sent"
    [(method, path, body)] = first.received
    assert (method, path) == ("POST", "/abcdefgh_12345") and b"result: confirmed" in body
    assert second.received == []


def test_a_redirected_notification_refuses_the_next_change(tmp_path, endpoints):
    (first, second), topic = endpoints
    first.answers.append((302, "http://127.0.0.1:%d/elsewhere" % second.server_address[1]))
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    runtime.notifier = _sender(first, topic)
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == "confirmed" and record["notification"] == "failed"
    assert second.received == []
    blocks = len(device.applied_blocks)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(key="other-host", request_id="req-0002-example"))
    assert "was not delivered" in caught.value.reasons[0]
    assert len(device.applied_blocks) == blocks
