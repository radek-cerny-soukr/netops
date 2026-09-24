from __future__ import annotations

import json
import time
import urllib.error

from fake_fortios import FakeFortiOS
from test_execute import SECRET, make_runtime, request

from netops_admin import execute, notify


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
        raise urllib.error.URLError("down")

    monkeypatch.setattr(notify.urllib.request, "urlopen", unreachable)
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
