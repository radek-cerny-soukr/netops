from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from pathlib import Path

TOPIC = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
PRIORITIES = {"confirmed": "3", "rejected": "3", "reverted": "4", "unknown": "5", "revert-failed": "5"}


def _topic(topic_file: str) -> str | None:
    try:
        lines = Path(topic_file).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        name, separator, value = line.strip().partition("=")
        if separator and name.strip() == "NTFY_TOPIC":
            value = value.strip().strip('"').strip("'")
            return value if TOPIC.match(value) else None
    return None


def message(record: dict) -> tuple:
    plan = record.get("plan", {})
    title = "netops-admin %s %s" % (record.get("device", "?"), record.get("result", "?"))
    lines = [
        "result: %s" % record.get("result"),
        "operation: %s %s %s" % (plan.get("op"), plan.get("table"), plan.get("key")),
        "change: %s" % record.get("change_id"),
        "request: %s" % record.get("request_id"),
    ]
    if record.get("reason"):
        lines.append("reason: %s" % record["reason"])
    if record.get("foreign_sessions"):
        lines.append("other administrator sessions were active: %d" % record["foreign_sessions"])
    if record.get("differences"):
        lines.append("differences: %d" % len(record["differences"]))
    if record.get("result") in ("unknown", "revert-failed") or record.get("reason") in ("administrator table", "foreign change", "not persisted"):
        lines.append("the device is blocked until a person investigates it")
    return title.encode("ascii", "replace").decode("ascii"), "\n".join(lines)


class NtfyNotifier:
    def __init__(self, server: str, topic_file: str, timeout_seconds: float, x509_strict: bool = True):
        self.server = server.rstrip("/")
        self.topic_file = topic_file
        self.timeout_seconds = timeout_seconds
        self.x509_strict = x509_strict

    def _context(self):
        context = ssl.create_default_context()
        if not self.x509_strict:
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        return context

    def __call__(self, record: dict) -> str:
        topic = _topic(self.topic_file)
        if topic is None:
            return "failed"
        title, body = message(record)
        request = urllib.request.Request(
            "%s/%s" % (self.server, topic), data=body.encode("utf-8"), method="POST",
            headers={"Title": title, "Priority": PRIORITIES.get(record.get("result"), "4"), "Tags": "netops"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds, context=self._context()) as answer:
                return "sent" if 200 <= answer.status < 300 else "failed"
        except (urllib.error.URLError, OSError, ValueError):
            return "failed"
