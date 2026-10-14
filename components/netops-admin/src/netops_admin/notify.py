from __future__ import annotations

import re
import json
import os
import subprocess
import sys
import ssl
import urllib.error
import urllib.request

from netops_admin.blocking import blocks
from netops_core.inputs import InputError, read_regular

TOPIC = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
TOPIC_FILE_MAX_BYTES = 64 * 1024
PRIORITIES = {"confirmed": "3", "rejected": "3", "reverted": "4", "unknown": "5", "revert-failed": "5"}


def _topic(topic_file: str) -> str | None:
    try:
        lines = read_regular(topic_file, TOPIC_FILE_MAX_BYTES).decode("utf-8").splitlines()
    except (OSError, InputError, ValueError):
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
    if blocks(record.get("result"), record.get("reason")):
        lines.append("the device is blocked until a person investigates it")
    return title.encode("ascii", "replace").decode("ascii"), "\n".join(lines)


class _Unredirected(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
        payload = {"url": request.full_url, "body": body, "title": title,
                   "priority": PRIORITIES.get(record.get("result"), "4"),
                   "timeout": self.timeout_seconds, "strict": self.x509_strict}
        environment = {"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1",
                       "PYTHONPATH": os.pathsep.join(str(path) for path in sys.path if path)}
        for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                     "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
            if name in os.environ:
                environment[name] = os.environ[name]
        worker = "import json,sys; from netops_admin.notify import _send; sys.stdout.write(_send(json.load(sys.stdin)))"
        try:
            answer = subprocess.run([sys.executable, "-B", "-c", worker],
                                    input=json.dumps(payload).encode("utf-8"), capture_output=True,
                                    timeout=self.timeout_seconds, env=environment, check=False)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return "failed"
        return "sent" if answer.returncode == 0 and answer.stdout == b"sent" else "failed"


def _send(payload) -> str:
    request = urllib.request.Request(payload["url"], data=payload["body"].encode("utf-8"), method="POST",
                                     headers={"Title": payload["title"], "Priority": payload["priority"], "Tags": "netops"})
    context = ssl.create_default_context()
    if not payload["strict"]:
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _Unredirected)
        with opener.open(request, timeout=payload["timeout"]) as answer:
            return "sent" if 200 <= answer.status < 300 and answer.url == request.full_url else "failed"
    except (urllib.error.URLError, OSError, ValueError):
        return "failed"
