"""Known secret literals survive exec/PTY normalization without disclosure or syntax edits."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

from netops_core.audit import Recorder
import pytest

from conftest import FORTIOS_STATUS, _target
from netops_helper.auth import _normalize_credential
import netops_helper.audit as audit
import netops_helper.engine as engine

ROUTE = "FGT-lab # routing entry for 203.0.113.88/32\r\n  via 192.0.2.1\r\n\r\n\r\nFGT-lab #\r\n"


def _exec(monkeypatch, stdout):
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda auth: ["192.0.2.10"])
    monkeypatch.setattr(engine, "host_key_line", lambda *a: "pinned")
    monkeypatch.setattr(engine, "_exec_command", lambda *a, **k: SimpleNamespace(rc=0, stdout=stdout))


def test_crlf_of_an_exec_read_becomes_lf_and_the_prompt_is_still_removed(monkeypatch):
    _exec(monkeypatch, ROUTE.encode())
    rc, text = engine._exec_read(_target("fortinet", "system_status"), "fortinet", "get router info routing-table details 203.0.113.88")
    assert rc == 0 and "\r" not in text
    assert text == "routing entry for 203.0.113.88/32\n  via 192.0.2.1\n\n\n"


def test_a_lone_carriage_return_is_left_alone(monkeypatch):
    _exec(monkeypatch, b"progress 10%\rprogress 100%\r\ndone\r\n")
    _, text = engine._exec_read(_target("fortinet", "system_status"), "fortinet", "get x")
    assert text == "progress 10%\rprogress 100%\ndone\n"


@pytest.fixture()
def audit_log(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "_RECORDER", Recorder(tmp_path / "audit.jsonl", "helper"))
    monkeypatch.setattr(engine, "record", audit.record)


@pytest.mark.parametrize("page_size", [1000, 1600])
def test_hash_and_pages_describe_the_unified_text(monkeypatch, audit_log, page_size):
    raw = ("řádek one\r\nline two\r\n" * 200).encode()
    expected = raw.decode().replace("\r\n", "\n").encode()
    _exec(monkeypatch, raw)
    reads = []

    def read(auth, platform, command, prompt=False):
        reads.append(command)
        return engine._exec_read(auth, platform, command)

    monkeypatch.setattr(engine, "_verified_read", read)
    target = _target("fortinet", "system_status")
    offset, snapshot, parts = 0, None, []
    while True:
        page = engine.ssh_read(target, "fortinet", "system_status", None, offset, page_size, snapshot)
        assert page["ok"] is True
        assert page["content_sha256"] == hashlib.sha256(expected).hexdigest()
        assert page["total_bytes"] == len(expected)
        assert page["pagination_source"] == ("fresh" if offset == 0 else "cached")
        part = page["untrusted_device_output"].encode()
        assert b"\r" not in part
        assert page["offset"] == offset and page["returned_bytes"] == len(part)
        parts.append(part)
        end = offset + len(part)
        assert page["complete"] == (end == len(expected))
        assert page["next_offset"] == (None if page["complete"] else end)
        if page["complete"]:
            break
        assert end > offset and len(part) <= page_size
        offset, snapshot = page["next_offset"], page["content_sha256"]
    assert len(parts) > 1 and b"".join(parts) == expected
    assert len(reads) == 1  # continuations use the redacted snapshot, never SSH


@pytest.mark.parametrize("echo_normalized", [False, True])
@pytest.mark.parametrize("secret", ["alfa-example\r\nbravo-example", "password:alfa-example\r\nbravo-example"])
def test_crlf_secret_is_redacted_before_and_after_normalization(monkeypatch, audit_log, echo_normalized, secret):
    kind, validated = _normalize_credential("password", secret)
    assert (kind, validated) == ("password", secret)
    echoed = secret.replace("\r\n", "\n") if echo_normalized else secret
    _exec(monkeypatch, (FORTIOS_STATUS + "echo " + echoed + "\r\n").encode())
    target = _target("fortinet", "system_status", secret=validated)
    result = engine.ssh_read(target, "fortinet", "system_status", None, 0, 1000)
    assert result["ok"] is True
    text = result["untrusted_device_output"]
    assert "alfa-example" not in text and "bravo-example" not in text
    assert "<REDACTED>" in text and "\r" not in text
    assert result["content_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert result["total_bytes"] == result["returned_bytes"] == len(text.encode())


@pytest.mark.parametrize("platform", sorted(engine.normalization.IDENTITY_PROFILES))
def test_switch_profiles_unify_line_ends_and_replace_secret_literals(monkeypatch, platform):
    # switch_read and locate_endpoint read through _exec_read too.
    secret = "alfa-example\r\nbravo-example"
    _exec(monkeypatch, b"% BGP not active\r\necho " + secret.replace("\r\n", "\n").encode() + b"\r\n")
    _, text = engine._exec_read(_target(platform, "x", secret=secret), platform, "show x")
    assert text == "% BGP not active\necho <REDACTED>\n"


@pytest.mark.parametrize("platform", ["fortiadc", "linux"])
def test_other_platforms_keep_the_line_ends_the_device_prints(monkeypatch, platform):
    _exec(monkeypatch, b"Command fail\r\n")
    _, text = engine._exec_read(_target(platform, "x"), platform, "show x")
    assert text == "Command fail\r\n"


@pytest.mark.parametrize("secret", [
    "alfa-example\r\nbravo-example",
    "password:alfa-example\r\nbravo-example",
    "alfa-example\r\r\nbravo-example",
    "alfa-example\rbravo-example",
])
def test_pty_secret_is_redacted_after_carriage_returns_are_removed(monkeypatch, audit_log, secret):
    target = _target("ruckus_unleashed", "system_info", secret=secret)
    command = engine.READ_QUERIES["ruckus_unleashed"]["system_info"].command
    prompt = engine._RUCKUS_ENABLE_PROMPT
    output = command.encode() + b"\r\necho " + secret.encode() + b"\r\n" + prompt

    class Terminal:
        def __init__(self, *a, **kw):
            self.responses = iter([b""] * 4 + [output])

        def expect(self, *a):
            return 0, next(self.responses)

        def discard(self, data):
            pass

        def send(self, text):
            pass

        def close(self):
            pass

    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda auth: ["192.0.2.10"])
    monkeypatch.setattr(engine, "host_key_line", lambda *a: "pinned")
    monkeypatch.setattr(engine.core_session, "Session", Terminal)
    result = engine.ssh_read(target, "ruckus_unleashed", "system_info", None, 0, 1000)
    assert result["ok"] is True and result["transport"] == "pty"
    text = result["untrusted_device_output"]
    assert text == "echo <REDACTED>"
    assert result["content_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert result["total_bytes"] == result["returned_bytes"] == len(text.encode())
