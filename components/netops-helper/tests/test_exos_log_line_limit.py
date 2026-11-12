"""EXOS log queries return at most a fixed number of lines (after redaction), cut at a message boundary."""
import pytest

import netops_helper.engine as engine
from conftest import _target

STAMP = "11/08/2026 22:{minute:02d}:{second:02d}.00 <Info:Test.Msg> message {number}"


def _log(count, extra=0):
    lines = []
    for number in range(count):
        lines.append(STAMP.format(minute=number // 60 % 60, second=number % 60, number=number))
        lines.extend(f"    continuation {number}.{part}" for part in range(extra))
    return "\n".join(lines) + "\n"


def _read(monkeypatch, query, body, offset=0, max_bytes=48000, content_sha256=None):
    monkeypatch.setattr(engine, "record", lambda *a, **kw: None)
    monkeypatch.setattr(engine, "_verified_read", lambda *a, **kw: (0, body))
    return engine.ssh_read(_target("extreme_exos", query), "extreme_exos", query, {}, offset, max_bytes, content_sha256)


@pytest.mark.parametrize("query", ["log_messages", "log_warnings"])
def test_log_over_the_limit_is_cut_and_says_so(monkeypatch, query):
    answer = _read(monkeypatch, query, _log(engine._LOG_MAX_LINES + 50), max_bytes=48_000)
    assert answer["line_limit"] == {"max_lines": engine._LOG_MAX_LINES, "total_lines": engine._LOG_MAX_LINES + 50,
                                    "returned_lines": engine._LOG_MAX_LINES, "truncated": True}
    text = answer["untrusted_device_output"]
    assert f"message {engine._LOG_MAX_LINES - 1}" in text and f"message {engine._LOG_MAX_LINES}" not in text
    assert "limited to the first" in text
    assert "log_line_limit" in answer["normalized"]["warnings"]


def test_log_within_the_limit_is_unchanged(monkeypatch):
    body = _log(engine._LOG_MAX_LINES)
    answer = _read(monkeypatch, "log_messages", body, max_bytes=48_000)
    assert answer["untrusted_device_output"] == body
    assert answer["line_limit"]["truncated"] is False
    assert "log_line_limit" not in answer["normalized"]["warnings"]


def test_multi_line_message_is_not_split_by_the_limit(monkeypatch):
    # 3 lines per message: 200 is not a multiple, the cut falls inside message 66.
    body = _log(100, extra=2)
    answer = _read(monkeypatch, "log_messages", body, max_bytes=48_000)
    text = answer["untrusted_device_output"]
    assert answer["line_limit"]["returned_lines"] == 198 and answer["line_limit"]["truncated"]
    assert "message 65" in text and "continuation 65.1" in text and "message 66" not in text and "continuation 66" not in text


@pytest.mark.parametrize("count", [engine._LOG_MAX_LINES, engine._LOG_MAX_LINES * 3])
def test_the_limit_applies_to_redacted_output_before_paging(monkeypatch, count):
    body = _log(count)
    first = _read(monkeypatch, "log_messages", body, max_bytes=2000)
    assert first["next_offset"] is not None
    assert first["line_limit"]["truncated"] == (count > engine._LOG_MAX_LINES)
    pages, answer = [first["untrusted_device_output"]], first
    while answer["next_offset"] is not None:
        answer = _read(monkeypatch, "log_messages", body, offset=answer["next_offset"], max_bytes=2000,
                       content_sha256=first["content_sha256"])
        assert answer["pagination_source"] == "cached"
        assert answer["line_limit"] == first["line_limit"]
        assert ("log_line_limit" in answer["normalized"]["warnings"]) == (count > engine._LOG_MAX_LINES)
        pages.append(answer["untrusted_device_output"])
    assert "".join(pages).count("<Info:Test.Msg>") == engine._LOG_MAX_LINES


def test_other_queries_and_profiles_are_not_limited(monkeypatch):
    body = _log(engine._LOG_MAX_LINES + 50)
    answer = _read(monkeypatch, "log_configuration", body, max_bytes=48_000)
    assert "line_limit" not in answer and answer["untrusted_device_output"] == body


@pytest.mark.parametrize("profile", ["cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos", "juniper_junos", "juniper_junos_els"])
def test_oldest_first_logs_keep_the_newest_lines(monkeypatch, profile):
    monkeypatch.setattr(engine, "record", lambda *a, **kw: None)
    body = "".join(f"Nov  8 22:00:00 host %SYS-6-TEST: message {number}\n" for number in range(engine._LOG_MAX_LINES + 50))
    monkeypatch.setattr(engine, "_verified_read", lambda *a, **kw: (0, body))
    auth = _target(profile, "log_messages")
    answer = first = engine.ssh_read(auth, profile, "log_messages", {}, 0, 2000, None)
    pages = [first["untrusted_device_output"]]
    assert first["next_offset"] is not None
    assert first["line_limit"] == {"max_lines": engine._LOG_MAX_LINES, "total_lines": engine._LOG_MAX_LINES + 50,
                                   "returned_lines": engine._LOG_MAX_LINES, "truncated": True}
    # A continuation must use the limited snapshot, even if the device output changes.
    monkeypatch.setattr(engine, "_verified_read", lambda *a, **kw: pytest.fail("pagination re-read the device"))
    while answer["next_offset"] is not None:
        answer = engine.ssh_read(auth, profile, "log_messages", {}, answer["next_offset"], 2000, first["content_sha256"])
        assert answer["pagination_source"] == "cached"
        assert answer["line_limit"] == first["line_limit"]
        assert "log_line_limit" in answer["normalized"]["warnings"]
        pages.append(answer["untrusted_device_output"])
    text = "".join(pages)
    assert answer["line_limit"]["truncated"] and answer["line_limit"]["returned_lines"] == engine._LOG_MAX_LINES
    assert "message 49 " not in text + " " and "message 50\n" in text and f"message {engine._LOG_MAX_LINES + 49}\n" in text
    assert "limited to the last" in text and "log_line_limit" in answer["normalized"]["warnings"]


@pytest.mark.parametrize("profile", ["juniper_junos", "juniper_junos_els"])
@pytest.mark.parametrize("query", ["log_messages", "log_interactive_commands"])
def test_junos_last_pager_mark_is_removed_and_does_not_make_the_log_truncated(monkeypatch, profile, query):
    monkeypatch.setattr(engine, "record", lambda *a, **kw: None)
    lines = [f"Nov  9 01:00:{number % 60:02d}  host mgd[1]: UI_TEST: message {number}\n" for number in range(120)]
    body = "".join(lines[:-1]) + "---(more 100%)---" + " " * 40 + lines[-1]       # as printed by `| last 200 | no-more`
    monkeypatch.setattr(engine, "_verified_read", lambda *a, **kw: (0, body))
    answer = engine.ssh_read(_target(profile, query), profile, query, {}, 0, 48_000, None)
    text = answer["untrusted_device_output"]
    assert "(more" not in text and "message 119\n" in text and answer["normalized"]["status"] != "truncated"


@pytest.mark.parametrize('profile', ['juniper_junos', 'juniper_junos_els'])
@pytest.mark.parametrize('query', ['log_messages', 'log_interactive_commands'])
def test_real_junos_pager_artifact_preserves_all_200_messages(monkeypatch, profile, query):
    from pathlib import Path
    path = Path(__file__).parent / 'fixtures/real/juniper_junos_els/vjunosswitch_26.2R1.7' / (query + '.admin.txt')
    body = path.read_text()
    expected = [line for line in body.splitlines() if line.strip() and '---(more 100%)---' not in line]
    assert len(expected) == 200
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, '_verified_read', lambda *a, **kw: (0, body))
    answer = engine.ssh_read(_target(profile, query), profile, query, {}, 0, 48_000, None)
    assert answer['untrusted_device_output'].splitlines() == expected
    assert answer['line_limit'] == {'max_lines': 200, 'total_lines': 200, 'returned_lines': 200, 'truncated': False}
    assert 'log_line_limit' not in answer['normalized']['warnings']
    assert answer['ok']
    assert answer['normalized']['status'] == 'unparsed'  # Raw log queries have no structured adapter.
