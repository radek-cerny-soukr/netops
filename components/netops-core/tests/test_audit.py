import json
import os
from types import SimpleNamespace
from unittest.mock import Mock
import stat

import pytest

from netops_core import audit as audit_module
from netops_core.audit import (
    COMPONENTS,
    FIELDS,
    STATUSES,
    AuditFieldError,
    AuditPersistenceError,
    Recorder,
)

OPERATION_ID = "op_" + "a" * 32
DEVICE = "fw-a.example.invalid"


def recorder(tmp_path, component="auditor", **kwargs):
    return Recorder(tmp_path / "audit.jsonl", component, **kwargs)


def lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_a_record_is_one_json_line_naming_the_component(tmp_path):
    keeper = recorder(tmp_path, "helper")
    keeper.record("ssh_read", device=DEVICE, status="ok", response_bytes=12)
    keeper.record("ssh_read", device=DEVICE, status="failed", detail="exit code 255")
    written = lines(tmp_path / "audit.jsonl")
    assert len(written) == 2
    assert written[0]["component"] == "helper"
    assert written[0]["event"] == "ssh_read"
    assert written[0]["device"] == DEVICE
    assert written[0]["response_bytes"] == 12
    assert written[1]["status"] == "failed"
    assert set(written[0]) == {
        "timestamp", "component", "event", "device", "status", "response_bytes"
    }
    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()[0]
    assert ", " not in raw
    assert raw.index('"component"') < raw.index('"device"') < raw.index('"event"')


def test_the_component_is_one_of_the_three_families(tmp_path):
    assert COMPONENTS == ("helper", "auditor", "admin")
    for component in COMPONENTS:
        recorder(tmp_path, component).record("started")
    with pytest.raises(AuditFieldError) as caught:
        recorder(tmp_path, "collector")
    assert "component must be one of helper, auditor, admin" in str(caught.value)
    assert "'collector'" in str(caught.value)


def test_an_unknown_field_is_refused_and_never_dropped(tmp_path):
    keeper = recorder(tmp_path)
    with pytest.raises(AuditFieldError) as caught:
        keeper.record("ssh_read", device=DEVICE, change_id="dead-field", persistent=True)
    said = str(caught.value)
    assert "change_id" in said
    assert "persistent" in said
    assert "unknown field" in said
    assert not (tmp_path / "audit.jsonl").exists()


def test_the_fields_of_a_record_are_written_down_in_the_module():
    assert "operation_id" in FIELDS
    assert "response_sha256" in FIELDS
    assert "pagination_source" in FIELDS
    assert "transport" in FIELDS
    assert "rc" in FIELDS
    assert "target" not in FIELDS
    assert isinstance(FIELDS, frozenset)


@pytest.mark.parametrize("status", ("started", "ok", "failed"))
def test_a_known_status_is_written_down(tmp_path, status):
    assert STATUSES == ("started", "ok", "failed")
    keeper = recorder(tmp_path)
    keeper.record("ssh_read", status=status)
    assert lines(tmp_path / "audit.jsonl")[0]["status"] == status


@pytest.mark.parametrize("status", ("done", "OK", "", None, 1, True))
def test_a_status_outside_the_list_is_refused(tmp_path, status):
    with pytest.raises(AuditFieldError) as caught:
        recorder(tmp_path).record("ssh_read", status=status)
    assert "status must be one of started, ok, failed" in str(caught.value)


def test_an_operation_id_must_look_like_the_helper_writes_it(tmp_path):
    keeper = recorder(tmp_path)
    keeper.record("ssh_read", operation_id=OPERATION_ID)
    assert lines(tmp_path / "audit.jsonl")[0]["operation_id"] == OPERATION_ID


@pytest.mark.parametrize(
    "operation_id",
    ("op_" + "a" * 31, "op_" + "A" * 32, "a" * 32, "", None, 1, "op_" + "g" * 32),
)
def test_a_broken_operation_id_is_refused(tmp_path, operation_id):
    with pytest.raises(AuditFieldError) as caught:
        recorder(tmp_path).record("ssh_read", operation_id=operation_id)
    assert "operation_id must look like op_" in str(caught.value)


def test_rotation_keeps_exactly_the_retained_segments(tmp_path):
    keeper = recorder(tmp_path, segment_bytes=260, retained_segments=3)
    for index in range(30):
        keeper.record("ssh_read", device=DEVICE, status="ok", detail="event-%02d" % index)
    segments = sorted(path.name for path in tmp_path.glob("audit.jsonl*"))
    assert segments == ["audit.jsonl", "audit.jsonl.1", "audit.jsonl.2"]
    assert sum((tmp_path / name).stat().st_size for name in segments) <= 3 * 260
    for name in segments:
        path = tmp_path / name
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        for record in lines(path):
            assert record["event"] == "ssh_read"
            assert record["component"] == "auditor"


def test_the_log_is_only_readable_by_its_owner(tmp_path):
    keeper = recorder(tmp_path)
    keeper.record("started")
    mode = stat.S_IMODE(os.stat(tmp_path / "audit.jsonl").st_mode)
    assert mode == 0o600


def test_a_record_larger_than_a_segment_is_refused(tmp_path):
    keeper = recorder(tmp_path, segment_bytes=64)
    with pytest.raises(AuditPersistenceError) as caught:
        keeper.record("ssh_read", detail="x" * 200)
    assert "exceeds the segment limit" in str(caught.value)


def test_the_directory_of_the_log_is_created_when_it_is_missing(tmp_path):
    keeper = Recorder(tmp_path / "state" / "audit.jsonl", "admin")
    keeper.record("started")
    assert (tmp_path / "state" / "audit.jsonl").exists()
    assert lines(tmp_path / "state" / "audit.jsonl")[0]["component"] == "admin"


@pytest.mark.parametrize("event", ("", "   ", None, 1, ["started"]))
def test_an_event_without_a_name_is_refused(tmp_path, event):
    with pytest.raises(AuditFieldError) as caught:
        recorder(tmp_path).record(event)
    assert "event must be a non-empty string" in str(caught.value)


@pytest.mark.parametrize("value", (0, -1, "many", None, True, 1.5))
def test_a_broken_rotation_budget_is_refused(tmp_path, value):
    with pytest.raises(AuditFieldError):
        recorder(tmp_path, segment_bytes=value)
    with pytest.raises(AuditFieldError):
        recorder(tmp_path, retained_segments=value)


def test_a_value_that_is_not_json_is_refused_naming_the_event(tmp_path):
    with pytest.raises(AuditFieldError) as caught:
        recorder(tmp_path).record("ssh_read", detail=object())
    assert "not serializable as json" in str(caught.value)
    assert "ssh_read" in str(caught.value)


class _Killed(BaseException):
    pass


def _record(keeper, tag, index=0):
    keeper.record("ssh_read", detail="%s-%d-%s" % (tag, index, "x" * 100))


def _segments(tmp_path):
    return {
        path.name: sorted({record["detail"][0] for record in lines(path)})
        for path in sorted(tmp_path.glob("audit.jsonl*"))
    }


@pytest.mark.parametrize("crashes", ((), (1,), (2,), (2, 1), (1, 2), (2, 1, 1)))
def test_a_rotation_interrupted_before_any_rename_loses_no_retained_segment(
    tmp_path, monkeypatch, crashes
):
    keeper = recorder(tmp_path, segment_bytes=450, retained_segments=3)
    for tag in "ABC":
        _record(keeper, tag, 0)
        _record(keeper, tag, 1)
    assert _segments(tmp_path) == {
        "audit.jsonl": ["C"], "audit.jsonl.1": ["B"], "audit.jsonl.2": ["A"],
    }
    real_replace = os.replace
    for crash_at in crashes:
        calls = []

        def replace(source, target, calls=calls, crash_at=crash_at):
            calls.append(target)
            if len(calls) == crash_at:
                raise _Killed()
            return real_replace(source, target)

        monkeypatch.setattr(os, "replace", replace)
        with pytest.raises(_Killed):
            _record(keeper, "D")
        monkeypatch.setattr(os, "replace", real_replace)
        assert "B" in sum(_segments(tmp_path).values(), [])
    _record(keeper, "E")
    assert _segments(tmp_path) == {
        "audit.jsonl": ["E"], "audit.jsonl.1": ["C"], "audit.jsonl.2": ["B"],
    }
    _record(keeper, "F")
    _record(keeper, "G")
    assert _segments(tmp_path) == {
        "audit.jsonl": ["G"], "audit.jsonl.1": ["E", "F"], "audit.jsonl.2": ["C"],
    }


def test_a_rotation_syncs_the_directory_after_its_renames(tmp_path, monkeypatch):
    keeper = recorder(tmp_path, segment_bytes=450, retained_segments=3)
    real_fsync = os.fsync
    synced = []

    def fsync(descriptor):
        synced.append("directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file")
        return real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fsync)
    _record(keeper, "A", 0)
    _record(keeper, "A", 1)
    assert synced == ["file", "file"]
    _record(keeper, "B", 0)
    assert synced == ["file", "file", "directory", "file"]
    assert sorted(path.name for path in tmp_path.glob("audit.jsonl*")) == [
        "audit.jsonl", "audit.jsonl.1",
    ]

def _write_os_proxy():
    return SimpleNamespace(**{
        **vars(os),
        "write": Mock(wraps=os.write),
        "fsync": Mock(wraps=os.fsync),
        "ftruncate": Mock(wraps=os.ftruncate),
        "close": Mock(wraps=os.close),
    })


def test_append_completes_positive_partial_writes(tmp_path, monkeypatch):
    path = tmp_path / "append.log"
    prefix, encoded = b"existing\n", b"next record\n"
    path.write_bytes(prefix)
    descriptor = os.open(path, os.O_RDWR | os.O_APPEND)
    real_write = os.write
    calls = []

    def write(fd, data):
        calls.append(data)
        return real_write(fd, data[:3])

    proxy = _write_os_proxy()
    proxy.write.side_effect = write
    monkeypatch.setattr(audit_module, "os", proxy)
    try:
        Recorder._append(descriptor, len(prefix), encoded)
    finally:
        os.close(descriptor)
    assert calls == [encoded[offset:] for offset in range(0, len(encoded), 3)]
    assert path.read_bytes() == prefix + encoded
    proxy.fsync.assert_called_once_with(descriptor)
    proxy.ftruncate.assert_not_called()


@pytest.mark.parametrize("progress", [0, -1])
@pytest.mark.parametrize("partial", [False, True])
def test_append_refuses_nonpositive_write_and_rolls_back(tmp_path, monkeypatch, progress, partial):
    path = tmp_path / "append.log"
    prefix, encoded = b"existing\n", b"next record\n"
    path.write_bytes(prefix)
    descriptor = os.open(path, os.O_RDWR | os.O_APPEND)
    real_write = os.write
    calls = []

    def write(fd, data):
        calls.append(data)
        if partial and len(calls) == 1:
            return real_write(fd, data[:3])
        if len(calls) == 1 + int(partial):
            return progress
        raise AssertionError("write retried after no progress")

    proxy = _write_os_proxy()
    proxy.write.side_effect = write
    monkeypatch.setattr(audit_module, "os", proxy)
    try:
        with pytest.raises(OSError, match="^short write to the audit log$"):
            Recorder._append(descriptor, len(prefix), encoded)
    finally:
        os.close(descriptor)
    assert calls == ([encoded, encoded[3:]] if partial else [encoded])
    assert path.read_bytes() == prefix
    proxy.ftruncate.assert_called_once_with(descriptor, len(prefix))
    proxy.fsync.assert_not_called()


@pytest.mark.parametrize("failure", ["write", "fsync"])
def test_append_preserves_io_error_and_rolls_back(tmp_path, monkeypatch, failure):
    path = tmp_path / "append.log"
    prefix, encoded = b"existing\n", b"next record\n"
    path.write_bytes(prefix)
    descriptor = os.open(path, os.O_RDWR | os.O_APPEND)
    error = OSError("storage unavailable")
    proxy = _write_os_proxy()
    getattr(proxy, failure).side_effect = error
    monkeypatch.setattr(audit_module, "os", proxy)
    try:
        with pytest.raises(OSError) as caught:
            Recorder._append(descriptor, len(prefix), encoded)
    finally:
        os.close(descriptor)
    assert caught.value is error
    assert path.read_bytes() == prefix
    proxy.ftruncate.assert_called_once_with(descriptor, len(prefix))


def test_record_reports_nonpositive_write_as_persistence_failure(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    prefix = b"existing\n"
    path.write_bytes(prefix)
    proxy = _write_os_proxy()
    proxy.write.side_effect = [0, AssertionError("write retried after no progress")]
    monkeypatch.setattr(audit_module, "os", proxy)
    with pytest.raises(AuditPersistenceError, match="short write to the audit log"):
        Recorder(path, "auditor").record("next")
    assert path.read_bytes() == prefix
    proxy.write.assert_called_once()


def test_open_log_closes_initial_descriptor_when_size_read_fails(monkeypatch):
    keeper = Recorder("audit.jsonl", "auditor")
    error = OSError("size read failed")
    opened = Mock(return_value=42)
    rotated = Mock()
    proxy = SimpleNamespace(
        O_RDWR=os.O_RDWR,
        O_APPEND=os.O_APPEND,
        fstat=Mock(side_effect=error),
        pread=Mock(),
        close=Mock(),
    )
    monkeypatch.setattr(audit_module, "_owned_descriptor", opened)
    monkeypatch.setattr(audit_module, "os", proxy)
    monkeypatch.setattr(keeper, "_rotate", rotated)
    with pytest.raises(OSError) as caught:
        keeper._open_log(b"x")
    assert caught.value is error
    opened.assert_called_once_with(keeper.path(), os.O_RDWR | os.O_APPEND)
    proxy.fstat.assert_called_once_with(42)
    proxy.close.assert_called_once_with(42)
    proxy.pread.assert_not_called()
    rotated.assert_not_called()


def test_open_log_closes_rotated_descriptor_when_size_read_fails(monkeypatch):
    keeper = Recorder("audit.jsonl", "auditor", segment_bytes=1)
    error = OSError("rotated size read failed")
    opened = Mock(side_effect=[42, 43])
    rotated = Mock()
    proxy = SimpleNamespace(
        O_RDWR=os.O_RDWR,
        O_APPEND=os.O_APPEND,
        fstat=Mock(side_effect=[SimpleNamespace(st_size=1), error]),
        pread=Mock(return_value=b"\n"),
        close=Mock(),
    )
    monkeypatch.setattr(audit_module, "_owned_descriptor", opened)
    monkeypatch.setattr(audit_module, "os", proxy)
    monkeypatch.setattr(keeper, "_rotate", rotated)
    with pytest.raises(OSError) as caught:
        keeper._open_log(b"x")
    assert caught.value is error
    assert opened.call_count == 2
    for invocation in opened.call_args_list:
        assert invocation.args == (keeper.path(), os.O_RDWR | os.O_APPEND)
        assert invocation.kwargs == {}
    assert [invocation.args for invocation in proxy.fstat.call_args_list] == [(42,), (43,)]
    assert [invocation.args for invocation in proxy.close.call_args_list] == [(42,), (43,)]
    proxy.pread.assert_called_once_with(42, 1, 0)
    rotated.assert_called_once_with()
