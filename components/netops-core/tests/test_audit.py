import json
import os
import stat

import pytest

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
