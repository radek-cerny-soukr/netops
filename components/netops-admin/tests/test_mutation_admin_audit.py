import datetime
import json
import os
import re
import stat

import pytest

from netops_admin import audit
from netops_admin.audit import MAX_EVENT_BYTES, AuditLog, export_state, export_updated_at, now_utc, summarized_changes
from netops_admin.config import DEFAULT_LIMITS
from netops_admin.errors import Rejected
from netops_admin.profiles import find_profile

STAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
NOW = 1000.0


def written_lines(path):
    return path.read_bytes().decode("ascii").splitlines()


def status_file(tmp_path, **fields):
    path = tmp_path / "export.json"
    path.write_text(json.dumps(fields))
    return path


def state_of(tmp_path, limits=None, **fields):
    return export_state(status_file(tmp_path, **fields), dict(DEFAULT_LIMITS, **(limits or {})), clock=lambda: NOW)


class ShortWrites:
    def __getattr__(self, name):
        return getattr(os, name)

    def write(self, descriptor, data):
        return os.write(descriptor, data[:-1])


class CreationModes:
    def __init__(self):
        self.modes = []

    def __getattr__(self, name):
        return getattr(os, name)

    def fchmod(self, descriptor, mode):
        self.modes.append(stat.S_IMODE(os.fstat(descriptor).st_mode))
        return os.fchmod(descriptor, mode)


def test_the_audit_clock_is_utc_seconds_with_a_z_suffix():
    before = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    stamp = now_utc()
    after = datetime.datetime.now(datetime.timezone.utc)
    assert STAMP.fullmatch(stamp), stamp
    parsed = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    assert before <= parsed <= after


def test_every_audit_event_carries_its_time_under_at(tmp_path):
    path = tmp_path / "audit.log"
    document = AuditLog(path).event("step", change_id="c1", device="lab", step="prepared", detail="ok")
    assert STAMP.fullmatch(document["at"])
    stored = json.loads(written_lines(path)[0])
    assert stored["at"] == document["at"]
    assert set(stored) == {"event", "at", "change_id", "device", "step", "detail"}


def test_a_list_in_an_audit_event_keeps_every_item(tmp_path):
    path = tmp_path / "audit.log"
    document = AuditLog(path).event("start", commands=["config firewall address", "end"], changes={"n": [1, None]})
    assert document["commands"] == ["config firewall address", "end"]
    assert document["changes"] == {"n": [1, None]}
    stored = json.loads(written_lines(path)[0])
    assert stored["commands"] == ["config firewall address", "end"]


@pytest.mark.parametrize("value", ["tab\there", "x" * 201, "café"])
def test_audit_text_outside_short_printable_ascii_is_refused_by_name(tmp_path, value):
    with pytest.raises(ValueError, match=r"^audit text must be short printable ASCII$"):
        AuditLog(tmp_path / "audit.log").event("step", detail=value)
    assert not (tmp_path / "audit.log").exists()


@pytest.mark.parametrize("value, name", [(1.5, "float"), (b"raw", "bytes"), ((1, 2), "tuple")])
def test_an_audit_value_of_another_type_is_refused_naming_the_type(tmp_path, value, name):
    with pytest.raises(ValueError) as caught:
        AuditLog(tmp_path / "audit.log").event("step", detail=value)
    assert str(caught.value) == "audit value of unsupported type %s" % name


def test_an_audit_field_the_event_does_not_carry_is_refused_by_name(tmp_path):
    with pytest.raises(ValueError) as caught:
        AuditLog(tmp_path / "audit.log").event("step", change_id="c1", bogus=1, other=2)
    assert str(caught.value) == "audit event step does not carry ['bogus', 'other']"
    assert not (tmp_path / "audit.log").exists()


def test_an_audit_line_is_compact_json_with_sorted_keys(tmp_path):
    path = tmp_path / "audit.log"
    document = AuditLog(path).event("step", step="b", device="lab", detail={"z": 1, "a": 2}, change_id="c1")
    line = written_lines(path)[0]
    assert line == json.dumps(document, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    assert ", " not in line and ": " not in line
    assert line.index('"change_id"') < line.index('"detail"') < line.index('"device"') < line.index('"event"')


def test_a_non_ascii_key_of_an_audit_mapping_is_written_as_an_ascii_escape(tmp_path):
    path = tmp_path / "audit.log"
    AuditLog(path).event("start", changes={"název": "removed"})
    raw = path.read_bytes()
    assert raw.isascii()
    assert b"n\\u00e1zev" in raw
    assert json.loads(raw)["changes"] == {"název": "removed"}


def _detail_for(size):
    probe = {"event": "step", "at": "2026-01-01T00:00:00Z", "detail": []}
    base = len(json.dumps(probe, sort_keys=True, separators=(",", ":"))) + 1
    room = size - base
    count = room // 203 + 1
    characters = room - 2 - 3 * (count - 1)
    lengths = [characters // count + (1 if index < characters % count else 0) for index in range(count)]
    return ["x" * length for length in lengths]


@pytest.mark.parametrize("size", [MAX_EVENT_BYTES - 1, MAX_EVENT_BYTES])
def test_an_audit_line_of_up_to_the_limit_is_written(tmp_path, size):
    path = tmp_path / "audit.log"
    AuditLog(path).event("step", detail=_detail_for(size))
    assert len(path.read_bytes()) == size


def test_an_audit_line_one_byte_over_the_limit_is_refused_naming_the_limit(tmp_path):
    with pytest.raises(ValueError) as caught:
        AuditLog(tmp_path / "audit.log").event("step", detail=_detail_for(MAX_EVENT_BYTES + 1))
    assert str(caught.value) == "audit event is larger than %d bytes" % MAX_EVENT_BYTES
    assert not (tmp_path / "audit.log").exists()


def test_a_short_write_to_the_audit_log_is_an_error_by_name(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "os", ShortWrites())
    with pytest.raises(OSError) as caught:
        AuditLog(tmp_path / "audit.log").event("step", detail="ok")
    assert str(caught.value) == "short write to the audit log"


@pytest.fixture
def fifo(tmp_path):
    path = tmp_path / "audit.log"
    os.mkfifo(path)
    reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    yield path
    os.close(reader)


def _open_descriptors():
    return set(os.listdir("/proc/self/fd"))


def test_an_audit_log_that_is_not_a_regular_file_is_refused_and_closed(fifo):
    before = _open_descriptors()
    with pytest.raises(OSError) as caught:
        AuditLog(fifo)._open()
    assert type(caught.value) is OSError
    assert str(caught.value) == "the audit log is not a regular file"
    assert _open_descriptors() == before


def test_the_writability_check_names_why_the_audit_log_is_unusable(fifo):
    with pytest.raises(Rejected) as caught:
        AuditLog(fifo).check_writable()
    assert caught.value.reasons == ["the audit log cannot be written durably: the audit log is not a regular file"]


def test_the_writability_check_reports_the_system_error_text(tmp_path):
    (tmp_path / "audit.log").mkdir()
    with pytest.raises(Rejected) as caught:
        AuditLog(tmp_path / "audit.log").check_writable()
    assert caught.value.reasons == ["the audit log cannot be written durably: %s" % os.strerror(21)]


def test_the_writability_check_creates_missing_parents_and_a_private_directory(tmp_path):
    previous = os.umask(0o022)
    try:
        path = tmp_path / "a" / "b" / "audit" / "audit.log"
        AuditLog(path).check_writable()
    finally:
        os.umask(previous)
    assert path.is_file()
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


@pytest.mark.parametrize("first", ["check_writable", "event"])
def test_a_new_audit_log_is_never_wider_than_its_mode_before_the_chmod(tmp_path, monkeypatch, first):
    spy = CreationModes()
    monkeypatch.setattr(audit, "os", spy)
    previous = os.umask(0o022)
    try:
        log = AuditLog(tmp_path / "audit.log")
        if first == "event":
            log.event("step", detail="ok")
        else:
            log.check_writable()
    finally:
        os.umask(previous)
    assert spy.modes[0] == 0o640


def test_a_removed_attribute_is_summarized_as_removed():
    profile = find_profile("fortios", "firewall address", "7.6.7 build3704")
    assert summarized_changes(profile, {"comment": None}) == {"comment": "removed"}


def test_an_address_change_is_summarized_by_its_type_only():
    profile = find_profile("fortios", "system dhcp server/reserved-address", "7.6.7 build3704")
    summary = summarized_changes(profile, {"ip": "192.0.2.40", "mac": "00:00:5e:00:53:01"})
    assert summary == {"ip": "ipv4-address changed", "mac": "mac-address changed"}
    network = find_profile("fortios", "firewall address", "7.6.7 build3704")
    assert summarized_changes(network, {"subnet": "192.0.2.0/24"}) == {"subnet": "ipv4-network changed"}


def test_an_integer_change_is_summarized_as_its_value():
    profile = find_profile("exos", "vlan", "33.7.1.6")
    assert summarized_changes(profile, {"tag": 42}) == {"tag": 42}


def test_an_export_status_with_an_infinite_time_has_no_update_time(tmp_path):
    path = tmp_path / "export.json"
    path.write_text('{"updated_at": 1e999, "pending": 0}')
    assert export_updated_at(path) is None
    path.write_text('{"updated_at": 990.5, "pending": 0}')
    assert export_updated_at(path) == 990.5


def test_an_unreadable_export_status_is_blocked_by_name(tmp_path):
    assert state_of(tmp_path, updated_at="soon", pending=0) == ("blocked", "export status cannot be read")


def test_a_pending_queue_without_an_age_counts_as_fresh(tmp_path):
    result = state_of(tmp_path, {"export_max_age_seconds": 0}, updated_at=NOW, pending=1, audit_file="/var/log/a")
    assert result == ("pending", None)


def test_an_export_status_up_to_five_seconds_ahead_is_accepted(tmp_path):
    assert state_of(tmp_path, updated_at=NOW + 5, pending=0, audit_file="/var/log/a") == ("acknowledged", None)


def test_an_export_status_more_than_five_seconds_ahead_is_unreadable(tmp_path):
    assert state_of(tmp_path, updated_at=NOW + 5.5, pending=0) == ("blocked", "export status cannot be read")


def test_an_export_status_exactly_at_its_age_limit_is_not_stale(tmp_path):
    limit = DEFAULT_LIMITS["export_status_max_age_seconds"]
    assert state_of(tmp_path, updated_at=NOW - limit, pending=0, audit_file="/var/log/a") == ("acknowledged", None)
    assert state_of(tmp_path, updated_at=NOW - limit - 0.5, pending=0) == ("blocked", "export status is stale")


def test_an_export_queue_exactly_at_its_limit_is_only_pending(tmp_path):
    limit = DEFAULT_LIMITS["export_max_pending"]
    assert state_of(tmp_path, updated_at=NOW, pending=limit, audit_file="/var/log/a") == ("pending", None)
    over = state_of(tmp_path, updated_at=NOW, pending=limit + 1)
    assert over == ("blocked", "export queue holds %d events, over the limit" % (limit + 1))


def test_an_oldest_event_exactly_at_its_age_limit_is_only_pending(tmp_path):
    limit = DEFAULT_LIMITS["export_max_age_seconds"]
    fields = {"updated_at": NOW, "pending": 3, "audit_file": "/var/log/a"}
    assert state_of(tmp_path, oldest_pending_age_seconds=limit, **fields) == ("pending", None)
    over = state_of(tmp_path, oldest_pending_age_seconds=limit + 0.5, **fields)
    assert over == ("blocked", "the oldest unsent audit event is older than the limit")
