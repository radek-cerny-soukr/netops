import json

import pytest

from netops_core.audit import AuditFieldError, Recorder


def test_diagnostic_recipe_window_and_timeout_are_allowed_metadata(tmp_path):
    path = tmp_path / "audit.jsonl"
    recorder = Recorder(path, "helper")
    recorder.record("diagnostic", recipe="logs", since="2026-01-02 00:00:00", until="2026-01-03 23:59:59", timeout=5)
    record = json.loads(path.read_text())
    assert record["recipe"] == "logs"
    assert record["since"] == "2026-01-02 00:00:00"
    assert record["until"] == "2026-01-03 23:59:59"
    assert record["timeout"] == 5


def test_unknown_diagnostic_field_is_rejected_before_writing(tmp_path):
    path = tmp_path / "audit.jsonl"
    recorder = Recorder(path, "helper")
    with pytest.raises(AuditFieldError, match="unknown_diagnostic"):
        recorder.record("diagnostic", recipe="sessions", timeout=5, unknown_diagnostic=True)
    assert not path.exists()
