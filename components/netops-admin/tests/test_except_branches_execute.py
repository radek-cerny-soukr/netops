from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request

from netops_admin import exec_fortios, execute
from netops_admin.errors import Rejected
from netops_core.target_lock import TargetBusy, TargetLockError


@pytest.mark.parametrize("error", [TargetBusy("target is busy"), TargetLockError("lock unavailable")])
def test_target_lock_failure_becomes_rejection(monkeypatch, error):
    @contextmanager
    def failing_lock(_fingerprint):
        raise error
        yield

    monkeypatch.setattr(execute, "target_lock", failing_lock)
    with pytest.raises(Rejected) as caught:
        with execute._target_lock(SimpleNamespace(host_key_fingerprint="SHA256:" + "A" * 43)):
            pytest.fail("the body must not run without the target lock")
    assert caught.value.reasons == [str(error)]


def test_plan_precheck_rejection_is_returned_unchanged(tmp_path, monkeypatch):
    def refuse(_access, _device, _plan, _snapshot_text=""):
        raise Rejected(["synthetic plan refusal"])

    monkeypatch.setattr(exec_fortios, "plan_prechecks", refuse)
    answer = execute.preview(make_runtime(tmp_path, FakeFortiOS()), "lab", request())
    assert answer["result"] == "rejected"
    assert answer["reasons"] == ["synthetic plan refusal"]


def test_plan_precheck_read_error_becomes_rejection(tmp_path, monkeypatch):
    def broken(_access, _device, _plan, _snapshot_text=""):
        raise RuntimeError("synthetic read failure")

    monkeypatch.setattr(exec_fortios, "plan_prechecks", broken)
    answer = execute.preview(make_runtime(tmp_path, FakeFortiOS()), "lab", request())
    assert answer["result"] == "rejected"
    assert answer["reasons"] == ["the device could not be read before any change: synthetic read failure"]
