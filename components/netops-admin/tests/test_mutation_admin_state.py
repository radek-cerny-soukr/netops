import errno
import fcntl
import json
import os
import re
import stat
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

from netops_admin import state
from netops_admin.errors import Rejected, StateUnreadable
from netops_admin.state import Store

CHANGE = "0123456789abcdef0123456789abcdef"
BOOT = "6F1C2D3E-4A5B-4C6D-8E9F-0A1B2C3D4E5F"
OTHER_BOOT = "11111111-2222-4333-8444-555555555555"
TEMPORARY = re.compile(r"\..+\.[0-9a-f]{16}\.tmp")


class OsProxy:
    def __init__(self, **overrides):
        self.overrides = overrides
        self.opened = []
        self.replaced = []

    def __getattr__(self, name):
        if name in self.overrides:
            return self.overrides[name]
        return getattr(os, name)

    def open(self, path, flags, *mode):
        self.opened.append(os.fspath(path))
        if "open" in self.overrides:
            return self.overrides["open"](path, flags, *mode)
        return os.open(path, flags, *mode)

    def replace(self, source, target):
        self.replaced.append(os.fspath(target))
        if "replace" in self.overrides:
            return self.overrides["replace"](source, target)
        return os.replace(source, target)


def record(**fields):
    document = {"change_id": CHANGE, "request_id": "req-0001-example", "device": "lab", "status": "finished"}
    document.update(fields)
    return document


def stored(store, document, name=CHANGE):
    path = store.operations / ("%s.json" % name)
    path.write_text(json.dumps(document))
    return path


def unreadable(call, *args):
    with pytest.raises(StateUnreadable) as caught:
        call(*args)
    return caught.value.reasons


def refused(call, *args):
    with pytest.raises(Rejected) as caught:
        call(*args)
    return caught.value.reasons


def operation_message(name=CHANGE):
    return ["the state file operations/%s.json cannot be read; a person must check it" % name]


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


@pytest.fixture
def umask():
    previous = os.umask(0o022)
    yield
    os.umask(previous)


def test_a_plain_operation_record_is_read(store):
    stored(store, record(steps=[{"step": "planned"}], safeguard={"fire_at": "x", "name": "n"}, foreign_sessions=0))
    assert store.operation(CHANGE)["status"] == "finished"


@pytest.mark.parametrize("fields", [
    {"steps": "planned"}, {"steps": [{"detail": "no step name"}]}, {"steps": ["planned"]},
    {"foreign_sessions": -1}, {"foreign_sessions": True}, {"foreign_sessions": 1.5},
    {"plan": "text"}, {"audit_policy": ["x"]},
    {"safeguard": {}}, {"safeguard": {"fire_at": "x", "name": 5}},
    {"result": 5}, {"device": "lab\nother"}, {"reason": "x" * 201},
    {"created_at_epoch": float("nan")}, {"finished_at_epoch": float("inf")}, {"budget_at_epoch": True},
])
def test_an_operation_record_with_a_malformed_field_is_unreadable(store, fields):
    stored(store, record(**fields))
    assert unreadable(store.operation, CHANGE) == operation_message()


@pytest.mark.parametrize("change_id", ["../../evil", "../evil", "..", "a/b", "", CHANGE[:31] + "/", CHANGE + "\n"])
def test_an_operation_is_looked_up_only_by_a_well_formed_change_id(store, change_id):
    (store.root.parent / "evil.json").write_text(json.dumps(record(change_id="evil")))
    (store.root / "evil.json").write_text(json.dumps(record(change_id="evil")))
    stored(store, record(change_id=".."), "..")
    assert store.operation(change_id) is None


def test_an_operation_record_behind_a_symbolic_link_is_unreadable(store, tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(record()))
    (store.operations / ("%s.json" % CHANGE)).symlink_to(outside)
    assert unreadable(store.operation, CHANGE) == operation_message()


@pytest.mark.parametrize("document", [
    {"change_id": CHANGE, "reason": "r"},
    {"device": "lab", "change_id": CHANGE},
    {"device": "lab", "reason": "r", "change_id": "../evil"},
    {"device": "lab", "reason": "r", "change_id": 5},
    {"device": "lab\n", "reason": "r"},
])
def test_a_malformed_block_is_unreadable(store, document):
    (store.blocks / "lab.json").write_text(json.dumps(document))
    assert unreadable(store.blocked, "lab") == ["the state file blocked/lab.json cannot be read; a person must check it"]


def test_a_block_with_or_without_a_change_is_read(store):
    store.block("lab", CHANGE, "postcheck failed")
    assert store.blocked("lab") == {"device": "lab", "change_id": CHANGE, "reason": "postcheck failed"}
    store.block("lab", None, "administrator table")
    assert store.blocked("lab")["change_id"] is None


def test_a_baseline_without_a_text_fingerprint_is_unreadable(store):
    (store.baselines / "lab.json").write_text(json.dumps({"device": "lab", "accounts": 5}))
    assert unreadable(store.baseline, "lab") == ["the state file baselines/lab.json cannot be read; a person must check it"]


def test_a_saved_baseline_names_its_device(store):
    store.save_baseline("lab", "f" * 64)
    assert json.loads((store.baselines / "lab.json").read_text()) == {"device": "lab", "accounts": "f" * 64}
    assert store.baseline("lab") == "f" * 64


def test_a_request_is_looked_up_only_by_a_well_formed_request_id(store):
    (store.root.parent / "evil-request.json").write_text(json.dumps(
        {"request_id": "../../evil-request", "change_id": CHANGE, "request_sha256": "x", "device": "lab"}))
    assert store.request("../../evil-request") is None
    assert store.request(5) is None


@pytest.mark.parametrize("fields", [{"device": "lab\nother"}, {"request_id": "req-0002-example"}])
def test_a_request_record_that_does_not_match_is_unreadable(store, fields):
    document = {"request_id": "req-0001-example", "change_id": CHANGE, "request_sha256": "x", "device": "lab"}
    document.update(fields)
    (store.requests / "req-0001-example.json").write_text(json.dumps(document))
    assert unreadable(store.request, "req-0001-example") == [
        "the state file requests/req-0001-example.json cannot be read; a person must check it"]


def test_a_state_entry_that_cannot_be_removed_is_unreadable(store):
    (store.blocks / "lab.json").mkdir()
    assert unreadable(store.unblock, "lab", None) == ["the state file blocked/lab.json cannot be read; a person must check it"]


def test_an_unreadable_count_of_refusals_needs_a_person(store):
    (store.root / "rejections.json").write_text('["x"]')
    assert refused(store.rejections_since, 0) == [
        "the count of refused requests (rejections.json) cannot be read; a person must check it"]


def test_a_refusal_exactly_at_the_window_start_is_kept_and_counted(store):
    (store.root / "rejections.json").write_text("[1000.0, 999.5]")
    store.note_rejection(1000.0 + state.REJECTION_WINDOW)
    assert json.loads((store.root / "rejections.json").read_text()) == [1000.0, 1000.0 + state.REJECTION_WINDOW]
    assert store.rejections_since(1000.0) == 2
    assert store.rejections_since(1000.5) == 1


def test_state_files_are_canonical_ascii_json(tmp_path):
    path = tmp_path / "record.json"
    document = {"zeta": 1, "alpha": {"n\u00e1zev": "\u00e9"}}
    state.write_atomic(path, document)
    raw = path.read_bytes()
    assert raw.decode("ascii") == json.dumps(document, sort_keys=True, ensure_ascii=True, indent=1) + "\n"
    assert raw.startswith(b'{\n "alpha": {\n  "n\\u00e1zev": "\\u00e9"\n }')


def test_state_files_are_created_private(tmp_path, umask):
    path = tmp_path / "record.json"
    state.write_atomic(path, {"a": 1})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_short_state_write_is_an_error_by_name_and_leaves_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "os", OsProxy(write=lambda descriptor, data: os.write(descriptor, data[:-1])))
    with pytest.raises(OSError) as caught:
        state.write_atomic(tmp_path / "record.json", {"a": 1})
    assert str(caught.value) == "short write"
    assert list(tmp_path.iterdir()) == []


def test_an_interrupted_state_write_leaves_a_temporary_the_next_start_removes(tmp_path, monkeypatch):
    root = tmp_path / "state"
    Store(root)

    def broken(source, target):
        raise OSError(errno.EIO, os.strerror(errno.EIO))
    proxy = OsProxy(replace=broken)
    monkeypatch.setattr(state, "os", proxy)
    with pytest.raises(OSError):
        state.write_atomic(root / "operations" / "x.json", {"a": 1})
    monkeypatch.undo()
    temporary = [path for path in proxy.opened if "x.json" in os.path.basename(path)][0]
    assert TEMPORARY.fullmatch(os.path.basename(temporary)), temporary
    assert os.path.basename(temporary).startswith(".x.json.")
    with open(temporary, "w") as handle:
        handle.write("{}")
    Store(root)
    assert not os.path.exists(temporary)


def test_the_original_error_surfaces_when_the_temporary_is_already_gone(tmp_path, monkeypatch):
    def vanished(source, target):
        os.unlink(source)
        raise OSError(errno.EIO, "fixture replace failed")
    monkeypatch.setattr(state, "os", OsProxy(replace=vanished))
    with pytest.raises(OSError) as caught:
        state.write_atomic(tmp_path / "record.json", {"a": 1})
    assert caught.value.strerror == "fixture replace failed"


def test_cleanup_keeps_what_is_not_a_regular_temporary(tmp_path):
    root = tmp_path / "state"
    Store(root)
    link = root / "operations" / ".x.json.0123456789abcdef.tmp"
    link.symlink_to(tmp_path / "elsewhere")
    folder = root / "requests" / ".y.json.0123456789abcdef.tmp"
    folder.mkdir()
    Store(root)
    assert link.is_symlink() and folder.is_dir()


def test_cleanup_syncs_a_directory_only_after_it_removed_a_temporary(tmp_path, monkeypatch):
    root = tmp_path / "state"
    Store(root)
    synced = []
    monkeypatch.setattr(state, "_fsync_directory", lambda path: synced.append(path))
    Store(root)
    assert synced == []
    (root / "operations" / ".x.json.0123456789abcdef.tmp").write_text("{}")
    Store(root)
    assert synced == [root / "operations"]


def test_a_store_creates_its_lock_directory(store):
    assert (store.root / "locks").is_dir()
    with store.lock("lab"):
        assert (store.root / "locks" / "lab.lock").is_file()


def test_a_store_over_a_file_names_the_system_error(tmp_path):
    (tmp_path / "state").write_text("")
    assert unreadable(Store, tmp_path / "state") == ["the state directory cannot be used: %s" % os.strerror(errno.EEXIST)]


def test_a_store_over_an_unusable_name_names_the_error_type(tmp_path):
    assert unreadable(Store, str(tmp_path / "st\0ate")) == ["the state directory cannot be used: ValueError"]


def test_a_lock_file_is_created_private(store, umask):
    with store.lock("lab"):
        pass
    assert stat.S_IMODE((store.locks / "lab.lock").stat().st_mode) == 0o600


def test_a_lock_behind_a_symbolic_link_names_the_system_error(store, tmp_path):
    (store.locks / "lab.lock").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(Rejected) as caught:
        store.lock("lab").__enter__()
    assert caught.value.reasons == ["the lock file lab.lock cannot be used: %s" % os.strerror(errno.ELOOP)]


def test_a_lock_that_is_not_a_regular_file_is_refused_and_closed(store):
    path = store.locks / "lab.lock"
    os.mkfifo(path)
    reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        before = set(os.listdir("/proc/self/fd"))
        with pytest.raises(Rejected) as caught:
            store.lock("lab").__enter__()
        assert caught.value.reasons == ["the lock file lab.lock is not a regular file"]
        assert set(os.listdir("/proc/self/fd")) == before
    finally:
        os.close(reader)


def test_a_held_device_lock_is_refused_by_name(store):
    with store.lock("lab"):
        with pytest.raises(Rejected) as caught:
            store.lock("lab").__enter__()
    assert caught.value.reasons == ["another operation holds the device lock"]


def _hold(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def test_the_admission_lock_waits_for_a_short_holder(store):
    holder = _hold(store.root / state.ADMISSION_LOCK)
    releaser = threading.Timer(0.3, lambda: os.close(holder))
    releaser.start()
    try:
        began = time.monotonic()
        with store.admission():
            waited = time.monotonic() - began
    finally:
        releaser.join()
    assert 0.2 <= waited < state.ADMISSION_WAIT_SECONDS


def test_the_admission_lock_gives_up_exactly_at_its_deadline(store, monkeypatch):
    holder = _hold(store.root / state.ADMISSION_LOCK)
    moments = iter([100.0, 100.0 + state.ADMISSION_WAIT_SECONDS, 200.0, 300.0])
    sleeps = []
    monkeypatch.setattr(state, "time", SimpleNamespace(monotonic=lambda: next(moments), sleep=sleeps.append))
    lock = store.admission()
    try:
        with pytest.raises(Rejected) as caught:
            lock.__enter__()
    finally:
        os.close(holder)
    assert caught.value.reasons == ["another operation holds the admission lock of the journal"]
    assert sleeps == []
    assert lock.descriptor is None


def test_a_write_probe_is_a_hidden_name_that_is_never_a_record(store, monkeypatch):
    proxy = OsProxy()
    monkeypatch.setattr(state, "os", proxy)
    store.check_writable()
    assert len(proxy.replaced) == 1
    assert re.fullmatch(r"\.write-probe-[0-9a-f]{16}", os.path.basename(proxy.replaced[0])), proxy.replaced
    assert [path.name for path in store.root.iterdir() if path.name.startswith(".write-probe")] == []


def test_a_journal_that_cannot_be_written_names_the_system_error(store, monkeypatch):
    def full(path, flags, *mode):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
    monkeypatch.setattr(state, "os", OsProxy(open=full))
    assert refused(store.check_writable) == ["the journal cannot be written durably: %s" % os.strerror(errno.ENOSPC)]


class Sysctl:
    def __init__(self, boot=BOOT, error=None):
        self.boot = boot
        self.error = error
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(argv, 0, self.boot + "\n", "")


@pytest.fixture
def darwin(monkeypatch):
    def install(boot=BOOT, error=None, monotonic=500.0, epoch=9000.0):
        sysctl = Sysctl(boot, error)
        monkeypatch.setattr(state, "sys", SimpleNamespace(platform="darwin"))
        monkeypatch.setattr(state, "subprocess", SimpleNamespace(run=sysctl, SubprocessError=subprocess.SubprocessError))
        monkeypatch.setattr(state, "time", SimpleNamespace(monotonic=lambda: monotonic, time=lambda: epoch))
        return sysctl
    return install


def anchor_file(store, document):
    (store.root / "budget-clock.json").write_text(json.dumps(document))


def test_on_macos_the_boot_session_comes_from_a_bounded_checked_sysctl(store, darwin):
    sysctl = darwin()
    assert store.budget_now() == 9000.0
    assert sysctl.calls == [(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
                             {"capture_output": True, "text": True, "timeout": 2, "check": True})]
    assert json.loads((store.root / "budget-clock.json").read_text()) == {"boot": BOOT, "epoch": 9000.0,
                                                                          "monotonic": 500.0}
    assert (store.root / ".budget-clock.lock").is_file()


def test_a_failing_boot_session_query_names_its_error_type(store, darwin):
    darwin(error=subprocess.TimeoutExpired(["sysctl"], 2))
    assert unreadable(store.budget_now) == ["the host budget clock cannot be read: TimeoutExpired"]


@pytest.mark.parametrize("boot", ["", "not-a-boot-identity", BOOT + "0"])
def test_an_unusable_boot_identity_is_refused_by_name(store, darwin, boot):
    darwin(boot=boot)
    assert unreadable(store.budget_now) == ["the host boot identity cannot be read for change budgets"]


def test_an_uppercase_boot_identity_and_anchor_are_accepted(store, darwin):
    darwin(monotonic=700.0)
    anchor_file(store, {"boot": BOOT, "epoch": 1000.0, "monotonic": 600.0})
    assert store.budget_now() == 1100.0


def test_the_budget_clock_continues_from_its_anchor(store, darwin):
    darwin(monotonic=750.5, epoch=123456.0)
    anchor_file(store, {"boot": BOOT, "epoch": 1000.0, "monotonic": 500.0})
    assert store.budget_now() == 1250.5


def test_a_new_boot_restarts_the_budget_clock_anchor(store, darwin):
    darwin(monotonic=20.0, epoch=5000.0)
    anchor_file(store, {"boot": OTHER_BOOT, "epoch": 1000.0, "monotonic": 500.0})
    assert store.budget_now() == 5000.0


@pytest.mark.parametrize("document", [
    {"boot": BOOT, "epoch": 1000.0, "monotonic": 500.0, "extra": 1},
    {"boot": BOOT, "epoch": 1000.0},
    {"boot": "not-a-boot-identity", "epoch": 1000.0, "monotonic": 500.0},
    {"boot": BOOT, "epoch": float("nan"), "monotonic": 500.0},
    {"boot": BOOT, "epoch": "1000", "monotonic": 500.0},
    {"boot": BOOT, "epoch": 1000.0, "monotonic": float("inf")},
    {"boot": BOOT, "epoch": 1000.0, "monotonic": True},
    [BOOT, 1000.0, 500.0],
])
def test_a_malformed_budget_clock_anchor_is_unreadable(store, darwin, document):
    darwin()
    anchor_file(store, document)
    assert unreadable(store.budget_now) == ["the state file budget-clock.json cannot be read; a person must check it"]


def test_a_monotonic_clock_behind_its_anchor_is_refused_by_name(store, darwin):
    darwin(monotonic=400.0)
    anchor_file(store, {"boot": BOOT, "epoch": 1000.0, "monotonic": 500.0})
    assert unreadable(store.budget_now) == ["the host monotonic clock moved backwards for change budgets"]
