import os
import stat

import pytest

from netops_core.audit import AuditPersistenceError, Recorder

TARGET_TEXT = b"a file that belongs to somebody else\n"


def target(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    path = elsewhere / "target"
    path.write_bytes(TARGET_TEXT)
    os.chmod(path, 0o644)
    return path


def untouched(path):
    assert path.read_bytes() == TARGET_TEXT
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644


def test_a_log_that_is_a_symbolic_link_is_refused_and_its_target_is_untouched(tmp_path):
    victim = target(tmp_path)
    log = tmp_path / "audit.jsonl"
    log.symlink_to(victim)
    with pytest.raises(AuditPersistenceError) as caught:
        Recorder(log, "admin").record("started")
    assert "symbolic link" in str(caught.value)
    untouched(victim)
    assert log.is_symlink()


def test_a_lock_that_is_a_symbolic_link_is_refused_and_its_target_is_untouched(tmp_path):
    victim = target(tmp_path)
    log = tmp_path / "audit.jsonl"
    keeper = Recorder(log, "auditor")
    keeper.lock_path().symlink_to(victim)
    with pytest.raises(AuditPersistenceError) as caught:
        keeper.record("started")
    assert "symbolic link" in str(caught.value)
    untouched(victim)
    assert keeper.lock_path().is_symlink()
    assert not log.exists()


def test_a_dangling_link_in_place_of_the_log_does_not_create_its_target(tmp_path):
    missing = tmp_path / "elsewhere" / "created-through-the-link"
    missing.parent.mkdir()
    log = tmp_path / "audit.jsonl"
    log.symlink_to(missing)
    with pytest.raises(AuditPersistenceError):
        Recorder(log, "helper").record("started")
    assert not missing.exists()
    assert log.is_symlink()


def test_a_log_reached_through_a_link_at_rotation_is_refused(tmp_path):
    log = tmp_path / "audit.jsonl"
    keeper = Recorder(log, "helper", segment_bytes=260, retained_segments=2)
    keeper.record("ssh_read", detail="x" * 150)
    victim = target(tmp_path)
    os.replace(log, tmp_path / "moved")
    log.symlink_to(victim)
    with pytest.raises(AuditPersistenceError):
        keeper.record("ssh_read", detail="y" * 150)
    untouched(victim)
    assert not (tmp_path / "audit.jsonl.1").exists()


def test_a_log_that_is_a_hard_link_is_refused_and_its_target_is_untouched(tmp_path):
    victim = target(tmp_path)
    log = tmp_path / "audit.jsonl"
    os.link(victim, log)
    with pytest.raises(AuditPersistenceError) as caught:
        Recorder(log, "admin").record("started")
    assert "hard link" in str(caught.value)
    untouched(victim)
    assert os.stat(victim).st_nlink == 2


def test_a_lock_that_is_a_hard_link_is_refused_and_its_target_is_untouched(tmp_path):
    victim = target(tmp_path)
    log = tmp_path / "audit.jsonl"
    keeper = Recorder(log, "auditor")
    os.link(victim, keeper.lock_path())
    with pytest.raises(AuditPersistenceError) as caught:
        keeper.record("started")
    assert "hard link" in str(caught.value)
    untouched(victim)
    assert not log.exists()


def test_a_fifo_in_place_of_the_log_is_refused_without_blocking(tmp_path):
    log = tmp_path / "audit.jsonl"
    os.mkfifo(log, 0o600)
    reader = os.open(log, os.O_RDONLY | os.O_NONBLOCK)
    try:
        with pytest.raises(AuditPersistenceError) as caught:
            Recorder(log, "helper").record("started")
        assert "not a regular file" in str(caught.value)
        assert os.read(reader, 4096) == b""
    finally:
        os.close(reader)
    assert stat.S_ISFIFO(os.lstat(log).st_mode)


def test_a_fifo_in_place_of_the_lock_is_refused_without_blocking(tmp_path):
    log = tmp_path / "audit.jsonl"
    keeper = Recorder(log, "auditor")
    os.mkfifo(keeper.lock_path(), 0o600)
    with pytest.raises(AuditPersistenceError) as caught:
        keeper.record("started")
    assert "not a regular file" in str(caught.value)
    assert stat.S_ISFIFO(os.lstat(keeper.lock_path()).st_mode)
    assert not log.exists()


def foreign_user(monkeypatch, own_calls):
    real = os.geteuid()
    calls = []

    def geteuid():
        calls.append(None)
        return real if len(calls) <= own_calls else real + 1

    monkeypatch.setattr(os, "geteuid", geteuid)


def owned_by_somebody_else(path):
    path.write_bytes(TARGET_TEXT)
    os.chmod(path, 0o644)


def test_a_log_of_another_user_is_refused_and_left_untouched(tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    owned_by_somebody_else(log)
    keeper = Recorder(log, "admin")
    foreign_user(monkeypatch, own_calls=1)
    with pytest.raises(AuditPersistenceError) as caught:
        keeper.record("started")
    assert "audit.jsonl belongs to user" in str(caught.value)
    untouched(log)


def test_a_lock_of_another_user_is_refused_and_left_untouched(tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    keeper = Recorder(log, "admin")
    owned_by_somebody_else(keeper.lock_path())
    foreign_user(monkeypatch, own_calls=0)
    with pytest.raises(AuditPersistenceError) as caught:
        keeper.record("started")
    assert ".audit.jsonl.lock belongs to user" in str(caught.value)
    untouched(keeper.lock_path())
    assert not log.exists()


def test_a_log_and_a_lock_that_exist_with_a_wider_mode_are_narrowed_to_0600(tmp_path):
    log = tmp_path / "audit.jsonl"
    keeper = Recorder(log, "auditor")
    for path in (log, keeper.lock_path()):
        path.write_bytes(b"")
        os.chmod(path, 0o644)
    keeper.record("started")
    for path in (log, keeper.lock_path()):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert log.read_bytes().count(b"\n") == 1
