import base64
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile

import pytest

from netops_core.target_lock import TargetBusy, TargetLockError, target_lock


def _pin(byte):
    return "SHA256:" + base64.b64encode(bytes([byte]) * 32).decode("ascii").rstrip("=")


def _isolated_directory(monkeypatch, directory):
    monkeypatch.delenv("NETOPS_TARGET_LOCK_DIR", raising=False)
    monkeypatch.setenv("TMPDIR", str(directory))
    monkeypatch.setattr(tempfile, "tempdir", str(directory))


def _contend(pin, result):
    try:
        with target_lock(pin):
            result.put("acquired")
    except TargetBusy:
        result.put("busy")


def test_target_lock_rejects_second_process(tmp_path, monkeypatch):
    _isolated_directory(monkeypatch, tmp_path)
    context = multiprocessing.get_context("fork")
    result = context.Queue()
    with target_lock(_pin(1)):
        process = context.Process(target=_contend, args=(_pin(1), result))
        process.start()
        process.join(5)
        assert process.exitcode == 0
        assert result.get(timeout=1) == "busy"


def test_target_lock_releases_after_exception(tmp_path, monkeypatch):
    _isolated_directory(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError):
        with target_lock(_pin(2)):
            raise RuntimeError("operation failed")
    with target_lock(_pin(2)):
        pass


def test_distinct_trusted_pins_use_independent_locks(tmp_path, monkeypatch):
    _isolated_directory(monkeypatch, tmp_path)
    with target_lock(_pin(3)):
        with target_lock(_pin(4)):
            pass


def test_standalone_lockfile_is_private_empty_and_persistent(tmp_path, monkeypatch):
    _isolated_directory(monkeypatch, tmp_path)
    pin = _pin(5)
    with target_lock(pin):
        pass
    directory = tmp_path / ("netops-target-locks-%d" % os.geteuid())
    files = list(directory.iterdir())
    assert len(files) == 1
    info = files[0].lstat()
    assert stat.S_ISREG(info.st_mode)
    assert info.st_nlink == 1
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_size == 0


def test_invalid_pin_fails_before_creating_lock_directory(tmp_path, monkeypatch):
    _isolated_directory(monkeypatch, tmp_path)
    with pytest.raises(TargetLockError, match="pin is invalid"):
        with target_lock("SHA256:bad"):
            pass
    assert list(tmp_path.iterdir()) == []



def test_bootstrap_demote_assigns_shared_group_only_to_helper_and_admin(monkeypatch):
    repository = Path(__file__).resolve().parents[3]
    monkeypatch.syspath_prepend(str(repository / "src"))
    from netops import bootstrap
    from netops.files import TARGET_LOCK_GID, TARGET_LOCK_ROLES, UIDS

    calls = []

    class Libc:
        @staticmethod
        def prctl(*arguments):
            return 0

    monkeypatch.setattr(bootstrap, "LIBC", Libc())
    monkeypatch.setattr(bootstrap.os, "setgroups", lambda groups: calls.append(("groups", list(groups))))
    monkeypatch.setattr(bootstrap.os, "setgid", lambda gid: calls.append(("gid", gid)))
    monkeypatch.setattr(bootstrap.os, "setuid", lambda uid: calls.append(("uid", uid)))

    for role, uid in UIDS.items():
        bootstrap.demote(uid, role in TARGET_LOCK_ROLES)

    expected = []
    for role, uid in UIDS.items():
        expected.extend([
            ("groups", [TARGET_LOCK_GID] if role in {"helper", "admin"} else []),
            ("gid", uid),
            ("uid", uid),
        ])
    assert calls == expected

@pytest.mark.parametrize("chmod_fails", [False, True])
def test_bootstrap_lock_directory_restores_groups(monkeypatch, chmod_fails):
    from netops import bootstrap
    from netops.files import TARGET_LOCK_GID

    groups = [17, 23]
    observed = []

    class Directory:
        def mkdir(self, mode):
            assert mode == 0o3770

    def setgroups(values):
        groups[:] = values

    def chmod(path, mode):
        observed.append((list(groups), mode))
        if chmod_fails:
            raise OSError("chmod refused")

    monkeypatch.setattr(bootstrap.os, "getgroups", lambda: list(groups))
    monkeypatch.setattr(bootstrap.os, "setgroups", setgroups)
    monkeypatch.setattr(bootstrap.os, "chown", lambda *args: None)
    monkeypatch.setattr(bootstrap.os, "chmod", chmod)
    if chmod_fails:
        with pytest.raises(OSError, match="chmod refused"):
            bootstrap.target_lock_directory(Directory())
    else:
        bootstrap.target_lock_directory(Directory())
    assert observed == [([17, 23, TARGET_LOCK_GID], 0o3770)]
    assert groups == [17, 23]
