from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import tempfile

from .hostkey import HostKeyError, checked_pin

TARGET_LOCK_GID = 51004
TARGET_LOCK_DIRECTORY_MODE = 0o3770
TARGET_LOCK_FILE_MODE = 0o660
STANDALONE_DIRECTORY_MODE = 0o700
STANDALONE_FILE_MODE = 0o600
TARGET_LOCK_ENV = "NETOPS_TARGET_LOCK_DIR"
OPEN_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
OPEN_FILE_FLAGS = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
CREATE_FILE_FLAGS = OPEN_FILE_FLAGS | os.O_CREAT | os.O_EXCL


class TargetLockError(ValueError):
    pass


class TargetBusy(ValueError):
    pass


def _directory():
    shared = os.environ.get(TARGET_LOCK_ENV)
    if shared:
        path = Path(shared)
        expected_uid = 0
        expected_gid = TARGET_LOCK_GID
        expected_mode = TARGET_LOCK_DIRECTORY_MODE
    else:
        expected_uid = os.geteuid()
        expected_gid = os.getegid()
        expected_mode = STANDALONE_DIRECTORY_MODE
        path = Path(tempfile.gettempdir()) / ("netops-target-locks-%d" % expected_uid)
        created = False
        try:
            path.mkdir(mode=STANDALONE_DIRECTORY_MODE)
            created = True
        except FileExistsError:
            pass
        except OSError:
            raise TargetLockError("target lock directory is unavailable or unsafe") from None
    try:
        descriptor = os.open(path, OPEN_DIRECTORY_FLAGS)
    except OSError:
        raise TargetLockError("target lock directory is unavailable or unsafe") from None
    try:
        if not shared and created:
            os.fchmod(descriptor, STANDALONE_DIRECTORY_MODE)
        information = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(information.st_mode)
            or information.st_uid != expected_uid
            or information.st_gid != expected_gid
            or stat.S_IMODE(information.st_mode) != expected_mode
        ):
            raise TargetLockError("target lock directory is unavailable or unsafe")
        return descriptor, expected_gid, TARGET_LOCK_FILE_MODE if shared else STANDALONE_FILE_MODE
    except OSError:
        os.close(descriptor)
        raise TargetLockError("target lock directory is unavailable or unsafe") from None
    except Exception:
        os.close(descriptor)
        raise


def _open_lock(directory_fd, name, expected_gid, expected_mode):
    try:
        descriptor = os.open(name, CREATE_FILE_FLAGS, expected_mode, dir_fd=directory_fd)
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(name, OPEN_FILE_FLAGS, dir_fd=directory_fd)
        except OSError:
            raise TargetLockError("target lock file is unavailable or unsafe") from None
        created = False
    except OSError:
        raise TargetLockError("target lock file is unavailable or unsafe") from None
    try:
        if created:
            os.fchmod(descriptor, expected_mode)
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 1
            or information.st_gid != expected_gid
            or information.st_uid not in ({51001, 51003} if expected_mode == TARGET_LOCK_FILE_MODE else {os.geteuid()})
            or stat.S_IMODE(information.st_mode) != expected_mode
            or information.st_size != 0
        ):
            raise TargetLockError("target lock file is unavailable or unsafe")
        return descriptor
    except OSError:
        os.close(descriptor)
        raise TargetLockError("target lock file is unavailable or unsafe") from None
    except Exception:
        os.close(descriptor)
        raise


@contextmanager
def target_lock(trusted_pin):
    try:
        pin = checked_pin(trusted_pin)
    except (HostKeyError, TypeError):
        raise TargetLockError("trusted SSH host-key pin is invalid") from None
    name = hashlib.sha256(pin.encode("ascii")).hexdigest() + ".lock"
    directory_fd, expected_gid, file_mode = _directory()
    descriptor = None
    locked = False
    try:
        descriptor = _open_lock(directory_fd, name, expected_gid, file_mode)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError:
            raise TargetBusy("target is busy with another operation") from None
        except OSError:
            raise TargetLockError("target lock could not be acquired") from None
        yield
    finally:
        if descriptor is not None:
            try:
                if locked:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        os.close(directory_fd)
