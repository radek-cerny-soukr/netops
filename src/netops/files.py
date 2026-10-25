import os
from pathlib import Path
import stat
import tempfile
from .diagnostics import operation_error

STATE = Path(os.environ.get("NETOPS_STATE_DIR", "/var/lib/netops"))
RUNTIME = Path(os.environ.get("NETOPS_RUNTIME_DIR", "/run/netops"))
UIDS = {"gateway": 51000, "helper": 51001, "auditor": 51002, "admin": 51003}
MAX_MESSAGE = 4 * 1024 * 1024

def check_regular(fd, owner=None):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise operation_error("file-regular")
    if owner is not None and info.st_uid != owner:
        raise operation_error("file-owner")
    if info.st_mode & 0o077:
        raise operation_error("file-mode")
    return info

def read_private(path, maximum=MAX_MESSAGE, owner=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = check_regular(fd, owner)
        if not before.st_mode & stat.S_IRUSR:
            raise operation_error("file-mode")
        if before.st_size > maximum:
            raise operation_error("file-size")
        chunks = []
        remaining = maximum + 1
        while remaining:
            part = os.read(fd, min(remaining, 65536))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        after = check_regular(fd, owner)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise operation_error("file-changed")
        data = b"".join(chunks)
        if len(data) > maximum or len(data) != after.st_size:
            raise operation_error("file-length")
        return data
    finally:
        os.close(fd)

def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def write_private(path, data, owner=None, replace=False):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".netops-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        if owner is not None:
            os.fchown(descriptor, owner, owner)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("No progress writing private file")
            view = view[written:]
        os.fsync(descriptor)
        if replace:
            if path.exists() or path.is_symlink():
                old = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    check_regular(old, owner)
                finally:
                    os.close(old)
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
        sync_directory(path.parent)
    finally:
        os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        sync_directory(path.parent)

