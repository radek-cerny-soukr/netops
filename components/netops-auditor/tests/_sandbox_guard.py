"""Sandbox of the test suite: writes stay in the test's temporary directories, the network on loopback.

tests/conftest.py loads this module and re-exports its hooks. While a test runs (setup, call
and teardown), every write entry point of the standard library is wrapped:

- builtins.open, io.open and pathlib.Path.open/write_text/write_bytes in a writing mode
  (w, a, x or +), os.open with O_WRONLY, O_RDWR, O_CREAT, O_TRUNC or O_APPEND;
- os.replace, os.rename, os.link, os.symlink, os.unlink, os.remove, os.rmdir, os.mkdir
  (and through it os.makedirs), os.chmod, os.chown, os.truncate, os.mkfifo, os.mknod,
  os.fchmod and os.fchown on a descriptor of a foreign path;
- shutil.copy, copy2, copyfile, copytree and move;
- sqlite3.connect of a database file in a writable mode.

A target is allowed only inside the test's tmp_path, the pytest base temporary directory
or the temporary directory of the process (TMPDIR). Symbolic links are resolved the way the
operation resolves them: open, chmod and truncate follow the last component; mkdir, unlink,
rename/replace, link/symlink and os.open with O_NOFOLLOW or O_CREAT|O_EXCL act on the entry
itself. mkdir, mkfifo and mknod of a path that already exists cannot write and are passed
through to fail with EEXIST. Special files (character and block
devices such as /dev/null and /dev/zero, FIFOs, sockets) are never a valid target of a
write, a replace or a rename, and never a valid source of a copy, wherever they live.
os.open of an existing special file is allowed as a probe, because the code under test opens
a path with O_NONBLOCK and refuses it after fstat; the first write to that descriptor
(os.write, writev, pwrite, ftruncate, os.fdopen or open in a writing mode) is refused. The
null device that the standard subprocess module opens for DEVNULL is not a write.

Each refusal raises SandboxViolation (a PermissionError carrying the path) and is also
recorded, so a refusal that the code under test swallows still fails the test with the path
in the message.

The network part needs pytest-socket (requirements-release.in): connect() is allowed to
127.0.0.1 and ::1 and to Unix sockets only. The sandbox adds what pytest-socket does not
cover: bind() to a non-loopback address (including the wildcard address), sendto() to a
non-loopback address, name resolution of anything but a literal address or localhost, and
reverse resolution of anything but a loopback address.

Documented exceptions, each with its reason:

- EXEMPT_DIRECTORIES: component-relative directories a test may write into. Empty: no test
  of the suite writes outside its temporary directories.
- EXEMPT_CALLERS: a standard-library module and the directory it may write into while it is
  on the call stack. multiprocessing.heap places the shared-memory arena of a
  multiprocessing.Value/Array in /dev/shm (mkstemp, unlinked at once); that is the kernel's
  shared memory, not a file of the host.
- A FIFO inside the sandbox may be written by the test itself (the writing frame is a
  function in this tests/ directory): tests feed a hostile pipe to the code under test to
  prove that it is refused. The code under test writing into a FIFO is still refused.
"""

from __future__ import annotations

import builtins
import errno
import io
import ipaddress
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import stat
import sys
import tempfile

import pytest

COMPONENT = Path(__file__).resolve().parents[1]
TESTS = str(COMPONENT / "tests") + os.sep
EXEMPT_DIRECTORIES: dict[str, str] = {}
EXEMPT_CALLERS = {
    "multiprocessing.heap": ("/dev/shm", "shared-memory arena of multiprocessing, unlinked at once"),
}
LOOPBACK_HOSTS = ("127.0.0.1", "::1")
LOCAL_NAMES = frozenset(("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"))
WRITE_MODE_CHARACTERS = frozenset("wax+")
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
SPECIAL_TYPES = (stat.S_ISCHR, stat.S_ISBLK, stat.S_ISFIFO, stat.S_ISSOCK)
ACTIVE = None


class SandboxViolation(PermissionError):
    """An operation of a test reached outside the test sandbox."""


def _real(path: str, follow: bool = True) -> str:
    if follow:
        return os.path.realpath(path)
    head, name = os.path.split(os.path.abspath(path))
    return os.path.join(os.path.realpath(head), name)


def _descriptor_path(descriptor: int) -> str | None:
    try:
        return os.readlink("/proc/self/fd/%d" % descriptor)
    except OSError:
        return None


def _resolve(path, dir_fd=None) -> str | None:
    if isinstance(path, int):
        return _descriptor_path(path)
    try:
        text = os.fsdecode(path)
    except TypeError:
        return None
    if dir_fd is not None and not os.path.isabs(text):
        base = _descriptor_path(dir_fd)
        if base is None:
            return None
        text = os.path.join(base, text)
    return os.path.abspath(text)


def _is_special(path: str, follow: bool) -> bool:
    try:
        mode = os.stat(path, follow_symlinks=follow).st_mode
    except (OSError, ValueError):
        return False
    return any(check(mode) for check in SPECIAL_TYPES)


def _loopback(host) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    if host in LOCAL_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _literal(host) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if host is None:
        return True
    if not isinstance(host, str):
        return False
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        return True
    except ValueError:
        return False


def _calling_modules(limit: int = 12):
    frame = sys._getframe(1)
    while frame is not None and limit:
        if frame.f_code.co_filename != __file__:
            yield frame.f_globals.get("__name__"), frame.f_code.co_filename
            limit -= 1
        frame = frame.f_back


def _fed_by_the_test() -> bool:
    for _module, filename in _calling_modules(1):
        return filename.startswith(TESTS)
    return False


def _exempt_caller(resolved: str) -> bool:
    for module, _filename in _calling_modules():
        rule = EXEMPT_CALLERS.get(module)
        if rule is not None and (resolved == rule[0] or resolved.startswith(rule[0] + os.sep)):
            return True
    return False


def _fifo(path: str) -> bool:
    try:
        return stat.S_ISFIFO(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def _inet(sock) -> bool:
    return sock.family in (socket.AF_INET, socket.AF_INET6)


class Sandbox:
    def __init__(self, nodeid: str, roots: list[str]):
        self.nodeid = nodeid
        self.roots = sorted({_real(root) for root in roots if root})
        self.violations: list[str] = []
        self.special_descriptors: dict[int, tuple[int, int, str]] = {}
        self._originals: list[tuple[object, str, object]] = []

    def allowed(self, path: str, follow: bool = True) -> bool:
        resolved = _real(path, follow)
        return any(resolved == root or resolved.startswith(root + os.sep) for root in self.roots)

    def refuse(self, operation: str, path, reason: str):
        message = "%s %s: %s" % (operation, path, reason)
        self.violations.append(message)
        raise SandboxViolation(errno.EPERM, "test sandbox refused " + message, str(path))

    def target(self, operation: str, path, dir_fd=None, *, special_follow=True, test_fed=False, follow=True):
        resolved = _resolve(path, dir_fd)
        if resolved is None:
            return
        if _is_special(resolved, special_follow):
            if test_fed and _fifo(resolved) and self.allowed(resolved) and _fed_by_the_test():
                return
            self.refuse(operation, resolved, "special file is never a write target")
        if not self.allowed(resolved, follow) and not _exempt_caller(resolved):
            self.refuse(operation, resolved, "outside tmp_path, the pytest base temporary directory and TMPDIR")

    def probe(self, path, dir_fd=None) -> str | None:
        """Return the resolved path when os.open would open an existing special file."""
        resolved = _resolve(path, dir_fd)
        if resolved is not None and _is_special(resolved, True):
            return resolved
        return None

    def remember_special(self, descriptor: int, resolved: str) -> None:
        try:
            status = os.fstat(descriptor)
        except OSError:
            return
        self.special_descriptors[descriptor] = (status.st_dev, status.st_ino, resolved)

    def descriptor_write(self, operation: str, descriptor) -> None:
        if not isinstance(descriptor, int) or descriptor not in self.special_descriptors:
            return
        device, inode, resolved = self.special_descriptors[descriptor]
        try:
            status = os.fstat(descriptor)
        except OSError:
            self.special_descriptors.pop(descriptor, None)
            return
        if (status.st_dev, status.st_ino) != (device, inode):
            self.special_descriptors.pop(descriptor, None)
            return
        if stat.S_ISFIFO(status.st_mode) and self.allowed(resolved) and _fed_by_the_test():
            return
        self.refuse(operation, resolved, "special file is never a write target")

    def source(self, operation: str, path, dir_fd=None):
        resolved = _resolve(path, dir_fd)
        if resolved is not None and _is_special(resolved, True):
            self.refuse(operation, resolved, "special file is never a copy or rename source")

    def _patch(self, owner, name, factory):
        original = getattr(owner, name)
        owned = not isinstance(owner, type) or name in vars(owner)
        self._originals.append((owner, name, original if owned else None))
        setattr(owner, name, factory(original))

    def activate(self) -> None:
        global ACTIVE
        ACTIVE = self
        sandbox = self

        def opener(original):
            def guarded_open(file, mode="r", *args, **kwargs):
                if isinstance(mode, str) and WRITE_MODE_CHARACTERS & set(mode):
                    if isinstance(file, int):
                        sandbox.descriptor_write("open(%r) of a descriptor" % mode, file)
                    else:
                        sandbox.target("open(%r)" % mode, file, test_fed=True)
                return original(file, mode, *args, **kwargs)
            return guarded_open

        def os_opener(original):
            def guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
                special = None
                if flags & WRITE_FLAGS:
                    caller = sys._getframe(1).f_globals.get("__name__")
                    special = sandbox.probe(path, dir_fd)
                    if caller == "subprocess" and special == os.devnull:
                        special = None
                    elif special is None:
                        entry = flags & os.O_NOFOLLOW or (flags & os.O_CREAT and flags & os.O_EXCL)
                        sandbox.target("os.open", path, dir_fd, follow=not entry)
                descriptor = original(path, flags, mode, dir_fd=dir_fd)
                if special is not None:
                    sandbox.remember_special(descriptor, special)
                return descriptor
            return guarded_os_open

        def moving(label):
            def factory(original):
                def guarded(src, dst, *args, src_dir_fd=None, dst_dir_fd=None, **kwargs):
                    sandbox.source(label, src, src_dir_fd)
                    sandbox.target(label + " (source removed)", src, src_dir_fd, special_follow=False, follow=False)
                    sandbox.target(label, dst, dst_dir_fd, special_follow=False, follow=False)
                    return original(src, dst, *args, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, **kwargs)
                return guarded
            return factory

        def creating(label):
            def factory(original):
                def guarded(src, dst, *args, **kwargs):
                    sandbox.target(label, dst, kwargs.get("dir_fd"), special_follow=False, follow=False)
                    return original(src, dst, *args, **kwargs)
                return guarded
            return factory

        def removing(label):
            def factory(original):
                def guarded(path, *args, **kwargs):
                    resolved = _resolve(path, kwargs.get("dir_fd"))
                    if resolved is not None and not sandbox.allowed(resolved, False) and not _exempt_caller(resolved):
                        sandbox.refuse(label, resolved, "outside tmp_path, the pytest base temporary directory and TMPDIR")
                    return original(path, *args, **kwargs)
                return guarded
            return factory

        def changing(label, special=False, entry=False):
            def factory(original):
                def guarded(path, *args, **kwargs):
                    resolved = _resolve(path, kwargs.get("dir_fd"))
                    if entry and resolved is not None and os.path.lexists(resolved):
                        resolved = None
                    if resolved is not None:
                        if special and _is_special(resolved, True):
                            sandbox.refuse(label, resolved, "special file is never a write target")
                        follow = not entry and kwargs.get("follow_symlinks", True)
                        if not sandbox.allowed(resolved, follow):
                            sandbox.refuse(label, resolved, "outside tmp_path, the pytest base temporary directory and TMPDIR")
                    return original(path, *args, **kwargs)
                return guarded
            return factory

        def descriptor(label):
            def factory(original):
                def guarded(fd, *args, **kwargs):
                    resolved = _resolve(fd)
                    if resolved is not None and resolved.startswith("/") and not sandbox.allowed(resolved):
                        sandbox.refuse(label, resolved, "outside tmp_path, the pytest base temporary directory and TMPDIR")
                    return original(fd, *args, **kwargs)
                return guarded
            return factory

        def copying(label):
            def factory(original):
                def guarded(src, dst, *args, **kwargs):
                    sandbox.source(label, src)
                    sandbox.target(label, dst)
                    return original(src, dst, *args, **kwargs)
                return guarded
            return factory

        def path_writer(label):
            def factory(original):
                def guarded(self, *args, **kwargs):
                    sandbox.target(label, self, test_fed=True)
                    return original(self, *args, **kwargs)
                return guarded
            return factory

        def path_opener(original):
            def guarded(self, mode="r", *args, **kwargs):
                if isinstance(mode, str) and WRITE_MODE_CHARACTERS & set(mode):
                    sandbox.target("Path.open(%r)" % mode, self, test_fed=True)
                return original(self, mode, *args, **kwargs)
            return guarded

        def descriptor_writer(label):
            def factory(original):
                def guarded(fd, *args, **kwargs):
                    sandbox.descriptor_write(label, fd)
                    return original(fd, *args, **kwargs)
                return guarded
            return factory

        def database(original):
            def guarded(database, *args, **kwargs):
                name = os.fsdecode(database) if isinstance(database, (str, bytes, os.PathLike)) else ""
                if kwargs.get("uri") and name.startswith("file:"):
                    location, _, query = name[5:].partition("?")
                    if "mode=ro" not in query and "mode=memory" not in query and location:
                        sandbox.target("sqlite3.connect", location)
                elif name and name != ":memory:":
                    sandbox.target("sqlite3.connect", name)
                return original(database, *args, **kwargs)
            return guarded

        def binder(original):
            def guarded(sock, address):
                if _inet(sock) and isinstance(address, tuple) and not _loopback(address[0]):
                    sandbox.refuse("socket.bind", address[0] or "<wildcard>", "only loopback addresses may be bound")
                return original(sock, address)
            return guarded

        def sender(original):
            def guarded(sock, data, *args):
                address = args[-1] if args else None
                if _inet(sock) and isinstance(address, tuple) and not _loopback(address[0]):
                    sandbox.refuse("socket.sendto", address[0], "only loopback addresses may be reached")
                return original(sock, data, *args)
            return guarded

        def reverse_resolver(original):
            def guarded(host):
                if not _loopback(host):
                    sandbox.refuse("socket.gethostbyaddr", host, "reverse resolution leaves the host")
                return original(host)
            return guarded

        def resolver(label):
            def factory(original):
                def guarded(host, *args, **kwargs):
                    if not (_literal(host) or _loopback(host)):
                        sandbox.refuse(label, host, "name resolution leaves the host")
                    return original(host, *args, **kwargs)
                return guarded
            return factory

        self._patch(builtins, "open", opener)
        self._patch(io, "open", opener)
        self._patch(os, "open", os_opener)
        for name in ("replace", "rename"):
            self._patch(os, name, moving("os." + name))
        for name in ("link", "symlink"):
            self._patch(os, name, creating("os." + name))
        for name in ("unlink", "remove", "rmdir"):
            self._patch(os, name, removing("os." + name))
        for name in ("mkdir", "mkfifo", "mknod"):
            self._patch(os, name, changing("os." + name, entry=True))
        for name in ("chmod", "chown"):
            self._patch(os, name, changing("os." + name))
        self._patch(os, "truncate", changing("os.truncate", special=True))
        for name in ("fchmod", "fchown"):
            self._patch(os, name, descriptor("os." + name))
        for name in ("copy", "copy2", "copyfile", "copytree", "move"):
            self._patch(shutil, name, copying("shutil." + name))
        for name in ("write", "writev", "pwrite", "pwritev", "ftruncate"):
            if hasattr(os, name):
                self._patch(os, name, descriptor_writer("os." + name))
        self._patch(os, "fdopen", lambda original: (
            lambda fd, mode="r", *args, **kwargs: (
                sandbox.descriptor_write("os.fdopen(%r)" % mode, fd)
                if isinstance(mode, str) and WRITE_MODE_CHARACTERS & set(mode) else None,
                original(fd, mode, *args, **kwargs))[1]))
        self._patch(Path, "open", path_opener)
        for name in ("write_text", "write_bytes"):
            self._patch(Path, name, path_writer("Path." + name))
        self._patch(sqlite3, "connect", database)
        self._patch(socket.socket, "bind", binder)
        self._patch(socket.socket, "sendto", sender)
        for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
            self._patch(socket, name, resolver("socket." + name))
        self._patch(socket, "gethostbyaddr", reverse_resolver)

    def deactivate(self) -> None:
        global ACTIVE
        ACTIVE = None
        while self._originals:
            owner, name, original = self._originals.pop()
            if original is None:
                delattr(owner, name)
            else:
                setattr(owner, name, original)

    def raise_if_violated(self, phase: str) -> None:
        if self.violations:
            listed = "\n  ".join(self.violations)
            self.violations = []
            pytest.fail(
                "test sandbox: %s of %s reached outside the sandbox:\n  %s" % (phase, self.nodeid, listed),
                pytrace=False,
            )


def _roots(item) -> list[str]:
    roots = [tempfile.gettempdir()]
    factory = getattr(item.config, "_tmp_path_factory", None)
    if factory is not None:
        try:
            roots.append(str(factory.getbasetemp()))
        except OSError:
            pass
    tmp_path = getattr(item, "funcargs", {}).get("tmp_path")
    if tmp_path is not None:
        roots.append(str(tmp_path))
    roots.extend(str(COMPONENT / relative) for relative in EXEMPT_DIRECTORIES)
    return roots


def _guard(item, phase):
    sandbox = Sandbox(item.nodeid, _roots(item))
    sandbox.activate()
    try:
        return (yield)
    finally:
        sandbox.deactivate()
        sandbox.raise_if_violated(phase)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_setup(item):
    return (yield from _guard(item, "setup"))


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item):
    return (yield from _guard(item, "call"))


@pytest.hookimpl(wrapper=True)
def pytest_runtest_teardown(item, nextitem):
    return (yield from _guard(item, "teardown"))


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    try:
        import pytest_socket
    except ImportError:
        raise pytest.UsageError(
            "the test suite needs pytest-socket from requirements-release.lock to keep tests off the network"
        ) from None
    if not config.pluginmanager.is_registered(pytest_socket):
        raise pytest.UsageError("pytest-socket is installed but not loaded; do not disable the plugin")
    settings = config.stash[pytest_socket._STASH_KEY]
    settings.allow_hosts = ",".join(LOOPBACK_HOSTS)
    settings.allow_unix_socket = True
