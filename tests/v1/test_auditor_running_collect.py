"""1.0.9 item 13: Auditor collect/run/status inside the running instance.

No device is contacted: collection uses the Auditor file channel. Workflow tests
simulate the instance identity while a helper holds a real flock. Identity tests
exercise the real checks separately, using real holders and /proc text fixtures.
"""
import asyncio
import contextlib
import fcntl
import io
import itertools
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

# Installed-image unit test (tests/v1 = /opt/netops/tests): the gateway package and the role packages it starts
# come from the production image built from the same commit, which also has fastmcp (verification, P3). The root
# tests/ job installs only the SBOM tooling, so this file must not live there.
from netops import __version__, operator  # noqa: E402
from netops import audit as audit_module  # noqa: E402
from netops.audit import Audit  # noqa: E402
from netops.files import UIDS, write_private  # noqa: E402
from netops.state import OperatorAccessError  # noqa: E402

# Byte copy of components/netops-auditor/tests/fixtures/fortios_clean.conf: tests/v1 ships in the image without components/.
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "fortios_clean.conf"
DEVICE = "fw-example"
SECTIONS = ("system global", "system interface", "firewall policy")
HOLDER = (
    "import fcntl, os, sys\n"
    "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n"
    "fcntl.flock(fd, fcntl.LOCK_EX)\n"
    "sys.stdout.write('held\\n')\n"
    "sys.stdout.flush()\n"
    "sys.stdin.read()\n"
)
# An operator `auditor <command>` whose workflow waits (like collection or a stdin read) after the
# preflight record and the result writer started; it runs in its own process group like a terminal job.
INTERRUPTED = (
    "import itertools, os, sys, time\n"
    "from pathlib import Path\n"
    "from unittest.mock import patch\n"
    "from netops import operator\n"
    "from netops.files import UIDS\n"
    "state, uid = Path(sys.argv[1]), os.geteuid()\n"
    "def waiting(role, arguments, outcome=None):\n"
    "    sys.stdout.write('waiting\\n')\n"
    "    sys.stdout.flush()\n"
    "    while True:\n"
    "        time.sleep(60)\n"
    "with patch.object(operator, 'STATE', state), patch.dict(UIDS, {'gateway': uid, 'auditor': uid}), \\\n"
    "        patch.object(operator, 'demote'), patch.object(operator, 'role_environment'), \\\n"
    "        patch.object(operator, '_running_instance_here', return_value=True), \\\n"
    "        patch.object(operator.os, 'geteuid', side_effect=itertools.chain([0], itertools.repeat(uid))), \\\n"
    "        patch.object(operator, '_role_main', waiting):\n"
    "    try:\n"
    "        operator.role_cli('auditor', sys.argv[2:])\n"
    "    except KeyboardInterrupt:\n"
    "        sys.exit(130)\n"
)


# Synchronisation points prepended to INTERRUPTED (review finding). Each sends a real SIGINT at one exact
# point of the result writer start; the operator process then ends on its own (no Ctrl+C from the test).
# Ctrl+C right after the result writer started and before the workflow runs: SIGINT to the operator process.
WRITER_STARTED = (
    "import os, signal\n"
    "from netops import operator\n"
    "real_start = operator._operator_audit_result\n"
    "def start(*arguments):\n"
    "    writer = real_start(*arguments)\n"
    "    os.kill(os.getpid(), signal.SIGINT)\n"
    "    return writer\n"
    "operator._operator_audit_result = start\n"
)
# Ctrl+C to the whole process group while the new result writer has not ignored SIGINT yet: the writer sends it
# to its group (itself and the operator process) just before its SIG_IGN and reports whether it was pending.
WRITER_BEFORE_IGNORE = (
    "import os, signal\n"
    "operator_pid, real_signal = os.getpid(), signal.signal\n"
    "def hooked(signum, handler):\n"
    "    if os.getpid() != operator_pid and signum == signal.SIGINT and handler is signal.SIG_IGN:\n"
    "        os.killpg(0, signal.SIGINT)\n"
    "        if signal.SIGINT in signal.sigpending():\n"
    "            os.write(1, b'writer-pending\\n')\n"
    "        previous = real_signal(signum, handler)\n"
    "        if signal.SIGINT not in signal.sigpending():\n"
    "            os.write(1, b'writer-discarded\\n')\n"
    "        return previous\n"
    "    return real_signal(signum, handler)\n"
    "signal.signal = hooked\n"
)


def _records(state):
    rows = []
    for path in sorted((state / "gateway" / "audit").glob("*.jsonl")):
        rows.extend(json.loads(line) for line in path.read_text().splitlines())
    return rows


def _operator_records(state):
    return [row for row in _records(state) if row["direction"] == "operator"]


class RunningCollectBase(unittest.TestCase):
    def setUp(self):
        self.uid = os.geteuid()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name) / "state"
        for role in ("gateway", "auditor"):
            (self.state / role).mkdir(parents=True, mode=0o700)
        write_private(self.state / "gateway/config.json", json.dumps({
            "version": 1, "product_version": __version__, "audit": {"mode": "local"}}).encode())
        write_private(self.state / "auditor/config.json", b'{"tenant":"default","catalog":"fortios"}')
        snapshot = Path(self.directory.name) / "fw-example.conf"
        shutil.copyfile(FIXTURE, snapshot)
        device = {"name": DEVICE, "platform": "fortios", "address": None, "port": None, "role": "perimeter",
                  "credential": None, "host_key_fingerprint": None, "legacy_ssh": None, "helper": None,
                  "auditor": {"channel": "file", "source": str(snapshot), "required_sections": list(SECTIONS),
                              "tls_fingerprint": None}}
        write_private(self.state / "auditor/inventory.json", json.dumps({"version": 2, "devices": [device]}).encode())
        self.holders = []
        self.simulated_instance = False
        self.addCleanup(self._stop_holders)

    def _stop_holders(self):
        for holder in self.holders:
            if holder.poll() is None:
                holder.stdin.close()
                holder.wait(10)
            holder.stdout.close()

    def environment(self, *, check_identity=False):
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(operator, "STATE", self.state))
        stack.enter_context(patch.dict(UIDS, {"gateway": self.uid, "auditor": self.uid}))
        stack.enter_context(patch.object(operator, "demote"))
        stack.enter_context(patch.object(operator, "role_environment"))
        if self.simulated_instance and not check_identity:
            # These tests exercise store locking/audit, not gateway identification.
            stack.enter_context(patch.object(operator, "_running_instance_here", return_value=True))
        return stack

    def as_root(self, stack):
        stack.enter_context(patch.object(operator.os, "geteuid", side_effect=itertools.chain([0], itertools.repeat(self.uid))))

    def start_instance(self, *arguments):
        """Workflow double: a real flock, with instance identity stubbed in environment()."""
        self.simulated_instance = True
        return self.start_holder(*arguments)

    def start_holder(self, *arguments):
        """An arbitrary process holding instance.lock; this is not a gateway."""
        holder = subprocess.Popen([sys.executable, "-c", HOLDER, str(self.state / "gateway/instance.lock"), *arguments],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.holders.append(holder)
        self.assertEqual(holder.stdout.readline(), b"held\n")
        return holder

    def hold_store_lock(self):
        descriptor = os.open(self.state / "auditor/store.lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor

    def assert_locked(self, name):
        descriptor = os.open(self.state / name, os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)

    def assert_free(self, name):
        descriptor = os.open(self.state / name, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)

    def collect(self, *extra):
        output = io.StringIO()
        with self.environment() as stack:
            self.as_root(stack)
            stack.enter_context(contextlib.redirect_stdout(output))
            code = operator.role_cli("auditor", ["collect", "--device", DEVICE, "--json", *extra])
        return code, output.getvalue()


class AuditorStoreLock(RunningCollectBase):
    def test_second_concurrent_collect_is_refused_with_stopped_instance(self):
        with self.environment():
            first = operator.acquire_auditor_state()
            try:
                self.assert_locked("gateway/instance.lock")
                self.assert_locked("auditor/store.lock")
                # A second `docker compose run` collect: the holder is no running instance of this container.
                with self.assertRaisesRegex(OperatorAccessError, "^Another NetOps instance or operator workflow holds the state"):
                    operator.acquire_auditor_state()
            finally:
                operator.release_state(first)
        self.assert_free("gateway/instance.lock")
        self.assert_free("auditor/store.lock")

    def test_second_concurrent_collect_is_refused_with_running_instance(self):
        self.start_instance("serve")
        with self.environment():
            first = operator.acquire_auditor_state()
            try:
                self.assert_locked("auditor/store.lock")
                with self.assertRaisesRegex(OperatorAccessError, "^Another Auditor write is running"):
                    operator.acquire_auditor_state()
            finally:
                operator.release_state(first)
        self.assert_free("auditor/store.lock")
        self.assert_locked("gateway/instance.lock")

    def test_collect_is_refused_while_the_store_lock_is_held_and_writes_no_audit(self):
        self.start_instance("serve")
        self.hold_store_lock()
        with patch("netops_auditor.cli.main") as main, \
                self.assertRaisesRegex(OperatorAccessError, "^Another Auditor write is running"):
            self.collect()
        main.assert_not_called()
        self.assertEqual(_records(self.state), [])

    def test_configure_auditor_is_refused_while_collect_holds_the_store_lock(self):
        self.hold_store_lock()
        before = (self.state / "auditor/config.json").read_bytes()

        class NoRead:
            def read(self, size):
                raise AssertionError("a refused configure must not read its input")
        with self.environment() as stack, patch.object(operator.sys, "stdin", type("S", (), {"buffer": NoRead()})()):
            self.as_root(stack)
            with self.assertRaisesRegex(OperatorAccessError, "^Another Auditor write is running"):
                operator.configure("auditor")
        self.assertEqual((self.state / "auditor/config.json").read_bytes(), before)
        self.assertEqual(_records(self.state), [])
        self.assert_free("gateway/instance.lock")

    def test_configure_auditor_is_refused_during_a_running_collect(self):
        self.start_instance("serve")
        with self.environment():
            collecting = operator.acquire_auditor_state()
            try:
                with self.environment() as stack:
                    self.as_root(stack)
                    with self.assertRaisesRegex(OperatorAccessError, "^Stop the running instance"):
                        operator.configure("auditor")
            finally:
                operator.release_state(collecting)

    def test_other_operator_workflows_take_the_store_lock_with_the_stopped_instance(self):
        with self.environment():
            descriptor = operator.acquire_state()
            try:
                self.assert_locked("gateway/instance.lock")
                self.assert_locked("auditor/store.lock")
            finally:
                operator.release_state(descriptor)
        self.assert_free("auditor/store.lock")
        self.start_instance("serve")
        with self.environment(), self.assertRaisesRegex(OperatorAccessError, "^Stop the running instance"):
            operator.acquire_state()

    def test_running_instance_in_another_container_is_refused(self):
        self.start_holder("serve")
        with self.environment():
            info = (self.state / "gateway/instance.lock").stat()
            locks = self.lock_record(info, pid=0)
            with self.proc_files({"/proc/locks": locks}), \
                    self.assertRaisesRegex(OperatorAccessError, "^Another NetOps instance or operator workflow holds the state"):
                operator.acquire_auditor_state()
        # refused before the store lock is opened: no store.lock is created, so none can stay held
        self.assertFalse((self.state / "auditor/store.lock").exists())

    def test_lock_holder_that_is_not_the_instance_is_refused(self):
        self.start_holder("auditor", "collect")
        with self.environment(), self.assertRaisesRegex(OperatorAccessError, "^Another NetOps instance or operator workflow holds the state"):
            operator.acquire_auditor_state()

    @staticmethod
    def lock_record(info, *, pid=1, major=None, minor=None):
        major = os.major(info.st_dev) if major is None else major
        minor = os.minor(info.st_dev) if minor is None else minor
        return f"1: FLOCK ADVISORY WRITE {pid} {major:02x}:{minor:02x}:{info.st_ino} 0 EOF\n".encode()

    @staticmethod
    def proc_files(files):
        real_open = open

        def read(path, *args, **kwargs):
            if path in files:
                if isinstance(files[path], OSError):
                    raise files[path]
                return io.BytesIO(files[path])
            return real_open(path, *args, **kwargs)
        return patch("builtins.open", side_effect=read)

    def assert_instance_identity(self, descriptor, expected):
        # The test runner may be PID 1; an exec operator is its child.
        reader, writer = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(reader)
            try:
                os.write(writer, bytes([operator._running_instance_here(descriptor)]))
            finally:
                os._exit(0)
        os.close(writer)
        try:
            result = os.read(reader, 1)
        finally:
            os.close(reader)
            _, status = os.waitpid(child, 0)
        self.assertEqual(status, 0)
        self.assertEqual(result, bytes([expected]))

    def test_container_pid_one_gateway_is_accepted_but_another_uid_is_refused(self):
        with self.environment(check_identity=True):
            descriptor = operator._open_instance_lock()
            try:
                # The supported entrypoint execs this argv as the container's PID 1.
                files = {"/proc/locks": self.lock_record(os.fstat(descriptor)),
                         "/proc/1/status": f"Name:\tpython\nUid:\t{self.uid}\t{self.uid}\t{self.uid}\t{self.uid}\n".encode(),
                         "/proc/1/cmdline": b"/usr/local/bin/python\0/usr/local/bin/netops\0serve\0"}
                with self.proc_files(files):
                    self.assert_instance_identity(descriptor, True)
                    with patch.dict(UIDS, {"gateway": self.uid + 1}):
                        self.assert_instance_identity(descriptor, False)
            finally:
                os.close(descriptor)

    def btrfs_proc_files(self, info):
        # Real proc formats: locks use hex 00:2d, mountinfo decimal 0:45. btrfs gives its
        # superblock an anonymous device (major 0) and every subvolume another one, so the
        # stat device of the lock (0:52) is neither of these. The parent mount is ext4 on
        # an NVMe partition (259:3); the unrelated mount is a second btrfs (0:47).
        def mount_path(path):
            return (os.fsencode(path).replace(b"\\", b"\\134").replace(b" ", b"\\040")
                    .replace(b"\t", b"\\011").replace(b"\n", b"\\012"))

        state = mount_path(self.state)
        mountinfo = (b"46 35 0:45 /@docker/volumes/netops/_data/gateway " + state + b"/gateway rw,relatime shared:22 - btrfs /dev/nvme0n1p2 rw,subvolid=256\n"
                     b"35 25 0:31 / / rw,relatime - overlay overlay rw\n"
                     b"45 35 259:3 /docker/volumes/netops/_data " + state + b" rw,relatime - ext4 /dev/nvme0n1p3 rw\n"
                     b"47 35 0:47 /@unrelated " + state + b"/gateway-other rw,relatime - btrfs /dev/sda1 rw,subvolid=257\n")
        return {"/proc/locks": self.lock_record(info, major=0, minor=45),
                "/proc/self/mountinfo": mountinfo,
                "/proc/1/status": f"Name:\tpython\nUid:\t{self.uid}\t{self.uid}\t{self.uid}\t{self.uid}\n".encode(),
                "/proc/1/cmdline": b"/usr/local/bin/python\0/usr/local/bin/netops\0serve\0"}

    def test_btrfs_pid_one_gateway_is_accepted_with_anonymous_stat_device(self):
        # Escapes in mount paths must decode before choosing the deepest mount.
        self.state = self.state.rename(self.state.with_name("state space\tline\nback\\slash"))
        with self.environment(check_identity=True):
            descriptor = operator._open_instance_lock()
            try:
                info = SimpleNamespace(st_dev=os.makedev(0, 52), st_ino=os.fstat(descriptor).st_ino)
                files = self.btrfs_proc_files(info)
                with self.proc_files(files), patch.object(operator.os, "fstat", return_value=info):
                    self.assertEqual(operator._instance_holder_pid(descriptor), 1)
                    self.assert_instance_identity(descriptor, True)
                    with patch.dict(UIDS, {"gateway": self.uid + 1}):
                        self.assert_instance_identity(descriptor, False)
            finally:
                os.close(descriptor)

    def test_btrfs_fake_holder_and_foreign_file_with_same_inode_are_refused(self):
        holder = self.start_holder("serve")
        with self.environment(check_identity=True):
            descriptor = operator._open_instance_lock()
            try:
                info = SimpleNamespace(st_dev=os.makedev(0, 52), st_ino=os.fstat(descriptor).st_ino)
                for pid, device, expected in ((holder.pid, (0, 45), holder.pid),
                                              (1, (259, 3), None), (1, (0, 47), None),
                                              (1, (259, 45), None), (1, (0, 46), None)):
                    with self.subTest(pid=pid, device=device):
                        files = self.btrfs_proc_files(info)
                        files["/proc/locks"] = self.lock_record(info, pid=pid, major=device[0], minor=device[1])
                        with self.proc_files(files), patch.object(operator.os, "fstat", return_value=info):
                            self.assertEqual(operator._instance_holder_pid(descriptor), expected)
                            self.assert_instance_identity(descriptor, False)
                files = self.btrfs_proc_files(info)
                # A preceding unrelated lock must not mask the real instance.
                files["/proc/locks"] = self.lock_record(info, major=0, minor=47) + files["/proc/locks"]
                with self.proc_files(files), patch.object(operator.os, "fstat", return_value=info):
                    self.assert_instance_identity(descriptor, True)
            finally:
                os.close(descriptor)

    def test_btrfs_unavailable_or_unusable_mountinfo_does_not_accept_an_inode_alone(self):
        with self.environment(check_identity=True):
            descriptor = operator._open_instance_lock()
            try:
                info = SimpleNamespace(st_dev=os.makedev(0, 52), st_ino=os.fstat(descriptor).st_ino)
                for mountinfo in (PermissionError("mountinfo unavailable"), b"", b"malformed\n",
                                  b"35 25 bad:device / / rw - btrfs /dev/nvme0n1p2 rw\n",
                                  b"35 25 0:45 / /unrelated rw - btrfs /dev/nvme0n1p2 rw\n"):
                    with self.subTest(mountinfo=mountinfo):
                        files = self.btrfs_proc_files(info)
                        files["/proc/self/mountinfo"] = mountinfo
                        with self.proc_files(files), patch.object(operator.os, "fstat", return_value=info):
                            self.assertIsNone(operator._instance_holder_pid(descriptor))
                            self.assert_instance_identity(descriptor, False)
            finally:
                os.close(descriptor)

    @staticmethod
    def fd_tables(tables):
        """Fake /proc/<pid>/fd: {directory: {name: (st_dev, st_ino)} or OSError}; other paths are real."""
        real_listdir, real_stat = os.listdir, os.stat

        def listdir(path=".", *args, **kwargs):
            if path in tables:
                if isinstance(tables[path], OSError):
                    raise tables[path]
                return list(tables[path])
            return real_listdir(path, *args, **kwargs)

        def stat(path, *args, **kwargs):
            directory, _, name = str(path).rpartition("/")
            if directory in tables and not isinstance(tables[directory], OSError):
                entry = tables[directory][name]
                if isinstance(entry, OSError):
                    raise entry
                return SimpleNamespace(st_dev=entry[0], st_ino=entry[1])
            return real_stat(path, *args, **kwargs)
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(operator.os, "listdir", side_effect=listdir))
        stack.enter_context(patch.object(operator.os, "stat", side_effect=stat))
        return stack

    def test_btrfs_same_inode_in_another_subvolume_is_resolved_by_the_open_descriptor(self):
        # Two FLOCK records with the same superblock device (0:45) and inode: one locks the
        # instance lock (subvolume device 0:52), the other a file of another subvolume (0:53).
        with self.environment(check_identity=True):
            descriptor = operator._open_instance_lock()
            try:
                info = SimpleNamespace(st_dev=os.makedev(0, 52), st_ino=os.fstat(descriptor).st_ino)
                ours, foreign = (info.st_dev, info.st_ino), (os.makedev(0, 53), info.st_ino)
                gone = FileNotFoundError("closed meanwhile")
                for gateway, other, expected, accepted in (
                        ({"0": (os.makedev(0, 31), 7), "3": ours}, {"4": foreign, "9": gone}, 1, True),
                        ({"3": foreign}, {"4": ours}, 42, False)):
                    for order in ((42, 1), (1, 42)):
                        with self.subTest(expected=expected, order=order):
                            files = self.btrfs_proc_files(info)
                            files["/proc/locks"] = b"".join(self.lock_record(info, pid=pid, major=0, minor=45) for pid in order)
                            tables = {"/proc/1/fd": gateway, "/proc/42/fd": other}
                            with self.proc_files(files), self.fd_tables(tables), \
                                    patch.object(operator.os, "fstat", return_value=info):
                                self.assertEqual(operator._instance_holder_pid(descriptor), expected)
                                self.assert_instance_identity(descriptor, accepted)
            finally:
                os.close(descriptor)

    def test_btrfs_same_inode_without_a_confirmed_descriptor_is_refused(self):
        with self.environment(check_identity=True):
            descriptor = operator._open_instance_lock()
            try:
                info = SimpleNamespace(st_dev=os.makedev(0, 52), st_ino=os.fstat(descriptor).st_ino)
                ours, foreign = (info.st_dev, info.st_ino), (os.makedev(0, 53), info.st_ino)
                denied = PermissionError(13, "Permission denied")
                cases = (
                    # The gateway's descriptors cannot be inspected (EACCES).
                    ((42, 1), {"/proc/1/fd": denied, "/proc/42/fd": {"4": foreign}}),
                    ((1, 42), {"/proc/1/fd": denied, "/proc/42/fd": {"4": foreign}}),
                    # The gateway has the lock open, but the other candidate cannot be ruled out.
                    ((1, 42), {"/proc/1/fd": {"3": ours}, "/proc/42/fd": denied}),
                    ((1, 42), {"/proc/1/fd": {"3": ours}, "/proc/42/fd": {"4": denied}}),
                    ((1, 0), {"/proc/1/fd": {"3": ours}}),
                    # Both have the instance lock open, or neither has.
                    ((1, 42), {"/proc/1/fd": {"3": ours}, "/proc/42/fd": {"4": ours}}),
                    ((1, 42), {"/proc/1/fd": {"3": foreign}, "/proc/42/fd": {"4": foreign}}),
                )
                for order, tables in cases:
                    with self.subTest(order=order, tables=tables):
                        files = self.btrfs_proc_files(info)
                        files["/proc/locks"] = b"".join(self.lock_record(info, pid=pid, major=0, minor=45) for pid in order)
                        with self.proc_files(files), self.fd_tables(tables), \
                                patch.object(operator.os, "fstat", return_value=info):
                            self.assertIsNone(operator._instance_holder_pid(descriptor))
                            self.assert_instance_identity(descriptor, False)
            finally:
                os.close(descriptor)

    def test_btrfs_overmount_of_the_same_depth_uses_the_last_mountinfo_line(self):
        with self.environment(check_identity=True):
            descriptor = operator._open_instance_lock()
            try:
                info = SimpleNamespace(st_dev=os.makedev(0, 52), st_ino=os.fstat(descriptor).st_ino)
                files = self.btrfs_proc_files(info)
                # A later mount on the same mountpoint (another btrfs, superblock 0:48) hides line 46.
                files["/proc/self/mountinfo"] += (b"52 35 0:48 /@netops/gateway " + os.fsencode(self.state)
                                                  + b"/gateway rw,relatime - btrfs /dev/nvme1n1p1 rw,subvolid=258\n")
                with self.proc_files(files), patch.object(operator.os, "fstat", return_value=info):
                    self.assertEqual(operator._instance_lock_mount_device(descriptor), (0, 48))
                for minor, expected in ((48, 1), (45, None)):
                    with self.subTest(minor=minor):
                        files["/proc/locks"] = self.lock_record(info, major=0, minor=minor)
                        with self.proc_files(files), patch.object(operator.os, "fstat", return_value=info):
                            self.assertEqual(operator._instance_holder_pid(descriptor), expected)
                            self.assert_instance_identity(descriptor, expected == 1)
            finally:
                os.close(descriptor)

    def test_real_gateway_uid_holder_with_serve_argv_is_refused(self):
        holder = self.start_holder("serve")
        with self.environment(check_identity=True):
            descriptor = operator._open_instance_lock()
            try:
                self.assertEqual(operator._instance_holder_pid(descriptor), holder.pid)
                self.assertFalse(operator._running_instance_here(descriptor))
            finally:
                os.close(descriptor)
            with self.assertRaisesRegex(OperatorAccessError, "^Another NetOps instance or operator workflow holds the state"):
                operator.acquire_auditor_state()
        self.assertFalse((self.state / "auditor/store.lock").exists())
        self.assertEqual(_records(self.state), [])

    def test_same_inode_on_another_device_does_not_match(self):
        with self.environment(check_identity=True):
            descriptor = operator._open_instance_lock()
            try:
                info = os.fstat(descriptor)
                for device in ({"major": os.major(info.st_dev) + 1}, {"minor": os.minor(info.st_dev) + 1}):
                    with self.subTest(device=device):
                        other = self.lock_record(info, pid=1, **device)
                        with self.proc_files({"/proc/locks": other}):
                            self.assertIsNone(operator._instance_holder_pid(descriptor))
                            self.assertFalse(operator._running_instance_here(descriptor))
                        with self.proc_files({"/proc/locks": other + self.lock_record(info, pid=42)}):
                            self.assertEqual(operator._instance_holder_pid(descriptor), 42)
            finally:
                os.close(descriptor)

    def test_non_root_and_other_commands_keep_their_refusals(self):
        self.start_instance("serve")
        with self.environment(), patch.object(operator.os, "geteuid", return_value=self.uid + 1), \
                self.assertRaisesRegex(OperatorAccessError, "default container user"):
            operator.role_cli("auditor", ["collect", "--device", DEVICE])
        for arguments in (["import-snapshot", "--name", "example"],):
            with self.subTest(arguments=arguments), self.environment() as stack:
                self.as_root(stack)
                with self.assertRaisesRegex(OperatorAccessError, "^Stop the running instance"):
                    operator.role_cli("auditor", arguments)


class RunningCollect(RunningCollectBase):
    def test_collect_with_running_instance_runs_under_the_store_lock_and_is_audited(self):
        self.start_instance("serve")
        from netops_auditor import cli as auditor_cli
        real = auditor_cli.main
        seen = []

        def main(arguments):
            self.assert_locked("auditor/store.lock")
            seen.append(list(arguments))
            return real(arguments)
        with patch.object(auditor_cli, "main", main):
            code, output = self.collect()
        self.assertIn(code, (0, 1, 3))
        self.assertEqual(len(seen), 1)
        self.assertIn("--store", seen[0])
        report = json.loads(output)
        self.assertEqual(report["device"], DEVICE)
        run_id = operator._latest_run_id(self.state / "auditor/store.sqlite")
        self.assertIsInstance(run_id, int)
        records = _operator_records(self.state)
        self.assertEqual([row["payload"]["action"] for row in records], ["operator-preflight", "operator-result"])
        preflight, result = records
        self.assertEqual(preflight["payload"], {"role": "auditor", "action": "operator-preflight", "workflow": "collect"})
        self.assertEqual(result["payload"], {"role": "auditor", "action": "operator-result", "workflow": "collect",
                                             "completed": True, "exit": code, "run_id": run_id})
        self.assertEqual(preflight["correlation"], result["correlation"])
        self.assert_free("auditor/store.lock")
        self.assert_locked("gateway/instance.lock")

    def test_run_from_stdin_with_running_instance_is_audited_with_its_run_id(self):
        self.start_instance("serve")
        output = io.StringIO()
        with self.environment() as stack:
            self.as_root(stack)
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(patch.object(operator.sys, "stdin", io.TextIOWrapper(io.BytesIO(FIXTURE.read_bytes()))))
            code = operator.role_cli("auditor", ["run", "--platform", "fortios", "--device", DEVICE, "--config", "-", "--json"])
        self.assertIn(code, (0, 1, 3))
        result = _operator_records(self.state)[-1]["payload"]
        self.assertEqual((result["workflow"], result["exit"], result["completed"]), ("run", code, True))
        self.assertEqual(result["run_id"], operator._latest_run_id(self.state / "auditor/store.sqlite"))
        self.assertEqual(list((self.state / "auditor").glob(".snapshot-*")), [])

    def test_failed_collect_records_preflight_and_an_incomplete_result(self):
        self.start_instance("serve")
        with self.assertRaises(ValueError):
            self.collect("--device", "no-such-device")
        preflight, result = _operator_records(self.state)
        self.assertEqual(preflight["payload"]["workflow"], "collect")
        self.assertEqual(result["payload"]["completed"], False)
        self.assertIsNone(result["payload"]["run_id"])
        self.assertIn("exception", result["payload"])
        self.assert_free("auditor/store.lock")

    def test_unavailable_audit_refuses_collect_before_the_engine_runs(self):
        self.start_instance("serve")
        write_private(self.state / "gateway/config.json", json.dumps({
            "version": 1, "product_version": __version__, "audit": {"mode": "unsupported"}}).encode(), replace=True)
        with patch("netops_auditor.cli.main") as main, self.assertRaisesRegex(ValueError, "audit"):
            self.collect()
        main.assert_not_called()
        self.assertFalse((self.state / "auditor/store.sqlite").exists())

    def test_status_with_running_instance_needs_no_audit_record(self):
        self.start_instance("serve")
        self.collect()
        before = len(_operator_records(self.state))
        output = io.StringIO()
        with self.environment() as stack:
            self.as_root(stack)
            stack.enter_context(contextlib.redirect_stdout(output))
            code = operator.role_cli("auditor", ["status", "--device", DEVICE, "--json"])
        self.assertIn(code, (0, 1))
        self.assertEqual(json.loads(output.getvalue())["device"], DEVICE)
        self.assertEqual(len(_operator_records(self.state)), before)

    def test_result_record_rejects_unexpected_content(self):
        for raw in (b'{"exit":0,"extra":1}', b'{"exit":"0"}', b'{"exception":"no spaces"}', b'[]',
                    b'{"exit":0,"exit":1}', b'{"run_id":true}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                operator._checked_result(raw)
        self.assertEqual(operator._checked_result(b""), {"completed": False, "exit": None, "run_id": None})


class InterruptedWorkflow(RunningCollectBase):
    """Ctrl+C during `docker compose exec netops netops auditor collect|run` (review finding 2)."""

    def interrupt(self, *arguments):
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join(path for path in sys.path if path))
        process = subprocess.Popen([sys.executable, "-c", INTERRUPTED, str(self.state), *arguments],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                                   start_new_session=True)
        try:
            self.assertEqual(process.stdout.readline(), b"waiting\n")
            self.assertEqual([row["payload"]["action"] for row in _operator_records(self.state)], ["operator-preflight"])
            # Ctrl+C: the terminal signals the whole foreground process group.
            os.killpg(process.pid, signal.SIGINT)
            # EOF on the pipes also waits for the forked result writer that inherited them.
            _, error = process.communicate(timeout=60)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
        self.assertEqual(process.returncode, 130, error)
        self.assertNotIn(b"could not be recorded", error)
        self.assertNotIn(b"Operator audit result failed", error)
        self.assert_one_interrupted_result(arguments[0])

    def assert_one_interrupted_result(self, workflow):
        records = _operator_records(self.state)
        self.assertEqual([row["payload"]["action"] for row in records], ["operator-preflight", "operator-result"])
        preflight, result = records
        self.assertEqual(result["payload"], {"role": "auditor", "action": "operator-result", "workflow": workflow,
                                             "completed": False, "exit": None, "run_id": None,
                                             "exception": "KeyboardInterrupt"})
        self.assertEqual(preflight["correlation"], result["correlation"])
        self.assert_free("auditor/store.lock")

    def test_ctrl_c_during_collect_with_running_instance_records_one_incomplete_result(self):
        self.start_instance("serve")
        self.interrupt("collect", "--device", DEVICE)
        self.assert_locked("gateway/instance.lock")

    def test_ctrl_c_during_run_with_stopped_instance_records_one_incomplete_result(self):
        self.interrupt("run", "--platform", "fortios", "--device", DEVICE, "--config", "-")
        self.assert_free("gateway/instance.lock")

    def run_hooked(self, hook, *arguments):
        """The operator process with a synchronisation point; it must end with 130 after reaping its writer."""
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join(path for path in sys.path if path))
        process = subprocess.Popen([sys.executable, "-c", hook + INTERRUPTED, str(self.state), *arguments],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                                   start_new_session=True)
        try:
            # EOF on the pipes also waits for the forked result writer that inherited them.
            output, error = process.communicate(timeout=60)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
        self.assertEqual(process.returncode, 130, error)
        self.assertNotIn(b"could not be recorded", error)
        self.assertNotIn(b"Operator audit result failed", error)
        self.assert_one_interrupted_result(arguments[0])
        return output

    def interrupt_in_process(self, point):
        """Real SIGINT to this process at one point of the result writer start; this caller catches it and goes on."""
        self.start_instance("serve")
        real_fork, real_start = os.fork, operator._operator_audit_result
        masks, writers, sent = [], [], []

        def ctrl_c(where):
            sent.append(where)
            signal.pthread_kill(threading.get_ident(), signal.SIGINT)

        def fork():
            blocked = signal.SIGINT in signal.pthread_sigmask(signal.SIG_BLOCK, [])
            if blocked and point == "before-fork":
                # stays pending until the caller restores its mask; a forked child does not inherit it
                ctrl_c(point)
            child = real_fork()
            if child:
                masks.append(blocked)
                if blocked:
                    writers.append(child)
                    if point == "after-fork":
                        ctrl_c(point)
            return child

        def start(*arguments):
            writer = real_start(*arguments)
            if point == "writer-started":
                # the window of the review finding: the writer exists, the workflow has not started
                ctrl_c(point)
            return writer

        def reap():  # a writer left behind by a failing run must not outlive the test
            for pid in writers:
                try:
                    if os.waitpid(pid, os.WNOHANG) == (0, 0):
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
        self.addCleanup(reap)
        before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        with patch.object(operator.os, "fork", fork), patch.object(operator, "_operator_audit_result", start), \
                patch("netops_auditor.cli.main") as main, self.assertRaises(KeyboardInterrupt):
            self.collect()
        self.assertEqual(sent, [point])
        main.assert_not_called()
        # Preflight fork unprotected as before; the result writer fork with SIGINT blocked.
        self.assertEqual(masks, [False, True])
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), before)
        # the caller has reaped its writer before the KeyboardInterrupt reached it
        with self.assertRaises(ChildProcessError):
            os.waitpid(writers[0], os.WNOHANG)
        self.assert_one_interrupted_result("collect")
        self.assert_locked("gateway/instance.lock")

    def test_ctrl_c_at_the_result_writer_fork_records_one_incomplete_result(self):
        self.interrupt_in_process("before-fork")

    def test_ctrl_c_right_after_the_result_writer_fork_records_one_incomplete_result(self):
        self.interrupt_in_process("after-fork")

    def test_ctrl_c_between_the_writer_start_and_the_workflow_records_one_incomplete_result(self):
        """Review finding: SIGINT after `_operator_audit_result` returned, before the workflow runs."""
        self.interrupt_in_process("writer-started")

    def test_ctrl_c_between_the_writer_start_and_the_workflow_ends_the_operator_with_130(self):
        self.start_instance("serve")
        output = self.run_hooked(WRITER_STARTED, "collect", "--device", DEVICE)
        self.assertNotIn(b"waiting", output)
        self.assert_locked("gateway/instance.lock")

    def test_group_ctrl_c_before_the_writer_ignores_sigint_records_one_incomplete_result(self):
        """Review note: the group SIGINT reaches the new writer while it is still blocked there."""
        output = self.run_hooked(WRITER_BEFORE_IGNORE, "run", "--platform", "fortios", "--device", DEVICE, "--config", "-")
        self.assertIn(b"writer-pending\n", output)
        self.assertIn(b"writer-discarded\n", output)
        self.assert_free("gateway/instance.lock")


class StoppedInstanceCompatibility(RunningCollectBase):
    def test_collect_with_stopped_instance_keeps_the_1_0_8_workflow(self):
        code, output = self.collect()
        self.assertIn(code, (0, 1, 3))
        self.assertEqual(json.loads(output)["device"], DEVICE)
        self.assert_free("gateway/instance.lock")
        self.assert_free("auditor/store.lock")
        actions = [row["payload"]["action"] for row in _operator_records(self.state)]
        self.assertEqual(actions, ["operator-preflight", "operator-result"])

    def test_stopped_instance_acquisition_holds_the_instance_lock_like_1_0_8(self):
        with self.environment():
            descriptor = operator.acquire_auditor_state()
            try:
                self.assert_locked("gateway/instance.lock")
            finally:
                operator.release_state(descriptor)

    def test_state_without_auditor_directory_needs_no_store_lock(self):
        shutil.rmtree(self.state / "auditor")
        with self.environment():
            descriptor = operator.acquire_state()
            operator.release_state(descriptor)
        self.assertFalse((self.state / "auditor").exists())


def _writer(directory, settings, writer, count, maximum):
    try:
        with patch.object(audit_module, "MAX_MESSAGE", maximum):
            audit = Audit(directory, settings)

            async def write():
                for sequence in range(count):
                    await audit.record("operator", {"writer": writer, "sequence": sequence, "pad": "x" * 200}, "c%d" % writer)
            asyncio.run(write())
    except BaseException:
        os._exit(1)
    os._exit(0)


def _forwarder(directory, settings, stop, delivered):
    try:
        audit = Audit(directory, settings)
        while True:
            finished = stop.is_set()
            batch = audit._batch()
            for path in batch:
                delivered.put(path.read_bytes())
            if batch:
                audit._remove(batch)
            elif finished:
                break
        delivered.close()
        delivered.join_thread()
    except BaseException:
        os._exit(1)
    os._exit(0)


class TwoProcessAudit(unittest.TestCase):
    WRITERS = 2
    COUNT = 150
    MAXIMUM = 4096

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "audit"
        self.context = multiprocessing.get_context("fork")

    def run_writers(self, settings):
        workers = [self.context.Process(target=_writer, args=(self.path, settings, writer, self.COUNT, self.MAXIMUM))
                   for writer in range(self.WRITERS)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(120)
        for worker in workers:
            if worker.is_alive():  # a hung writer must not keep the test run alive at exit
                worker.kill()
                worker.join()
        self.assertEqual([worker.exitcode for worker in workers], [0] * self.WRITERS)

    @staticmethod
    def keys(lines):
        keys = []
        for line in lines:
            payload = json.loads(line)["payload"]
            keys.append((payload["writer"], payload["sequence"]))
        return keys

    def test_local_rotation_neither_loses_nor_duplicates_a_record(self):
        settings = {"mode": "local", "segment_bytes": self.MAXIMUM, "budget_bytes": 64 * 1024 * 1024}
        self.run_writers(settings)
        segments = sorted(self.path.glob("*.jsonl"))
        self.assertGreater(len(segments), 2)
        lines = [line for path in segments for line in path.read_bytes().splitlines()]
        keys = self.keys(lines)
        self.assertEqual(sorted(keys), sorted((writer, sequence) for writer in range(self.WRITERS) for sequence in range(self.COUNT)))
        for path in segments:
            self.assertTrue(path.read_bytes().endswith(b"\n"))

    def test_local_budget_deletion_never_duplicates_and_keeps_the_budget(self):
        budget = self.MAXIMUM * 4
        settings = {"mode": "local", "segment_bytes": self.MAXIMUM, "budget_bytes": budget}
        with patch.object(audit_module, "MAX_MESSAGE", self.MAXIMUM):
            self.run_writers(settings)
        segments = list(self.path.glob("*.jsonl"))
        self.assertLessEqual(sum(path.stat().st_size for path in segments), budget)
        keys = self.keys(line for path in segments for line in path.read_bytes().splitlines())
        self.assertTrue(keys)
        self.assertEqual(len(keys), len(set(keys)))
        # Deletion removes whole oldest segments only: the newest record of the last writer survives.
        newest = json.loads((self.path / "current.jsonl").read_bytes().splitlines()[-1])["payload"]
        self.assertEqual(newest["sequence"], self.COUNT - 1)

    def test_syslog_queue_with_concurrent_delivery_neither_loses_nor_duplicates_a_record(self):
        settings = {"mode": "syslog", "host": "syslog.example.invalid", "budget_bytes": 64 * 1024 * 1024}
        self.path.mkdir(mode=0o700)
        stop, delivered = self.context.Event(), self.context.Queue()
        forwarder = self.context.Process(target=_forwarder, args=(self.path, settings, stop, delivered))
        forwarder.start()
        try:
            self.run_writers(settings)
        except BaseException:
            # nobody drains `delivered` on this path: the forwarder would block in join_thread() and the
            # interpreter would wait for it forever at exit
            forwarder.kill()
            forwarder.join()
            raise
        finally:
            stop.set()
        lines = []
        while forwarder.is_alive() or not delivered.empty():
            try:
                lines.extend(delivered.get(timeout=1).splitlines())
            except Exception:
                pass
        forwarder.join(60)
        self.assertEqual(forwarder.exitcode, 0)
        lines.extend(line for path in self.path.glob("*.queue") for line in path.read_bytes().splitlines())
        keys = self.keys(lines)
        self.assertEqual(sorted(keys), sorted((writer, sequence) for writer in range(self.WRITERS) for sequence in range(self.COUNT)))


if __name__ == "__main__":
    unittest.main()
