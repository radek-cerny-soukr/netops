from contextlib import contextmanager
import errno
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from netops import audit, files


class ReadAdmissionAfterPrivilegedOpen(unittest.TestCase):
    @contextmanager
    def readable_open(self, mode, payload):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-private"
            path.write_bytes(payload)
            path.chmod(0o600)
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            retained = os.open(path, flags)
            opened = []
            calls = []

            def duplicate(actual_path, actual_flags, *args, **kwargs):
                self.assertEqual(Path(actual_path), path)
                self.assertEqual(actual_flags, flags)
                self.assertFalse(args)
                self.assertFalse(kwargs)
                descriptor = os.dup(retained)
                opened.append(descriptor)
                calls.append((actual_path, actual_flags))
                return descriptor

            try:
                path.chmod(mode)
                before = os.fstat(retained)
                self.assertEqual(stat.S_IMODE(before.st_mode), mode)
                self.assertEqual(before.st_uid, os.geteuid())
                self.assertEqual(os.pread(retained, len(payload) + 1, 0), payload)
                with patch.object(os, "open", side_effect=duplicate):
                    yield path
                self.assertEqual(len(calls), 1, "the actual reader must open the target exactly once")
                after = os.fstat(retained)
                self.assertEqual(
                    (after.st_ino, after.st_uid, after.st_mode, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns),
                    (before.st_ino, before.st_uid, before.st_mode, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns),
                )
                self.assertEqual(os.pread(retained, len(payload) + 1, 0), payload)
                for descriptor in opened:
                    with self.assertRaises(OSError) as caught:
                        os.fstat(descriptor)
                    self.assertEqual(caught.exception.errno, errno.EBADF)
            finally:
                for descriptor in opened:
                    try:
                        os.close(descriptor)
                    except OSError as exc:
                        if exc.errno != errno.EBADF:
                            raise
                os.close(retained)

    def assert_read_refused(self, operation):
        try:
            operation()
        except PermissionError as exc:
            self.assertEqual(exc.errno, errno.EACCES)
        except ValueError as exc:
            self.assertEqual(str(exc), "Private file permissions are required")
        else:
            self.fail("a successful privileged open must not bypass missing owner-read permission")

    def test_read_private_rejects_owner_unreadable_modes_after_successful_open(self):
        payload = b"synthetic-private-bytes\n"
        for mode in (0o000, 0o200):
            with self.subTest(mode=oct(mode)), self.readable_open(mode, payload) as path:
                self.assert_read_refused(lambda: files.read_private(path, owner=os.geteuid()))

    def test_read_private_preserves_read_only_and_read_write_modes(self):
        payload = b"synthetic-private-bytes\n"
        for mode in (0o400, 0o600):
            with self.subTest(mode=oct(mode)), self.readable_open(mode, payload) as path:
                self.assertEqual(files.read_private(path, owner=os.geteuid()), payload)

    def test_incomplete_tail_rejects_owner_unreadable_modes_after_successful_open(self):
        for mode in (0o000, 0o200):
            for payload in (b"", b'{"synthetic":true}\n', b'{"synthetic":'):
                with self.subTest(mode=oct(mode), payload=payload), self.readable_open(mode, payload) as path:
                    self.assert_read_refused(lambda: audit.incomplete_tail(path))

    def test_incomplete_tail_preserves_empty_complete_and_fragment_semantics(self):
        for mode in (0o400, 0o600):
            for payload, expected in ((b"", False), (b'{"synthetic":true}\n', False),
                                      (b'{"synthetic":', True)):
                with self.subTest(mode=oct(mode), expected=expected), self.readable_open(mode, payload) as path:
                    self.assertIs(audit.incomplete_tail(path), expected)

    def test_owner_validation_precedes_new_read_permission_policy(self):
        for mode in (0o000, 0o400):
            with self.subTest(mode=oct(mode)), self.readable_open(mode, b"synthetic\n") as path:
                with self.assertRaisesRegex(ValueError, "^Unexpected file owner$"):
                    files.read_private(path, owner=os.geteuid() + 1)

    def test_generic_check_regular_preserves_existing_write_descriptors(self):
        for mode in (0o000, 0o200, 0o400, 0o600):
            with self.subTest(mode=oct(mode)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "synthetic-write"
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    path.chmod(mode)
                    before = files.check_regular(descriptor, os.geteuid())
                    self.assertEqual(stat.S_IMODE(before.st_mode), mode)
                    self.assertEqual(os.write(descriptor, b"x"), 1)
                    self.assertEqual(files.check_regular(descriptor, os.geteuid()).st_size, 1)
                finally:
                    os.close(descriptor)
