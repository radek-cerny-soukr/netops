from contextlib import ExitStack
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from netops import audit, certificates, files, init
import test_read_admission_permissions as read_controls


class AuditOwnerAndParentAdmission(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "gateway").mkdir(mode=0o700)
        self.parent = self.root / "gateway" / "audit"
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(files.UIDS, {"gateway": os.geteuid()}))
        self.stack.enter_context(patch.dict(os.environ, {"NETOPS_SERVER_NAME": "synthetic.example.invalid"}))
        self.verify = self.stack.enter_context(patch.object(certificates, "verify_pairs", return_value=None))
        self.fd_control = read_controls.ReadAdmissionAfterPrivilegedOpen()

    def check(self, mode):
        init.check_start({"server_name": "synthetic.example.invalid", "audit": {"mode": mode}}, self.root)

    def call_tail(self, path, owner, reader=None):
        if reader is None:
            reader = audit.incomplete_tail
        try:
            return reader(path, owner=owner)
        except TypeError as exc:
            if "unexpected keyword argument" in str(exc) and "'owner'" in str(exc):
                self.fail("missing optional-owner incomplete_tail API before implementation")
            raise

    def assert_parent_refused(self, mode):
        try:
            self.check(mode)
        except ValueError as exc:
            self.assertEqual(str(exc), "Unsafe audit directory ownership or permissions")
        except OSError as exc:
            self.fail("parent admission guard was not reached before filesystem error: " + type(exc).__name__)
        else:
            self.fail("unsafe audit parent was admitted")
        self.verify.assert_not_called()

    def test_tail_explicit_owner_mismatch_uses_real_fstat(self):
        with self.fd_control.readable_open(0o600, b'{"synthetic":true}\n') as path:
            with self.assertRaisesRegex(ValueError, "^Unexpected file owner$"):
                self.call_tail(path, os.geteuid() + 1)

    def test_tail_explicit_correct_owner_preserves_complete_positive(self):
        with self.fd_control.readable_open(0o600, b'{"synthetic":true}\n') as path:
            self.assertIs(self.call_tail(path, os.geteuid()), False)

    def test_tail_explicit_none_preserves_generic_positive(self):
        with self.fd_control.readable_open(0o600, b'{"synthetic":true}\n') as path:
            self.assertIs(self.call_tail(path, None), False)

    def test_real_private_parent_is_accepted_for_local_and_syslog(self):
        self.parent.mkdir(mode=0o700)
        for mode in ("local", "syslog"):
            with self.subTest(mode=mode):
                self.verify.reset_mock()
                self.check(mode)
                self.verify.assert_called_once_with()
                self.assertEqual(self.parent.lstat().st_mode & 0o7777, 0o700)

    def test_missing_parent_is_allowed_without_creation_for_both_modes(self):
        for mode in ("local", "syslog"):
            with self.subTest(mode=mode):
                self.verify.reset_mock()
                self.check(mode)
                self.verify.assert_called_once_with()
                self.assertFalse(self.parent.exists())

    def test_wrong_parent_owner_is_refused_for_both_modes(self):
        self.parent.mkdir(mode=0o700)
        with patch.dict(files.UIDS, {"gateway": os.geteuid() + 1}):
            for mode in ("local", "syslog"):
                with self.subTest(mode=mode):
                    self.assert_parent_refused(mode)

    def test_inaccessible_or_nonprivate_parent_modes_are_refused(self):
        self.parent.mkdir(mode=0o700)
        for permissions in (0o000, 0o500, 0o600, 0o750):
            for mode in ("local", "syslog"):
                with self.subTest(mode=mode, permissions=oct(permissions)):
                    self.parent.chmod(permissions)
                    try:
                        self.assert_parent_refused(mode)
                    finally:
                        self.parent.chmod(0o700)

    def test_regular_file_parent_is_refused_for_both_modes(self):
        self.parent.write_bytes(b"synthetic-not-a-directory")
        self.parent.chmod(0o700)
        for mode in ("local", "syslog"):
            with self.subTest(mode=mode):
                self.assert_parent_refused(mode)

    def test_symlink_parent_is_refused_without_following_real_target(self):
        target = self.root / "synthetic-directory"
        target.mkdir(mode=0o700)
        self.parent.symlink_to(target, target_is_directory=True)
        for mode in ("local", "syslog"):
            with self.subTest(mode=mode):
                self.assert_parent_refused(mode)

    def test_parent_lstat_permission_and_io_errors_propagate_as_same_object(self):
        original = Path.lstat
        for code in (errno.EACCES, errno.EIO):
            for mode in ("local", "syslog"):
                with self.subTest(mode=mode, errno=code):
                    fault = OSError(code, "synthetic audit-parent lstat fault")
                    calls = []

                    def failed(path, *args, **kwargs):
                        if path == self.parent:
                            calls.append(path)
                            raise fault
                        return original(path, *args, **kwargs)

                    with patch.object(Path, "lstat", new=failed):
                        with self.assertRaises(OSError) as caught:
                            self.check(mode)
                    self.assertIs(caught.exception, fault)
                    self.assertEqual(calls, [self.parent])
                    self.verify.assert_not_called()

    def test_local_check_passes_gateway_owner_to_real_tail(self):
        self.parent.mkdir(mode=0o700)
        current = self.parent / "current.jsonl"
        current.write_bytes(b'{"synthetic":true}\n')
        current.chmod(0o600)
        original = audit.incomplete_tail
        calls = []

        def owner_checked(path, owner=None):
            calls.append((path, owner))
            self.assertEqual(owner, files.UIDS["gateway"], "check_start omitted the declared gateway owner")
            return self.call_tail(path, owner, reader=original)

        with patch.object(audit, "incomplete_tail", new=owner_checked):
            self.check("local")
        self.assertEqual(calls, [(current, files.UIDS["gateway"])])
        self.verify.assert_called_once_with()
