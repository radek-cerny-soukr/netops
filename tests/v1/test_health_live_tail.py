import fcntl
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import netops.audit as audit_module
from netops.audit import Audit, AuditUnavailable, incomplete_tail, live_incomplete_tail as health_tail


class HealthLiveTail(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "audit"
        self.directory.mkdir(mode=0o700)
        self.audit = Audit(str(self.directory), {"mode": "local", "budget_bytes": 1 << 30})
        self.audit._append({"direction": "request", "n": 0})

    def locked_by_other(self, path):
        fd = os.open(path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            return True
        finally:
            os.close(fd)

    def test_barrier_inside_real_write_is_writing_not_incomplete_and_completes(self):
        real_write = os.write
        middle, release, seen = threading.Event(), threading.Event(), {}

        def barrier_write(fd, data):
            if middle.is_set():
                return real_write(fd, data)
            written = real_write(fd, bytes(data[:len(data) // 2]))
            seen["old_reader_incomplete"] = incomplete_tail(self.audit.current)
            seen["health_incomplete"] = health_tail(self.audit.current)
            seen["locked"] = self.locked_by_other(self.audit.current)
            middle.set()
            release.wait(10)
            return written

        failures = []

        def append():
            try:
                self.audit._append({"direction": "request", "n": 1, "pad": "x" * 200000})
            except BaseException as error:
                failures.append(error)

        with patch.object(audit_module.os, "write", barrier_write):
            writer = threading.Thread(target=append)
            writer.start()
            try:
                self.assertTrue(middle.wait(10))
            finally:
                release.set()
                writer.join(10)
        self.assertFalse(writer.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(seen["old_reader_incomplete"], "the barrier really sits inside a partial record")
        self.assertTrue(seen["locked"], "the writer holds its lock from before the first write")
        self.assertFalse(seen["health_incomplete"], "health must read a segment being written as writing, not as incomplete")
        self.assertFalse(incomplete_tail(self.audit.current))
        self.assertFalse(health_tail(self.audit.current))
        lines = self.audit.current.read_bytes().splitlines()
        self.assertEqual([json.loads(line)["n"] for line in lines], [0, 1])
        self.assertFalse(self.locked_by_other(self.audit.current))

    def test_lock_is_held_through_fsync(self):
        real_fsync, seen = os.fsync, {}

        def checking_fsync(fd):
            if os.fstat(fd).st_ino == self.audit.current.stat().st_ino:
                seen["locked"] = self.locked_by_other(self.audit.current)
            return real_fsync(fd)

        with patch.object(audit_module.os, "fsync", checking_fsync):
            self.audit._append({"direction": "request", "n": 1})
        self.assertTrue(seen["locked"])
        self.assertFalse(self.locked_by_other(self.audit.current))

    def test_truly_truncated_unlocked_record_is_still_refused_by_health_and_writer(self):
        with open(self.audit.current, "ab") as stream:
            stream.write(b'{"direction":"request","payl')
        self.assertTrue(incomplete_tail(self.audit.current))
        self.assertTrue(health_tail(self.audit.current))
        with self.assertRaises(AuditUnavailable):
            self.audit._append({"direction": "request", "n": 2})

    def test_segment_vanished_after_listing_is_not_incomplete(self):
        self.assertFalse(health_tail(self.directory / "1.jsonl"))

    def test_other_io_problems_are_not_hidden(self):
        target = self.directory / "target"
        target.write_bytes(b"{}\n")
        target.chmod(0o600)
        cases = {}
        link = self.directory / "link.jsonl"
        link.symlink_to(target)
        cases["symlink"] = link
        folder = self.directory / "folder.jsonl"
        folder.mkdir()
        cases["directory"] = folder
        hard = self.directory / "hard.jsonl"
        os.link(target, hard)
        cases["hardlink"] = hard
        loose = self.directory / "loose.jsonl"
        loose.write_bytes(b"{}\n")
        loose.chmod(0o644)
        cases["group-readable"] = loose
        for name, path in cases.items():
            with self.subTest(case=name):
                with self.assertRaises((OSError, ValueError)):
                    health_tail(path)

    def test_unreadable_segment_is_not_hidden(self):
        path = self.directory / "unreadable.jsonl"
        path.write_bytes(b"{}\n")
        path.chmod(0o600)
        with patch.object(audit_module.os, "open", side_effect=PermissionError(13, "Permission denied")):
            with self.assertRaises(PermissionError):
                health_tail(path)
        if os.geteuid() != 0:
            path.chmod(0o000)
            with self.assertRaises(PermissionError):
                health_tail(path)


if __name__ == "__main__":
    unittest.main()
