import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netops.audit import queued_bytes


class HealthQueueBytes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        for index, size in enumerate((10, 20, 30)):
            (self.directory / ("%d-x.queue" % index)).write_bytes(b"q" * size)
        (self.directory / "ignored.jsonl").write_bytes(b"j" * 99)

    def test_counts_queued_record_bytes_only(self):
        self.assertEqual(queued_bytes(self.directory), 60)

    def test_record_removed_by_the_forwarder_after_listing_is_not_an_error(self):
        real_stat = Path.stat
        removed = self.directory / "1-x.queue"
        unlinked = []

        def stat(path, *args, **kwargs):
            if path == removed and not unlinked:
                os.unlink(removed)
                unlinked.append(removed)
            return real_stat(path, *args, **kwargs)

        with patch.object(Path, "stat", stat):
            total = queued_bytes(self.directory)
        self.assertEqual(unlinked, [removed])
        self.assertFalse(os.path.lexists(removed))
        self.assertEqual(total, 40)

    def test_dangling_queue_entry_is_not_hidden(self):
        (self.directory / "3-x.queue").symlink_to(self.directory / "absent")
        with self.assertRaises(FileNotFoundError):
            queued_bytes(self.directory)

    def test_other_errors_are_not_hidden(self):
        with patch.object(Path, "stat", side_effect=PermissionError(13, "Permission denied")):
            with self.assertRaises(PermissionError):
                queued_bytes(self.directory)

    def test_error_while_confirming_a_missing_record_is_not_hidden(self):
        missing = self.directory / "1-x.queue"
        real_stat = Path.stat

        def stat(path, *args, **kwargs):
            if path == missing:
                raise FileNotFoundError(2, "No such file or directory")
            return real_stat(path, *args, **kwargs)

        def lstat(path):
            raise PermissionError(13, "Permission denied")

        with patch.object(Path, "stat", stat), patch.object(Path, "lstat", lstat):
            with self.assertRaises(PermissionError):
                queued_bytes(self.directory)


if __name__ == "__main__":
    unittest.main()
