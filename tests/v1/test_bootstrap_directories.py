import os
from pathlib import Path
import stat
import tempfile
import unittest

from netops.bootstrap import directory


class BootstrapDirectories(unittest.TestCase):
    def test_new_directory_uses_declared_mode_under_both_normal_and_private_umask(self):
        with tempfile.TemporaryDirectory() as raw:
            for requested in (0o700, 0o755):
                for mask in (0o022, 0o077):
                    with self.subTest(requested=requested, mask=mask):
                        path = Path(raw) / ("mode_" + oct(requested) + "_mask_" + oct(mask))
                        previous = os.umask(mask)
                        try:
                            directory(path, os.getuid(), requested)
                        finally:
                            os.umask(previous)
                        info = path.lstat()
                        self.assertEqual(info.st_uid, os.getuid())
                        self.assertEqual(stat.S_IMODE(info.st_mode), requested)

    def test_existing_wrong_mode_and_symlink_are_refused_without_repair(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            existing = root / "existing"
            existing.mkdir(mode=0o700)
            before = existing.lstat()
            with self.assertRaisesRegex(ValueError, "Unsafe state directory"):
                directory(existing, os.getuid(), 0o755)
            after = existing.lstat()
            self.assertEqual((after.st_mode, after.st_uid, after.st_ctime_ns),
                             (before.st_mode, before.st_uid, before.st_ctime_ns))
            self.assertEqual(stat.S_IMODE(after.st_mode), 0o700)
            link = root / "link"
            link.symlink_to(existing, target_is_directory=True)
            link_before = link.lstat()
            target_before = existing.lstat()
            with self.assertRaisesRegex(ValueError, "Unsafe state directory"):
                directory(link, os.getuid(), 0o700)
            self.assertEqual(link.lstat(), link_before)
            self.assertEqual(existing.lstat(), target_before)
            self.assertTrue(link.is_symlink())
            self.assertEqual(stat.S_IMODE(existing.lstat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
