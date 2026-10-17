import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import redteam


def walk(top):
    done = subprocess.run([sys.executable, "-c", redteam.SETUID_WALKER, top], capture_output=True, text=True, timeout=60)
    return done.returncode, dict(line.split(" ", 1) for line in done.stdout.splitlines() if " " in line)


class SetuidWalker(unittest.TestCase):
    def test_clean_tree_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            os.makedirs(os.path.join(directory, "usr", "bin"))
            with open(os.path.join(directory, "usr", "bin", "tool"), "w") as stream:
                stream.write("x")
            rc, lines = walk(directory)
            self.assertEqual(rc, 0)
            self.assertEqual(lines["FOUND"].split(), [])
            self.assertEqual(lines["UNREADABLE"], "0")

    def test_setuid_and_setgid_files_are_reported_outside_skipped_trees(self):
        with tempfile.TemporaryDirectory() as directory:
            for relative, mode in (("usr/bin/su-like", 0o4755), ("usr/bin/sg-like", 0o2755), ("proc/ignored", 0o4755)):
                path = os.path.join(directory, relative)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as stream:
                    stream.write("x")
                os.chmod(path, mode)
            rc, lines = walk(directory)
            self.assertEqual(rc, 0)
            self.assertEqual(sorted(lines["FOUND"].split()), sorted([os.path.join(directory, "usr/bin/sg-like"), os.path.join(directory, "usr/bin/su-like")]))


if __name__ == "__main__":
    unittest.main()
