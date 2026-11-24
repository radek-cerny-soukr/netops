import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('cumulative_regression', ROOT / 'release/cumulative_regression.py')
cumulative = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cumulative)
SOCKET = Path('/var/run/docker.sock')
REAL_STAT = Path.stat


def commands(suites):
    """Commands main() would run, with docker and the Docker socket replaced by fakes."""
    seen = []

    def fake_run(command, **_):
        seen.append(command)
        return mock.Mock(returncode=0)

    def fake_stat(path, *a, **k):
        return os.stat('/') if path == SOCKET else REAL_STAT(path, *a, **k)

    with tempfile.TemporaryDirectory() as directory:
        argv = ['x', '--image', 'p', '--engine-image', 'e', '--tooling-image', 't', '--commit', 'c',
                '--output-dir', str(Path(directory) / 'out')]
        for suite in suites:
            argv += ['--suite', suite]
        with (mock.patch('sys.argv', argv), mock.patch.object(cumulative.subprocess, 'run', fake_run),
              mock.patch.object(Path, 'stat', fake_stat), mock.patch('builtins.print')):
            cumulative.main()
    return seen


class EngineTemporaryStorage(unittest.TestCase):
    def test_every_engine_role_and_replay_gets_two_gibibytes_of_pytmp(self):
        seen = commands(['engine-core', 'engine-helper', 'engine-auditor', 'engine-admin', 'replay'])
        self.assertEqual(len(seen), 5)
        for command in seen:
            with self.subTest(command=command[-3:]):
                mounts = [command[i + 1] for i, word in enumerate(command) if word == '--tmpfs']
                pytmp = [m for m in mounts if m.startswith('/pytmp:')]
                self.assertEqual(len(pytmp), 1, mounts)
                self.assertIn('size=2g', pytmp[0].split(','))
                self.assertEqual(command[command.index('--memory') + 1], '2g')

    def test_no_pytmp_tmpfs_is_smaller_than_two_gibibytes(self):
        text = (ROOT / 'release/cumulative_regression.py').read_text()
        self.assertNotIn('/pytmp:rw,nosuid,nodev,exec,size=512m', text)


if __name__ == '__main__':
    unittest.main()
