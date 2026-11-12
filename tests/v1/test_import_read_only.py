"""Imports must work before the runtime has a writable temporary directory."""

import os
import subprocess
import sys
import unittest


class ReadOnlyImport(unittest.TestCase):
    def test_helper_import_does_not_resolve_or_create_temporary_paths(self):
        for module in ("netops_helper.engine", "netops_helper.server"):
            with self.subTest(module=module):
                result = subprocess.run(
                    [sys.executable, "-B", "-c", """
import importlib
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

missing = '/nonexistent/netops-import-regression'
tempfile.tempdir = missing
assert os.environ['TMPDIR'] == ''
assert not Path(missing).exists()
with patch('tempfile.gettempdir', side_effect=FileNotFoundError('no usable tempdir')) as lookup:
    importlib.import_module(sys.argv[1])
lookup.assert_not_called()
from netops_helper import engine
assert engine._lane_directory.cache_info().currsize == 0
with patch('tempfile.gettempdir', return_value=missing) as lookup:
    expected = Path(missing) / ('netops-helper-ssh-lanes-%d' % os.geteuid())
    assert engine._lane_directory() == expected
    assert engine._lane_directory() == expected
lookup.assert_called_once_with()
assert not Path(missing).exists()
""", module],
                    env={**os.environ, "TMPDIR": ""},
                    capture_output=True, text=True, timeout=120,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
