import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class SmokePrerequisites(unittest.TestCase):
    def test_first_apt_install_provisions_python_before_key_parser(self):
        script = (Path(__file__).resolve().parents[1] / "platform_smoke.sh").read_text()
        body = script.split("install_apt() {\n", 1)[1].split("\n}\n", 1)[0]
        shell = r"""sudo() {
  printf '%s\0' "$@" >> "$CALLS"
  printf '\n' >> "$CALLS"
  case "$*" in *' install '*) return 1;; esac
  return 0
}
ID=debian
install_apt() {
""" + body + "\n}\ninstall_apt\n"
        with tempfile.TemporaryDirectory() as directory:
            calls = Path(directory) / "calls"
            result = subprocess.run(["bash", "-c", shell], env={**os.environ, "CALLS": str(calls)}, capture_output=True)
            self.assertEqual(result.returncode, 1, "fixture must stop after the dependency installation, before privileged filesystem writes")
            invoked = [line.split(b"\0") for line in calls.read_bytes().splitlines()]
            installs = [args for args in invoked if b"install" in args]
            self.assertEqual(len(installs), 1)
            self.assertIn(b"python3", installs[0], "fresh Raspberry Pi OS must get python3 before PGP parsing and selftest JSON parsing")


if __name__ == "__main__":
    unittest.main()
