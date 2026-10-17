import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

class ComposeStateIdentity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("docker") is None:
            raise RuntimeError("Docker Compose is required; missing prerequisites must fail, not skip")
        subprocess.run(["docker", "compose", "version"], check=True, capture_output=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("COMPOSE_", "NETOPS_", "DOCKER_CONTEXT"))}
        self.env.update(NETOPS_IMAGE="local/netops:configuration-test",
                        NETOPS_BIND_IP="127.0.0.1", NETOPS_PORT="18443",
                        NETOPS_SERVER_NAME="localhost")

    def resolve(self, directory, project=None, env=None, check=True):
        directory.mkdir()
        shutil.copy2(ROOT / "compose.yaml", directory / "compose.yaml")
        command = ["docker", "compose", "--project-directory", str(directory)]
        if project:
            command += ["-p", project]
        command += ["config", "--format", "json"]
        result = subprocess.run(command, env=self.env if env is None else env,
                                text=True, capture_output=True, check=check)
        return json.loads(result.stdout) if check else result

    def test_moving_directory_keeps_the_same_state_volume(self):
        before = self.resolve(self.base / "first-install")
        after = self.resolve(self.base / "moved-install")
        self.assertEqual(before["name"], "netops")
        self.assertEqual(before["volumes"], after["volumes"])
        self.assertEqual(before["volumes"]["netops-state"]["name"], "netops_netops-state")
        self.assertEqual(before["services"]["netops"]["volumes"],
                         after["services"]["netops"]["volumes"])

    def test_explicit_instances_have_different_state_volumes(self):
        first = self.resolve(self.base / "one", "example-one")
        second = self.resolve(self.base / "two", "example-two")
        self.assertNotEqual(first["volumes"]["netops-state"]["name"],
                            second["volumes"]["netops-state"]["name"])

    def test_no_implicit_bind_address(self):
        env = dict(self.env)
        del env["NETOPS_BIND_IP"]
        result = self.resolve(self.base / "missing-bind", env=env, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NETOPS_BIND_IP", result.stderr)

if __name__ == "__main__":
    unittest.main()
