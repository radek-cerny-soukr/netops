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
        directory.mkdir(exist_ok=True)
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

    def test_cpu_default_and_single_cpu_host_override(self):
        default = self.resolve(self.base / "default-cpus")
        self.assertEqual(float(default["services"]["netops"]["cpus"]), 2)
        single = self.resolve(self.base / "single-cpu", env={**self.env, "NETOPS_CPUS": "1"})
        self.assertEqual(float(single["services"]["netops"]["cpus"]), 1)
        example = (ROOT / "env.example").read_text()
        self.assertIn("# NETOPS_CPUS=1", example)

    def test_no_implicit_bind_address(self):
        env = dict(self.env)
        del env["NETOPS_BIND_IP"]
        result = self.resolve(self.base / "missing-bind", env=env, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NETOPS_BIND_IP", result.stderr)

    def test_fortiadc_backup_key_path_from_install_dotenv(self):
        variable = "NETOPS_FORTIADC_BACKUP_KEY_FILE"
        key_path = "/var/lib/netops/helper/fortiadc-backup.key"
        default = self.resolve(self.base / "default-archive")["services"]["netops"]
        self.assertFalse(default["environment"].get(variable))

        install = self.base / "configured-archive"
        install.mkdir()
        (install / ".env").write_text(f"{variable}={key_path}\n")
        service = self.resolve(install)["services"]["netops"]
        self.assertEqual(service["environment"].get(variable), key_path)
        self.assertTrue(any(volume["source"] == "netops-state" and volume["target"] == "/var/lib/netops"
                            for volume in service["volumes"]))

    def test_no_new_privileges_uses_current_security_opt_syntax(self):
        config = self.resolve(self.base / "security-opt")
        self.assertEqual(config["services"]["netops"]["security_opt"],
                         ["no-new-privileges=true"])

if __name__ == "__main__":
    unittest.main()
