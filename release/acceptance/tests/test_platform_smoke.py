import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "platform_smoke.sh"


def function(source, name):
    head = name + "() {"
    if source.count(head) != 1:
        return ""
    return head + source.split(head, 1)[1].split("\n}\n", 1)[0] + "\n}\n"


def fedora_selinux_block(source):
    marker = 'if [ "$ID" = fedora ]; then\n  mode=$(getenforce)'
    if source.count(marker) != 1:
        return ""
    return marker + source.split(marker, 1)[1].split("\nfi\n", 1)[0] + "\nfi\n"


def run(script, root, env=None, argv0="bash"):
    clean = dict(os.environ, TMPDIR=str(root), **(env or {}))
    for key in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
        clean.pop(key, None)
    return subprocess.run(["/bin/bash", "-c", "set -u\n" + script, argv0], env=clean, capture_output=True, text=True, timeout=10)


REPORT = "report() { printf 'REPORT %s %s %s\\n' \"$1\" \"$2\" \"$3\"; }\n"


class SelinuxCheckNeedsRunningProcess(unittest.TestCase):
    STUB = r"""
ID=fedora REF=ghcr.io/example/netops@sha256:feed
getenforce() { echo Enforcing; }
sleep() { :; }
sudo() {
  case "$1 $2" in
    "docker run") echo c0ffee;;
    "docker inspect")
      case "$4" in
        '{{.ProcessLabel}}') echo system_u:system_r:container_t:s0:c1,c2;;
        '{{.State.Running}}') echo "$RUNNING";;
        '{{.State.Pid}}') echo "$PID";;
        *) return 97;;
      esac;;
    "docker rm") return 0;;
    *) return 97;;
  esac
}
ps() {
  case "$*" in
    -eZ) printf 'LABEL PID TTY TIME CMD\nsystem_u:system_r:container_t:s0:c7,c9 4242 ? 00:00:00 other-container\n';;
    "-o label= -p 777") [ "$RUNNING" = true ] && echo system_u:system_r:container_t:s0:c1,c2; [ "$RUNNING" = true ];;
    *) return 1;;
  esac
}
"""

    def check(self, running, pid):
        block = fedora_selinux_block(SOURCE.read_text())
        self.assertTrue(block, "Fedora SELinux block not found")
        with tempfile.TemporaryDirectory(prefix="netops-smoke-selinux-") as tmp:
            result = run(REPORT + self.STUB + block, Path(tmp), {"RUNNING": running, "PID": pid})
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [r for r in result.stdout.splitlines() if r.startswith("REPORT selinux ")]
        self.assertEqual(len(rows), 1, result.stdout)
        return rows[0]

    def test_exited_container_is_not_selinux_proof(self):
        self.assertTrue(self.check("false", "0").startswith("REPORT selinux FAIL"))

    def test_running_confined_process_passes(self):
        row = self.check("true", "777")
        self.assertTrue(row.startswith("REPORT selinux PASS"), row)
        self.assertIn("pid 777", row)


class PackageManagerLock(unittest.TestCase):
    def test_dispatch_waits_before_install(self):
        source = SOURCE.read_text()
        self.assertIn("ubuntu|debian) wait_pkg_idle && install_apt ;;", source)
        self.assertIn("fedora) wait_pkg_idle && install_rpm ;;", source)

    def wait(self, busy):
        body = function(SOURCE.read_text(), "wait_pkg_idle")
        self.assertTrue(body, "wait_pkg_idle missing")
        stub = r"""
sleep() { :; }
sudo() { [ "$1" = cloud-init ] && { echo cloud-init >> "$CALLS"; return 0; }; return 97; }
command() { [ "$1 $2" = "-v cloud-init" ] && return 0; builtin command "$@"; }
systemctl() {
  printf 'systemctl %s\n' "$*" >> "$CALLS"
  n=$(grep -c '^systemctl' "$CALLS")
  [ "$n" -le "$BUSY" ]
}
"""
        with tempfile.TemporaryDirectory(prefix="netops-smoke-lock-") as tmp:
            calls = Path(tmp) / "calls"
            calls.touch()
            result = run(REPORT + stub + body + "wait_pkg_idle; echo RC=$?\n", Path(tmp), {"CALLS": str(calls), "BUSY": str(busy)})
            return result, calls.read_text().splitlines()

    def test_waits_until_package_jobs_finish(self):
        result, calls = self.wait(2)
        self.assertIn("RC=0", result.stdout, result.stderr)
        self.assertEqual(calls[0], "cloud-init")
        self.assertEqual(sum(c.startswith("systemctl is-active") for c in calls), 3)
        for unit in ("apt-daily.service", "apt-daily-upgrade.service", "dnf-makecache.service"):
            self.assertIn(unit, calls[1])

    def test_gives_up_with_fail_report(self):
        result, calls = self.wait(10000)
        self.assertIn("RC=1", result.stdout, result.stderr)
        self.assertIn("REPORT package-manager FAIL", result.stdout)

    def test_every_apt_get_call_waits_for_the_dpkg_lock(self):
        body = function(SOURCE.read_text(), "install_apt")
        self.assertTrue(body)
        stub = r"""
ID=debian DOCKER_APT_FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
pgp_fpr() { cat >/dev/null; echo "$DOCKER_APT_FPR"; }
dpkg() { echo amd64; }
sudo() {
  while [ "${1#*=}" != "$1" ]; do shift; done
  case "$1" in
    apt-get) printf '%s\n' "$*" >> "$CALLS";;
    tee) cat >/dev/null;;
  esac
  return 0
}
"""
        with tempfile.TemporaryDirectory(prefix="netops-smoke-apt-") as tmp:
            calls = Path(tmp) / "calls"
            calls.touch()
            keyring = Path(tmp) / "docker.asc"
            keyring.touch()
            body = body.replace("/etc/apt/keyrings/docker.asc", str(keyring))
            result = run(REPORT + stub + body + "install_apt; echo RC=$?\n", Path(tmp), {"CALLS": str(calls)})
            lines = calls.read_text().splitlines()
        self.assertIn("RC=0", result.stdout, result.stderr)
        self.assertEqual(len(lines), 4, lines)
        for line in lines:
            self.assertIn("-o DPkg::Lock::Timeout=600", line)


class FedoraDaemonConfigRestart(unittest.TestCase):
    def install(self, existing):
        body = function(SOURCE.read_text(), "install_rpm")
        self.assertTrue(body)
        with tempfile.TemporaryDirectory(prefix="netops-smoke-daemon-") as tmp:
            root = Path(tmp)
            (root / "fedora-daemon.json").write_text('{"selinux-enabled": true}\n')
            target, calls, repo = root / "etc-docker-daemon.json", root / "calls", root / "docker-ce.repo"
            calls.touch()
            if existing is not None:
                target.write_text(existing)
            body = body.replace("/etc/docker/daemon.json", shlex.quote(str(target))).replace("/etc/yum.repos.d/docker-ce.repo", shlex.quote(str(repo)))
            stub = r"""
DOCKER_RPM_FPR=060A61C51B558A7F742B77AAC52FEB6B621E9F35
pgp_fpr() { cat >/dev/null; printf '%s\n' "$DOCKER_RPM_FPR"; }
rpm() { printf '621e9f35\n'; }
curl() { printf 'key\n'; }
sudo() {
  case "$1" in
    test|cmp|install) command "$@";;
    systemctl|dnf) printf '%s\n' "$*" >> "$CALLS";;
    *) return 97;;
  esac
}
"""
            result = run(REPORT + stub + body + "install_rpm; echo RC=$?\n", root, {"CALLS": str(calls)}, argv0=str(root / "platform_smoke.sh"))
            return result, calls.read_text().splitlines(), target.read_text()

    def test_unchanged_daemon_json_does_not_restart_docker(self):
        result, calls, content = self.install('{"selinux-enabled": true}\n')
        self.assertIn("RC=0", result.stdout, result.stderr)
        self.assertNotIn("systemctl restart docker", calls)
        self.assertEqual(content, '{"selinux-enabled": true}\n')

    def test_new_daemon_json_is_installed_and_applied(self):
        result, calls, content = self.install(None)
        self.assertIn("RC=0", result.stdout, result.stderr)
        self.assertIn("systemctl restart docker", calls)
        self.assertEqual(content, '{"selinux-enabled": true}\n')


if __name__ == "__main__":
    unittest.main(verbosity=2)
