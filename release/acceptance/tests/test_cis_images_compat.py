import contextlib
import ast
import io
import os
from pathlib import Path
import runpy
import sys
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "cis_bench.sh"
FORMAT = r"table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}"

class DockerImagesCompat(unittest.TestCase):
    def execute(self, args, output=""):
        shell = SOURCE.read_text()
        marker = "<<'PY_COMPAT_WRAPPER'\n"
        self.assertIn(marker, shell, "self-contained Docker compatibility source missing")
        body = shell.split(marker, 1)[1].split("\nPY_COMPAT_WRAPPER", 1)[0]
        tree = ast.parse(body)
        template = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "template" for t in n.targets))
        self.assertTrue(template.startswith("#!/usr/bin/python3\n"), "Executable header missing")
        stream = io.StringIO()
        def forward(*unused):
            stream.write(output)
        with mock.patch.object(sys, "argv", [str(SOURCE), *args]), mock.patch("os.execv", side_effect=forward) as spy, contextlib.redirect_stdout(stream):
            exec(compile(template, "embedded-docker-compatibility", "exec"), {"__name__": "__main__"})
        return spy, stream.getvalue()

    def test_exact_images_uses_real_legacy_arguments(self):
        spy, output = self.execute(["images"])
        spy.assert_called_once_with("/usr/bin/docker", ["/usr/bin/docker","image","ls","--format",FORMAT])
        self.assertEqual(output, "")

    def test_no_extra_or_multiple_header(self):
        real_output = "REPOSITORY\tTAG\tIMAGE ID\tCREATED\tSIZE\nexample/netops\tcandidate\t0123456789ab\tone hour ago\t100MB\n"
        spy, output = self.execute(["images"], real_output)
        self.assertEqual(output, real_output)
        self.assertEqual(output.count("REPOSITORY"), 1)

    def test_unknown_or_other_arguments_delegate_unchanged(self):
        for args in [[],["images","--unknown-flag"],["images","-q"],["images","--format","json"],["image","ls"],["version"]]:
            with self.subTest(args=args):
                spy, output = self.execute(args)
                spy.assert_called_once_with("/usr/bin/docker", ["/usr/bin/docker",*args])
                self.assertEqual(output, "")


class FedoraRepositoryReuse(unittest.TestCase):
    def invoke_repo(self, shape):
        source = SOURCE.with_name("platform_smoke.sh").read_text()
        self.assertEqual(source.count("install_rpm() {"), 1)
        body = "install_rpm() {" + source.split("install_rpm() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        self.assertEqual(body.count("/etc/yum.repos.d/docker-ce.repo"), 1 if "local repo=" in body else 0)
        with tempfile.TemporaryDirectory(prefix="netops-repo-reuse-") as tmp:
            root = Path(tmp)
            repo, expected, calls = root / "docker-ce.repo", root / "expected.repo", root / "calls"
            expected.write_bytes(b"[docker-ce-stable]\nbaseurl=https://example.invalid/public/\ngpgcheck=1\n")
            calls.touch()
            if shape in ("same", "repeat", "unreadable", "fetch_failed"):
                repo.write_bytes(expected.read_bytes())
            elif shape == "different":
                repo.write_bytes(b"[foreign-operator-repo]\n")
            elif shape == "symlink":
                repo.symlink_to(expected)
            before = repo.read_bytes() if repo.exists() else None
            was_link = repo.is_symlink()
            body = body.replace("/etc/yum.repos.d/docker-ce.repo", shlex.quote(str(repo)))
            stub = r"""
sudo() {
  case "$1" in
    test) command "$@";;
    cmp)
      [ "$CASE" != unreadable ] || return 2
      command "$@";;
    dnf)
      printf '%s\n' "$*" >> "$CALLS"
      case "$*" in
        'dnf -y -q config-manager addrepo --from-repofile https://download.docker.com/linux/fedora/docker-ce.repo')
          [ ! -e "$REPO" ] && [ ! -L "$REPO" ] || return 1
          cp "$EXPECTED" "$REPO";;
        'dnf -y -q install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin') return 0;;
        *) return 97;;
      esac;;
    systemctl)
      [ "$*" = 'systemctl enable --now docker' ] || return 97;;
    *) return 97;;
  esac
}
curl() {
  if [ "$*" = '-fsSL https://download.docker.com/linux/fedora/gpg' ]; then
    printf 'synthetic public key\n'
  elif [ "$#" = 4 ] && [ "$1" = -fsSL ] && [ "$2" = https://download.docker.com/linux/fedora/docker-ce.repo ] && [ "$3" = -o ]; then
    [ "$CASE" != fetch_failed ] || return 22
    cp "$EXPECTED" "$4"
  else
    return 97
  fi
}
pgp_fpr() { cat >/dev/null; printf '%s\n' "$DOCKER_RPM_FPR"; }
rpm() { printf '621e9f35\n'; }
report() { printf 'REPORT %s %s\n' "$1" "$2"; }
"""
            script = "set -u\nDOCKER_RPM_FPR=060A61C51B558A7F742B77AAC52FEB6B621E9F35\n" + stub + body
            script += "install_rpm; first=$?; second=-1\nif [ \"$CASE\" = repeat ]; then install_rpm; second=$?; fi\nprintf 'RCS=%s:%s\\n' \"$first\" \"$second\"\n"
            env = dict(os.environ, CASE=shape, REPO=str(repo), EXPECTED=str(expected), CALLS=str(calls), TMPDIR=str(root))
            for key in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
                env.pop(key, None)
            result = subprocess.run(["/bin/bash", "-c", script], env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [r for r in result.stdout.splitlines() if r.startswith("RCS=")]
            self.assertEqual(len(rows), 1, result.stdout)
            rc = tuple(map(int, rows[0][4:].split(":")))
            after = repo.read_bytes() if repo.exists() else None
            self.assertEqual(repo.is_symlink(), was_link)
            if before is not None:
                self.assertEqual(after, before, "existing repository must remain byte identical")
            return rc, calls.read_text().splitlines(), result.stdout

    def test_repeat_identical_repository_succeeds(self):
        rc, calls, output = self.invoke_repo("repeat")
        self.assertEqual(rc, (0, 0))
        self.assertFalse(any("addrepo" in call for call in calls))
        self.assertEqual(output.count("REPORT docker-repo-key PASS"), 2)

    def test_missing_repository_keeps_original_install_and_key_proof(self):
        rc, calls, output = self.invoke_repo("missing")
        self.assertEqual(rc, (0, -1))
        self.assertEqual(sum("addrepo" in call for call in calls), 1)
        self.assertEqual(sum("dnf -y -q install " in call for call in calls), 1)
        self.assertEqual(output.count("REPORT docker-repo-key PASS"), 1)

    def test_existing_identical_repository_reused(self):
        rc, calls, output = self.invoke_repo("same")
        self.assertEqual(rc, (0, -1))
        self.assertFalse(any("addrepo" in call for call in calls))
        self.assertEqual(output.count("REPORT docker-repo-key PASS"), 1)

    def test_foreign_symlink_unreadable_or_unverified_repository_refused(self):
        for shape in ("different", "symlink", "unreadable", "fetch_failed"):
            with self.subTest(shape=shape):
                rc, calls, output = self.invoke_repo(shape)
                self.assertEqual(rc, (1, -1))
                self.assertFalse(any("addrepo" in call or "dnf -y -q install " in call for call in calls))
                self.assertNotIn("REPORT docker-repo-key PASS", output)

if __name__ == "__main__":
    unittest.main(verbosity=2)
