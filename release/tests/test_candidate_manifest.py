import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
SCRIPT = os.path.join(HERE, "..", "candidate_manifest.py")
A = "sha256:" + "a" * 64
B = "sha256:" + "b" * 64
I = "sha256:" + "c" * 64
COMMIT = "1" * 40
IMAGE = "ghcr.io/o/r"


def index(entries, media="application/vnd.oci.image.index.v1+json"):
    return {"mediaType": media, "manifests": [{"digest": d, "platform": {"os": o, "architecture": a}} for d, o, a in entries]}


class CandidateManifest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.release = os.path.join(self.d, "release")
        self.write("digest-amd64.txt", A + "\n")
        self.write("digest-arm64.txt", B + "\n")
        for arch in ("amd64", "arm64"):
            self.write("sbom-%s.cdx.json" % arch, json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7",
                "metadata": {"component": {"type": "container", "name": IMAGE, "version": A if arch == "amd64" else B}},
                "components": [{"type": "library", "name": "synthetic-package", "version": "1.0"}]}))
            self.write("grype-%s.json" % arch, "{}")
            self.write("gate-%s.json" % arch, json.dumps({"status": "pass"}))
        self.write("index.json", json.dumps(index([(A, "linux", "amd64"), (B, "linux", "arm64")])))
        self.write("compose.yaml", "services: {}\n")
        self.write("env.example", "NETOPS_IMAGE=replace-me\nNETOPS_PORT=8443\n")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, content):
        with open(os.path.join(self.d, name), "w") as stream:
            stream.write(content)

    def run_tool(self, commit=COMMIT, index_digest=I, version="1.0.0", extra=()):
        proc = subprocess.run([sys.executable, SCRIPT, "--version", version, "--repository", "o/r", "--commit", commit,
                               "--image", IMAGE, "--index-digest", index_digest, "--index-raw", os.path.join(self.d, "index.json"),
                               "--run-id", "1", "--run-attempt", "1", "--dir", self.d, "--compose", os.path.join(self.d, "compose.yaml"),
                               "--env", os.path.join(self.d, "env.example"), "--release-dir", self.release, *extra], capture_output=True, text=True)
        manifest = None
        path = os.path.join(self.release, "netops-%s-manifest.json" % version)
        if proc.returncode == 0:
            manifest = json.load(open(path))
        return proc.returncode, manifest, proc.stderr

    def sums(self):
        lines = open(os.path.join(self.release, "netops-1.0.0-SHA256SUMS")).read().splitlines()
        return {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in lines}

    def test_valid_candidate(self):
        rc, m, err = self.run_tool()
        self.assertEqual(rc, 0, err)
        self.assertEqual(m["image"]["platforms"]["arm64"]["digest"], B)
        self.assertEqual(m["image"]["platforms"]["amd64"]["files"]["sbom"]["file"], "netops-1.0.0-linux-amd64.cdx.json")
        self.assertEqual(m["vulnerability_gate"], "pass")

    def test_env_example_is_pinned_to_the_index(self):
        self.run_tool()
        env = open(os.path.join(self.release, "env.example")).read()
        self.assertIn("NETOPS_IMAGE=%s@%s\n" % (IMAGE, I), env)
        self.assertIn("NETOPS_PORT=8443", env)

    def test_sha256sums_cover_every_release_file_and_the_manifest(self):
        rc, m, _ = self.run_tool()
        sums = self.sums()
        files = sorted(n for n in os.listdir(self.release) if n != "netops-1.0.0-SHA256SUMS")
        self.assertEqual(sorted(sums), files)
        self.assertIn("netops-1.0.0-manifest.json", sums)
        for name, value in sums.items():
            self.assertEqual(hashlib.sha256(open(os.path.join(self.release, name), "rb").read()).hexdigest(), value, name)
        self.assertEqual(m["release_files"]["env.example"], sums["env.example"])
        self.assertEqual(m["release_files"]["compose.yaml"], sums["compose.yaml"])

    def test_worst_gate_wins(self):
        self.write("gate-arm64.json", json.dumps({"status": "needs-assessment"}))
        self.write("gate-amd64.json", json.dumps({"status": "fail"}))
        self.assertEqual(self.run_tool()[1]["vulnerability_gate"], "fail")

    def test_unknown_gate_status_is_unknown(self):
        self.write("gate-amd64.json", json.dumps({"status": "ok"}))
        self.assertEqual(self.run_tool()[1]["vulnerability_gate"], "unknown")

    def test_swapped_platforms_rejected(self):
        self.write("index.json", json.dumps(index([(B, "linux", "amd64"), (A, "linux", "arm64")])))
        self.assertEqual(self.run_tool()[0], 1)

    def test_attestation_manifest_rejected(self):
        self.write("index.json", json.dumps(index([(A, "linux", "amd64"), (B, "linux", "arm64"), (I, "unknown", "unknown")])))
        rc, _, err = self.run_tool()
        self.assertEqual(rc, 1)
        self.assertIn("attestation", err)

    def test_missing_platform_rejected(self):
        self.write("index.json", json.dumps(index([(A, "linux", "amd64")])))
        self.assertEqual(self.run_tool()[0], 1)

    def test_single_manifest_rejected(self):
        self.write("index.json", json.dumps({"mediaType": "application/vnd.oci.image.manifest.v1+json"}))
        self.assertEqual(self.run_tool()[0], 1)

    def test_same_digest_rejected(self):
        self.write("digest-arm64.txt", A)
        self.assertEqual(self.run_tool()[0], 1)

    def test_malformed_inputs_rejected(self):
        self.assertEqual(self.run_tool(commit="abc")[0], 1)
        self.assertEqual(self.run_tool(index_digest="sha256:xyz")[0], 1)
        self.assertEqual(self.run_tool(version="1.0")[0], 1)
        self.write("digest-amd64.txt", "latest")
        self.assertEqual(self.run_tool()[0], 1)

    def test_env_without_or_with_two_image_lines_rejected(self):
        self.write("env.example", "NETOPS_PORT=8443\n")
        rc, _, err = self.run_tool()
        self.assertEqual(rc, 1)
        self.assertIn("exactly one NETOPS_IMAGE", err)

    def test_non_empty_release_directory_rejected(self):
        os.makedirs(self.release)
        with open(os.path.join(self.release, "stale"), "w") as stream:
            stream.write("x")
        self.assertEqual(self.run_tool()[0], 1)

    def test_assessments_become_a_release_file(self):
        self.write("a.json", json.dumps([{"id": "CVE-1", "package": "x", "exploitable": False, "reasoning": "r"}]))
        rc, _, err = self.run_tool(extra=("--assessments", os.path.join(self.d, "a.json")))
        self.assertEqual(rc, 0, err)
        self.assertIn("netops-1.0.0-vulnerability-assessments.json", self.sums())

    def test_incomplete_assessment_rejected(self):
        self.write("a.json", json.dumps([{"id": "CVE-1", "package": "x"}]))
        rc, _, err = self.run_tool(extra=("--assessments", os.path.join(self.d, "a.json")))
        self.assertEqual(rc, 1)
        self.assertIn("vulnerability assessments", err)

    def test_missing_sbom_rejected(self):
        os.remove(os.path.join(self.d, "sbom-arm64.cdx.json"))
        self.assertEqual(self.run_tool()[0], 1)


if __name__ == "__main__":
    unittest.main()
