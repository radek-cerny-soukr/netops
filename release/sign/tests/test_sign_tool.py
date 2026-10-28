import concurrent.futures
import contextlib
import io
import multiprocessing
import sys
import time
import traceback
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "netops-release-sign.ps1")
PWSH = os.environ.get("NETOPS_PWSH_IMAGE",
                      "mcr.microsoft.com/powershell@sha256:2c21f3fda52e3562910aab93def4c8d039ee2f78d8d6033cc6678991e0fb7759"
                      if platform.machine().lower() in ("aarch64", "arm64") else
                      "mcr.microsoft.com/powershell@sha256:810c4f1e0c9d23022c3ec18c50a6205ee4b60766f1739d329b2948df1fd7d5b0")
COMMIT = "a" * 40
IMAGE = "ghcr.io/radek-cerny-soukr/netops"
A = "sha256:" + "1" * 64
B = "sha256:" + "2" * 64
V = "1.0.4"
ARCHES = ("amd64", "arm64")
SUITES = ("blackbox", "redteam", "failclosed", "syslog", "device", "token-output")
BLIND_INSTALL_ROWS = ("blind-install-fedora-amd64", "blind-install-debian-amd64")
BLIND_ROWS = BLIND_INSTALL_ROWS + ("blind-upgrade-amd64",)
ROWS = (["actions-%s-%s" % (a, s) for a in ARCHES for s in SUITES]
        + ["actions-%s-engine-%s" % (a, r) for a in ARCHES for r in ("core", "helper", "auditor", "admin")]
        + list(BLIND_ROWS) + ["code-review"])
OPTIONAL_ROWS = ("codex-cli-e2e",)
OLD_ROWS = (["%s-%s-%s" % (o, a, d) for o in ("ubuntu", "debian", "fedora") for a in ARCHES for d in ("rootful", "rootless")]
            + ["rpios-arm64-%s" % d for d in ("rootful", "rootless")]
            + ["upgrade-amd64", "upgrade-arm64", "upgrade-fedora-amd64", "claude-code-e2e", "syslog-load"])
INSTALL_CHECKS = ("cosign-verify-blob", "sha256sum-check", "container-healthy", "health-ready", "version-is-candidate",
                  "unauthenticated-401", "mcp-tools-list", "audit-without-token")
UPGRADE_CHECKS = ("upgrade-steps-from-docs", "health-ready", "version-is-candidate", "data-preserved", "token-preserved", "ca-preserved")
UPGRADE_ROW = "blind-upgrade-amd64"
FROM_VERSION = "1.0.3"
FROM_IMAGE = IMAGE + "@sha256:0ddf246ca5e22f7df89abb9cf8f7c9fd10920eec39b4a02ad7fddac04a3b65ce"


def release_docs():
    return {"CHANGELOG.md": "# NetOps changelog\n\n## %s - 2026-10-26\n" % V, "README.md": "Acceptance of %s: blind runs.\n" % V,
            "release/notes-%s.md" % V: "## Acceptance\n\nBlind runs.\n", "docs/archive/0.x/old.md": "TODO(historical): kept.\n"}


def blind_checks(row):
    return INSTALL_CHECKS if row in BLIND_INSTALL_ROWS else UPGRADE_CHECKS


def default_report(row):
    if row in BLIND_ROWS:
        report = {"version": V, "rehearsal": False, "checks": [{"check": c, "status": "PASS"} for c in blind_checks(row)]}
        if row == UPGRADE_ROW:
            report.update(from_version=FROM_VERSION, from_image=FROM_IMAGE)
    else:
        report = {"checks": [{"check": "x", "status": "PASS"}]}
    if row in BLIND_ROWS or row == "code-review":
        report["protocol_sha256"] = "3" * 64
    return report


FINDING = {"id": "CVE-1", "package": "libx", "version": "1.0", "type": "apk"}
SUMS = "netops-%s-SHA256SUMS" % V
BUNDLE = SUMS + ".sigstore.json"


class Missing:
    def __repr__(self):
        return "MISSING"


MISSING = Missing()


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Registry:
    def __init__(self):
        self.index = b""
        self.manifest_status = 200
        self.snapdir = None
        self.seen = []
        registry = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path.startswith("/token"):
                    registry.observe()
                    body, status = json.dumps({"token": "anon"}).encode(), 200
                elif self.path.startswith("/v2/") and self.headers.get("Authorization") == "Bearer anon":
                    body, status = registry.index, registry.manifest_status
                else:
                    body, status = b"", 401
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def observe(self):
        if self.snapdir is None:
            return
        for name in sorted(os.listdir(self.snapdir)):
            path = os.path.join(self.snapdir, name)
            if name.startswith("netops-sign-"):
                files = sorted(os.listdir(path))
                sums = sha(open(os.path.join(path, SUMS), "rb").read()) if SUMS in files else None
                self.seen.append((name, os.lstat(path).st_mode & 0o7777, files, sums))

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class SignTool(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sign-")
        os.chmod(self.dir, 0o755)
        self.registry = Registry()
        self.digests = {"amd64": A, "arm64": B}
        self.set_index([(A, "amd64"), (B, "arm64")])
        self.findings = {a: [dict(FINDING, severity="Medium", state="not-fixed")] for a in ARCHES}
        self.assessments = [dict(FINDING, exploitable=False, reasoning="unreachable", evidence="not imported")]
        self.reports = {row: default_report(row) for row in ROWS + list(OPTIONAL_ROWS)}
        self.gate_status = "needs-assessment"
        self.db_built = "2026-10-15T00:00:00Z"
        self.db_age = 1.0
        self.db_descriptor = {"status": {"built": self.db_built}}
        self.matches_override = None
        self.extra_lines = []
        self.skip_from_sums = set()
        self.image = IMAGE
        self.commit = COMMIT
        self.patches = {}
        self.cosign_sign_rc = 0
        self.cosign_verify_rc = 0
        self.cosign_tamper = False
        self.cosign_race_bundle = False
        self.source = None

    def patch(self, kind, content, arch=None):
        if kind in self.patches:
            self.patches[kind](content, arch)
        return content

    def tearDown(self):
        self.registry.close()
        shutil.rmtree(self.dir)

    def set_index(self, entries):
        self.registry.index = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                                          "manifests": [{"digest": d, "platform": {"os": "linux", "architecture": a}} for d, a in entries]}).encode()
        self.index_digest = "sha256:" + sha(self.registry.index)

    def write(self, name, content):
        path = os.path.join(self.dir, name)
        with open(path, "w") as stream:
            stream.write(content if isinstance(content, str) else json.dumps(content, indent=1))
        os.chmod(path, 0o644)
        return sha(open(path, "rb").read())

    def build(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        self.write("compose.yaml", "services: {}\n")
        self.write("env.example", "NETOPS_IMAGE=%s@%s\nNETOPS_PORT=8443\n" % (self.image, self.index_digest))
        platforms = {}
        for arch in ARCHES:
            matches = [{"vulnerability": {"id": f["id"], "severity": f["severity"], "fix": {"state": f["state"]}},
                        "artifact": {"name": f["package"], "version": f["version"], "type": f["type"]}} for f in self.findings[arch]]
            ref = "%s@%s" % (self.image, self.digests[arch])
            scan = self.patch("scan", {"descriptor": {"db": self.db_descriptor}, "source": {"type": "image", "target": {"userInput": ref, "repoDigests": [ref]}}, "matches": matches if self.matches_override is None else self.matches_override}, arch)
            files = {}
            for kind, name, content in (("sbom", "netops-%s-linux-%s.cdx.json" % (V, arch), {"bomFormat": "CycloneDX"}),
                                        ("scan", "netops-%s-linux-%s-grype.json" % (V, arch), scan),
                                        ("gate", "netops-%s-linux-%s-gate.json" % (V, arch), self.patch("gate", {"status": self.gate_status, "database_built": self.db_built, "database_age_hours": self.db_age}, arch))):
                files[kind] = {"file": name, "sha256": self.write(name, content)}
            platforms[arch] = {"digest": self.digests[arch], "files": files}
        self.write("netops-%s-vulnerability-assessments.json" % V, self.assessments)
        manifest = {"schema": "netops-release-candidate/1", "product": "netops", "version": V,
                    "source": {"repository": "radek-cerny-soukr/netops", "commit": self.commit},
                    "image": {"name": self.image, "index_digest": self.index_digest, "platforms": platforms},
                    "release_files": {n: sha(open(os.path.join(self.dir, n), "rb").read()) for n in ("compose.yaml", "env.example")}}
        self.write("netops-%s-manifest.json" % V, self.patch("manifest", manifest))
        entries = []
        for row, report in self.reports.items():
            body = {"candidate_commit": self.commit, "candidate_image": self.index_digest}
            body.update(report)
            name = "acceptance-%s.json" % row
            entries.append({"row": row, "file": name, "sha256": self.write(name, body)})
        self.write("netops-%s-acceptance-manifest.json" % V, self.patch("acceptance", {"schema": "netops-acceptance-manifest/1", "candidate_commit": self.commit,
                                                                                    "candidate_image": self.index_digest, "reports": entries}))
        lines = ["%s  %s" % (sha(open(os.path.join(self.dir, n), "rb").read()), n) for n in sorted(os.listdir(self.dir)) if n not in self.skip_from_sums]
        self.write("netops-%s-SHA256SUMS" % V, "\n".join(lines + self.extra_lines) + "\n")

    def run_tool(self, check_only=True, stdin="", extra=(), build=True, culture=None):
        if build:
            self.build()
        cosign = os.path.join(self.dir, "..", os.path.basename(self.dir) + "-cosign")
        script = ["#!/bin/sh", "echo \"cosign $*\" >> /log/cosign.log"]
        if self.cosign_tamper:
            script.append("[ \"$1\" = sign-blob ] && printf 'tampered\\n' > /c/%s" % SUMS)
        if self.cosign_race_bundle:
            script.append("[ \"$1\" = sign-blob ] && printf 'foreign\\n' > /c/%s" % BUNDLE)
        script += ["for a in \"$@\"; do last=\"$a\"; done",
                   "echo \"$1 $(sha256sum < \"$last\" | cut -d' ' -f1) $last\" >> /log/cosign.sha",
                   "for a in \"$@\"; do case \"$prev\" in --bundle) echo bundle > \"$a\";; esac; prev=\"$a\"; done",
                   "case \"$1\" in sign-blob) exit %d;; verify-blob) exit %d;; esac" % (self.cosign_sign_rc, self.cosign_verify_rc),
                   "exit 0"]
        with open(cosign, "w") as stream:
            stream.write("\n".join(script) + "\n")
        os.chmod(cosign, 0o755)
        self.logdir = tempfile.mkdtemp(prefix="signlog-")
        os.chmod(self.logdir, 0o777)
        snapdir = tempfile.mkdtemp(prefix="signtmp-")
        self.registry.snapdir = snapdir
        self.registry.seen = []
        # Own, exact-byte copy of the tool outside both the candidate dir and the private
        # snapshot set (their contents are asserted exactly in test_b1_check_only_uses_a_private_snapshot_that_is_removed
        # and must never include tool.ps1), and outside self.logdir (mounted rw at /log, which
        # would otherwise give a second, writable path to the same inode as the ro /tool.ps1 mount).
        # Only this owned copy gets SELinux-relabelled; the real release/sign/netops-release-sign.ps1
        # in the checkout is never touched.
        tooldir = tempfile.mkdtemp(prefix="signtool-")
        toolcopy = os.path.join(tooldir, "tool.ps1")
        shutil.copyfile(TOOL, toolcopy)
        os.chmod(toolcopy, 0o644)
        sourcedir = tempfile.mkdtemp(prefix="signsrc-")
        os.chmod(sourcedir, 0o755)
        for name, content in (release_docs() if self.source is None else self.source).items():
            path = os.path.join(sourcedir, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(content)
        args = ["-CandidateDir", "/c", "-SourceDir", "/s", "-Cosign", "/cosign", "-Registry", "http://127.0.0.1:%d" % self.registry.port, *extra]
        if check_only:
            args.append("-CheckOnly")
        command = ["pwsh", "-NoProfile", "-File", "/tool.ps1", *args]
        if culture is not None:
            command = ["pwsh", "-NoProfile", "-Command",
                       "[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('%s'); "
                       "$probe = [DateTimeOffset]::MinValue; "
                       "'CULTURE ' + [Threading.Thread]::CurrentThread.CurrentCulture.Name; "
                       "'AMBIENT_TRYPARSE ' + [DateTimeOffset]::TryParse('10/15/2026 00:00:00', [ref]$probe); "
                       "& /tool.ps1 %s; exit $LASTEXITCODE" % (culture, " ".join(args))]
        try:
            proc = subprocess.run(["docker", "run", "--rm", "-i", "--network", "host", "--user", "%d:%d" % (os.getuid(), os.getgid()), "-e", "HOME=/tmp",
                                   "-e", "TMPDIR=" + snapdir, "-v", snapdir + ":" + snapdir + ":Z",
                                   "-v", self.dir + ":/c:Z", "-v", cosign + ":/cosign:ro,Z", "-v", self.logdir + ":/log:Z", "-v", toolcopy + ":/tool.ps1:ro,Z",
                                   "-v", sourcedir + ":/s:ro,Z", PWSH, *command], input=stdin, capture_output=True, text=True, timeout=240)
        finally:
            shutil.rmtree(tooldir)
            shutil.rmtree(sourcedir)
        os.remove(cosign)
        self.registry.snapdir = None
        self.snapshot_left = [n for n in os.listdir(snapdir) if n.startswith("netops-sign-")]
        self.snapdir = snapdir
        shutil.rmtree(snapdir)
        self.cosign_log = open(os.path.join(self.logdir, "cosign.log")).read().splitlines() if os.path.exists(os.path.join(self.logdir, "cosign.log")) else []
        self.cosign_sha = [line.split(" ") for line in open(os.path.join(self.logdir, "cosign.sha")).read().splitlines()] if os.path.exists(os.path.join(self.logdir, "cosign.sha")) else []
        shutil.rmtree(self.logdir)
        self.assertEqual(self.snapshot_left, [], "the private snapshot must be removed after every run")
        return proc.returncode, proc.stdout + proc.stderr

    def run_function(self, body, user=None):
        snapdir = tempfile.mkdtemp(prefix="signfn-")
        script = ("$ErrorActionPreference = 'Stop'\n"
                  "$ast = [System.Management.Automation.Language.Parser]::ParseFile('/tool.ps1', [ref]$null, [ref]$null)\n"
                  "foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { . ([scriptblock]::Create($f.Extent.Text)) }\n"
                  + body)
        # Same owned, exact-byte tool copy as run_tool(): never relabel the real TOOL file.
        tooldir = tempfile.mkdtemp(prefix="signtoolfn-")
        toolcopy = os.path.join(tooldir, "tool.ps1")
        shutil.copyfile(TOOL, toolcopy)
        os.chmod(toolcopy, 0o644)
        try:
            proc = subprocess.run(["docker", "run", "--rm", "--network", "none", "--user", user or "%d:%d" % (os.getuid(), os.getgid()), "-e", "HOME=/tmp",
                                   "-v", snapdir + ":/snap:Z", "-v", toolcopy + ":/tool.ps1:ro,Z",
                                   PWSH, "pwsh", "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=240)
        finally:
            shutil.rmtree(tooldir)
        return proc.returncode, proc.stdout + proc.stderr, snapdir

    def assert_refused(self, text, extra=()):
        rc, out = self.run_tool(extra=extra)
        self.assertEqual(rc, 1, out)
        self.assertIn(text, out)
        return out

    def test_open_release_documentation_refuses_signing(self):
        cases = (("README.md", "- **Acceptance:** TODO(acceptance-%s): describe it.\n" % V, "README.md:1: open placeholder TODO(acceptance-%s)" % V),
                 ("CHANGELOG.md", "# NetOps changelog\n\n## %s - TODO(release-date)\n" % V, "CHANGELOG.md:3: open placeholder TODO(release-date)"),
                 ("CHANGELOG.md", "# NetOps changelog\n\n## %s - TODO(release-date)\n" % V, "CHANGELOG.md has no dated section ## %s" % V),
                 ("release/notes-%s.md" % V, None, "release/notes-%s.md is missing" % V),
                 ("components/x/docs/tools.md", "Text.\nTODO(\n", "components/x/docs/tools.md:2: open placeholder TODO("))
        clean = release_docs()
        for name, content, expected in cases:
            with self.subTest(name=name, expected=expected):
                self.source = dict(clean)
                if content is None:
                    del self.source[name]
                else:
                    self.source[name] = content
                rc, out = self.run_tool(check_only=False, stdin="SIGN\n")
                self.assertEqual(rc, 1, out)
                self.assertRegex(out, r"release documentation\s+FAIL")
                self.assertIn(expected, out)
                self.assertIn("Signing refused: every row must be PASS.", out)
                self.assertEqual(self.cosign_log, [])

    def test_complete_candidate_passes(self):
        self.reports = {r: v for r, v in self.reports.items()}
        rc, out = self.run_tool()
        self.assertEqual(rc, 0, out)
        self.assertIn("OVERALL: PASS", out)

    def test_acceptance_rows_are_the_1_0_2_rows(self):
        rc, out = self.run_tool()
        self.assertEqual(rc, 0, out)
        self.assertEqual(sorted(set(re.findall(r"(?m)^acceptance (\S+)", out))), sorted(ROWS + list(OPTIONAL_ROWS)))
        self.assertEqual(len(ROWS), 24)
        for old in OLD_ROWS:
            self.assertNotRegex(out, r"(?m)^acceptance %s\s" % re.escape(old))

    def test_missing_rows_are_not_run(self):
        self.reports = {r: v for r, v in self.reports.items() if not r.startswith("blind-install-fedora")}
        out = self.assert_refused("OVERALL: NOT RUN")
        self.assertRegex(out, r"(?m)^acceptance blind-install-fedora-amd64\s+NOT RUN\s+no report")

    def test_engine_rows_are_required(self):
        del self.reports["actions-arm64-engine-admin"]
        rc, out = self.run_tool()
        self.assertEqual(rc, 1, out)
        self.assertIn("actions-arm64-engine-admin", out)
        self.assertIn("OVERALL: NOT RUN", out)

    def test_device_row_is_required(self):
        del self.reports["actions-amd64-device"]
        rc, out = self.run_tool()
        self.assertEqual(rc, 1, out)
        self.assertIn("actions-amd64-device", out)
        self.assertIn("OVERALL: NOT RUN", out)

    def test_each_blind_row_and_code_review_is_required(self):
        for row in BLIND_ROWS + ("code-review",):
            with self.subTest(row=row):
                reports = self.reports
                self.reports = {r: v for r, v in reports.items() if r != row}
                rc, out = self.run_tool()
                self.reports = reports
                self.assertEqual(rc, 1, out)
                self.assertRegex(out, r"(?m)^acceptance %s\s+NOT RUN\s+no report" % re.escape(row))
                self.assertIn("OVERALL: NOT RUN", out)

    def test_1_0_1_layer_reports_do_not_replace_blind_rows(self):
        self.reports = {r: v for r, v in self.reports.items() if r not in BLIND_ROWS}
        for row in OLD_ROWS:
            self.reports[row] = {"checks": [{"check": "x", "status": "PASS"}], "protocol_sha256": "3" * 64}
        out = self.assert_refused("OVERALL: NOT RUN")
        for row in BLIND_ROWS:
            self.assertRegex(out, r"(?m)^acceptance %s\s+NOT RUN\s+no report" % re.escape(row))

    def test_codex_row_is_optional_and_states_why(self):
        del self.reports["codex-cli-e2e"]
        rc, out = self.run_tool()
        self.assertEqual(rc, 0, out)
        self.assertIn("OVERALL: PASS", out)
        self.assertRegex(out, r"(?m)^acceptance codex-cli-e2e\s+NOT RUN\s+optional, does not block: no report")
        self.reports["codex-cli-e2e"] = {"checks": [{"check": "helper_status", "status": "NOT RUN", "detail": "no Codex tokens available"}]}
        rc, out = self.run_tool()
        self.assertEqual(rc, 0, out)
        self.assertIn("OVERALL: PASS", out)
        self.assertRegex(out, r"(?m)^acceptance codex-cli-e2e\s+NOT RUN\s+optional, does not block: 1 of 1 checks not run: no Codex tokens available")

    def test_failed_codex_row_still_refuses(self):
        self.reports["codex-cli-e2e"] = {"checks": [{"check": "helper_status", "status": "FAIL"}]}
        out = self.assert_refused("OVERALL: FAIL")
        self.assertRegex(out, r"(?m)^acceptance codex-cli-e2e\s+FAIL")

    def test_blind_rows_need_exactly_their_checks_passed(self):
        def checks(row, drop=(), fail=(), notrun=(), extra=()):
            return dict(default_report(row), checks=[{"check": c, "status": "FAIL" if c in fail else "NOT RUN" if c in notrun else "PASS"}
                                                     for c in blind_checks(row) if c not in drop]
                        + [{"check": c, "status": "PASS"} for c in extra])
        for row in BLIND_ROWS:
            first, last = blind_checks(row)[0], blind_checks(row)[-1]
            cases = ((checks(row, fail=(last,)), "FAIL", "checks failed: " + last),
                     (checks(row, notrun=(first,)), "NOT RUN", "checks not run"),
                     (checks(row, drop=(last,)), "FAIL", "required check missing or repeated: " + last),
                     (checks(row, extra=(first,)), "FAIL", "required check missing or repeated: " + first),
                     (checks(row, extra=("extra-check",)), "FAIL", "blind report must have exactly %d checks" % len(blind_checks(row))),
                     (dict(default_report(row), checks=[dict(c, check=c["check"].upper()) for c in checks(row)["checks"]]), "FAIL", "required check missing or repeated: " + first))
            for report, status, text in cases:
                with self.subTest(row=row, text=text):
                    self.reports[row] = report
                    rc, out = self.run_tool()
                    self.reports[row] = default_report(row)
                    self.assertEqual(rc, 1, out)
                    self.assertNotIn("OVERALL: PASS", out)
                    self.assertRegex(out, r"(?m)^acceptance %s\s+%s" % (re.escape(row), status))
                    self.assertIn(text, out)

    def test_blind_rows_and_code_review_need_a_protocol_sha256(self):
        for row in BLIND_ROWS + ("code-review",):
            for value in (None, "", "3" * 63, "A" * 64, 7, "3" * 64 + "\n"):
                with self.subTest(row=row, value=value):
                    report = default_report(row)
                    if value is None:
                        del report["protocol_sha256"]
                    else:
                        report["protocol_sha256"] = value
                    self.reports[row] = report
                    rc, out = self.run_tool()
                    self.reports[row] = default_report(row)
                    self.assertEqual(rc, 1, out)
                    self.assertRegex(out, r"(?m)^acceptance %s\s+FAIL" % re.escape(row))
                    self.assertIn("no protocol SHA-256", out)

    def test_blind_report_must_not_be_a_rehearsal(self):
        for row in BLIND_ROWS:
            for value in (True, "false", 0, None, MISSING):
                with self.subTest(row=row, value=value):
                    report = default_report(row)
                    if value is MISSING:
                        del report["rehearsal"]
                    else:
                        report["rehearsal"] = value
                    self.reports[row] = report
                    rc, out = self.run_tool()
                    self.reports[row] = default_report(row)
                    self.assertEqual(rc, 1, out)
                    self.assertRegex(out, r"(?m)^acceptance %s\s+FAIL\s+rehearsal report: rehearsal must be JSON false" % re.escape(row))

    def test_blind_report_must_name_the_candidate_version(self):
        for row in BLIND_ROWS:
            for value in ("1.0.3", V + " ", "v" + V, 103, None, MISSING):
                with self.subTest(row=row, value=value):
                    report = default_report(row)
                    if value is MISSING:
                        del report["version"]
                    else:
                        report["version"] = value
                    self.reports[row] = report
                    rc, out = self.run_tool()
                    self.reports[row] = default_report(row)
                    self.assertEqual(rc, 1, out)
                    self.assertRegex(out, r"(?m)^acceptance %s\s+FAIL\s+report does not name version %s" % (re.escape(row), re.escape(V)))

    def test_blind_upgrade_must_start_from_the_1_0_3_release_image(self):
        cases = [("from_version", v) for v in ("1.0.4", "1.0.2", FROM_VERSION + " ", "v" + FROM_VERSION, 102, None, MISSING)]
        cases += [("from_image", v) for v in (IMAGE + "@" + A, IMAGE + ":1.0.3", IMAGE + "@sha256:" + "0" * 64, FROM_IMAGE.split("@")[1],
                                              FROM_IMAGE.upper(), FROM_IMAGE + " ", None, MISSING)]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                report = default_report(UPGRADE_ROW)
                if value is MISSING:
                    del report[field]
                else:
                    report[field] = value
                self.reports[UPGRADE_ROW] = report
                rc, out = self.run_tool()
                self.reports[UPGRADE_ROW] = default_report(UPGRADE_ROW)
                self.assertEqual(rc, 1, out)
                self.assertRegex(out, r"(?m)^acceptance %s\s+FAIL\s+upgrade report does not start from NetOps %s \(%s\)"
                                 % (re.escape(UPGRADE_ROW), re.escape(FROM_VERSION), re.escape(FROM_IMAGE)))

    def test_install_rows_do_not_need_an_upgrade_origin(self):
        for row in BLIND_INSTALL_ROWS:
            self.assertNotIn("from_version", default_report(row))
        rc, out = self.run_tool()
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"(?m)^acceptance %s\s+PASS" % re.escape(UPGRADE_ROW))

    def test_blind_report_of_another_candidate_fails(self):
        for row in BLIND_ROWS:
            for field, value, text in (("candidate_commit", "b" * 40, "report is not for this commit"),
                                       ("candidate_image", "sha256:" + "9" * 64, "report is not for this image index")):
                with self.subTest(row=row, field=field):
                    self.reports[row] = dict(default_report(row), **{field: value})
                    rc, out = self.run_tool()
                    self.reports[row] = default_report(row)
                    self.assertEqual(rc, 1, out)
                    self.assertRegex(out, r"(?m)^acceptance %s\s+FAIL\s+%s" % (re.escape(row), re.escape(text)))

    def test_tool_signs_only_1_0_4_and_later(self):
        global V
        saved = V
        try:
            for version, expected in (("1.0.3", 1), ("1.0.2", 1), ("0.9.9", 1), ("1.0.4", 0), ("1.0.10", 0), ("1.1.0", 0)):
                with self.subTest(version=version):
                    V = version
                    self.reports = {row: default_report(row) for row in ROWS + list(OPTIONAL_ROWS)}
                    rc, out = self.run_tool()
                    self.assertEqual(rc, expected, out)
                    if expected:
                        self.assertRegex(out, r"(?m)^manifest\s+FAIL\s+this signing tool signs netops 1\.0\.4 and later, not %s" % re.escape(version))
                    else:
                        self.assertIn("OVERALL: PASS", out)
        finally:
            V = saved

    def test_read_json_decodes_utf8_whatever_the_default_encoding(self):
        rc, out, snapdir = self.run_function(
            "[IO.File]::WriteAllBytes('/snap/x.json', [Text.Encoding]::UTF8.GetBytes('{\"d\":\"' + [char]0x10D + '\"}'))\n"
            "$PSDefaultParameterValues['Get-Content:Encoding'] = 'ascii'\n"
            "$o = Read-Json '/snap/x.json'; 'DECODED ' + $o.d.Length + ' ' + [int]$o.d[0]\n")
        try:
            self.assertIn("DECODED 1 269", out)
        finally:
            shutil.rmtree(snapdir)

    def test_single_platform_is_not_enough(self):
        self.reports = {"actions-amd64-blackbox": self.reports["actions-amd64-blackbox"]}
        self.assert_refused("OVERALL: NOT RUN")

    def test_not_run_rows_cannot_be_waived(self):
        self.reports = {r: v for r, v in self.reports.items() if not r.startswith("blind-")}
        rc, out = self.run_tool(extra=("-AcceptNotRun", "blind-install-fedora-amd64"))
        self.assertNotEqual(rc, 0, out)
        self.assertNotIn("OVERALL: PASS", out)

    def test_stale_database_fails(self):
        self.db_built = "2000-01-01T00:00:00Z"
        self.db_descriptor = {"status": {"built": self.db_built}}
        self.db_age = positive = 233000.0
        self.assert_refused("does not match a fresh gate result")

    def test_database_without_build_time_fails(self):
        self.db_descriptor = {}
        self.assert_refused("parseable database build time")

    def test_matches_must_be_an_array(self):
        self.matches_override = "none"
        self.assert_refused("matches is not a JSON array")

    def test_null_matches_fail(self):
        self.build()
        for arch in ARCHES:
            name = "netops-1.0.4-linux-%s-grype.json" % arch
            scan = json.load(open(os.path.join(self.dir, name)))
            scan["matches"] = None
            self.write(name, scan)
        manifest = json.load(open(os.path.join(self.dir, "netops-1.0.4-manifest.json")))
        for arch in ARCHES:
            name = "netops-1.0.4-linux-%s-grype.json" % arch
            manifest["image"]["platforms"][arch]["files"]["scan"]["sha256"] = sha(open(os.path.join(self.dir, name), "rb").read())
        self.write("netops-1.0.4-manifest.json", manifest)
        lines = ["%s  %s" % (sha(open(os.path.join(self.dir, n), "rb").read()), n) for n in sorted(os.listdir(self.dir)) if n != "netops-1.0.4-SHA256SUMS"]
        self.write("netops-1.0.4-SHA256SUMS", "\n".join(lines) + "\n")
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("matches is not a JSON array", out)

    def test_unknown_severity_fails(self):
        self.findings["amd64"] = [dict(FINDING, severity="UNKNOWN", state="not-fixed")]
        self.assert_refused("unknown severity")

    def test_low_finding_needs_assessment_too(self):
        self.findings["arm64"] = [dict(FINDING, id="CVE-9", severity="Low", state="not-fixed")]
        self.assert_refused("not assessed for this exact package version")

    def test_empty_checks_fail(self):
        self.reports["code-review"] = {"checks": [], "protocol_sha256": "3" * 64}
        self.assert_refused("report has no checks")

    def test_unknown_status_fails(self):
        self.reports["codex-cli-e2e"] = {"checks": [{"check": "x", "status": "UNKNOWN"}]}
        self.assert_refused("unknown status UNKNOWN")

    def test_report_without_commit_or_image_fails(self):
        self.reports["blind-upgrade-amd64"] = dict(default_report("blind-upgrade-amd64"), candidate_commit=None)
        self.assert_refused("report is not for this commit")
        self.reports["blind-upgrade-amd64"] = dict(default_report("blind-upgrade-amd64"), candidate_image="sha256:" + "9" * 64)
        self.assert_refused("report is not for this image index")

    def test_unsigned_report_in_directory_fails(self):
        self.skip_from_sums = {"acceptance-blind-upgrade-amd64.json"}
        self.assert_refused("not in the signed checksum list")

    def test_traversal_absolute_and_duplicate_lines_fail(self):
        for line in ("%s  ../outside.json" % ("0" * 64), "%s  /etc/passwd" % ("0" * 64), "%s  netops-1.0.4-manifest.json" % ("0" * 64)):
            self.extra_lines = [line]
            self.assert_refused("checksums")

    def test_symlinked_file_fails(self):
        self.build()
        target = os.path.join(self.dir, "compose.yaml")
        content = open(target).read()
        outside = self.dir + "-outside"
        with open(outside, "w") as stream:
            stream.write(content)
        os.remove(target)
        os.symlink(outside, target)
        rc, out = self.run_tool(build=False)
        os.remove(outside)
        self.assertEqual(rc, 1, out)

    def test_bundle_name_link_fails(self):
        for target in ("compose.yaml", "missing-target"):
            self.build()
            os.symlink(target, os.path.join(self.dir, "netops-1.0.4-SHA256SUMS.sigstore.json"))
            rc, out = self.run_tool(build=False)
            self.assertEqual(rc, 1, out)
            self.assertIn("is a link or reparse point", out)

    def test_linked_sums_and_manifest_fail_before_reading(self):
        for name in ("netops-1.0.4-SHA256SUMS", "netops-1.0.4-manifest.json"):
            self.build()
            path = os.path.join(self.dir, name)
            os.rename(path, path + ".real")
            os.symlink(name + ".real", path)
            rc, out = self.run_tool(build=False)
            self.assertEqual(rc, 1, out)
            self.assertIn(name + " is a link or reparse point", out)

    def test_directory_in_candidate_fails(self):
        self.build()
        os.mkdir(os.path.join(self.dir, "netops-1.0.4-SHA256SUMS.sigstore.json"))
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("is a directory", out)

    def test_other_unlisted_bundle_fails(self):
        self.build()
        self.write("other.sigstore.json", "{}")
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("other.sigstore.json is in the candidate directory but not in the signed checksum list", out)

    def test_existing_bundle_passes_check_but_is_never_overwritten(self):
        self.build()
        self.write("netops-1.0.4-SHA256SUMS.sigstore.json", "{}")
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 0, out)
        rc, out = self.run_tool(check_only=False, stdin="SIGN\n", build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("already exists", out)
        self.assertEqual(self.cosign_log, [])

    def test_manifest_version_with_path_fails(self):
        self.build()
        path = os.path.join(self.dir, "netops-1.0.4-manifest.json")
        manifest = json.load(open(path))
        manifest["version"] = "../" + V
        with open(path, "w") as stream:
            json.dump(manifest, stream)
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("no valid version", out)

    def test_tampered_file_fails(self):
        self.build()
        self.write("netops-1.0.4-linux-arm64.cdx.json", '{"x":1}')
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("SHA-256 differs", out)

    def test_unknown_gate_status_fails(self):
        self.gate_status = "ok"
        self.assert_refused("gate status ok")

    def test_scan_of_other_digest_fails(self):
        self.digests = {"amd64": A, "arm64": B}
        self.build()
        scan_name = "netops-1.0.4-linux-amd64-grype.json"
        scan = json.load(open(os.path.join(self.dir, scan_name)))
        scan["source"]["target"]["userInput"] = IMAGE + "@" + B
        self.write(scan_name, scan)
        manifest = json.load(open(os.path.join(self.dir, "netops-1.0.4-manifest.json")))
        manifest["image"]["platforms"]["amd64"]["files"]["scan"]["sha256"] = sha(open(os.path.join(self.dir, scan_name), "rb").read())
        self.write("netops-1.0.4-manifest.json", manifest)
        lines = ["%s  %s" % (sha(open(os.path.join(self.dir, n), "rb").read()), n) for n in sorted(os.listdir(self.dir)) if n != "netops-1.0.4-SHA256SUMS"]
        self.write("netops-1.0.4-SHA256SUMS", "\n".join(lines) + "\n")
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("raw scan is not of", out)

    def test_fixable_high_in_raw_scan_fails_even_if_gate_says_pass(self):
        self.gate_status = "pass"
        self.findings["arm64"] = [dict(FINDING, severity="High", state="fixed")]
        self.assert_refused("fixable High/Critical")

    def test_assessment_for_other_version_does_not_cover(self):
        self.assessments = [dict(FINDING, version="0.9", exploitable=False, reasoning="r", evidence="e")]
        self.assert_refused("not assessed for this exact package version")

    def test_exploitable_assessment_does_not_cover(self):
        self.assessments = [dict(FINDING, exploitable=True, reasoning="r", evidence="e")]
        self.assert_refused("not assessed")

    def refuse_assessment_values(self, field, values):
        base = self.assessments[0]
        for value in values:
            with self.subTest(field=field, value=value):
                item = {k: v for k, v in base.items() if k != field}
                if value is not MISSING:
                    item[field] = value
                self.assessments = [item]
                self.assert_refused("not assessed for this exact package version")
        self.assessments = [base]

    def test_exploitable_must_be_boolean_false(self):
        self.refuse_assessment_values("exploitable", (0, "false", "False", "0", True, None, MISSING))

    def test_reasoning_must_be_non_blank_string(self):
        self.refuse_assessment_values("reasoning", ("", "   ", None, 5, ["x"], MISSING))

    def test_evidence_must_be_non_blank_string(self):
        self.refuse_assessment_values("evidence", (MISSING, "", "   ", None, 5, ["x"]))

    def test_valid_assessment_covers(self):
        rc, out = self.run_tool()
        self.assertEqual(rc, 0, out)
        for arch in ARCHES:
            self.assertRegex(out, r"(?m)^vulnerabilities %s\s+PASS" % arch)
        self.assertNotIn("not assessed", out)

    def test_swapped_index_fails(self):
        self.set_index([(B, "amd64"), (A, "arm64")])
        self.assert_refused("index platforms differ")

    def test_index_bytes_must_match_digest(self):
        self.build()
        self.registry.index = self.registry.index + b" "
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("index bytes hash to", out)

    def test_private_registry_fails(self):
        self.registry.manifest_status = 401
        self.assert_refused("is the package public")

    def test_unpinned_env_fails(self):
        self.build()
        self.write("env.example", "NETOPS_IMAGE=%s:latest\n" % IMAGE)
        manifest = json.load(open(os.path.join(self.dir, "netops-1.0.4-manifest.json")))
        manifest["release_files"]["env.example"] = sha(open(os.path.join(self.dir, "env.example"), "rb").read())
        self.write("netops-1.0.4-manifest.json", manifest)
        lines = ["%s  %s" % (sha(open(os.path.join(self.dir, n), "rb").read()), n) for n in sorted(os.listdir(self.dir)) if n != "netops-1.0.4-SHA256SUMS"]
        self.write("netops-1.0.4-SHA256SUMS", "\n".join(lines) + "\n")
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("does not pin", out)

    def test_sign_requires_exact_confirmation(self):
        rc, out = self.run_tool(check_only=False, stdin="sign\n")
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.cosign_log, [])

    def test_sign_then_verify(self):
        rc, out = self.run_tool(check_only=False, stdin="SIGN\n")
        self.assertEqual(rc, 0, out)
        snap = re.escape(self.snapdir) + r"/netops-sign-[0-9a-f-]{36}/"
        self.assertRegex(self.cosign_log[0], r"^cosign sign-blob --yes --fulcio-auth-flow=normal --bundle %s%s %s%s$" % (snap, re.escape(BUNDLE), snap, re.escape(SUMS)))
        self.assertRegex(self.cosign_log[1], r"^cosign verify-blob --bundle %s%s --certificate-identity 325383355\+radek-cerny-soukr@users\.noreply\.github\.com --certificate-oidc-issuer https://github\.com/login/oauth %s%s$" % (snap, re.escape(BUNDLE), snap, re.escape(SUMS)))
        self.assertEqual(open(os.path.join(self.dir, BUNDLE), "rb").read(), b"bundle\n")

    def test_no_signing_after_failure(self):
        self.registry.manifest_status = 404
        rc, out = self.run_tool(check_only=False, stdin="SIGN\n")
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.cosign_log, [])

    def validated_sums(self):
        return sha(open(os.path.join(self.dir, SUMS), "rb").read())

    def test_b1_cosign_signs_the_snapshot_copy_of_the_validated_sums(self):
        self.build()
        validated = self.validated_sums()
        rc, out = self.run_tool(check_only=False, stdin="SIGN\n", build=False)
        self.assertEqual(rc, 0, out)
        self.assertEqual([entry[0] for entry in self.cosign_sha], ["sign-blob", "verify-blob"], self.cosign_sha)
        for verb, digest, path in self.cosign_sha:
            self.assertFalse(path.startswith("/c/"), (verb, path))
            self.assertTrue(path.startswith(self.snapdir + "/netops-sign-"), (verb, path))
            self.assertEqual(digest, validated, verb)
        self.assertIn("Signed and verified the validated snapshot of %s (SHA-256 %s). Bundle: /c/%s" % (SUMS, validated, BUNDLE), out)

    def test_b1_change_of_the_original_after_sign_is_not_signed(self):
        self.build()
        validated = self.validated_sums()
        self.cosign_tamper = True
        rc, out = self.run_tool(check_only=False, stdin="SIGN\n", build=False)
        self.assertNotEqual(self.validated_sums(), validated)
        self.assertEqual([(entry[0], entry[1]) for entry in self.cosign_sha], [("sign-blob", validated), ("verify-blob", validated)], self.cosign_sha)
        self.assertEqual(rc, 1, out)
        self.assertIn("Signed the validated snapshot of %s (SHA-256 %s), but /c/%s no longer matches it." % (SUMS, validated, SUMS), out)
        self.assertNotIn("Signed and verified", out)
        self.assertFalse(os.path.lexists(os.path.join(self.dir, BUNDLE)))

    def test_b1_symlink_in_candidate_fails_without_signing(self):
        self.build()
        os.symlink("compose.yaml", os.path.join(self.dir, "extra.json"))
        rc, out = self.run_tool(check_only=False, stdin="SIGN\n", build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("extra.json is a link or reparse point", out)
        self.assertEqual(self.cosign_log, [])

    def test_b1_subdirectory_in_candidate_fails(self):
        self.build()
        os.mkdir(os.path.join(self.dir, "sub"))
        with open(os.path.join(self.dir, "sub", "inner.json"), "w") as stream:
            stream.write("{}")
        rc, out = self.run_tool(check_only=False, stdin="SIGN\n", build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("sub is a directory", out)
        self.assertEqual(self.cosign_log, [])

    def test_b1_non_regular_file_in_candidate_fails_before_reading(self):
        self.build()
        os.mkfifo(os.path.join(self.dir, "pipe"))
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("pipe is empty or not a regular file", out)

    def test_v3_failed_sign_blob_refuses_and_leaves_no_bundle(self):
        self.cosign_sign_rc = 1
        rc, out = self.run_tool(check_only=False, stdin="SIGN\n")
        self.assertEqual(rc, 1, out)
        self.assertIn("cosign sign-blob failed", out)
        self.assertEqual(len(self.cosign_log), 1, self.cosign_log)
        self.assertFalse(os.path.lexists(os.path.join(self.dir, BUNDLE)))

    def test_v3_failed_verify_blob_refuses_and_leaves_no_bundle(self):
        self.cosign_verify_rc = 1
        rc, out = self.run_tool(check_only=False, stdin="SIGN\n")
        self.assertEqual(rc, 1, out)
        self.assertIn("Verification of the new signature failed", out)
        self.assertEqual(len(self.cosign_log), 2, self.cosign_log)
        self.assertFalse(os.path.lexists(os.path.join(self.dir, BUNDLE)))

    def test_v1_image_name_must_be_the_repository(self):
        for image in ("ghcr.io/evil/netops", "ghcr.io/radek-cerny-soukr/netops-evil", "ghcr.io/Radek-Cerny-Soukr/netops", "ghcr.io/radek-cerny-soukr/netops/x"):
            with self.subTest(image=image):
                self.image = image
                out = self.assert_refused("is not ghcr.io/radek-cerny-soukr/netops")
                self.assertRegex(out, r"(?m)^registry\s+FAIL")

    def test_v2_acceptance_row_differing_in_case_is_not_the_required_row(self):
        row = "actions-amd64-blackbox"

        def upper(acceptance, arch):
            for entry in acceptance["reports"]:
                if entry["row"] == row:
                    entry["row"] = row.upper()
        self.patches = {"acceptance": upper}
        out = self.assert_refused("OVERALL: NOT RUN")
        self.assertRegex(out, r"(?m)^acceptance %s\s+NOT RUN\s+no report" % row)

    def test_v2_assessment_differing_in_case_does_not_cover(self):
        for field, value in (("id", "cve-1"), ("package", "LIBX"), ("type", "APK")):
            with self.subTest(field=field):
                self.assessments = [dict(FINDING, exploitable=False, reasoning="unreachable", evidence="not imported", **{field: value})]
                self.assert_refused("not assessed for this exact package version")

    def test_d1_trailing_newline_fails(self):
        cases = (("commit", None, "repository or commit invalid"),
                 ("version", lambda m, a: m.update(version=V + "\n"), "no valid version"),
                 ("index digest", lambda m, a: m["image"].update(index_digest=m["image"]["index_digest"] + "\n"), "index digest invalid"),
                 ("platform digest", lambda m, a: m["image"]["platforms"]["amd64"].update(digest=A + "\n"), "platform amd64 missing or malformed"))
        for label, patch, text in cases:
            with self.subTest(field=label):
                self.commit = COMMIT + "\n" if patch is None else COMMIT
                self.patches = {} if patch is None else {"manifest": patch}
                self.assert_refused(text)

    def test_b1_bundle_appearing_in_the_original_is_never_overwritten(self):
        self.cosign_race_bundle = True
        rc, out = self.run_tool(check_only=False, stdin="SIGN\n")
        self.assertEqual(rc, 1, out)
        self.assertIn("already exists", out)
        self.assertEqual(open(os.path.join(self.dir, BUNDLE), "rb").read(), b"foreign\n")

    def test_b1_check_only_uses_a_private_snapshot_that_is_removed(self):
        self.build()
        validated = self.validated_sums()
        files = sorted(os.listdir(self.dir))
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.cosign_log, [])
        self.assertEqual(len(self.registry.seen), 1, self.registry.seen)
        name, mode, copied, sums = self.registry.seen[0]
        self.assertRegex(name, r"^netops-sign-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        self.assertEqual(mode, 0o700)
        self.assertEqual(copied, files)
        self.assertEqual(sums, validated)

    def test_b1_snapshot_directory_must_be_new(self):
        rc, out, snapdir = self.run_function(
            "$fresh = '/snap/netops-sign-fresh'; New-SnapshotDir $fresh; 'CREATED ' + (Get-Item -LiteralPath $fresh).UnixMode\n"
            "$taken = '/snap/netops-sign-taken'; [void][IO.Directory]::CreateDirectory($taken); [IO.File]::WriteAllText($taken + '/sentinel', 'x')\n"
            "try { New-SnapshotDir $taken; 'REUSED' } catch { 'REFUSED ' + $_.Exception.Message }\n")
        try:
            self.assertIn("CREATED drwx------", out)
            self.assertEqual(os.lstat(os.path.join(snapdir, "netops-sign-fresh")).st_mode & 0o7777, 0o700)
            self.assertEqual(os.listdir(os.path.join(snapdir, "netops-sign-fresh")), [])
            self.assertIn("REFUSED snapshot directory already exists: /snap/netops-sign-taken", out)
            self.assertNotIn("REUSED", out)
            self.assertEqual(os.listdir(os.path.join(snapdir, "netops-sign-taken")), ["sentinel"])
        finally:
            shutil.rmtree(snapdir)

    def test_b1_private_dir_guard_rejects_wrong_mode_or_owner(self):
        rc, out, snapdir = self.run_function(
            "$good = '/snap/good'; [void][IO.Directory]::CreateDirectory($good, [IO.UnixFileMode]'UserRead, UserWrite, UserExecute'); 'GOOD ' + (Test-PrivateDir $good)\n"
            "$wide = '/snap/wide'; [void][IO.Directory]::CreateDirectory($wide, [IO.UnixFileMode]'UserRead, UserWrite, UserExecute, GroupRead, GroupExecute'); 'WIDE ' + (Test-PrivateDir $wide)\n"
            "$foreign = '/snap/foreign'; [void][IO.Directory]::CreateDirectory($foreign, [IO.UnixFileMode]'UserRead, UserWrite, UserExecute'); chown 4321:4321 $foreign; 'FOREIGN ' + (Test-PrivateDir $foreign)\n",
            user="0:0")
        try:
            self.assertIn("GOOD True", out)
            self.assertIn("WIDE False", out)
            self.assertIn("FOREIGN False", out)
            self.assertEqual(os.lstat(os.path.join(snapdir, "foreign")).st_uid, 4321)
        finally:
            # Must reach the files chown'd to a foreign uid above; cleanup rc is checked below
            # so a stuck/denied cleanup fails the test instead of looking green.
            cleanup = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", snapdir + ":/snap:Z", PWSH,
                                      "rm", "-rf", "/snap/good", "/snap/wide", "/snap/foreign"],
                                      capture_output=True, text=True, timeout=240)
            shutil.rmtree(snapdir)
            self.assertEqual(cleanup.returncode, 0, cleanup.stdout + cleanup.stderr)

    def test_iso_build_time_with_day_over_12_passes_under_cs_and_en_culture(self):
        self.assertEqual(self.db_built, "2026-10-15T00:00:00Z")
        for culture, ambient in (("cs-CZ", "False"), ("en-US", "True")):
            with self.subTest(culture=culture):
                rc, out = self.run_tool(culture=culture)
                self.assertIn("CULTURE " + culture, out)
                self.assertIn("AMBIENT_TRYPARSE " + ambient, out)
                self.assertEqual(rc, 0, out)
                for arch in ARCHES:
                    self.assertRegex(out, r"(?m)^vulnerabilities %s\s+PASS.*database 2026-10-15T00:00:00Z" % arch)

    def test_build_time_must_be_a_json_string(self):
        values = (("boolean", True), ("number", 15), ("array", [self.db_built]), ("object", {"built": self.db_built}), ("null", None))
        for field, text in (("raw", "parseable database build time"), ("gate", "does not match a fresh gate result")):
            for label, value in values:
                with self.subTest(field=field, type=label):
                    self.db_descriptor = {"status": {"built": self.db_built}}
                    self.patches = {}
                    if field == "raw":
                        self.db_descriptor = {"status": {"built": value}}
                    else:
                        self.patches = {"gate": lambda gate, arch, v=value: gate.update(database_built=v)}
                    rc, out = self.run_tool(culture="cs-CZ")
                    self.assertIn("CULTURE cs-CZ", out)
                    self.assertEqual(rc, 1, out)
                    self.assertIn(text, out)

    def test_build_time_comparison_with_gate_is_lexical(self):
        self.patches = {"gate": lambda gate, arch: gate.update(database_built="2026-10-15T00:00:00+00:00")}
        rc, out = self.run_tool(culture="cs-CZ")
        self.assertEqual(rc, 1, out)
        self.assertIn("does not match a fresh gate result", out)

    def test_build_time_without_zone_fails(self):
        self.db_built = "2026-10-15T00:00:00"
        self.db_descriptor = {"status": {"built": self.db_built}}
        rc, out = self.run_tool(culture="en-US")
        self.assertEqual(rc, 1, out)
        self.assertIn("parseable database build time", out)

    def test_build_time_keeps_status_then_db_precedence(self):
        cases = (("status first", {"status": {"built": self.db_built}, "built": "1999-01-01T00:00:00Z"}, 0),
                 ("fallback to db", {"status": {"built": None}, "built": self.db_built}, 0),
                 ("db only", {"built": self.db_built}, 0),
                 ("status wins even if the gate names db", {"status": {"built": "2026-10-14T00:00:00Z"}, "built": self.db_built}, 1))
        for label, descriptor, expected in cases:
            with self.subTest(case=label):
                self.db_descriptor = descriptor
                rc, out = self.run_tool(culture="cs-CZ")
                self.assertEqual(rc, expected, out)

    def test_non_string_identity_fields_fail(self):
        for label, kind, change, text in NON_STRING_CASES:
            with self.subTest(field=label):
                self.apply_case(kind, change)
                rc, out = self.run_tool()
                self.assertEqual(rc, 1, out)
                self.assertNotIn("OVERALL: PASS", out)
                if text:
                    self.assertIn(text, out)

    def apply_case(self, kind, change):
        self.patches = {}
        self.reports = {row: default_report(row) for row in ROWS + list(OPTIONAL_ROWS)}
        if kind == "report":
            self.reports["blind-install-debian-amd64"].update(change)
        else:
            self.patches = {kind: lambda content, arch: change(content) if arch in (None, "amd64") else None}


def setter(*path):
    def outer(value):
        def inner(content):
            target = content
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
        return inner
    return outer


def scan_target_true(scan):
    scan["source"]["target"]["userInput"] = True
    scan["source"]["target"]["repoDigests"] = [True]


NON_STRING_CASES = (
    ("manifest.schema true", "manifest", setter("schema")(True), "unknown schema, product or version"),
    ("manifest.product true", "manifest", setter("product")(True), "unknown schema, product or version"),
    ("manifest.version list", "manifest", setter("version")([V]), "no valid version"),
    ("manifest.source.repository true", "manifest", setter("source", "repository")(True), "repository or commit invalid"),
    ("manifest.source.commit list", "manifest", setter("source", "commit")([COMMIT]), "repository or commit invalid"),
    ("manifest.image.name true", "manifest", setter("image", "name")(True), None),
    ("manifest.image.index_digest list", "manifest", lambda m: m["image"].update(index_digest=[m["image"]["index_digest"]]), "index digest invalid"),
    ("manifest platform digest list", "manifest", setter("image", "platforms", "amd64", "digest")([A]), "platform amd64 missing or malformed"),
    ("manifest.release_files compose.yaml true", "manifest", setter("release_files", "compose.yaml")(True), "release_files.compose.yaml differs from the checksum list"),
    ("acceptance.schema true", "acceptance", setter("schema")(True), "acceptance manifest is for another candidate"),
    ("acceptance.candidate_commit true", "acceptance", setter("candidate_commit")(True), "acceptance manifest is for another candidate"),
    ("acceptance.candidate_image true", "acceptance", setter("candidate_image")(True), "acceptance manifest is for another candidate"),
    ("report.candidate_commit true", "report", {"candidate_commit": True}, "report is not for this commit"),
    ("report.candidate_image true", "report", {"candidate_image": True}, "report is not for this image index"),
    ("gate.database_built true", "gate", setter("database_built")(True), "does not match a fresh gate result"),
    ("scan target true", "scan", scan_target_true, "raw scan is not of"),
)


class _ParallelResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seen = []

    def startTest(self, test):
        self.seen.append(test._testMethodName)
        super().startTest(test)


def _run_parallel_test(name):
    log = io.StringIO()
    with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
        result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=_ParallelResult).run(
            unittest.TestSuite([SignTool(name)]))
    counts = (result.testsRun, len(result.failures), len(result.errors), len(result.skipped),
              len(result.expectedFailures), len(result.unexpectedSuccesses))
    return result.seen, counts, log.getvalue()


def _suite_tests(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _suite_tests(test)
        else:
            yield test


def _parallel_main(workers):
    started = time.monotonic()
    discovered = list(_suite_tests(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])))
    if any(type(test) is not SignTool for test in discovered):
        raise SystemExit("Parallel signing tests support only SignTool; use NETOPS_SIGN_TEST_WORKERS=1")
    names = [test._testMethodName for test in discovered]
    if len(names) != len(set(names)):
        raise SystemExit("Parallel signing test discovery contains duplicate test IDs")
    seen, counts = [], [0] * 6
    with concurrent.futures.ProcessPoolExecutor(
            max_workers=workers, mp_context=multiprocessing.get_context("spawn")) as pool:
        pending = {pool.submit(_run_parallel_test, name): name for name in names}
        for future in concurrent.futures.as_completed(pending):
            name = pending[future]
            try:
                actual, measured, log = future.result()
            except Exception:
                counts[2] += 1
                for line in traceback.format_exc().splitlines():
                    print("[%s] %s" % (name, line), flush=True)
                continue
            seen.extend(actual)
            counts = [a + b for a, b in zip(counts, measured)]
            for line in log.splitlines():
                print("[%s] %s" % (name, line), flush=True)
    complete = bool(names) and sorted(seen) == sorted(names) and counts[0] == len(names)
    failed = not complete or any(counts[i] for i in (1, 2, 3, 5))
    if not complete:
        print("Incomplete test coverage: expected %r; observed %r" % (names, seen))
    print("\nRan %d tests in %.3fs\n" % (counts[0], time.monotonic() - started))
    labels = ("failures", "errors", "skipped", "expected failures", "unexpected successes")
    details = ", ".join("%s=%d" % (label, n) for label, n in zip(labels, counts[1:]) if n)
    print("FAILED (%s)" % (details or "incomplete coverage") if failed else
          ("OK (%s)" % details if details else "OK"), flush=True)
    return int(failed)


if __name__ == "__main__":
    requested = os.environ.get("NETOPS_SIGN_TEST_WORKERS", "1")
    if requested not in ("1", "2", "3", "4"):
        raise SystemExit("NETOPS_SIGN_TEST_WORKERS must be 1, 2, 3 or 4")
    if len(sys.argv) > 1 or requested == "1":
        unittest.main()
    else:
        raise SystemExit(_parallel_main(int(requested)))
