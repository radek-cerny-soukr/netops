import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import scan_gate

NOW = datetime(2026, 10, 15, 0, 0, tzinfo=timezone.utc)


def report(matches, built="2026-10-14T20:00:00Z", nested=True):
    db = {"status": {"built": built}} if nested else {"built": built}
    return {"descriptor": {"db": db}, "matches": matches}


def match(severity, state, vid="CVE-2026-0001", name="libx"):
    return {"vulnerability": {"id": vid, "severity": severity, "fix": {"state": state, "versions": ["2"] if state == "fixed" else []}},
            "artifact": {"name": name, "version": "1", "type": "deb"}}


class Evaluate(unittest.TestCase):
    def test_clean_report_passes(self):
        self.assertEqual(scan_gate.evaluate(report([]), NOW)["status"], "pass")

    def test_low_and_negligible_need_assessment(self):
        r = scan_gate.evaluate(report([match("Low", "fixed"), match("Negligible", "not-fixed", "CVE-2")]), NOW)
        self.assertEqual(r["status"], "needs-assessment")
        self.assertEqual(r["counts"], {"Low": 1, "Negligible": 1})
        self.assertEqual(len(r["assessment_required"]), 2)

    def test_unknown_severity_or_incomplete_finding_is_unknown(self):
        self.assertEqual(scan_gate.evaluate(report([match("UNKNOWN", "fixed")]), NOW)["status"], "unknown")
        broken = match("Medium", "fixed")
        del broken["artifact"]["version"]
        self.assertEqual(scan_gate.evaluate(report([broken]), NOW)["status"], "unknown")

    def test_medium_is_never_automatic_pass(self):
        for state in ("fixed", "not-fixed", "wont-fix", None):
            r = scan_gate.evaluate(report([match("Medium", state)]), NOW)
            self.assertEqual(r["status"], "needs-assessment", state)
            self.assertEqual(r["assessment_required"][0]["severity"], "Medium")

    def test_fixable_high_fails(self):
        r = scan_gate.evaluate(report([match("High", "fixed")]), NOW)
        self.assertEqual(r["status"], "fail")
        self.assertEqual(r["fixable_blocking"][0]["fix_versions"], ["2"])

    def test_fixed_unavailable_requires_explicit_evidence_and_assessment(self):
        assessment = {"id": "CVE-2026-0001", "package": "libx", "version": "1", "type": "deb",
                      "exploitable": False, "reasoning": "No exposure", "evidence": "Code review"}
        finding = report([match("High", "fixed")])
        self.assertEqual(scan_gate.evaluate(finding, NOW, [assessment])["status"], "fail")
        assessment.update(fixed_version_not_released=True, fix_unavailable_evidence="https://example.org/fix",
                          fix_unavailable_versions=["2"], fix_unavailable_checked=NOW.date().isoformat())
        result = scan_gate.evaluate(finding, NOW, [assessment])
        self.assertEqual(result["status"], "needs-assessment")
        self.assertEqual(len(result["assessment_required"]), 1)
        self.assertEqual(scan_gate.evaluate(report([match("High", "not-fixed")]), NOW, [assessment])["status"], "needs-assessment")
        assessment["fix_unavailable_evidence"] = ""
        self.assertEqual(scan_gate.evaluate(finding, NOW, [assessment])["status"], "fail")

    def unavailable_assessment(self):
        return {"id": "CVE-2026-0001", "package": "libx", "version": "1", "type": "deb",
                "exploitable": False, "reasoning": "No exposure", "evidence": "Code review",
                "fixed_version_not_released": True, "fix_unavailable_versions": ["2"],
                "fix_unavailable_checked": NOW.date().isoformat(),
                "fix_unavailable_evidence": "https://example.org/fix"}

    def test_invalid_unavailable_fix_metadata_blocks(self):
        changes = {
            "fix_unavailable_evidence": (None, "", "https://", "https:// ", "https:///fix", "http://example.org/fix", "https://["),
            "fix_unavailable_checked": (None, "", "invalid", "2026-02-30", "20261015", "2026-10-15T00:00:00Z",
                                        (NOW.date() - timedelta(days=15)).isoformat(),
                                        (NOW.date() + timedelta(days=1)).isoformat()),
            "fix_unavailable_versions": (None, [], ["3"], ["2", "3"], "2"),
            "id": ("CVE-OTHER",), "package": ("other",), "version": ("0",), "type": ("apk",),
            "exploitable": (True, None, "false", 0),
            "fixed_version_not_released": (False, "true", 1),
        }
        for field, values in changes.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    assessment = self.unavailable_assessment()
                    assessment[field] = value
                    self.assertEqual(scan_gate.evaluate(report([match("High", "fixed")]), NOW,
                                                        [assessment])["status"], "fail")
            with self.subTest(missing=field):
                assessment = self.unavailable_assessment()
                del assessment[field]
                self.assertEqual(scan_gate.evaluate(report([match("Critical", "fixed")]), NOW,
                                                    [assessment])["status"], "fail")

    def test_unavailable_fix_date_boundary(self):
        for days in (0, 14, 15):
            with self.subTest(days=days):
                assessment = self.unavailable_assessment()
                assessment["fix_unavailable_checked"] = (NOW.date() - timedelta(days=days)).isoformat()
                self.assertEqual(scan_gate.evaluate(report([match("High", "fixed")]), NOW,
                                                    [assessment])["status"],
                                 "needs-assessment" if days <= 14 else "fail")

    def test_new_scan_fix_version_invalidates_assessment(self):
        finding = match("High", "fixed")
        finding["vulnerability"]["fix"]["versions"] = ["3"]
        self.assertEqual(scan_gate.evaluate(report([finding]), NOW,
                                            [self.unavailable_assessment()])["status"], "fail")

    def test_fixed_finding_without_versions_still_blocks(self):
        for versions in (None, [], "2"):
            with self.subTest(versions=versions):
                finding = match("High", "fixed")
                finding["vulnerability"]["fix"]["versions"] = versions
                for assessments in ([], [self.unavailable_assessment()]):
                    self.assertEqual(scan_gate.evaluate(report([finding]), NOW, assessments)["status"], "fail")

    def test_fixable_critical_fails_even_with_unfixed(self):
        r = scan_gate.evaluate(report([match("Critical", "fixed"), match("High", "not-fixed", "CVE-2")]), NOW)
        self.assertEqual(r["status"], "fail")

    def test_unfixed_high_is_never_pass(self):
        for state in ("not-fixed", "wont-fix", "unknown", None):
            r = scan_gate.evaluate(report([match("High", state)]), NOW)
            self.assertEqual(r["status"], "needs-assessment", state)

    def test_missing_database_time_is_unknown(self):
        self.assertEqual(scan_gate.evaluate({"descriptor": {}, "matches": []}, NOW)["status"], "unknown")

    def test_flat_database_layout_is_read(self):
        self.assertEqual(scan_gate.evaluate(report([], nested=False), NOW)["status"], "pass")

    def test_stale_database_is_unknown(self):
        old = (NOW - timedelta(hours=49)).isoformat()
        self.assertEqual(scan_gate.evaluate(report([], built=old), NOW)["status"], "unknown")

    def test_future_database_is_unknown(self):
        future = (NOW + timedelta(hours=3)).isoformat()
        self.assertEqual(scan_gate.evaluate(report([], built=future), NOW)["status"], "unknown")

    def test_missing_matches_is_unknown(self):
        self.assertEqual(scan_gate.evaluate({"descriptor": {"db": {"built": "2026-10-14T20:00:00Z"}}}, NOW)["status"], "unknown")


class Command(unittest.TestCase):
    def run_gate(self, content):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.json")
            with open(path, "w") as stream:
                stream.write(content)
            out = os.path.join(tmp, "o.json")
            summary = os.path.join(tmp, "s.md")
            proc = subprocess.run([sys.executable, scan_gate.__file__, path, "--name", "t", "--output", out, "--summary", summary],
                                  capture_output=True, text=True)
            with open(out) as stream, open(summary) as text:
                return proc.returncode, json.load(stream), text.read()

    def fresh(self, matches):
        return json.dumps(report(matches, built=datetime.now(timezone.utc).isoformat()))

    def test_rc_pass(self):
        self.assertEqual(self.run_gate(self.fresh([]))[0], 0)

    def test_rc_fail(self):
        rc, result, summary = self.run_gate(self.fresh([match("High", "fixed")]))
        self.assertEqual((rc, result["status"]), (1, "fail"))
        self.assertIn("CVE-2026-0001", summary)

    def test_rc_needs_assessment_is_zero_but_recorded(self):
        rc, result, summary = self.run_gate(self.fresh([match("Critical", "not-fixed")]))
        self.assertEqual((rc, result["status"]), (0, "needs-assessment"))
        self.assertIn("written assessment required", summary)

    def test_rc_malformed_json_is_unknown(self):
        rc, result, _ = self.run_gate("{not json")
        self.assertEqual((rc, result["status"]), (2, "unknown"))

    def test_rc_empty_file_is_unknown(self):
        self.assertEqual(self.run_gate("")[0], 2)


class DailyScan(unittest.TestCase):
    """Run both workflow commands against the supplied 2026-11-12 findings."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        release = Path(scan_gate.__file__).resolve().parent
        for name in ("scan_gate.py", "assessment_check.py", "vulnerability-assessments.json"):
            shutil.copyfile(release / name, self.directory / name)
        # Frozen 17-entry assessment list from released 1.0.7, commit d803dde.
        self.asset = self.directory / "netops-1.0.7-vulnerability-assessments.json"
        shutil.copyfile(release / "tests/fixtures/assessments-1.0.7.json", self.asset)
        self.repository = self.directory / "vulnerability-assessments.json"
        self.records = json.loads(self.repository.read_text(encoding="utf-8"))
        identities = [("CVE-2025-15367", "python", "3.14.10", "binary"),
                      ("CVE-2026-103995", "python", "3.14.10", "binary"),
                      ("CVE-2026-116566", "python", "3.14.10", "binary"),
                      ("CVE-2026-119170", "python", "3.14.10", "binary")]
        identities += [("CVE-2025-60876", package, "1.37.0-r31", "apk")
                       for package in ("busybox", "busybox-binsh", "ssl_client")]
        identities += [("CVE-2026-%s" % number, "sqlite-libs", "3.53.4-r0", "apk")
                       for number in (*range(119371, 119380), 119586, 119591)]
        findings = []
        for vid, package, version, kind in identities:
            finding = match("High", "fixed" if vid == "CVE-2026-119170" else "not-fixed", vid, package)
            finding["artifact"].update(version=version, type=kind)
            finding["vulnerability"]["fix"]["versions"] = ["3.14.11"] if vid == "CVE-2026-119170" else []
            findings.append(finding)
        self.report = self.directory / "grype.json"
        self.report.write_text(json.dumps(report(findings, built=datetime.now(timezone.utc).isoformat())), encoding="utf-8")

    def run_daily(self, arch, scan_asset=False, check_asset=True):
        gate_path = self.directory / ("gate-%s.json" % arch)
        # The daily workflow passes the asset only to assessment_check.
        # Exercise optional scan_gate --assessments as well.
        asset_args = ["--assessments", str(self.asset)]
        scan = subprocess.run([sys.executable, "-B", str(self.directory / "scan_gate.py"), str(self.report),
                               "--name", "v1.0.7 linux/" + arch, "--output", str(gate_path),
                               *(asset_args if scan_asset else [])], cwd=self.directory.parent,
                              text=True, capture_output=True)
        check = subprocess.run([sys.executable, "-B", str(self.directory / "assessment_check.py"), str(gate_path),
                                *(asset_args if check_asset else [])], cwd=self.directory.parent,
                               text=True, capture_output=True)
        return scan, check, json.loads(gate_path.read_text(encoding="utf-8"))

    def test_both_architectures_pass_with_old_asset_and_repository_overlay(self):
        old = json.loads(self.asset.read_text(encoding="utf-8"))
        self.assertEqual(len(old), 17)
        self.assertNotIn("CVE-2026-119170", {a["id"] for a in old})
        for arch in ("amd64", "arm64"):
            for scan_asset in (False, True):
                with self.subTest(arch=arch, scan_asset=scan_asset):
                    scan, check, gate = self.run_daily(arch, scan_asset=scan_asset)
                    self.assertEqual(scan.returncode, 0, scan.stdout + scan.stderr)
                    self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
                    self.assertEqual(gate["status"], "needs-assessment")
                    self.assertEqual(len(gate["assessment_required"]), 18)
                    self.assertEqual(gate["fixable_blocking"], [])
                    self.assertEqual(gate["name"], "v1.0.7 linux/" + arch)

    def test_without_repository_119170_daily_scan_fails(self):
        self.repository.write_text(json.dumps([a for a in self.records if a["id"] != "CVE-2026-119170"]), encoding="utf-8")
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                scan, check, gate = self.run_daily(arch)
                self.assertEqual(scan.returncode, 1)
                self.assertEqual(check.returncode, 1)
                self.assertEqual(gate["status"], "fail")
                self.assertEqual(len(gate["assessment_required"]), 17)
                self.assertEqual(gate["fixable_blocking"][0]["id"], "CVE-2026-119170")

    def test_released_fix_still_blocks_even_with_nonexploitable_assessment(self):
        for assessment in self.records:
            if assessment["id"] == "CVE-2026-119170":
                assessment["fixed_version_not_released"] = False
        self.repository.write_text(json.dumps(self.records), encoding="utf-8")
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                scan, check, gate = self.run_daily(arch, scan_asset=True)
                self.assertEqual(scan.returncode, 1)
                self.assertEqual(check.returncode, 1)
                self.assertEqual(gate["fixable_blocking"][0]["fix_versions"], ["3.14.11"])

    def test_no_release_asset_needed(self):
        self.asset.unlink()
        for scan_asset, check_asset in ((False, False), (True, True)):
            with self.subTest(scan_asset=scan_asset, check_asset=check_asset):
                scan, check, gate = self.run_daily("amd64", scan_asset=scan_asset, check_asset=check_asset)
                self.assertEqual(scan.returncode, 0, scan.stdout + scan.stderr)
                self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
                self.assertEqual(len(gate["assessment_required"]), 18)

    def test_asset_only_record_survives_merge_and_repository_overrides_stale_record(self):
        # Remove a repository assessment so that this finding must use the asset.
        self.records = [a for a in self.records if a["id"] != "CVE-2026-119591"]
        self.repository.write_text(json.dumps(self.records), encoding="utf-8")
        old = json.loads(self.asset.read_text(encoding="utf-8"))
        for assessment in old:
            if assessment["id"] == "CVE-2026-103995":
                assessment["exploitable"] = True
        self.asset.write_text(json.dumps(old), encoding="utf-8")
        scan, check, _ = self.run_daily("amd64", scan_asset=True)
        self.assertEqual(scan.returncode, 0, scan.stdout + scan.stderr)
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)


if __name__ == "__main__":
    unittest.main()
