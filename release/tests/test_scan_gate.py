import json
import os
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
            with open(out) as stream:
                return proc.returncode, json.load(stream), open(summary).read()

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


if __name__ == "__main__":
    unittest.main()
