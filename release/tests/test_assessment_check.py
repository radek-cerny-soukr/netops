import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import assessment_check

OK = {"id": "CVE-1", "package": "libx", "version": "1.0", "type": "apk", "exploitable": False, "reasoning": "unreachable", "evidence": "reviewed unreachable source path"}
REQ = {"id": "CVE-1", "package": "libx", "version": "1.0", "type": "apk"}


class AssessmentCheck(unittest.TestCase):
    def test_pass_needs_nothing(self):
        self.assertEqual(assessment_check.check({"status": "pass"}, [])[0], 0)

    def test_covered_findings_pass(self):
        gate = {"status": "needs-assessment", "assessment_required": [REQ]}
        self.assertEqual(assessment_check.check(gate, [OK])[0], 0)

    def test_new_finding_fails(self):
        gate = {"status": "needs-assessment", "assessment_required": [REQ, {"id": "CVE-2", "package": "liby", "version": "2", "type": "apk"}]}
        rc, message = assessment_check.check(gate, [OK])
        self.assertEqual(rc, 1)
        self.assertIn("CVE-2|liby|2|apk", message)

    def test_exploitable_or_unreasoned_assessment_does_not_cover(self):
        gate = {"status": "needs-assessment", "assessment_required": [REQ]}
        self.assertEqual(assessment_check.check(gate, [dict(OK, exploitable=True)])[0], 1)
        self.assertEqual(assessment_check.check(gate, [dict(OK, exploitable=0)])[0], 1)
        self.assertEqual(assessment_check.check(gate, [dict(OK, reasoning="")])[0], 1)

    def test_missing_or_invalid_evidence_does_not_cover(self):
        gate = {"status": "needs-assessment", "assessment_required": [REQ]}
        missing = dict(OK)
        del missing["evidence"]
        self.assertEqual(assessment_check.check(gate, [missing])[0], 1)
        for value in (None, "", " \t\n", 0, False, [], {}, ["source"], {"source": "reviewed"}):
            with self.subTest(value=value):
                self.assertEqual(assessment_check.check(gate, [dict(OK, evidence=value)])[0], 1)

    def test_nonstring_or_blank_reasoning_does_not_cover(self):
        gate = {"status": "needs-assessment", "assessment_required": [REQ]}
        for value in (None, "", " \t\n", 0, True, [], {}, ["unreachable"], {"reason": "unreachable"}):
            with self.subTest(value=value):
                self.assertEqual(assessment_check.check(gate, [dict(OK, reasoning=value)])[0], 1)

    def test_same_cve_other_package_does_not_cover(self):
        gate = {"status": "needs-assessment", "assessment_required": [dict(REQ, package="libz")]}
        self.assertEqual(assessment_check.check(gate, [OK])[0], 1)

    def test_other_version_or_type_does_not_cover(self):
        for change in ({"version": "1.1"}, {"type": "binary"}):
            gate = {"status": "needs-assessment", "assessment_required": [dict(REQ, **change)]}
            self.assertEqual(assessment_check.check(gate, [OK])[0], 1, change)

    def test_fail_and_unknown_fail(self):
        for status in ("fail", "unknown", None):
            self.assertEqual(assessment_check.check({"status": status}, [OK])[0], 1)


class LoadAssessments(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.repository = self.directory / "vulnerability-assessments.json"
        self.asset = self.directory / "released.json"
        self.repository.write_text(json.dumps([OK]), encoding="utf-8")
        override = patch.object(assessment_check, "__file__", str(self.directory / "assessment_check.py"))
        override.start()
        self.addCleanup(override.stop)

    def test_repository_only_and_missing_optional_asset(self):
        self.assertEqual(assessment_check.load_assessments(), [OK])
        self.assertEqual(assessment_check.load_assessments(self.asset), [OK])

    def test_merge_preserves_asset_only_records_and_repository_wins(self):
        other = dict(OK, id="CVE-2")
        other_package = dict(OK, package="liby")
        self.asset.write_text(json.dumps([dict(OK, evidence="old"), other, other_package]), encoding="utf-8")
        records = assessment_check.load_assessments(self.asset)
        self.assertEqual(records, [OK, other, other_package])

    def test_override_is_by_cve_package_even_when_version_or_type_changed(self):
        for changes in ({"version": "0.9"}, {"type": "binary"}):
            self.asset.write_text(json.dumps([dict(OK, **changes)]), encoding="utf-8")
            self.assertEqual(assessment_check.load_assessments(self.asset), [OK])

    def test_repository_can_revoke_released_assessment(self):
        self.asset.write_text(json.dumps([OK]), encoding="utf-8")
        self.repository.write_text(json.dumps([dict(OK, exploitable=True)]), encoding="utf-8")
        records = assessment_check.load_assessments(self.asset)
        gate = {"status": "needs-assessment", "assessment_required": [REQ]}
        self.assertEqual(assessment_check.check(gate, records)[0], 1)

    def test_malformed_asset_or_repository_fails_closed(self):
        for path in (self.asset, self.repository):
            for content in ("{broken", "{}", '["bad"]', '[{"id": "CVE-1"}]'):
                with self.subTest(path=path.name, content=content):
                    path.write_text(content, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        assessment_check.load_assessments(self.asset)
            path.write_text("[]", encoding="utf-8")

    def test_missing_repository_fails_closed(self):
        self.repository.unlink()
        with self.assertRaises(FileNotFoundError):
            assessment_check.load_assessments()


if __name__ == "__main__":
    unittest.main()
