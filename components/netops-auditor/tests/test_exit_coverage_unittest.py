import unittest

from netops_auditor import cli


class CoverageExitTest(unittest.TestCase):
    def test_principled_factory_gap_does_not_hide_other_gaps(self):
        factory = {"status": "not-evaluated", "reason": "factory-provenance-unproven:profile=cert", "required": True}
        report = {"platform": "fortiadc", "evaluation_complete": False, "findings": [],
                  "rule_status": {"fortiadc.tls.factory-certificate": factory}}
        self.assertEqual(cli._exit_code(report), 0)
        report["rule_status"]["fortiadc.other"] = {"status": "not-evaluated", "reason": "section-absent", "required": True}
        self.assertEqual(cli._exit_code(report), 3)
        report["rule_status"].pop("fortiadc.other")
        factory["reason"] = "identity-mismatch"
        self.assertEqual(cli._exit_code(report), 3)
