from pathlib import Path
import unittest

from netops_admin import audit_gate
from netops_auditor import engine, l1_exos, l1_fortios, management


# Byte copies of components/netops-auditor/tests/fixtures/{exos,fortios}_clean.conf: tests/v1 ships
# in the image without components/.
FIXTURES = Path(__file__).resolve().parent / "fixtures"


class AuditorAdminGateCompatibility(unittest.TestCase):
    def test_legacy_catalog_engine_and_admin_pre_post(self):
        for platform, parser in (("exos", l1_exos), ("fortios", l1_fortios)):
            text = (FIXTURES / (platform + "_clean.conf")).read_text()
            with self.subTest(platform=platform):
                for policy in (None, management.validate_policy({"version": 1, "platform": platform}, platform)):
                    found, statuses = engine.evaluate(parser.parse(text), "example", "switch",
                                                      engine.load_catalog(platform), policy)
                    self.assertEqual(found, ())
                    self.assertTrue(statuses)
                    before = audit_gate.baseline(platform, text, "switch", policy)
                    self.assertEqual(audit_gate.new_blocking(platform, before, text, "switch", policy), [])
