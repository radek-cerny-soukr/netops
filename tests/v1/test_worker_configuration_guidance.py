import unittest
from unittest.mock import patch

from netops import worker
from netops_admin import mcp_server as admin


class WorkerConfigurationGuidance(unittest.TestCase):
    def test_actual_unconfigured_admin_has_fixed_operator_guidance(self):
        with patch.object(admin, "_CONFIGURATION", None):
            result = worker._admin_configuration_refusal(admin)
        self.assertTrue(result["isError"])
        text = result["content"][0]["text"]
        self.assertIn("admin_not_configured", text)
        self.assertIn("Stop NetOps", text)
        self.assertIn("docker compose run --rm -T netops configure admin", text)

    def test_unconfigured_error_does_not_expose_internal_configuration_values(self):
        with patch.object(admin, "configuration", side_effect=admin.ConfigurationError("SYNTHETIC-PRIVATE-CONFIG-CANARY")):
            result = worker._admin_configuration_refusal(admin)
        self.assertTrue(result["isError"])
        self.assertNotIn("SYNTHETIC-PRIVATE", str(result))

    def test_configured_admin_and_unexpected_failures_do_not_become_configuration_refusals(self):
        with patch.object(admin, "_CONFIGURATION", object()):
            self.assertIsNone(worker._admin_configuration_refusal(admin))
        with patch.object(admin, "configuration", side_effect=OSError("SYNTHETIC-PRIVATE-IO-CANARY")), \
                self.assertRaises(OSError):
            worker._admin_configuration_refusal(admin)


if __name__ == "__main__":
    unittest.main()
