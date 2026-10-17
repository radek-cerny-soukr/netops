import json
import subprocess
import sys
import unittest


class Selftest(unittest.TestCase):
    def test_helper_lists_the_target_scope_tool_the_gateway_exposes(self):
        result = subprocess.run([sys.executable, "-B", "-m", "netops", "selftest"], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        roles = json.loads(result.stdout)["roles"]
        helper = roles["helper"]
        self.assertIn("target_scope", helper["names"])
        self.assertEqual(helper["names"].count("target_scope"), 1)
        for role in ("helper", "auditor", "admin"):
            self.assertEqual(roles[role]["tools"], len(roles[role]["names"]))


if __name__ == "__main__":
    unittest.main()
