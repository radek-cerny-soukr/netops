import importlib.util
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("sign_tool_fixture", os.path.join(HERE, "test_sign_tool.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

TOKEN_ROWS = ["actions-%s-token-output" % a for a in fixture.ARCHES]
EXPECTED_REQUIRED = 40


def acceptance_rows(output):
    return sorted(set(re.findall(r"(?m)^acceptance (\S+)", output)))


class SignTokenOutput(fixture.SignTool):
    locals().update({name: None for name in dir(fixture.SignTool) if name.startswith("test_")})

    def setUp(self):
        super().setUp()
        for row in TOKEN_ROWS:
            self.reports[row] = {"checks": [{"check": "token-output-bytes", "status": "PASS"}]}

    def test_token_output_rows_are_only_the_actions_rows(self):
        self.assertEqual(len(TOKEN_ROWS), 2)
        self.assertEqual(len(set(fixture.ROWS) - set(TOKEN_ROWS)), 38)
        self.assertEqual(len(set(fixture.ROWS) | set(TOKEN_ROWS)), EXPECTED_REQUIRED)

    def test_complete_candidate_with_token_rows_passes_and_requires_40_rows(self):
        rc, out = self.run_tool()
        self.assertEqual(rc, 0, out)
        self.assertIn("OVERALL: PASS", out)
        rows = acceptance_rows(out)
        self.assertEqual(len(rows), EXPECTED_REQUIRED + len(fixture.OPTIONAL_ROWS), rows)
        for row in TOKEN_ROWS:
            self.assertIn(row, rows)

    def test_each_missing_token_row_is_not_run(self):
        for row in TOKEN_ROWS:
            with self.subTest(row=row):
                reports = self.reports
                self.reports = {r: v for r, v in reports.items() if r != row}
                rc, out = self.run_tool()
                self.reports = reports
                self.assertEqual(rc, 1, out)
                self.assertIn("OVERALL: NOT RUN", out)
                self.assertRegex(out, r"(?m)^acceptance %s\s+NOT RUN" % re.escape(row))

    def test_failed_token_report_refuses(self):
        for row in TOKEN_ROWS:
            with self.subTest(row=row):
                self.reports[row] = {"checks": [{"check": "token-output-bytes", "status": "FAIL"}]}
                out = self.assert_refused("OVERALL: FAIL")
                self.assertRegex(out, r"(?m)^acceptance %s\s+FAIL" % re.escape(row))
                self.reports[row] = {"checks": [{"check": "token-output-bytes", "status": "PASS"}]}

    def test_token_report_for_another_commit_or_image_refuses(self):
        row = "actions-arm64-token-output"
        self.reports[row] = {"checks": [{"check": "token-output-bytes", "status": "PASS"}], "candidate_commit": "b" * 40}
        self.assert_refused("report is not for this commit")
        self.reports[row] = {"checks": [{"check": "token-output-bytes", "status": "PASS"}], "candidate_image": "sha256:" + "9" * 64}
        self.assert_refused("report is not for this image index")

    def test_token_report_not_matching_the_signed_file_refuses(self):
        self.build()
        path = os.path.join(self.dir, "acceptance-actions-amd64-token-output.json")
        with open(path, "a") as stream:
            stream.write("\n")
        rc, out = self.run_tool(build=False)
        self.assertEqual(rc, 1, out)
        self.assertNotIn("OVERALL: PASS", out)


if __name__ == "__main__":
    unittest.main()
