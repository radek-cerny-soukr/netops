import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class WorkflowDownloadRetry(unittest.TestCase):
    def test_release_downloads_have_retry_and_timeouts(self):
        checked = set()
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            content = path.read_text().replace('\\\n', ' ')
            lines = content.splitlines()
            for index, line in enumerate(lines):
                if 'curl ' in line and 'github.com/' in line and '/releases/download/' in line:
                    checked.add(path.name)
                    with self.subTest(workflow=path.name):
                        for option in ('--retry 5', '--retry-all-errors', '--retry-delay 10', '--retry-max-time 300', '--connect-timeout 20', '--max-time 120'):
                            self.assertIn(option, line)
                        next_line = next((later for later in lines[index + 1:] if later.strip()), "")
                        self.assertIn("sha256sum -c", next_line)
        self.assertTrue({"candidate.yml", "cve-daily.yml"} <= checked)


if __name__ == "__main__":
    unittest.main()
