import os
import subprocess
import sys
import tempfile
import unittest

GATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "placeholder_gate.py")
WORKFLOW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".github", "workflows", "candidate.yml")


class PlaceholderGate(unittest.TestCase):
    def tree(self, files):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        for name, content in files.items():
            path = os.path.join(directory.name, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(content)
        return directory.name

    def clean(self):
        return {
            "CHANGELOG.md": "# NetOps changelog\n\n## 9.8.7 - 2026-10-26\n\n- Fixed.\n\n## 9.8.6 - 2026-10-25\n",
            "README.md": "Acceptance of 9.8.7: blind runs.\n",
            "release/notes-9.8.7.md": "NetOps 9.8.7.\n\n## Acceptance\n\nBlind runs.\n",
            "docs/testing.md": "Release acceptance.\n",
            "docs/archive/0.x/old.md": "TODO(historical): kept as it was.\n",
        }

    def run_gate(self, files, version="9.8.7", extra=()):
        proc = subprocess.run([sys.executable, "-B", GATE, "--version", version, "--root", self.tree(files), *extra],
                              capture_output=True, text=True, timeout=60)
        return proc.returncode, proc.stdout

    def test_filled_candidate_passes(self):
        rc, out = self.run_gate(self.clean())
        self.assertEqual(rc, 0, out)
        self.assertIn("placeholder_gate=PASS", out)

    def test_open_placeholders_fail_and_name_the_file(self):
        cases = (
            ("CHANGELOG.md", "# NetOps changelog\n\n## 9.8.7 - TODO(release-date)\n", "TODO(release-date)"),
            ("release/notes-9.8.7.md", "## Acceptance\n\nTODO(acceptance-9.8.7): describe it.\n", "TODO(acceptance-9.8.7)"),
            ("release/notes-9.8.7.md", "Text. TODO(LOW-1) TODO(LOW-2): extend this.\n", "TODO(LOW-2)"),
            ("README.md", "- **Acceptance:** TODO(acceptance-9.8.7): describe it.\n", "TODO(acceptance-9.8.7)"),
            ("docs/testing.md", "the runs of 9.8.7, TODO(acceptance-9.8.7): the runs.\n", "TODO(acceptance-9.8.7)"),
            ("components/x/docs/tools.md", "TODO(\n", "TODO()"),
        )
        for name, content, expected in cases:
            with self.subTest(name=name, expected=expected):
                files = self.clean()
                files[name] = content
                rc, out = self.run_gate(files)
                self.assertEqual(rc, 1, out)
                self.assertIn("placeholder_gate=FAIL", out)
                self.assertIn(os.path.normpath(name) + ":", out)
                self.assertIn(expected, out)

    def test_missing_notes_or_undated_changelog_fail(self):
        files = self.clean()
        del files["release/notes-9.8.7.md"]
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)
        self.assertIn("notes-9.8.7.md is missing", out)
        rc, out = self.run_gate(self.clean(), version="9.8.8")
        self.assertEqual(rc, 1, out)
        self.assertIn("no dated section ## 9.8.8", out)
        self.assertIn("notes-9.8.8.md is missing", out)

    def test_candidate_stage_tolerates_only_the_acceptance_and_release_date_placeholders(self):
        files = self.clean()
        files["CHANGELOG.md"] = "# NetOps changelog\n\n## 9.8.7 - TODO(release-date)\n\n- Fixed.\n"
        files["README.md"] = "- **Acceptance of 9.8.7:** TODO(acceptance-9.8.7): describe it.\n"
        files["release/notes-9.8.7.md"] = "## Acceptance\n\nTODO(acceptance-9.8.7): describe it.\n"
        rc, out = self.run_gate(files, extra=("--candidate",))
        self.assertEqual(rc, 0, out)
        self.assertIn("placeholder_gate=PASS", out)
        self.assertIn("PENDING CHANGELOG.md:3: TODO(release-date)", out)
        self.assertIn("PENDING README.md:1: TODO(acceptance-9.8.7)", out)
        self.assertIn("PENDING release/notes-9.8.7.md:3: TODO(acceptance-9.8.7)", out)
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)
        self.assertIn("placeholder_gate=FAIL", out)
        cases = (
            ("README.md", "TODO(acceptance-9.8.6): old.\n", "README.md:1: open placeholder TODO(acceptance-9.8.6)"),
            ("README.md", "TODO(acceptance-9.8.7 unclosed.\n", "README.md:1: open placeholder TODO(acceptance-9.8.7)"),
            ("README.md", "Released on TODO(release-date).\n", "README.md:1: open placeholder TODO(release-date)"),
            ("CHANGELOG.md", "# NetOps changelog\n\n## 9.8.6 - TODO(release-date)\n", "CHANGELOG.md has no dated section ## 9.8.7"),
            ("docs/testing.md", "TODO(LOW-1): extend this.\n", "docs/testing.md:1: open placeholder TODO(LOW-1)"),
        )
        for name, content, expected in cases:
            with self.subTest(name=name, expected=expected):
                changed = dict(files)
                changed[name] = content
                rc, out = self.run_gate(changed, extra=("--candidate",))
                self.assertEqual(rc, 1, out)
                self.assertIn("placeholder_gate=FAIL", out)
                self.assertIn(expected, out)
        changed = dict(files)
        del changed["release/notes-9.8.7.md"]
        rc, out = self.run_gate(changed, extra=("--candidate",))
        self.assertEqual(rc, 1, out)
        self.assertIn("notes-9.8.7.md is missing", out)

    def test_invalid_version_is_refused(self):
        rc, out = self.run_gate(self.clean(), version="9.8")
        self.assertNotEqual(rc, 0, out)

    def test_candidate_workflow_runs_the_gate_for_its_version(self):
        with open(WORKFLOW, encoding="utf-8") as stream:
            workflow = stream.read()
        self.assertIn('python3 -B release/placeholder_gate.py --version "$VERSION" --candidate\n', workflow)
        self.assertEqual(workflow.count("release/placeholder_gate.py"), 1)


if __name__ == "__main__":
    unittest.main()
