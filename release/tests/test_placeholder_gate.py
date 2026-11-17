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
            "CHANGELOG.md": "# NetOps changelog\n\n## 1.0.11 - 2026-10-26\n\n- Fixed.\n\n## 1.0.10 - 2026-10-25\n",
            "README.md": "Acceptance of 1.0.11: blind runs.\n",
            "release/notes-1.0.11.md": "NetOps 1.0.11.\n\n## Acceptance\n\nBlind runs.\n",
            "docs/testing.md": "Release acceptance.\n",
            "docs/archive/0.x/old.md": "TODO(historical): kept as it was.\n",
        }

    def run_gate(self, files, version="1.0.11", extra=()):
        proc = subprocess.run([sys.executable, "-B", GATE, "--version", version, "--root", self.tree(files), *extra],
                              capture_output=True, text=True, timeout=60)
        return proc.returncode, proc.stdout

    def test_filled_candidate_passes(self):
        rc, out = self.run_gate(self.clean())
        self.assertEqual(rc, 0, out)
        self.assertIn("placeholder_gate=PASS", out)

    def test_open_placeholders_fail_and_name_the_file(self):
        cases = (
            ("CHANGELOG.md", "# NetOps changelog\n\n## 1.0.11 - TODO(release-date)\n", "TODO(release-date)"),
            ("release/notes-1.0.11.md", "## Acceptance\n\nTODO(acceptance-1.0.11): describe it.\n", "TODO(acceptance-1.0.11)"),
            ("release/notes-1.0.11.md", "Text. TODO(LOW-1) TODO(LOW-2): extend this.\n", "TODO(LOW-2)"),
            ("README.md", "- **Acceptance:** TODO(acceptance-1.0.11): describe it.\n", "TODO(acceptance-1.0.11)"),
            ("docs/testing.md", "the runs of 1.0.11, TODO(acceptance-1.0.11): the runs.\n", "TODO(acceptance-1.0.11)"),
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
        del files["release/notes-1.0.11.md"]
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)
        self.assertIn("notes-1.0.11.md is missing", out)
        rc, out = self.run_gate(self.clean(), version="1.0.12")
        self.assertEqual(rc, 1, out)
        self.assertIn("no dated section ## 1.0.12", out)
        self.assertIn("notes-1.0.12.md is missing", out)

    def test_candidate_stage_tolerates_only_the_acceptance_and_release_date_placeholders(self):
        files = self.clean()
        files["CHANGELOG.md"] = "# NetOps changelog\n\n## 1.0.11 - TODO(release-date)\n\n- Fixed.\n"
        files["README.md"] = "- **Acceptance of 1.0.11:** TODO(acceptance-1.0.11): describe it.\n"
        files["release/notes-1.0.11.md"] = "## Acceptance\n\nTODO(acceptance-1.0.11): describe it.\n"
        rc, out = self.run_gate(files, extra=("--candidate",))
        self.assertEqual(rc, 0, out)
        self.assertIn("placeholder_gate=PASS", out)
        self.assertIn("PENDING CHANGELOG.md:3: TODO(release-date)", out)
        self.assertIn("PENDING README.md:1: TODO(acceptance-1.0.11)", out)
        self.assertIn("PENDING release/notes-1.0.11.md:3: TODO(acceptance-1.0.11)", out)
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)
        self.assertIn("placeholder_gate=FAIL", out)
        cases = (
            ("README.md", "TODO(acceptance-1.0.10): old.\n", "README.md:1: open placeholder TODO(acceptance-1.0.10)"),
            ("README.md", "TODO(acceptance-1.0.11 unclosed.\n", "README.md:1: open placeholder TODO(acceptance-1.0.11)"),
            ("README.md", "Released on TODO(release-date).\n", "README.md:1: open placeholder TODO(release-date)"),
            ("CHANGELOG.md", "# NetOps changelog\n\n## 1.0.10 - TODO(release-date)\n", "CHANGELOG.md has no dated section ## 1.0.11"),
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
        del changed["release/notes-1.0.11.md"]
        rc, out = self.run_gate(changed, extra=("--candidate",))
        self.assertEqual(rc, 1, out)
        self.assertIn("notes-1.0.11.md is missing", out)

    def test_markdown_that_is_not_utf8_fails_with_the_file_and_without_a_traceback(self):
        cases = (
            ("docs/testing.md", b"Release acceptance.\n\xff\n", "FAIL docs/testing.md: not valid UTF-8 at byte 20"),
            ("CHANGELOG.md", b"# NetOps changelog\n\n## 1.0.11 - 2026-10-26\n\n- Fixed \xe8.\n", "FAIL CHANGELOG.md: not valid UTF-8 at byte 52"),
        )
        for name, content, expected in cases:
            with self.subTest(name=name):
                files = self.clean()
                files["README.md"] = "Acceptance of 1.0.11: TODO(LOW-9) blind runs.\n"
                root = self.tree(files)
                with open(os.path.join(root, name), "wb") as stream:
                    stream.write(content)
                proc = subprocess.run([sys.executable, "-B", GATE, "--version", "1.0.11", "--root", root],
                                      capture_output=True, text=True, timeout=60)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertEqual(proc.stderr, "")
                self.assertEqual(proc.stdout.count(expected), 1, proc.stdout)
                self.assertIn("FAIL README.md:1: open placeholder TODO(LOW-9)", proc.stdout)
                self.assertTrue(proc.stdout.endswith("placeholder_gate=FAIL\n"), proc.stdout)

    def test_line_numbers_follow_crlf_and_cr_line_ends(self):
        root = self.tree(self.clean())
        with open(os.path.join(root, "docs/testing.md"), "wb") as stream:
            stream.write(b"one\r\ntwo\rTODO(LOW-3): three.\n")
        proc = subprocess.run([sys.executable, "-B", GATE, "--version", "1.0.11", "--root", root],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("FAIL docs/testing.md:3: open placeholder TODO(LOW-3)", proc.stdout)

    def test_non_ascii_utf8_markdown_passes(self):
        files = self.clean()
        files["docs/testing.md"] = "Release acceptance – café résumé.\n"
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 0, out)
        self.assertIn("placeholder_gate=PASS", out)

    def test_invalid_version_is_refused(self):
        for version in ("1.0", "0.9.9", "1.1.0", "2.0.0", "1.0.11rc1"):
            with self.subTest(version=version):
                rc, out = self.run_gate(self.clean(), version=version)
                self.assertEqual(rc, 2, out)

    def test_candidate_workflow_runs_the_gate_for_its_version(self):
        with open(WORKFLOW, encoding="utf-8") as stream:
            workflow = stream.read()
        self.assertIn('python3 -B release/placeholder_gate.py --version "$VERSION" --candidate\n', workflow)
        self.assertEqual(workflow.count("release/placeholder_gate.py"), 1)


if __name__ == "__main__":
    unittest.main()
