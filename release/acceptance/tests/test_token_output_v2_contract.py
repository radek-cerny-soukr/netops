import json
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(os.environ.get("CHECKER", Path(__file__).resolve().parents[1] / "token_output.py"))
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"


def token(prefix=""):
    return prefix + "".join(secrets.choice(ALPHABET) for _ in range(64 - len(prefix)))


class TokenOutputV2Contract(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.addCleanup(self.dir.cleanup)
        self.value = token("-")
        self.token_file = self.root / "token.txt"
        self.token_file.write_bytes(self.value.encode() + b"\n")

    def capture(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        return str(path)

    def run_checker(self, files, allow=(), token_file=None):
        output = self.root / "report.json"
        if output.exists():
            output.unlink()
        command = [sys.executable, "-B", str(CHECKER), "--token-file", str(token_file or self.token_file), "--files", *files, "--output", str(output)]
        for path in allow:
            command += ["--allow-empty-file", path]
        process = subprocess.run(command, capture_output=True, text=True, timeout=30)
        report = json.loads(output.read_text()) if output.exists() else None
        self.assertNotIn(self.value, process.stdout + process.stderr + (json.dumps(report) if report else ""))
        return process, report

    def assertPassReport(self, process, report):
        self.assertEqual(process.returncode, 0, process.stderr[-300:])
        self.assertIsNotNone(report)
        self.assertEqual([c["status"] for c in report["checks"]], ["PASS"])
        self.assertEqual(report["summary"], {"PASS": 1})

    def assertFailClosed(self, process, report):
        self.assertEqual(process.returncode, 1, "a gate decision exits 1, not an argument error")
        self.assertIsNotNone(report, "every decision, including a bad allowance, writes the exact report")
        self.assertEqual([c["status"] for c in report["checks"]], ["FAIL"])
        self.assertEqual(report["summary"], {"FAIL": 1})

    def standard(self, log=b""):
        return [self.capture("init.txt", b"initialized\n"), self.capture("up.txt", b"started\n"), self.capture("container-after-up.txt", log)]

    def test_default_empty_capture_fails(self):
        for index in range(3):
            with self.subTest(empty=index):
                contents = [b"initialized\n", b"started\n", b"log\n"]
                contents[index] = b""
                files = [self.capture("f%d.txt" % i, c) for i, c in enumerate(contents)]
                self.assertFailClosed(*self.run_checker(files))

    def test_explicitly_allowed_empty_log_passes_and_is_counted(self):
        files = self.standard()
        process, report = self.run_checker(files, allow=[files[2]])
        self.assertPassReport(process, report)
        self.assertIn("1", report["checks"][0]["detail"], "allowed empty captures must be counted in the PASS detail")

    def test_allowance_never_skips_scanning(self):
        files = self.standard(log=b"x " + self.value.encode() + b" y\n")
        self.assertFailClosed(*self.run_checker(files, allow=[files[2]]))
        files = self.standard(log=b"quiet but present\n")
        self.assertPassReport(*self.run_checker(files, allow=[files[2]]))

    def test_allowance_must_name_an_existing_readable_listed_file(self):
        files = self.standard()
        outside = self.capture("not-listed.txt", b"")
        for name, allow, listed in (("not-listed", [outside], files), ("absent", [str(self.root / "absent.txt")], files + [str(self.root / "absent.txt")]),
                                    ("directory", [str(self.root)], files + [str(self.root)])):
            with self.subTest(case=name):
                self.assertFailClosed(*self.run_checker(listed, allow=allow))

    def test_more_than_one_allowance_fails(self):
        files = [self.capture("init.txt", b"initialized\n"), self.capture("up.txt", b""), self.capture("container-after-up.txt", b"")]
        self.assertFailClosed(*self.run_checker(files, allow=[files[1], files[2]]))

    def test_allowance_matches_after_path_normalisation(self):
        files = self.standard()
        dotted = str(self.root / "." / "container-after-up.txt")
        self.assertPassReport(*self.run_checker(files, allow=[dotted]))

    def test_unlisted_allowance_fails_even_when_every_listed_output_is_non_empty(self):
        files = self.standard(log=b"log\n")
        outside = self.capture("not-listed-empty.txt", b"")
        self.assertFailClosed(*self.run_checker(files, allow=[outside]))

    def test_allowance_does_not_cover_other_empty_captures(self):
        files = [self.capture("init.txt", b""), self.capture("up.txt", b"started\n"), self.capture("container-after-up.txt", b"")]
        self.assertFailClosed(*self.run_checker(files, allow=[files[2]]))

    def test_malformed_token_fails_even_with_allowance(self):
        files = self.standard()
        bad = self.root / "bad-token.txt"
        bad.write_bytes(b"short\n")
        self.assertFailClosed(*self.run_checker(files, allow=[files[2]], token_file=bad))

    def test_leak_in_other_file_fails_with_allowance(self):
        files = [self.capture("init.txt", b"secret " + self.value.encode() + b"\n"), self.capture("up.txt", b"started\n"), self.capture("container-after-up.txt", b"")]
        self.assertFailClosed(*self.run_checker(files, allow=[files[2]]))

    def test_clean_non_empty_outputs_pass_without_allowance(self):
        self.assertPassReport(*self.run_checker(self.standard(log=b"log\n")))


MUTANTS = {
    "allowance-ignored": ("            if name not in allowed:", "            if True:"),
    "allowance-for-all": ("            if name not in allowed:", "            if False:"),
    "emptiness-ignored": ("        if not content:", "        if False:"),
    "allowed-not-scanned": ("        try:\n            content = Path(name).read_bytes()", "        if name in allowed:\n            continue\n        try:\n            content = Path(name).read_bytes()"),
    "membership-unchecked": ("    if len(allowed) > 1 or any(name not in outputs for name in allowed):", "    if len(allowed) > 1:"),
    "many-allowances": ("    if len(allowed) > 1 or any(name not in outputs for name in allowed):", "    if any(name not in outputs for name in allowed):"),
}


def run_mutants():
    source = CHECKER.read_text()
    results = {}
    for name, (old, new) in MUTANTS.items():
        assert source.count(old) == 1, name
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checker.py"
            path.write_text(source.replace(old, new, 1))
            process = subprocess.run([sys.executable, "-B", "-m", "unittest", "-q", "test_token_output_v2_contract"], cwd=Path(__file__).parent,
                                     env=dict(os.environ, CHECKER=str(path)), capture_output=True, text=True, timeout=300)
            results[name] = "killed" if process.returncode != 0 else "SURVIVED"
    return results


if __name__ == "__main__":
    if sys.argv[1:] == ["mutants"]:
        print(json.dumps(run_mutants()))
    else:
        unittest.main()
