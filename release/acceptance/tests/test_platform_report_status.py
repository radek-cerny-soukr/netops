import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).resolve().parents[1] / "report_status.py"
COMMIT = "c" * 40
IMAGE = "sha256:" + "7" * 64
BASE = ["blackbox", "redteam", "failclosed", "syslog", "device", "token-output", "after-restart", "nonroot"]
OPERATIONS = ["smoke", "restart", "down", "ownership"]


def suites(os_name):
    return BASE + (["selinux"] if os_name == "fedora" else [])


class ReportStatusPeer(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def build(self, os_name="ubuntu", label="ubuntu-amd64", commit=COMMIT, image=IMAGE):
        out = self.root / "reports"
        if out.exists():
            shutil.rmtree(out)
        out.mkdir()
        for suite in suites(os_name):
            checks = [{"check": "%s-%d" % (suite, i), "status": "PASS"} for i in range(3)]
            self.write(out, label, suite, {"candidate_commit": commit, "candidate_image": image, "checks": checks, "summary": {"PASS": 3}})
        self.status = {key: 0 for key in suites(os_name) + OPERATIONS}
        return out

    def write(self, out, label, suite, report):
        (out / ("acceptance-%s-%s.json" % (label, suite))).write_text(json.dumps(report))

    def report(self, out, label, suite):
        return json.loads((out / ("acceptance-%s-%s.json" % (label, suite))).read_text())

    def run_checker(self, out, os_name="ubuntu", label="ubuntu-amd64", status_text=None, commit=COMMIT, image=IMAGE):
        status_file = self.root / "command-status.tsv"
        status_file.write_text(status_text if status_text is not None else "".join("%s\t%d\n" % kv for kv in self.status.items()))
        output = self.root / "platform-status.json"
        if output.exists():
            output.unlink()
        process = subprocess.run([sys.executable, "-B", str(CHECKER), "--directory", str(out), "--label", label, "--os", os_name,
                                  "--commit", commit, "--image-digest", image, "--command-status", str(status_file), "--output", str(output)],
                                 capture_output=True, text=True, timeout=30)
        report = json.loads(output.read_text()) if output.exists() else None
        return process, report

    def assertPass(self, process, report):
        self.assertEqual(process.returncode, 0, (process.stdout + process.stderr)[-400:])
        self.assertEqual(report["summary"], {"PASS": 1})
        self.assertEqual([c["status"] for c in report["checks"]], ["PASS"])
        self.assertEqual((report["candidate_commit"], report["candidate_image"]), (COMMIT, IMAGE))

    def assertFail(self, process, report):
        self.assertEqual(process.returncode, 1, (process.stdout + process.stderr)[-400:])
        self.assertIsNotNone(report, "every decision writes the status report")
        self.assertEqual(report["summary"], {"FAIL": 1})
        self.assertEqual([c["status"] for c in report["checks"]], ["FAIL"])

    def test_complete_platforms_pass(self):
        for os_name in ("ubuntu", "debian", "fedora"):
            with self.subTest(os=os_name):
                label = os_name + "-arm64"
                self.assertPass(*self.run_checker(self.build(os_name, label), os_name, label))

    def test_each_missing_report_fails(self):
        for suite in suites("fedora"):
            with self.subTest(suite=suite):
                out = self.build("fedora", "fedora-amd64")
                (out / ("acceptance-fedora-amd64-%s.json" % suite)).unlink()
                self.assertFail(*self.run_checker(out, "fedora", "fedora-amd64"))

    def test_extra_or_foreign_report_fails(self):
        for name in ("acceptance-ubuntu-amd64-selinux.json", "acceptance-debian-amd64-blackbox.json", "acceptance-ubuntu-amd64-blackbox-2.json"):
            with self.subTest(extra=name):
                out = self.build()
                (out / name).write_text((out / "acceptance-ubuntu-amd64-blackbox.json").read_text())
                self.assertFail(*self.run_checker(out))

    def test_binding_mismatch_fails_for_each_suite(self):
        for suite in suites("ubuntu"):
            for field, value in (("candidate_commit", "d" * 40), ("candidate_image", "sha256:" + "8" * 64), ("candidate_commit", None)):
                with self.subTest(suite=suite, field=field, value=value):
                    out = self.build()
                    report = self.report(out, "ubuntu-amd64", suite)
                    if value is None:
                        del report[field]
                    else:
                        report[field] = value
                    self.write(out, "ubuntu-amd64", suite, report)
                    self.assertFail(*self.run_checker(out))

    def test_malformed_checks_fail(self):
        cases = {
            "no-checks": lambda r: r.update(checks=[], summary={"PASS": 0}),
            "checks-not-list": lambda r: r.update(checks={"check": "x", "status": "PASS"}),
            "missing-checks": lambda r: r.pop("checks"),
            "check-not-object": lambda r: r.update(checks=["PASS"], summary={"PASS": 1}),
            "duplicate-name": lambda r: r["checks"].__setitem__(1, dict(r["checks"][0])),
            "empty-name": lambda r: r["checks"][0].update(check=""),
            "non-string-name": lambda r: r["checks"][0].update(check=7),
            "fail-check": lambda r: r["checks"][2].update(status="FAIL"),
            "not-run-check": lambda r: r["checks"][2].update(status="NOT RUN"),
            "lowercase-pass": lambda r: r["checks"][2].update(status="pass"),
            "summary-count": lambda r: r.update(summary={"PASS": 2}),
            "summary-extra": lambda r: r.update(summary={"PASS": 3, "FAIL": 0}),
            "summary-missing": lambda r: r.pop("summary"),
        }
        for name, mutate in cases.items():
            for suite in ("blackbox", "token-output", "nonroot"):
                with self.subTest(case=name, suite=suite):
                    out = self.build()
                    report = self.report(out, "ubuntu-amd64", suite)
                    mutate(report)
                    self.write(out, "ubuntu-amd64", suite, report)
                    self.assertFail(*self.run_checker(out))

    def test_unreadable_report_fails(self):
        for content in (b"", b"{", b"[]", b"\xff\xfe", b"null"):
            with self.subTest(content=content):
                out = self.build()
                (out / "acceptance-ubuntu-amd64-device.json").write_bytes(content)
                self.assertFail(*self.run_checker(out))

    def test_report_directory_instead_of_file_fails(self):
        out = self.build()
        path = out / "acceptance-ubuntu-amd64-syslog.json"
        path.unlink()
        path.mkdir()
        self.assertFail(*self.run_checker(out))

    def test_nonzero_suite_rc_with_pass_report_fails(self):
        for suite in suites("fedora"):
            with self.subTest(suite=suite):
                out = self.build("fedora", "fedora-amd64")
                self.status[suite] = 1
                self.assertFail(*self.run_checker(out, "fedora", "fedora-amd64"))

    def test_zero_rc_with_failed_report_fails(self):
        out = self.build()
        report = self.report(out, "ubuntu-amd64", "redteam")
        report["checks"][0]["status"] = "FAIL"
        report["summary"] = {"PASS": 2, "FAIL": 1}
        self.write(out, "ubuntu-amd64", "redteam", report)
        self.assertFail(*self.run_checker(out))

    def test_failed_report_with_nonzero_rc_and_forged_pass_summary_fails(self):
        for suite in ("blackbox", "token-output", "nonroot"):
            with self.subTest(suite=suite):
                out = self.build()
                report = self.report(out, "ubuntu-amd64", suite)
                report["checks"][1]["status"] = "FAIL"
                self.write(out, "ubuntu-amd64", suite, report)
                self.status[suite] = 1
                self.assertFail(*self.run_checker(out))

    def test_each_failed_operation_fails(self):
        for operation in OPERATIONS:
            for rc in (1, 255):
                with self.subTest(operation=operation, rc=rc):
                    out = self.build()
                    self.status[operation] = rc
                    self.assertFail(*self.run_checker(out))

    def test_malformed_status_file_fails(self):
        good = "".join("%s\t0\n" % key for key in suites("ubuntu") + OPERATIONS)
        cases = {
            "empty": "",
            "missing-operation": good.replace("down\t0\n", ""),
            "missing-suite": good.replace("syslog\t0\n", ""),
            "extra-key": good + "selinux\t0\n",
            "duplicate-key": good + "smoke\t0\n",
            "space-separator": good.replace("smoke\t0", "smoke 0"),
            "three-fields": good.replace("smoke\t0", "smoke\t0\t0"),
            "non-integer": good.replace("smoke\t0", "smoke\tok"),
            "out-of-range": good.replace("smoke\t0", "smoke\t256"),
            "negative": good.replace("smoke\t0", "smoke\t-1"),
            "blank-line": good + "\n",
            "unknown-key-instead": good.replace("ownership\t0", "owner\t0"),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.assertFail(*self.run_checker(self.build(), status_text=text))

    def test_missing_status_file_or_directory_fails(self):
        out = self.build()
        status_file = self.root / "command-status.tsv"
        output = self.root / "platform-status.json"
        for directory, status in ((str(out), str(self.root / "absent.tsv")), (str(self.root / "absent-dir"), None)):
            with self.subTest(directory=directory, status=status):
                status_file.write_text("".join("%s\t0\n" % key for key in suites("ubuntu") + OPERATIONS))
                process = subprocess.run([sys.executable, "-B", str(CHECKER), "--directory", directory, "--label", "ubuntu-amd64", "--os", "ubuntu",
                                          "--commit", COMMIT, "--image-digest", IMAGE, "--command-status", status or str(status_file), "--output", str(output)],
                                         capture_output=True, text=True, timeout=30)
                self.assertFail(process, json.loads(output.read_text()))

    def test_unsupported_platform_fails_closed(self):
        for os_name in ("rpios", "raspbian", "Ubuntu", "", "arch"):
            with self.subTest(os=os_name):
                self.assertFail(*self.run_checker(self.build(), os_name=os_name))

    def test_fedora_requires_selinux_and_others_reject_it(self):
        out = self.build("ubuntu", "fedora-amd64")
        self.status["selinux"] = 0
        self.assertFail(*self.run_checker(out, "fedora", "fedora-amd64"))
        out = self.build("fedora", "ubuntu-amd64")
        self.assertFail(*self.run_checker(out, "ubuntu", "ubuntu-amd64"))

    def test_label_must_match_report_names(self):
        out = self.build(label="ubuntu-amd64")
        self.assertFail(*self.run_checker(out, label="ubuntu-arm64"))

    def test_status_report_is_bound_to_arguments(self):
        out = self.build(commit="e" * 40, image="sha256:" + "9" * 64)
        process, report = self.run_checker(out, commit="e" * 40, image="sha256:" + "9" * 64)
        self.assertEqual(process.returncode, 0)
        self.assertEqual((report["candidate_commit"], report["candidate_image"]), ("e" * 40, "sha256:" + "9" * 64))


if __name__ == "__main__":
    unittest.main()
