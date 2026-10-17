import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sys
import pytest

class Results:
    def __init__(self):
        self.counts = Counter()
        self.skips = []

    def pytest_deselected(self, items):
        self.counts["deselected"] += len(items)

    def pytest_runtest_logreport(self, report):
        if report.failed:
            self.counts["failed" if report.when == "call" else "error"] += 1
        elif report.skipped:
            self.counts["skipped"] += 1
            self.skips.append({"nodeid": report.nodeid, "reason": str(report.longrepr)})
        elif report.when == "call" and report.passed:
            self.counts["passed"] += 1

def complete_result(exit_code, results):
    return (int(exit_code) == 0 and results.counts["passed"] > 0
            and not results.skips
            and not any(results.counts[name] for name in ("failed", "error", "skipped", "deselected")))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=("core", "helper", "auditor", "admin"))
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--output", default="/pytmp/engine-report.json")
    args = parser.parse_args()
    root = Path("/repo")
    distribution = root / "components" / ("netops-" + args.role)
    installed = Path("/usr/local/lib/python3.14/site-packages")
    mismatches = []
    for path in (distribution / "src").rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        other = installed / path.relative_to(distribution / "src")
        if not other.is_file() or other.read_bytes() != path.read_bytes():
            mismatches.append(str(path.relative_to(root)))
    if mismatches:
        raise RuntimeError("Tests and installed application differ: " + ", ".join(mismatches))
    plugin = Results()
    os.environ.pop("NETOPS_ASKPASS_PROGRAM", None)
    os.chdir(distribution)
    code = pytest.main(["-q", "-p", "no:cacheprovider", "tests", "--basetemp=/pytmp/pytest"], plugins=[plugin])
    passed = complete_result(code, plugin)
    report = {"candidate_commit": args.candidate_commit, "candidate_image": args.candidate_image,
              "role": args.role, "counts": dict(plugin.counts), "conditional_skips": plugin.skips,
              "checks": [{"check": args.role + "-functional-regression", "status": "PASS" if passed else "FAIL",
                          "detail": json.dumps(dict(plugin.counts), sort_keys=True) + "; installed source and runtime data bytes verified; skipped or deselected tests block acceptance"}]}
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
