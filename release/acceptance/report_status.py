import argparse
import json
from pathlib import Path


BASE_SUITES = ("blackbox", "redteam", "failclosed", "syslog", "device", "token-output")
OPERATIONS = ("smoke", "restart", "down", "ownership")


def expected_suites(os_name):
    if os_name not in ("ubuntu", "debian", "fedora"):
        raise ValueError("Unsupported platform")
    return BASE_SUITES + ("after-restart", "nonroot") + (("selinux",) if os_name == "fedora" else ())


def check_reports(directory, label, os_name, commit, image, status_file):
    try:
        suites = expected_suites(os_name)
        statuses = {}
        for line in Path(status_file).read_text().splitlines():
            key, value = line.split("\t")
            if key in statuses or not 0 <= int(value) <= 255:
                return False, "Command status file malformed"
            statuses[key] = int(value)
        if set(statuses) != set(suites + OPERATIONS):
            return False, "Command status set differs from expected commands"
        expected = {"acceptance-%s-%s.json" % (label, suite) for suite in suites}
        actual = {path.name for path in Path(directory).glob("acceptance-*.json")}
        if actual != expected:
            return False, "Report file set differs from expected suites"
        for suite in suites:
            path = Path(directory) / ("acceptance-%s-%s.json" % (label, suite))
            report = json.loads(path.read_text())
            if report.get("candidate_commit") != commit or report.get("candidate_image") != image:
                return False, "Report candidate binding differs"
            checks = report.get("checks")
            if not isinstance(checks, list) or not checks:
                return False, "Report has no checks"
            names = [check.get("check") for check in checks]
            if any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(names):
                return False, "Report check identities malformed"
            passed = all(check.get("status") == "PASS" for check in checks)
            if passed != (statuses[suite] == 0):
                return False, "Command rc/report mismatch"
            if not passed:
                return False, "Report contains a non-PASS check"
            if report.get("summary") != {"PASS": len(checks)}:
                return False, "Report summary differs from its checks"
        if any(statuses[key] for key in OPERATIONS):
            return False, "Platform setup or cleanup command failed"
    except (OSError, ValueError, TypeError, AttributeError):
        return False, "Report or command status could not be read"
    return True, "Every expected report and command passed"


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--os", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--command-status", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    passed, detail = check_reports(args.directory, args.label, args.os, args.commit, args.image_digest, args.command_status)
    status = "PASS" if passed else "FAIL"
    report = {"schema": "netops-acceptance-platform-status/1", "candidate_commit": args.commit,
              "candidate_image": args.image_digest, "summary": {status: 1},
              "checks": [{"check": "platform-reports", "status": status, "detail": detail}]}
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
