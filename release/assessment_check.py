#!/usr/bin/env python3
import argparse
import json
import sys


def check(gate, assessments):
    status = gate.get("status")
    if status == "pass":
        return 0, "no finding needs an assessment"
    if status != "needs-assessment":
        return 1, "gate status %s" % status
    key = lambda item: (item.get("id"), item.get("package"), item.get("version"), item.get("type"))
    covered = {key(item) for item in assessments if item.get("exploitable") is False
               and isinstance(item.get("reasoning"), str) and item["reasoning"].strip()
               and isinstance(item.get("evidence"), str) and item["evidence"].strip()}
    missing = sorted({"|".join(str(part) for part in key(entry)) for entry in gate.get("assessment_required", [])
                      if key(entry) not in covered})
    if missing:
        return 1, "not covered by the released assessments: " + ", ".join(missing)
    return 0, "every finding is covered by the released assessments"


def main():
    parser = argparse.ArgumentParser(description="Compare a scan gate result with the assessments shipped in a release")
    parser.add_argument("gate")
    parser.add_argument("--assessments")
    args = parser.parse_args()
    try:
        with open(args.gate, encoding="utf-8") as stream:
            gate = json.load(stream)
        assessments = []
        if args.assessments:
            with open(args.assessments, encoding="utf-8") as stream:
                assessments = json.load(stream)
        rc, message = check(gate, assessments)
    except (OSError, ValueError) as error:
        rc, message = 2, "%s: %s" % (type(error).__name__, error)
    print("assessment_check=%s %s" % ("ok" if rc == 0 else "failed", message))
    return rc


if __name__ == "__main__":
    sys.exit(main())
