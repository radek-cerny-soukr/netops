#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path


def load_assessments(released_path=None):
    """Overlay released assessments with current repository records by CVE/package."""
    repository_path = Path(__file__).resolve().with_name("vulnerability-assessments.json")
    merged = {}
    paths = ([Path(released_path)] if released_path else []) + [repository_path]
    for path in paths:
        try:
            with path.open(encoding="utf-8") as stream:
                records = json.load(stream)
        except FileNotFoundError:
            if path != repository_path:
                continue  # Daily scans can run without a released assessment asset.
            raise
        if not isinstance(records, list) or any(
            not isinstance(item, dict) or any(
                not isinstance(item.get(field), str) or not item[field].strip()
                for field in ("id", "package", "version", "type"))
            for item in records
        ):
            raise ValueError("assessments must be a list of records with id, package, version and type: " + str(path))
        for item in records:
            merged[item["id"], item["package"]] = item
    return list(merged.values())


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
        return 1, "not covered by the merged assessments: " + ", ".join(missing)
    return 0, "every finding is covered by the merged assessments"


def main():
    parser = argparse.ArgumentParser(description="Compare a scan gate result with released and current repository assessments")
    parser.add_argument("gate")
    parser.add_argument("--assessments", help="Optional release asset; repository assessments take precedence")
    args = parser.parse_args()
    try:
        with open(args.gate, encoding="utf-8") as stream:
            gate = json.load(stream)
        assessments = load_assessments(args.assessments)
        rc, message = check(gate, assessments)
    except (OSError, ValueError) as error:
        rc, message = 2, "%s: %s" % (type(error).__name__, error)
    print("assessment_check=%s %s" % ("ok" if rc == 0 else "failed", message))
    return rc


if __name__ == "__main__":
    sys.exit(main())
