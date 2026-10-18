#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime, timezone

BLOCKING = {"Critical", "High"}
SEVERITIES = {"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
MAX_DB_AGE_HOURS = 48


def db_built(report):
    db = report.get("descriptor", {}).get("db")
    if not isinstance(db, dict):
        return None
    for holder in (db.get("status"), db):
        if isinstance(holder, dict) and isinstance(holder.get("built"), str):
            return holder["built"]
    return None


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def evaluate(report, now):
    if not isinstance(report, dict) or not isinstance(report.get("matches"), list):
        return {"status": "unknown", "reason": "report has no matches list"}
    built = db_built(report)
    if built is None:
        return {"status": "unknown", "reason": "report does not name the vulnerability database build time"}
    try:
        age = (now - parse_time(built)).total_seconds() / 3600
    except ValueError:
        return {"status": "unknown", "reason": "database build time is not ISO 8601: " + built}
    if age > MAX_DB_AGE_HOURS or age < -1:
        return {"status": "unknown", "reason": "database age %.1f h is outside 0..%d h" % (age, MAX_DB_AGE_HOURS)}
    fixable, unfixed, counts = [], [], {}
    for match in report["matches"]:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        severity = vuln.get("severity")
        if severity not in SEVERITIES or not vuln.get("id") or not all(artifact.get(k) for k in ("name", "version", "type")):
            return {"status": "unknown", "reason": "finding with unknown severity or missing id, package, version or type"}
        counts[severity] = counts.get(severity, 0) + 1
        fix = vuln.get("fix", {})
        entry = {"id": vuln.get("id"), "severity": severity, "package": artifact.get("name"),
                 "version": artifact.get("version"), "type": artifact.get("type"),
                 "fix_state": fix.get("state"), "fix_versions": fix.get("versions", [])}
        (fixable if severity in BLOCKING and fix.get("state") == "fixed" else unfixed).append(entry)
    key = lambda e: (e["severity"], e["id"] or "", e["package"] or "")
    result = {"database_built": built, "database_age_hours": round(age, 1), "counts": counts,
              "fixable_blocking": sorted(fixable, key=key), "assessment_required": sorted(unfixed, key=key)}
    if fixable:
        result["status"] = "fail"
    elif unfixed:
        result["status"] = "needs-assessment"
    else:
        result["status"] = "pass"
    return result


def markdown(name, result):
    lines = ["### Vulnerability gate: " + name, "", "Status: **" + result["status"] + "**"]
    if "reason" in result:
        lines.append("Reason: " + result["reason"])
        return "\n".join(lines) + "\n"
    lines.append("Database built %s (%s h old); counts %s" % (
        result["database_built"], result["database_age_hours"], json.dumps(result["counts"], sort_keys=True)))
    for title, key in (("Fixable High/Critical (blocks)", "fixable_blocking"),
                       ("Every other finding, any severity (written assessment required before release)", "assessment_required")):
        if result[key]:
            lines += ["", title, "", "| ID | Severity | Package | Version | Fix |", "|---|---|---|---|---|"]
            lines += ["| %s | %s | %s | %s | %s |" % (e["id"], e["severity"], e["package"], e["version"],
                                                     ", ".join(e["fix_versions"]) or e["fix_state"])
                      for e in result[key]]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--name", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary")
    args = parser.parse_args()
    try:
        with open(args.report, encoding="utf-8") as stream:
            report = json.load(stream)
        result = evaluate(report, datetime.now(timezone.utc))
    except (OSError, ValueError) as error:
        result = {"status": "unknown", "reason": "%s: %s" % (type(error).__name__, error)}
    result["name"] = args.name
    with open(args.output, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=1, sort_keys=True)
        stream.write("\n")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as stream:
            stream.write(markdown(args.name, result))
    print("scan_gate=%s name=%s" % (result["status"], args.name))
    return {"pass": 0, "needs-assessment": 0, "fail": 1}.get(result["status"], 2)


if __name__ == "__main__":
    sys.exit(main())
