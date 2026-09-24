from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from . import __version__

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"
TOOL = "netops-auditor"
INFORMATION_URI = "https://github.com/radek-cerny-soukr/netops"
FINGERPRINT_KEY = "netopsFingerprint/v2"
LEVELS = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "3.0"}
DEVICE_KEYS = ("tenant", "device", "platform", "snapshot_sha256", "rules_version", "rule_coverage", "evaluation")


class SarifError(Exception):
    pass


def artifact_uri(path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate.as_uri()
    return quote(PurePosixPath(candidate.as_posix()).as_posix())


def _rule(rule, platform: str) -> dict:
    properties = {"tags": ["security", platform], "netops-class": rule.rule_class, "refs": list(rule.refs)}
    if rule.severity in SECURITY_SEVERITY:
        properties["security-severity"] = SECURITY_SEVERITY[rule.severity]
    return {
        "id": rule.id,
        "shortDescription": {"text": rule.title},
        "help": {"text": rule.remediation},
        "defaultConfiguration": {"level": LEVELS[rule.severity]},
        "properties": properties,
    }


def _result(item: dict, index: int, title: str, uri: str, report: dict) -> dict:
    location = {"artifactLocation": {"uri": uri}}
    if item["line"] >= 1:
        location["region"] = {"startLine": item["line"]}
    result = {
        "ruleId": item["rule_id"],
        "ruleIndex": index,
        "level": LEVELS[item["severity"]],
        "message": {"text": "%s: %s" % (item["object_key"], title)},
        "locations": [
            {
                "physicalLocation": location,
                "logicalLocations": [{"fullyQualifiedName": item["object_key"]}],
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: item["fingerprint"]},
        "properties": {
            "tenant": report["tenant"],
            "device": report["device"],
            "section": item["section"],
            "class": item["class"],
            "state": item["state"],
            "evidence": item["evidence"],
        },
    }
    if item["state"] == "suppressed":
        result["suppressions"] = [{"kind": "external", "status": "accepted"}]
    return result


def _document(rules: list, results: list, devices: list) -> dict:
    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL,
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {"devices": devices},
            }
        ],
    }


def document(report: dict, rules, config_path: str) -> dict:
    described = [_rule(rule, report["platform"]) for rule in rules]
    index = {rule.id: position for position, rule in enumerate(rules)}
    titles = {rule.id: rule.title for rule in rules}
    uri = artifact_uri(config_path)
    results = [
        _result(item, index[item["rule_id"]], titles[item["rule_id"]], uri, report)
        for item in report["findings"]
    ]
    device = {key: report[key] for key in DEVICE_KEYS if key in report}
    return _document(described, results, [device])


def _single_run(item, source: str) -> dict:
    if not isinstance(item, dict) or item.get("version") != VERSION:
        raise SarifError("%s is not a SARIF %s document" % (source, VERSION))
    runs = item.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise SarifError("%s must hold exactly one run" % source)
    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})
    if driver.get("name") != TOOL:
        raise SarifError("%s was not produced by %s" % (source, TOOL))
    if driver.get("version") != __version__:
        raise SarifError("%s comes from %s %s, not %s" % (source, TOOL, driver.get("version"), __version__))
    return run


def merge(documents) -> dict:
    if not documents:
        raise SarifError("nothing to merge")
    rules, positions, results, devices = [], {}, [], []
    for source, item in documents:
        run = _single_run(item, source)
        local = run["tool"]["driver"].get("rules", [])
        for rule in local:
            known = positions.get(rule["id"])
            if known is None:
                positions[rule["id"]] = len(rules)
                rules.append(rule)
            elif rules[known] != rule:
                raise SarifError("%s describes rule %s differently" % (source, rule["id"]))
        for result in run.get("results", []):
            if result.get("ruleId") not in positions:
                raise SarifError("%s reports rule %s it does not describe" % (source, result.get("ruleId")))
            merged = dict(result)
            merged["ruleIndex"] = positions[result["ruleId"]]
            results.append(merged)
        devices.extend(run.get("properties", {}).get("devices", []))
    return _document(rules, results, devices)


def render(item: dict) -> str:
    return json.dumps(item, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
