from __future__ import annotations

import hashlib
import json

from netops_auditor import checks_exos, checks_fortios, l1_exos, l1_fortios, management
from netops_auditor.engine import EVALUATED, evaluate as evaluate_rules, load_catalog
from netops_auditor.state import evaluation_complete

from netops_admin.errors import Rejected

PARSERS = {"fortios": l1_fortios, "exos": l1_exos}
CHECKS = (checks_exos, checks_fortios)
TENANT = "netops-admin"
BLOCKING_SEVERITIES = ("high", "medium")
TABLE_RULES = {
    "firewall address": set(),
    "firewall addrgrp": {"group-empty", "group-dangling", "group-cycle"},
    "system dhcp server/reserved-address": {"dhcp-conflict", "dhcp-subnet"},
    "vlan": set(), "ports": set(), "vlan-membership": {"port-native", "port-policy"},
}
LISTED_RULES = 8


class Incomplete(Rejected):
    def __init__(self, reasons, codes):
        super().__init__(reasons)
        self.summary = "%d mandatory rules: %s" % (len(codes), ", ".join(sorted(set(codes.values()))))


def _required(policy, table) -> set:
    return set((policy or {}).get("required_rules", [])) | TABLE_RULES.get(table, set())


def rule_status(platform: str, text: str, device: str, policy=None, table=None) -> tuple:
    parser = PARSERS.get(platform)
    if parser is None:
        raise Rejected(["the auditor holds no rules for %s" % platform])
    tree = parser.parse(text)
    rules = load_catalog(platform)
    found, states = evaluate_rules(tree, TENANT, device, rules, policy)
    required, prefix = _required(policy, table), "%s.management." % platform
    statuses = {}
    for rule in rules:
        state, reason = states[rule.id]
        name = rule.id[len(prefix):] if rule.id.startswith(prefix) else None
        statuses[rule.id] = {"status": state, "reason": reason, "required": name is None or name in required}
    if not evaluation_complete(found, statuses):
        codes = {rule: item["reason"] or item["status"] for rule, item in statuses.items()
                 if item["required"] and item["status"] != EVALUATED}
        missing = ["%s (%s)" % (rule, code) for rule, code in sorted(codes.items())]
        listed = ", ".join(missing[:LISTED_RULES]) + (" and %d more" % (len(missing) - LISTED_RULES)
                                                       if len(missing) > LISTED_RULES else "")
        raise Incomplete(["the auditor evaluation is not complete: mandatory rules not evaluated: "
                        + (listed or "the snapshot is outside the evaluated scope")], codes)
    return found, statuses


def findings(platform: str, text: str, device: str, policy=None) -> dict:
    result = {}
    for finding in rule_status(platform, text, device, policy)[0]:
        signature = hashlib.sha256(json.dumps(dict(finding.evidence), sort_keys=True).encode()).hexdigest()
        result[finding.fingerprint()] = (finding.rule_id, finding.severity, signature)
    return result


def new_blocking(platform: str, before, after_text: str, device: str, policy=None) -> list:
    after = findings(platform, after_text, device, policy)
    result = set()
    for fingerprint, value in after.items():
        if value[1] not in BLOCKING_SEVERITIES:
            continue
        if fingerprint not in before:
            result.add(value[0])
        elif isinstance(before, dict) and tuple(before[fingerprint]) != tuple(value):
            result.add(value[0])
    return sorted(result)


def evaluate(platform, text, policy, table):
    tree = PARSERS[platform].parse(text)
    coverage = management.coverage(platform, tree, policy)
    missing = sorted(name for name in _required(policy, table) if coverage.get(name) != "evaluated")
    if missing:
        raise Incomplete(["mandatory audit rules were not evaluated: " + ", ".join(missing)],
                         {name: coverage.get(name, "not-evaluated") for name in missing})
    rule_status(platform, text, TENANT, policy, table)
    return coverage


def check_policy(plan, policy, text):
    if not policy:
        return
    table, key = plan["table"], plan["key"]
    folded = key.casefold()
    if (table == "firewall addrgrp" and folded in {v.casefold() for v in policy.get("protected_groups", [])}) or (
        table in ("ports", "vlan-membership") and key in policy.get("protected_ports", [])
    ) or (table == "vlan" and folded in {v.casefold() for v in policy.get("management_vlans", [])}):
        raise Rejected(["the requested object is protected by the audit policy"])
    target = {
        "firewall address": "firewall address/" + key,
        "firewall addrgrp": "firewall addrgrp/" + key,
        "ports": "ports/" + key,
        "vlan": "vlan/" + key,
        "vlan-membership": "ports/" + key,
        "system dhcp server/reserved-address": "system dhcp server/" + key.replace(":", "/reserved-address/"),
    }.get(table)
    if table == "vlan-membership":
        if key not in policy.get("port_vlans", {}):
            raise Rejected(["the selected port has no explicit VLAN allowlist"])
        before, after = plan["predicted"]["before"], plan["predicted"]["after"]
        changed = set(before.get("tagged", "").split()) ^ set(after.get("tagged", "").split())
        if before["untagged"] != after["untagged"]:
            changed |= {before["untagged"], after["untagged"]}
        if {v.casefold() for v in changed} & {v.casefold() for v in policy.get("management_vlans", [])}:
            raise Rejected(["the change touches a management VLAN"])
    for finding in rule_status(plan["platform"], text, plan["device"], policy, table)[0]:
        if target and (finding.object_key == target or finding.object_key.startswith(target + "/")):
            if finding.severity in BLOCKING_SEVERITIES:
                raise Rejected(["the planned object violates " + finding.rule_id])


def rule_count(platform: str) -> int:
    return len(load_catalog(platform))
