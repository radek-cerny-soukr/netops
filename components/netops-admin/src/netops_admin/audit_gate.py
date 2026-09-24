from __future__ import annotations

import hashlib
import json

from netops_auditor import checks_exos, checks_fortios, l1_exos, l1_fortios, management
from netops_auditor.engine import load_catalog, run

from netops_admin.errors import Rejected

PARSERS = {"fortios": l1_fortios, "exos": l1_exos}
CHECKS = (checks_exos, checks_fortios)
TENANT = "netops-admin"
BLOCKING_SEVERITIES = ("high", "medium")


def findings(platform: str, text: str, device: str, policy=None) -> dict:
    parser = PARSERS.get(platform)
    if parser is None:
        raise Rejected(["the auditor holds no rules for %s" % platform])
    tree = parser.parse(text)
    result = {}
    for finding in run(tree, TENANT, device, load_catalog(platform), policy):
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
    required = set((policy or {}).get("required_rules", []))
    required |= {
        "firewall address": set(),
        "firewall addrgrp": {"group-empty", "group-dangling", "group-cycle"},
        "system dhcp server/reserved-address": {"dhcp-conflict", "dhcp-subnet"},
        "vlan": set(), "ports": set(), "vlan-membership": {"port-native", "port-policy"},
    }.get(table, set())
    missing = sorted(name for name in required if coverage.get(name) != "evaluated")
    if missing:
        raise Rejected(["mandatory audit rules were not evaluated: " + ", ".join(missing)])
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
    tree = PARSERS[plan["platform"]].parse(text)
    for finding in run(tree, TENANT, plan["device"], load_catalog(plan["platform"]), policy):
        if target and (finding.object_key == target or finding.object_key.startswith(target + "/")):
            if finding.severity in BLOCKING_SEVERITIES:
                raise Rejected(["the planned object violates " + finding.rule_id])


def rule_count(platform: str) -> int:
    return len(load_catalog(platform))
