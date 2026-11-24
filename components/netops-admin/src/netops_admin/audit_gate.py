from __future__ import annotations

import hashlib
import json

from netops_auditor import checks_exos, checks_fortios, l1_exos, l1_fortios, management
from netops_auditor.engine import EVALUATED, NOT_EVALUATED, SECTION_MISSING, evaluate as evaluate_rules, load_catalog
from netops_auditor.state import evaluation_complete

from netops_admin import exos
from netops_admin.errors import Rejected

PARSERS = {"fortios": l1_fortios, "exos": l1_exos}
# Admin platforms for which the Auditor holds no rule catalog: the audit gate has nothing to evaluate there, it
# reports 0 rules and 0 findings, and an audit policy is refused (it could not be enforced)
WITHOUT_RULES = ("eos", "ios", "iosxe", "nxos", "junos")
NO_POLICY = "the Auditor holds no rules for %s; an audit policy cannot be enforced on this platform"
CHECKS = (checks_exos, checks_fortios)
TENANT = "netops-admin"
BLOCKING_SEVERITIES = ("high", "medium")
TABLE_RULES = {
    "firewall address": set(),
    "firewall addrgrp": {"group-empty", "group-dangling", "group-cycle"},
    "system dhcp server/reserved-address": {"dhcp-conflict", "dhcp-subnet"},
    "system dns-database/dns-entry": set(),
    "vlan": set(), "ports": set(), "inline-power": set(), "vlan-membership": {"port-native", "port-policy"},
}
LISTED_RULES = 8
UNEVALUATED = "not-evaluated:"
BASELINE = "baseline"
NOT_VISIBLE = "admin-visibility-unproven"
OWN_SAFEGUARD_RULE = "fortios.mgmt.netops-safeguard-leftover"


class Incomplete(Rejected):
    def __init__(self, reasons, codes):
        super().__init__(reasons)
        self.summary = "%d mandatory rules: %s" % (len(codes), ", ".join(sorted(set(codes.values()))))


def _required(policy, table) -> set:
    # 1.0.12 firewall commit: a profile batch names every table of its steps
    rules = set((policy or {}).get("required_rules", []))
    for name in (table if isinstance(table, tuple) else (table,)):
        rules |= TABLE_RULES.get(name, set())
    return rules


def plan_tables(plan):
    """The table argument of evaluate: the table of the plan, or the tables of the steps of a batch."""
    if "batch_steps" in plan:
        return tuple(dict.fromkeys(step["table"] for step in plan["batch_steps"]))
    return plan["table"]


def unevaluated(before) -> dict:
    if not isinstance(before, dict):
        return {}
    return {value[0]: value[2] for key, value in before.items() if key.startswith(UNEVALUATED)}


def tolerated(before, rule, item) -> bool:
    reason = item["reason"] or item["status"]
    if item["status"] != NOT_EVALUATED or not (reason == NOT_VISIBLE or reason.startswith(SECTION_MISSING + ": ")):
        return False
    return before == BASELINE or unevaluated(before).get(rule) == reason


def finding_count(before) -> int:
    return len(before) - len(unevaluated(before))


def unevaluated_note(before) -> str:
    reasons = sorted(set(unevaluated(before).values()))
    if not reasons:
        return ""
    listed = ", ".join(reasons[:2]) + (" and %d more" % (len(reasons) - 2) if len(reasons) > 2 else "")
    return "; %d not evaluated before and after: %s" % (len(unevaluated(before)), listed[:100])


def summary(before) -> str:
    return "%d findings on the current configuration%s" % (finding_count(before), unevaluated_note(before))


def _without_rules(platform, policy) -> bool:
    if platform not in WITHOUT_RULES:
        return False
    if policy:
        raise Rejected([NO_POLICY % platform])
    return True


def rule_status(platform: str, text: str, device: str, policy=None, table=None, before=None) -> tuple:
    if _without_rules(platform, policy):
        return [], {}
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
    checked = {rule: dict(item, required=item["required"] and (rule.startswith(prefix)
                                                               or not tolerated(before, rule, item)))
               for rule, item in statuses.items()}
    if not evaluation_complete(found, checked):
        codes = {rule: item["reason"] or item["status"] for rule, item in checked.items()
                 if item["required"] and item["status"] != EVALUATED}
        missing = ["%s (%s)" % (rule, code) for rule, code in sorted(codes.items())]
        listed = ", ".join(missing[:LISTED_RULES]) + (" and %d more" % (len(missing) - LISTED_RULES)
                                                       if len(missing) > LISTED_RULES else "")
        raise Incomplete(["the auditor evaluation is not complete: mandatory rules not evaluated: "
                        + (listed or "the snapshot is outside the evaluated scope")], codes)
    return found, statuses


def _own(finding, own) -> bool:
    return (own is not None and finding.rule_id == OWN_SAFEGUARD_RULE
            and dict(finding.evidence).get("name", "").startswith(own))


def findings(platform: str, text: str, device: str, policy=None, before=None, own=None) -> dict:
    found, statuses = rule_status(platform, text, device, policy, before=before)
    result = {}
    for finding in found:
        if _own(finding, own):
            continue
        signature = hashlib.sha256(json.dumps(dict(finding.evidence), sort_keys=True).encode()).hexdigest()
        result[finding.fingerprint()] = (finding.rule_id, finding.severity, signature)
    if before == BASELINE:
        prefix = "%s.management." % platform
        for rule, item in sorted(statuses.items()):
            if item["required"] and not rule.startswith(prefix) and tolerated(before, rule, item):
                result[UNEVALUATED + rule] = (rule, item["status"], item["reason"] or item["status"])
    return result


def baseline(platform: str, text: str, device: str, policy=None) -> dict:
    return findings(platform, text, device, policy, BASELINE)


def new_blocking(platform: str, before, after_text: str, device: str, policy=None, own=None) -> list:
    after = findings(platform, after_text, device, policy, before, own)
    result = set()
    for fingerprint, value in after.items():
        if value[1] not in BLOCKING_SEVERITIES:
            continue
        if fingerprint not in before:
            result.add(value[0])
        elif isinstance(before, dict) and tuple(before[fingerprint]) != tuple(value):
            result.add(value[0])
    return sorted(result)


def evaluate(platform, text, policy, table, before=None):
    if _without_rules(platform, policy):
        return {}
    tree = PARSERS[platform].parse(text)
    coverage = management.coverage(platform, tree, policy)
    missing = sorted(name for name in _required(policy, table) if coverage.get(name) != "evaluated")
    if missing:
        raise Incomplete(["mandatory audit rules were not evaluated: " + ", ".join(missing)],
                         {name: coverage.get(name, "not-evaluated") for name in missing})
    rule_status(platform, text, TENANT, policy, table, before)
    return coverage


def check_policy(plan, policy, text, prior=None):
    if not policy:
        return
    if "batch_steps" in plan:
        for step in plan["batch_steps"]:
            check_policy(step, policy, text, prior)
        return
    table, key = plan["table"], plan["key"]
    folded = key.casefold()
    if (table == "firewall addrgrp" and folded in {v.casefold() for v in policy.get("protected_groups", [])}) or (
        (table in ("ports", "vlan-membership", "inline-power")
         or (plan["platform"] == "exos" and table == exos.BOUNCE_TABLE)) and key in policy.get("protected_ports", [])
    ) or (table == "vlan" and folded in {v.casefold() for v in policy.get("management_vlans", [])}):
        raise Rejected(["the requested object is protected by the audit policy"])
    if plan["platform"] == "exos" and table == "vrrp" and key.split(":", 1)[0].casefold() in {
            v.casefold() for v in policy.get("management_vlans", [])}:
        # 1.0.12 switch ip routing: VRRP on a management VLAN is a change of the management VLAN
        raise Rejected(["the requested object is protected by the audit policy"])
    if plan["platform"] == "exos" and table == "vrrp" and policy.get("protected_ports"):
        # 1.0.12 switch ip routing r2 (review finding 3): VRRP changes its VLAN; a protected member port of that VLAN protects it
        vlan = key.split(":", 1)[0]
        members = exos.vlan_ports(exos.Snapshot(text, plan["firmware"]), vlan)
        ports = set(" ".join(members.values()).split())
        if ports.intersection(policy.get("protected_ports", [])):
            raise Rejected(["the requested object is protected by the audit policy"])
    if plan["platform"] == "exos" and table == "vlan":
        before, after = plan["predicted"]["before"], plan["predicted"]["after"]
        if exos.changed_vlan_ports(before, after).intersection(policy.get("protected_ports", [])):
            raise Rejected(["the requested object is protected by the audit policy"])
    target = {
        "firewall address": "firewall address/" + key,
        "firewall addrgrp": "firewall addrgrp/" + key,
        "ports": "ports/" + key,
        "inline-power": "ports/" + key,
        "vlan": "vlan/" + key,
        "vlan-membership": "ports/" + key,
        "system dhcp server/reserved-address": "system dhcp server/" + key.replace(":", "/reserved-address/"),
        "system dns-database/dns-entry": "system dns-database/" + key.replace(":", "/dns-entry/"),
    }.get("ports" if plan["platform"] == "exos" and table == exos.BOUNCE_TABLE else table)
    if table == "vlan-membership":
        if key not in policy.get("port_vlans", {}):
            raise Rejected(["the selected port has no explicit VLAN allowlist"])
        before, after = plan["predicted"]["before"], plan["predicted"]["after"]
        changed = set(before.get("tagged", "").split()) ^ set(after.get("tagged", "").split())
        if before["untagged"] != after["untagged"]:
            changed |= {before["untagged"], after["untagged"]}
        if {v.casefold() for v in changed} & {v.casefold() for v in policy.get("management_vlans", [])}:
            raise Rejected(["the change touches a management VLAN"])
    for finding in rule_status(plan["platform"], text, plan["device"], policy, table, prior)[0]:
        if target and (finding.object_key == target or finding.object_key.startswith(target + "/")):
            if finding.severity in BLOCKING_SEVERITIES:
                raise Rejected(["the planned object violates " + finding.rule_id])


def rule_count(platform: str) -> int:
    if platform in WITHOUT_RULES:
        return 0
    return len(load_catalog(platform))
