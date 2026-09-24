from __future__ import annotations

import hashlib
import json
import re

from netops_auditor.management import exos_model, ports
from netops_admin.errors import Rejected


def model(snapshot):
    try:
        return exos_model(snapshot.configuration)
    except ValueError:
        raise Rejected(["VLAN membership cannot be evaluated from this snapshot"]) from None


def states(snapshot):
    _vlans, members, _descriptions = model(snapshot)
    result = {}
    for port, modes in members.items():
        if len(modes["untagged"]) != 1:
            continue
        result[port] = {"untagged": next(iter(modes["untagged"])),
                        "tagged": " ".join(sorted(modes["tagged"]))}
    return result


def prechecks(snapshot, key, before, after):
    vlans, members, _descriptions = model(snapshot)
    if key not in members or len(members[key]["untagged"]) != 1 or not after.get("untagged"):
        return ["the port must have exactly one known native VLAN before and after the change"]
    named = set(after.get("tagged", "").split()) | {after["untagged"]}
    if named - set(vlans):
        return ["a requested VLAN does not exist"]
    if after["untagged"] in after.get("tagged", "").split():
        return ["the native VLAN cannot also be tagged on this port"]
    for command in snapshot.commands:
        t = command.tokens
        if t[:2] == ("enable", "sharing"):
            try:
                group = t.index("grouping") if "grouping" in t else t.index("group")
                affected = ports(t[2]) | ports(t[group + 1])
            except (ValueError, IndexError):
                return ["link aggregation cannot be evaluated"]
            if key in affected:
                return ["VLAN membership changes on link aggregation ports are unsupported"]
        if t == ("configure", "vlan", "untagged-ports", "auto-move", "off") and before.get("untagged") != after["untagged"]:
            return ["native VLAN movement is disabled on this switch"]
    return []


def render(port, before, after):
    old_tagged, new_tagged = set(before.get("tagged", "").split()), set(after.get("tagged", "").split())
    old_native, new_native = before["untagged"], after["untagged"]
    result = ["configure vlan %s delete ports %s" % (name, port) for name in sorted(old_tagged - new_tagged)
              if name != new_native]
    if old_native != new_native:
        if new_native in old_tagged:
            result.append("configure vlan %s delete ports %s" % (new_native, port))
        result.append("configure vlan %s add ports %s untagged" % (new_native, port))
    result.extend("configure vlan %s add ports %s tagged" % (name, port)
                  for name in sorted(new_tagged - old_tagged))
    return result


def rest_digest(snapshot, port, commands=None):
    vlans, members, descriptions = model(snapshot)
    other = {key: {mode: sorted(names) for mode, names in modes.items()}
             for key, modes in members.items() if key != port}
    lines = [command.text for command in (snapshot.commands if commands is None else commands)
             if command.tokens[:2] != ("configure", "vlan") or command.tokens[3:5] != ("add", "ports")]
    body = {"other_memberships": other, "configuration": lines}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def prediction(snapshot, port, state):
    _vlans, members, _descriptions = model(snapshot)
    members[port] = {"tagged": set(state.get("tagged", "").split()), "untagged": {state["untagged"]}}
    lines = ["# Module vlan configuration."]
    lines += [command.text for command in snapshot.commands
              if command.tokens[:2] != ("configure", "vlan") or command.tokens[3:5] != ("add", "ports")]
    for key, modes in sorted(members.items()):
        for mode, names in sorted(modes.items()):
            lines += ["configure vlan %s add ports %s %s" % (name, key, mode) for name in sorted(names)]
    return "\n".join(lines) + "\n"


def shown(text, port):
    if "VLAN Name(s)" not in text or "Untagged" not in text:
        raise Rejected(["the check account membership answer is not recognised"])
    modes = {"Tagged": set(), "Untagged": set()}
    current = None
    matched = False
    for line in text.splitlines():
        row = re.fullmatch(r"\s*(?:(\d+)\s+)?(Untagged|Tagged)\s+(.*?)\s*", line)
        if row:
            if row[1] is not None and row[1] != port:
                raise Rejected(["the check account returned another port"])
            if row[1] == port:
                matched = True
            if not matched:
                if row[1] is None and not row[3].strip():
                    continue
                raise Rejected(["membership answer has no selected port"])
            current = row[2]
            names = re.split(r"[,\s]+", row[3])
            if not all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", name) for name in names):
                raise Rejected(["unsupported VLAN name in membership answer"])
            modes[current].update(names)
        elif matched and line.strip():
            if not current or not re.fullmatch(r"\s+[A-Za-z][A-Za-z0-9_, -]*\s*", line):
                raise Rejected(["unsupported membership continuation"])
            modes[current].update(re.split(r"[,\s]+", line.strip()))
    if not matched or len(modes["Untagged"]) != 1:
        raise Rejected(["the check account must report one native VLAN"])
    return {"untagged": next(iter(modes["Untagged"])), "tagged": " ".join(sorted(modes["Tagged"]))}
