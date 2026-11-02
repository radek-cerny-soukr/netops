"""Read-only FortiADC server load-balancing triage: parsers, rules and verdict."""

from __future__ import annotations

import re
import shlex
from typing import Any

MISSING_REASONS = frozenset((
    "timeout", "truncated", "empty", "unsupported", "permission_denied",
    "device_cli_error", "unparsed", "not_applicable",
))
REQUIRED_STEPS = ("vs_config", "pool_config", "slb_vs_stat", "system_performance")
MAX_HEALTH_CHECKS = 4
RATE_COST = 17
FAULT_RULES = frozenset((
    "F-VS-DISABLED", "F-VS-AVAIL", "F-MEMBER-DOWN", "F-POOL-ALL-DOWN", "F-MISMATCH", "F-TLS-FAIL",
))
STATE = re.compile(r"[A-Z_]+")
_ECHO = re.compile(r"(?:diagnose|execute|get) \S")
_VDOM = re.compile(r"vdom name is\s+(\S+)")
_VS_STAT = re.compile(r"\tvirtual-server: (\S+), availability:(\S+)")
_COUNTER = re.compile(r"([A-Za-z][A-Za-z ]{0,40}): (-?[0-9]+)")
_POOL = re.compile(r"\t\treal-server-pool: (\S+)")
_MEMBER_STAT = re.compile(r"\t\tid:([0-9]+), hc_state: (\S+), last-state-change-time: ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})")
_LOAD_VS = re.compile(r"\tvirtual-server (\S+)")
_LOAD_POOL = re.compile(r"\t\treal-server (\S+)")
_LOAD_MEMBER = re.compile(r"\t\tid:([0-9]+), status ([0-9]+), weight ([0-9]+)")
_TLS_CLIENT = "VS client-side SSL statistics:"
_TLS_SERVER = re.compile(r"VS server-side SSL statistics for server with id ([0-9]+):")
_TLS_OK = re.compile(r"\t# of succeeded HANDSHAKEs: ([0-9]+), average latency [0-9]+\(us\)")
_TLS_FAIL = re.compile(r"\t# of failed HANDSHAKEs: ([0-9]+)\( *[0-9]+%\)")
_DOS = re.compile(r"\[vs: (\S+)\]: (Total access alloc node =|Alloced num) ([0-9]+)")
_DOS_TRAILER = re.compile(r"=+Only show [0-9]+ items=+")
_KV = re.compile(r"\s*([A-Za-z][^:]{0,79}?)\s*:\s*(.*)")


class TriageParseError(ValueError):
    pass


def _lines(text: str) -> list[str]:
    if not isinstance(text, str):
        raise TriageParseError("device output is not text")
    lines = [line for line in text.replace("\r\n", "\n").split("\n") if line.strip()]
    if lines and _ECHO.match(lines[0]):
        lines = lines[1:]
    if not lines:
        raise TriageParseError("device output is empty")
    return lines


def parse_config_object(text: str, family: str, name: str) -> dict[str, Any]:
    head = "config " + family
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    try:
        start = lines.index(head)
    except ValueError:
        raise TriageParseError("configuration header is missing") from None
    fields: dict[str, list[str]] = {}
    members: list[dict[str, Any]] = []
    stack: list[tuple[str, str]] = []
    found = False
    for raw in lines[start + 1:]:
        try:
            words = shlex.split(raw, comments=False, posix=True)
        except ValueError:
            raise TriageParseError("configuration line is not tokenizable") from None
        verb, top = words[0], stack[-1][0] if stack else None
        if verb == "edit" and len(words) == 2 and top in (None, "config"):
            if top is None:
                if found or words[1] != name:
                    raise TriageParseError("configuration carries another object")
                found = True
            elif len(stack) == 2 and stack[1] == ("config", "pool_member"):
                members.append({"id": words[1], "fields": {}})
            stack.append(("edit", words[1]))
        elif verb == "config" and len(words) == 2 and top == "edit":
            stack.append(("config", words[1]))
        elif verb in ("set", "unset") and len(words) >= 2 and top == "edit":
            if verb == "unset":
                continue
            if len(stack) == 1:
                fields[words[1]] = words[2:]
            elif len(stack) == 3 and stack[1] == ("config", "pool_member"):
                members[-1]["fields"][words[1]] = words[2:]
        elif verb == "next" and len(words) == 1 and top == "edit":
            stack.pop()
        elif verb == "end" and len(words) == 1 and top in (None, "config"):
            if top is None:
                break
            stack.pop()
        else:
            raise TriageParseError("configuration line has an unknown shape")
    else:
        raise TriageParseError("configuration block is not closed")
    if not found:
        raise TriageParseError("configuration object is missing")
    return {"fields": fields, "members": members}


def _one(fields: dict[str, list[str]], key: str) -> str | None:
    value = fields.get(key)
    if value is None or len(value) == 0:
        return None
    if len(value) != 1:
        raise TriageParseError("configuration field has several values")
    return value[0]


def virtual_server_config(text: str, name: str) -> dict[str, Any]:
    fields = parse_config_object(text, "load-balance virtual-server", name)["fields"]
    status = _one(fields, "status")
    if status is None:
        raise TriageParseError("virtual server status is missing")
    return {
        "status": status, "type": _one(fields, "type"),
        "pool": _one(fields, "load-balance-pool"),
        "client_ssl_profile": _one(fields, "client-ssl-profile"),
        "waf_profile": _one(fields, "waf-profile"),
        "dos_profile": _one(fields, "dos-profile"),
    }


def pool_config(text: str, name: str) -> dict[str, Any]:
    parsed = parse_config_object(text, "load-balance pool", name)
    fields = parsed["fields"]
    members = []
    for member in parsed["members"]:
        status = _one(member["fields"], "status")
        if status is None or not member["id"].isdigit():
            raise TriageParseError("pool member status is missing")
        own = member["fields"].get("health-check-list", [])
        inherit = _one(member["fields"], "health-check-inherit")
        members.append({
            "id": int(member["id"]), "real_server": _one(member["fields"], "real-server"),
            "port": _one(member["fields"], "pool_member_service_port"), "status": status,
            "health_check": list(own) if inherit == "disable" else None,
        })
    control = _one(fields, "health-check-ctrl")
    return {
        "health_check_ctrl": control,
        "health_check": list(fields.get("health-check-list", [])) if control != "disable" else [],
        "members": members,
    }


def health_check_config(text: str, name: str) -> dict[str, Any]:
    fields = parse_config_object(text, "system health-check", name)["fields"]
    return {key: _one(fields, key) for key in ("type", "port", "interval", "timeout", "up-retry", "down-retry")
            if key in fields}


def parse_vs_stat(text: str, virtual_server: str, vdom: str) -> dict[str, Any]:
    lines = _lines(text)
    found = _VDOM.fullmatch(lines[0])
    if not found or found.group(1) != vdom:
        raise TriageParseError("vs_stat vdom header has an unknown shape")
    result: dict[str, Any] = {"availability": None, "counters": {}, "pools": []}
    owner: dict[str, Any] | None = None
    for line in lines[1:]:
        header = _VS_STAT.fullmatch(line)
        if header:
            if header.group(1) != virtual_server or result["availability"] is not None:
                raise TriageParseError("vs_stat carries another virtual server")
            if not STATE.fullmatch(header.group(2)):
                raise TriageParseError("vs_stat availability has an unknown shape")
            result["availability"], owner = header.group(2), result
            continue
        if result["availability"] is None:
            raise TriageParseError("vs_stat line precedes its virtual server")
        pool = _POOL.fullmatch(line)
        if pool:
            result["pools"].append({"name": pool.group(1), "members": []})
            owner = None
            continue
        member = _MEMBER_STAT.fullmatch(line)
        if member:
            if not result["pools"] or not STATE.fullmatch(member.group(2)):
                raise TriageParseError("vs_stat member has an unknown shape")
            owner = {"id": int(member.group(1)), "hc_state": member.group(2),
                     "last_state_change": member.group(3), "counters": {}}
            result["pools"][-1]["members"].append(owner)
            continue
        depth = 3 if owner is not None and owner is not result else 2
        counter = _COUNTER.fullmatch(line[depth:]) if line.startswith("\t" * depth) and line[depth:depth + 1] != "\t" else None
        if counter is None or owner is None:
            raise TriageParseError("vs_stat line has an unknown shape")
        owner["counters"][counter.group(1)] = int(counter.group(2))
    if result["availability"] is None:
        raise TriageParseError("vs_stat virtual server is missing")
    return result


def parse_slb_load(text: str, virtual_server: str) -> dict[str, Any]:
    lines = _lines(text)
    if not _VDOM.fullmatch(lines[0]):
        raise TriageParseError("slb_load vdom header has an unknown shape")
    servers: dict[str, list[dict[str, Any]]] = {}
    current: list[dict[str, Any]] | None = None
    pool: dict[str, Any] | None = None
    for line in lines[1:]:
        vs = _LOAD_VS.fullmatch(line)
        if vs:
            if vs.group(1) in servers:
                raise TriageParseError("slb_load repeats a virtual server")
            current, pool = servers.setdefault(vs.group(1), []), None
            continue
        found = _LOAD_POOL.fullmatch(line)
        if found and current is not None:
            pool = {"name": found.group(1), "members": []}
            current.append(pool)
            continue
        member = _LOAD_MEMBER.fullmatch(line)
        if member and pool is not None:
            pool["members"].append({"id": int(member.group(1)), "status": int(member.group(2)),
                                    "weight": int(member.group(3))})
            continue
        raise TriageParseError("slb_load line has an unknown shape")
    return {"present": virtual_server in servers, "pools": servers.get(virtual_server, [])}


def parse_tls_stats(text: str) -> dict[str, Any]:
    lines = _lines(text)
    sides: list[dict[str, Any]] = []
    for line in lines:
        server = _TLS_SERVER.fullmatch(line)
        if line == _TLS_CLIENT or server:
            sides.append({"side": "client" if server is None else "server",
                          "server_id": int(server.group(1)) if server else None,
                          "succeeded": None, "failed": None})
            continue
        if not sides or not line.startswith("\t"):
            raise TriageParseError("TLS statistics line has an unknown shape")
        succeeded, failed = _TLS_OK.fullmatch(line), _TLS_FAIL.fullmatch(line)
        if succeeded:
            sides[-1]["succeeded"] = int(succeeded.group(1))
        elif failed:
            sides[-1]["failed"] = int(failed.group(1))
    if (not sides or sides[0]["side"] != "client"
            or any(side["succeeded"] is None or side["failed"] is None for side in sides)):
        raise TriageParseError("TLS statistics miss handshake counters")
    return {"client": sides[0], "servers": sides[1:]}


def parse_dos(text: str, virtual_server: str) -> dict[str, Any]:
    lines = _lines(text)
    if len(lines) != 2 or not _DOS_TRAILER.fullmatch(lines[1]):
        raise TriageParseError("DoS output has an unknown shape")
    found = _DOS.fullmatch(lines[0])
    if not found or found.group(1) != virtual_server:
        raise TriageParseError("DoS output has an unknown shape")
    return {"metric": found.group(2).rstrip(" ="), "value": int(found.group(3))}


def parse_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in _lines(text):
        found = _KV.fullmatch(line)
        if not found or found.group(1) in values:
            raise TriageParseError("key-value output has an unknown shape")
        values[found.group(1)] = found.group(2).strip()
    return values


def _finding(rule: str, layer: str, obj: str, fact: str, sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {"id": rule, "layer": layer, "object": obj, "fact": fact, "sources": sources}


def evaluate(chain: dict[str, Any], sources: dict[str, dict[str, Any]], target: str) -> tuple[list, list, list]:
    findings: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    vs, pool = chain.get("vs") or {}, chain.get("pool") or {}
    vs_config, vs_runtime = vs.get("config"), vs.get("runtime")
    name = chain["virtual_server"]
    if vs_config and vs_config["status"] != "enable":
        findings.append(_finding("F-VS-DISABLED", "config", name, "status " + vs_config["status"],
                                 [sources["vs_config"]]))
    if vs_runtime and vs_runtime["availability"] != "HEALTHY":
        findings.append(_finding("F-VS-AVAIL", "runtime", name, "availability:" + vs_runtime["availability"],
                                 [sources["slb_vs_stat"]]))
    config_members = (pool.get("config") or {}).get("members")
    runtime_pools = vs_runtime["pools"] if vs_runtime else None
    runtime_members: dict[int, dict[str, Any]] = {}
    if runtime_pools is not None:
        for item in runtime_pools:
            for member in item["members"]:
                runtime_members[member["id"]] = member
    if config_members is not None:
        enabled = [m for m in config_members if m["status"] == "enable"]
        for member in config_members:
            if member["status"] != "enable":
                findings.append(_finding("F-MEMBER-DISABLED", "config", "%s id %d" % (pool["name"], member["id"]),
                                         "status " + member["status"], [sources["pool_config"]]))
        if pool["config"]["health_check"] == [] and not any(m["health_check"] for m in config_members):
            findings.append(_finding("F-NO-HC", "config", pool["name"], "pool has no health check",
                                     [sources["pool_config"]]))
        if runtime_pools is not None:
            down = []
            for member in enabled:
                state = runtime_members.get(member["id"])
                if state is not None and state["hc_state"] != "UP":
                    down.append(member)
                    checks = member["health_check"] or pool["config"]["health_check"]
                    findings.append(_finding(
                        "F-MEMBER-DOWN", "runtime", "%s id %d" % (pool["name"], member["id"]),
                        "real-server %s, hc_state: %s, last-state-change-time: %s, health-check %s" % (
                            member["real_server"] or "-", state["hc_state"], state["last_state_change"],
                            ",".join(checks) or "-"),
                        [sources["pool_config"], sources["slb_vs_stat"]]))
                    for check in checks[:1]:
                        steps.append({"tool": "fortios_diagnostics",
                                      "arguments": {"target": target, "recipe": "health_check_verify",
                                                    "interface": "", "health_check": check},
                                      "why": "repeat health check %s against real-server %s; address = its enrolled IPv4" % (
                                          check, member["real_server"])})
                    steps.append({"tool": "fortios_diagnostics",
                                  "arguments": {"target": target, "recipe": "ping", "interface": ""},
                                  "why": "reachability of real-server %s; address = its enrolled IPv4" % member["real_server"]})
            if enabled and not any(runtime_members.get(m["id"], {}).get("hc_state") == "UP" for m in enabled):
                findings.append(_finding("F-POOL-ALL-DOWN", "runtime", pool["name"],
                                         "no enabled member reports hc_state UP",
                                         [sources["pool_config"], sources["slb_vs_stat"]]))
            elif not enabled:
                findings.append(_finding("F-POOL-ALL-DOWN", "config", pool["name"], "pool has no enabled member",
                                         [sources["pool_config"]]))
            if down:
                hypotheses.append({"text": "backend service or health check path fails for %d member(s)" % len(down),
                                   "based_on": ["F-MEMBER-DOWN"]})
            configured, measured = {m["id"] for m in config_members}, set(runtime_members)
            names = {item["name"] for item in runtime_pools}
            if configured != measured or names - {pool["name"]}:
                findings.append(_finding(
                    "F-MISMATCH", "config", pool["name"],
                    "config member ids %s, vs_stat member ids %s, vs_stat pools %s" % (
                        sorted(configured), sorted(measured), sorted(names)),
                    [sources["pool_config"], sources["slb_vs_stat"]]))
    load = chain.get("load")
    if load is not None and config_members is not None:
        loaded = {m["id"] for item in load["pools"] for m in item["members"]}
        configured = {m["id"] for m in config_members}
        if not load["present"] or loaded != configured:
            findings.append(_finding("F-MISMATCH", "runtime", name,
                                     "slb_load present %s, member ids %s, config member ids %s" % (
                                         load["present"], sorted(loaded), sorted(configured)),
                                     [sources["pool_config"], sources["slb_load"]]))
    tls = (chain.get("tls") or {}).get("runtime")
    if tls is not None:
        for side in [tls["client"], *tls["servers"]]:
            if side["failed"] > 0:
                label = "client-side" if side["side"] == "client" else "server-side id %d" % side["server_id"]
                findings.append(_finding("F-TLS-FAIL", "runtime", name,
                                         "%s failed HANDSHAKEs: %d, succeeded: %d" % (
                                             label, side["failed"], side["succeeded"]),
                                         [sources["tls_handshake_stats"]]))
        if any(f["id"] == "F-TLS-FAIL" for f in findings):
            hypotheses.append({"text": "TLS negotiation fails for part of the clients or real servers",
                               "based_on": ["F-TLS-FAIL"]})
    dos = (chain.get("dos") or {}).get("runtime") or {}
    for query, value in sorted(dos.items()):
        findings.append(_finding("F-DOS", "runtime", name, "%s %d" % (value["metric"], value["value"]),
                                 [sources[query]]))
    waf = chain.get("waf") or {}
    if waf.get("config") is not None:
        findings.append(_finding("F-WAF", "config", waf["config"]["profile"], "WAF profile attached",
                                 [sources["waf_config"]]))
    if waf.get("runtime") is not None:
        findings.append(_finding("F-WAF", "runtime", "waf-signature-status",
                                 "; ".join("%s: %s" % item for item in sorted(waf["runtime"].items())),
                                 [sources["waf_signature_status"]]))
    return findings, hypotheses, steps


def verdict(findings: list[dict[str, Any]], missing: list[dict[str, Any]], executed: set[str]) -> str:
    if missing or any(step not in executed for step in REQUIRED_STEPS):
        return "incomplete"
    if any(finding["id"] in FAULT_RULES for finding in findings):
        return "fault_found"
    return "no_fault_in_checked_data"
