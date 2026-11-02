from __future__ import annotations

import re

from .triage_health import REASONS, Unparsed, UnsupportedPlatform, _lines, _utc, identity

STEPS = (
    ("identity", "system_status"),
    ("tunnel", "ipsec_summary"),
    ("route", "routing_table"),
    ("ike", "ike_errors"),
)
PLANNED_READS = len(STEPS)
REQUIRED = frozenset(query for _, query in STEPS)
TUNNEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,34}")

_SUMMARY = re.compile(
    r"'([^']+)'\s+(\S+)\s+selectors\(total,up\):\s*(\d+)/(\d+)\s+"
    r"rx\(pkt,err\):\s*(\d+)/(\d+)\s+tx\(pkt,err\):\s*(\d+)/(\d+)")
_ROUTE = re.compile(r"([A-Za-z][A-Za-z0-9 *]{0,7}?)\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})(?=\s|$)(.*)")
_INTERFACE = re.compile(r"via ([A-Za-z0-9_.-]+) tunnel \S+|via \S+, ([^,\s()]+)|directly connected, ([^,\s()]+)")
_COUNTER = re.compile(r"([A-Za-z0-9_.-]+):((?: \d+)+)")


def valid_tunnel(name):
    return isinstance(name, str) and TUNNEL_NAME.fullmatch(name) is not None


def ipsec_summary(text):
    tunnels = []
    for line in _lines(text):
        if not line.strip():
            continue
        found = _SUMMARY.fullmatch(line.strip())
        if not found:
            raise Unparsed()
        numbers = [int(value) for value in found.groups()[2:]]
        tunnels.append({"name": found.group(1), "peer": found.group(2),
                        "selectors_total": numbers[0], "selectors_up": numbers[1],
                        "rx_packets": numbers[2], "rx_errors": numbers[3],
                        "tx_packets": numbers[4], "tx_errors": numbers[5]})
    return tunnels


def routing_table(text):
    routes = []
    prefix = None
    for line in _lines(text):
        if not line.strip():
            continue
        head = _ROUTE.fullmatch(line)
        if head:
            prefix = (head.group(2), " ".join(head.group(1).split()))
            rest = head.group(3)
        elif prefix is not None and (line[:1].isspace() or line.startswith("[")):
            rest = line
        else:
            continue
        for match in _INTERFACE.finditer(rest):
            routes.append({"prefix": prefix[0], "code": prefix[1],
                           "interface": next(group for group in match.groups() if group)})
    if prefix is None:
        raise Unparsed()
    return routes


def ike_errors(text):
    counters = {}
    for line in _lines(text):
        if not line.strip():
            continue
        found = _COUNTER.fullmatch(line.strip())
        if not found or found.group(1) in counters:
            raise Unparsed()
        counters[found.group(1)] = sum(int(value) for value in found.group(2).split())
    if not counters:
        raise Unparsed()
    return {"counters": len(counters), "nonzero": {name: value for name, value in counters.items() if value}}


PARSERS = {"ipsec_summary": ipsec_summary, "routing_table": routing_table, "ike_errors": ike_errors}


def _instance(name, tunnel):
    return name == tunnel or re.fullmatch(re.escape(tunnel) + r"_\d+", name) is not None


def findings_for(tunnel, instances, routes, sources):
    found = []

    def add(rule, query, obj, fact):
        found.append({"id": rule, "layer": "runtime", "object": "vpn:" + obj, "fact": fact, "sources": [sources[query]]})

    if instances is None:
        return found
    if not instances:
        add("F-VPN-NOT-FOUND", "ipsec_summary", tunnel, "tunnel not in get vpn ipsec tunnel summary")
        return found
    for item in instances:
        counts = "selectors(total,up): %d/%d" % (item["selectors_total"], item["selectors_up"])
        if item["selectors_up"] == 0:
            add("F-VPN-DOWN", "ipsec_summary", item["name"], counts)
        elif item["selectors_up"] < item["selectors_total"]:
            add("F-VPN-PARTIAL", "ipsec_summary", item["name"], counts)
        if item["selectors_up"] > 0 and item["rx_packets"] == 0:
            add("F-VPN-NO-RX", "ipsec_summary", item["name"],
                "selectors up %d but rx(pkt) 0" % item["selectors_up"])
        if item["rx_errors"] > 0 or item["tx_errors"] > 0:
            add("F-VPN-ERRORS", "ipsec_summary", item["name"],
                "rx(err) %d, tx(err) %d" % (item["rx_errors"], item["tx_errors"]))
    if routes is not None and not routes:
        add("F-VPN-NO-ROUTE", "routing_table", tunnel, "no route in routing-table via " + tunnel)
    return found


def run(read, clock, tunnel):
    if not valid_tunnel(tunnel):
        raise ValueError("invalid_argument: tunnel must match [A-Za-z0-9][A-Za-z0-9_.-]{0,34}")
    started = clock()
    missing = []
    parsed = {}
    sources = {}
    checked = []
    first = read("system_status")
    if not first.get("ok"):
        raise UnsupportedPlatform("config_platform_not_supported: the identity read failed")
    ident = identity(first["text"])
    for _, query in STEPS[1:]:
        moment = clock()
        answer = read(query)
        if not answer.get("ok"):
            reason = answer.get("reason")
            missing.append({"step": query, "reason": reason if reason in REASONS else "device_cli_error"})
            continue
        if not answer["text"].strip() and query != "ipsec_summary":
            missing.append({"step": query, "reason": "empty"})
            continue
        sources[query] = {"call": "triage_vpn", "query": query,
                          "content_sha256": answer["content_sha256"], "captured_at": _utc(moment)}
        try:
            parsed[query] = PARSERS[query](answer["text"])
        except Unparsed:
            missing.append({"step": query, "reason": "unparsed"})
        else:
            checked.append(query)
    instances = None
    if "ipsec_summary" in parsed:
        instances = [item for item in parsed["ipsec_summary"] if _instance(item["name"], tunnel)]
    routes = None
    if "routing_table" in parsed:
        routes = [item for item in parsed["routing_table"] if _instance(item["interface"], tunnel)]
        routes = [item for number, item in enumerate(routes) if item not in routes[:number]]
    findings = findings_for(tunnel, instances, routes, sources)
    if missing:
        verdict = "incomplete"
    elif findings:
        verdict = "fault_found"
    else:
        verdict = "no_fault_in_checked_data"
    return {
        "ok": True,
        "tunnel": tunnel,
        "identity": ident,
        "started_at": _utc(started),
        "finished_at": _utc(clock()),
        "chain": {"tunnel": {"name": tunnel, "instances": instances}, "routes": routes,
                  "ike_errors": parsed.get("ike_errors")},
        "findings": findings,
        "hypotheses": [],
        "next_steps": [],
        "missing": missing,
        "checked": ["system_status"] + checked,
        "verdict": verdict,
    }
