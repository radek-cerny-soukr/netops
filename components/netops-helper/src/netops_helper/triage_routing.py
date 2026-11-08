from __future__ import annotations

import ipaddress
import re

from .triage_health import (REASONS, SDWAN_NOT_RUNNING, Unparsed, UnsupportedPlatform, _lines, _utc,
                            sdwan_health)

IDENTITIES = frozenset({
    ("FortiGate-60F", "7.6.8", "3744"),
})
STEPS = ("system_status", "route_lookup", "policy_routes_ipv4", "sdwan_health", "arp_table")
PLANNED_READS = len(STEPS)
NOT_SIMULATED = (
    "policy route and SD-WAN rule match on source, ports, protocol and ingress interface",
    "SD-WAN member selection inside a matching rule",
    "firewall policy, NAT and session state",
    "recursive next-hop resolution",
)
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"


def identity(text):
    from netops_core import platforms
    try:
        found = tuple(platforms.version_record(text))
    except platforms.VersionRecordError:
        raise UnsupportedPlatform("config_platform_not_supported: one exact FortiOS identity is required") from None
    if found not in IDENTITIES:
        raise UnsupportedPlatform("config_platform_not_supported: triage_routing is not qualified for this model and build")
    return {"product": found[0], "version": found[1], "build": found[2]}


def route_lookup(text):
    lines = [line for line in _lines(text) if line.strip()]
    body = [line.strip() for line in lines if not re.fullmatch(r"Routing table for VRF=\d+", line.strip())]
    if body == ["% Network not in table"]:
        return None
    if len(body) < 3 or not body[0].startswith("Routing entry for "):
        raise Unparsed()
    prefix = re.fullmatch(r"Routing entry for (" + _IPV4 + r"/\d{1,2})", body[0])
    known = re.fullmatch(r'Known via "([^"]+)", distance (\d+), metric (\d+)(, best)?(?:, .*)?', body[1])
    if not prefix or not known:
        raise Unparsed()
    route = {"prefix": str(ipaddress.IPv4Network(prefix.group(1))), "protocol": known.group(1),
             "distance": int(known.group(2)), "metric": int(known.group(3)), "best": bool(known.group(4)),
             "next_hops": []}
    for line in body[2:]:
        if re.fullmatch(r"Last update \S+ ago", line):
            continue
        hop = re.fullmatch(r"(\* )?(?:vrf \d+ )?(?:is )?directly connected, ([^\s,]+)(?:, .*)?", line)
        if hop:
            route["next_hops"].append({"fib": bool(hop.group(1)), "gateway": None, "interface": hop.group(2),
                                       "recursive": []})
            continue
        hop = re.fullmatch(r"(\* )?vrf \d+ (" + _IPV4 + r")(.*)", line) or re.fullmatch(r"(\* )(" + _IPV4 + r")(.*)", line)
        if hop:
            rest = hop.group(3)
            via = re.search(r"(?:^|,) ?via ([^\s,]+)", rest)
            route["next_hops"].append({"fib": bool(hop.group(1)), "gateway": hop.group(2),
                                       "interface": via.group(1) if via else None,
                                       "recursive": re.findall(r"\(recursive via (\S+)", rest)})
            continue
        more = re.fullmatch(r"\(recursive via (\S+)[^()]*\)(?:, .*)?", line)
        if more and route["next_hops"]:
            route["next_hops"][-1]["recursive"].append(more.group(1))
            continue
        raise Unparsed()
    if not route["next_hops"]:
        raise Unparsed()
    for item in route["next_hops"]:
        if item["gateway"] is not None:
            ipaddress.IPv4Address(item["gateway"])
    return route


def _covers(value, address):
    try:
        if "/" in value:
            base, mask = value.split("/", 1)
            mask_int = int(ipaddress.IPv4Address(mask))
            return int(address) & mask_int == int(ipaddress.IPv4Address(base)) & mask_int
        if "-" in value:
            low, high = value.split("-", 1)
            return ipaddress.IPv4Address(low) <= address <= ipaddress.IPv4Address(high)
        return ipaddress.IPv4Address(value) == address
    except ValueError:
        raise Unparsed() from None


def policy_routes(text, address):
    target = ipaddress.IPv4Address(address)
    entries = []
    for line in _lines(text):
        stripped = line.strip()
        if not stripped:
            continue
        if re.fullmatch(r"list route policy info\(vf=[^()\s]+\):", stripped):
            if entries:
                raise Unparsed()
            continue
        head = re.match(r"id=(\d+)\b", stripped)
        if head:
            service = re.search(r"\bvwl_service=\d+\(([^()]*)\)", stripped)
            gateway = re.search(r"\bgwy=(" + _IPV4 + r")\b", stripped)
            entries.append({"id": int(head.group(1)), "service": service.group(1) if service else None,
                            "oif": [name or number for number, name in
                                    re.findall(r"\boif=(\d+)(?:\(([^()]*)\))?", stripped)],
                            "gateway": gateway.group(1) if gateway else None,
                            "destination": None, "evaluable": True})
        elif not entries:
            raise Unparsed()
        entry = entries[-1]
        if not head and re.match(r"path\(\d+\):", stripped):
            entry["oif"] += [name or number for number, name in
                             re.findall(r"\boif=(\d+)(?:\(([^()]*)\))?", stripped)]
            gateway = re.search(r"\bgwy=(" + _IPV4 + r")\b", stripped)
            if gateway and entry["gateway"] is None:
                entry["gateway"] = gateway.group(1)
        if any(value != "0" for value in re.findall(r"negate(?:=(\S+))?", stripped)):
            entry["evaluable"] = False
        if stripped.startswith("internet service"):
            entry["evaluable"] = False
        dest = re.fullmatch(r"destination(?: wildcard)?\((\d+)\):(.*)", stripped)
        if stripped.startswith("destination") and not dest:
            raise Unparsed()
        if dest:
            values = dest.group(2).split()
            if len(values) != int(dest.group(1)) or entry["destination"] is not None:
                raise Unparsed()
            entry["destination"] = any(_covers(value, target) for value in values)
    total = len(entries)
    covering = []
    unevaluated = []
    for entry in entries:
        if not entry["evaluable"] or entry["destination"] is None:
            unevaluated.append(entry["id"])
        elif entry["destination"]:
            covering.append({key: entry[key] for key in ("id", "service", "oif", "gateway")})
    return {"entries": total, "covering": covering, "unevaluated": unevaluated}


_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"


def arp_table(text):
    rows = []
    header = 0
    for line in _lines(text):
        stripped = line.strip()
        if not stripped:
            continue
        if re.fullmatch(r"Address\s+Age\(min\)\s+Hardware Addr\s+Interface", stripped):
            header += 1
            continue
        row = re.fullmatch(r"(" + _IPV4 + r")\s+(\S+)\s+(" + _MAC + r")\s+(\S+)", stripped)
        if not row or not header:
            raise Unparsed()
        ipaddress.IPv4Address(row.group(1))
        rows.append({"address": row.group(1), "interface": row.group(4),
                     "complete": row.group(3).replace(":", "").strip("0") != ""})
    if header != 1:
        raise Unparsed()
    return rows


def _source(query, answer, moment):
    return {"call": "triage_routing", "query": query, "content_sha256": answer["content_sha256"],
            "captured_at": _utc(moment)}


def _evaluate(address, parsed, sources):
    findings = []
    hypotheses = []
    next_steps = []
    route = parsed.get("route_lookup", False)
    if route is None:
        findings.append({"id": "F-ROUTE-NONE", "layer": "routing", "object": "route:" + address,
                         "fact": "% Network not in table", "sources": [sources["route_lookup"]]})
        next_steps.append({"tool": "ssh_read", "arguments": {"platform": "fortinet", "query": "routing_table"},
                           "why": "full IPv4 table: which covering or default route is absent"})
    hops = [hop for hop in (route or {}).get("next_hops", ()) if hop["fib"]] if route else []
    members = parsed.get("sdwan_health") or []
    for hop in hops:
        if hop["recursive"] or hop["interface"] is None:
            continue
        for member in members:
            if member["member"] == hop["interface"] and member["state"] == "dead":
                findings.append({"id": "F-EGRESS-SDWAN-DEAD", "layer": "sdwan",
                                 "object": "sdwan:%s:%d" % (member["health_check"], member["seq"]),
                                 "fact": "next hop via %s; Seq(%d %s): state(dead)" % (
                                     hop["interface"], member["seq"], member["member"]),
                                 "sources": [sources["route_lookup"], sources["sdwan_health"]]})
                step = {"tool": "ssh_read", "arguments": {"platform": "fortinet", "query": "sdwan_member_detail",
                                                          "parameters": {"member": str(member["seq"])}},
                        "why": "member detail of the dead egress member (the member must be enrolled)"}
                if step not in next_steps:
                    next_steps.append(step)
    arp = parsed.get("arp_table")
    if arp is not None:
        for hop in hops:
            if hop["gateway"] is None or hop["recursive"]:
                continue
            if hop["interface"] is None:
                continue
            rows = [row for row in arp if row["address"] == hop["gateway"] and row["interface"] == hop["interface"]]
            if any(not row["complete"] for row in rows) and not any(row["complete"] for row in rows):
                findings.append({"id": "F-NEXTHOP-ARP-INCOMPLETE", "layer": "neighbor", "object": "arp:" + hop["gateway"],
                                 "fact": "gateway %s has an ARP entry with hardware address 00:00:00:00:00:00" % hop["gateway"],
                                 "sources": [sources["route_lookup"], sources["arp_table"]]})
            elif not rows:
                if any(row["address"] == hop["gateway"] for row in arp):
                    text = ("gateway %s has no ARP entry on egress interface %s (it is in the ARP table only on "
                            "another interface): it may not have answered ARP there, or the entry aged out" % (
                                hop["gateway"], hop["interface"]))
                else:
                    text = ("gateway %s is not in the ARP table: it may not have answered ARP, "
                            "or the entry aged out" % hop["gateway"])
                hypotheses.append({"id": "H-NEXTHOP-NO-ARP", "basis": [sources["route_lookup"], sources["arp_table"]],
                                   "text": text})
    proute = parsed.get("policy_routes_ipv4")
    if proute:
        for entry in proute["covering"]:
            hypotheses.append({"id": "H-POLICY-ROUTE", "basis": [sources["policy_routes_ipv4"]],
                               "text": "policy route id=%d%s covers %s; when its source, port and ingress match, "
                                       "it overrides the routing-table result" % (
                                           entry["id"], " (SD-WAN rule %s)" % entry["service"] if entry["service"] else "",
                                           address)})
        if proute["unevaluated"]:
            hypotheses.append({"id": "H-POLICY-UNEVALUATED", "basis": [sources["policy_routes_ipv4"]],
                               "text": "policy route ids %s use internet services, negation or no destination "
                                       "list and were not evaluated" % ", ".join(str(i) for i in proute["unevaluated"])})
    return findings, hypotheses, next_steps


def run(read, clock, address):
    started = clock()
    target = str(ipaddress.IPv4Address(address))
    first = read("system_status", None)
    if not first.get("ok"):
        raise UnsupportedPlatform("config_platform_not_supported: the identity read failed")
    ident = identity(first["text"])
    parsed = {}
    sources = {}
    missing = []
    checked = ["system_status"]
    for query in STEPS[1:]:
        moment = clock()
        answer = read(query, {"address": target} if query == "route_lookup" else None)
        if not answer.get("ok"):
            reason = answer.get("reason")
            missing.append({"step": query, "reason": reason if reason in REASONS else "device_cli_error"})
            continue
        text = answer["text"]
        if query == "sdwan_health" and (not text.strip() or text.strip() in SDWAN_NOT_RUNNING):
            missing.append({"step": query, "reason": "not_applicable"})
            continue
        if not text.strip():
            missing.append({"step": query, "reason": "empty"})
            continue
        sources[query] = _source(query, answer, moment)
        try:
            if query == "route_lookup":
                parsed[query] = route_lookup(text)
            elif query == "policy_routes_ipv4":
                parsed[query] = policy_routes(text, target)
            elif query == "sdwan_health":
                parsed[query] = sdwan_health(text)
            else:
                parsed[query] = arp_table(text)
        except (Unparsed, ValueError):
            parsed.pop(query, None)
            missing.append({"step": query, "reason": "unparsed"})
        else:
            checked.append(query)
    findings, hypotheses, next_steps = _evaluate(target, parsed, sources)
    gaps = [item for item in missing if item["reason"] != "not_applicable"]
    if gaps:
        verdict = "incomplete"
    elif findings:
        verdict = "fault_found"
    else:
        verdict = "no_fault_in_checked_data"
    arp = parsed.get("arp_table")
    route = parsed.get("route_lookup")
    gateways = []
    if route and arp is not None:
        for hop in route["next_hops"]:
            if hop["fib"] and hop["gateway"] and not hop["recursive"]:
                rows = [row for row in arp if row["address"] == hop["gateway"] and row["interface"] == hop["interface"]]
                gateways.append({"gateway": hop["gateway"],
                                 "arp": "unknown" if hop["interface"] is None else
                                 "absent" if not rows else
                                 "complete" if any(row["complete"] for row in rows) else "incomplete"})
    sdwan = parsed.get("sdwan_health")
    chain = {
        "route": route,
        "policy_routes": parsed.get("policy_routes_ipv4"),
        "sdwan": None if sdwan is None else {
            "egress_members": [m for m in sdwan if route and m["member"] in
                               {hop["interface"] for hop in route["next_hops"] if hop["fib"]}],
            "member_names_shown": all(m["member"] for m in sdwan)},
        "gateways": gateways if route and arp is not None else None,
    }
    return {
        "ok": True,
        "identity": ident,
        "address": target,
        "started_at": _utc(started),
        "finished_at": _utc(clock()),
        "chain": chain,
        "findings": findings,
        "hypotheses": hypotheses,
        "next_steps": next_steps,
        "missing": missing,
        "checked": checked,
        "dataplane_simulated": False,
        "not_simulated": list(NOT_SIMULATED),
        "verdict": verdict,
    }
