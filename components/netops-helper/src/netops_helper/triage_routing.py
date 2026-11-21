from __future__ import annotations

import ipaddress
import re

from .triage_health import (missing_read, SDWAN_NOT_RUNNING, Unparsed, UnsupportedPlatform, _lines, _utc,
                            firmware_fields, firmware_support, in_vdom, sdwan_health, vdom_scope)

# Tested identities (G00): not a gate; another model or build runs with firmware_support "untested" and a warning.
IDENTITIES = frozenset({
    ("FortiGate-60F", "7.6.8", "3744"),
    ("FortiGate-80F", "8.0.2", "0251"),
})
STEPS = ("system_status", "route_lookup", "policy_routes_ipv4", "sdwan_health", "arp_table")
PLANNED_READS = len(STEPS)
NOT_SIMULATED = (
    "policy route and SD-WAN rule match on source, ports, protocol and ingress interface",
    "SD-WAN member selection inside a matching rule",
    "firewall policy, NAT and session state",
    "recursive next-hop resolution",
)
_INTERFACE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}")
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"


def vdom_mode(text):
    found = re.search(r"^Virtual domain configuration: *(\S+) *$", text, re.MULTILINE)
    return found.group(1) if found else None


def identity(text):
    from netops_core import platforms
    try:
        found = tuple(platforms.version_record(text))
    except platforms.VersionRecordError:
        raise UnsupportedPlatform("config_platform_not_supported: one exact FortiOS identity is required") from None
    from .fortios_diagnostics import well_formed
    if not well_formed(found):
        raise UnsupportedPlatform("config_platform_not_supported: one exact FortiOS identity is required")
    if not found[0].startswith(platforms.PRODUCT_HARDWARE["fortios"]):
        raise UnsupportedPlatform("config_platform_not_supported: the target is not a FortiOS product")
    return {"product": found[0], "version": found[1], "build": found[2]}


_VRF = r"(?:\d+|default\(\d+\))"


def _route_entry(body):
    if len(body) < 2:
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
        hop = re.fullmatch(r"(\* )?(?:vrf " + _VRF + r" )?(?:is )?directly connected, ([^\s,]+)(?:, .*)?", line)
        if hop:
            route["next_hops"].append({"fib": bool(hop.group(1)), "gateway": None, "interface": hop.group(2),
                                       "recursive": []})
            continue
        hop = (re.fullmatch(r"(\* )?vrf " + _VRF + r" (" + _IPV4 + r")(.*)", line)
               or re.fullmatch(r"(\* )(" + _IPV4 + r")(.*)", line))
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


def route_lookup(text):
    lines = [line for line in _lines(text) if line.strip()]
    body = [line.strip() for line in lines if not re.fullmatch(r"Routing table for VRF=" + _VRF, line.strip())]
    if body == ["% Network not in table"]:
        return None
    if len(body) < 3 or not body[0].startswith("Routing entry for "):
        raise Unparsed()
    blocks = []
    for line in body:
        if line.startswith("Routing entry for "):
            blocks.append([])
        blocks[-1].append(line)
    routes = [_route_entry(block) for block in blocks]
    if len(routes) == 1:
        return routes[0]
    # FortiOS 8.0.2 lists every route of the matching prefix (e.g. a non-best BGP route beside the connected one)
    best = [route for route in routes if route["best"]]
    if len(best) != 1:
        raise Unparsed()
    return best[0]


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


def _member_interface(member):
    # FortiOS names allow only letters, digits, space, "-" and "_" (Fortinet naming rules,
    # https://community.fortinet.com/fortigate-3/technical-tip-naming-rules-and-character-restrictions-98552),
    # so a "/" in a member name always separates "<interface>/<member name>" (8.0.2: LTE-1/MOD-1-LTE).
    name = member["member"]
    return name.split("/", 1)[0] if name else None


def _fib_interfaces(route):
    return {hop["interface"] for hop in (route or {}).get("next_hops", ())
            if hop["fib"] and hop["interface"] is not None}


def _source(query, answer, moment):
    return {"call": "triage_routing", "query": query, "content_sha256": answer["content_sha256"],
            "captured_at": _utc(moment)}


def _evaluate(address, parsed, sources, alias):
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
            if _member_interface(member) == hop["interface"] and member["state"] == "dead":
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
    interface = next((hop["interface"] for hop in hops if hop["interface"] is not None
                      and _INTERFACE_NAME.fullmatch(hop["interface"])), None)
    if interface is not None:
        next_steps.extend(
            {"tool": "fortios_diagnostics",
             "arguments": {"target": alias, "recipe": recipe, "address": address, "interface": interface},
             "why": "measure from the firewall through %s, the interface of the first forwarding next hop "
                    "(the target must enroll the recipe, the address and this interface)" % interface}
            for recipe in ("ping", "traceroute")
        )
    return findings, hypotheses, next_steps


def _junos_route(text, address):
    from .tables import route_junos

    if not text.strip():
        return []
    rows, unknown = route_junos(text, include_next_hop_type=True)
    requested = ipaddress.IPv4Address(address)
    if (unknown or not rows or any(requested not in ipaddress.ip_network(row["prefix"]) for row in rows)
            or not re.search(r"(?m)^[ \t]*State: <[^>\r\n]*\bActive\b", text)):
        raise Unparsed()
    return rows


def _junos_ospf(text):
    from .tables import ospf_neighbors

    if not text.strip() or text.strip() == "OSPF is not running":
        return []
    rows, unknown = ospf_neighbors(text, "junos")
    if unknown or not re.search(r"(?m)^Address\s+(?:Intf|Interface)\s+State\s+ID\s+Pri\s+Dead", text):
        raise Unparsed()
    return rows


def _junos_bgp(text):
    from .tables import junos_bgp_peers

    rows, unknown = junos_bgp_peers(text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines and lines[-1] == "BGP is not running" and not unknown and not rows:
        return []
    counts = re.findall(r"(?m)^Groups: \d+ Peers: (\d+) Down peers: (\d+)[ \t]*$", text)
    if (unknown or not counts or sum(int(total) for total, _ in counts) != len(rows)
            or sum(int(down) for _, down in counts) != sum(row["state"] != "Established" for row in rows)):
        raise Unparsed()
    return rows


def run_junos(profile, read, clock, address):
    from .triage_health import junos_checks, junos_verdict

    result, parsed = junos_checks(profile, "triage_routing", read, clock, {
        "route_lookup": lambda text: _junos_route(text, address),
        "ospf_neighbors": _junos_ospf,
        "bgp_summary": _junos_bgp,
    }, {"route_lookup": {"address": address}})
    result["address"] = address
    result["chain"] = parsed
    findings = []
    for rule, query, data in (
        ("no_active_route", "route_lookup", [{"address": address}] if parsed.get("route_lookup") == [] else []),
        ("discarding_route", "route_lookup", [
            row for row in parsed.get("route_lookup", ()) if row.get("next_hop_type") in {"Discard", "Reject"}
        ]),
        ("ospf_adjacency_incomplete", "ospf_neighbors", [
            row for row in parsed.get("ospf_neighbors", ()) if row["state"] in {"down", "attempt", "init",
                                                                               "exstart", "exchange", "loading"}
        ]),
        ("bgp_peer_down", "bgp_summary", [
            row for row in parsed.get("bgp_summary", ()) if row["state"] != "Established"
        ]),
    ):
        findings.extend({"rule": rule, "fact": fact, "sources": [result["sources"][query]]} for fact in data)
    return junos_verdict(result, findings)


def run(read, clock, address, alias):
    started = clock()
    target = str(ipaddress.IPv4Address(address))
    first = read("system_status", None)
    if not first.get("ok"):
        raise UnsupportedPlatform("config_platform_not_supported: the identity read failed")
    ident = identity(first["text"])
    support = firmware_support(ident, IDENTITIES, "triage_routing")
    scope = vdom_scope(first["text"])
    parsed = {}
    sources = {}
    missing = []
    checked = ["system_status"]
    for query in STEPS[1:]:
        moment = clock()
        answer = read(query, {"address": target} if query == "route_lookup" else None)
        if not answer.get("ok"):
            missing.append(missing_read(query, answer))
            continue
        if not in_vdom(scope, answer):
            # Multi-VDOM: data not read in the verified session VDOM never feeds the verdict.
            missing.append({"step": query, "reason": "vdom_unverified"})
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
    findings, hypotheses, next_steps = _evaluate(target, parsed, sources, alias)
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
    fib_interfaces = _fib_interfaces(route)
    chain = {
        "route": route,
        "policy_routes": parsed.get("policy_routes_ipv4"),
        "sdwan": None if sdwan is None else {
            "egress_members": [m for m in sdwan if _member_interface(m) in fib_interfaces],
            "member_names_shown": all(m["member"] for m in sdwan)},
        "gateways": gateways if route and arp is not None else None,
    }
    return {
        "ok": True,
        "identity": ident,
        "vdom_mode": vdom_mode(first["text"]),
        "vdom": scope["vdom"] if scope else None,
        "current_vdom": scope["vdom"] if scope else None,
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
        **firmware_fields(support),
    }


# G51 IOS diagnostics are individual read-only catalogue queries, independent of
# the FortiOS routing triage above. Full protocol/CEF/PBR details remain raw CLI;
# only the address/RIB/VRF outputs below have normalized table adapters.
IOS_TABLES = {
    'vrfs': 'vrf', 'vrf_route_lookup': 'route', 'vrf_arp_table': 'neighbor_l3',
    'vrf_ip_interfaces': 'ip_interface', 'ipv6_route_table': 'route',
    'ip_interface_details': 'ip_interface', 'ipv6_interface_details': 'ip_interface',
}


def ios_vrfs(table, text):
    from . import tables as t
    previous = None
    def handle(raw, value):
        nonlocal previous
        if re.fullmatch(r'Name\s+Default RD\s+Interfaces?', value):
            return []
        match = re.fullmatch(r'(\S+)\s+((?:\d+(?:\.\d+)?|(?:\d{1,3}\.){3}\d{1,3}):\d+|<not set>)(?:\s+(\S+))?', value)
        if match:
            identifier = match[2].split(':', 1)[0]
            if identifier.count('.') == 3:
                ipaddress.IPv4Address(identifier)
            elif '.' in identifier and any(int(part) > 65535 for part in identifier.split('.')):
                return None
            previous = match[1]
            return t.record(table, name=previous, rd=match[2] if match[2] != '<not set>' else None,
                            interfaces=[t.port(match[3])] if match[3] else [])
        if previous and re.fullmatch(r'\S+', value):
            return t.record(table, name=previous, interfaces=[t.port(value)])
        return None
    rows, unknown = t.scan(text, handle)
    merged = {}
    for row in rows:
        if row['name'] not in merged:
            merged[row['name']] = row
        else:
            merged[row['name']]['interfaces'].extend(row['interfaces'])
    return list(merged.values()), unknown


def ios_vrf_interfaces(table, text):
    from . import tables as t
    def handle(raw, value):
        if re.fullmatch(r'Interface\s+IP-Address\s+VRF\s+Protocol', value):
            return []
        match = re.fullmatch(r'(\S+)\s+(\S+)\s+(\S+)\s+(up|down)', value)
        if match:
            if match[2] == 'unassigned':
                return []
            return t.record(table, interface=t.port(match[1]), ip=str(ipaddress.IPv4Address(match[2])),
                            vrf=match[3], oper_status=match[4])
        return None
    return t.scan(text, handle)


def ios_read(query, text, parameters, state, platform="cisco_ios"):
    """Normalize a complete IOS capture, preserving CLI output separately in ssh_read."""
    from . import tables as t
    if query not in IOS_TABLES:
        return {}
    result = t.parse(platform, IOS_TABLES[query], query, text, status=state)
    if (parameters or {}).get('vrf'):
        for row in result['records']:
            row['vrf'] = parameters['vrf']
    return {'normalized': result}


def ios_vrf_routes(table, text):
    from . import tables as t
    body = re.sub(r'(?m)^Routing Table: [^\r\n]+[\r\n]*', '', text)
    rows, unknown = t.route_ios(body)
    if rows and all(row['next_hop'] is None and row['interface'] is None for row in rows):
        return [], [{'line': n, 'text': raw} for n, raw in enumerate(text.splitlines(), 1) if raw.strip()]
    return rows, unknown



# IOS runbooks report local observations, with line references into the redacted
# catalogue snapshot. Each check stays independent of unavailable reads.
CISCO_RUNBOOK_TESTED = {
    "cisco_ios": ("IOS", ("15.9(3)M12", "15.2(20200924:215240)")),
    "cisco_xe": ("IOS XE", ("17.18.2",)),
}


def cisco_runbook_plan(tool, args):
    address = args.get("address", args.get("dst"))
    vrf = args.get("vrf")
    route = ("vrf_route_lookup", {"address": address, "vrf": vrf}) if vrf else ("route_lookup", {"address": address})
    if tool == "triage_port":
        reads = [("interface_details", {"interface": args["interface"]}), ("stp_tree", {})]
    elif tool == "triage_routing":
        reads = [route, ("vrf_arp_table", {"vrf": vrf})] if vrf else [route]
        if args.get("sla_id") is not None:
            reads.append(("ip_sla_statistics", {}))
    else:
        reads = [("ip_interface_details", {"interface": args["interface"]}), route, ("cef_lookup", {"address": address}),
                 ("ip_policy", {}), ("route_maps", {}), ("ipv4_access_lists", {})]
    return [("version", {}), *reads]


class CiscoRunbook:
    def __init__(self, read, plan, platform):
        self.read = read
        self.platform = platform
        self.plan = dict(plan)
        self.sources = {}
        self.findings = {}
        self.captures = {}

    def capture(self, query, parameters=None):
        from . import normalization

        if query not in self.captures:
            parameters = self.plan[query] if parameters is None else parameters
            item = self.read(query, parameters)
            output = item.get("untrusted_device_output", "")
            state = item.get("_capture_state") or normalization.output_status(output, rc=item.get("rc"), profile=self.platform)
            if not item.get("ok"):
                state = (state if state not in {"ok", "empty"} else
                         item.get("reason") or item.get("error_code") or "read_failed")
            elif item.get("complete") is not True or item.get("next_offset") is not None:
                state = "truncated" if item.get("truncated") or item.get("next_offset") else "incomplete"
            self.sources[query] = {"status": state, "parameters": parameters,
                                   "content_sha256": item.get("content_sha256")}
            self.captures[query] = output if state in {"ok", "empty"} else None
        return self.captures[query]

    @staticmethod
    def lines(query, text, pattern):
        return [(match, {"query": query, "line_number": number, "untrusted_device_output": line})
                for number, line in enumerate(text.splitlines(), 1)
                if (match := re.fullmatch(pattern, line.strip()))]

    def found(self, check, status, *evidence, **fields):
        self.findings[check] = {"status": status, "evidence": list(evidence), **fields}

    def unknown(self, check, query, reason="unparsed", *evidence, **fields):
        state = self.sources[query]["status"]
        self.found(check, "unknown", *evidence, query=query, reason=reason if state in {"ok", "empty"} else state, **fields)

    def result(self):
        missing = [{"check": check, "query": finding["query"], "reason": finding["reason"]}
                   for check, finding in self.findings.items() if finding["status"] == "unknown"]
        return {"ok": not missing, "verdict": "incomplete" if missing else "observations",
                "findings": self.findings, "sources": self.sources, "missing": missing}


_CISCO_LINK = r"([A-Za-z0-9][A-Za-z0-9:/.-]{0,63}) is (up|down|administratively down|reset), line protocol is (up|down)(?: \([^()]+\))?"


def cisco_interface_line(runbook, query, text, interface):
    from .normalization import normalize_port

    lines = runbook.lines(query, text, _CISCO_LINK)
    if len(lines) == 1 and normalize_port(lines[0][0][1])["name"].lower() == normalize_port(interface)["name"].lower():
        return lines[0]
    return None


def run_cisco_port(runbook, interface):
    from . import tables

    query = "interface_details"
    text = runbook.capture(query)
    line = cisco_interface_line(runbook, query, text, interface) if text else None
    if line:
        match, evidence = line
        runbook.found("link", "up" if match[2] == match[3] == "up" else "down", evidence,
                      link_state=match[2], line_protocol=match[3])
    else:
        runbook.unknown("link", query)
    query = "stp_tree"
    text = runbook.capture(query)
    rows, unknown = tables.stp_tree(text or "", "ios")
    selected = [row for row in rows if row["port"].lower() == tables.port(interface).lower()]
    instances = runbook.lines(query, text or "", r"(?:VLAN\d{4}|MST\d+)")
    headers = runbook.lines(query, text or "", r"Interface\s+Role\s+Sts\s+Cost\s+Prio\.Nbr\s+Type")
    absent = runbook.lines(query, text or "", r"No spanning tree instances? exist(?:s)?\.")
    if not unknown and len(absent) == 1 and not instances:
        runbook.found("spanning_tree", "no_instances", absent[0][1])
    elif not unknown and selected and len(instances) == len(headers):
        observations = []
        for match, evidence in runbook.lines(query, text, r"(\S+)\s+(\S+)\s+(\S+)\s+\d+\s+\d+\.\d+\s+.+"):
            if tables.port(match[1]).lower() != tables.port(interface).lower():
                continue
            instance = next((line for _, line in reversed(instances) if line["line_number"] < evidence["line_number"]), None)
            if instance is not None:
                observations.append((instance, evidence))
        if len(observations) == len(selected):
            runbook.found("spanning_tree", "state_observed", *(line for pair in observations for line in pair),
                          instances=[{"instance": row["instance"], "state": row["state"]} for row in selected])
        else:
            runbook.unknown("spanning_tree", query)
    else:
        runbook.unknown("spanning_tree", query, "interface_not_listed" if instances and not unknown
                        and len(instances) == len(headers) else "unparsed")


def cisco_route(runbook, address, vrf=None):
    from . import tables

    query = "vrf_route_lookup" if vrf else "route_lookup"
    table = vrf or "global"
    text = runbook.capture(query, {"address": address, "vrf": vrf} if vrf else {"address": address})
    absent = runbook.lines(query, text or "", r"% (?:Subnet|Network) not in table|% Route not found")
    scope = runbook.lines(query, text or "", r"Routing Table: (\S+)")
    scope_ok = (len(scope) == 1 and scope[0][0][1] == vrf) if vrf else not scope
    route_text = re.sub(r"(?m)^Routing Table: \S+[ \t]*$", "", text or "")
    if len(absent) == 1 and route_text.strip() == absent[0][1]["untrusted_device_output"].strip() and (scope_ok or not scope):
        runbook.found("route", "not_in_table", *(line for _, line in [*scope, *absent]), table=table)
        return []
    rows, unknown = tables.route_ios(route_text)
    prefixes = runbook.lines(query, text or "", r"Routing entry for .+")
    protocol = runbook.lines(query, text or "", r'Known via "[^"]+", .+')
    paths = runbook.lines(query, text or "", r"\*?\s*(?:directly connected, via \S+|[0-9.]+(?:, .+)?)")
    metrics = runbook.lines(query, text or "", r"Route metric is \d+, traffic share count is \d+.*")
    if (not scope_ok or unknown or len(prefixes) != 1 or len(protocol) != 1 or not rows
            or len(rows) != len(paths) or len(paths) != len(metrics)
            or any(not (row["interface"] or row["next_hop"])
                   or ipaddress.IPv4Address(address) not in ipaddress.IPv4Network(row["prefix"]) for row in rows)):
        runbook.unknown("route", query, table=table)
        return []
    runbook.found("route", "route_observed", *(line for _, line in [*scope, *prefixes, *protocol, *paths]),
                  records=rows, table=table)
    return rows


def run_cisco_routing(runbook, address, vrf, sla_id):
    from . import tables
    from .triage_health import xe_ip_sla

    routes = cisco_route(runbook, address, vrf)
    if vrf:
        query = "vrf_arp_table"
        if len(routes) == 1 and routes[0]["interface"] and routes[0]["interface"].lower() != "null0":
            next_hop = routes[0]["next_hop"] or address
            output = runbook.capture(query)
            result = tables.parse(runbook.platform, "neighbor_l3", query, output or "", status="ok")
            rows = [row for row in result["records"] if row["ip"] == next_hop and row.get("interface")
                    and row["interface"].lower() == routes[0]["interface"].lower()]
            lines = runbook.lines(query, output or "", rf"Internet\s+{re.escape(next_hop)}\s+.+\s+(\S+)")
            lines = [line for match, line in lines if tables.port(match[1]).lower() == routes[0]["interface"].lower()]
            if result["coverage"]["complete"] and len(rows) == len(lines) == 1:
                runbook.found("vrf_neighbor", "resolved" if rows[0]["mac"] else "unresolved",
                              *runbook.findings["route"]["evidence"], *lines, record=rows[0])
            else:
                runbook.unknown("vrf_neighbor", query, "neighbor_not_identified")
        else:
            runbook.found("vrf_neighbor", "unknown", query=query, reason="route_next_hop_not_identified")
    if sla_id is not None:
        query = "ip_sla_statistics"
        text = runbook.capture(query)
        summary = xe_ip_sla(text or "")
        blocks = runbook.lines(query, text or "", r"IPSLA operation id: (\d+)")
        selected = [line for match, line in blocks if int(match[1]) == sla_id]
        if summary["complete"] and len(selected) == 1:
            start, = selected
            end = next((line["line_number"] for _, line in blocks if line["line_number"] > start["line_number"]), None)
            for match, line in runbook.lines(query, text, r"Latest operation return code: (.+)"):
                if start["line_number"] < line["line_number"] and (end is None or line["line_number"] < end):
                    runbook.found("ip_sla", "operation_observed", start, line, id=sla_id, return_code=match[1])
                    return
        runbook.unknown("ip_sla", query, "operation_not_listed" if summary["complete"] else "unparsed")
# --- G11 (1.0.12): routing information base and BGP neighbor detail ------------------------------------------------

ROUTE_DATABASE_QUERIES = frozenset({"routing_table_database", "ipv6_routing_table_database"})
BGP_NEIGHBOR_QUERIES = frozenset({"bgp_neighbor_detail", "ipv6_bgp_neighbor_detail"})
_RIB_CODES = {"K": "kernel", "C": "connected", "S": "static", "R": "rip", "O": "ospf", "B": "bgp", "i": "isis",
              "V": "bgp", "E": "bgp", "L": "leaked", "D": "leaked"}
_RIB_LEGEND_ITEM = re.compile(r"(?:[A-Za-z][A-Za-z0-9]*|\*|>) - [A-Za-z][A-Za-z0-9 /-]*")
_RIB_HEAD = re.compile(r"(?P<code>[KCSROBiVELD])(?: (?P<sub>IA|N1|N2|E1|E2|L1|L2|ia))?\s+(?P<flags>[*>p]{1,3})?\s*"
                       r"(?P<prefix>[0-9A-Fa-f:.]+/\d{1,3})\s+(?P<rest>.+)")
_RIB_NEXT = re.compile(r"(?P<flags>[*>p]{1,3})?\s*(?P<rest>(?:\[|is directly|via ).+)")
_RIB_REST = (
    # Measured on 60F 7.6.8 and 80F 8.0.2 (IPv4 and IPv6 database output).
    re.compile(r"is directly connected, (?P<interface>[^,\s]+)(?:, \S+)?"),
    re.compile(r"(?:\[(?P<distance>\d+)/(?P<metric>\d+)\] )?via (?P<gateway>[0-9A-Fa-f:.]+), (?P<interface>[^,\s]+)"
               r"(?:, \S+)?(?:, \[\d+/\d+\])?"),
    re.compile(r"\[(?P<distance>\d+)/(?P<metric>\d+)\] via (?P<interface>[^,\s]+) tunnel (?P<gateway>[0-9.]+)"
               r"(?:, \S+)?(?:, \[\d+/\d+\])?"),
    re.compile(r"\[(?P<distance>\d+)/(?P<metric>\d+)\] via (?P<gateway>[0-9.]+) +\(recursive via (?P<interface>[^,\s()]+)"
               r"(?: tunnel [0-9.]+)?\)(?:, \S+)?(?:, \[\d+/\d+\])?"),
    re.compile(r"\[(?P<distance>\d+)/(?P<metric>\d+)\] via (?P<gateway>[0-9A-Fa-f:.]+)"
               r" +\(recursive via (?P<resolved>[0-9A-Fa-f:.]+), (?P<interface>[^,\s()]+)\)"
               r"(?:, [^,\s]+)?(?:, \[\d+/\d+\])?"),
)
_RIB_INACTIVE = re.compile(r" inactive(?=,|$)")


def _rib_entry(prefix, protocol, flags, rest):
    path, markers = _RIB_INACTIVE.subn("", rest)
    for pattern in _RIB_REST:
        found = pattern.fullmatch(path)
        if found:
            parts = found.groupdict()
            gateway = parts.get("gateway")
            if gateway is not None:
                gateway = str(ipaddress.ip_address(gateway))
                if gateway == "::":
                    gateway = None
            if parts.get("resolved"):
                ipaddress.ip_address(parts["resolved"])
            distance = parts.get("distance")
            return {"prefix": prefix, "protocol": protocol, "selected": ">" in flags and not markers, "fib": "*" in flags,
                    "stale": "p" in flags, "distance": int(distance) if distance is not None else None,
                    "metric": int(parts["metric"]) if parts.get("metric") is not None else None,
                    "gateway": gateway, "interface": parts["interface"], "via": rest}
    raise ValueError("unrecognized route entry")


def route_database(text, start, end):
    """Parse `get router info[6] routing-table database` (60F 7.6.8 and 80F 8.0.2 measured).

    Every next hop has `selected` (a `>` without an explicit `inactive` marker), `fib` (`*`) and `stale` (`p`).
    `inactive` lists unselected entries alongside the selected paths of that prefix. An unselected entry may
    still be in the FIB. Only entries whose line starts inside [start, end) of the UTF-8
    output are returned (the ssh_read page); counts and `inactive` cover the whole output. A line of another shape
    makes the state incomplete.
    """
    entries, page, unreadable, position, current, vrf = [], [], 0, 0, None, "default"
    for raw in text.splitlines(keepends=True):
        line_start, position = position, position + len(raw.encode("utf-8"))
        line = raw.rstrip("\r\n")
        value = line.strip()
        heading = re.fullmatch(r"Routing table for VRF=(\S+)", value)
        if heading:
            name = heading.group(1).split("(")[0]
            vrf = "default" if name in ("0", "default") else name
            current = None
            continue
        legend = value.removeprefix("Codes: ")
        items = [item.strip() for item in legend.split(",") if item.strip()]  # an IPv6 legend line ends with ","
        if not value or value in ("IPv6 Routing Table", "Timers: Uptime") or items and all(
                _RIB_LEGEND_ITEM.fullmatch(item) for item in items):
            continue
        head = _RIB_HEAD.fullmatch(value)
        follow = _RIB_NEXT.fullmatch(value) if head is None and line[:1].isspace() and current else None
        try:
            if head:
                # The printed prefix in canonical form; host bits are kept as printed, never merged into another route.
                prefix = str(ipaddress.ip_interface(head.group("prefix")))
                protocol = _RIB_CODES[head.group("code")]
                entry = _rib_entry(prefix, protocol, head.group("flags") or "", head.group("rest"))
                current = (prefix, protocol)
            elif follow:
                entry = _rib_entry(current[0], current[1], follow.group("flags") or "", follow.group("rest"))
            else:
                raise ValueError("unrecognized line")
        except ValueError:
            unreadable += 1
            current = None
            continue
        entry["vrf"] = vrf
        entries.append(entry)
        if start <= line_start < end:
            page.append(entry)
    inactive = []
    for entry in entries:
        if not entry["selected"]:
            winners = [{key: other[key] for key in ("protocol", "distance", "gateway", "interface")}
                       for other in entries if other["selected"] and other["prefix"] == entry["prefix"]
                       and other["vrf"] == entry["vrf"]]
            inactive.append({**{key: entry[key] for key in ("prefix", "protocol", "distance", "gateway", "interface",
                                                            "fib", "vrf")}, "selected_instead": winners})
    state = "incomplete" if unreadable else "ok" if entries else "empty"
    return {"state": state, "total_entries": len(entries), "selected": sum(e["selected"] for e in entries),
            "fib": sum(e["fib"] for e in entries), "not_selected": len(inactive), "unreadable_lines": unreadable,
            "inactive": inactive, "entries": page,
            "note": "selected_instead lists selected paths for the same prefix and VRF. The FIB flag is independent "
                    "of RIB selection, and the database does not identify the reason for every unselected path."}


_BGP_HEAD = re.compile(r"BGP neighbor is (?P<neighbor>[0-9A-Fa-f:.]+), remote AS (?P<remote_as>\d+(?:\.\d+)?), "
                       r"local AS (?P<local_as>\d+(?:\.\d+)?), (?P<link>internal|external) link")
_BGP_FIELDS = (
    (re.compile(r"BGP version \d+, remote router ID (?P<remote_router_id>[0-9.]+)"), None),
    (re.compile(r"BGP state = (?P<state>[A-Za-z]+)(?:, up for (?P<up_for>\S+))?"), None),
    (re.compile(r"Last read \S+, hold time is (?P<hold_time>\d+), keepalive interval is (?P<keepalive>\d+) seconds"), int),
    (re.compile(r"Configured hold time is (?P<configured_hold_time>\d+), keepalive interval is "
                r"(?P<configured_keepalive>\d+) seconds"), int),
    (re.compile(r"Received (?P<messages_received>\d+) messages, (?P<notifications_received>\d+) notifications, \d+ in queue"), int),
    (re.compile(r"Sent (?P<messages_sent>\d+) messages, (?P<notifications_sent>\d+) notifications, \d+ in queue"), int),
    (re.compile(r"Connections established (?P<connections_established>\d+); dropped (?P<connections_dropped>\d+)"), int),
    (re.compile(r"Last Reset: (?P<last_reset>\S+)(?:, due to (?P<last_reset_reason>.+))?"), None),
    (re.compile(r"Notification Error Message: \((?P<last_notification>.*)\)"), None),
    (re.compile(r"Local host: (?P<local_address>[0-9A-Fa-f:.]+), Local port: \d+"), None),
    (re.compile(r"Nexthop interface: (?P<nexthop_interface>\S+)"), None),
)
# Measured lines whose values are not projected.
_BGP_KNOWN = re.compile(
    r"VRF \S+ neighbor table:|Neighbor capabilities:|Route refresh request: received \d+, sent \d+|"
    r"NLRI treated as withdraw: \d+|Minimum time between advertisement runs is \d+ seconds|Default weight \d+|"
    r"BGP table version \d+, neighbor version \d+|Index \d+, Offset \d+, Mask 0x[0-9a-fA-F]+|"
    r"Inbound soft reconfiguration allowed|Foreign host: \S+, Foreign port: \d+|Egress interface: \d+|"
    r"Nexthop: \S+|Nexthop global: \S+|Nexthop local: \S+|BGP connection: .+")
_BGP_CAPABILITY = re.compile(r"(?P<name>Route refresh|Address family [A-Za-z0-9 ]+?): (?P<value>.+)")
_BGP_FAMILY = re.compile(r"For address family: (?P<family>.+)")
# The Helper redacts the word after "Community" (SNMP community guard), so it is not matched literally.
_BGP_ACCEPTED = re.compile(r"Community \S+ sent to this neighbor .*?(?P<accepted>\d+) accepted prefixes, "
                           r"(?P<rib>\d+) prefixes in rib")
_BGP_ANNOUNCED = re.compile(r"(?P<announced>\d+) announced prefixes")
_BGP_DETAIL_FIELDS = ("state", "remote_router_id", "hold_time", "keepalive", "configured_hold_time",
                      "configured_keepalive", "connections_established", "connections_dropped")


def _bgp_detail_complete(neighbor):
    if any(neighbor[field] is None for field in _BGP_DETAIL_FIELDS):
        return False
    if neighbor["connections_dropped"] and not neighbor["last_reset_reason"]:
        return False
    return neighbor["state"] != "Established" or (
        neighbor["up_for"] is not None and bool(neighbor["capabilities"]) and bool(neighbor["address_families"])
        and all(all(value is not None for value in family.values()) for family in neighbor["address_families"].values())
    )


def bgp_neighbors(text, start, end):
    """Parse `get router info[6] bgp neighbors [<peer>]` (80F 8.0.2 measured with three iBGP peers; 60F 7.6.8 without
    BGP answers nothing; an unknown peer answers `% No neighbor exist`).

    Each `BGP neighbor is ...` block gives state, uptime, timers, message and notification counters, the last reset
    and its reason, capabilities and per address family accepted/announced prefixes. Only neighbors whose block
    starts inside [start, end) of the UTF-8 output are returned (the ssh_read page); counts cover the whole output.
    Unknown lines and neighbor blocks missing required detail make the state incomplete.
    """
    neighbors, page, unreadable, position, current, family = [], [], 0, 0, None, None
    lines = [raw for raw in text.splitlines(keepends=True)]
    if [raw.strip() for raw in lines if raw.strip()] == ["% No neighbor exist"]:
        return {"state": "no_such_neighbor", "total_neighbors": 0, "unreadable_lines": 0, "neighbors": []}
    for raw in lines:
        line_start, position = position, position + len(raw.encode("utf-8"))
        value = raw.strip()
        if not value:
            continue
        head = _BGP_HEAD.fullmatch(value)
        if head:
            current = dict.fromkeys((
                "neighbor", "remote_as", "local_as", "link", "remote_router_id", "state", "up_for", "hold_time",
                "keepalive", "configured_hold_time", "configured_keepalive", "messages_received", "messages_sent",
                "notifications_received", "notifications_sent", "connections_established", "connections_dropped",
                "last_reset", "last_reset_reason", "last_notification", "local_address", "nexthop_interface"))
            current.update(head.groupdict(), capabilities={}, address_families={})
            current["neighbor"] = str(ipaddress.ip_address(current["neighbor"]))
            neighbors.append(current)
            family = None
            if start <= line_start < end:
                page.append(current)
            continue
        if current is None:
            if not _BGP_KNOWN.fullmatch(value):
                unreadable += 1
            continue
        for pattern, convert in _BGP_FIELDS:
            found = pattern.fullmatch(value)
            if found:
                current.update({key: convert(item) if convert and item is not None else item
                                for key, item in found.groupdict().items()})
                if "connections_established" in found.groupdict():
                    family = None  # the connection lines follow the address family sections
                break
        else:
            capability = _BGP_CAPABILITY.fullmatch(value) if family is None else None
            selected = _BGP_FAMILY.fullmatch(value)
            accepted = _BGP_ACCEPTED.fullmatch(value) if family is not None else None
            announced = _BGP_ANNOUNCED.fullmatch(value) if family is not None else None
            if capability:
                current["capabilities"][capability.group("name")] = capability.group("value")
            elif selected:
                family = current["address_families"].setdefault(
                    selected.group("family"), {"accepted_prefixes": None, "prefixes_in_rib": None,
                                               "announced_prefixes": None})
            elif accepted:
                family.update(accepted_prefixes=int(accepted.group("accepted")), prefixes_in_rib=int(accepted.group("rib")))
            elif announced:
                family["announced_prefixes"] = int(announced.group("announced"))
            elif not _BGP_KNOWN.fullmatch(value):
                unreadable += 1
    state = "incomplete" if unreadable or not all(map(_bgp_detail_complete, neighbors)) else "ok" if neighbors else "empty"
    return {"state": state, "total_neighbors": len(neighbors),
            "established": sum(1 for neighbor in neighbors if neighbor["state"] == "Established"),
            "unreadable_lines": unreadable, "neighbors": page}


# --- G120 (1.0.12, EP10): EOS routing summaries of single ssh_read queries (not steps of the FortiOS triage) ------
# Measured on cEOS 4.36.1F (GNS3 netops-d-lab, 2026-11-18). The raw redacted output stays in untrusted_device_output.
def eos_ospf_neighbors(text):
    """Structure `show ip ospf neighbor` (cEOS 4.36.1F). FULL and 2WAY (DROTHER peers on a broadcast segment) are
    healthy; any other adjacency state is a finding. A row of another shape makes the state incomplete."""
    from . import tables

    rows, unknown = tables.ospf_neighbors(text, "eos", eos_details=True)
    header = any(tables.EOS_OSPF_HEADER.fullmatch(line.strip()) for line in _lines(text))
    for row in rows:
        row["state"] = row["state"].upper()
    findings = [{"id": "F-EOS-OSPF-NOT-FULL", "object": "ospf:%s:%s" % (row["vrf"], row["neighbor_id"]),
                 "fact": "adjacency %s on %s" % (row["state"], row["interface"])}
                for row in rows if row["state"] not in ("FULL", "2WAY")]
    states = {}
    for row in rows:
        states[row["state"]] = states.get(row["state"], 0) + 1
    state = "incomplete" if unknown or (rows and not header) else "ok" if rows else "empty"
    return {"state": state, "neighbors": rows, "by_state": states, "unreadable_lines": len(unknown),
            "findings": findings}


def eos_bgp_summary(text):
    """Summarize the EOS BGP peer table using the existing normalized state and counter parser."""
    from . import tables

    lines = [line.strip() for line in _lines(text) if line.strip() and line.strip() != "> show ip bgp summary"]
    inactive = len(lines) == 1 and re.fullmatch(r"% BGP (?:inactive|not active)(?: at line \d+)?", lines[0]) is not None
    peers, unknown = ([], []) if inactive else tables.bgp_peers("\n".join(lines), "eos")
    states = {}
    for peer in peers:
        states[peer["state"]] = states.get(peer["state"], 0) + 1
    unreadable = len(unknown) + sum(peer["state"] == "Established" and peer["prefixes"] is None for peer in peers)
    header = any(re.match(r"Neighbor\s+V\s+AS\s+", line) for line in lines)
    if inactive:
        state = "not_applicable"
    elif unreadable or (peers and not header):
        state = "incomplete"
    else:
        state = "ok" if peers else "empty" if header else "unparsed"
    return {"state": state, "peers": peers, "by_state": states, "unreadable_lines": unreadable}


def eos_route_lookup(text, address):
    """Structure `show ip route <address>` (cEOS 4.36.1F). The matching route follows the legend; when only the
    `Gateway of last resort` block is printed the address is reached by the default route."""
    from . import tables
    missing_hops = []
    rows, unknown = tables.route_eos(text, missing_hops=missing_hops)
    unreadable = len(unknown) + len(missing_hops)
    target = ipaddress.IPv4Address(address)
    routes = [{"prefix": row["prefix"], "protocol": row["protocol"], "next_hop": row["next_hop"],
               "interface": row["interface"]} for row in rows]
    prefixes = sorted({row["prefix"] for row in routes}, key=lambda value: -ipaddress.ip_network(value).prefixlen)
    covering = [value for value in prefixes if target in ipaddress.ip_network(value)]
    if unreadable or not routes or not covering:
        return {"state": "incomplete" if routes or unreadable else "empty", "address": address, "matched_prefix": None,
                "default_route": None, "routes": routes, "unreadable_lines": unreadable}
    best = covering[0]
    return {"state": "ok", "address": address, "matched_prefix": best, "default_route": best == "0.0.0.0/0",
            "routes": [route for route in routes if route["prefix"] == best], "unreadable_lines": 0}


def eos_routing_payload(query, text, parameters, capture_state):
    if query == "ospf_neighbors":
        summary, key = eos_ospf_neighbors(text), "ospf_summary"
    elif query == "bgp_summary":
        summary, key = eos_bgp_summary(text), "bgp_summary"
    elif query == "route_lookup":
        summary, key = eos_route_lookup(text, parameters["address"]), "route_lookup_summary"
    else:
        return {}
    if capture_state not in (None, "ok", "empty") and summary["state"] in ("ok", "empty"):
        summary["state"] = "incomplete"
    return {key: summary}


def nxos_path_route(text, address):
    """Validate a default-VRF lookup and its reported number of best unicast paths."""
    from .tables import route_nxos

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or lines[0] != 'IP Route Table for VRF "default"':
        return 'unparsed', []
    body = [line for line in lines[1:] if line not in (
        "'*' denotes best ucast next-hop", "'**' denotes best mcast next-hop",
        "'[x/y]' denotes [preference/metric]", "'%<string>' in via output denotes VRF <string>",
    )]
    if body == ['Route not found']:
        return 'empty', []
    if not body:
        return 'unparsed', []
    header = re.fullmatch(r'([.0-9]+/\d+), ubest/mbest: (\d+)/(\d+)(?:, attached)?', body[0])
    if not header:
        return 'unparsed', []
    try:
        if ipaddress.IPv4Address(address) not in ipaddress.IPv4Network(header[1]):
            return 'unparsed', []
        rows, unknown = route_nxos(text)
        best = [row for row, line in zip(rows, body[1:]) if line.startswith('*via ')]
        if (unknown or len(rows) != len(body) - 1 or
                any(not re.match(r'^\*{0,2}via ', line) or '%' in line for line in body[1:]) or
                len(best) != int(header[2]) or not best or
                any(row['prefix'] != header[1] or row['interface'] is None for row in best)):
            return 'unparsed', []
    except ValueError:
        return 'unparsed', []
    return 'ok', best
