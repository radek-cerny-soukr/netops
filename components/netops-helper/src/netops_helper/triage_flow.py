from __future__ import annotations

import ipaddress
import re

from .triage_health import (REASONS, firmware_fields, firmware_support, missing_read, Unparsed, UnsupportedPlatform,
                            _lines, _utc)
from .triage_routing import _INTERFACE_NAME, route_lookup, vdom_mode

# Tested identity (G00): not a gate; another model or build runs with firmware_support "untested" and a warning
# (the iprope lookup parser reports an unknown shape as unparsed). VDOMs disabled stays a real scope limit.
IDENTITIES = frozenset({("FortiGate-80F", "8.0.2", "0251")})
STEPS = ("system_status", "route_dst", "route_src", "policy_lookup", "session")
PLANNED_READS = len(STEPS)
PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1}
VERDICTS = frozenset({"allowed_and_session_seen", "allowed_no_session", "denied_by_policy", "no_route", "incomplete"})
SESSION_REPORTED = 5
NOT_SIMULATED = (
    "policy route and SD-WAN rule selection of the egress interface",
    "firewall policy schedule, user or device identity, internet service and other conditions the lookup does not report",
    "NAT of a flow without a session (the policy lookup does not report NAT)",
    "traffic to the FortiGate itself (local-in policy) and IPv6",
    "reverse-path filtering and asymmetric routing",
)
INGRESS_ASSUMPTION = "the ingress interface is the interface of the route to the source address"
SESSION_NOTE = ("observations of the sessions the device holds for this source, destination, destination port and "
                "protocol with any source port: not a policy lookup, and not an exhaustive or unambiguous answer for "
                "the whole range of source ports")


def assumptions(source_port):
    if source_port is None:
        return [INGRESS_ASSUMPTION,
                "the source port is unknown: the device CLI has no documented wildcard for the policy lookup, so no "
                "lookup was run and no policy verdict is given; the sessions below are observations only"]
    return [INGRESS_ASSUMPTION, "the policy lookup uses the source port %d given by the caller" % source_port]


def validate(src, dst, port, proto, source_port=None):
    """Return the checked flow, or the reason that the tool does not handle it; never touches a device."""
    if not isinstance(src, str) or not isinstance(dst, str):
        raise ValueError("src and dst must be IP address literals")
    versions = set()
    for value in (src, dst):
        if "%" in value:
            raise ValueError("src and dst must be canonical IP address literals without a zone")
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("src and dst must be canonical IP address literals") from None
        if str(address) != value:
            raise ValueError("src and dst must be canonical IP address literals")
        if (address.is_multicast or address.is_unspecified or address.is_loopback
                or (address.version == 4 and int(address) == 4294967295)):
            raise ValueError("src and dst must be unicast, non-loopback addresses")
        versions.add(address.version)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    if not isinstance(proto, str) or proto not in PROTOCOLS:
        raise ValueError("proto must be tcp, udp or icmp")
    if source_port is not None and (type(source_port) is not int or not 1 <= source_port <= 65535):
        raise ValueError("source_port must be omitted, null or an integer from 1 to 65535")
    if source_port is not None and proto == "icmp":
        raise ValueError("source_port does not apply to icmp")
    if versions != {4}:
        return {"unsupported": "ipv6_not_supported"}
    return {"src": src, "dst": dst, "port": port, "proto": proto, "source_port": source_port}


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
    if vdom_mode(text) != "disable":
        raise UnsupportedPlatform("config_platform_not_supported: triage_flow is measured only with VDOMs disabled")
    return {"product": found[0], "version": found[1], "build": found[2]}


def policy_lookup(text):
    lines = [line.strip() for line in _lines(text) if line.strip()]
    if not lines:
        raise Unparsed()
    error = [re.fullmatch(r"Error code: (err_[a-z_]+)", line) for line in lines]
    if any(error):
        if len([line for line in lines if line != "No authentication."]) != 1:
            raise Unparsed()
        return {"error": next(item.group(1) for item in error if item)}
    keyed = {}
    for line in lines:
        if line == "No authentication.":
            continue
        if line == "No policy matched":
            key, value = "matched", "no"
        else:
            found = re.fullmatch(r"(sec_default_action|firewall policy id|firewall proxy-policy id|"
                                 r"matched policy_type|policy_action): (\S+)", line)
            if not found:
                raise Unparsed()
            key, value = found.groups()
        if key in keyed:
            raise Unparsed()
        keyed[key] = value
    for key in ("firewall policy id", "firewall proxy-policy id"):
        if not re.fullmatch(r"0|[1-9]\d{0,9}", keyed.get(key, "x")):
            raise Unparsed()
    if keyed.get("matched") == "no":
        if (set(keyed) != {"matched", "sec_default_action", "firewall policy id", "firewall proxy-policy id"}
                or keyed["sec_default_action"] != "deny" or keyed["firewall policy id"] != "0"
                or keyed["firewall proxy-policy id"] != "0"):
            raise Unparsed()
        return {"matched": False, "policy_id": None, "action": "deny", "implicit": True}
    if (set(keyed) != {"firewall policy id", "firewall proxy-policy id", "matched policy_type", "policy_action"}
            or keyed["firewall policy id"] == "0" or keyed["firewall proxy-policy id"] != "0"
            or keyed["matched policy_type"] != "policy" or keyed["policy_action"] not in ("accept", "deny")):
        raise Unparsed()
    return {"matched": True, "policy_id": int(keyed["firewall policy id"]), "action": keyed["policy_action"],
            "implicit": False}


_ADDRESS = r"\d{1,3}(?:\.\d{1,3}){3}"
_ORG_HOOK = re.compile(r"^hook=(pre|post) dir=org act=(noop|snat|dnat) (" + _ADDRESS + r"):(\d+)->(" + _ADDRESS +
                       r"):(\d+)\((" + _ADDRESS + r"):(\d+)\)[ \t]*$", re.M)
_SESSION_TOTAL = re.compile(r"(?m)^total session:? (\d+)[ \t]*$")


_PROMPT_LINE = re.compile(r"[A-Za-z0-9_.+-]+(?: \([A-Za-z0-9_.+-]+\)|\((?:Primary|Secondary)\))? [#$]")
HEAD_LINES = 3
HEAD_WIDTH = 80


def _empty_list(text):
    """True when nothing but prompts, CR and blank lines surround the one measured line `total session: 0`."""
    lines = [line.strip() for line in text.replace("\r", "").split("\n")]
    return [line for line in lines if line and not _PROMPT_LINE.fullmatch(line)] == ["total session: 0"]


def head(text):
    """The first lines of an output the parser does not know, shortened and printable, for the diagnosis."""
    lines = [line.strip() for line in text.replace("\r", "").split("\n")]
    return ["".join(char if " " <= char <= "~" else "?" for char in line[:HEAD_WIDTH])
            for line in [line for line in lines if line][:HEAD_LINES]]


def sessions(text, src, dst, dport, proto, sport=None):
    """Parse a filtered `diagnose sys session list`; the Helper repeats the tuple filter itself."""
    numbers = re.split(r"(?m)^(?=session info:)", text.replace("\r\n", "\n"))
    blocks = numbers[1:]
    if not blocks:
        if not _empty_list(text):
            raise Unparsed()  # an empty list is only the measured one-line shape; anything else is unknown
        return {"device_total": 0, "matching": 0, "sessions": [], "complete": True}
    total = _SESSION_TOTAL.findall(numbers[-1])
    if len(total) != 1:
        raise Unparsed()
    found = []
    complete = True
    for block in blocks:
        head = re.match(r"session info: proto=(\d+) proto_state=(\d+) duration=(\d+) expire=(\d+) ", block)
        policy = re.search(r"(?m)^misc=\S+ policy_id=(\d+) ", block)
        hooks = _ORG_HOOK.findall(block)
        if not head or not policy or len(hooks) != 1:
            complete = False
            continue
        _, act, source, sport_seen, target, port, nat_address, nat_port = hooks[0]
        if (head.group(1), source, target, port) != (str(PROTOCOLS[proto]), src, dst, str(dport)):
            continue
        if sport is not None and int(sport_seen) != sport:
            continue
        nat = None if act == "noop" else {"action": act, "translated": nat_address + ":" + nat_port}
        found.append({"policy_id": int(policy.group(1)), "proto_state": head.group(2),
                      "duration_s": int(head.group(3)), "expire_s": int(head.group(4)),
                      "source_port": int(sport_seen), "nat": nat})
    complete = complete and int(total[0]) == len(blocks) == len(found)
    return {"device_total": int(total[0]), "matching": len(found), "sessions": found[:SESSION_REPORTED],
            "complete": complete}


def _source(query, answer, moment):
    return {"call": "triage_flow", "query": query, "content_sha256": answer["content_sha256"],
            "captured_at": _utc(moment)}


def _interfaces(route):
    return [hop["interface"] for hop in (route or {}).get("next_hops", ()) if hop["fib"]]


def _read(read, query, parameters, moment, missing, sources, key, parse):
    answer = read(query, parameters)
    if not answer.get("ok"):
        missing.append(missing_read(key, answer))
        return None
    if not answer["text"].strip():
        missing.append({"step": key, "reason": "empty"})
        return None
    sources[key] = _source(query, answer, moment)
    try:
        return {"value": parse(answer["text"])}
    except (Unparsed, ValueError):
        missing.append({"step": key, "reason": "unparsed"})
        return None


def run(read, clock, flow, alias, read_sessions=None):
    """`read(query, parameters)` returns the helper's read answer; `read_sessions(interface)` the session text
    or a reason string, `None` when the target does not enrol the session recipe."""
    started = clock()
    src, dst, port, proto = flow["src"], flow["dst"], flow["port"], flow["proto"]
    sport = flow.get("source_port")
    first = read("system_status", None)
    if not first.get("ok"):
        raise UnsupportedPlatform("config_platform_not_supported: the identity read failed")
    ident = identity(first["text"])
    support = firmware_support(ident, IDENTITIES, "triage_flow")
    sources = {}
    missing = []
    checked = ["system_status"]
    findings = []
    next_steps = []
    parsed = {}
    for key, address in (("route_dst", dst), ("route_src", src)):
        item = _read(read, "route_lookup", {"address": address}, clock(), missing, sources, key, route_lookup)
        if item is not None:
            parsed[key] = item["value"]
            checked.append(key)
    if "route_dst" in parsed and parsed["route_dst"] is None:
        findings.append({"id": "F-FLOW-NO-ROUTE-DST", "layer": "routing", "object": "route:" + dst,
                         "fact": "% Network not in table (the routing table only; policy routes were not evaluated)",
                         "sources": [sources["route_dst"]]})
        next_steps.append({"tool": "ssh_read",
                           "arguments": {"target": alias, "platform": "fortinet", "query": "routing_table"},
                           "why": "full IPv4 table: which covering or default route is absent"})
    if "route_src" in parsed and parsed["route_src"] is None:
        findings.append({"id": "F-FLOW-NO-ROUTE-SRC", "layer": "routing", "object": "route:" + src,
                         "fact": "% Network not in table: no ingress interface can be derived, and reverse-path "
                                 "filtering may drop the packet",
                         "sources": [sources["route_src"]]})
    ingress = _interfaces(parsed.get("route_src"))
    egress = sorted(set(name for name in _interfaces(parsed.get("route_dst")) if name is not None))
    device = ingress[0] if (ingress and len(set(ingress)) == 1 and ingress[0] is not None
                            and _INTERFACE_NAME.fullmatch(ingress[0])) else None
    policy = None
    unknown_port_sessions = False
    session = {"state": "not_run"}
    if proto == "icmp":
        missing.append({"step": "policy_lookup", "reason": "unsupported"})
        missing.append({"step": "session", "reason": "unsupported"})
    elif parsed.get("route_src") is None:
        missing.append({"step": "policy_lookup", "reason": "ingress_unknown"})
    elif device is None:
        missing.append({"step": "policy_lookup", "reason": "ingress_not_unique"})
    elif device is not None and parsed.get("route_dst", False) is not None and sport is None:
        missing.append({"step": "policy_lookup", "reason": "source_port_unknown"})
        unknown_port_sessions = "route_dst" in parsed  # sessions only when both routes were derived
    elif device is not None and parsed.get("route_dst", False) is not None:
        item = _read(read, "policy_lookup_ipv4",
                     {"src_ip": src, "src_port": str(sport), "dst_ip": dst, "dst_port": str(port),
                      "protocol": str(PROTOCOLS[proto]), "device": device, "pol_type": "policy"},
                     clock(), missing, sources, "policy_lookup", policy_lookup)
        if item is not None:
            policy = item["value"]
            if "error" in policy:
                missing.append({"step": "policy_lookup", "reason": "device_cli_error"})
                findings.append({"id": "F-FLOW-LOOKUP-ERROR", "layer": "policy", "object": "policy_lookup",
                                 "fact": "the device refused the policy lookup with %s for ingress %s" % (
                                     policy["error"], device),
                                 "sources": [sources["policy_lookup"]]})
                policy = None
            else:
                checked.append("policy_lookup")
    if (policy is not None and policy["action"] == "accept") or unknown_port_sessions:
        if read_sessions is None:
            missing.append({"step": "session", "reason": "not_enrolled"})
        else:
            answer = read_sessions(device)
            if not isinstance(answer, dict) or not answer.get("ok"):
                reason = answer.get("reason") if isinstance(answer, dict) else None
                missing.append(missing_read("session", answer if isinstance(answer, dict) else {},
                                            REASONS | {"not_enrolled", "restore_unverified", "scope_refused"}))
                if reason in {"restore_unverified", "scope_refused"}:
                    session = {"state": reason, "failed_step": "session", "detail": answer["detail"]}
            else:
                sources["session"] = _source("sessions", answer, clock())
                try:
                    session = {"state": "read", **sessions(answer["text"], src, dst, port, proto, sport)}
                except (Unparsed, ValueError):
                    missing.append({"step": "session", "reason": "unparsed", "first_lines": head(answer["text"])})
                else:
                    checked.append("session")
                    if sport is None:
                        shown = session["sessions"]
                        session.update(exhaustive_for_any_source_port=False, note=SESSION_NOTE, reported=len(shown),
                                       truncated=session["matching"] > len(shown),
                                       observed_policy_ids=sorted({item["policy_id"] for item in shown}))
                    if not session["complete"]:
                        missing.append({"step": "session", "reason": "incomplete"})
    elif policy is not None:
        session = {"state": "not_needed"}
    if policy is not None:
        if policy["matched"]:
            fact = "policy id %d, action %s (lookup for source port %d on ingress %s)" % (
                policy["policy_id"], policy["action"], sport, device)
        else:
            fact = "no policy matched: implicit deny (lookup for source port %d on ingress %s)" % (
                sport, device)
        findings.append({"id": "F-FLOW-POLICY-DENY" if policy["action"] == "deny" else "F-FLOW-POLICY-ACCEPT",
                         "layer": "policy", "object": "policy:%s" % (policy["policy_id"] or "implicit"),
                         "fact": fact, "sources": [sources["policy_lookup"]]})
        if policy["matched"]:
            next_steps.append({"tool": "config_read",
                               "arguments": {"target": alias, "platform": "fortinet", "section": "firewall policy"},
                               "why": "policy %d: services, NAT, schedule and security profiles (the lookup does not "
                                      "report them; the target must enrol configuration access)" % policy["policy_id"]})
    if session.get("state") == "read" and session["matching"]:
        findings.append({"id": "F-FLOW-SESSION", "layer": "session", "object": "session:%s>%s:%d" % (src, dst, port),
                         "fact": "%d session%s for this source, destination, port and protocol on the device (%s)" % (
                             session["matching"], "s" * (session["matching"] > 1),
                             "source port %d" % sport if sport is not None else
                             "any source port; observations only, not a policy lookup"),
                         "sources": [sources["session"]]})
    if missing:
        verdict = "incomplete"
    elif "route_dst" in parsed and parsed["route_dst"] is None:
        verdict = "no_route"
    elif policy is None:
        verdict = "incomplete"
    elif policy["action"] == "deny":
        verdict = "denied_by_policy"
    elif session["state"] == "read":
        verdict = "allowed_and_session_seen" if session["matching"] else "allowed_no_session"
    else:
        verdict = "incomplete"
    route_dst = parsed.get("route_dst")
    result = {
        "ok": session["state"] not in {"restore_unverified", "scope_refused"},
        "identity": ident,
        "vdom_mode": "disable",
        "flow": {"src": src, "dst": dst, "port": port, "proto": proto, "source_port": sport},
        "started_at": _utc(started),
        "finished_at": _utc(clock()),
        "vantage": {"kind": "device_cli_lookup", "device": alias, "packets_sent": False,
                    "ingress_interface": device, "ingress_inferred_from": "route to src",
                    "policy_lookup_source_port": sport if proto != "icmp" else None},
        "chain": {
            "ingress": {"route": parsed.get("route_src"), "interface": device},
            "egress": {"route": route_dst, "interfaces": egress},
            "policy": None if policy is None else {"matched": policy["matched"], "policy_id": policy["policy_id"],
                                                   "action": policy["action"], "implicit": policy["implicit"],
                                                   "nat": "not_reported_by_lookup"},
            "session": session,
        },
        "findings": findings,
        "missing": missing,
        "checked": checked,
        "assumptions": assumptions(sport),
        "next_steps": next_steps,
        "dataplane_simulated": False,
        "not_simulated": list(NOT_SIMULATED),
        "verdict": verdict,
        **firmware_fields(support),
    }

    if session["state"] in {"restore_unverified", "scope_refused"}:
        result.update(error_code=session["state"], failed_step="session", error=session["detail"])
    return result


_SRX_POLICY = re.compile(
    r"(?mi)^[ \t]*Policy:[ \t]*(\S+?),[ \t]*action-type:[ \t]*([^,\n]+),[^\n]*?"
    r"\bState:[ \t]*([^,\n]+),[ \t]*Index:[ \t]*(\d+)"
)
_SRX_POLICY_ZONE_PAIR = re.compile(r"(?mi)^[ \t]*From zone:[ \t]*([^,\n]+),[ \t]*To zone:[ \t]*([^,\n]+)")


def srx_policies(text):
    """SRX policy and match-policy output share the same policy record header."""
    rows = []
    blocks = re.split(r"(?mi)(?=^[ \t]*Policy:)", text)
    complete = True
    for block in blocks[1:]:
        header = _SRX_POLICY.match(block)
        if header is None:
            complete = False
            continue
        name, action, state, index = header.groups()
        zones = _SRX_POLICY_ZONE_PAIR.search(block)
        if zones is None:
            complete = False
        rows.append({"name": name, "action": action.strip(), "state": state.strip(), "index": int(index),
                     "from_zone": zones[1].strip() if zones else None, "to_zone": zones[2].strip() if zones else None})
    default = re.search(r"(?mi)^[ \t]*Default policy:[ \t]*(\S+)", blocks[0])
    complete = complete and bool(rows or default)
    return {"records": rows, "default_policy": default[1] if default else None, "complete": complete}


_SRX_HITS_HEADER = re.compile(
    r"(?i)index[ \t]+from zone[ \t]+to zone[ \t]+name[ \t]+policy count((?:[ \t]+action)(?:[ \t]+redirects?)?)?")
_SRX_HITS_TOTAL = re.compile(r"(?i)Number of polic(?:y|ies):[ \t]*(\d+)")
_SRX_HITS_DETAIL = {"url-categories": ("url_categories", re.compile(r"(?i)Name[ \t]+Count")),
                    "dynamic-applications": ("dynamic_applications", re.compile(r"(?i)Name[ \t]+Application Count"))}


def srx_policy_hits(text):
    """Every documented `show security policies hit-count` layout (Juniper CLI reference J-C7B534872022).

    The classic table (`index ... policy count`) always ends with `Number of policy: N`, so it is complete only
    with that footer and a matching row count. The Junos 21.2+ table (`Logical system:` heading, `Action` and
    optional `Redirect(s)` column) has no footer: there it is complete when a heading row was read, every row
    has all heading columns and policy indexes are unique per logical system; a footer, when present, must still
    match. `detail` URL-category and dynamic-application sub-tables are attached to the preceding policy. Any
    line that is none of these makes the result incomplete, so the read is reported as `unparsed`.
    """
    rows, sections = [], []
    section = detail = None
    complete = True
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        logical = re.fullmatch(r"(?i)Logical system:[ \t]*(\S+)", line)
        header = _SRX_HITS_HEADER.fullmatch(line)
        total = _SRX_HITS_TOTAL.fullmatch(line)
        if logical or header and (section is None or section["columns"] is not None):
            section = {"logical_system": logical[1] if logical else None, "columns": None, "rows": [], "total": None}
            sections.append(section)
            detail = None
            if logical:
                continue
        if header:
            extra = (header[1] or "").split()
            section["columns"] = 5 + len(extra)
            section["redirect"] = len(extra) == 2
            continue
        if section is None or section["columns"] is None or section["total"] is not None:
            complete = False
            continue
        if total:
            section["total"] = int(total[1])
            detail = None
            continue
        fields = line.split()
        if (len(fields) == section["columns"] and fields[0].isascii() and fields[0].isdecimal()
                and fields[4].isascii() and fields[4].isdecimal()
                and (not section["redirect"] or fields[6].isascii() and fields[6].isdecimal())):
            index, source, destination, name, hits = fields[:5]
            row = {"index": int(index), "from_zone": source, "to_zone": destination, "name": name, "hits": int(hits),
                   "action": fields[5] if len(fields) > 5 else None,
                   "redirect": int(fields[6]) if len(fields) > 6 else None,
                   "logical_system": section["logical_system"]}
            section["rows"].append(row)
            rows.append(row)
            detail = None
            continue
        kind = _SRX_HITS_DETAIL.get(line.lower())
        if kind and section["rows"]:
            detail = {"key": kind[0], "heading": kind[1], "seen_heading": False}
            section["rows"][-1].setdefault(kind[0], [])
            continue
        if detail and not detail["seen_heading"] and detail["heading"].fullmatch(line):
            detail["seen_heading"] = True
            continue
        item = re.fullmatch(r"(\S+)[ \t]+(\d+)", line)
        if detail and detail["seen_heading"] and item:
            section["rows"][-1][detail["key"]].append({"name": item[1], "count": int(item[2])})
            continue
        complete = False
    for part in sections:
        if part["columns"] is None:
            complete = False
        elif part["total"] is None:
            # Only the classic layout documents a footer; without it that table may be cut off.
            complete = complete and part["columns"] > 5
        else:
            complete = complete and part["total"] == len(part["rows"])
        indexes = [row["index"] for row in part["rows"]]
        complete = complete and len(indexes) == len(set(indexes))
        for row in part["rows"]:
            for key, _ in _SRX_HITS_DETAIL.values():
                complete = complete and bool(row.get(key, True))
    return {"records": rows, "complete": complete and bool(sections)}


_SRX_SESSION = re.compile(r"(?m)^[ \t]*Session ID:\s*(\d+),\s*Policy name:\s*([^,\n]+),([^\n]*)")
_SRX_WING = re.compile(
    r"(?m)^[ \t]*(In|Out):\s*(\S+)/(\d+)\s*-->\s*(\S+)/(\d+);(\w+)"
    r"[^\n]*?\bIf:\s*(\S+?)(?:,|$)"
)


def srx_sessions(text):
    """Compare the original tuple with the reverse of the reply tuple to identify NAT."""
    rows = []
    counts = re.findall(r"(?mi)^[ \t]*Total sessions:\s*(\d+)[ \t]*$", text)
    headers = list(_SRX_SESSION.finditer(text))
    for index, header in enumerate(headers):
        session_id, policy, fields = header.groups()
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        wings = {}
        for direction, src, src_port, dst, dst_port, protocol, interface in _SRX_WING.findall(text, header.end(), end):
            wings[direction] = {"src": src, "src_port": int(src_port), "dst": dst,
                                "dst_port": int(dst_port), "protocol": protocol, "interface": interface}
        timeout = re.search(r"\bTimeout:\s*(\d+)", fields)
        original, reply = wings.get("In"), wings.get("Out")
        translation = None
        if original and reply:
            translation = {}
            for side, reverse in (("src", "dst"), ("dst", "src")):
                translated = {"address": reply[reverse], "port": reply[f"{reverse}_port"]}
                if (original[side], original[f"{side}_port"]) != (translated["address"], translated["port"]):
                    translation[side] = translated
        rows.append({"id": int(session_id), "policy": policy.strip(), "timeout": int(timeout[1]) if timeout else None,
                     "original": original, "reply": reply, "translation": translation})
    complete = bool(counts) and sum(map(int, counts)) == len(rows) and all(
        row["translation"] is not None and row["timeout"] is not None for row in rows
    )
    return {"records": rows, "complete": complete}


_SRX_NAT_RULE = re.compile(r"(?mi)^[ \t]*(?:source|destination) NAT rule:\s*(\S+)\s+Rule-set:\s*(\S+)")


def _srx_nat_addresses(text, name):
    match = re.search(rf"(?m)^[ \t]*{name} addresses[ \t]*:[ \t]*([^\n]+)", text)
    if match is None:
        return []
    addresses = [match[1].strip()]
    for line in text[match.end():].splitlines()[1:]:
        if not re.fullmatch(r"[ \t]+[0-9a-fA-F.:/]+(?:[ \t]+-[ \t]+[0-9a-fA-F.:/]+)?[ \t]*", line):
            break
        addresses.append(line.strip())
    return addresses


def srx_nat_rules(text):
    rows = []
    headers = list(_SRX_NAT_RULE.finditer(text))
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        block = text[header.end():end]
        fields = {}
        for line in block.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields[key.strip()] = value.strip()
        hits = fields.get("Translation hits", "")
        rows.append({"name": header[1], "rule_set": header[2],
                     "from": fields.get("From zone") or fields.get("From interface") or fields.get("From routing instance"),
                     "to": fields.get("To zone") or fields.get("To interface") or fields.get("To routing instance"),
                     "source_addresses": _srx_nat_addresses(block, "Source"),
                     "destination_addresses": _srx_nat_addresses(block, "Destination"),
                     "action": fields.get("Action"), "translation_hits": int(hits) if hits.isdecimal() else None})
    total = re.search(r"(?mi)^Total (?:destination-nat )?rules:\s*(\d+)", text)
    complete = bool(total and int(total[1]) == len(rows)) and all(
        row["action"] and row["translation_hits"] is not None for row in rows
    )
    return {"records": rows, "complete": complete}


NXOS_PATH_REQUIRED = ('version', 'interface_details', 'route_lookup')


def nxos_path_plan(interface, address):
    """Existing catalogue reads, in the default IPv4 VRF."""
    from .tables import port

    scoped = {'interface': interface}
    plan = [
        ('version', None), ('interface_details', scoped), ('route_lookup', {'address': address}),
        ('stp_interface_detail', scoped), ('lldp_neighbor_interface', scoped),
        ('forwarding_ipv4_route', None), ('ipv4_access_lists_summary', None), ('arp_table', None),
    ]
    if port(interface).startswith('Port-channel'):
        plan.append(('vpc_status', None))
    return plan


def _nxos_fib(text, address):
    """Read matching rows in the default/base FIB, per reported slot."""
    slots, slot, table, header = {}, None, False, False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or re.fullmatch(r'[-+=]+', line):
            continue
        label = re.fullmatch(r'slot\s+(\d+)', line)
        if label and label[1] not in slots:
            slot, table, header = label[1], False, False
            slots[slot] = []
            continue
        if slot is not None and line == 'IPv4 routes for table default/base' and not table:
            table = True
            continue
        if table and not header and [field.strip() for field in line.split('|')] == [
            'Prefix', 'Next-hop', 'Interface', 'Labels', 'Partial Install',
        ]:
            header = True
            continue
        fields = line.split()
        if not header or len(fields) != 3:
            return 'unparsed', []
        prefix, hop, interface = fields
        try:
            network = ipaddress.IPv4Network(prefix)
            if hop not in {'Attached', 'Drop', 'Receive'}:
                ipaddress.IPv4Address(hop)
        except ValueError:
            return 'unparsed', []
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9/.-]*', interface):
            return 'unparsed', []
        slots[slot].append((network, hop, interface))
    if not slots or any(not rows for rows in slots.values()):
        return 'unparsed', []
    matches = []
    dest = ipaddress.IPv4Address(address)
    for slot, rows in slots.items():
        candidates = [(network, hop, interface) for network, hop, interface in rows if dest in network]
        longest = max((network.prefixlen for network, _, _ in candidates), default=-1)
        matches.extend({'slot': int(slot), 'prefix': str(network), 'next_hop': hop, 'interface': interface}
                       for network, hop, interface in candidates if network.prefixlen == longest)
    return ('ok' if matches else 'empty'), matches


def nxos_path_run(read, interface, address):
    from . import tables
    from .triage_routing import nxos_path_route

    profile = 'cisco_nxos'
    selected_port = tables.port(interface)
    findings, missing, sources = {}, [], {}
    routes = []
    identity = None

    for query, parameters in nxos_path_plan(interface, address):
        neighbors = {(route['next_hop'] or address, route['interface']) for route in routes
                     if route['protocol'] != 'local' and route['interface'] != 'Null0'}
        if query == 'arp_table' and not neighbors:
            continue
        answer = read(query, parameters)
        output = answer.get('untrusted_device_output', '')
        state = answer.get('_capture_state')
        records = None
        if (answer.get('error_code') == 'empty' or answer.get('reason') == 'identity_empty'
                or (answer['ok'] and not output.strip())):
            state = 'missing'
        elif not answer['ok']:
            state = answer.get('reason') or answer.get('error_code') or answer.get('status') or 'device_cli_error'
        elif not answer.get('complete') or answer.get('next_offset') is not None:
            normalized = answer.get('normalized', {})
            state = normalized.get('status') if normalized.get('status') not in ('ok', 'empty', None) else 'truncated'
        elif query == 'version' and state == 'ok':
            identity = answer.get('normalized', {}).get('identity')
            state = 'ok' if identity else 'unparsed'
        elif state in ('ok', 'empty'):
            if query == 'interface_details':
                header = re.match(r'^([^\s]+) is (up|down)(?:\s|$)', output.lstrip())
                if (header and tables.port(header[1]) == selected_port and
                        re.search(r'(?m)^\s*\d+ Tx pause[ \t]*$', output)):
                    records = [{'port': selected_port, 'link_state': header[2]}]
                else:
                    state = 'unparsed'
            elif query == 'route_lookup':
                state, routes = nxos_path_route(output, address)
                records = routes if state in ('ok', 'empty') else None
            elif query == 'forwarding_ipv4_route':
                state, fib = _nxos_fib(output, address)
                records = fib if state in ('ok', 'empty') else None
            elif query == 'vpc_status':
                vpc = answer.get('vpc', {})
                state = vpc.get('state', 'unparsed')
                if state == 'measured':
                    state = 'ok'
                    records = [row for row in vpc.get('members', []) if tables.port(row['port']) == selected_port]
            else:
                normalized = answer.get('normalized')
                if query == 'arp_table':
                    normalized = tables.parse(profile, 'neighbor_l3', query, output, status=state)
                    counts = re.findall(r'(?m)^Total number of entries:\s*(\d+)[ \t]*$', output)
                    if counts != [str(len(normalized['records']))]:
                        normalized = None
                state = 'unparsed'
                if normalized and normalized['coverage']['complete']:
                    state = normalized['status']
                    records = normalized['records']
                    if query == 'arp_table':
                        records = [row for row in records if (row['ip'], row['interface']) in neighbors]
                    elif query == 'ipv4_access_lists_summary':
                        ports = {selected_port, *(route['interface'] for route in routes)}
                        records = [{'name': row['name'], **{
                            key: [binding for binding in row[key] if tables.port(binding['interface']) in ports]
                            for key in ('configured_interfaces', 'active_interfaces')
                        }} for row in records]
                        records = [row for row in records if row['configured_interfaces'] or row['active_interfaces']]
        state = state or 'unparsed'
        if records is not None and len(records) > 20:
            records, state = records[:20], 'record_limit'
        if records is not None and state in ('ok', 'empty', 'record_limit'):
            findings[query] = {'source': query, 'records': records}
        elif query != 'version' and state in ('ok', 'empty'):
            state = 'unparsed'
        if state not in ('ok', 'empty'):
            missing.append({'source': query, 'reason': state})

        digest = answer.get('content_sha256')
        sources[query] = {'status': state, **({'content_sha256': digest} if digest else {})}
        if query == 'version' and identity is None:
            break

    return {
        'ok': not missing, 'verdict': 'incomplete' if missing else 'observed',
        'platform': profile, 'vrf': 'default', 'interface': selected_port, 'destination': address,
        'identity': identity, 'findings': findings, 'missing': missing, 'sources': sources,
        'rib_status': ('route_observed' if routes else 'route_not_found')
        if 'route_lookup' in findings else 'unknown',
        'vantage': {'packets_sent': False, 'scope': 'Local port, default IPv4 RIB/FIB, ARP and IPv4 ACL bindings. '
                    'ACL rules and packet delivery are unevaluated. vPC observations are local to this switch.'},
    }


def _cisco_ingress_vrf(runbook, interface):
    from .triage_routing import cisco_interface_line

    query = "ip_interface_details"
    text = runbook.capture(query) or ""
    if not cisco_interface_line(runbook, query, text, interface):
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    vpn = [line for line in lines if re.match(r"(?:VPN|(?:ip )?VRF)\b", line, re.I)]
    # The WCCP tail follows the VPN field on IOS and IOS XE routed IPv4 ports.
    # Require it before treating an absent VPN field as the global table.
    if (not vpn or runbook.platform != "cisco_ios") and not any(
        re.fullmatch(r"IPv4 WCCP Redirect exclude is (?:enabled|disabled)", line) for line in lines
    ):
        return None
    if not vpn:
        return ""
    if len(vpn) == 1:
        match = re.fullmatch(r'VPN Routing/Forwarding "([A-Za-z0-9][A-Za-z0-9_.:-]{0,63})"', vpn[0])
        if match:
            return match[1]
    return None


def _cisco_cef(runbook, destination, vrf):
    query = "vrf_cef_lookup" if vrf else "cef_lookup"
    parameters = {"address": destination, "vrf": vrf} if vrf else {"address": destination}
    table = vrf or "global"
    text = runbook.capture(query, parameters) or ""
    prefixes = runbook.lines(query, text, r"(\d+\.\d+\.\d+\.\d+/\d+), epoch \d+(?:, .+)?")
    paths = runbook.lines(query, text, r"(?:attached to|nexthop \d+\.\d+\.\d+\.\d+) (\S+)")
    recursions = runbook.lines(query, text, r"recursive via \d+\.\d+\.\d+\.\d+(?:/\d+)?")
    adjacency = runbook.lines(query, text, r"Adj source: IP adj out of \S+, addr \d+\.\d+\.\d+\.\d+ [0-9A-Fa-f]+"
                             r"|Dependent covered prefix type adjfib, cover \d+\.\d+\.\d+\.\d+/\d+"
                             r"|\d+ RR source \[no flags\]")
    if (len(prefixes) != 1 or not paths
            or sum(map(len, (prefixes, paths, recursions, adjacency))) != sum(bool(line.strip()) for line in text.splitlines())):
        runbook.unknown("cef", query, table=table)
        return
    try:
        network = ipaddress.IPv4Network(prefixes[0][0][1])
    except ValueError:
        runbook.unknown("cef", query, table=table)
        return
    if ipaddress.IPv4Address(destination) not in network:
        runbook.unknown("cef", query, "destination_not_covered", table=table)
        return
    egress = [match[1] for match, _ in paths]
    runbook.found("cef", "discard_path_observed" if all(name.lower() == "null0" for name in egress) else "path_observed",
                  *(line for _, line in [*prefixes, *recursions, *paths]), prefix=str(network),
                  egress_interfaces=egress, table=table)


def _cisco_ingress_acl(runbook, interface):
    from .triage_routing import cisco_interface_line

    query = "ip_interface_details"
    text = runbook.capture(query) or ""
    line = cisco_interface_line(runbook, query, text, interface)
    disabled = runbook.lines(query, text, r"Internet protocol processing disabled")
    acls = runbook.lines(query, text, r"Inbound\s+(Common\s+)?access list is (not set|[A-Za-z0-9_.-]+)")
    if line and len(disabled) == 1:
        runbook.found("ingress_acl", "ipv4_processing_disabled", line[1], disabled[0][1])
    elif (line and any(match[1] is None for match, _ in acls) and len({bool(match[1]) for match, _ in acls}) == len(acls)
          and sum(bool(re.match(r"Inbound\s+(?:Common\s+)?access list\b", row.strip())) for row in text.splitlines()) == len(acls)):
        names = [match[2] for match, _ in acls if match[2] != "not set"]
        runbook.found("ingress_acl", "bindings_observed" if names else "no_binding", line[1],
                      *(evidence for _, evidence in acls), access_lists=names)
        return names
    else:
        runbook.unknown("ingress_acl", query)
    return []


def _cisco_policy_maps(runbook, interface):
    from .normalization import normalize_port

    query = "ip_policy"
    text = runbook.capture(query) or ""
    headers = runbook.lines(query, text, r"Interface\s+Route map")
    bindings = runbook.lines(query, text, r"([A-Za-z][A-Za-z0-9./-]*\d[A-Za-z0-9./-]*)\s+([A-Za-z0-9_.-]+)")
    if (len(headers) != 1 or len(headers) + len(bindings) != sum(bool(line.strip()) for line in text.splitlines())
            or any(line["line_number"] < headers[0][1]["line_number"] for _, line in bindings)):
        runbook.unknown("ip_policy", query)
        return []
    port = normalize_port(interface)["name"].lower()
    selected = [(match, line) for match, line in bindings if normalize_port(match[1])["name"].lower() == port]
    if not selected:
        runbook.found("ip_policy", "no_binding", headers[0][1], interface=interface)
        return []
    if len(selected) != 1:
        runbook.unknown("ip_policy", query, "ambiguous_binding")
        return []
    match, binding = selected[0]
    name = match[2]
    runbook.found("ip_policy", "binding_observed", binding, route_map=name)
    return _cisco_route_map(runbook, name, binding)


def _cisco_route_map(runbook, name, binding):
    query = "route_maps"
    text = runbook.capture(query) or ""
    headings = runbook.lines(query, text, r"route-map (\S+), (permit|deny), sequence (\d+)")
    matches = runbook.lines(query, text, r"ip address \(access-lists\): ([A-Za-z0-9_. -]+)")
    sets = runbook.lines(query, text, r"interface (\S+)")
    counters = runbook.lines(query, text, r"Policy routing matches: (\d+) packets, (\d+) bytes")
    markers = runbook.lines(query, text, r"(?:Match|Set) clauses:")
    if len(headings) + len(matches) + len(sets) + len(counters) + len(markers) != sum(
            bool(line.strip()) for line in text.splitlines()):
        runbook.unknown("route_map", query)
        return []
    clauses, evidence, names = [], [binding], []
    for index, (header, line) in enumerate(headings):
        if header[1] != name:
            continue
        end = headings[index + 1][1]["line_number"] if index + 1 < len(headings) else float("inf")
        def block(rows):
            return [(row, ref) for row, ref in rows if line["line_number"] < ref["line_number"] < end]

        block_matches, block_sets, block_counters, block_markers = map(block, (matches, sets, counters, markers))
        if len(block_counters) != 1 or [ref["untrusted_device_output"].strip() for _, ref in block_markers] != [
                "Match clauses:", "Set clauses:"]:
            runbook.unknown("route_map", query)
            return []
        match_marker, set_marker = (ref["line_number"] for _, ref in block_markers)
        counter_line = block_counters[0][1]["line_number"]
        if (any(not match_marker < ref["line_number"] < set_marker for _, ref in block_matches)
                or any(not set_marker < ref["line_number"] < counter_line for _, ref in block_sets)
                or counter_line <= set_marker):
            runbook.unknown("route_map", query)
            return []
        names.extend(acl for row, _ in block_matches for acl in row[1].split())
        interfaces = [row[1] for row, _ in block_sets]
        clauses.append({"sequence": int(header[3]), "action": header[2], "set_interfaces": interfaces,
                        "sets_null0": header[2] == "permit" and [name.lower() for name in interfaces] == ["null0"],
                        "policy_matches": int(block_counters[0][0][1])})
        evidence.extend([line, *(ref for _, ref in [*block_matches, *block_sets, *block_counters])])
    if not clauses:
        runbook.unknown("route_map", query, "route_map_not_listed")
        return []
    runbook.found("route_map", "clauses_observed", *evidence, route_map=name, clauses=clauses)
    return names


def _cisco_acl_evidence(runbook, names):
    from .tables import _ios_acl_rows

    query = "ipv4_access_lists"
    text = runbook.capture(query) or ""
    parsed, unknown = _ios_acl_rows(text)
    records = [record for record in parsed if record["family"] == "ipv4" and record["name"] in names]
    if unknown or len(records) != len(names) or {record["name"] for record in records} != names:
        runbook.unknown("access_lists", query, "unparsed" if unknown else "access_list_not_listed")
        return
    headings = runbook.lines(query, text, r"(?:IPv6|Standard IP|Extended IP) access list (\S+)(?: \([^()]+\))*")
    evidence = []
    rules = runbook.lines(query, text, r"(?:\d+ )?(?:permit|deny) .+")
    for index, (match, line) in enumerate(headings):
        if match[1] in names:
            evidence.append(line)
            end = headings[index + 1][1]["line_number"] if index + 1 < len(headings) else float("inf")
            evidence.extend(ref for _, ref in rules if line["line_number"] < ref["line_number"] < end)
    runbook.found("access_lists", "definitions_observed", *evidence, access_lists=sorted(names))


def run_cisco_flow(runbook, interface, destination):
    from .triage_routing import cisco_route

    vrf = _cisco_ingress_vrf(runbook, interface)
    if vrf is None:
        for check in ("route", "cef"):
            runbook.unknown(check, "ip_interface_details", "ingress_vrf_unverified", table=None)
    else:
        cisco_route(runbook, destination, vrf)
        _cisco_cef(runbook, destination, vrf)
    acl_names = set(_cisco_ingress_acl(runbook, interface) + _cisco_policy_maps(runbook, interface))
    if acl_names:
        _cisco_acl_evidence(runbook, acl_names)
