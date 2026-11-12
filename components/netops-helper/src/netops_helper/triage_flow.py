from __future__ import annotations

import ipaddress
import re

from .triage_health import REASONS, missing_read, Unparsed, UnsupportedPlatform, _lines, _utc
from .triage_routing import _INTERFACE_NAME, route_lookup, vdom_mode

IDENTITIES = frozenset({("FortiGate-80F", "8.0.2", "0251")})
STEPS = ("system_status", "route_dst", "route_src", "policy_lookup", "session")
PLANNED_READS = len(STEPS)
PROBE_SOURCE_PORT = 40000
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
ASSUMPTIONS = (
    "the ingress interface is the interface of the route to the source address",
    "the policy lookup uses the fixed source port %d: a policy whose service restricts the source port to a range "
    "that does not contain %d is not matched by the lookup, although a connection from such a source port may match it" % (
        PROBE_SOURCE_PORT, PROBE_SOURCE_PORT),
)


def validate(src, dst, port, proto):
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
    if versions != {4}:
        return {"unsupported": "ipv6_not_supported"}
    return {"src": src, "dst": dst, "port": port, "proto": proto}


def identity(text):
    from netops_core import platforms
    try:
        found = tuple(platforms.version_record(text))
    except platforms.VersionRecordError:
        raise UnsupportedPlatform("config_platform_not_supported: one exact FortiOS identity is required") from None
    if found not in IDENTITIES:
        raise UnsupportedPlatform("config_platform_not_supported: triage_flow is not qualified for this model and build")
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


def sessions(text, src, dst, dport, proto):
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
        _, act, source, sport, target, port, nat_address, nat_port = hooks[0]
        if (head.group(1), source, target, port) != (str(PROTOCOLS[proto]), src, dst, str(dport)):
            continue
        nat = None if act == "noop" else {"action": act, "translated": nat_address + ":" + nat_port}
        found.append({"policy_id": int(policy.group(1)), "proto_state": head.group(2),
                      "duration_s": int(head.group(3)), "expire_s": int(head.group(4)),
                      "source_port": int(sport), "nat": nat})
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
    first = read("system_status", None)
    if not first.get("ok"):
        raise UnsupportedPlatform("config_platform_not_supported: the identity read failed")
    ident = identity(first["text"])
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
    session = {"state": "not_run"}
    if proto == "icmp":
        missing.append({"step": "policy_lookup", "reason": "unsupported"})
        missing.append({"step": "session", "reason": "unsupported"})
    elif parsed.get("route_src") is None:
        missing.append({"step": "policy_lookup", "reason": "ingress_unknown"})
    elif device is None:
        missing.append({"step": "policy_lookup", "reason": "ingress_not_unique"})
    elif device is not None and parsed.get("route_dst", False) is not None:
        item = _read(read, "policy_lookup_ipv4",
                     {"src_ip": src, "src_port": str(PROBE_SOURCE_PORT), "dst_ip": dst, "dst_port": str(port),
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
    if policy is not None and policy["action"] == "accept":
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
                    session = {"state": "read", **sessions(answer["text"], src, dst, port, proto)}
                except (Unparsed, ValueError):
                    missing.append({"step": "session", "reason": "unparsed", "first_lines": head(answer["text"])})
                else:
                    checked.append("session")
                    if not session["complete"]:
                        missing.append({"step": "session", "reason": "incomplete"})
    elif policy is not None:
        session = {"state": "not_needed"}
    if policy is not None:
        if policy["matched"]:
            fact = "policy id %d, action %s (lookup for source port %d on ingress %s)" % (
                policy["policy_id"], policy["action"], PROBE_SOURCE_PORT, device)
        else:
            fact = "no policy matched: implicit deny (lookup for source port %d on ingress %s)" % (
                PROBE_SOURCE_PORT, device)
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
                         "fact": "%d session%s for this source, destination, port and protocol on the device (any source "
                                 "port)" % (session["matching"], "s" * (session["matching"] > 1)),
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
        "flow": {"src": src, "dst": dst, "port": port, "proto": proto},
        "started_at": _utc(started),
        "finished_at": _utc(clock()),
        "vantage": {"kind": "device_cli_lookup", "device": alias, "packets_sent": False,
                    "ingress_interface": device, "ingress_inferred_from": "route to src",
                    "policy_lookup_source_port": PROBE_SOURCE_PORT if proto != "icmp" else None},
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
        "assumptions": list(ASSUMPTIONS),
        "next_steps": next_steps,
        "dataplane_simulated": False,
        "not_simulated": list(NOT_SIMULATED),
        "verdict": verdict,
    }

    if session["state"] in {"restore_unverified", "scope_refused"}:
        result.update(error_code=session["state"], failed_step="session", error=session["detail"])
    return result
