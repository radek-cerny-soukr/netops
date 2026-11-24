from __future__ import annotations

import re

from .triage_health import (IDENTITIES, missing_read, Unparsed, UnsupportedPlatform, _lines, _utc, firmware_fields,
                           firmware_support, identity, in_vdom, vdom_fields, vdom_scope)

STEPS = (
    ("identity", "system_status"),
    ("tunnel", "ipsec_summary"),
    ("route", "routing_table"),
    ("ike", "ike_errors"),
)
# ipsec status (FP-09): detail of the named phase-1 tunnel, read only when the summary lists it under exactly that name
# and only when the detail queries are enrolled; key material is withheld by the engine before parsing.
DETAIL_STEPS = (
    ("phase1", "ike_gateway_detail"),
    ("phase2", "ipsec_tunnel_detail"),
)
DETAIL_IDENTITIES = frozenset({("FortiGate-60F", "7.6.8", "3744")})
PLANNED_READS = len(STEPS) + len(DETAIL_STEPS)
REQUIRED = frozenset(query for _, query in STEPS)
# packet errors below this share of the packets of their direction are a notice, not a fault (1 %)
ERROR_SHARE_FAULT = 0.01
# HA synchronisation counters in `diagnose vpn ike errors` describe the cluster, not IKE failures: context only
CONTEXT_PREFIX = "ha."
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
    nonzero = {name: value for name, value in counters.items() if value}
    return {"counters": len(counters),
            "nonzero": {name: value for name, value in nonzero.items() if not name.startswith(CONTEXT_PREFIX)},
            "context": {name: value for name, value in nonzero.items() if name.startswith(CONTEXT_PREFIX)}}


# The label is split at its first colon (str.partition) and only then checked: no regex backtracks over the value.
_LABEL = re.compile(r"[A-Za-z][A-Za-z0-9 _/().-]*")
# The general response floor can also mask the secret suffix of the psksecret label.
_REDACTED_KEY_LINE = re.compile(
    r"(?i)^[ \t]*(?:(?:enc|auth)[ \t]+key[ \t]*[:=][ \t]*<REDACTED>"
    r"|(?:set[ \t]+)?(?:psk\[REDACTED\]|(?:psksecret|psk)(?:[ \t]*[:=][ \t]*|[ \t]+)"
    r"(?:<REDACTED>|\[REDACTED\])))[ \t]*"
)
_SA_COUNTS = re.compile(r"created (\d+)/(\d+)\s+established (\d+)/(\d+)(?:\s+time \S+ ms)?")
_GATEWAY_ADDR = re.compile(r"(\S+):(\d+) -> (\S+):(\d+)")


def _pair(found, first):
    return [int(found.group(first)), int(found.group(first + 1))]


def ike_gateway_detail(text):
    """`diagnose vpn ike gateway list name <phase1>`: the gateway records and their IKE SAs.

    Measured (FortiGate-60F 7.6.8): no output at all while no IKE SA exists (peer not answering). Every line is a
    `label: value` line; any other line, a missing name/addr/SA count or an SA without status is unparsed."""
    gateways = []
    current = None
    sa = None
    for line in _lines(text):
        if not line.strip() or _REDACTED_KEY_LINE.fullmatch(line):
            continue
        head, colon, value = line.partition(":")
        label, value = head.strip(), value.strip()
        if not colon or not _LABEL.fullmatch(label):
            raise Unparsed()
        indented = line[:1].isspace()
        if not indented and label == "name":
            current = {"name": value, "version": None, "interface": None, "local": None, "peer": None,
                       "created": None, "ike_sa": None, "ipsec_sa": None, "sas": []}
            gateways.append(current)
            sa = None
            continue
        if current is None:
            raise Unparsed()
        if not indented:
            if label == "version":
                current["version"] = value
            elif label == "interface":
                current["interface"] = value.split()[0] if value else None
            elif label == "addr":
                addr = _GATEWAY_ADDR.fullmatch(value)
                if not addr:
                    raise Unparsed()
                current["local"] = "%s:%s" % (addr.group(1), addr.group(2))
                current["peer"] = "%s:%s" % (addr.group(3), addr.group(4))
            elif label == "created":
                current["created"] = value
            elif label in ("IKE SA", "IPsec SA"):
                counts = _SA_COUNTS.fullmatch(value)
                if not counts:
                    raise Unparsed()
                current["ike_sa" if label == "IKE SA" else "ipsec_sa"] = {
                    "created": _pair(counts, 1), "established": _pair(counts, 3)}
            continue
        if label == "id/spi":
            sa = {"spi": value, "direction": None, "status": None, "proposal": None, "lifetime_rekey": None,
                  "dpd_sent_recv": None}
            current["sas"].append(sa)
        elif sa is None:
            raise Unparsed()
        elif label == "direction":
            sa["direction"] = value
        elif label == "status":
            sa["status"] = value
        elif label == "proposal":
            sa["proposal"] = value
        elif label == "lifetime/rekey":
            sa["lifetime_rekey"] = value
        elif label == "DPD sent/recv":
            sa["dpd_sent_recv"] = value
    for gateway in gateways:
        if None in (gateway["peer"], gateway["ike_sa"], gateway["ipsec_sa"]) or any(
                item["status"] is None for item in gateway["sas"]):
            raise Unparsed()
        established = sum(item["status"].startswith("established") for item in gateway["sas"])
        if established != gateway["ike_sa"]["established"][0] or (
                not gateway["sas"] and gateway["ike_sa"]["created"][0]):
            raise Unparsed()
    return gateways


_TUNNEL_HEADER = re.compile(r"list ipsec tunnel by names in vd \d+")
_KEYVALUE = re.compile(r"([A-Za-z_][A-Za-z0-9_.\[\]-]*)=(\S*)")
_ENDPOINT = re.compile(r"[0-9A-Fa-f.:]+:\d+")
_SELECTOR = re.compile(r"[ \t]+(src|dst): (\d+):([0-9.:a-fA-F]+-[0-9.:a-fA-F]+):(\d+)[ \t]*")
_SA_TRAFFIC = re.compile(r"[ \t]+dec:pkts/bytes=(\d+)/(\d+), enc:pkts/bytes=(\d+)/(\d+)[ \t]*")
_KNOWN_LINE = re.compile(r"[ \t]*(?:-{10,}|[A-Za-z_][A-Za-z0-9_./\[\]-]*[:=].*)")


def ipsec_tunnel_detail(text):
    """`diagnose vpn tunnel list name <phase1>`: tunnel state, counters, DPD and each phase 2 selector with SA.

    The header line must be present; a header alone means the kernel has no tunnel of that name. Lines that are
    neither `key=value` nor `label:` lines, a tunnel without `stat:`, or a proxyid count other than
    `proxyid_num` are unparsed."""
    lines = [line for line in _lines(text) if line.strip()]
    if not lines or not _TUNNEL_HEADER.fullmatch(lines[0].strip()):
        raise Unparsed()
    tunnels = []
    current = None
    proxy = None
    for line in lines[1:]:
        if _REDACTED_KEY_LINE.fullmatch(line):
            continue
        if not _KNOWN_LINE.fullmatch(line):
            raise Unparsed()
        stripped = line.strip()
        pairs = dict(_KEYVALUE.findall(line))
        if stripped.startswith("name="):
            peers = [token.split("->") for token in line.split() if "->" in token]
            if (len(peers) != 1 or len(peers[0]) != 2 or not all(_ENDPOINT.fullmatch(item) for item in peers[0])
                    or "status" not in pairs):
                raise Unparsed()
            current = {"name": pairs["name"], "status": pairs["status"],
                       "local": peers[0][0], "peer": peers[0][1],
                       "proxyid_num": None, "rx_packets": None, "tx_packets": None, "rx_bytes": None,
                       "tx_bytes": None, "dpd_status": None, "nat_traversal": None, "selectors": []}
            tunnels.append(current)
            proxy = None
            continue
        if stripped.startswith("-") or current is None:
            if current is None and not stripped.startswith("-"):
                raise Unparsed()
            continue
        if stripped.startswith("proxyid_num="):
            current["proxyid_num"] = int(pairs["proxyid_num"])
        elif stripped.startswith("stat:"):
            try:
                current.update({"rx_packets": int(pairs["rxp"]), "tx_packets": int(pairs["txp"]),
                                "rx_bytes": int(pairs["rxb"]), "tx_bytes": int(pairs["txb"])})
            except (KeyError, ValueError):
                raise Unparsed() from None
        elif stripped.startswith("dpd:"):
            current["dpd_status"] = pairs.get("status")
        elif stripped.startswith("natt:"):
            current["nat_traversal"] = pairs.get("mode")
        elif stripped.startswith("proxyid="):
            if "sa" not in pairs or not pairs["sa"].isdigit():
                raise Unparsed()
            # Measured: `sa=2` lists two SA blocks (e.g. after a rekey); their counters are summed.
            proxy = {"name": pairs["proxyid"], "sa": int(pairs["sa"]), "src": None, "dst": None,
                     "dec_packets": 0, "dec_bytes": 0, "enc_packets": 0, "enc_bytes": 0, "traffic_rows": 0}
            current["selectors"].append(proxy)
        elif proxy is not None and _SELECTOR.fullmatch(line):
            found = _SELECTOR.fullmatch(line)
            proxy[found.group(1)] = "%s:%s:%s" % (found.group(2), found.group(3), found.group(4))
        elif proxy is not None and _SA_TRAFFIC.fullmatch(line):
            found = _SA_TRAFFIC.fullmatch(line)
            proxy["traffic_rows"] += 1
            for number, field in enumerate(("dec_packets", "dec_bytes", "enc_packets", "enc_bytes"), 1):
                proxy[field] += int(found.group(number))
    for tunnel in tunnels:
        if tunnel["rx_packets"] is None or tunnel["proxyid_num"] != len(tunnel["selectors"]):
            raise Unparsed()
        for item in tunnel["selectors"]:
            if item["src"] is None or item["dst"] is None or item.pop("traffic_rows") != item["sa"]:
                raise Unparsed()
    return tunnels


PARSERS = {"ipsec_summary": ipsec_summary, "routing_table": routing_table, "ike_errors": ike_errors,
           "ike_gateway_detail": ike_gateway_detail, "ipsec_tunnel_detail": ipsec_tunnel_detail}


def _instance(name, tunnel):
    return name == tunnel or re.fullmatch(re.escape(tunnel) + r"_\d+", name) is not None


def _share(errors, packets):
    return 0.0 if errors == 0 else errors / packets if packets else float("inf")


def findings_for(tunnel, instances, routes, sources):
    found = []

    def add(rule, query, obj, fact, severity="fault"):
        found.append({"id": rule, "severity": severity, "layer": "runtime", "object": "vpn:" + obj, "fact": fact,
                      "sources": [sources[query]]})

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
            share = max(_share(item["rx_errors"], item["rx_packets"]), _share(item["tx_errors"], item["tx_packets"]))
            add("F-VPN-ERRORS", "ipsec_summary", item["name"],
                "rx(err) %d of %d, tx(err) %d of %d packets (%s)" % (
                    item["rx_errors"], item["rx_packets"], item["tx_errors"], item["tx_packets"],
                    "%.2f %% at most" % (share * 100) if share != float("inf") else "errors without packets"),
                "fault" if share >= ERROR_SHARE_FAULT else "notice")
    if routes is not None and not routes:
        add("F-VPN-NO-ROUTE", "routing_table", tunnel, "no route in routing-table via " + tunnel)
    return found


def _detail(read, clock, tunnel, instances, scope, parsed, sources, missing, checked):
    """Phase 1/2 detail of the exactly named tunnel. Not enrolled = `not_enrolled` (the summary triage stays as
    it was); enrolled but failed = a missing step, the verdict becomes incomplete."""
    if not instances or not any(item["name"] == tunnel for item in instances):
        return {"status": "not_applicable", "phase1": None, "phase2": None,
                "last_error": {"status": "unavailable", "reason": "detail_not_applicable"}}
    attempted = False
    previous_missing = len(missing)
    for _, query in DETAIL_STEPS:
        moment = clock()
        answer = read(query, {"tunnel": tunnel})
        if answer.get("reason") == "not_enrolled":
            continue
        attempted = True
        if not answer.get("ok"):
            missing.append(missing_read(query, answer))
            continue
        if not in_vdom(scope, answer):
            missing.append({"step": query, "reason": "vdom_unverified"})
            continue
        sources[query] = {"call": "triage_vpn", "query": query,
                          "content_sha256": answer["content_sha256"], "captured_at": _utc(moment)}
        try:
            parsed[query] = PARSERS[query](answer["text"])
        except Unparsed:
            missing.append({"step": query, "reason": "unparsed"})
        else:
            checked.append(query)
    phase1 = parsed.get("ike_gateway_detail")
    phase2 = parsed.get("ipsec_tunnel_detail")
    if len(missing) > previous_missing:
        status, reason = "incomplete", "detail_incomplete"
    elif attempted:
        # The verified name-scoped outputs carry status and counters, with no per-tunnel last error.
        status, reason = "read", "not_reported_by_fortios"
    else:
        status, reason = "not_enrolled", "detail_not_enrolled"
    return {"status": status,
            "phase1": None if phase1 is None else [item for item in phase1 if item["name"] == tunnel],
            "phase2": None if phase2 is None else [item for item in phase2 if item["name"] == tunnel],
            "last_error": {"status": "unavailable", "reason": reason}}


def detail_findings(tunnel, parsed, sources):
    """F-VPN-IKE-DOWN: the tunnel is known to the kernel (`diagnose vpn tunnel list`) but has no established IKE
    SA (`diagnose vpn ike gateway list` empty or without an established SA). Needs both detail reads."""
    if "ike_gateway_detail" not in parsed or "ipsec_tunnel_detail" not in parsed:
        return []
    kernel = [item for item in parsed["ipsec_tunnel_detail"] if item["name"] == tunnel]
    gateways = [item for item in parsed["ike_gateway_detail"] if item["name"] == tunnel]
    if not kernel or any(sa["status"].startswith("established") for gw in gateways for sa in gw["sas"]):
        return []
    state = kernel[0]
    fact = "no established IKE SA (phase 1) for %s; tunnel status=%s, dpd status=%s, selectors with SA %d/%d" % (
        tunnel, state["status"], state["dpd_status"], sum(1 for item in state["selectors"] if item["sa"]),
        len(state["selectors"]))
    return [{"id": "F-VPN-IKE-DOWN", "severity": "fault", "layer": "runtime", "object": "vpn:" + tunnel,
             "fact": fact, "sources": [sources["ike_gateway_detail"], sources["ipsec_tunnel_detail"]]}]


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
    scope = vdom_scope(first["text"])
    for _, query in STEPS[1:]:
        moment = clock()
        answer = read(query)
        if not answer.get("ok"):
            missing.append(missing_read(query, answer))
            continue
        if not in_vdom(scope, answer):
            # Multi-VDOM: a tunnel list of another or an unverified VDOM is no evidence for this VDOM.
            missing.append({"step": query, "reason": "vdom_unverified"})
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
    detail = _detail(read, clock, tunnel, instances, scope, parsed, sources, missing, checked)
    detailed = detail["status"] in {"read", "incomplete"}
    support = firmware_support(ident, DETAIL_IDENTITIES if detailed else IDENTITIES,
                               "triage_vpn with IPsec detail" if detailed else "triage_vpn")
    routes = None
    if "routing_table" in parsed:
        routes = [item for item in parsed["routing_table"] if _instance(item["interface"], tunnel)]
        routes = [item for number, item in enumerate(routes) if item not in routes[:number]]
    findings = findings_for(tunnel, instances, routes, sources)
    findings.extend(detail_findings(tunnel, parsed, sources))
    if scope and scope["vdom_mode"] == "multiple":
        for item in findings:
            if item["id"] == "F-VPN-NOT-FOUND":
                # Measured: the summary lists only the tunnels of the current VDOM.
                item["fact"] += " in VDOM " + str(scope["vdom"])
    if missing:
        verdict = "incomplete"
    elif any(item["severity"] == "fault" for item in findings):
        verdict = "fault_found"
    else:
        verdict = "no_fault_in_checked_data"
    return {
        "ok": True,
        "tunnel": tunnel,
        "identity": ident,
        **vdom_fields(scope),
        "current_vdom": scope["vdom"] if scope else None,
        "started_at": _utc(started),
        "finished_at": _utc(clock()),
        "chain": {"tunnel": {"name": tunnel, "instances": instances}, "routes": routes,
                  "ike_errors": parsed.get("ike_errors"), "detail": detail},
        "findings": findings,
        "hypotheses": [],
        "next_steps": [],
        "missing": missing,
        "checked": ["system_status"] + checked,
        "verdict": verdict,
        **firmware_fields(support),
    }


def srx_ike_associations(text):
    rows = []
    headings = False
    unknown = False
    for raw in text.splitlines():
        cols = raw.split()
        if not cols:
            continue
        if cols[0] == "Index" and {"State", "Remote", "Mode"} <= set(cols):
            headings = True
            continue
        if len(cols) != 6 or not cols[0].isdecimal():
            unknown = True
            continue
        index, *values = cols
        if values[0] in {"UP", "DOWN"}:
            state, _, _, mode, peer = values
        else:
            peer, state, _, _, mode = values
        if state not in {"UP", "DOWN"}:
            unknown = True
            continue
        rows.append({"id": int(index), "remote_gateway": peer, "state": state.lower(), "mode": mode})
    return {"records": rows, "complete": headings and bool(rows) and not unknown}


_SRX_IPSEC_SA = re.compile(r"(?mi)^[ \t]*ID:\s*(\d+)\s+Virtual-system:\s*([^,]+),\s*VPN Name:\s*([^\n]+)")
_SRX_IPSEC_WING = re.compile(r"(?mi)^[ \t]*Direction:\s*(inbound|outbound),\s*SPI:\s*([0-9a-fx]+)")


def srx_ipsec_associations(text):
    rows = []
    headers = list(_SRX_IPSEC_SA.finditer(text))
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        block = text[header.end():end]
        gateway = re.search(r"Local Gateway:\s*(\S+),\s*Remote Gateway:\s*(\S+)", block)
        bind = re.search(r"Bind-interface:\s*([^,\s]+)", block)
        wings = list(_SRX_IPSEC_WING.finditer(block))
        associations = []
        for number, wing in enumerate(wings):
            wing_end = wings[number + 1].start() if number + 1 < len(wings) else len(block)
            state = re.search(r"\bState:[ \t]*([^,\n]+)", block[wing.end():wing_end])
            associations.append({"direction": wing[1].lower(), "spi": wing[2], "state": state[1].strip() if state else None})
        rows.append({"id": int(header[1]), "virtual_system": header[2].strip(), "name": header[3].strip(),
                     "local_gateway": gateway[1] if gateway else None, "remote_gateway": gateway[2] if gateway else None,
                     "interface": bind[1] if bind else None, "associations": associations})
    complete = bool(rows) and len(rows) == len(re.findall(r"(?mi)^[ \t]*ID:", text)) and all(
        row["remote_gateway"] and {"inbound", "outbound"} == {
            sa["direction"] for sa in row["associations"] if sa["state"]
        } for row in rows
    )
    return {"records": rows, "complete": complete}


def srx_ipsec_statistics(text):
    rows = []
    scope = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if re.fullmatch(r"node\d+:", line):
            scope = {"node": line[:-1]}
            current = None
        elif line.startswith("Virtual-system:"):
            scope = {**scope, "virtual_system": line.partition(":")[2].strip()}
            current = None
        elif line in {"ESP Statistics:", "AH Statistics:", "Errors:"}:
            current = {"section": line[:-1], "counters": {}, **scope}
            rows.append(current)
        elif current is not None:
            for field in line.split(","):
                name, separator, value = field.partition(":")
                tokens = value.split(maxsplit=1)
                if separator and tokens and tokens[0].isascii() and tokens[0].isdecimal():
                    current["counters"][name.strip()] = int(tokens[0])
    esp = {"Encrypted bytes", "Decrypted bytes", "Encrypted packets", "Decrypted packets"}
    errors = {"ESP authentication failures", "ESP decryption failures", "Replay errors"}
    complete = any(row["section"] == "ESP Statistics" for row in rows) and any(row["section"] == "Errors" for row in rows) and all(
        (esp if row["section"] == "ESP Statistics" else errors if row["section"] == "Errors" else set()) <= row["counters"].keys()
        for row in rows
    )
    return {"records": rows, "complete": complete}
