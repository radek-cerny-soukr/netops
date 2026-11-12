#!/usr/bin/env python3
import argparse
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import tarfile
from pathlib import Path

PROTOCOL = "2025-06-18"
UNCHANGED = ("gateway/ca.pem", "gateway/ca.key", "gateway/server.key", "gateway/token")
MAY_CHANGE = {"gateway/instance.lock", "gateway/server.pem", "gateway/config.json",
              "gateway/audit/rejections.json", "helper/operations.jsonl", "admin/operations.jsonl"}
DYNAMIC_KEYS = {"time", "timestamp", "now", "uptime", "uptime_seconds", "started", "started_at",
                "checked_at", "generated_at", "days_remaining", "expires_in_days", "age_hours"}
API_KINDS = ("added", "definition", "response")
KEY_FIELDS = ("added_keys", "removed_keys", "changed_keys")
VALUE_FIELDS = ("added_keys", "changed_keys")
SHORT_SCALAR = 64
CATALOG = "read_query_catalog"
CATALOG_PAGE_LIMIT = 100
CATALOG_MAX_PAGES = 64
COMPARED = (("helper_status", "helper_status"), ("target_scope", "target_scope"),
            ("read_query_catalog", "read_query_catalog"), ("ssh_read_not_enrolled", "ssh_read"),
            ("audit_status", "audit_status"), ("admin_status", "admin_status"))
MCP_FILES = ("from-mcp.json", "to-mcp.json", "rollback-mcp.json")
# Prompts and the server capabilities are part of the compared API next to the tools: a prompt is the API
# object "prompt:<name>", the capabilities of the initialize result are the object "mcp:capabilities".
PROMPT_PREFIX = "prompt:"
CAPABILITIES = "mcp:capabilities"
PLACEHOLDER_REASON = re.compile(r"\bTODO\(")


def post(url, body, token=None, session=None, context=None):
    host, port, path = re.match(r"https://([^/:]+):(\d+)(/.*)", url).groups()
    connection = http.client.HTTPSConnection(host, int(port), context=context, timeout=30)
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": PROTOCOL}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if session:
        headers["Mcp-Session-Id"] = session
    try:
        connection.request("POST", path, body=json.dumps(body).encode(), headers=headers)
        response = connection.getresponse()
        raw = response.read()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, raw
    finally:
        connection.close()


def decode(headers, raw):
    if headers.get("content-type", "").startswith("text/event-stream"):
        for block in raw.decode().split("\n\n"):
            data = "\n".join(line[5:].lstrip() for line in block.splitlines() if line.startswith("data:"))
            if data:
                message = json.loads(data)
                if "id" in message:
                    return message
        raise ValueError("no JSON-RPC response in event stream")
    return json.loads(raw)


def mcp(args):
    token = Path(args.token_file).read_text().strip()
    context = ssl.create_default_context(cafile=args.ca)
    result = {"probes": {}, "calls": {}}
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL, "capabilities": {},
                       "clientInfo": {"name": "netops-upgrade-check", "version": "1"}}}
    result["probes"]["no_token"] = post(args.url, init, context=context)[0]
    result["probes"]["wrong_token"] = post(args.url, init, token="x" * len(token), context=context)[0]
    status, headers, raw = post(args.url, init, token=token, context=context)
    result["probes"]["token"] = status
    if status == 200:
        result["calls"]["initialize"] = {"http": status, "reply": decode(headers, raw)}
        session = headers.get("mcp-session-id")
        post(args.url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, token=token, session=session, context=context)
        calls = [("tools/list", "tools/list", {}), ("prompts/list", "prompts/list", {})] + [
            (name, "tools/call", {"name": tool, "arguments": arguments}) for name, tool, arguments in (
                ("helper_status", "helper_status", {}),
                ("audit_status", "audit_status", {}),
                ("admin_status", "admin_status", {"request_id": "upgrade-check-request"}),
                ("target_scope", "target_scope", {"target": args.target}),
                ("read_query_catalog", "read_query_catalog", {}),
                ("ssh_read_not_enrolled", "ssh_read", {"target": "not-enrolled.example.invalid", "platform": "linux", "query": "kernel"}))]
        for number, (name, method, params) in enumerate(calls, start=2):
            status, headers, raw = post(args.url, {"jsonrpc": "2.0", "id": number, "method": method, "params": params},
                                        token=token, session=session, context=context)
            result["calls"][name] = {"http": status, "reply": decode(headers, raw) if status == 200 else None}
        pages, offset = [], 0
        while len(pages) < CATALOG_MAX_PAGES:
            number += 1
            status, headers, raw = post(args.url, {"jsonrpc": "2.0", "id": number, "method": "tools/call", "params": {
                "name": CATALOG, "arguments": {"offset": offset, "limit": CATALOG_PAGE_LIMIT}}},
                token=token, session=session, context=context)
            reply = decode(headers, raw) if status == 200 else None
            pages.append({"http": status, "reply": reply})
            following = (((reply or {}).get("result") or {}).get("structuredContent") or {}).get("next_offset")
            if type(following) is not int or following <= offset:
                break
            offset = following
        result["calls"][CATALOG + "_pages"] = pages
    Path(args.out).write_text(json.dumps(result, indent=1, sort_keys=True))
    return 0 if result["probes"]["token"] == 200 else 1


def manifest(path):
    return {row[0]: row[1:] for row in json.loads(Path(path).read_text())}


def tar_members(path):
    with tarfile.open(path) as archive:
        return {m.name.removeprefix("./"): archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}


def json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return {str: "string", list: "array", dict: "object"}.get(type(value), type(value).__name__)


def strip_dynamic(value, product):
    if isinstance(value, dict):
        return {k: "<product>" if k == "version" and v == product else
                "<dynamic:%s>" % json_type(v) if k in DYNAMIC_KEYS else strip_dynamic(v, product)
                for k, v in value.items()}
    if isinstance(value, list):
        return [strip_dynamic(v, product) for v in value]
    return value


def tool_payload(reply, product):
    result = (reply or {}).get("result") or {}
    content = result.get("structuredContent")
    if content is None:
        texts = [c.get("text", "") for c in result.get("content", [])]
        try:
            content = [json.loads(t) for t in texts]
        except ValueError:
            content = texts
    return {"isError": bool(result.get("isError")), "content": strip_dynamic(content, product)}


def diff_manifest(old, new, may_change):
    problems = []
    for path in sorted(set(old) | set(new)):
        audit = path.startswith("gateway/audit/") and path.endswith(".jsonl")
        if path not in new:
            problems.append("missing " + path)
        elif path not in old:
            if not audit:
                problems.append("new " + path)
        elif old[path] == new[path]:
            continue
        elif old[path][:3] != new[path][:3]:
            problems.append("owner/mode " + (path or "."))
        elif not (audit or path in may_change):
            problems.append("changed " + path)
    return problems


def load_api_changes(path, env):
    if not path or not Path(path).is_file():
        return [], [], None
    raw = Path(path).read_bytes()
    info = {"file": Path(path).name, "sha256": hashlib.sha256(raw).hexdigest()}
    def unique(pairs):
        names = [k for k, _ in pairs]
        if len(names) != len(set(names)):
            raise ValueError("repeated key %s" % sorted({k for k in names if names.count(k) > 1}))
        return dict(pairs)

    try:
        doc = json.loads(raw, object_pairs_hook=unique)
    except ValueError as error:
        return [], ["declaration is not JSON: %s" % error], info
    if not isinstance(doc, dict) or set(doc) != {"from", "to", "changes"} or not isinstance(doc["changes"], list):
        return [], ["declaration must have exactly the keys from, to, changes (list)"], info
    problems = []
    if (doc["from"], doc["to"]) != (env["FROM_VERSION"], env["TO_VERSION"]):
        problems.append("declaration is for %s -> %s, not %s -> %s" % (doc["from"], doc["to"], env["FROM_VERSION"], env["TO_VERSION"]))
    items, seen = [], set()
    for item in doc["changes"]:
        text = json.dumps(item, sort_keys=True)
        if not isinstance(item, dict) or not {"tool", "kind", "reason"} <= set(item) \
                or not all(isinstance(item[k], str) and item[k].strip() for k in ("tool", "kind", "reason")):
            problems.append("item must have non-empty tool, kind, reason: %s" % text)
            continue
        if item["kind"] not in API_KINDS:
            problems.append("change kind %r not allowed for %s" % (item["kind"], item["tool"]))
            continue
        if PLACEHOLDER_REASON.search(item["reason"]):
            problems.append("reason of %s %s is an unreviewed placeholder" % (item["tool"], item["kind"]))
            continue
        allowed = {"tool", "kind", "reason", "breaking"} | (set(KEY_FIELDS) if item["kind"] != "added" else set())
        fields = {f: item.get(f, [] if f == "removed_keys" else {}) for f in KEY_FIELDS if f in allowed}
        if set(item) - allowed or not isinstance(item.get("breaking", False), bool) \
                or not isinstance(fields.get("removed_keys", []), list) \
                or not all(isinstance(fields[f], dict) and all(valid_expectation(e) for e in fields[f].values())
                           for f in VALUE_FIELDS if f in fields) \
                or not all(isinstance(p, str) and p.startswith("/") for v in fields.values() for p in v) \
                or (item["kind"] != "added" and not any(fields.values())):
            problems.append("invalid item %s: %s" % (item["kind"], text))
            continue
        keys = [(item["tool"], "added", "", "")] if item["kind"] == "added" else \
            [(item["tool"], item["kind"], f, p) for f, v in fields.items() for p in v]
        repeated = [k for k in keys if k in seen]
        if repeated:
            problems.append("repeated item %s" % " ".join(x for x in repeated[0] if x))
            continue
        seen.update(keys)
        items.append(item)
    info["changes"] = doc["changes"]
    return items, problems, info


def fingerprint(value):
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def short_scalar(value):
    return value is None or isinstance(value, (bool, int, float)) or isinstance(value, str) and len(value) <= SHORT_SCALAR


def valid_expectation(e):
    return isinstance(e, dict) and "sha256" in e and set(e) <= {"sha256", "value"} \
        and isinstance(e["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", e["sha256"]) is not None


def value_at(doc, pointer):
    for part in pointer.split("/")[1:]:
        doc = doc[part.replace("~1", "/").replace("~0", "~")]
    return doc


def expectation_ok(e, value):
    return e["sha256"] == fingerprint(value) and (
        e["value"] == value and json_type(e["value"]) == json_type(value) if "value" in e else not short_scalar(value))


def tool_definitions(m):
    """Tools, prompts and server capabilities of one capture; a server without prompts lists none."""
    calls = m.get("calls", {})
    reply = (calls.get("tools/list") or {}).get("reply") or {}
    found = {t["name"]: t for t in reply.get("result", {}).get("tools", [])}
    prompts = ((calls.get("prompts/list") or {}).get("reply") or {}).get("result") or {}
    found.update({PROMPT_PREFIX + p["name"]: p for p in prompts.get("prompts", []) if isinstance(p, dict) and "name" in p})
    capabilities = (((calls.get("initialize") or {}).get("reply") or {}).get("result") or {}).get("capabilities")
    if isinstance(capabilities, dict):
        found[CAPABILITIES] = capabilities
    return found


def tool_names(m):
    return sorted(tool_definitions(m))


def pointer_diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        out = {f: [] for f in KEY_FIELDS}
        for k in sorted(set(a) | set(b)):
            p = path + "/" + k.replace("~", "~0").replace("/", "~1")
            if k not in a:
                out["added_keys"].append(p)
            elif k not in b:
                out["removed_keys"].append(p)
            else:
                for f, v in pointer_diff(a[k], b[k], p).items():
                    out[f] += v
        return out
    return {"added_keys": [], "removed_keys": [], "changed_keys": [] if a == b else [path]}


def catalog_payload(m):
    pages = m.get("calls", {}).get(CATALOG + "_pages") or []
    merged, returned, last = {}, 0, None
    for page in pages:
        result = (page.get("reply") or {}).get("result") or {}
        c = result.get("structuredContent")
        if result.get("isError") or not isinstance(c, dict) or not isinstance(c.get("returned"), int):
            return None
        for field in ("queries", "query_metadata"):
            for platform, entries in (c.get(field) or {}).items():
                merged.setdefault(field, {}).setdefault(platform, {}).update(entries)
        for k, v in c.items():
            if k not in ("queries", "query_metadata", "offset", "returned", "next_offset") and merged.setdefault(k, v) != v:
                return None
        returned, last = returned + c["returned"], c.get("next_offset")
    count = sum(len(v) for v in merged.get("queries", {}).values())
    if not pages or last is not None or returned != merged.get("total") or count != returned:
        return None
    return {"isError": False, "content": merged}


def compare_mcp(mf, mt, from_version, to_version, items, problems):
    declared, expected, new_values = set(), {}, {}
    for item in items:
        if item["kind"] == "added":
            declared.add((item["tool"], "added", "", ""))
        else:
            declared |= {(item["tool"], item["kind"], f, p) for f in KEY_FIELDS for p in item.get(f, [])}
            expected.update({(item["tool"], item["kind"], f, p): e for f in VALUE_FIELDS for p, e in item.get(f, {}).items()})
    df, dt = tool_definitions(mf), tool_definitions(mt)
    observed_t = {(t, "added", "", "") for t in set(dt) - set(df)}
    removed = sorted(set(df) - set(dt))
    for t in sorted(set(df) & set(dt)):
        for f, v in pointer_diff(df[t], dt[t]).items():
            for p in v:
                observed_t.add((t, "definition", f, p))
                if f in VALUE_FIELDS:
                    new_values[(t, "definition", f, p)] = value_at(dt[t], p)
    observed_r, errors, incomplete = set(), [], []
    for name, tool in COMPARED:
        if tool == CATALOG:
            a, b = catalog_payload(mf), catalog_payload(mt)
            if a is None or b is None:
                incomplete.append(name)
                continue
        else:
            if any(not (m.get("calls", {}).get(name) or {}).get("reply", {}).get("result") for m in (mf, mt)):
                incomplete.append(name)
                continue
            a = tool_payload((mf.get("calls", {}).get(name) or {}).get("reply"), from_version)
            b = tool_payload((mt.get("calls", {}).get(name) or {}).get("reply"), to_version)
        if (name != "ssh_read_not_enrolled" and b["isError"]) or a["isError"] != b["isError"]:
            errors.append(name)
        for f, v in pointer_diff(a["content"], b["content"]).items():
            for p in v:
                observed_r.add((tool, "response", f, p))
                if f in VALUE_FIELDS and p.startswith("/"):
                    new_values[(tool, "response", f, p)] = value_at(b["content"], p)
    wrong = {k for k, e in expected.items() if k in new_values and not expectation_ok(e, new_values[k])}
    wrong_t = {k for k in wrong if k[1] != "response"}
    wrong_r = wrong - wrong_t
    show = lambda keys: sorted(" ".join(x for x in k if x) for k in keys) or "none"
    decl_t = {k for k in declared if k[1] != "response"}
    decl_r = {k for k in declared if k[1] == "response"}
    breaking = sorted({i["tool"] for i in items if i.get("breaking")})
    tools_ok = not problems and bool(df) and bool(dt) and not removed and observed_t == decl_t and not wrong_t
    tools_detail = "FROM %d, TO %d tools, prompts and capabilities; declared: %d; undeclared: %s; removed: %s; stale declaration: %s; different value: %s; BREAKING: %s" % (
        len(df), len(dt), len(observed_t & decl_t), show(observed_t - decl_t), removed or "none",
        show(decl_t - observed_t), show(wrong_t), breaking or "none")
    resp_ok = not problems and bool(mt) and bool(mf) and observed_r == decl_r and not wrong_r and not errors and not incomplete
    resp_detail = "declared: %d; undeclared: %s; stale declaration: %s; different value: %s; error or changed isError: %s; incomplete catalogue: %s" % (
        len(observed_r & decl_r), show(observed_r - decl_r), show(decl_r - observed_r), show(wrong_r), errors or "none", incomplete or "none")
    if problems:
        tools_detail += "; declaration: " + "; ".join(problems)
        resp_detail += "; declaration: " + "; ".join(problems)
    return tools_ok, tools_detail, resp_ok, resp_detail


def report(args):
    w = Path(args.work)
    env = json.loads((w / "params.json").read_text())
    checks = []

    def check(name, ok, detail=""):
        checks.append({"check": name, "result": "OK" if ok else "FAIL", "detail": detail})

    def read(name, default=""):
        p = w / name
        return p.read_text().strip() if p.exists() else default

    def load(name):
        p = w / name
        return json.loads(p.read_text()) if p.exists() and p.stat().st_size else None

    steps = [line.split(" ", 2) for line in read("steps.log").splitlines() if line]
    failed = [s[1] for s in steps if s[0] != "rc=0"]
    check("procedure-steps", not failed, "failed steps: " + ", ".join(failed) if failed else "%d steps rc 0" % len(steps))

    image_ok = read("to-image-id.txt") == read("to-expected-image-id.txt") != ""
    version = read("to-version.txt")
    check("TO-version-running", image_ok and version == env["TO_VERSION"],
          "netops version=%r, container on TO image=%s" % (version, image_ok))
    check("health-ready", read("to-health.txt") == "ready", read("to-health.txt"))

    src, restored = w / "backup.tar.source-manifest.json", w / "backup.tar.restored-manifest.json"
    m0 = manifest(src) if src.exists() else {}
    m1 = manifest(w / "m1.json") if (w / "m1.json").exists() else {}
    m2 = manifest(w / "m2.json") if (w / "m2.json").exists() else {}
    check("restore-manifest-identical", src.exists() and restored.exists() and src.read_bytes() == restored.read_bytes() and len(m0) > 5,
          "%d paths" % len(m0))

    same = [p for p in UNCHANGED if p in m0 and m0.get(p) == m1.get(p) == m2.get(p)]
    ca_same = read("to-ca.pem") == read("from-ca.pem") != ""
    check("CA-key-token-unchanged", len(same) == len(UNCHANGED) and ca_same,
          "identical %d/%d (%s), CA output identical=%s" % (len(same), len(UNCHANGED), ",".join(same), ca_same))

    before, after = (tar_members(w / "backup.tar") if (w / "backup.tar").exists() else {}), \
        (tar_members(w / "after-gw.tar") if (w / "after-gw.tar").exists() else {})
    try:
        c0, c2 = json.loads(before["gateway/config.json"]), json.loads(after["gateway/config.json"])
        declared = {k for k in set(c0) | set(c2) if c0.get(k) != c2.get(k)}
        ok = declared <= {"product_version"} and c2.get("product_version") == env["TO_VERSION"]
        check("configuration-unchanged", ok, "changed keys: %s" % sorted(declared))
    except (KeyError, ValueError) as error:
        check("configuration-unchanged", False, "%s: %s" % (type(error).__name__, error))

    problems = diff_manifest(m0, m1, MAY_CHANGE) if m0 and m1 else ["manifest missing"]
    roles = sorted(p for p in m0 if p.split("/")[0] in ("helper", "auditor", "admin") and m0[p][4] is not None)
    populated = all(any(p.startswith(role + "/") for p in roles) for role in ("helper", "auditor", "admin"))
    check("role-data-unchanged", not problems and populated,
          "%d role files; %s" % (len(roles), "; ".join(problems) or "only allowed changes"))

    segments = sorted(p for p in before if p.startswith("gateway/audit/") and p.endswith(".jsonl"))
    bad = [p for p in segments if not after.get(p, b"").startswith(before[p])]
    new_audit = b"".join(after[p][len(before.get(p, b"")):] for p in sorted(after) if p.startswith("gateway/audit/") and p.endswith(".jsonl"))
    upgrade = [json.loads(line).get("payload", {}) for line in new_audit.splitlines() if b'"upgrade"' in line]
    want = {"from": env["FROM_VERSION"], "to": env["TO_VERSION"]}
    upgrade_ok = any(r.get("upgrade") == want for r in upgrade) if env["FROM_VERSION"] != env["TO_VERSION"] else True
    check("audit-prefix", bool(segments) and not bad,
          "%d segments, prefix broken: %s" % (len(segments), bad or "none"))
    check("audit-record-upgrade", upgrade_ok, "instance_start upgrade=%s found=%s" % (want, upgrade_ok))

    mf, mt = load("from-mcp.json") or {}, load("to-mcp.json") or {}
    api_items, problems, api_info = load_api_changes(args.api_changes, env)
    tools_ok, tools_detail, resp_ok, resp_detail = compare_mcp(mf, mt, env["FROM_VERSION"], env["TO_VERSION"], api_items, problems)
    def populated_roles(m, product):
        auditor = tool_payload((m.get("calls", {}).get("audit_status") or {}).get("reply"), product)
        admin = tool_payload((m.get("calls", {}).get("admin_status") or {}).get("reply"), product)
        a, d = auditor["content"], admin["content"]
        devices = a.get("devices", []) if isinstance(a, dict) else []
        return (not auditor["isError"] and not admin["isError"] and
                any(row.get("run_id") is not None and row.get("findings_total", 0) > 0 for row in devices) and
                isinstance(d, dict) and d.get("request_id") == "upgrade-check-request" and
                d.get("change_id") == "a" * 32 and d.get("status") == "finished" and d.get("result") == "confirmed")
    check("nonempty-auditor-admin", all(populated_roles(m, product) for m, product in
          ((mf, env["FROM_VERSION"]), (mt, env["TO_VERSION"]), (load("rollback-mcp.json") or {}, env["FROM_VERSION"]))),
          "Auditor run with findings and completed Admin request resolve before/after/rollback")
    def coverage_gaps(m, product):
        auditor = tool_payload((m.get("calls", {}).get("audit_status") or {}).get("reply"), product)
        rows = auditor["content"].get("devices", []) if isinstance(auditor["content"], dict) else []
        coverage = next((row.get("coverage") for row in rows if row.get("device") == "upgrade-adc"), None) or {}
        return ([gap.get("rule_id") for gap in coverage.get("inherent_gaps", [])] == ["fortiadc.tls.factory-certificate"]
                and [gap.get("reason") for gap in coverage.get("actionable_gaps", [])] == ["visibility:networking"])
    check("auditor-coverage-gaps-after-upgrade", coverage_gaps(mt, env["TO_VERSION"]),
          "the seeded FortiADC run keeps one inherent and one actionable coverage gap in TO")
    tf = tool_names(mf)
    check("mcp-tools-list", tools_ok, tools_detail)
    check("mcp-role-responses", resp_ok, resp_detail)
    probes = mt.get("probes", {})
    check("token-valid-no-token-401", probes == {"no_token": 401, "wrong_token": 401, "token": 200}, json.dumps(probes, sort_keys=True))
    conn_f = [l for l in read("from-connection.txt").splitlines() if not re.search(r"\bdays?\b|expir", l, re.I)]
    conn_t = [l for l in read("to-connection.txt").splitlines() if not re.search(r"\bdays?\b|expir", l, re.I)]
    check("connection-identical", conn_f == conn_t and len(conn_t) > 0, "%d lines without CA days" % len(conn_t))

    second = diff_manifest(m1, m2, MAY_CHANGE - {"gateway/config.json", "gateway/server.pem"}) if m1 and m2 else ["manifest missing"]
    check("second-start-changes-nothing", not second and m1.get("gateway/config.json") == m2.get("gateway/config.json"),
          "; ".join(second) or "config.json identical, only allowed appends")

    secrets = [Path(p).read_bytes().strip() for p in args.secret if Path(p).exists()]
    leaks = []
    for name in ("to-logs.txt", "from-logs.txt", "steps.log") + MCP_FILES:
        data = (w / name).read_bytes() if (w / name).exists() else b""
        leaks += [name for s in secrets if s and s in data]
    check("no-token-or-password-in-logs", len(secrets) == len(args.secret) and not leaks and (w / "to-logs.txt").exists(),
          "leaks: %s" % (leaks or "none"))

    rb = load("rollback-mcp.json") or {}
    rb_ok = read("rollback-version.txt") == env["FROM_VERSION"] and read("rollback-health.txt") == "ready" \
        and rb.get("probes", {}).get("token") == 200 and bool(tf) and tool_definitions(rb) == tool_definitions(mf)
    check("rollback-FROM", rb_ok, "version=%r health=%r mcp=%s" % (read("rollback-version.txt"), read("rollback-health.txt"), rb.get("probes")))
    pre_rb = w / "from-before-rollback-manifest.json"
    check("FROM-untouched-until-rollback", pre_rb.exists() and src.exists() and pre_rb.read_bytes() == src.read_bytes(),
          "FROM manifest before rollback = backup manifest")

    ok = all(c["result"] == "OK" for c in checks)
    out = Path(args.out)
    for name in MCP_FILES:
        data = (w / name).read_bytes() if (w / name).exists() else b""
        for s in secrets:
            data = data.replace(s, b"<masked>") if s else data
        if data:
            (out / ("mcp-" + name.removesuffix("-mcp.json") + ".json")).write_bytes(data)
    doc = {"result": "OK" if ok else "FAIL", "params": env, "api_changes": api_info, "checks": checks,
           "steps": [{"rc": s[0][3:], "step": s[1], "seconds": s[2] if len(s) > 2 else ""} for s in steps]}
    (out / "report.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    lines = ["%-4s %-28s %s" % (c["result"], c["check"], c["detail"]) for c in checks]
    lines += ["BREAKING %s %s: %s" % (i["tool"], i["kind"], i["reason"]) for i in api_items if i.get("breaking")]
    lines.append("TOTAL %s: %d/%d OK, FROM %s -> TO %s" % (doc["result"], sum(c["result"] == "OK" for c in checks),
                                                          len(checks), env["FROM_IMAGE"], env["TO_IMAGE"]))
    (out / "summary.txt").write_text("\n".join(lines) + "\n")
    leaks_out = [p.name for p in out.iterdir() for s in secrets if s and s in p.read_bytes()]
    if leaks_out:
        print("SECRET IN OUTPUT: " + ", ".join(leaks_out), file=sys.stderr)
        return 1
    print("\n".join(lines))
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("mcp")
    p.add_argument("--url", required=True)
    p.add_argument("--ca", required=True)
    p.add_argument("--token-file", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("report")
    p.add_argument("--work", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--secret", action="append", default=[])
    p.add_argument("--api-changes")
    args = parser.parse_args()
    return mcp(args) if args.cmd == "mcp" else report(args)


if __name__ == "__main__":
    sys.exit(main())
