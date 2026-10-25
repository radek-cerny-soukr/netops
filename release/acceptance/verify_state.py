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
                "checked_at", "generated_at", "days_remaining", "expires_in_days"}


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
        session = headers.get("mcp-session-id")
        post(args.url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, token=token, session=session, context=context)
        calls = [("tools/list", "tools/list", {})] + [
            (name, "tools/call", {"name": tool, "arguments": arguments}) for name, tool, arguments in (
                ("helper_status", "helper_status", {}),
                ("target_scope", "target_scope", {"target": args.target}),
                ("read_query_catalog", "read_query_catalog", {}),
                ("ssh_read_not_enrolled", "ssh_read", {"target": "not-enrolled.example.invalid", "platform": "linux", "query": "kernel"}))]
        for number, (name, method, params) in enumerate(calls, start=2):
            status, headers, raw = post(args.url, {"jsonrpc": "2.0", "id": number, "method": method, "params": params},
                                        token=token, session=session, context=context)
            result["calls"][name] = {"http": status, "reply": decode(headers, raw) if status == 200 else None}
    Path(args.out).write_text(json.dumps(result, indent=1, sort_keys=True))
    return 0 if result["probes"]["token"] == 200 else 1


def manifest(path):
    return {row[0]: row[1:] for row in json.loads(Path(path).read_text())}


def tar_members(path):
    with tarfile.open(path) as archive:
        return {m.name.removeprefix("./"): archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}


def strip_dynamic(value, product):
    if isinstance(value, dict):
        return {k: "<product>" if k == "version" and v == product else strip_dynamic(v, product)
                for k, v in value.items() if k not in DYNAMIC_KEYS}
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
    check("kroky-postupu", not failed, "neuspesne kroky: " + ", ".join(failed) if failed else "%d kroku rc 0" % len(steps))

    image_ok = read("to-image-id.txt") == read("to-expected-image-id.txt") != ""
    version = read("to-version.txt")
    check("bezi-verze-TO", image_ok and version == env["TO_VERSION"],
          "netops version=%r, kontejner na obrazu TO=%s" % (version, image_ok))
    check("health-ready", read("to-health.txt") == "ready", read("to-health.txt"))

    src, restored = w / "backup.tar.source-manifest.json", w / "backup.tar.restored-manifest.json"
    m0 = manifest(src) if src.exists() else {}
    m1 = manifest(w / "m1.json") if (w / "m1.json").exists() else {}
    m2 = manifest(w / "m2.json") if (w / "m2.json").exists() else {}
    check("obnova-manifest-shodny", src.exists() and restored.exists() and src.read_bytes() == restored.read_bytes() and len(m0) > 5,
          "%d cest" % len(m0))

    same = [p for p in UNCHANGED if p in m0 and m0.get(p) == m1.get(p) == m2.get(p)]
    ca_same = read("to-ca.pem") == read("from-ca.pem") != ""
    check("CA-klic-token-beze-zmeny", len(same) == len(UNCHANGED) and ca_same,
          "shodne %d/%d (%s), ca vystup shodny=%s" % (len(same), len(UNCHANGED), ",".join(same), ca_same))

    before, after = (tar_members(w / "backup.tar") if (w / "backup.tar").exists() else {}), \
        (tar_members(w / "after-gw.tar") if (w / "after-gw.tar").exists() else {})
    try:
        c0, c2 = json.loads(before["gateway/config.json"]), json.loads(after["gateway/config.json"])
        declared = {k for k in set(c0) | set(c2) if c0.get(k) != c2.get(k)}
        ok = declared <= {"product_version"} and c2.get("product_version") == env["TO_VERSION"]
        check("konfigurace-beze-zmeny", ok, "zmenene klice: %s" % sorted(declared))
    except (KeyError, ValueError) as error:
        check("konfigurace-beze-zmeny", False, "%s: %s" % (type(error).__name__, error))

    problems = diff_manifest(m0, m1, MAY_CHANGE) if m0 and m1 else ["chybi manifest"]
    roles = sorted(p for p in m0 if p.split("/")[0] in ("helper", "auditor", "admin") and m0[p][4] is not None)
    check("data-roli-beze-zmeny", not problems and len(roles) > 0,
          "%d souboru roli; %s" % (len(roles), "; ".join(problems) or "jen povolene zmeny"))

    segments = sorted(p for p in before if p.startswith("gateway/audit/") and p.endswith(".jsonl"))
    bad = [p for p in segments if not after.get(p, b"").startswith(before[p])]
    new_audit = b"".join(after[p][len(before.get(p, b"")):] for p in sorted(after) if p.startswith("gateway/audit/") and p.endswith(".jsonl"))
    upgrade = [json.loads(line).get("payload", {}) for line in new_audit.splitlines() if b'"upgrade"' in line]
    want = {"from": env["FROM_VERSION"], "to": env["TO_VERSION"]}
    upgrade_ok = any(r.get("upgrade") == want for r in upgrade) if env["FROM_VERSION"] != env["TO_VERSION"] else True
    check("audit-prefix", bool(segments) and not bad,
          "%d segmentu, prefix porusen: %s" % (len(segments), bad or "zadny"))
    check("audit-zaznam-upgrade", upgrade_ok, "instance_start upgrade=%s nalezen=%s" % (want, upgrade_ok))

    mf, mt = load("from-mcp.json") or {}, load("to-mcp.json") or {}

    def tools(m):
        reply = (m.get("calls", {}).get("tools/list") or {}).get("reply") or {}
        return sorted(t["name"] for t in reply.get("result", {}).get("tools", []))
    tf, tt = tools(mf), tools(mt)
    check("mcp-tools-list", tf == tt and len(tt) > 0, "FROM %d, TO %d nastroju" % (len(tf), len(tt)))
    diffs = []
    for name in ("helper_status", "target_scope", "read_query_catalog", "ssh_read_not_enrolled"):
        a = tool_payload((mf.get("calls", {}).get(name) or {}).get("reply"), env["FROM_VERSION"])
        b = tool_payload((mt.get("calls", {}).get(name) or {}).get("reply"), env["TO_VERSION"])
        if a != b or (name != "ssh_read_not_enrolled" and b["isError"]):
            diffs.append(name)
    check("mcp-odpovedi-roli", not diffs and bool(mt), "odlisne: %s" % (diffs or "zadne"))
    probes = mt.get("probes", {})
    check("token-plati-bez-tokenu-401", probes == {"no_token": 401, "wrong_token": 401, "token": 200}, json.dumps(probes, sort_keys=True))
    conn_f = [l for l in read("from-connection.txt").splitlines() if not re.search(r"\bdays?\b|expir", l, re.I)]
    conn_t = [l for l in read("to-connection.txt").splitlines() if not re.search(r"\bdays?\b|expir", l, re.I)]
    check("connection-shodne", conn_f == conn_t and len(conn_t) > 0, "%d radku bez dnu CA" % len(conn_t))

    second = diff_manifest(m1, m2, MAY_CHANGE - {"gateway/config.json", "gateway/server.pem"}) if m1 and m2 else ["chybi manifest"]
    check("druhy-start-nic-nemeni", not second and m1.get("gateway/config.json") == m2.get("gateway/config.json"),
          "; ".join(second) or "config.json shodny, jen povolene appendy")

    secrets = [Path(p).read_bytes().strip() for p in args.secret if Path(p).exists()]
    leaks = []
    for name in ("to-logs.txt", "from-logs.txt", "steps.log"):
        data = (w / name).read_bytes() if (w / name).exists() else b""
        leaks += [name for s in secrets if s and s in data]
    check("token-ani-heslo-v-logs", len(secrets) == len(args.secret) and not leaks and (w / "to-logs.txt").exists(),
          "uniky: %s" % (leaks or "zadne"))

    rb = load("rollback-mcp.json") or {}
    rb_ok = read("rollback-version.txt") == env["FROM_VERSION"] and read("rollback-health.txt") == "ready" \
        and rb.get("probes", {}).get("token") == 200 and tools(rb) == tf
    check("rollback-FROM", rb_ok, "verze=%r health=%r mcp=%s" % (read("rollback-version.txt"), read("rollback-health.txt"), rb.get("probes")))
    pre_rb = w / "from-before-rollback-manifest.json"
    check("FROM-nedotcena-do-rollbacku", pre_rb.exists() and src.exists() and pre_rb.read_bytes() == src.read_bytes(),
          "manifest FROM pred rollbackem = manifest zalohy")

    ok = all(c["result"] == "OK" for c in checks)
    out = Path(args.out)
    doc = {"result": "OK" if ok else "FAIL", "params": env, "checks": checks,
           "steps": [{"rc": s[0][3:], "step": s[1], "seconds": s[2] if len(s) > 2 else ""} for s in steps]}
    (out / "report.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    lines = ["%-4s %-28s %s" % (c["result"], c["check"], c["detail"]) for c in checks]
    lines.append("CELKEM %s: %d/%d OK, FROM %s -> TO %s" % (doc["result"], sum(c["result"] == "OK" for c in checks),
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
    args = parser.parse_args()
    return mcp(args) if args.cmd == "mcp" else report(args)


if __name__ == "__main__":
    sys.exit(main())
