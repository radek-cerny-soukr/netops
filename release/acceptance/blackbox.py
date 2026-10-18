#!/usr/bin/env python3
import argparse
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlsplit

PROTOCOL = "2025-06-18"
MAX_LEAF_DAYS = 90


class Result:
    def __init__(self):
        self.items = []

    def add(self, check, spec, status, detail):
        self.items.append({"check": check, "spec": spec, "status": status, "detail": detail})

    def summary(self):
        counts = {}
        for item in self.items:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        return counts


def tls_context(cafile=None, verify=True, minimum=None, maximum=None):
    if verify:
        context = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if minimum:
        context.minimum_version = minimum
    if maximum:
        context.maximum_version = maximum
    return context


def post(target, body, token=None, context=None, session=None, path_suffix="", extra_headers=None, timeout=15):
    parts = urlsplit(target)
    connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=context, timeout=timeout)
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": PROTOCOL}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if session:
        headers["Mcp-Session-Id"] = session
    headers.update(extra_headers or {})
    try:
        connection.request("POST", (parts.path or "/") + path_suffix, body=json.dumps(body).encode(), headers=headers)
        response = connection.getresponse()
        raw = response.read()
        return response.status, dict((k.lower(), v) for k, v in response.getheaders()), raw
    finally:
        connection.close()


def decode_rpc(headers, raw):
    kind = headers.get("content-type", "")
    if kind.startswith("application/json"):
        return json.loads(raw)
    if kind.startswith("text/event-stream"):
        messages = []
        for block in raw.decode("utf-8", "replace").split("\n\n"):
            data = [line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")]
            if data:
                messages.append(json.loads("\n".join(data)))
        responses = [m for m in messages if "id" in m and ("result" in m or "error" in m)]
        if len(responses) != 1:
            raise ValueError("expected exactly one JSON-RPC response in the event stream, found %d" % len(responses))
        return responses[0]
    raise ValueError("unexpected content type %r" % kind)


def initialize_body(request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL, "capabilities": {},
                       "clientInfo": {"name": "netops-acceptance", "version": "1.0.0"}}}


def mcp_session(target, token, context):
    status, headers, raw = post(target, initialize_body(), token=token, context=context)
    if status != 200:
        raise RuntimeError("initialize returned HTTP %d" % status)
    reply = decode_rpc(headers, raw)
    if "result" not in reply:
        raise RuntimeError("initialize returned error %r" % reply.get("error"))
    session = headers.get("mcp-session-id")
    status, _, _ = post(target, {"jsonrpc": "2.0", "method": "notifications/initialized"}, token=token, context=context, session=session)
    if status not in (200, 202, 204):
        raise RuntimeError("notifications/initialized returned HTTP %d" % status)
    return session, reply["result"]


def check_plain_http(result, target):
    parts = urlsplit(target)
    connection = http.client.HTTPConnection(parts.hostname, parts.port or 443, timeout=10)
    try:
        connection.request("POST", parts.path or "/", body=json.dumps(initialize_body()).encode(),
                           headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
        response = connection.getresponse()
        body = response.read(4096)
        if response.status == 200 or b"jsonrpc" in body:
            result.add("plain-http-refused", "F12", "FAIL", "plain HTTP request answered with HTTP %d" % response.status)
        else:
            result.add("plain-http-refused", "F12", "PASS", "plain HTTP answered only HTTP %d without JSON-RPC" % response.status)
    except (http.client.HTTPException, OSError) as error:
        result.add("plain-http-refused", "F12", "PASS", "plain HTTP failed: %s" % type(error).__name__)
    finally:
        connection.close()


def check_untrusted_ca(result, target, token):
    try:
        post(target, initialize_body(), token=token, context=tls_context())
        result.add("system-trust-rejects", "F13", "FAIL", "server certificate verified against the system trust store; expected the private NetOps CA only")
    except ssl.SSLCertVerificationError as error:
        result.add("system-trust-rejects", "F13", "PASS", "system trust store rejects the server: %s" % error.verify_message)
    except OSError as error:
        result.add("system-trust-rejects", "F13", "FAIL", "unexpected error %s: %s" % (type(error).__name__, error))


def check_wrong_hostname(result, target, cafile, token):
    parts = urlsplit(target)
    address = None
    try:
        candidates = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)
    except OSError as error:
        result.add("hostname-verified", "F13", "NOT RUN", "cannot resolve %s: %s" % (parts.hostname, error))
        return
    for family, kind, proto, _, sockaddr in candidates:
        try:
            with socket.socket(family, kind, proto) as probe:
                probe.settimeout(5)
                probe.connect(sockaddr)
            address = sockaddr[0]
            break
        except OSError:
            continue
    if address is None:
        result.add("hostname-verified", "F13", "NOT RUN", "no resolved address of %s accepts TCP" % parts.hostname)
        return
    if address == parts.hostname:
        result.add("hostname-verified", "F13", "NOT RUN", "target is already an address; no alternate name to try")
        return
    alternate = "https://%s:%d%s" % (address if ":" not in address else "[%s]" % address, parts.port or 443, parts.path or "/")
    try:
        post(alternate, initialize_body(), token=token, context=tls_context(cafile))
        result.add("hostname-verified", "F13", "FAIL", "certificate also accepted for %s (not in SAN)" % address)
    except ssl.SSLCertVerificationError:
        result.add("hostname-verified", "F13", "PASS", "address %s not covered by the certificate is rejected" % address)
    except OSError as error:
        result.add("hostname-verified", "F13", "FAIL", "unexpected error %s: %s" % (type(error).__name__, error))


def check_legacy_tls(result, target, cafile, token):
    for name, version in (("TLSv1.1", ssl.TLSVersion.TLSv1_1), ("TLSv1", ssl.TLSVersion.TLSv1)):
        try:
            context = tls_context(cafile, minimum=version, maximum=version)
            context.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError) as error:
            result.add("legacy-tls-refused-" + name, "F12", "NOT RUN", "local OpenSSL cannot offer %s: %s" % (name, error))
            continue
        try:
            post(target, initialize_body(), token=token, context=context)
            result.add("legacy-tls-refused-" + name, "F12", "FAIL", "%s handshake accepted" % name)
        except (ssl.SSLError, OSError) as error:
            result.add("legacy-tls-refused-" + name, "F12", "PASS", "%s refused: %s" % (name, type(error).__name__))


def check_authentication(result, target, cafile, token):
    context = tls_context(cafile)
    cases = (("no-token", None, ""), ("wrong-token", "x" * len(token), ""), ("empty-token", "", ""),
             ("token-in-query", None, "?token=" + token), ("token-in-query-access_token", None, "?access_token=" + token))
    for name, value, suffix in cases:
        try:
            status, headers, raw = post(target, initialize_body(), token=value, context=context, path_suffix=suffix)
        except OSError as error:
            result.add("auth-" + name, "F12/F14", "FAIL", "connection error %s" % type(error).__name__)
            continue
        leaked = token.encode() in raw or any(token in v for v in headers.values())
        if status in (401, 403) and not leaked and b'"result"' not in raw:
            result.add("auth-" + name, "F12/F14", "PASS", "HTTP %d" % status)
        else:
            result.add("auth-" + name, "F12/F14", "FAIL", "HTTP %d, token echoed=%s" % (status, leaked))


def check_session(result, target, cafile, token, expect_tools):
    context = tls_context(cafile)
    try:
        session, info = mcp_session(target, token, context)
        status, headers, raw = post(target, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, token=token, context=context, session=session)
        reply = decode_rpc(headers, raw)
        names = sorted(tool["name"] for tool in reply["result"]["tools"])
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        result.add("mcp-initialize-and-list", "F12", "FAIL", "%s: %s" % (type(error).__name__, error))
        return None
    missing = sorted(set(expect_tools) - set(names))
    if missing:
        result.add("mcp-initialize-and-list", "F12", "FAIL", "tools missing: %s" % ", ".join(missing))
    else:
        result.add("mcp-initialize-and-list", "F12", "PASS", "server %s, %d tools" % (info.get("serverInfo", {}).get("name"), len(names)))
    return {"session": session, "tools": names}


def openssl_text(path):
    return subprocess.run(["openssl", "x509", "-in", path, "-noout", "-text"], capture_output=True, text=True, check=True).stdout


def leaf_pem(target, cafile):
    parts = urlsplit(target)
    context = tls_context(cafile)
    with socket.create_connection((parts.hostname, parts.port or 443), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=parts.hostname) as tls:
            return ssl.DER_cert_to_PEM_cert(tls.getpeercert(binary_form=True)), tls.version()


def check_certificates(result, target, cafile, expect_name):
    try:
        ca = openssl_text(cafile)
    except (OSError, subprocess.CalledProcessError) as error:
        result.add("ca-name-constraints", "F13", "NOT RUN", "cannot read CA: %s" % error)
        return
    if "X509v3 Name Constraints: critical" not in ca:
        result.add("ca-name-constraints", "F13", "FAIL", "CA has no critical Name Constraints extension")
    elif re.search(r"Permitted:\s*\n(\s+(DNS|IP):[^\n]+\n)+", ca) is None:
        result.add("ca-name-constraints", "F13", "FAIL", "Name Constraints without a permitted subtree")
    else:
        block = ca.split("X509v3 Name Constraints: critical", 1)[1].split("X509v3", 1)[0]
        permitted = re.search(r"Permitted:\s*\n((?:\s+(?:DNS|IP):[^\n]+\n)+)", block)
        excluded = re.search(r"Excluded:\s*\n((?:\s+(?:DNS|IP):[^\n]+\n)+)", block)
        names = (permitted.group(1) if permitted else "") + (excluded.group(1) if excluded else "")
        missing = [kind for kind in ("DNS", "IP") if kind + ":" not in names]
        if missing:
            result.add("ca-name-constraints", "F13", "FAIL", "name type %s left unconstrained (RFC 5280): the CA could sign any such name" % "/".join(missing))
        else:
            permitted_dns = len(re.findall(r"DNS:", permitted.group(1) if permitted else ""))
            excluded_text = excluded.group(1) if excluded else ""
            all_v4 = "IP:0.0.0.0/0.0.0.0" in excluded_text
            all_v6 = re.search(r"IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0", excluded_text) is not None
            status = "PASS" if permitted_dns >= 1 and all_v4 and all_v6 else "FAIL"
            result.add("ca-name-constraints", "F13", status, "critical name constraints: %d permitted DNS subtree(s); all IPv4 addresses excluded: %s; all IPv6 addresses excluded: %s" % (permitted_dns, all_v4, all_v6))
    if not re.search(r"CA:TRUE, pathlen:0", ca):
        result.add("ca-pathlen-zero", "F13", "FAIL", "CA basic constraints are not CA:TRUE, pathlen:0")
    else:
        result.add("ca-pathlen-zero", "F13", "PASS", "CA:TRUE, pathlen:0")
    try:
        pem, version = leaf_pem(target, cafile)
    except (OSError, ssl.SSLError) as error:
        result.add("leaf-certificate", "F13", "FAIL", "TLS with the NetOps CA failed: %s" % error)
        return
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as stream:
        stream.write(pem)
        path = stream.name
    try:
        leaf = openssl_text(path)
        dates = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-startdate", "-enddate"], capture_output=True, text=True, check=True).stdout
    finally:
        os.unlink(path)
    found = dict(line.split("=", 1) for line in dates.strip().splitlines())
    start = datetime.strptime(found["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    end = datetime.strptime(found["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (end - start).days
    problems = []
    if days > MAX_LEAF_DAYS:
        problems.append("validity %d days exceeds %d" % (days, MAX_LEAF_DAYS))
    if "CA:TRUE" in leaf:
        problems.append("leaf is a CA")
    if "TLS Web Server Authentication" not in leaf:
        problems.append("no serverAuth extended key usage")
    if expect_name and ("DNS:" + expect_name not in leaf and "IP Address:" + expect_name not in leaf):
        problems.append("SAN does not contain %s" % expect_name)
    result.add("leaf-certificate", "F13", "FAIL" if problems else "PASS",
               "; ".join(problems) if problems else "%d days, %s, SAN contains %s" % (days, version, expect_name))


def wait_ready(target, cafile, token, seconds):
    import time
    deadline = time.monotonic() + seconds
    while True:
        try:
            mcp_session(target, token, tls_context(cafile))
            return True
        except Exception:
            if time.monotonic() > deadline:
                return False
            time.sleep(2)


def run(args):
    result = Result()
    with open(args.token_file, encoding="utf-8") as stream:
        token = stream.read().strip()
    if not token:
        raise SystemExit("token file is empty")
    if args.wait_seconds and not wait_ready(args.url, args.ca, token, args.wait_seconds):
        result.add("endpoint-ready", "F11", "FAIL", "no successful MCP initialize within %d s" % args.wait_seconds)
        return result
    expect_tools = [t for t in args.expect_tool]
    check_plain_http(result, args.url)
    check_untrusted_ca(result, args.url, token)
    check_wrong_hostname(result, args.url, args.ca, token)
    check_legacy_tls(result, args.url, args.ca, token)
    check_authentication(result, args.url, args.ca, token)
    check_certificates(result, args.url, args.ca, args.expect_name)
    check_session(result, args.url, args.ca, token, expect_tools)
    return result


def main():
    parser = argparse.ArgumentParser(description="Black-box transport, TLS and authentication checks of a running NetOps endpoint")
    parser.add_argument("--url", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--expect-name", required=True)
    parser.add_argument("--expect-tool", action="append", default=[])
    parser.add_argument("--commit")
    parser.add_argument("--image-digest")
    parser.add_argument("--wait-seconds", type=int, default=0)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = run(args)
    report = {"schema": "netops-acceptance-blackbox/1", "url": args.url, "summary": result.summary(), "checks": result.items}
    if args.commit:
        report["candidate_commit"] = args.commit
    if args.image_digest:
        report["candidate_image"] = args.image_digest
    with open(args.output, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=1)
        stream.write("\n")
    for item in result.items:
        print("%-8s %-34s %-8s %s" % (item["status"], item["check"], item["spec"], item["detail"]))
    print("blackbox=%s" % json.dumps(result.summary(), sort_keys=True))
    return 0 if set(result.summary()) <= {"PASS"} else 1


if __name__ == "__main__":
    sys.exit(main())
