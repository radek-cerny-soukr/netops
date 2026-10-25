#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blackbox

RECEIVER_IMAGE = "python:3.14.9-alpine3.24@sha256:dbeb11d16bb95c3a7e3c25c842cb9f20cbc8c18f8be0461a4a0dcc861ad386a0"
HERE = os.path.dirname(os.path.abspath(__file__))
SIZES = {"small": 100, "large": 1000000}


def run(cmd, cwd=None, env=None, timeout=300, stdin=None):
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, input=stdin)


def pki(directory):
    def openssl(*args):
        run(["openssl", *args], cwd=directory)
    for ca in ("rxca", "otherca"):
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", ca + ".key", "-out", ca + ".pem",
                "-days", "2", "-subj", "/CN=" + ca, "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
    for ca, name in (("rxca", "rx"), ("otherca", "bad")):
        with open(os.path.join(directory, name + ".ext"), "w") as stream:
            stream.write("subjectAltName=DNS:syslog-rx\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\n")
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", name + ".key", "-out", name + ".csr", "-subj", "/CN=syslog-rx")
        openssl("x509", "-req", "-in", name + ".csr", "-CA", ca + ".pem", "-CAkey", ca + ".key", "-CAcreateserial", "-days", "2", "-extfile", name + ".ext", "-out", name + ".pem")
    for name in os.listdir(directory):
        os.chmod(os.path.join(directory, name), 0o644)


def events(path):
    with open(path) as stream:
        return [json.loads(line) for line in stream if line.strip()]


def part_rows(delivered):
    return [e["text"].partition(" netops - - - ")[2] for e in delivered]


def reassembled(delivered):
    groups = {}
    for text in part_rows(delivered):
        try:
            row = json.loads(text)
            chunk = base64.b64decode(row["data_b64"], validate=True)
            groups.setdefault((row["record_id"], row["parts"], row["sha256"]), {})[row["part"]] = chunk
        except (ValueError, KeyError, TypeError):
            continue
    records = {}
    for (record_id, parts, digest), chunks in groups.items():
        if sorted(chunks) == list(range(parts)):
            raw = b"".join(chunks[part] for part in range(parts))
            if hashlib.sha256(raw).hexdigest() == digest:
                records[record_id] = raw.decode("utf-8", "replace")
    return records


def main():
    parser = argparse.ArgumentParser(description="F20: audit delivery to a TLS syslog receiver (RFC 5425), untrusted receiver refused, large records complete")
    parser.add_argument("--compose-file", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--port", type=int, default=28480)
    parser.add_argument("--project", default="netopssyslogcheck")
    parser.add_argument("--commit")
    parser.add_argument("--image-digest")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = blackbox.Result()
    work = tempfile.mkdtemp(prefix="netops-syslog-")
    os.chmod(work, 0o755)
    env = dict(os.environ, COMPOSE_PROJECT_NAME=args.project)
    network = args.project + "_default"
    shutil.copy(args.compose_file, os.path.join(work, "compose.yaml"))
    shutil.copy(os.path.join(HERE, "syslog_receiver.py"), os.path.join(work, "syslog_receiver.py"))
    os.chmod(os.path.join(work, "syslog_receiver.py"), 0o644)
    with open(os.path.join(work, ".env"), "w") as stream:
        stream.write("NETOPS_IMAGE=%s\nNETOPS_BIND_IP=127.0.0.1\nNETOPS_PORT=%d\nNETOPS_SERVER_NAME=localhost\n" % (args.image, args.port))
    received = os.path.join(work, "received.jsonl")

    def compose(*cmd, timeout=300, stdin=None):
        return run(["docker", "compose", *cmd], cwd=work, env=env, timeout=timeout, stdin=stdin)

    def receiver(name, cert):
        run(["docker", "rm", "-f", name])
        open(received, "w").close()
        os.chmod(received, 0o666)
        run(["docker", "run", "-d", "--name", name, "--network", network, "--network-alias", "syslog-rx", "-v", work + ":/w:z",
             RECEIVER_IMAGE, "python", "/w/syslog_receiver.py", "/w/pki/%s.pem" % cert, "/w/pki/%s.key" % cert, "/w/received.jsonl"])

    def queue_bytes():
        out = compose("exec", "-T", "--user", "0:0", "netops", "sh", "-c", "cat /var/lib/netops/gateway/audit/*.queue 2>/dev/null | wc -c").stdout.strip()
        return int(out or 0)

    try:
        os.makedirs(os.path.join(work, "pki"))
        pki(os.path.join(work, "pki"))
        init = compose("run", "--rm", "-T", "netops", "init", "--audit", "syslog", "--syslog-host", "syslog-rx", "--syslog-port", "6514")
        if init.returncode != 0:
            raise RuntimeError("init rc %d: %s" % (init.returncode, init.stderr[-300:]))
        trust = json.dumps({"host": "syslog-rx", "port": 6514, "ca_pem": open(os.path.join(work, "pki", "rxca.pem")).read()})
        configured = compose("run", "-T", "--rm", "netops", "configure", "syslog", stdin=trust)
        if configured.returncode != 0:
            raise RuntimeError("configure syslog rc %d: %s" % (configured.returncode, configured.stderr[-300:]))
        run(["docker", "network", "create", network])
        receiver("netops-syslog-bad", "bad")
        compose("up", "-d", "--wait", timeout=240)
        ca = os.path.join(work, "ca.pem")
        with open(ca, "w") as stream:
            stream.write(compose("run", "--rm", "-T", "netops", "ca").stdout)
        token = compose("run", "--rm", "-T", "netops", "token", "show").stdout.strip()
        context = blackbox.tls_context(ca)
        url = "https://localhost:%d/mcp" % args.port
        deadline = time.monotonic() + 120
        while True:
            try:
                blackbox.mcp_session(url, token, context)
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(2)
        marker = os.urandom(4).hex()

        def call(label, size):
            body = {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                    "params": {"name": "rule_detail", "arguments": {"rule_id": "%s-%s-%s" % (marker, label, "z" * size)}}}
            status, _, _ = blackbox.post(url, body, token=token, context=context, timeout=60)
            return status

        call("untrusted", SIZES["small"])
        time.sleep(15)
        seen = events(received)
        delivered = [e for e in seen if e["event"] == "message"]
        refused = [e for e in seen if e["event"] == "tls_failed"]
        pending = queue_bytes()
        if delivered or not refused or pending == 0:
            result.add("syslog-untrusted-receiver", "F20", "FAIL", "messages %d, TLS refusals %d, queue %d B" % (len(delivered), len(refused), pending))
        else:
            result.add("syslog-untrusted-receiver", "F20", "PASS", "TLS refused %d times, nothing delivered, queue holds %d B" % (len(refused), pending))
        run(["docker", "rm", "-f", "netops-syslog-bad"])
        receiver("netops-syslog-rx", "rx")
        statuses = {label: call(label, size) for label, size in SIZES.items()}
        deadline = time.monotonic() + 90
        while queue_bytes() and time.monotonic() < deadline:
            time.sleep(3)
        time.sleep(3)
        delivered = [e for e in events(received) if e["event"] == "message"]
        problems = []
        if not all(e["text"].startswith("<") and " netops " in e["text"][:80] for e in delivered):
            problems.append("message without an RFC 5424 header")
        records = reassembled(delivered)
        archive = "".join(row + "\n" for row in part_rows(delivered))
        for label, size in [("untrusted", SIZES["small"])] + list(SIZES.items()):
            needle = "%s-%s-%s" % (marker, label, "z" * size)
            complete = [record_id for record_id, record in records.items() if needle in record]
            if not complete:
                problems.append("%s request record (%d B argument) not delivered complete" % (label, size))
                continue
            rebuilt = compose("run", "--rm", "-T", "netops", "audit", "reassemble", "--record-id", complete[0], stdin=archive)
            if rebuilt.returncode != 0 or rebuilt.stdout != records[complete[0]]:
                problems.append("%s request record not reassembled by netops audit reassemble (rc %d)" % (label, rebuilt.returncode))
        remaining = queue_bytes()
        if remaining:
            problems.append("queue still holds %d B" % remaining)
        result.add("syslog-delivery", "F18/F20", "FAIL" if problems else "PASS",
                   "; ".join(problems) if problems else "queued record delivered after trust, small and 1 MB records complete, queue empty; HTTP %s" % statuses)
    except Exception as error:
        result.add("syslog-delivery", "F18/F20", "FAIL", "%s: %s" % (type(error).__name__, error))
    finally:
        compose("down", "-v", "--remove-orphans")
        for name in ("netops-syslog-bad", "netops-syslog-rx"):
            run(["docker", "rm", "-f", name])
        run(["docker", "network", "rm", network])
        shutil.rmtree(work, ignore_errors=True)
    report = {"schema": "netops-acceptance-syslog/1", "summary": result.summary(), "checks": result.items}
    if args.commit:
        report["candidate_commit"] = args.commit
    if args.image_digest:
        report["candidate_image"] = args.image_digest
    with open(args.output, "w") as stream:
        json.dump(report, stream, indent=1)
    for item in result.items:
        print("%-8s %-26s %-8s %s" % (item["status"], item["check"], item["spec"], item["detail"]))
    return 0 if set(result.summary()) <= {"PASS"} else 1


if __name__ == "__main__":
    sys.exit(main())
