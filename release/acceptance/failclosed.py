#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blackbox

UNREACHABLE = "192.0.2.1"
BUDGET = 16777216
CHUNK = 200000


def main():
    parser = argparse.ArgumentParser(description="F19: a full audit queue must refuse new operations; uses its own throw-away instance")
    parser.add_argument("--compose-file", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--port", type=int, default=28444)
    parser.add_argument("--project", default="netopsfailclosed")
    parser.add_argument("--commit")
    parser.add_argument("--image-digest")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = blackbox.Result()
    work = tempfile.mkdtemp(prefix="netops-failclosed-")
    os.chmod(work, 0o700)
    shutil.copy(args.compose_file, os.path.join(work, "compose.yaml"))
    with open(os.path.join(work, ".env"), "w") as stream:
        stream.write("NETOPS_IMAGE=%s\nNETOPS_BIND_IP=127.0.0.1\nNETOPS_PORT=%d\nNETOPS_SERVER_NAME=localhost\n" % (args.image, args.port))
    env = dict(os.environ, COMPOSE_PROJECT_NAME=args.project)

    def compose(*cmd, timeout=300):
        return subprocess.run(["docker", "compose", *cmd], cwd=work, env=env, capture_output=True, text=True, timeout=timeout)

    try:
        init = compose("run", "--rm", "-T", "netops", "init", "--audit", "syslog", "--syslog-host", UNREACHABLE,
                       "--syslog-port", "6514", "--audit-budget", str(BUDGET))
        if init.returncode != 0:
            result.add("audit-fail-closed", "F19", "FAIL", "init rc %d: %s" % (init.returncode, init.stderr[-300:]))
            raise SystemExit
        compose("up", "-d")
        ca = os.path.join(work, "ca.pem")
        with open(ca, "w") as stream:
            stream.write(compose("run", "--rm", "-T", "netops", "ca").stdout)
        token = compose("run", "--rm", "-T", "netops", "token", "show").stdout.strip()
        context = blackbox.tls_context(ca)
        url = "https://localhost:%d/mcp" % args.port
        deadline = time.monotonic() + 90
        while True:
            try:
                blackbox.mcp_session(url, token, context)
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(2)
        accepted, refusal = 0, None
        for i in range(1, 400):
            body = {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                    "params": {"name": "rule_detail", "arguments": {"rule_id": "fill-%04d-" % i + "x" * CHUNK}}}
            status, _, raw = blackbox.post(url, body, token=token, context=context, timeout=60)
            text = raw.decode("utf-8", "replace")
            if "audit_unavailable" in text:
                refusal = (i, status, text)
                break
            if status != 200:
                result.add("audit-fail-closed", "F19", "FAIL", "request %d HTTP %d before the queue filled: %s" % (i, status, text[:200]))
                raise SystemExit
            accepted += 1
        if refusal is None:
            result.add("audit-fail-closed", "F19", "FAIL", "%d requests of %d bytes accepted; queue never refused" % (accepted, CHUNK))
            raise SystemExit
        i, status, text = refusal
        reply = json.loads(text)
        pending_raw = compose("run", "--rm", "-T", "netops", "audit", "pending")
        pending, noise = [], []
        for line in pending_raw.stdout.splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                if line.strip():
                    noise.append(line.strip()[:120])
                continue
            if isinstance(entry, dict) and entry.get("direction") == "request":
                pending.append("%s %s" % (entry.get("correlation"), json.dumps(entry.get("payload"))[:120]))
        problems = []
        if status != 503:
            problems.append("refusal HTTP %d" % status)
        if reply.get("automatic_retry") is not False or reply.get("operation_may_have_completed") is not False:
            problems.append("refusal body %r" % reply)
        if pending:
            problems.append("%d requests without a recorded outcome: %s" % (len(pending), "; ".join(pending[:3])))
        if noise:
            problems.append("audit pending printed non-JSON output: %s" % " | ".join(noise[:3]))
        if accepted * CHUNK > BUDGET * 1.05:
            problems.append("more data accepted (%d B) than the budget %d B" % (accepted * CHUNK, BUDGET))
        result.add("audit-fail-closed", "F19", "FAIL" if problems else "PASS",
                   "; ".join(problems) if problems else "request %d refused with HTTP 503 audit_unavailable after %d accepted, nothing pending" % (i, accepted))
    except SystemExit:
        pass
    except Exception as error:
        result.add("audit-fail-closed", "F19", "FAIL", "%s: %s" % (type(error).__name__, error))
    finally:
        compose("down", "-v", "--remove-orphans")
        shutil.rmtree(work, ignore_errors=True)
    report = {"schema": "netops-acceptance-failclosed/1", "summary": result.summary(), "checks": result.items}
    if args.commit:
        report["candidate_commit"] = args.commit
    if args.image_digest:
        report["candidate_image"] = args.image_digest
    with open(args.output, "w") as stream:
        json.dump(report, stream, indent=1)
    for item in result.items:
        print("%-8s %-20s %-6s %s" % (item["status"], item["check"], item["spec"], item["detail"]))
    return 0 if set(result.summary()) <= {"PASS"} else 1


if __name__ == "__main__":
    sys.exit(main())
