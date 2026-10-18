#!/usr/bin/env python3
import argparse
import json
import os
import pwd
import secrets
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blackbox

GOOD = "accept-good"
WRONG_PIN = "accept-wrong-pin"
QUERY = "kernel"
NOT_ENABLED = "hostname"


def privileged(cmd):
    return cmd if os.geteuid() == 0 else ["sudo", "-n", *cmd]


def run(cmd, check=True, timeout=180, **kwargs):
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)
    if check and proc.returncode != 0:
        raise RuntimeError("%s failed with %d: %s" % (" ".join(cmd[:4]), proc.returncode, proc.stderr.strip()[-300:]))
    return proc


class External:
    def __init__(self, args):
        self.user = args.target_user
        self.key = args.target_key_file

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Fixture:
    def __init__(self, user):
        self.user = user
        self.directory = tempfile.mkdtemp(prefix="netops-device-")
        self.key = os.path.join(self.directory, "client")
        self.created = False

    def __enter__(self):
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "netops-acceptance", "-f", self.key])
        try:
            pwd.getpwnam(self.user)
            raise RuntimeError("fixture account %s already exists; refusing to reuse it" % self.user)
        except KeyError:
            pass
        run(privileged(["useradd", "-m", "-s", "/bin/sh", self.user]))
        self.created = True
        public = open(self.key + ".pub", encoding="utf-8").read().strip()
        home = pwd.getpwnam(self.user).pw_dir
        staged = os.path.join(self.directory, "authorized_keys")
        with open(staged, "w", encoding="utf-8") as stream:
            stream.write('restrict,command="uname -a" %s\n' % public)
        run(privileged(["install", "-d", "-m", "700", "-o", self.user, "-g", self.user, home + "/.ssh"]))
        run(privileged(["install", "-m", "600", "-o", self.user, "-g", self.user, staged, home + "/.ssh/authorized_keys"]))
        return self

    def __exit__(self, *exc):
        if self.created:
            run(privileged(["userdel", "-r", self.user]), check=False)
        shutil.rmtree(self.directory, ignore_errors=True)


def host_pin():
    out = run(["ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub"]).stdout.split()
    return out[1]


def compose(args, *cmd, stdin=None, timeout=300):
    return run(["docker", "compose", "-p", args.project, *cmd], cwd=args.compose_dir, input=stdin, timeout=timeout, check=False)


def configure_helper(args, document):
    compose(args, "stop")
    proc = compose(args, "run", "-T", "--rm", "netops", "configure", "helper", stdin=json.dumps(document))
    up = compose(args, "up", "-d", "--wait")
    return proc.returncode, (proc.stdout + proc.stderr).strip().splitlines()[-1:] , up.returncode


def device(name, address, port, pin, egress_address):
    return {"name": name, "platform": "linux", "address": address, "port": port, "role": "lab", "credential": "accept-key",
            "host_key_fingerprint": pin, "legacy_ssh": None, "auditor": None,
            "helper": {"account_role": "read-only", "ssh_platform": "linux", "enabled_queries": [QUERY],
                       "egress": {"addresses": [egress_address], "tcp_ports": [port], "udp_ports": [], "tcp_port_ranges": [],
                                  "udp_port_ranges": [], "allow_icmp": False, "allow_dns": False, "tls_server_names": []}}}


def audit_pairs(args):
    export = compose(args, "run", "--rm", "-T", "netops", "audit", "export").stdout
    requests, responses = set(), {}
    for line in export.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
        if record.get("direction") == "request" and payload.get("method") == "tools/call" and params.get("name") == "ssh_read":
            requests.add(record.get("correlation"))
        elif record.get("direction") == "response":
            responses[record.get("correlation")] = json.dumps(payload)
    return {c: responses.get(c) for c in requests}


def call(url, token, context, session, name, arguments, request_id):
    status, headers, raw = blackbox.post(url, {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                                               "params": {"name": name, "arguments": arguments}},
                                         token=token, context=context, session=session, timeout=90)
    reply = blackbox.decode_rpc(headers, raw)
    return status, reply.get("result") or {"isError": True, "content": [{"type": "text", "text": json.dumps(reply.get("error"))}]}


def text_of(result):
    return "".join(item.get("text", "") for item in result.get("content", []) if isinstance(item, dict))


def execute(args):
    result = blackbox.Result()
    with open(args.token_file, encoding="utf-8") as stream:
        token = stream.read().strip()
    wrong = "SHA256:" + "A" * 43
    if args.target_address:
        address, port, pin, expected = args.target_address, args.target_port, args.target_pin, args.expected_output
        fixture_context = External(args)
    else:
        address = run(["docker", "network", "inspect", args.project + "_default", "--format", "{{(index .IPAM.Config 0).Gateway}}"]).stdout.strip()
        port, pin, expected = 22, host_pin(), run(["uname", "-a"]).stdout.strip()
        fixture_context = Fixture(args.fixture_user)
    with fixture_context as fixture:
        key = open(fixture.key, encoding="utf-8").read()
        document = {"inventory": {"version": 2, "devices": [device(GOOD, address, port, pin, address), device(WRONG_PIN, address, port, wrong, address)]},
                    "vault": {"version": 2, "credentials": {"accept-key": {"kind": "ssh-key", "login": fixture.user, "value": key}}}}
        rc, last, up = configure_helper(args, document)
        del key, document
        if rc != 0 or up != 0:
            result.add("device-configure", "F32", "FAIL", "configure helper rc %d (%s), up rc %d" % (rc, " ".join(last)[:200], up))
            return result
        result.add("device-configure", "F32", "PASS", "operator configure helper with an ssh-key credential, two Linux devices and an opt-in query")
        if not blackbox.wait_ready(args.url, args.ca, token, 120):
            result.add("device-endpoint-ready", "F11", "FAIL", "no MCP initialize within 120 s after configuration")
            return result
        context = blackbox.tls_context(cafile=args.ca)
        session, _ = blackbox.mcp_session(args.url, token, context)
        before = audit_pairs(args)
        status, good = call(args.url, token, context, session, "ssh_read", {"target": GOOD, "platform": "linux", "query": QUERY}, 11)
        output = text_of(good)
        if status == 200 and good.get("isError") is False and expected in output:
            result.add("device-read", "F32", "PASS", "ssh_read %s over SSH with a pinned host key returned the fixture's forced-command output" % QUERY)
        else:
            result.add("device-read", "F32", "FAIL", "HTTP %d, isError %s, output %d characters, expected output present %s" % (status, good.get("isError"), len(output), expected in output))
        status, pinned = call(args.url, token, context, session, "ssh_read", {"target": WRONG_PIN, "platform": "linux", "query": QUERY}, 12)
        refused = text_of(pinned)
        if pinned.get("isError") is True and expected not in refused and "host key" in refused.lower() and "-32603" not in refused:
            result.add("device-host-key-pin", "F32", "PASS", "wrong host key pin refused as an MCP error before any device output")
        else:
            result.add("device-host-key-pin", "F32", "FAIL", "isError %s, device output present %s" % (pinned.get("isError"), expected in refused))
        status, blocked = call(args.url, token, context, session, "ssh_read", {"target": GOOD, "platform": "linux", "query": NOT_ENABLED}, 13)
        denied = text_of(blocked)
        if blocked.get("isError") is True and expected not in denied and "-32603" not in denied:
            result.add("device-query-opt-in", "F32", "PASS", "query outside enabled_queries refused as an MCP error (%s)" % ("policy_scope" if "policy_scope" in denied else "other refusal"))
        else:
            result.add("device-query-opt-in", "F32", "FAIL", "isError %s, device output present %s" % (blocked.get("isError"), expected in denied))
        after = audit_pairs(args)
        new = {c: r for c, r in after.items() if c not in before}
        complete = [c for c, r in new.items() if r is not None]
        output_audited = any(expected in r for r in new.values() if r)
        if len(new) == 3 and len(complete) == 3 and output_audited:
            result.add("device-audit", "F32", "PASS", "three ssh_read requests audited, each with its response; the device output is in the audited response")
        else:
            result.add("device-audit", "F32", "FAIL", "new ssh_read requests %d, with response %d, device output audited %s" % (len(new), len(complete), output_audited))
        rc, last, up = configure_helper(args, {"inventory": {"version": 2, "devices": []}, "vault": {"version": 2, "credentials": {}}})
        result.add("device-unenroll", "F32", "PASS" if rc == 0 and up == 0 else "FAIL", "empty helper configuration restored: configure rc %d, up rc %d" % (rc, up))
    return result


def main():
    parser = argparse.ArgumentParser(description="Real read-only device operation through the Helper role against a local SSH fixture")
    parser.add_argument("--compose-dir", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--fixture-user", default="netops-accept-" + secrets.token_hex(3))
    parser.add_argument("--target-address", help="use an existing SSH fixture instead of a temporary local account")
    parser.add_argument("--target-port", type=int, default=22)
    parser.add_argument("--target-user")
    parser.add_argument("--target-key-file")
    parser.add_argument("--target-pin")
    parser.add_argument("--expected-output", help="exact output of the fixture's forced command")
    parser.add_argument("--commit")
    parser.add_argument("--image-digest")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.target_address and not all((args.target_user, args.target_key_file, args.target_pin, args.expected_output)):
        parser.error("--target-address needs --target-user, --target-key-file, --target-pin and --expected-output")
    result = execute(args)
    report = {"schema": "netops-acceptance-device/1", "summary": result.summary(), "checks": result.items}
    if args.commit:
        report["candidate_commit"] = args.commit
    if args.image_digest:
        report["candidate_image"] = args.image_digest
    with open(args.output, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=1)
        stream.write("\n")
    for item in result.items:
        print("%-8s %-24s %-6s %s" % (item["status"], item["check"], item["spec"], item["detail"]))
    print("device=%s" % json.dumps(result.summary(), sort_keys=True))
    return 0 if set(result.summary()) <= {"PASS"} else 1


if __name__ == "__main__":
    sys.exit(main())
