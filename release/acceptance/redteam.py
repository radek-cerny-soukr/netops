#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blackbox

ROLE_UIDS = {"gateway": 51000, "helper": 51001, "auditor": 51002, "admin": 51003}
CANARY = "Xy-Secret-Canary-" + os.urandom(6).hex()
MARKER = "plain-marker-" + os.urandom(6).hex()
ESCAPES = "\x1b[31mRED\x1b]0;netops-title\x07\x1b[2J\x9b1m"
SETUID_WALKER = """
import os, stat, sys
top = sys.argv[1]
skip = {os.path.join(top, name) for name in ("proc", "sys", "dev")}
found, unreadable = [], []
for base, dirs, files in os.walk(top, onerror=lambda error: unreadable.append(error.filename)):
    dirs[:] = [name for name in dirs if os.path.join(base, name) not in skip]
    for name in files:
        path = os.path.join(base, name)
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            unreadable.append(path)
            continue
        if stat.S_ISREG(mode) and mode & 0o6000:
            found.append(path)
print("FOUND " + " ".join(sorted(found)))
print("UNREADABLE %d" % len(unreadable))
"""


class Ctx:
    def __init__(self, args):
        self.args = args
        self.result = blackbox.Result()
        self.env = dict(os.environ, COMPOSE_PROJECT_NAME=args.project)

    def compose(self, *cmd, check=False, timeout=180):
        proc = subprocess.run(["docker", "compose", *cmd], cwd=self.args.compose_dir, env=self.env, capture_output=True, text=True, timeout=timeout)
        if check and proc.returncode != 0:
            raise RuntimeError("docker compose %s rc %d: %s" % (" ".join(cmd), proc.returncode, proc.stderr[-400:]))
        return proc

    def docker(self, *cmd, timeout=120):
        return subprocess.run(["docker", *cmd], capture_output=True, text=True, timeout=timeout)

    def token(self):
        return self.compose("run", "--rm", "-T", "netops", "token", "show", check=True).stdout.strip()

    def container(self):
        cid = self.compose("ps", "-q", "netops", check=True).stdout.strip()
        if not cid:
            raise RuntimeError("netops container is not running")
        return cid

    def call(self, token, name, arguments, request_id=10):
        context = blackbox.tls_context(self.args.ca)
        body = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
        status, headers, raw = blackbox.post(self.args.url, body, token=token, context=context)
        return status, raw.decode("utf-8", "replace")

    def add(self, check, spec, status, detail):
        self.result.add(check, spec, status, detail)


def wait_ready(ctx, token, seconds=90):
    import time
    context = blackbox.tls_context(ctx.args.ca)
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            blackbox.mcp_session(ctx.args.url, token, context)
            return None
        except Exception as error:
            last = error
            time.sleep(2)
    return "%s: %s" % (type(last).__name__, last)


def status_fields(pid):
    fields = {}
    with open("/proc/%s/status" % pid) as stream:
        for line in stream:
            key, _, value = line.partition(":")
            fields[key] = value.strip()
    return fields


def check_container_config(ctx):
    info = json.loads(ctx.docker("inspect", ctx.container()).stdout)[0]
    host = info["HostConfig"]
    problems = []
    if host.get("Privileged"):
        problems.append("privileged")
    if not host.get("ReadonlyRootfs"):
        problems.append("rootfs writable")
    if host.get("NetworkMode") == "host":
        problems.append("host network")
    if "ALL" not in (host.get("CapDrop") or []):
        problems.append("cap_drop ALL missing")
    if not any(o.startswith("no-new-privileges") for o in host.get("SecurityOpt") or []):
        problems.append("no-new-privileges missing")
    if not host.get("PidsLimit") or not host.get("Memory") or not host.get("NanoCpus"):
        problems.append("missing pids/memory/cpu limit")
    for mount in info.get("Mounts", []):
        if "docker.sock" in (mount.get("Source") or ""):
            problems.append("docker socket mounted")
    for binding in (host.get("PortBindings") or {}).values():
        for item in binding or []:
            if item.get("HostIp") in ("", "0.0.0.0", "::"):
                problems.append("port published on all interfaces")
    ctx.add("container-profile", "F23/F8", "FAIL" if problems else "PASS",
            "; ".join(problems) if problems else "read-only, cap_drop ALL, no-new-privileges, limits, no socket, explicit bind %s" % [i.get("HostIp") for b in (host.get("PortBindings") or {}).values() for i in b])


def run_process_collector(ctx, command, environment):
    import hashlib
    import stat

    directory = getattr(ctx.args, "process_profile_dir", "process-profile-collector")
    os.mkdir(directory, 0o700)
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    files = {}
    def save(stdout, stderr, actual_rc, timed_out, outcome):
        stdout = stdout.encode("utf-8") if isinstance(stdout, str) else (stdout or b"")
        stderr = stderr.encode("utf-8") if isinstance(stderr, str) else (stderr or b"")
        token = getattr(ctx, "process_profile_token", None)
        scan = "UNKNOWN"
        if type(token) is str and re.fullmatch(r"[A-Za-z0-9_-]{64}", token):
            scan = "FAIL" if token.encode() in stdout or token.encode() in stderr else "PASS"
        result = {"schema": "netops-process-profile-collector/1", "actual_rc": actual_rc,
                  "timed_out": timed_out, "timeout_seconds": 150, "outcome": outcome,
                  "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
                  "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                  "mcp_token_scan": scan}
        for name, data in (("collector.stdout", stdout), ("collector.stderr", stderr),
                           ("result.json", (json.dumps(result, sort_keys=True) + "\n").encode())):
            with os.fdopen(files.pop(name), "wb") as stream:
                stream.write(data)
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("collector-capture-directory")
        for name in ("collector.stdout", "collector.stderr", "result.json"):
            file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            files[name] = file
            info = os.fstat(file)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError("collector-capture-file")
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=150, env=environment)
        except subprocess.TimeoutExpired as error:
            save(error.stdout, error.stderr, None, True, "timeout")
            raise
        except OSError:
            save(b"", b"", None, False, "spawn-error")
            raise
        if type(done.returncode) is not int:
            raise ValueError("collector-return-code")
        save(done.stdout, done.stderr, done.returncode, False, "completed")
        return done
    finally:
        for file in files.values():
            os.close(file)
        os.close(parent)


def check_processes(ctx):
    import hashlib
    import shutil
    import stat

    profile_reason = None
    try:
        from health_bootstrap_profile import assess_trace, HEALTH
        environment = dict(os.environ)
        if not sys.platform.startswith("linux"):
            ctx.add("process-profile", "F16/F23", "NOT RUN", "QA unsupported: requires a local rootful Linux Docker host")
            return
        if environment.get("DOCKER_CONTEXT") or not environment.get("DOCKER_HOST"):
            context = ctx.docker("context", "inspect", "--format", "{{json .Endpoints.docker.Host}}")
            if context.returncode:
                raise ValueError("context")
            endpoint = json.loads(context.stdout)
        else:
            endpoint = environment["DOCKER_HOST"]
        if type(endpoint) is not str or not endpoint or "\0" in endpoint:
            raise ValueError("context")
        if not endpoint.startswith("unix:///"):
            if not endpoint.startswith(("ssh://", "tcp://", "npipe://")):
                raise ValueError("context")
            ctx.add("process-profile", "F16/F23", "NOT RUN", "QA unsupported: requires the original local Unix Docker transport")
            return
        daemon = ctx.docker("info", "--format", '{"security":{{json .SecurityOptions}},"default":{{json .DefaultRuntime}},"runtimes":{{json .Runtimes}}}')
        if daemon.returncode:
            raise ValueError("daemon")
        daemon = json.loads(daemon.stdout)
        security = daemon["security"]
        if type(security) is not list or not all(type(item) is str for item in security):
            raise ValueError("security")
        if any(item.split(",", 1)[0] == "name=rootless" for item in security):
            ctx.add("process-profile", "F16/F23", "NOT RUN", "QA unsupported: rootless is outside this qualified host-process collector; product profile not evaluated")
            return
        cid = ctx.container()
        if re.fullmatch(r"[0-9a-f]{64}", cid) is None:
            raise ValueError("container")
        fmt = ('{"id":{{json .Id}},"image":{{json .Image}},"pid":{{json .State.Pid}},'
               '"running":{{json .State.Running}},"restarts":{{json .RestartCount}},"runtime":{{json .HostConfig.Runtime}},"source_image":{{json .Config.Image}}}')
        original = ctx.docker("inspect", "--type", "container", "--format", fmt, cid)
        if original.returncode:
            raise ValueError("inspect")
        original = json.loads(original.stdout)
        source_image = original.pop("source_image")
        if type(source_image) is not str or not source_image:
            raise ValueError("image-reference")
        if (original["id"] != cid or original["running"] is not True or
                re.fullmatch(r"sha256:[0-9a-f]{64}", original["image"]) is None or
                type(original["pid"]) is not int or original["pid"] <= 0 or
                type(original["restarts"]) is not int or original["restarts"] < 0 or type(original["runtime"]) is not str):
            raise ValueError("identity")
        expected = ctx.args.image_digest
        if expected is not None:
            if type(expected) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", expected) is None:
                raise ValueError("expected-image")
            if expected == original["image"]:
                reference = expected
            elif (source_image == expected or
                  (source_image.count("@") == 1 and source_image.split("@", 1)[0] and
                   not any(part.isspace() for part in source_image) and source_image.endswith("@" + expected))):
                reference = source_image
            else:
                raise ValueError("expected-image")
            resolved = ctx.docker("image", "inspect", "--format", "{{.Id}}", reference)
            if resolved.returncode or resolved.stdout.strip() != original["image"]:
                raise ValueError("expected-image")
        selected = original["runtime"] or daemon["default"]
        runtime = daemon["runtimes"][selected]
        configured = runtime.get("path") or ""
        command = [sys.executable, "-B", os.path.join(os.path.dirname(os.path.abspath(__file__)), "collect_health_bootstrap_trace.py"), cid]
        if not configured.startswith("/"):
            if (selected not in ("runc", "io.containerd.runc.v2") or configured not in ("", "runc") or
                    runtime.get("runtimeType", "") not in ("", "io.containerd.runc.v2")):
                raise ValueError("runtime")
            path = shutil.which("runc")
            if path is None:
                raise ValueError("runtime")
            path = os.path.realpath(path, strict=True)
            info = os.stat(path)
            if (os.path.basename(path) != "runc" or not stat.S_ISREG(info.st_mode) or
                    info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111):
                raise ValueError("runtime")
            command += ["--runtime-path", path]
        if os.geteuid() != 0:
            home = environment.get("HOME")
            if not home or not os.path.isabs(home):
                raise ValueError("home")
            environment.setdefault("DOCKER_CONFIG", os.path.join(home, ".docker"))
            preserved = "HOME,DOCKER_HOST,DOCKER_CONTEXT,DOCKER_CONFIG,DOCKER_TLS_VERIFY,DOCKER_CERT_PATH"
            command = ["sudo", "-n", "--preserve-env=" + preserved, *command]
        done = run_process_collector(ctx, command, environment)
        if done.returncode != 0:
            if done.returncode == 1:
                failure = json.loads(done.stdout)
                failed_assessment = failure.get("assessment") if type(failure) is dict else None
                if type(failed_assessment) is dict and failed_assessment.get("passed") is False:
                    reason = failed_assessment.get("reason")
                    if type(reason) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,79}", reason):
                        profile_reason = reason
            raise ValueError("collector")
        trace = json.loads(done.stdout)
        predicate_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "health_bootstrap_profile.py")
        with open(predicate_path, "rb") as stream:
            predicate_sha = hashlib.sha256(stream.read()).hexdigest()
        if trace.get("predicate_sha256") != predicate_sha:
            raise ValueError("predicate-source")
        if trace.get("collector_error", False) is not False or trace["assessment"].get("passed") is not True:
            raise ValueError("collector")
        for name in ("initial_metadata", "final_metadata"):
            if trace[name] != original:
                raise ValueError("identity")
        if trace["container_id"] != cid or trace["init"][0] != original["pid"]:
            raise ValueError("identity")
        assessment = assess_trace(trace, require_scope=True)
        if assessment.get("passed") is not True:
            profile_reason = assessment.get("reason")
        duration = trace["end"] - trace["begin"]
        if (assessment.get("passed") is not True or type(duration) not in (int, float) or
                not duration >= 85):
            raise ValueError("profile")
        health_keys = {tuple(row["key"]) for sample in trace["samples"] for row in sample["processes"]
                       if tuple(row["argv"]) == HEALTH}
        if len(health_keys) < 2:
            raise ValueError("health-cycles")
        summary = {"duration_seconds": round(duration, 3), "samples": assessment["samples"],
                   "root_samples": assessment["root_samples"], "health_processes": len(health_keys), "role_uids": ROLE_UIDS,
                   "role_capabilities_zero": True, "role_no_new_privileges": True}
        ctx.add("process-profile", "F16/F23", "PASS", json.dumps(summary, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, RuntimeError, ImportError, OverflowError, subprocess.SubprocessError):
        ctx.add("process-profile", "F16/F23", "FAIL", "QA process trace unavailable, incomplete or outside the required profile; no process-profile qualification" +
                ("; reason=" + profile_reason if type(profile_reason) is str else ""))


def check_token_leaks(ctx, token):
    cid = ctx.container()
    places = {"docker inspect": ctx.docker("inspect", cid).stdout, "docker logs": ctx.docker("logs", cid).stdout + ctx.docker("logs", cid).stderr}
    top = ctx.docker("top", cid, "-eo", "pid").stdout.split()[1:]
    cmdlines = ""
    for pid in top:
        try:
            with open("/proc/%s/cmdline" % pid, "rb") as stream:
                cmdlines += stream.read().decode("utf-8", "replace")
        except OSError:
            pass
    places["process argv"] = cmdlines
    places["audit export"] = ctx.compose("run", "--rm", "-T", "netops", "audit", "export").stdout
    leaked = [name for name, text in places.items() if token in text]
    ctx.add("token-not-leaked", "F14", "FAIL" if leaked else "PASS", ("token found in " + ", ".join(leaked)) if leaked else "absent from " + ", ".join(places))


def check_role_isolation(ctx):
    cid = ctx.container()
    walker = "import os\nfor d, _, names in os.walk('/var/lib/netops'):\n    for n in names:\n        p = os.path.join(d, n)\n        s = os.lstat(p)\n        print(s.st_uid, oct(s.st_mode & 0o777), p)"
    listing = ctx.docker("exec", "--user", "0:0", cid, "python", "-c", walker).stdout.splitlines()
    files = [line.split(" ", 2) for line in listing if line.count(" ") >= 2]
    if not files:
        ctx.add("role-isolation", "F16", "NOT RUN", "no state files found")
        return
    breaches = []
    for role, uid in ROLE_UIDS.items():
        foreign = [path for owner, mode, path in files if int(owner) != uid and not path.endswith("ca.pem")]
        script = "import sys\nok=[]\nfor p in sys.argv[1:]:\n    try:\n        open(p,'rb').read(1); ok.append(p)\n    except OSError:\n        pass\nprint('\\n'.join(ok))"
        proc = ctx.docker("exec", "--user", "%d:%d" % (uid, uid), cid, "python", "-c", script, *foreign)
        readable = [p for p in proc.stdout.splitlines() if p]
        breaches += ["%s reads %s" % (role, p) for p in readable]
        audit_dir = "/var/lib/netops/gateway/audit"
        if role != "gateway":
            wproc = ctx.docker("exec", "--user", "%d:%d" % (uid, uid), cid, "python", "-c",
                               "import os,sys\ntry:\n    open(sys.argv[1]+'/injected.jsonl','a').write('x')\n    print('WROTE')\nexcept OSError as e:\n    print(type(e).__name__)", audit_dir)
            if "WROTE" in wproc.stdout:
                breaches.append("%s writes into the audit directory" % role)
    ctx.add("role-isolation", "F16", "FAIL" if breaches else "PASS",
            "; ".join(breaches[:12]) if breaches else "%d state files; no role reads another role's files or writes the audit" % len(files))


def check_redaction_and_escapes(ctx, token):
    args = {"device": "lab-device", "table": "system admin", "op": "update", "key": "x",
            "changes": {"password": CANARY, "secret": CANARY, "comments": "c"}, "reason": ESCAPES,
            "user_request": "red-team " + ESCAPES, "request_id": "redteam-" + os.urandom(4).hex()}
    status, raw = ctx.call(token, "admin_preview", args, 31)
    ctx.call(token, "rule_detail", {"rule_id": ESCAPES + MARKER}, 32)
    export = ctx.compose("run", "--rm", "-T", "netops", "audit", "export").stdout
    tail = ctx.compose("run", "--rm", "-T", "netops", "audit", "tail", "--lines", "50").stdout
    problems = []
    if CANARY in raw:
        problems.append("canary echoed in the MCP response")
    if CANARY in export:
        problems.append("secret canary stored %d times in the audit export" % export.count(CANARY))
    if MARKER not in export:
        problems.append("non-secret argument missing from the audit (over-redaction or truncation)")
    if re.search(r"redact", export, re.I) is None:
        problems.append("audit does not mark redaction")
    if "admin_preview" not in export or args["request_id"] not in export:
        problems.append("admin_preview request not found in audit")
    raw_controls = [c for c in ("\x1b", "\x07", "\x9b") if c in tail]
    if raw_controls:
        problems.append("audit tail emits raw control characters %r" % raw_controls)
    ctx.add("audit-redaction-and-escaping", "F18/F22", "FAIL" if problems else "PASS",
            "; ".join(problems) if problems else "password/secret fields redacted and marked, tail neutralizes ESC/BEL/CSI, request and response recorded")


def check_rotation_and_idempotence(ctx, token):
    ca_before = ctx.compose("run", "--rm", "-T", "netops", "ca", check=True).stdout
    init = ctx.compose("run", "--rm", "-T", "netops", "init", "--audit", "local", "--accept-local-audit")
    ca_after = ctx.compose("run", "--rm", "-T", "netops", "ca", check=True).stdout
    token_after = ctx.token()
    if init.returncode != 0 or ca_before != ca_after or token_after != token:
        ctx.add("init-idempotent", "F9", "FAIL", "rc %d, CA same=%s, token same=%s" % (init.returncode, ca_before == ca_after, token_after == token))
    else:
        ctx.add("init-idempotent", "F9", "PASS", "repeated init keeps CA and token")
    restart = ctx.compose("restart", timeout=240)
    context = blackbox.tls_context(ctx.args.ca)
    error = wait_ready(ctx, token)
    ok = restart.returncode == 0 and error is None
    ctx.add("restart-keeps-identity", "F9", "PASS" if ok else "FAIL", "after restart the same CA and token serve MCP" if ok else "restart rc %d, %s" % (restart.returncode, error))
    rotate = ctx.compose("run", "--rm", "-T", "netops", "token", "rotate")
    new = ctx.token()
    wait_ready(ctx, new, 30)
    old_status, _, _ = blackbox.post(ctx.args.url, blackbox.initialize_body(), token=token, context=context)
    new_status, _, _ = blackbox.post(ctx.args.url, blackbox.initialize_body(), token=new, context=context)
    if rotate.returncode == 0 and new != token and old_status in (401, 403) and new_status == 200:
        ctx.add("token-rotation", "F14", "PASS", "old token HTTP %d immediately, new token HTTP %d" % (old_status, new_status))
    else:
        ctx.add("token-rotation", "F14", "FAIL", "rotate rc %d, changed=%s, old HTTP %d, new HTTP %d" % (rotate.returncode, new != token, old_status, new_status))
    return new


def check_startup_stop(ctx, token):
    import time
    problems = []
    immediate = None
    cid = None
    owned = False
    prefix = None
    stopped_records = None
    def inspect():
        result = ctx.docker("inspect", cid)
        if result.returncode:
            raise RuntimeError("Cannot inspect the owned instance")
        info = json.loads(result.stdout)[0]
        if info["Id"] != cid or info["Config"].get("Labels", {}).get("com.docker.compose.project") != ctx.args.project:
            raise RuntimeError("Unexpected instance ownership")
        return info
    def audit():
        result = ctx.compose("run", "--rm", "-T", "netops", "audit", "export", check=True)
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    def preserved(records, prior):
        return len(records) >= len(prior) and records[:len(prior)] == prior
    try:
        cid = ctx.container()
        before = inspect()
        if not before["State"]["Running"]:
            raise RuntimeError("Instance is not running")
        owned = True
        prefix = audit()
        if not prefix:
            raise RuntimeError("Running instance audit is empty")
        ctx.compose("stop", check=True)
        normal = inspect()["State"]
        if normal["Running"] or normal["ExitCode"] != 0 or normal["OOMKilled"]:
            problems.append("normal stop was not clean")
        normal_records = audit()
        if not preserved(normal_records, prefix):
            problems.append("normal stop changed prior audit content")
        if not normal_records or normal_records[-1].get("direction") != "instance_stop":
            problems.append("normal stop did not leave instance_stop as final record")
        ctx.compose("up", "-d", "--wait", check=True, timeout=240)
        if ctx.container() != cid:
            raise RuntimeError("Startup unexpectedly replaced the container")
        ctx.compose("restart", check=True, timeout=240)
        began = time.monotonic()
        ctx.compose("stop", check=True)
        immediate = time.monotonic() - began
        after = inspect()
        state = after["State"]
        if state["Running"] or state["ExitCode"] != 0 or state["OOMKilled"]:
            problems.append("immediate restart-stop was not clean (exit %d)" % state["ExitCode"])
        if after["Image"] != before["Image"]:
            problems.append("instance image changed")
        stopped_records = audit()
        if not preserved(stopped_records, normal_records):
            problems.append("restart-stop changed prior audit content")
        if not stopped_records or stopped_records[-1].get("direction") != "instance_stop":
            problems.append("restart-stop did not leave instance_stop as final record")
        events = [event.get("direction") for event in stopped_records[len(normal_records):] if event.get("direction") in ("instance_start", "instance_stop")]
        if events not in (["instance_start", "instance_stop"], ["instance_start", "instance_stop"] * 2):
            problems.append("new lifecycle records do not form complete start-stop pairs")
    except Exception as error:
        problems.append("startup-stop control failed: " + type(error).__name__)
    finally:
        if owned:
            try:
                current = inspect()
                if current["Image"] != before["Image"]:
                    raise RuntimeError("Instance image changed before restoration")
                ctx.compose("up", "-d", "--wait", check=True, timeout=240)
                error = wait_ready(ctx, token)
                current = inspect()
                if ctx.container() != cid or current["Image"] != before["Image"] or not current["State"]["Running"]:
                    raise RuntimeError("Restoration changed the owned instance identity")
                if error is not None:
                    problems.append("instance did not restore with the original CA and token")
                restored_records = audit()
                prior = stopped_records if stopped_records is not None else prefix
                if prior is not None and not preserved(restored_records, prior):
                    problems.append("restoration changed prior audit content")
            except Exception as error:
                problems.append("instance restore failed: " + type(error).__name__)
    detail = "; ".join(problems) if problems else "normal and immediate restart-stop exit 0, prior audit preserved through restoration, final stop records and complete lifecycle pairs, original container/image/CA/token restored; immediate stop %.3fs" % immediate
    ctx.add("startup-stop", "F9/F18/F23/F28", "FAIL" if problems else "PASS", detail)


def check_setuid(ctx):
    image = json.loads(ctx.docker("inspect", ctx.container()).stdout)[0]["Image"]
    proc = ctx.docker("run", "--rm", "--network", "none", "--user", "0:0", "--entrypoint", "python", image, "-c", SETUID_WALKER, "/")
    lines = dict(line.split(" ", 1) for line in proc.stdout.splitlines() if " " in line)
    if proc.returncode != 0 or "FOUND" not in lines and "UNREADABLE" not in lines:
        ctx.add("no-setuid-files", "CIS-4.8", "FAIL", "image walk rc %d" % proc.returncode)
        return
    found = lines.get("FOUND", "").split()
    unreadable = int(lines.get("UNREADABLE", "1"))
    status = "FAIL" if found or unreadable else "PASS"
    ctx.add("no-setuid-files", "CIS-4.8", status,
            ("setuid/setgid files: " + ", ".join(found)) if found else "no setuid or setgid file in the image filesystem; %d unreadable paths" % unreadable)


def main():
    parser = argparse.ArgumentParser(description="Red-team checks of a running NetOps 1.0 instance; run on the Docker host")
    parser.add_argument("--compose-dir", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--token-out", required=True)
    parser.add_argument("--commit")
    parser.add_argument("--image-digest")
    parser.add_argument("--process-profile-dir", default="process-profile-collector")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    ctx = Ctx(args)
    token = ctx.token()
    ctx.process_profile_token = token
    for check in (check_container_config, check_processes, check_setuid):
        check(ctx)
    check_token_leaks(ctx, token)
    check_role_isolation(ctx)
    check_redaction_and_escapes(ctx, token)
    token = check_rotation_and_idempotence(ctx, token)
    check_startup_stop(ctx, token)
    with open(args.token_out, "w") as stream:
        stream.write(token)
    os.chmod(args.token_out, 0o600)
    report = {"schema": "netops-acceptance-redteam/1", "summary": ctx.result.summary(), "checks": ctx.result.items}
    if args.commit:
        report["candidate_commit"] = args.commit
    if args.image_digest:
        report["candidate_image"] = args.image_digest
    with open(args.output, "w") as stream:
        json.dump(report, stream, indent=1)
    for item in ctx.result.items:
        print("%-8s %-30s %-8s %s" % (item["status"], item["check"], item["spec"], item["detail"]))
    print("redteam=%s" % json.dumps(ctx.result.summary(), sort_keys=True))
    return 0 if set(ctx.result.summary()) <= {"PASS"} else 1


if __name__ == "__main__":
    sys.exit(main())
