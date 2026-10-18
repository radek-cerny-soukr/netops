import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import stat
import subprocess
import sys
import time

from health_bootstrap_profile import assess_trace, HEALTH, SERVE, WORKER, runtime_exec_argv, InvalidProfile, verified_exit, observed_permissions, runtime_permissions

PREDICATE_SHA = "be7510ba47cb16d0f40c4181a6b94ff2968067c3036d75d75e0ba716174bbadc"
IDENTITY_MAP = [0, 0, 4294967295]
REFERENCE = {}
DOCKER_FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},'
                 '"pid":{{json .State.Pid}},"running":{{json .State.Running}},'
                 '"restarts":{{json .RestartCount}},"runtime":{{json .HostConfig.Runtime}},"health":{{json .Config.Healthcheck}}}')


class EvidenceError(Exception):
    pass


class RuntimeExecTransition(EvidenceError):
    pass


class RuntimeParentExited(EvidenceError):
    pass


class ExecTransitionLimit(EvidenceError):
    pass


EXEC_RETRIES = 3


class ProcessExited(EvidenceError):
    pass


PARENT_GONE = {FileNotFoundError: "parent-ENOENT", ProcessLookupError: "parent-ESRCH", RuntimeParentExited: "parent-exited"}


def require(condition, code):
    if not condition:
        raise EvidenceError(code)


def clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def read(path, limit=65536):
    with open(path, "rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "proc-field-too-large")
    return data


def proc_stat(pid):
    data = read(f"/proc/{pid}/stat").decode("utf-8")
    fields = data[data.rindex(")") + 2:].split()
    return (pid, int(fields[19])), int(fields[1])


def identity_maps(pid):
    for name in ("uid_map", "gid_map"):
        rows = [list(map(int, line.split())) for line in read(f"/proc/{pid}/{name}").splitlines()]
        require(rows == [IDENTITY_MAP], "nonidentity-user-or-group-map-unsupported")


def command(pid):
    data = read(f"/proc/{pid}/cmdline")
    require(data != b"", "empty-process-command")
    require(data.endswith(b"\0"), "unreadable-process-command")
    return tuple(part.decode("utf-8") for part in data[:-1].split(b"\0"))


def product_command(argv):
    return argv in (HEALTH, SERVE) or any(argv == WORKER + (role,) for role in ("helper", "auditor", "admin"))


def cgroup_path(pid):
    rows = read(f"/proc/{pid}/cgroup").decode("ascii").splitlines()
    require(len(rows) == 1 and rows[0].startswith("0::/"), "cgroup-v2-required")
    path = rows[0][3:]
    require(".." not in PurePosixPath(path).parts, "unsafe-cgroup-path")
    return path


def read_at(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(65537)
    require(len(data) <= 65536, "proc-field-too-large")
    return data


def stat_at(directory, pid):
    data = read_at(directory, "stat").decode("utf-8")
    fields = data[data.rindex(")") + 2:].split()
    require(int(data.split(" ", 1)[0]) == pid, "procdir-pid-mismatch")
    return (pid, int(fields[19])), int(fields[1])


def exe_identity(info):
    return [info.st_dev, info.st_ino]


def stat_detail_at(directory, pid):
    data = read_at(directory, "stat").decode("utf-8")
    fields = data[data.rindex(")") + 2:].split()
    require(int(data.split(" ", 1)[0]) == pid, "procdir-pid-mismatch")
    return (pid, int(fields[19])), int(fields[1]), fields[0]


def cgroup_at(directory):
    rows = read_at(directory, "cgroup").decode("ascii").splitlines()
    require(len(rows) == 1 and rows[0].startswith("0::/"), "cgroup-v2-required")
    path = rows[0][3:]
    require(".." not in PurePosixPath(path).parts, "unsafe-cgroup-path")
    return path


def permissions_at(directory):
    fields = dict(line.split(":", 1) for line in read_at(directory, "status").decode("ascii").splitlines())
    return {"uids": list(map(int, fields["Uid"].split())), "gids": list(map(int, fields["Gid"].split())),
            "groups": list(map(int, fields["Groups"].split())), "nnp": int(fields["NoNewPrivs"]),
            "caps": {key: int(fields[field], 16) for key, field in
                     (("inh", "CapInh"), ("prm", "CapPrm"), ("eff", "CapEff"), ("bnd", "CapBnd"), ("amb", "CapAmb"))}}


def pidfd_events(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    return sum(event for _, event in poller.poll(0))


def close_binding(handle):
    os.close(handle["pidfd"])
    os.close(handle["directory"])


def pin_process(pid, expected_cgroup):
    require(hasattr(os, "pidfd_open"), "pidfd-required-for-process-continuity")
    directory = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pidfd, reads = None, []
    try:
        first, first_parent, state = stat_detail_at(directory, pid)
        reads.append([list(first), first_parent])
        pin = exe_identity(os.fstat(directory))
        pidfd = os.pidfd_open(pid, 0)
        after, after_parent, after_state = stat_detail_at(directory, pid)
        reads.append([list(after), after_parent])
        require(first == after, "initial-process-key-changed")
        current_pin = exe_identity(os.stat(f"/proc/{pid}", follow_symlinks=False))
        group = cgroup_at(directory)
        require(pin == current_pin, "initial-procdir-identity-changed")
        require(group == expected_cgroup, "initial-process-cgroup-mismatch")
        require(state != "Z" and after_state != "Z" and not pidfd_events(pidfd),
                "unverified-initial-process-binding")
        return {"directory": directory, "pidfd": pidfd, "key": first, "reads": reads,
                "evidence": {"method": "procdir+pidfd", "key_before": list(first), "key_after": list(after),
                             "procdir_identity": pin, "procdir_identity_after": current_pin,
                             "cgroup": group, "bound_at": clock()}}
    except BaseException as error:
        if isinstance(error, Exception):
            error.netops_child_reads = reads
        if pidfd is not None:
            os.close(pidfd)
        os.close(directory)
        raise


def check_binding(handle):
    key, _, _ = stat_detail_at(handle["directory"], handle["key"][0])
    require(key == handle["key"] and
            exe_identity(os.stat(f"/proc/{key[0]}", follow_symlinks=False)) ==
            handle["evidence"]["procdir_identity"], "process-binding-identity-race")


def terminal_exit(handle, timeout=0):
    require(type(timeout) in (int, float) and 0 <= timeout <= .020,
            "invalid-terminal-wait-timeout")
    started = clock()
    if timeout:
        poller = select.poll()
        poller.register(handle["pidfd"], select.POLLIN)
        wait_started = clock()
        poller.poll(int(timeout * 1000))
        wait_elapsed = clock() - wait_started
    key = handle["key"]
    directory = handle["directory"]
    proof = {"key": list(key), "binding": handle["evidence"], "read_started_at": started,
             "poll_before": pidfd_events(handle["pidfd"]), "replacement_key": None}
    if timeout:
        proof["terminal_wait"] = {"requested_seconds": timeout, "elapsed_seconds": wait_elapsed}
    try:
        before, _, state_before = stat_detail_at(directory, key[0])
        proof.update(key_before=list(before), state_before=state_before)
        proof["cgroup_before"] = cgroup_at(directory)
        proof["permissions"] = permissions_at(directory)
        after, _, state_after = stat_detail_at(directory, key[0])
        proof.update(key_after=list(after), state_after=state_after)
        proof["cgroup_after"] = cgroup_at(directory)
        proof.update(kind="zombie", procdir_identity=exe_identity(os.fstat(directory)))
    except (FileNotFoundError, ProcessLookupError):
        try:
            stat_detail_at(directory, key[0])
        except (FileNotFoundError, ProcessLookupError):
            pass
        else:
            raise EvidenceError("terminal-field-missing-before-reap")
        replacement = None
        try:
            replacement, _ = proc_stat(key[0])
        except (FileNotFoundError, ProcessLookupError):
            pass
        proof.update(kind="reaped", proc_missing=True,
                     replacement_key=list(replacement) if replacement is not None else None)
    proof["poll_after"] = pidfd_events(handle["pidfd"])
    proof["read_finished_at"] = clock()
    return proof


def runtime_parent(pid, child, shim_pid, cid, runtime):
    started = clock()
    directory = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pidfd = None
    try:
        require(hasattr(os, "pidfd_open"), "pidfd-required-for-runtime-parent")
        pidfd = os.pidfd_open(pid, 0)
        pin = exe_identity(os.fstat(directory))
        first, parent_pid = stat_at(directory, pid)
        require(first[1] <= child[1], "runtime-parent-born-after-child")
        raw = read_at(directory, "cmdline")
        if raw == b"":
            raise RuntimeParentExited("runtime-parent-exited")
        require(raw.endswith(b"\0"), "unreadable-runtime-command")
        argv = [part.decode("utf-8") for part in raw[:-1].split(b"\0")]
        try:
            runtime_exec_argv(argv, cid)
        except InvalidProfile as error:
            raise EvidenceError(error.args[0]) from None
        exe = os.readlink("exe", dir_fd=directory)
        actual = exe_identity(os.stat("exe", dir_fd=directory))
        require(exe == runtime["path"] and actual == runtime["exe_identity"], "runtime-executable-mismatch")
        origin = shim(shim_pid, cid)
        require(parent_pid == origin["key"][0], "runtime-parent-foreign-shim")
        after, after_parent_pid = stat_at(directory, pid)
        actual_after = exe_identity(os.stat("exe", dir_fd=directory))
        parent_after, _ = proc_stat(after_parent_pid)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        if poller.poll(0):
            raise RuntimeParentExited("runtime-parent-exited-during-proof")
        current, current_parent_pid = proc_stat(pid)
        current_pin = exe_identity(os.stat(f"/proc/{pid}", follow_symlinks=False))
        require(first == after == current and parent_pid == after_parent_pid == current_parent_pid and
                parent_after == tuple(origin["key"]) and pin == current_pin and actual == actual_after,
                "runtime-parent-identity-race")
        require(shim(shim_pid, cid) == origin, "runtime-parent-shim-race")
        return {"key": list(first), "key_after": list(after),
                "parent": list(origin["key"]), "parent_after": list(parent_after),
                "exe": exe, "exe_identity": actual, "exe_identity_after": actual_after,
                "argv": argv, "shim": origin, "pin": "procdir+pidfd", "alive_after": True,
                "procdir_identity": pin, "procdir_identity_after": current_pin,
                "read_started_at": started, "read_finished_at": clock()}
    finally:
        if pidfd is not None:
            os.close(pidfd)
        os.close(directory)


def file_stat(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns]


def read_executable(fd, before):
    started, blocks, count = clock(), [], 0
    require(stat.S_ISREG(before[2]) and 0 < before[4] <= 67108864, "invalid-runtime-file")
    while True:
        block = os.pread(fd, 1048576, count)
        if not block:
            break
        count += len(block)
        require(count <= 67108864, "runtime-file-too-large")
        blocks.append(block)
    after = file_stat(os.fstat(fd))
    require(before == after and count == before[4], "runtime-file-changed-or-incomplete")
    return started, after, b"".join(blocks)


def hash_executable(fd, before, opened_at):
    started, after, data = read_executable(fd, before)
    require("data" in REFERENCE and len(data) == len(REFERENCE["data"]) and data == REFERENCE["data"],
            "runtime-content-mismatch")
    return {"stat_before": before, "stat_after": after, "opened_at": opened_at,
            "read_started_at": started, "read_finished_at": clock(),
            "sha256": REFERENCE["sha256"], "bytes_hashed": len(data), "method": "bytes-equal-to-verified-reference"}


def host_binary(runtime):
    fd = os.open(runtime["path"], os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened_at, before = clock(), file_stat(os.fstat(fd))
        require(before[:2] == runtime["exe_identity"] and before[3] == 0 and
                not before[2] & 0o022, "unsafe-host-runtime-binary")
        started, after, data = read_executable(fd, before)
        digest = hashlib.sha256(data).hexdigest()
        if "data" not in REFERENCE:
            REFERENCE.update(sha256=digest, data=data)
        return {"stat_before": before, "stat_after": after, "opened_at": opened_at,
                "read_started_at": started, "read_finished_at": clock(),
                "sha256": digest, "bytes_hashed": len(data)}
    finally:
        os.close(fd)


def runtime_parent_after_enoent(handle, child, shim_pid, cid, runtime, expected_cgroup, executable, reason="parent-ENOENT"):
    started, reads = clock(), []
    for attempt in range(3):
        require(clock() - started <= .05, "runtime-parent-retry-exhausted")
        check_binding(handle)
        first, parent_pid = stat_at(handle["directory"], child[0])
        before = exe_identity(os.stat("exe", dir_fd=handle["directory"]))
        argv = command(child[0])
        group = cgroup_at(handle["directory"])
        identity_maps(child[0])
        origin = shim(shim_pid, cid)
        proof = None
        if parent_pid == origin["key"][0]:
            parent = tuple(origin["key"])
        else:
            try:
                proof = runtime_parent(parent_pid, child, shim_pid, cid, runtime)
                parent = tuple(proof["key"])
            except (FileNotFoundError, ProcessLookupError, RuntimeParentExited):
                parent = None
        after, after_parent_pid = stat_at(handle["directory"], child[0])
        after_exe = exe_identity(os.stat("exe", dir_fd=handle["directory"]))
        after_group = cgroup_at(handle["directory"])
        check_binding(handle)
        try:
            after_argv = command(child[0])
        except EvidenceError as error:
            if error.args != ("empty-process-command",) or argv != ("runc", "init"):
                raise
            require(group == after_group == expected_cgroup, "runtime-parent-retry-cgroup-changed")
            require(first == after == child and before == after_exe == executable and parent_pid == after_parent_pid,
                    "runtime-parent-retry-child-changed")
            read = {"key_before": list(first), "key_after": list(after), "argv": list(argv),
                    "exe_identity_before": before, "exe_identity_after": after_exe,
                    "cgroup_before": group, "cgroup_after": after_group,
                    "parent_pid_before": parent_pid, "parent_pid_after": after_parent_pid,
                    "read_started_at": started, "time": clock()}
            require(read["time"] - started <= .05, "runtime-parent-retry-exhausted")
            current, _ = proc_stat(child[0])
            current_group = cgroup_path(child[0])
            read["fresh_finished_at"] = clock()
            if current != child or current_group != expected_cgroup:
                raise
            require(read["fresh_finished_at"] - started <= .05, "runtime-parent-retry-exhausted")
            raise RuntimeExecTransition("runtime-exec-transition-retry-empty-command",
                                        {"key": list(current), "cgroup": current_group, "first_argv": ["runc", "init"],
                                         "empty": True, "retry_read": read})
        if first == after == child and group == after_group == expected_cgroup and after_argv == HEALTH:
            raise RuntimeExecTransition("runtime-exec-transition-during-retry", {"key": list(after), "cgroup": after_group,
                                                                                 "first_argv": list(argv), "second_argv": list(after_argv)})
        require(first == after == child and before == after_exe == executable and
                argv == after_argv == ("runc", "init") and
                group == after_group == expected_cgroup and parent_pid == after_parent_pid,
                "runtime-parent-retry-child-changed")
        reads.append({"key_before": list(first), "key_after": list(after), "argv": list(argv),
                      "exe_identity_before": before, "exe_identity_after": after_exe,
                      "cgroup_before": group, "cgroup_after": after_group, "time": clock()})
        finished = clock()
        require(finished - started <= .05, "runtime-parent-retry-exhausted")
        if parent is not None:
            return parent_pid, parent, proof, {"reason": reason, "reads": reads,
                                              "read_started_at": started, "read_finished_at": finished}
    raise EvidenceError("runtime-parent-retry-exhausted")


def exec_transition(pid, key, expected_cgroup, reason, **facts):
    current, _ = proc_stat(pid)
    group = cgroup_path(pid)
    if current == key and group == expected_cgroup:
        raise RuntimeExecTransition(reason, {"key": list(current), "cgroup": group, **facts})


def exec_command(pid, key, expected_cgroup, runtime_before):
    try:
        return command(pid)
    except EvidenceError as error:
        if error.args == ("empty-process-command",) and runtime_before:
            exec_transition(pid, key, expected_cgroup, "runtime-exec-transition-empty-command", first_argv=["runc", "init"], empty=True)
        raise


def process(pid, expected_cgroup, shim_pid, cid, runtime, handle, previous_row=None, partial=None):
    started, executable_fd, group_before = clock(), None, None
    try:
        check_binding(handle)
        first, parent_pid = proc_stat(pid)
        require(first == handle["key"], "process-binding-identity-race")
        if partial is not None:
            partial.update(key=list(first))
        argv = exec_command(pid, first, expected_cgroup,
                            previous_row is not None and tuple(previous_row["argv"]) == ("runc", "init"))
        known = argv == ("runc", "init") or product_command(argv)
        require(known, "unknown-process-command-suppressed")
        is_runtime = argv == ("runc", "init")
        if is_runtime:
            executable_fd = os.open("exe", os.O_RDONLY, dir_fd=handle["directory"])
            opened_at, executable_stat = clock(), file_stat(os.fstat(executable_fd))
            group_before = cgroup_at(handle["directory"])
            if partial is not None:
                partial["cgroup_before"] = group_before
        permissions = permissions_at(handle["directory"])
        if partial is not None:
            partial.update(key=list(first), argv=list(argv), permissions=permissions)
        try:
            if is_runtime:
                runtime_permissions(permissions, argv, previous_row)
            else:
                observed_permissions(permissions, argv, previous_row)
        except InvalidProfile as error:
            raise EvidenceError("observed-profile-" + error.args[0]) from None
        proof, retry = None, None
        if is_runtime and parent_pid != shim_pid:
            try:
                proof = runtime_parent(parent_pid, first, shim_pid, cid, runtime)
                parent = tuple(proof["key"])
            except (FileNotFoundError, ProcessLookupError, RuntimeParentExited) as error:
                parent_pid, parent, proof, retry = runtime_parent_after_enoent(
                    handle, first, shim_pid, cid, runtime, expected_cgroup, executable_stat[:2],
                    reason=PARENT_GONE[type(error)])
        else:
            try:
                parent, _ = proc_stat(parent_pid)
            except (FileNotFoundError, ProcessLookupError):
                if argv == HEALTH and parent_pid != shim_pid:
                    exec_transition(pid, first, expected_cgroup, "runtime-exec-transition-parent-exited",
                                    first_argv=list(argv), first_parent=parent_pid)
                raise
        identity_maps(pid)
        require(cgroup_path(pid) == expected_cgroup, "process-left-container-cgroup")
        identity_maps(pid)
        second, second_parent = proc_stat(pid)
        if partial is not None:
            partial.update(second_key=list(second), second_parent=second_parent)
        check_binding(handle)
        require(first == second, "process-key-changed-during-snapshot")
        after_argv = exec_command(pid, first, expected_cgroup, is_runtime)
        if partial is not None:
            partial["second_argv"] = list(after_argv)
        if (is_runtime and after_argv == HEALTH or
                parent_pid != second_parent == shim_pid and argv in (("runc", "init"), HEALTH)):
            exec_transition(pid, first, expected_cgroup, "runtime-exec-transition-during-snapshot", first_argv=list(argv),
                            second_argv=list(after_argv), first_parent=parent_pid, second_parent=second_parent)
        require(parent_pid == second_parent, "process-parent-changed-during-snapshot")
        require(after_argv == argv, "process-command-changed-during-snapshot")
        if is_runtime:
            second_exe = exe_identity(os.stat("exe", dir_fd=handle["directory"]))
            if partial is not None:
                partial["second_exe"] = second_exe
            require(second_exe == executable_stat[:2], "runtime-executable-changed-during-snapshot")
            group_after = cgroup_at(handle["directory"])
            require(group_before == group_after == expected_cgroup, "runtime-process-left-container-cgroup")
        finished = clock()
        result = {"key": list(first), "parent": list(parent), "argv": list(argv), **permissions,
                  "read_started_at": started, "read_finished_at": finished, "binding": handle["evidence"]}
        if proof is not None:
            result["runtime_parent"] = proof
        if retry is not None:
            result["parent_retry"] = retry
        if is_runtime:
            result["runtime_executable"] = {
                "pin": "opened-current-exe", "key_before": list(first), "key_after": list(second),
                "procdir_identity": handle["evidence"]["procdir_identity"],
                "cgroup_before": group_before, "cgroup_after": group_after, "snapshot_finished_at": finished,
                "file": hash_executable(executable_fd, executable_stat, opened_at)}
            require(result["runtime_executable"]["file"]["sha256"] == runtime["binary"]["sha256"],
                    "runtime-content-mismatch")
        return result
    except RuntimeExecTransition:
        if executable_fd is not None:
            require(group_before == expected_cgroup, "runtime-process-left-container-cgroup")
        if executable_fd is not None and partial is not None:
            partial["runtime_executable"] = {"pin": "opened-current-exe", "procdir_identity": handle["evidence"]["procdir_identity"],
                                             "file": hash_executable(executable_fd, executable_stat, opened_at)}
        raise
    finally:
        if executable_fd is not None:
            os.close(executable_fd)


def shim(pid, cid):
    first, _ = proc_stat(pid)
    exe = os.readlink(f"/proc/{pid}/exe")
    argv = command(pid)
    require(exe in ("/usr/bin/containerd-shim-runc-v2", "/usr/local/bin/containerd-shim-runc-v2") and
            len(argv) == 7 and argv[:6] == (exe, "-namespace", "moby", "-id", cid, "-address") and
            argv[6] == "/run/containerd/containerd.sock", "unverified-container-shim")
    actual, expected = os.stat(f"/proc/{pid}/exe"), os.stat(exe)
    require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino), "shim-executable-mismatch")
    require(proc_stat(pid)[0] == first, "shim-identity-race")
    return {"key": list(first), "exe": exe, "argv": list(argv), "exe_identity": exe_identity(actual)}


def inspect(cid):
    result = subprocess.run(["docker", "inspect", "--type", "container", "--format", DOCKER_FORMAT, cid],
                            capture_output=True, text=True, timeout=10)
    require(result.returncode == 0, "docker-inspect-failed")
    info = json.loads(result.stdout)
    require(info["id"] == cid and info["running"] is True and type(info["pid"]) is int and info["pid"] > 0,
            "container-not-running-or-identity-mismatch")
    health = info["health"]
    require(health["Test"] == ["CMD", "netops", "health"] and health["Interval"] == 30000000000 and
            health["Timeout"] == 10000000000, "unreviewed-health-configuration")
    return {key: info[key] for key in ("id", "image", "pid", "running", "restarts", "runtime")}


def runtime_metadata(container_runtime, explicit_path):
    result = subprocess.run(["docker", "info", "--format",
                             '{"default":{{json .DefaultRuntime}},"runtimes":{{json .Runtimes}}}'],
                            capture_output=True, text=True, timeout=10)
    require(result.returncode == 0, "docker-runtime-info-failed")
    info = json.loads(result.stdout)
    selected = container_runtime or info["default"]
    config = info["runtimes"][selected]
    configured = config.get("path") or ""
    if configured.startswith("/"):
        require(explicit_path is None or os.path.realpath(explicit_path) == os.path.realpath(configured),
                "explicit-runtime-conflicts-with-docker")
        path, origin = configured, "docker-runtime-path"
    else:
        require(selected in ("runc", "io.containerd.runc.v2") and configured in ("", "runc") and
                config.get("runtimeType", "") in ("", "io.containerd.runc.v2") and explicit_path is not None,
                "abstract-docker-runtime-needs-explicit-host-runc")
        path, origin = explicit_path, "explicit-host-runc"
    require(type(path) is str and path.startswith("/") and os.path.basename(path) == "runc",
            "absolute-host-runc-path-required")
    path = os.path.realpath(path, strict=True)
    require(os.path.basename(path) == "runc", "canonical-runc-name-required")
    actual = os.stat(path)
    require(stat.S_ISREG(actual.st_mode) and actual.st_uid == 0 and not actual.st_mode & 0o022,
            "unsafe-host-runtime-binary")
    return {"path": path, "exe_identity": exe_identity(actual), "origin": origin,
            "docker_runtime": selected, "docker_configured_path": configured,
            "docker_runtime_type": config.get("runtimeType", "")}


def members(directory):
    require(not any(stat.S_ISDIR(os.stat(name, dir_fd=directory, follow_symlinks=False).st_mode)
                    for name in os.listdir(directory)), "nested-cgroups-unsupported")
    fd = os.open("cgroup.procs", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(1048577)
    require(len(data) <= 1048576, "cgroup-membership-too-large")
    pids = list(map(int, data.split()))
    require(len(set(pids)) == len(pids) and all(pid > 0 for pid in pids), "invalid-cgroup-membership")
    return set(pids)


def code(error):
    return error.args[0] if isinstance(error, EvidenceError) else "proc-read-or-schema-failed"


def failure(error, **fields):
    item = {"reason": code(error), **fields}
    if not isinstance(error, EvidenceError):
        item.update(error=type(error).__name__, errno=getattr(error, "errno", None))
        if hasattr(error, "netops_stage"):
            item["stage"] = error.netops_stage
    return item


PROC_NAMES = frozenset(("stat", "cgroup", "status", "exe", "cmdline", "uid_map", "gid_map", "mountinfo", "ns/pid",
                        "root/proc", "cgroup.procs"))


def proc_operation(path):
    if type(path) is not str:
        return None
    name = os.path.normpath(path)
    if (re.fullmatch("/proc(/[A-Za-z0-9_.]{1,32}){1,4}", name) or name in PROC_NAMES or
            re.fullmatch("[0-9]{1,10}", name)):
        return name
    return "other"


def process_profile(row):
    profile = {key: value for key, value in row.items() if key not in ("read_started_at", "read_finished_at")}
    if "runtime_parent" in profile:
        profile["runtime_parent"] = {key: value for key, value in profile["runtime_parent"].items()
                                     if key not in ("read_started_at", "read_finished_at")}
    return profile


class NamespaceScope:
    def __init__(self, init, path, handles, context=None):
        import ctypes
        import fcntl
        self.ctypes, self.ioctl = ctypes, fcntl.ioctl
        self.fds, self.owned, self.inside_seen, self.outside_seen, self.inside_locals = [], [], set(), set(), {}
        self.init, self.path, self.handles, self.context, self.identities, self.parents = init, path, handles, context, {}, {}
        self.parent_pins, self.links, self.unlinked, self.child_reads = {}, {}, {}, {}
        try:
            require(os.uname().machine in ("x86_64", "aarch64") and ctypes.sizeof(ctypes.c_long) == 8,
                    "namespace-ioctl-abi-unsupported")
            self.observer = self.pin(os.getpid(), cgroup_path(os.getpid()), owned=True)
            self.init_handle = self.pin(init[0], path)
            require(self.init_handle["key"] == init, "namespace-init-key-mismatch")
            self.hostproc = self.open("/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.hostns = self.open("ns/pid", os.O_RDONLY, self.observer["directory"])
            self.ownns = self.open("ns/pid", os.O_RDONLY, self.init_handle["directory"])
            self.ownproc = self.open("root/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     self.init_handle["directory"])
            self.host_identity, self.own_identity = self.identity(self.hostns), self.identity(self.ownns)
            require(self.host_identity != self.own_identity, "container-host-pid-namespace-shared")
            parent = self.ioctl(self.ownns, 0xb702)
            self.fds.append(parent)
            os.set_inheritable(parent, False)
            require(self.identity(parent) == self.host_identity, "container-pid-namespace-parent-unbound")
            self.host_pid1 = self.open("1", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, self.hostproc)
            self.host_pid1_key = stat_at(self.host_pid1, 1)[0]
            self.host_mount = self.mount(self.hostproc, self.observer["directory"])
            self.own_mount = self.mount(self.ownproc, self.init_handle["directory"])
            self.header = {"method": "procfs-nsfs-pidfd-v1", "init": list(init),
                           "observer": list(self.observer["key"]), "observer_namespace": self.host_identity,
                           "container_namespace": self.own_identity, "container_parent_namespace": self.identity(parent),
                           "host_proc": self.host_mount, "container_proc": self.own_mount,
                           "host_proc_pid1": list(self.host_pid1_key), "host_proc_pid1_namespace": self.host_identity,
                           "max_capture_passes": 2, "snapshot_budget_seconds": .2}
            self.verify_authority()
        except BaseException:
            self.close()
            raise

    def open(self, name, flags, directory=None):
        fd = os.open(name, flags, dir_fd=directory)
        self.fds.append(fd)
        return fd

    def identity(self, fd):
        return exe_identity(os.fstat(fd))

    def pin(self, pid, path, owned=False):
        key, parent = proc_stat(pid)
        reads = self.child_reads.setdefault(pid, [])
        reads.append([list(key), parent])
        if not owned and key in self.handles:
            handle = self.handles[key]
        else:
            try:
                handle = pin_process(pid, path)
            except Exception as error:
                reads.extend(getattr(error, "netops_child_reads", []))
                raise
            reads.extend(handle.get("reads", []))
            if handle["key"] != key:
                close_binding(handle)
                raise EvidenceError("namespace-process-reused-during-pin")
            if owned:
                self.owned.append(handle)
            else:
                self.handles[key] = handle
        self.live(handle, path)
        return handle

    def live(self, handle, path):
        check_binding(handle)
        if pidfd_events(handle["pidfd"]):
            raise ProcessExited("namespace-process-exited")
        require(cgroup_at(handle["directory"]) == path, "namespace-process-not-live-or-cgroup-changed")

    def zombie(self, key, local_pid):
        events = pidfd_events(self.handles[key]["pidfd"])
        host, _, state = stat_detail_at(self.handles[key]["directory"], key[0])
        fd = os.open(str(local_pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.ownproc)
        try:
            local, _, local_state = stat_detail_at(fd, local_pid)
        finally:
            os.close(fd)
        if events & select.POLLIN and host == key and state == local_state == "Z" and local == (local_pid, key[1]):
            return {"pidfd_events": events, "key": list(host), "state": state, "local_key": list(local),
                    "local_state": local_state, "verified_at": clock()}
        return None

    def identify(self, handle):
        found = self.identities[handle["key"][0]]
        found["binding"] = handle["evidence"]
        try:
            found["fd"] = os.open("exe", os.O_RDONLY, dir_fd=handle["directory"])
            found.update(opened_at=clock(), stat=file_stat(os.fstat(found["fd"])))
            found["permissions"] = permissions_at(handle["directory"])
        except (OSError, ValueError, KeyError):
            return

    def parent_facts(self, pin, shim_pid, cid):
        facts = {}
        try:
            facts["cgroup"] = cgroup_at(pin["directory"])
            facts["permissions"] = permissions_at(pin["directory"])
            facts["active_namespace"] = self.namespace(pin["directory"])
            facts["fd"] = os.open("exe", os.O_RDONLY, dir_fd=pin["directory"])
            facts.update(opened_at=clock(), stat=file_stat(os.fstat(facts["fd"])))
            facts["shim_cgroup"] = cgroup_path(shim_pid)
            facts["shim"] = shim(shim_pid, cid)
        except (OSError, ValueError, KeyError, EvidenceError):
            if "fd" in facts:
                os.close(facts["fd"])
            return None
        return facts

    def link(self, child, parent_pid, observed_at, unknown=False):
        shim_pid, cid, runtime = self.context
        if parent_pid == shim_pid:
            return
        try:
            if not any(key[0] == parent_pid for key in self.parent_pins):
                directory = os.open(f"/proc/{parent_pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                pin = {"directory": directory}
                try:
                    pin["pidfd"] = os.pidfd_open(parent_pid, 0)
                    key, _ = stat_at(directory, parent_pid)
                    pin["pinned_at"] = clock()
                    pin["facts"] = self.parent_facts(pin, shim_pid, cid)
                    pin["proof"] = runtime_parent(parent_pid, child, shim_pid, cid, runtime)
                    events, polled_at = pidfd_events(pin["pidfd"]), clock()
                    require(tuple(pin["proof"]["key"]) == key and not events, "runtime-parent-pin-race")
                    if pin["facts"] is not None:
                        pin["facts"].update(alive_at_pin=True, alive_polled_at=polled_at)
                except BaseException:
                    self.unpin(pin)
                    raise
                self.parent_pins[key] = pin
            for key, pin in self.parent_pins.items():
                if key[0] == parent_pid and key[1] <= child[1]:
                    alive, alive_at = not pidfd_events(pin["pidfd"]), clock()
                    try:
                        again, again_parent = proc_stat(child[0])
                    except (FileNotFoundError, ProcessLookupError) as error:
                        if unknown and alive and (type(error), error.errno) in ((FileNotFoundError, errno.ENOENT),
                                                                                (ProcessLookupError, errno.ESRCH)):
                            self.unlinked[child] = {"parent_key": list(key), "parent_alive_at": alive_at,
                                                    "child_stat": {"key": list(child), "parent_pid": parent_pid, "at": observed_at},
                                                    "restat_error": type(error).__name__, "restat_errno": error.errno,
                                                    "restat_at": clock(), "stage": "link-child-restat"}
                        raise
                    restat_at = clock()
                    if again == child and again_parent == parent_pid and not pidfd_events(pin["pidfd"]):
                        self.links[child] = {"key": list(key), "child_stat_at": observed_at, "child_restat_at": restat_at,
                                             "child_restat_key": list(again), "child_restat_parent": again_parent,
                                             "parent_alive_at": clock()}
        except (OSError, ValueError, KeyError, EvidenceError):
            return

    def unpin(self, pin):
        if pin.get("facts") is not None:
            os.close(pin["facts"]["fd"])
        if "pidfd" in pin:
            os.close(pin["pidfd"])
        os.close(pin["directory"])

    def release(self):
        for pin in self.parent_pins.values():
            self.unpin(pin)
        self.parent_pins, self.links, self.unlinked, self.child_reads = {}, {}, {}, {}

    def exited(self, key):
        try:
            fd = os.open(str(key[0]), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.hostproc)
        except FileNotFoundError:
            return "reaped"
        try:
            current, _, state = stat_detail_at(fd, key[0])
            if current == key and state == "Z" and cgroup_at(fd) == self.path:
                return "zombie"
        except (FileNotFoundError, ProcessLookupError):
            return "reaped"
        finally:
            os.close(fd)
        return None

    def absent(self, pid, root=None):
        try:
            os.stat(str(pid), dir_fd=self.ownproc if root is None else root, follow_symlinks=False)
        except FileNotFoundError:
            return True
        return False

    def namespace(self, directory):
        fd = os.open("ns/pid", os.O_RDONLY, dir_fd=directory)
        try:
            require(self.ioctl(fd, 0xb703) == 0x20000000, "not-a-pid-namespace")
            return self.identity(fd)
        finally:
            os.close(fd)

    def mount(self, fd, taskdir):
        buf = self.ctypes.create_string_buffer(256)
        require(self.ctypes.CDLL(None, use_errno=True).fstatfs(fd, buf) == 0,
                "procfs-type-read-failed")
        magic = self.ctypes.c_long.from_buffer(buf).value
        require(magic == 0x9fa0, "authoritative-procfs-required")
        info = read(f"/proc/self/fdinfo/{fd}").decode("ascii").splitlines()
        ids = [int(line.split(":", 1)[1]) for line in info if line.startswith("mnt_id:")]
        require(len(ids) == 1, "procfs-mount-id-unavailable")
        mountinfo = read_at(taskdir, "mountinfo")
        rows = [line.split() for line in mountinfo.decode("ascii").splitlines()
                if line.split()[0] == str(ids[0])]
        require(len(rows) == 1, "procfs-mount-not-bound-to-task-view")
        row = rows[0]
        separator = row.index("-")
        options = set(row[5].split(",")) | set(row[separator + 3].split(","))
        require(row[3:5] == ["/", "/proc"] and row[separator + 1] == "proc" and
                not any(item.startswith("subset=") or item.startswith("hidepid=") and item != "hidepid=0"
                        for item in options), "restricted-or-unbound-procfs-view")
        return {"identity": self.identity(fd), "magic": magic, "mount_id": ids[0], "root": "/",
                "mountpoint": "/proc", "fstype": "proc", "hidepid": 0, "subset": "all",
                "mount_row_sha256": hashlib.sha256(" ".join(row).encode("ascii")).hexdigest()}

    def verify_authority(self):
        require(exe_identity(os.stat("/proc", follow_symlinks=False)) == self.identity(self.hostproc),
                "observer-procfs-replaced")
        self.live(self.observer, self.observer["evidence"]["cgroup"])
        self.live(self.init_handle, self.path)
        require(self.namespace(self.observer["directory"]) == self.host_identity and
                self.namespace(self.init_handle["directory"]) == self.own_identity and
                self.namespace(self.host_pid1) == self.host_identity and
                stat_at(self.host_pid1, 1)[0] == self.host_pid1_key,
                "observer-host-proc-pid1-namespace-unbound")
        require(os.readlink("self", dir_fd=self.hostproc) == str(os.getpid()), "observer-proc-self-unbound")
        for root, pid, key in ((self.hostproc, os.getpid(), self.observer["key"]),
                               (self.ownproc, 1, (1, self.init[1]))):
            fd = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                require(stat_at(fd, pid)[0] == key, "procfs-visible-key-unbound")
            finally:
                os.close(fd)
        require(self.ioctl(self.ownns, 0x8004b706, 1) == self.init[0] and
                self.ioctl(self.ownns, 0x8004b708, self.init[0]) == 1,
                "container-proc-pid1-mapping-unbound")
        current = os.open("root/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=self.init_handle["directory"])
        try:
            require(self.identity(current) == self.identity(self.ownproc), "container-procfs-replaced")
        finally:
            os.close(current)
        require(self.mount(self.hostproc, self.observer["directory"]) == self.host_mount and
                self.mount(self.ownproc, self.init_handle["directory"]) == self.own_mount,
                "authoritative-procfs-mount-changed")
        return {"observer": list(self.observer["key"]), "init": list(self.init),
                "observer_namespace": self.host_identity, "container_namespace": self.own_identity,
                "host_proc_pid1_namespace": self.host_identity, "host_proc_pid1": list(self.host_pid1_key),
                "host_proc_self_pid": os.getpid(), "host_proc": self.host_mount, "container_proc": self.own_mount,
                "pid1_host": self.init[0], "init_local_pid": 1}

    def inside(self, local_pid, host_pid):
        local = os.open(str(local_pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.ownproc)
        try:
            first = stat_at(local, local_pid)[0]
            local_identity = self.identity(local)
            handle = self.pin(host_pid, self.path)
            active = self.namespace(handle["directory"])
            require(active != self.host_identity and self.namespace(local) == active and
                    first[1] == handle["key"][1] and self.identity(local) == local_identity and
                    self.ioctl(self.ownns, 0x8004b706, local_pid) == host_pid and
                    self.ioctl(self.ownns, 0x8004b708, host_pid) == local_pid and
                    stat_at(local, local_pid)[0] == first and
                    exe_identity(os.stat(str(local_pid), dir_fd=self.ownproc, follow_symlinks=False)) == local_identity,
                    "inside-namespace-mapping-unstable")
            self.live(handle, self.path)
            require(handle["key"] not in self.outside_seen, "namespace-classification-changed")
            self.inside_seen.add(handle["key"])
            self.inside_locals[handle["key"]] = local_pid
            return {"local_pid": local_pid, "key": list(handle["key"]), "active_namespace": active,
                    "procdir_identity": local_identity, "procdir_identity_after": local_identity,
                    "binding": handle["evidence"],
                    "from_namespace": host_pid, "in_namespace": local_pid, "verified_at": clock()}
        finally:
            os.close(local)

    def outside(self, pid, handle=None):
        handle = self.pin(pid, self.path) if handle is None else handle
        started = clock()
        active = self.namespace(handle["directory"])
        self.live(handle, self.path)
        require(active == self.host_identity and active != self.own_identity and
                handle["key"][0] == pid and handle["key"] not in self.inside_seen,
                "cgroup-only-process-not-proven-observer-host-namespace")
        require(self.namespace(handle["directory"]) == active, "outside-namespace-identity-changed")
        self.live(handle, self.path)
        self.outside_seen.add(handle["key"])
        return {"key": list(handle["key"]), "active_namespace_before": active,
                "active_namespace_after": active, "binding": handle["evidence"],
                "pidfd_alive_before": True, "pidfd_alive_after": True, "method": "held-active-host-pidns-v1",
                "read_started_at": started, "read_finished_at": clock()}

    def classify_host(self, pid):
        handle = self.pin(pid, self.path)
        active = self.namespace(handle["directory"])
        self.identities.setdefault(pid, {})["active_namespace"] = active
        if active == self.host_identity:
            self.identify(handle)
        self.live(handle, self.path)
        if active == self.host_identity:
            return self.outside(pid, handle)
        return None

    def inventory(self, directory):
        result = {"read_started_at": clock(), "mappings": [], "excluded": [], "failures": [], "vanished": [],
                  "exited_helpers": [], "unobserved": []}
        gone, vanished = object(), set()
        gone_marker = gone
        where = {"stage": "authority-before"}

        def refuse(error, point):
            error.netops_point = point
            return error

        def forget(error, stage, pid, local):
            known = [(key, value) for key, value in self.inside_locals.items() if value != 1 and key in self.handles and
                     pid in (None, key[0]) and local in (None, value)]
            if len(known) != 1:
                raise refuse(error, "forget-key-not-unique")
            if known[0][0][0] in members(directory):
                raise refuse(error, "forget-still-member")
            key, local = known[0]
            entry = {"pid": key[0], "key": list(key), "local_pid": local, "stage": stage,
                     "error": type(error).__name__, "errno": getattr(error, "errno", None)}
            try:
                proof = self.zombie(key, local)
            except (FileNotFoundError, ProcessLookupError):
                if not self.absent(local):
                    raise refuse(error, "forget-local-present")
            else:
                if proof is None:
                    raise refuse(error, "forget-zombie-unproven")
                entry["zombie"] = proof
            entry["verified_absent_at"] = clock()
            result["vanished"].append(entry)
            vanished.add(key[0])
            return gone

        def retire(error, key, parent_pid, found):
            shim_pid, cid, runtime = self.context
            handle = self.handles.get(key)
            if key in self.inside_seen:
                raise refuse(error, "retire-inside-seen")
            if key[0] in members(directory):
                raise refuse(error, "retire-still-member")
            if handle is not None and not pidfd_events(handle["pidfd"]) & select.POLLIN:
                raise refuse(error, "retire-pidfd-live")
            state = self.exited(key)
            if state is None:
                raise refuse(error, "retire-exit-unproven")
            if (found.get("active_namespace", self.host_identity) != self.host_identity or
                    found.get("permissions", {"uids": [0] * 4})["uids"] != [0] * 4):
                raise refuse(error, "retire-not-host-root")
            entry = {"key": list(key), "parent_pid": parent_pid, "stage": "classify-host", "exit": state,
                     "reason": "identified" if "permissions" in found else "parent-verified"}
            entry.update({name: found[name] for name in ("binding", "active_namespace", "permissions") if name in found})
            if "fd" in found:
                entry["file"] = hash_executable(found["fd"], found["stat"], found["opened_at"])
                if (entry["file"]["sha256"], entry["file"]["bytes_hashed"]) != (runtime["binary"]["sha256"],
                                                                                runtime["binary"]["bytes_hashed"]):
                    raise refuse(error, "retire-content-mismatch")
            link = self.links.get(key)
            if (link is None or link["key"][0] != parent_pid) and key in self.unlinked:
                return reaped(error, key, parent_pid, entry, state)
            if link is None or link["key"][0] != parent_pid:
                raise refuse(error, "retire-no-parent-link")
            entry.update(runtime_parent=self.parent_pins[tuple(link["key"])]["proof"], parent_link=link)
            entry.update(error=type(error).__name__, errno=getattr(error, "errno", None), verified_absent_at=clock())
            result["exited_helpers"].append(entry)
            vanished.add(key[0])
            return gone

        def reaped(error, key, parent_pid, entry, state):
            shim_pid, cid, runtime = self.context
            gone = self.unlinked[key]
            parent_key = tuple(gone["parent_key"])
            pins = [candidate for candidate in self.parent_pins if candidate[0] == parent_pid]
            pin = self.parent_pins.get(parent_key)
            facts = pin.get("facts") if pin is not None else None
            if (type(error), getattr(error, "errno", None)) not in ((FileNotFoundError, errno.ENOENT), (ProcessLookupError, errno.ESRCH)):
                raise refuse(error, "retire-reaped-error")
            if state != "reaped":
                raise refuse(error, "retire-reaped-not-reaped")
            if key in self.handles:
                raise refuse(error, "retire-reaped-child-pinned")
            if pins != [parent_key]:
                raise refuse(error, "retire-reaped-identity")
            reads = list(self.child_reads.get(key[0], []))
            if any(read != [list(key), parent_pid] for read in reads):
                raise refuse(error, "retire-reaped-child-read-contradiction")
            if not parent_key[1] < key[1]:
                raise refuse(error, "retire-reaped-parent-not-older")
            if (facts is None or facts["cgroup"] != facts["shim_cgroup"] or
                    facts["cgroup"] == self.path or facts["permissions"]["uids"] != [0] * 4 or
                    facts["active_namespace"] != self.host_identity or facts["shim"] != pin["proof"]["shim"]):
                raise refuse(error, "retire-reaped-parent-facts")
            try:
                file = hash_executable(facts["fd"], facts["stat"], facts["opened_at"])
            except (OSError, ValueError, EvidenceError):
                raise refuse(error, "retire-reaped-parent-content") from None
            if (file["sha256"], file["bytes_hashed"]) != (runtime["binary"]["sha256"], runtime["binary"]["bytes_hashed"]):
                raise refuse(error, "retire-reaped-parent-content")
            try:
                self.ioctl(self.ownns, 0x8004b708, key[0])
            except OSError as failure:
                if failure.errno not in (errno.ESRCH, errno.ENOTTY):
                    raise refuse(error, "retire-reaped-namespace-unknown") from None
                namespace_errno = failure.errno
            else:
                raise refuse(error, "retire-reaped-visible-in-namespace")
            if key[0] in members(directory):
                raise refuse(error, "retire-reaped-still-member")
            entry.update(reason="reaped-before-restat", runtime_parent=pin["proof"], child_stat=gone["child_stat"],
                         child_reads=reads, namespace_absence_errno=namespace_errno,
                         parent_pin={"key": list(parent_key), "pinned_at": pin["pinned_at"], "alive_at_pin": facts["alive_at_pin"],
                                     "alive_at_pin_basis": "outer-pidfd-poll-after-role-proof",
                                     "alive_polled_at": facts["alive_polled_at"],
                                     "cgroup": facts["cgroup"], "shim_cgroup": facts["shim_cgroup"], "shim": facts["shim"],
                                     "permissions": facts["permissions"], "active_namespace": facts["active_namespace"],
                                     "file": file},
                         unlinked={name: gone[name] for name in ("parent_key", "parent_alive_at", "restat_error",
                                                                 "restat_errno", "restat_at", "stage")})
            entry.update(error=type(error).__name__, errno=error.errno, verified_absent_at=clock())
            result["exited_helpers"].append(entry)
            vanished.add(key[0])
            return gone_marker

        def unobserved(error, pid):
            known = [key for key in self.handles if key[0] == pid]
            if any(key in self.inside_locals for key in known):
                return forget(error, "classify-host", pid, None)
            if known:
                if len(known) != 1 or known[0] not in self.outside_seen:
                    raise refuse(error, "unobserved-known-not-outside")
                return retire(error, known[0], self.parents.get(known[0]), {})
            if pid in members(directory):
                raise refuse(error, "unobserved-still-member")
            if not self.absent(pid, self.hostproc):
                raise refuse(error, "unobserved-hostproc-present")
            result["unobserved"].append({"pid": pid, "stage": "classify-host", "error": type(error).__name__,
                                         "errno": error.errno, "verified_absent_at": clock()})
            vanished.add(pid)
            return gone

        def classify(pid):
            try:
                first, parent_pid = proc_stat(pid)
            except (FileNotFoundError, ProcessLookupError) as error:
                return unobserved(error, pid)
            unknown = first not in self.handles and first not in self.inside_seen and first not in self.outside_seen
            self.parents[first] = parent_pid
            self.link(first, parent_pid, clock(), unknown)
            try:
                return self.classify_host(pid)
            except (FileNotFoundError, ProcessLookupError, EvidenceError) as error:
                if type(error) is EvidenceError and error.args != ("unverified-initial-process-binding",):
                    raise
                return retire(error, first, parent_pid, self.identities.get(pid, {}))
            finally:
                found = self.identities.pop(pid, None)
                if found is not None and "fd" in found:
                    os.close(found["fd"])

        try:
            result["authority_before"] = self.verify_authority()
            where = {"stage": "cgroup-members"}
            raw = members(directory)
            excluded = set()
            known_inside = {key[0] for key in self.inside_seen}
            for pid in sorted(raw - known_inside):
                where = {"stage": "classify-host-first", "pid": pid}
                proof = classify(pid)
                if proof is gone:
                    continue
                if proof is not None:
                    result["excluded"].append(proof)
                    excluded.add(pid)
            where = {"stage": "container-procfs-list"}
            local_pids = sorted(int(name) for name in os.listdir(self.ownproc) if name.isascii() and name.isdecimal())
            require(local_pids and local_pids[0] == 1 and len(local_pids) == len(set(local_pids)),
                    "invalid-container-procfs-membership")
            result.update(cgroup_pids=sorted(raw), visible_pids=local_pids)
            inside = set()
            for local_pid in local_pids:
                host_pid = None
                where = {"stage": "inside-mapping", "local_pid": local_pid}
                try:
                    host_pid = self.ioctl(self.ownns, 0x8004b706, local_pid)
                    where["pid"] = host_pid
                    require(host_pid > 0, "invalid-namespace-host-pid")
                    mapping = self.inside(local_pid, host_pid)
                except (FileNotFoundError, ProcessLookupError, ProcessExited) as error:
                    forget(error, "inside-mapping", host_pid, local_pid)
                    continue
                except OSError as error:
                    if error.errno != errno.ENOTTY:
                        raise
                    error.netops_stage = "inside-mapping"
                    forget(error, "inside-mapping", host_pid, local_pid)
                    continue
                require(host_pid not in inside, "duplicate-namespace-host-mapping")
                inside.add(host_pid)
                result["mappings"].append(mapping)
            for pid in sorted(raw - inside - excluded - vanished):
                where = {"stage": "classify-host-second", "pid": pid}
                proof = classify(pid)
                if proof is gone:
                    continue
                if proof is not None:
                    result["excluded"].append(proof)
                    excluded.add(pid)
                else:
                    local_pid = self.ioctl(self.ownns, 0x8004b708, pid)
                    require(local_pid > 0, "invalid-namespace-local-pid")
                    result["mappings"].append(self.inside(local_pid, pid))
                    inside.add(pid)
            where = {"stage": "end-membership"}
            result["end_cgroup_pids"] = sorted(members(directory))
            result["end_visible_pids"] = sorted(int(name) for name in os.listdir(self.ownproc)
                                                if name.isascii() and name.isdecimal())
            result["stable"] = (result["end_cgroup_pids"] == result["cgroup_pids"] and
                                result["end_visible_pids"] == result["visible_pids"] and
                                not any("zombie" in item for item in result["vanished"]))
            where = {"stage": "authority-after"}
            result["authority_after"] = self.verify_authority()
            result["complete"] = True
        except (OSError, ValueError, KeyError, EvidenceError) as error:
            result["complete"] = False
            result["failures"].append(failure(error, diagnostic={**where, "point": getattr(error, "netops_point", None),
                                                                 "operation": proc_operation(getattr(error, "filename", None))}))
        result["read_finished_at"] = clock()
        return result

    def close(self):
        self.release()
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()
        for handle in self.owned:
            close_binding(handle)
        self.owned.clear()


def scoped_inventory(scope, directory, failures, inventories):
    result = scope.inventory(directory)
    inventories.append(result)
    failures.extend(result["failures"])
    return {item["key"][0] for item in result["mappings"]}


def sample(directory, path, init, shim_pid, cid, previous, runtime, handles, previous_time, scope=None):
    failures, races, rows, exit_proofs = [], [], {}, {}
    read_started = clock()
    inventories, observed_rows, observed_failures = [], {}, []
    first = (members(directory) if scope is None else
             scoped_inventory(scope, directory, failures, inventories))
    vanished_reads = set()
    previous_pids = {key[0] for key in previous}
    def capture(pids):
        for pid in sorted(pids, key=lambda value: (value in previous_pids, value)):
            partial, attempts = {"pid": pid}, []
            try:
                key, _ = proc_stat(pid)
                if key not in handles:
                    handle = pin_process(pid, path)
                    if handle["key"] != key:
                        close_binding(handle)
                        raise EvidenceError("process-reused-during-binding")
                    handles[key] = handle
                while True:
                    try:
                        row = process(pid, path, shim_pid, cid, runtime, handles[key], previous.get(key), partial)
                        break
                    except RuntimeExecTransition as transition:
                        attempts.append({"reason": transition.args[0], "facts": transition.args[1] if len(transition.args) > 1 else None,
                                         "partial": partial, "binding": handles[key]["evidence"], "time": clock()})
                        partial = {"pid": pid}
                        if len(attempts) > EXEC_RETRIES:
                            raise ExecTransitionLimit("runtime-exec-transition-limit") from None
                if attempts:
                    row["exec_transitions"] = attempts
                rows[tuple(row["key"])] = row
            except ExecTransitionLimit:
                failures.append({"pid": pid, "reason": "runtime-exec-transition-limit", "attempts": attempts})
            except (OSError, ValueError, KeyError, EvidenceError) as error:
                if isinstance(error, (FileNotFoundError, ProcessLookupError)):
                    vanished_reads.add(pid)
                if type(error) is EvidenceError and error.args == ("empty-process-command",):
                    prior = previous.get(tuple(partial.get("key", ())))
                    if prior is not None and tuple(prior["argv"]) == HEALTH and prior["uids"] == [51000] * 4:
                        try:
                            observed_permissions(prior, HEALTH, prior)
                        except InvalidProfile:
                            pass
                        else:
                            vanished_reads.add(pid)
                failures.append(failure(error, pid=pid, partial_observation=partial, **({"attempts": attempts} if attempts else {})))
        observed_rows.update(rows)
        observed_failures.extend(failures[len(observed_failures):])

    capture(first)
    capture_passes = 0
    if scope is None:
        last = members(directory)
        added, removed = last - first, first - last
        if added:
            failures.append({"reason": "new-process-during-snapshot", "pids": sorted(added)})
    else:
        seen_keys = {tuple(item["key"]) for entry in inventories
                     for item in entry["mappings"] + entry["excluded"]}
        all_inside = set(first)
        while True:
            last = scoped_inventory(scope, directory, failures, inventories)
            current_keys = {tuple(item["key"]) for item in inventories[-1]["mappings"] + inventories[-1]["excluded"]}
            added_keys = current_keys - seen_keys
            all_inside.update(last)
            if not added_keys and inventories[-1].get("stable") is True:
                break
            if capture_passes == 2:
                failures.append({"reason": "namespace-discovery-limit", "keys": [list(key) for key in sorted(added_keys)]})
                break
            if clock() - read_started > .2:
                failures.append({"reason": "namespace-snapshot-budget-exceeded"})
                break
            capture_passes += 1
            capture({key[0] for key in added_keys if key[0] in last})
            seen_keys.update(current_keys)
        removed = all_inside - last

    observed_failures = list(failures)

    def prove_exit(key):
        prior, handle, timeout = previous[key], handles[key], 0
        if (tuple(prior["key"]) == key == handle["key"] and
                prior["binding"] == handle["evidence"] and
                tuple(prior["argv"]) == HEALTH and prior["uids"] == [51000] * 4):
            try:
                observed_permissions(prior, HEALTH, prior)
            except InvalidProfile:
                pass
            else:
                timeout = .020
        proof = terminal_exit(handle, timeout=timeout)
        try:
            verified_exit(proof, previous[key], path, clock(), previous_time)
        except InvalidProfile as error:
            failures.append({"pid": key[0], "reason": error.args[0], "exit_observation": proof})
            return False
        exit_proofs[key] = proof
        replacement = proof["replacement_key"]
        if replacement is not None:
            races.append({"kind": "verified-pid-reuse", "key": list(key), "replacement_key": replacement})
        return True

    for pid in sorted(removed):
        old = [key for key in previous if key[0] == pid]
        captured = [key for key in rows if key[0] == pid]
        unchanged = len(old) == 1 and captured == old and process_profile(rows[old[0]]) == process_profile(previous[old[0]])
        absent_read = not captured and pid in vanished_reads
        try:
            proven = len(old) == 1 and (unchanged or absent_read) and prove_exit(old[0])
        except (OSError, ValueError, KeyError, EvidenceError) as error:
            failures.append(failure(error, pid=pid))
            proven = False
        if proven:
            rows.pop(old[0], None)
            failures = [item for item in failures if not (item.get("pid") == pid and
                        item.get("reason") in ("proc-read-or-schema-failed", "empty-process-command") and pid in vanished_reads)]
            races.append({"kind": "verified-known-exit-during-snapshot", "key": list(old[0])})
        else:
            failures.append({"pid": pid, "reason": "unclassified-transient-process"})
    for key in sorted(set(previous) - set(rows) - set(exit_proofs)):
        try:
            prove_exit(key)
        except (OSError, ValueError, KeyError, EvidenceError) as error:
            failures.append(failure(error, pid=key[0]))
    observed_shim = None
    try:
        observed_shim = shim(shim_pid, cid)
        require(proc_stat(init[0])[0] == init and cgroup_path(init[0]) == path, "gateway-identity-or-cgroup-changed")
    except (OSError, ValueError, KeyError, EvidenceError) as error:
        failures.append(failure(error))
    if scope is not None and clock() - read_started > .2:
        failures.append({"reason": "namespace-snapshot-budget-exceeded"})
    if scope is not None and sum(len(entry.get("unobserved", [])) for entry in inventories) > 4:
        failures.append({"reason": "unobserved-transient-limit"})
    complete = not failures and {key[0] for key in rows} == last
    for key in exit_proofs:
        close_binding(handles.pop(key))
    if scope is not None:
        scope.release()
    result = {"time": clock(), "complete": complete, "shim": observed_shim, "pids": sorted(last),
            "read_started_at": read_started, "membership_before": sorted(first),
            "processes": list(rows.values()), "exited": [list(key) for key in sorted(exit_proofs)],
            "exit_proofs": list(exit_proofs.values()), "races": races, "failures": failures}
    if scope is not None:
        result["scope"] = {"inventories": inventories, "capture_passes": capture_passes,
                           "observed_processes": list(observed_rows.values()),
                           "observed_failures": observed_failures, "closed": complete}
    return result


def collect(cid, explicit_runtime=None):
    require(os.geteuid() == 0, "root-read-access-required")
    require(bool(re.fullmatch("[0-9a-f]{64}", cid)), "full-container-id-required")
    require(hashlib.sha256(Path(__file__).with_name("health_bootstrap_profile.py").read_bytes()).hexdigest() == PREDICATE_SHA,
            "predicate-source-mismatch")
    before = inspect(cid)
    runtime = runtime_metadata(before["runtime"], explicit_runtime)
    REFERENCE.clear()
    runtime["binary"] = host_binary(runtime)
    init, shim_pid = proc_stat(before["pid"])
    identity_maps(init[0])
    path = cgroup_path(init[0])
    require(any(part in (cid, "docker-" + cid + ".scope") for part in PurePosixPath(path).parts), "cgroup-container-id-mismatch")
    base = Path("/sys/fs/cgroup").resolve(strict=True)
    target = (base / path.lstrip("/")).resolve(strict=True)
    require(target.is_relative_to(base) and target != base, "cgroup-outside-approved-root")
    directory = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    trace = None
    handles = {}
    scope = None
    try:
        require(init[0] in members(directory), "gateway-not-in-container-cgroup")
        initial_shim = shim(shim_pid, cid)
        scope = NamespaceScope(init, path, handles, (shim_pid, cid, runtime))
        started = clock()
        trace = {"container_id": cid, "clock": "CLOCK_BOOTTIME", "uid_namespace": "container",
                 "ticks_per_second": os.sysconf("SC_CLK_TCK"), "health_interval": 30, "health_timeout": 10,
                 "begin": started, "init": list(init), "samples": [], "cgroup": path,
                 "collector_schema": "health-bootstrap-trace-v5", "scope": scope.header, "runtime": runtime, "rootless_supported": False,
                 "predicate_sha256": PREDICATE_SHA, "initial_metadata": before}
        previous, previous_time, next_tick, deadline, settling = {}, started, started, started + 85, None
        while True:
            delay = min(next_tick, deadline) - clock()
            if delay > 0:
                time.sleep(delay)
            row = sample(directory, path, init, shim_pid, cid, previous, runtime, handles, previous_time, scope=scope)
            previous_time = row["time"]
            if row["shim"] != initial_shim:
                row["complete"] = False
                row["failures"].append({"reason": "shim-identity-changed"})
            trace["samples"].append(row)
            previous = {tuple(item["key"]): item for item in row["processes"]}
            now = row["time"]
            if settling is None and now >= started + 85:
                settling = {key for key, item in previous.items() if item["uids"] == [0] * 4}
                deadline = max([started + 85] + [key[1] / trace["ticks_per_second"] + 10 for key in settling])
            if settling is not None:
                unresolved = [key for key in settling if key in previous and
                              (previous[key]["uids"] != [51000] * 4 or any(previous[key]["caps"].values()))]
                if not unresolved or now >= deadline:
                    break
            next_tick += .05
        trace["end"] = clock()
        after = inspect(cid)
        require(before == after and proc_stat(init[0])[0] == init and
                runtime_metadata(after["runtime"], explicit_runtime) == {key: value for key, value in runtime.items() if key != "binary"},
                "container-or-runtime-changed-during-observation")
        final_binary = host_binary(runtime)
        require(final_binary["stat_before"] == runtime["binary"]["stat_before"] and
                final_binary["sha256"] == runtime["binary"]["sha256"], "host-runtime-changed-during-observation")
        trace["final_metadata"] = after
        trace["assessment"] = assess_trace(trace, require_scope=True)
        return trace
    except (OSError, ValueError, KeyError, IndexError, TypeError, EvidenceError, subprocess.SubprocessError) as error:
        if trace is None:
            raise
        trace["end"] = clock()
        trace["assessment"] = {"passed": False, "reason": code(error)}
        trace["collector_error"] = True
        return trace
    finally:
        if scope is not None:
            scope.close()
        for handle in handles.values():
            close_binding(handle)
        os.close(directory)


def main():
    try:
        require(len(sys.argv) in (2, 4) and (len(sys.argv) == 2 or sys.argv[2] == "--runtime-path"),
                "usage-full-container-id-optional-runtime-path")
        result = collect(sys.argv[1], sys.argv[3] if len(sys.argv) == 4 else None)
        rc = 2 if result.get("collector_error") else (0 if result["assessment"]["passed"] else 1)
    except (OSError, ValueError, KeyError, IndexError, TypeError, EvidenceError, subprocess.SubprocessError) as error:
        result, rc = {"assessment": {"passed": False, "reason": code(error)}, "collector_error": True}, 2
    print(json.dumps(result, separators=(",", ":")))
    return rc


if __name__ == "__main__":
    sys.exit(main())
