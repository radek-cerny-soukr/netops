import math
import re

CAPS = ("inh", "prm", "eff", "bnd", "amb")
BOOTSTRAP_CAPS = 0x1CB
HEALTH = ("/usr/local/bin/python", "/usr/local/bin/netops", "health")
SERVE = ("/usr/local/bin/python", "/usr/local/bin/netops", "serve")
WORKER = ("/usr/local/bin/python", "-m", "netops", "worker")
ROLES = {"helper": 51001, "auditor": 51002, "admin": 51003}


class InvalidProfile(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise InvalidProfile(reason)


def identity(value):
    require(isinstance(value, (list, tuple)) and len(value) == 2 and
            all(type(x) is int and x > 0 for x in value), "invalid-identity")
    return tuple(value)


def number(value):
    require(type(value) in (int, float) and math.isfinite(value), "invalid-clock")
    return value


def executable_identity(value):
    require(type(value) is list and len(value) == 2 and
            type(value[0]) is int and value[0] >= 0 and
            type(value[1]) is int and value[1] > 0, "invalid-executable-identity")
    return tuple(value)


def runtime_exec_argv(argv, cid):
    require(type(argv) is list and all(type(x) is str for x in argv), "unverified-runtime-command")
    prefix = ["runc", "--root", "/var/run/docker/runtime-runc/moby", "--log",
              "/run/containerd/io.containerd.runtime.v2.task/moby/" + cid + "/log.json",
              "--log-format", "json", "--systemd-cgroup", "exec", "--process"]
    require(len(argv) == 15 and argv[:10] == prefix and
            re.fullmatch(r"/tmp/runc-process[0-9]+", argv[10]) is not None and
            argv[11:13] == ["--detach", "--pid-file"] and
            re.fullmatch(r"/run/containerd/io\.containerd\.runtime\.v2\.task/moby/" + cid +
                         r"/[0-9a-f]{64}\.pid", argv[13]) is not None and
            argv[14:] == [cid], "unverified-runtime-command")


def verified_runtime_parent(row, trace, shim, rows, now):
    proof = row["runtime_parent"]
    runtime = trace["runtime"]
    parent = identity(row["parent"])
    require(parent not in rows and parent[0] != identity(shim["key"])[0] and
            identity(shim["key"])[1] <= parent[1] and
            parent[0] not in {key[0] for key in rows} and parent[1] <= row["key"][1],
            "runtime-parent-not-external")
    require(identity(proof["key"]) == parent == identity(proof["key_after"]), "runtime-parent-identity-race")
    require(identity(proof["parent"]) == identity(proof["parent_after"]) == identity(shim["key"]),
            "runtime-parent-foreign-shim")
    require(proof["shim"] == shim, "runtime-parent-stale-shim")
    require(runtime["origin"] in ("docker-runtime-path", "explicit-host-runc") and
            type(runtime["path"]) is str and runtime["path"].startswith("/") and
            runtime["path"].endswith("/runc") and proof["exe"] == runtime["path"],
            "unverified-runtime-executable")
    require(executable_identity(proof["exe_identity"]) == executable_identity(runtime["exe_identity"]) and
            executable_identity(proof["exe_identity_after"]) == executable_identity(runtime["exe_identity"]),
            "runtime-executable-mismatch")
    require(proof["pin"] == "procdir+pidfd" and proof["alive_after"] is True and
            executable_identity(proof["procdir_identity"]) == executable_identity(proof["procdir_identity_after"]),
            "unverified-runtime-parent-pin")
    require(number(row["read_started_at"]) <= number(proof["read_started_at"]) <=
            number(proof["read_finished_at"]) <= number(row["read_finished_at"]) <= now and
            now - number(proof["read_started_at"]) <= .200000001,
            "stale-runtime-parent-proof")
    runtime_exec_argv(proof["argv"], trace["container_id"])


def verified_file_bytes(value, *, host=False):
    before, after = value["stat_before"], value["stat_after"]
    require(type(before) is list and len(before) == 7 and before == after and
            all(type(x) is int and x >= 0 for x in before), "unstable-runtime-file")
    executable_identity(before[:2])
    require(before[2] & 0o170000 == 0o100000 and 0 < before[4] <= 67108864 and
            value["bytes_hashed"] == before[4], "incomplete-runtime-file")
    require(type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None,
            "invalid-runtime-digest")
    require(number(value["opened_at"]) <= number(value["read_started_at"]) <=
            number(value["read_finished_at"]), "invalid-runtime-file-clock")
    if host:
        require(before[3] == 0 and not before[2] & 0o022, "unsafe-host-runtime-binary")
    return before


def runtime_permissions(value, argv, previous=None):
    require(tuple(argv) == ("runc", "init"), "unverified-runtime-command")
    require(value["uids"] == value["gids"] == [0] * 4 and
            type(value["groups"]) is list and value["groups"] in ([], [0]), "unsafe-runtime-identity")
    require(type(value["nnp"]) is int and value["nnp"] in (0, 1) and
            type(value["caps"]) is dict and set(value["caps"]) == set(CAPS) and
            all(type(x) is int and x >= 0 for x in value["caps"].values()), "unknown-runtime-permissions")
    if previous is not None:
        require(tuple(previous["argv"]) != HEALTH, "health-reverted-to-runtime")
        require(tuple(previous["argv"]) == ("runc", "init") and previous["uids"] == [0] * 4,
                "runtime-reescalation")


def verified_runtime_executable(row, trace, now):
    runtime, proof = trace["runtime"], row["runtime_executable"]
    host, file = runtime["binary"], proof["file"]
    host_stat = verified_file_bytes(host, host=True)
    child_stat = verified_file_bytes(file)
    require(runtime["origin"] in ("docker-runtime-path", "explicit-host-runc") and
            type(runtime["path"]) is str and runtime["path"].startswith("/") and
            runtime["path"].endswith("/runc") and host_stat[:2] == runtime["exe_identity"] and
            number(host["read_finished_at"]) <= number(trace["begin"]), "unverified-host-runtime-pin")
    require(file["sha256"] == host["sha256"] and child_stat[4] == host_stat[4],
            "runtime-content-mismatch")
    key = identity(row["key"])
    require(proof["pin"] == "opened-current-exe" and
            identity(proof["key_before"]) == key == identity(proof["key_after"]) and
            executable_identity(proof["procdir_identity"]) ==
            executable_identity(row["binding"]["procdir_identity"]), "runtime-executable-identity-race")
    require(proof["cgroup_before"] == proof["cgroup_after"] == trace["cgroup"],
            "runtime-process-left-container-cgroup")
    require(number(row["read_started_at"]) <= number(file["opened_at"]) <=
            number(proof["snapshot_finished_at"]) == number(row["read_finished_at"]) <=
            number(file["read_started_at"]) <= number(file["read_finished_at"]) <= now,
            "stale-runtime-executable-proof")
    if "parent_retry" in row:
        retry = row["parent_retry"]
        require(retry["reason"] == "parent-ENOENT" and 1 <= len(retry["reads"]) <= 3 and
                number(row["read_started_at"]) <= number(retry["read_started_at"]) <=
                number(retry["read_finished_at"]) <= number(row["read_finished_at"]) and
                retry["read_finished_at"] - retry["read_started_at"] <= .050000001,
                "unbounded-runtime-parent-retry")
        for read in retry["reads"]:
            require(identity(read["key_before"]) == key == identity(read["key_after"]) and
                    read["exe_identity_before"] == read["exe_identity_after"] == child_stat[:2] and
                    read["cgroup_before"] == read["cgroup_after"] == trace["cgroup"] and
                    read["argv"] == ["runc", "init"] and
                    retry["read_started_at"] <= number(read["time"]) <= retry["read_finished_at"],
                    "unverified-runtime-parent-retry")


def bound_identity(binding, key, cgroup):
    require(binding["method"] == "procdir+pidfd" and
            identity(binding["key_before"]) == key == identity(binding["key_after"]) and
            executable_identity(binding["procdir_identity"]) == executable_identity(binding["procdir_identity_after"]) and
            binding["cgroup"] == cgroup, "unverified-process-binding")
    number(binding["bound_at"])


def terminal_permissions(value, previous):
    for field in ("uids", "gids"):
        require(type(value[field]) is list and len(value[field]) == 4 and
                all(type(x) is int and x >= 0 for x in value[field]), "unknown-terminal-permissions")
    require(type(value["groups"]) is list and all(type(x) is int and x >= 0 for x in value["groups"]),
            "unknown-terminal-permissions")
    require(type(value["caps"]) is dict and set(value["caps"]) == set(CAPS) and
            all(type(x) is int and x >= 0 for x in value["caps"].values()),
            "unknown-terminal-permissions")
    require(type(value["nnp"]) is int and value["nnp"] == 1, "terminal-no-new-privileges-required")
    uid = value["uids"][0]
    require(value["uids"] == [uid] * 4, "mixed-terminal-uids")
    previous_uid = previous["uids"][0]
    if uid == 0:
        require(previous_uid == 0 and value["gids"] in ([0] * 4, [51000] * 4) and
                set(value["groups"]) <= {0}, "unsafe-terminal-identity")
        caps = value["caps"]
        require(caps["inh"] == caps["amb"] == 0 and
                all(not caps[k] & ~BOOTSTRAP_CAPS for k in ("eff", "prm", "bnd")),
                "extra-terminal-capability")
    else:
        require((uid == previous_uid or (previous_uid == 0 and uid == 51000 and
                                         tuple(previous["argv"]) == HEALTH)) and
                value["gids"] == [uid] * 4 and value["groups"] == [] and
                not any(value["caps"].values()), "unsafe-terminal-identity")


def observed_permissions(value, argv, previous=None):
    cmd = tuple(argv)
    if cmd == SERVE:
        expected = 51000
    elif len(cmd) == 5 and cmd[:4] == WORKER and cmd[4] in ROLES:
        expected = ROLES[cmd[4]]
    else:
        require(cmd in (HEALTH, ("runc", "init")), "unknown-observed-command")
        expected = 0
    terminal_permissions(value, {"uids": [expected] * 4, "argv": cmd})
    if cmd == ("runc", "init"):
        require(value["uids"] == [0] * 4, "nonroot-runc-init")
    if previous is not None:
        prior_cmd = tuple(previous["argv"])
        require(not (prior_cmd == HEALTH and cmd == ("runc", "init")), "health-reverted-to-runtime")
        require(cmd == prior_cmd or (prior_cmd == ("runc", "init") and cmd == HEALTH),
                "observed-command-changed")
        permission_context = ({**previous, "argv": cmd}
                              if prior_cmd == ("runc", "init") and cmd == HEALTH else previous)
        terminal_permissions(value, permission_context)


def verified_exit(proof, previous, cgroup, now, last):
    key = identity(proof["key"])
    require(key == identity(previous["key"]) and proof["binding"] == previous["binding"],
            "exit-binding-mismatch")
    bound_identity(proof["binding"], key, cgroup)
    require(number(proof["binding"]["bound_at"]) <= number(previous["read_started_at"]) and
            last <= number(proof["read_started_at"]) <= number(proof["read_finished_at"]) <= now,
            "stale-exit-proof")
    for field in ("poll_before", "poll_after"):
        events = proof[field]
        require(type(events) is int and events & 1 and not events & (8 | 32),
                "original-pidfd-not-terminal")
    for field in ("cgroup_before", "cgroup_after"):
        if field in proof:
            require(proof[field] == cgroup, "terminal-process-left-container-cgroup")
    for field in ("key_before", "key_after"):
        if field in proof:
            require(identity(proof[field]) == key, "terminal-identity-changed")
    for field in ("state_before", "state_after"):
        if field in proof:
            require(proof[field] == "Z", "unverified-terminal-state")
    if "permissions" in proof:
        terminal_permissions(proof["permissions"], previous)
    kind = proof["kind"]
    if kind == "zombie":
        require(identity(proof["key_before"]) == key == identity(proof["key_after"]) and
                proof["state_before"] == proof["state_after"] == "Z",
                "unverified-terminal-state")
        require(executable_identity(proof["procdir_identity"]) ==
                executable_identity(proof["binding"]["procdir_identity"]), "terminal-procdir-reused")
        require(proof["cgroup_before"] == proof["cgroup_after"] == cgroup,
                "terminal-process-left-container-cgroup")
        require(proof["replacement_key"] is None, "unclassified-terminal-reuse")
        terminal_permissions(proof["permissions"], previous)
    else:
        require(kind == "reaped" and proof["proc_missing"] is True, "unverified-process-exit-kind")
        if proof["replacement_key"] is not None:
            replacement = identity(proof["replacement_key"])
            require(replacement[0] == key[0] and replacement != key, "unclassified-terminal-reuse")
    return key


def assess_legacy_trace(trace, *, admin_enabled=True):
    try:
        require(type(admin_enabled) is bool, "invalid-role-configuration")
        require(trace["collector_schema"] == "health-bootstrap-trace-v4", "unreviewed-collector-schema")
        cgroup = trace["cgroup"]
        require(type(cgroup) is str and cgroup.startswith("/") and cgroup != "/", "invalid-container-cgroup")
        cid = trace["container_id"]
        require(type(cid) is str and len(cid) == 64 and all(c in "0123456789abcdef" for c in cid), "invalid-container-id")
        require(any(part in (cid, "docker-" + cid + ".scope") for part in cgroup.split("/")),
                "cgroup-container-id-mismatch")
        require(trace["clock"] == "CLOCK_BOOTTIME" and trace["uid_namespace"] == "container", "unknown-clock-or-identity-namespace")
        hz = trace["ticks_per_second"]
        require(type(hz) is int and hz > 0, "invalid-clock")
        require(trace["health_interval"] == 30 and trace["health_timeout"] == 10, "unreviewed-health-configuration")
        begin, end = number(trace["begin"]), number(trace["end"])
        require(end - begin >= 60, "insufficient-observation-window")
        init = identity(trace["init"])
        samples = trace["samples"]
        require(type(samples) is list and samples, "empty-trace")
        previous, retired, health, fixed_roles, bindings = {}, set(), {}, None, {}
        shim_key, shim_profile = None, None
        last, root_samples = begin, 0
        expected = {k: v for k, v in ROLES.items() if admin_enabled or k != "admin"}
        for sample in samples:
            now = number(sample["time"])
            require(begin <= now <= end and 0 <= now - last <= .200000001, "sampling-gap-or-order")
            sample_previous_time = last
            last = now
            require(sample["complete"] is True, "incomplete-process-sample")
            shim = sample["shim"]
            current_shim = identity(shim["key"])
            argv = tuple(shim["argv"])
            require(shim["exe"] in ("/usr/bin/containerd-shim-runc-v2", "/usr/local/bin/containerd-shim-runc-v2") and
                    len(argv) == 7 and argv[0] == shim["exe"] and
                    argv[1:5] == ("-namespace", "moby", "-id", cid) and
                    argv[5] == "-address" and type(argv[6]) is str and bool(argv[6]), "unverified-container-shim")
            if shim_key is None:
                shim_key, shim_profile = current_shim, (shim["exe"], argv, executable_identity(shim["exe_identity"]))
            require(current_shim == shim_key and (shim["exe"], argv, executable_identity(shim["exe_identity"])) == shim_profile, "shim-identity-changed")
            require(init != shim_key, "invalid-gateway-shim-identity")
            rows = {}
            for row in sample["processes"]:
                key = identity(row["key"])
                require(key not in rows and key not in retired, "duplicate-or-retired-identity")
                require(key[1] / hz <= now, "process-born-after-sample")
                identity(row["parent"])
                for field in ("uids", "gids"):
                    require(type(row[field]) is list and len(row[field]) == 4 and
                            all(type(x) is int and x >= 0 for x in row[field]), "unknown-process-permissions")
                require(type(row["groups"]) in (list, tuple) and all(type(x) is int and x >= 0 for x in row["groups"]), "unknown-process-permissions")
                require(type(row["nnp"]) is int and row["nnp"] in (0, 1), "no-new-privileges-required")
                require(type(row["caps"]) is dict and set(row["caps"]) == set(CAPS) and
                        all(type(v) is int and v >= 0 for v in row["caps"].values()), "unknown-process-permissions")
                require(type(row["argv"]) in (list, tuple) and bool(row["argv"]) and
                        all(type(x) is str and x and "\0" not in x for x in row["argv"]), "unknown-process-command")
                if tuple(row["argv"]) == ("runc", "init"):
                    runtime_permissions(row, row["argv"], previous.get(key))
                    verified_runtime_executable(row, trace, now)
                else:
                    observed_permissions(row, row["argv"], previous.get(key))
                bound_identity(row["binding"], key, cgroup)
                require(number(row["binding"]["bound_at"]) <= number(row["read_started_at"]) <=
                        number(row["read_finished_at"]) <= now, "stale-process-binding")
                if key in bindings:
                    require(bindings[key] == row["binding"], "process-binding-changed")
                else:
                    bindings[key] = row["binding"]
                rows[key] = row
            pids = sample["pids"]
            require(shim_key not in rows, "shim-inside-container-process-set")
            require(type(pids) is list and all(type(p) is int and p > 0 for p in pids) and
                    len(set(pids)) == len(pids) == len(rows) and set(pids) == {k[0] for k in rows}, "process-enumeration-mismatch")
            exited = [identity(k) for k in sample["exited"]]
            require(len(set(exited)) == len(exited) and set(exited) == set(previous) - set(rows), "unverified-process-exit")
            proofs = sample["exit_proofs"]
            require(type(proofs) is list and len(proofs) == len(exited), "missing-exit-proof")
            proof_keys = []
            for proof in proofs:
                proof_key = identity(proof["key"])
                require(proof_key in previous, "exit-without-prior-identity")
                proof_keys.append(verified_exit(proof, previous[proof_key], cgroup, now, sample_previous_time))
                replacement = proof.get("replacement_key")
                if replacement is not None:
                    require(identity(replacement) in rows and
                            {"kind": "verified-pid-reuse", "key": list(proof_key),
                             "replacement_key": replacement} in sample["races"], "silent-pid-reuse")
            require(len(set(proof_keys)) == len(proof_keys) and set(proof_keys) == set(exited),
                    "exit-proof-enumeration-mismatch")
            for key in exited:
                retired.add(key)
                if key in health and health[key]["root"] and not health[key]["closed"]:
                    require(health[key]["seen_health"], "runc-exit-without-health-proof")
                    require(now - key[1] / hz <= 10, "bootstrap-exceeded-health-timeout")
                    health[key]["closed"] = True
            require(init in rows and identity(rows[init]["parent"]) == shim_key and
                    tuple(rows[init]["argv"]) == SERVE and rows[init]["uids"] == [51000] * 4,
                    "missing-or-changed-gateway")
            current_roles = {}
            for role, uid in expected.items():
                matches = [k for k, r in rows.items() if r["uids"] == [uid] * 4 and
                           identity(r["parent"]) == init and tuple(r["argv"]) == WORKER + (role,)]
                require(len(matches) == 1, "missing-or-duplicate-role")
                current_roles[role] = matches[0]
            if fixed_roles is None:
                fixed_roles = current_roles
            require(current_roles == fixed_roles, "role-identity-changed")
            role_uids = {init: 51000, **{key: expected[role] for role, key in current_roles.items()}}
            for key, row in rows.items():
                uid = row["uids"][0]
                require(all(u == uid for u in row["uids"]), "mixed-process-uids")
                parent, cmd, caps = identity(row["parent"]), tuple(row["argv"]), row["caps"]
                if uid == 0:
                    root_samples += 1
                    require(key not in role_uids, "root-in-role-tree")
                    if parent != shim_key:
                        require(cmd == ("runc", "init"), "root-in-role-tree")
                        verified_runtime_parent(row, trace, shim, rows, now)
                    require(cmd in (HEALTH, ("runc", "init")), "unknown-root-command")
                    if cmd != ("runc", "init"):
                        require(row["gids"] in ([0] * 4, [51000] * 4) and set(row["groups"]) <= {0}, "unsafe-bootstrap-groups")
                        require(caps["inh"] == caps["amb"] == 0 and
                                all(not caps[k] & ~BOOTSTRAP_CAPS for k in ("eff", "prm", "bnd")), "extra-bootstrap-capability")
                else:
                    require(uid in role_uids.values() and row["gids"] == [uid] * 4 and
                            row["groups"] == [], "unknown-process-identity")
                    require(not any(caps.values()), "privileged-long-lived-process")
                    if parent != shim_key:
                        ancestor, visited = key, set()
                        while ancestor not in role_uids:
                            require(ancestor in rows and ancestor not in visited and rows[ancestor]["uids"] == [uid] * 4, "unknown-role-ancestry")
                            visited.add(ancestor)
                            ancestor = identity(rows[ancestor]["parent"])
                        require(role_uids[ancestor] == uid, "foreign-role-ancestry")
                if (parent == shim_key or uid == 0) and key != init:
                    require(uid in (0, 51000) and (cmd == HEALTH or (uid == 0 and cmd == ("runc", "init"))), "unknown-shim-child")
                    state = health.setdefault(key, {"root": False, "demoted": False, "closed": False, "seen_health": False})
                    require(not (uid == 0 and state["demoted"]), "root-reescalation")
                    require(not (state["seen_health"] and cmd == ("runc", "init")), "health-reverted-to-runtime")
                    state["seen_health"] |= parent == shim_key and cmd == HEALTH
                    if uid == 0:
                        require(now - key[1] / hz <= 10, "bootstrap-exceeded-health-timeout")
                        state["root"] = True
                    else:
                        if state["root"] and not state["closed"]:
                            require(now - key[1] / hz <= 10, "bootstrap-exceeded-health-timeout")
                        state["demoted"], state["closed"] = True, True
            previous = rows
        require(0 <= end - last <= .200000001, "sampling-tail-gap")
        require(all(not state["root"] or state["closed"] for state in health.values()), "unsettled-bootstrap-at-trace-end")
        return {"passed": True, "reason": "profile-observed", "samples": len(samples), "root_samples": root_samples}
    except InvalidProfile as error:
        return {"passed": False, "reason": error.args[0]}
    except (KeyError, TypeError, ValueError, IndexError, OverflowError):
        return {"passed": False, "reason": "invalid-trace-schema"}


def namespace_identity(value):
    require(type(value) is list and len(value) == 2 and
            all(type(item) is int and item > 0 for item in value), "invalid-namespace-identity")
    return tuple(value)


def namespace_mount(value):
    namespace_identity(value["identity"])
    require(value["magic"] == 0x9fa0 and type(value["mount_id"]) is int and value["mount_id"] > 0 and
            value["root"] == "/" and value["mountpoint"] == "/proc" and value["fstype"] == "proc" and
            value["hidepid"] == 0 and value["subset"] == "all" and
            type(value["mount_row_sha256"]) is str and len(value["mount_row_sha256"]) == 64 and
            all(ch in "0123456789abcdef" for ch in value["mount_row_sha256"]),
            "unbound-namespace-procfs-mount")


def assess_namespace_scope(trace):
    require(trace["collector_schema"] == "health-bootstrap-trace-v5", "mandatory-namespace-scope-missing")
    header = trace["scope"]
    require(header["method"] == "procfs-nsfs-pidfd-v1" and header["max_capture_passes"] == 2 and
            header["snapshot_budget_seconds"] == .2, "unreviewed-namespace-scope-method")
    init, observer = identity(header["init"]), identity(header["observer"])
    require(init == identity(trace["init"]) and observer != init, "namespace-init-or-observer-unbound")
    host = namespace_identity(header["observer_namespace"])
    own = namespace_identity(header["container_namespace"])
    require(host != own and namespace_identity(header["container_parent_namespace"]) == host and
            namespace_identity(header["host_proc_pid1_namespace"]) == host and
            type(header["host_proc_pid1"]) is list and len(header["host_proc_pid1"]) == 2 and
            header["host_proc_pid1"][0] == 1 and type(header["host_proc_pid1"][1]) is int and
            header["host_proc_pid1"][1] >= 0, "namespace-authority-unbound")
    namespace_mount(header["host_proc"])
    namespace_mount(header["container_proc"])
    expected_authority = {"observer": list(observer), "init": list(init),
                          "observer_namespace": list(host), "container_namespace": list(own),
                          "host_proc_pid1_namespace": list(host), "host_proc_pid1": header["host_proc_pid1"],
                          "host_proc_self_pid": observer[0], "host_proc": header["host_proc"],
                          "container_proc": header["container_proc"], "pid1_host": init[0], "init_local_pid": 1}
    seen_inside, seen_outside = set(), set()
    for sample in trace["samples"]:
        proof = sample["scope"]
        begin, end = number(sample["read_started_at"]), number(sample["time"])
        require(0 <= end - begin <= .200000001 and proof["closed"] is True,
                "namespace-snapshot-budget-or-closure")
        count = proof["capture_passes"]
        inventories = proof["inventories"]
        require(type(count) is int and 0 <= count <= 2 and type(inventories) is list and
                len(inventories) == count + 2, "unbounded-namespace-discovery")
        all_mappings, observed_keys = {}, set()
        exits = {identity(row["key"]) for row in sample["exit_proofs"]}
        exit_pids = {key[0] for key in exits}
        for index, inventory in enumerate(inventories):
            require(inventory["complete"] is True and inventory["failures"] == [] and
                    inventory["authority_before"] == inventory["authority_after"] == expected_authority,
                    "namespace-inventory-authority-or-read-failed")
            start, finish = number(inventory["read_started_at"]), number(inventory["read_finished_at"])
            require(begin <= start <= finish <= end, "namespace-inventory-time-unbound")
            raw, visible = inventory["cgroup_pids"], inventory["visible_pids"]
            for pids in (raw, visible, inventory["end_cgroup_pids"], inventory["end_visible_pids"]):
                require(type(pids) is list and pids == sorted(set(pids)) and
                        all(type(pid) is int and pid > 0 for pid in pids), "invalid-namespace-inventory")
            require(visible and visible[0] == 1, "container-proc-pid1-missing")
            mapped, local_ids, excluded = {}, set(), set()
            for item in inventory["mappings"]:
                key = identity(item["key"])
                local = item["local_pid"]
                require(type(local) is int and local > 0 and local not in local_ids and key[0] not in mapped and
                        item["from_namespace"] == key[0] and item["in_namespace"] == local and
                        namespace_identity(item["active_namespace"]) != host and key not in seen_outside,
                        "inside-namespace-mapping-unbound")
                require(namespace_identity(item["procdir_identity"]) ==
                        namespace_identity(item["procdir_identity_after"]), "inside-procdir-identity-race")
                bound_identity(item["binding"], key, trace["cgroup"])
                require(number(item["binding"]["bound_at"]) <= number(item["verified_at"]) <= finish,
                        "namespace-mapping-binding-time")
                if local == 1:
                    require(key == init and namespace_identity(item["active_namespace"]) == own,
                            "container-proc-pid1-map-mismatch")
                if key in all_mappings:
                    require(all_mappings[key] == (local, item["binding"], item["active_namespace"]),
                            "namespace-mapping-changed")
                all_mappings[key] = (local, item["binding"], item["active_namespace"])
                mapped[key[0]] = key
                local_ids.add(local)
                seen_inside.add(key)
            require(set(visible) <= local_ids and 1 in local_ids, "visible-container-process-unmapped")
            for item in inventory["excluded"]:
                key = identity(item["key"])
                bound_identity(item["binding"], key, trace["cgroup"])
                require(namespace_identity(item["active_namespace_before"]) == host ==
                        namespace_identity(item["active_namespace_after"]) and
                        item["pidfd_alive_before"] is True and item["pidfd_alive_after"] is True and
                        item["method"] == "held-active-host-pidns-v1" and
                        key not in seen_inside and key[0] not in mapped and key[0] not in excluded and
                        key[1] / trace["ticks_per_second"] <= number(item["read_started_at"]) and
                        start <= number(item["read_started_at"]) <= number(item["read_finished_at"]) <= finish and
                        number(item["binding"]["bound_at"]) <= number(item["read_started_at"]),
                        "unproven-cgroup-only-host-exclusion")
                excluded.add(key[0])
                seen_outside.add(key)
            vanished = inventory.get("vanished", [])
            require(type(vanished) is list, "unproven-vanished-cgroup-process")
            vanished_pids = set()
            for item in vanished:
                pid = item.get("pid") if type(item) is dict else None
                at = item.get("verified_absent_at") if type(item) is dict else None
                require(type(pid) is int and pid in raw and pid not in mapped and pid not in excluded and
                        pid not in inventory["end_cgroup_pids"] and pid not in vanished_pids and
                        pid in exit_pids and item.get("stage") == "classify-host" and
                        item.get("error") in ("FileNotFoundError", "ProcessLookupError") and
                        type(at) in (int, float) and math.isfinite(at) and start <= at <= finish,
                        "unproven-vanished-cgroup-process")
                vanished_pids.add(pid)
            if index == len(inventories) - 1:
                require(vanished == [], "unproven-vanished-cgroup-process")
            require(set(raw) <= set(mapped) | excluded | vanished_pids and excluded <= set(raw),
                    "cgroup-process-unclassified")
            keys = set(mapped.values()) | {identity(item["key"]) for item in inventory["excluded"]}
            if index == len(inventories) - 1:
                require(inventory["stable"] is True and raw == inventory["end_cgroup_pids"] and
                        visible == inventory["end_visible_pids"] and keys <= observed_keys,
                        "namespace-final-membership-not-closed")
                require(set(mapped) == set(sample["pids"]), "namespace-final-profile-membership-mismatch")
            observed_keys.update(keys)
        observations = proof["observed_processes"]
        require(type(observations) is list and type(proof["observed_failures"]) is list,
                "namespace-observation-union-missing")
        observation_keys = [identity(row["key"]) for row in observations]
        require(len(observation_keys) == len(set(observation_keys)), "duplicate-namespace-observation")
        for row in observations:
            key = identity(row["key"])
            require(key in all_mappings and row["binding"] == all_mappings[key][1] and
                    begin <= number(row["read_started_at"]) <= number(row["read_finished_at"]) <= end,
                    "namespace-full-observation-unbound")
        for failure in proof["observed_failures"]:
            require(failure.get("pid") in exit_pids and
                    failure.get("reason") in ("proc-read-or-schema-failed", "empty-process-command") and
                    any(race.get("kind") == "verified-known-exit-during-snapshot" and
                        identity(race["key"])[0] == failure["pid"] for race in sample["races"]),
                    "unresolved-earlier-namespace-observation-failure")
        require(set(observation_keys) <= {identity(row["key"]) for row in sample["processes"]} | exits,
                "discarded-earlier-namespace-observation")
        require(set(all_mappings) <= set(observation_keys) | exits,
                "inside-process-without-full-observation-or-existing-exit-proof")
        for row in sample["processes"]:
            require(row in observations, "namespace-profile-row-not-in-observed-union")


def assess_trace(trace, *, admin_enabled=True, require_scope=False):
    try:
        require(type(require_scope) is bool, "invalid-namespace-scope-configuration")
        if require_scope or trace.get("collector_schema") == "health-bootstrap-trace-v5":
            assess_namespace_scope(trace)
            profile = dict(trace)
            profile["collector_schema"] = "health-bootstrap-trace-v4"
            return assess_legacy_trace(profile, admin_enabled=admin_enabled)
        return assess_legacy_trace(trace, admin_enabled=admin_enabled)
    except InvalidProfile as error:
        return {"passed": False, "reason": error.args[0]}
    except (KeyError, TypeError, ValueError, IndexError, OverflowError):
        return {"passed": False, "reason": "invalid-namespace-trace-schema"}


