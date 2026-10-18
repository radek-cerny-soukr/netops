import copy
import unittest
from unittest import mock
from types import SimpleNamespace
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from health_bootstrap_profile import assess_trace as assess_observed_trace, observed_permissions, InvalidProfile
import collect_health_bootstrap_trace as collector


CID = "a" * 64
SHIM = [90, 900]
INIT = [100, 1000]
HEALTH = ["/usr/local/bin/python", "/usr/local/bin/netops", "health"]


def process(pid, birth, uid, argv, parent):
    return {"key": [pid, birth], "parent": list(parent), "uids": [uid] * 4,
            "gids": [uid] * 4, "groups": [], "nnp": 1,
            "caps": dict.fromkeys(("inh", "prm", "eff", "bnd", "amb"), 0), "argv": list(argv)}


def root_health(pid=200, birth=10100, argv=None):
    row = process(pid, birth, 0, HEALTH if argv is None else argv, SHIM)
    row["caps"].update(eff=0x1CB, prm=0x1CB, bnd=0x1CB)
    return row


def fixture():
    rows = [process(100, 1000, 51000, ["/usr/local/bin/python", "/usr/local/bin/netops", "serve"], SHIM)]
    for pid, role, uid in ((101, "helper", 51001), (102, "auditor", 51002), (103, "admin", 51003)):
        rows.append(process(pid, 1000, uid, ["/usr/local/bin/python", "-m", "netops", "worker", role], INIT))
    shim = {"key": SHIM, "exe_identity": [8, 1001], "exe": "/usr/bin/containerd-shim-runc-v2",
            "argv": ["/usr/bin/containerd-shim-runc-v2", "-namespace", "moby", "-id", CID, "-address", "/run/containerd/containerd.sock"]}
    return {"runtime": runtime_fixture(), "container_id": CID, "clock": "CLOCK_BOOTTIME", "uid_namespace": "container",
            "ticks_per_second": 100, "health_interval": 30, "health_timeout": 10,
            "begin": 100.0, "end": 185.0, "init": INIT,
            "samples": [{"time": 100 + i / 10, "complete": True, "shim": copy.deepcopy(shim),
                         "pids": [100, 101, 102, 103], "processes": copy.deepcopy(rows), "exited": []}
                        for i in range(851)]}


def insert(trace, first, last, row, *, exited=False):
    for sample in trace["samples"][first:last]:
        sample["processes"].append(copy.deepcopy(row))
        sample["pids"].append(row["key"][0])
    if exited:
        trace["samples"][last]["exited"].append(list(row["key"]))


def runtime_file_fixture(opened=99.0, *, device=8):
    info = [device, 1002, 0o100755, 0, 32, 1000000000, 1000000000]
    return {"stat_before": list(info), "stat_after": list(info), "opened_at": opened,
            "read_started_at": opened, "read_finished_at": opened,
            "sha256": "d" * 64, "bytes_hashed": 32}


def runtime_fixture():
    return {"path": "/usr/bin/runc", "exe_identity": [8, 1002], "origin": "explicit-host-runc",
            "docker_runtime": "runc", "docker_configured_path": "", "docker_runtime_type": "io.containerd.runc.v2",
            "binary": runtime_file_fixture()}


def runtime_executable_fixture(row, cgroup):
    file = runtime_file_fixture(row["read_finished_at"], device=88)
    file.update(opened_at=row["read_started_at"], method="bytes-equal-to-verified-reference")
    return {"pin": "opened-current-exe", "key_before": list(row["key"]), "key_after": list(row["key"]),
            "procdir_identity": list(row["binding"]["procdir_identity"]),
            "cgroup_before": cgroup, "cgroup_after": cgroup,
            "snapshot_finished_at": row["read_finished_at"], "file": file}


def observed_fixture(trace):
    trace = copy.deepcopy(trace)
    trace["collector_schema"] = "health-bootstrap-trace-v4"
    trace["cgroup"] = "/qa/docker-" + CID + ".scope"
    if "runtime" in trace:
        trace["runtime"].setdefault("binary", runtime_file_fixture())
    bindings, previous = {}, {}
    for sample in trace["samples"]:
        sample.setdefault("races", [])
        for row in sample["processes"]:
            key = tuple(row["key"])
            row.setdefault("read_started_at", sample["time"])
            row.setdefault("read_finished_at", sample["time"])
            if key not in bindings:
                inode = key[0] * 1000000 + key[1]
                bindings[key] = {"method": "procdir+pidfd", "key_before": list(key), "key_after": list(key),
                                 "procdir_identity": [9, inode], "procdir_identity_after": [9, inode],
                                 "cgroup": trace["cgroup"], "bound_at": row["read_started_at"]}
            row["binding"] = copy.deepcopy(bindings[key])
            if tuple(row["argv"]) == ("runc", "init"):
                row.setdefault("runtime_executable", runtime_executable_fixture(row, trace["cgroup"]))
        current = {tuple(row["key"]): row for row in sample["processes"]}
        sample["exit_proofs"] = []
        for key_list in sample["exited"]:
            key = tuple(key_list)
            if key not in previous:
                continue
            replacement = next((list(k) for k in current if k[0] == key[0] and k != key), None)
            sample["exit_proofs"].append({"kind": "reaped", "key": list(key), "proc_missing": True,
                                          "binding": copy.deepcopy(previous[key]["binding"]),
                                          "poll_before": 17, "poll_after": 17, "replacement_key": replacement,
                                          "read_started_at": sample["time"], "read_finished_at": sample["time"]})
            if replacement is not None:
                sample["races"].append({"kind": "verified-pid-reuse", "key": list(key), "replacement_key": replacement})
        previous = current
    return trace


def assess_trace(trace):
    return assess_observed_trace(observed_fixture(trace))


class HealthBootstrapProfileControls(unittest.TestCase):
    def reject(self, trace):
        self.assertIs(assess_trace(trace)["passed"], False)

    def test_pure_steady_roles(self):
        trace = fixture()
        original = copy.deepcopy(trace)
        self.assertTrue(assess_trace(trace)["passed"])
        self.assertEqual(trace, original)

    def test_runc_same_identity_demotes_then_exits(self):
        trace = fixture()
        insert(trace, 10, 13, root_health(argv=["runc", "init"]))
        insert(trace, 13, 17, process(200, 10100, 51000, HEALTH, SHIM))
        trace["samples"][17]["exited"] = [[200, 10100]]
        self.assertTrue(assess_trace(trace)["passed"])

    def test_exact_health_can_exit_without_observed_demote(self):
        trace = fixture()
        insert(trace, 10, 17, root_health())
        trace["samples"][17]["exited"] = [[200, 10100]]
        self.assertTrue(assess_trace(trace)["passed"])

    def test_gid_transition_and_legitimate_pid_reuse_keep_distinct_identities(self):
        trace = fixture()
        row = root_health()
        row["gids"] = [51000] * 4
        insert(trace, 10, 12, row)
        trace["samples"][12]["exited"] = [[200, 10100]]
        insert(trace, 13, 15, root_health(birth=10130))
        trace["samples"][15]["exited"] = [[200, 10130]]
        self.assertTrue(assess_trace(trace)["passed"])

    def test_nonexistent_or_unreadable_root_is_not_discarded(self):
        trace = fixture()
        insert(trace, 10, 11, root_health(), exited=True)
        trace["samples"][10]["pids"].remove(200)
        self.reject(trace)
        trace = fixture()
        trace["samples"][10]["complete"] = False
        self.reject(trace)
        trace = fixture()
        del trace["samples"][10]["processes"][0]["caps"]["prm"]
        self.reject(trace)

    def test_persistent_and_already_old_health_root(self):
        trace = fixture()
        insert(trace, 10, 122, root_health())
        trace["samples"][122]["exited"] = [[200, 10100]]
        self.reject(trace)
        trace = fixture()
        insert(trace, 0, 2, root_health(birth=8000))
        trace["samples"][2]["exited"] = [[200, 8000]]
        self.reject(trace)

    def test_pid1_root_and_role_tree_root(self):
        trace = fixture()
        trace["samples"][10]["processes"][0]["uids"] = [0] * 4
        self.reject(trace)
        trace = fixture()
        row = root_health()
        row["parent"] = [101, 1000]
        insert(trace, 10, 11, row, exited=True)
        self.reject(trace)
        trace = fixture()
        row = trace["samples"][10]["processes"][0]
        row["uids"], row["gids"] = [51001] * 4, [51001] * 4
        self.reject(trace)

    def test_extra_capabilities_and_nnp_zero(self):
        for field in ("eff", "prm", "bnd", "inh", "amb"):
            trace = fixture()
            row = root_health()
            row["caps"][field] |= 1 << 21
            insert(trace, 10, 11, row, exited=True)
            self.reject(trace)
        for index in range(4):
            trace = fixture()
            trace["samples"][10]["processes"][index]["nnp"] = 0
            self.reject(trace)
        trace = fixture()
        row = root_health()
        row["nnp"] = 0
        insert(trace, 10, 11, row, exited=True)
        self.reject(trace)

    def test_demoted_health_cannot_reescalate(self):
        trace = fixture()
        insert(trace, 10, 11, root_health())
        insert(trace, 11, 12, process(200, 10100, 51000, HEALTH, SHIM))
        insert(trace, 12, 13, root_health(), exited=True)
        self.reject(trace)

    def test_missing_roles_empty_trace_and_sampling_gap(self):
        trace = fixture()
        for sample in trace["samples"][10:]:
            sample["processes"].pop()
            sample["pids"].pop()
        trace["samples"][10]["exited"] = [[103, 1000]]
        self.reject(trace)
        trace = fixture()
        trace["samples"] = []
        self.reject(trace)
        trace = fixture()
        del trace["samples"][20:23]
        self.reject(trace)

    def test_wrong_parent_command_or_container_shim(self):
        for parent, argv in (([91, 900], HEALTH), (SHIM, HEALTH + ["extra"]), (SHIM, ["sh", "-c", "netops health"])):
            trace = fixture()
            row = root_health(argv=argv)
            row["parent"] = parent
            insert(trace, 10, 11, row, exited=True)
            self.reject(trace)
        trace = fixture()
        trace["samples"][10]["shim"]["argv"][4] = "b" * 64
        self.reject(trace)

    def test_pid_reuse_cannot_close_previous_root_identity(self):
        trace = fixture()
        insert(trace, 10, 11, root_health(argv=["runc", "init"]))
        insert(trace, 11, 12, process(200, 10110, 51000, HEALTH, SHIM))
        trace["samples"][11]["exited"] = [[200, 10100]]
        self.reject(trace)

    def test_runc_only_exit_and_unverified_or_open_exit_fail(self):
        trace = fixture()
        insert(trace, 10, 11, root_health(argv=["runc", "init"]))
        trace["samples"][11]["exited"] = [[200, 10100]]
        self.reject(trace)
        trace = fixture()
        insert(trace, 10, 11, root_health())
        self.reject(trace)
        trace = fixture()
        insert(trace, 840, 851, root_health(birth=18400))
        self.reject(trace)

    def test_permanent_role_profile_is_checked_after_first_sample(self):
        for index in range(4):
            for field, value in (("groups", [999]), ("gids", [0] * 4)):
                trace = fixture()
                trace["samples"][700]["processes"][index][field] = value
                self.reject(trace)
            trace = fixture()
            trace["samples"][700]["processes"][index]["caps"]["bnd"] = 1
            self.reject(trace)


PARENT = [95, 10099]


def external_fixture():
    trace = fixture()
    trace["runtime"] = {"path": "/usr/bin/runc", "exe_identity": [8, 1002],
                        "origin": "explicit-host-runc", "docker_runtime": "runc",
                        "docker_configured_path": "", "docker_runtime_type": "io.containerd.runc.v2"}
    argv = ["runc", "--root", "/var/run/docker/runtime-runc/moby", "--log",
            "/run/containerd/io.containerd.runtime.v2.task/moby/" + CID + "/log.json",
            "--log-format", "json", "--systemd-cgroup", "exec", "--process",
            "/tmp/runc-process484860385", "--detach", "--pid-file",
            "/run/containerd/io.containerd.runtime.v2.task/moby/" + CID + "/" + "c" * 64 + ".pid", CID]
    row = root_health(argv=["runc", "init"])
    row["parent"] = list(PARENT)
    row["read_started_at"], row["read_finished_at"] = 101.08, 101.095
    row["runtime_parent"] = {
        "key": list(PARENT), "key_after": list(PARENT),
        "parent": list(SHIM), "parent_after": list(SHIM),
        "exe": "/usr/bin/runc", "exe_identity": [8, 1002], "exe_identity_after": [8, 1002],
        "argv": argv, "shim": copy.deepcopy(trace["samples"][11]["shim"]),
        "pin": "procdir+pidfd", "alive_after": True,
        "procdir_identity": [9, 2020], "procdir_identity_after": [9, 2020],
        "read_started_at": 101.081, "read_finished_at": 101.09}
    insert(trace, 11, 12, row)
    insert(trace, 12, 13, root_health(argv=["runc", "init"]))
    insert(trace, 13, 15, root_health())
    insert(trace, 15, 17, process(200, 10100, 51000, HEALTH, SHIM))
    trace["samples"][17]["exited"] = [[200, 10100]]
    return trace


def external_row(trace):
    return trace["samples"][11]["processes"][-1]


class ExternalRuntimeParentControls(unittest.TestCase):
    def reject(self, trace, reason=None):
        actual = assess_trace(trace)
        self.assertIs(actual["passed"], False)
        if reason is not None:
            self.assertEqual(actual["reason"], reason)

    def test_actual_external_runc_then_shim_init_health_demote_exit(self):
        trace = external_fixture()
        original = copy.deepcopy(trace)
        self.assertTrue(assess_trace(trace)["passed"])
        self.assertEqual(trace, original)

    def test_external_origin_can_exit_only_after_same_identity_health(self):
        trace = external_fixture()
        for sample in trace["samples"][15:17]:
            sample["processes"].pop()
            sample["pids"].pop()
        trace["samples"][15]["exited"] = [[200, 10100]]
        trace["samples"][17]["exited"] = []
        self.assertTrue(assess_trace(trace)["passed"])

    def test_foreign_or_prefix_cid_and_extra_argv_are_rejected(self):
        for index, value in ((14, "b" * 64), (14, CID[:12]),
                             (4, "/run/containerd/io.containerd.runtime.v2.task/moby/" + "b" * 64 + "/log.json"),
                             (13, "/run/containerd/io.containerd.runtime.v2.task/moby/" + "b" * 64 + "/" + "c" * 64 + ".pid"),
                             (8, "run"), (10, "/tmp/foreign-process1")):
            with self.subTest(index=index, value=value):
                trace = external_fixture()
                external_row(trace)["runtime_parent"]["argv"][index] = value
                self.reject(trace, "unverified-runtime-command")
        trace = external_fixture()
        external_row(trace)["runtime_parent"]["argv"].append("--extra")
        self.reject(trace, "unverified-runtime-command")

    def test_foreign_runtime_exe_device_inode_are_rejected(self):
        for field, value in (("exe", "/tmp/runc"), ("exe_identity", [8, 9999]),
                             ("exe_identity", [88, 1002]), ("exe_identity_after", [8, 9999])):
            with self.subTest(field=field, value=value):
                trace = external_fixture()
                external_row(trace)["runtime_parent"][field] = value
                self.reject(trace)
        trace = external_fixture()
        trace["runtime"]["origin"] = "argv-only"
        self.reject(trace)

    def test_missing_parent_or_runtime_corroboration_is_rejected(self):
        for field in ("runtime_parent", "parent"):
            trace = external_fixture()
            del external_row(trace)[field]
            self.reject(trace)
        trace = external_fixture()
        del trace["runtime"]
        self.reject(trace)
        for field in ("key_after", "shim", "argv", "exe_identity_after", "alive_after"):
            trace = external_fixture()
            del external_row(trace)["runtime_parent"][field]
            self.reject(trace)

    def test_stale_reused_parent_and_shim_are_rejected(self):
        for field in ("key", "key_after", "parent", "parent_after"):
            trace = external_fixture()
            external_row(trace)["runtime_parent"][field][1] += 1
            self.reject(trace)
        trace = external_fixture()
        external_row(trace)["parent"][1] += 1
        self.reject(trace)
        trace = external_fixture()
        external_row(trace)["runtime_parent"]["shim"]["key"][1] += 1
        self.reject(trace)
        trace = external_fixture()
        external_row(trace)["runtime_parent"]["shim"]["exe_identity"][1] += 1
        self.reject(trace)
        trace = external_fixture()
        external_row(trace)["parent"] = [90, 10099]
        external_row(trace)["runtime_parent"]["key"] = [90, 10099]
        external_row(trace)["runtime_parent"]["key_after"] = [90, 10099]
        self.reject(trace)

    def test_unpinned_exited_or_old_parent_proof_is_rejected(self):
        for field, value in (("pin", "procdir"), ("alive_after", False),
                             ("procdir_identity_after", [9, 2021]),
                             ("read_started_at", 100.8), ("read_finished_at", 102.0)):
            trace = external_fixture()
            external_row(trace)["runtime_parent"][field] = value
            self.reject(trace)

    def test_external_parent_must_be_outside_container_role_tree(self):
        trace = external_fixture()
        row = external_row(trace)
        row["parent"] = [101, 1000]
        row["runtime_parent"]["key"] = [101, 1000]
        row["runtime_parent"]["key_after"] = [101, 1000]
        self.reject(trace, "runtime-parent-not-external")

    def test_python_health_with_external_parent_is_rejected(self):
        trace = external_fixture()
        external_row(trace)["argv"] = list(HEALTH)
        self.reject(trace, "root-in-role-tree")

    def test_external_init_without_later_actual_health_is_rejected(self):
        trace = external_fixture()
        for sample in trace["samples"][13:17]:
            sample["processes"].pop()
            sample["pids"].pop()
        trace["samples"][13]["exited"] = [[200, 10100]]
        trace["samples"][17]["exited"] = []
        self.reject(trace, "runc-exit-without-health-proof")
        trace = external_fixture()
        for sample in trace["samples"][13:17]:
            sample["processes"][-1]["key"][1] = 10130
        trace["samples"][13]["exited"] = [[200, 10100]]
        trace["samples"][17]["exited"] = [[200, 10130]]
        self.reject(trace)

    def test_external_bootstrap_cannot_remain_root_beyond_kernel_ten_seconds(self):
        trace = external_fixture()
        for sample in trace["samples"][15:17]:
            sample["processes"].pop()
            sample["pids"].pop()
        trace["samples"][17]["exited"] = []
        insert(trace, 15, 113, root_health())
        trace["samples"][113]["exited"] = [[200, 10100]]
        self.reject(trace, "bootstrap-exceeded-health-timeout")

    def test_external_phase_keeps_all_permission_invariants(self):
        for field, value in (("uids", [0, 0, 1, 0]), ("gids", [0, 0, 1, 0]),
                             ("groups", [51000])):
            trace = external_fixture()
            external_row(trace)[field] = value
            self.reject(trace)
        trace = external_fixture()
        trace["samples"][13]["processes"][-1]["nnp"] = 0
        self.reject(trace)
        for field in ("inh", "prm", "eff", "bnd", "amb"):
            trace = external_fixture()
            trace["samples"][13]["processes"][-1]["caps"][field] |= 1 << 21
            self.reject(trace)

    def test_health_cannot_revert_to_runc_init(self):
        trace = external_fixture()
        trace["samples"][14]["processes"][-1]["argv"] = ["runc", "init"]
        self.reject(trace, "health-reverted-to-runtime")

    def test_nonidentity_user_namespace_is_not_supported(self):
        trace = external_fixture()
        trace["uid_namespace"] = "host-mapped"
        self.reject(trace)


def zombie_fixture():
    trace = observed_fixture(external_fixture())
    row = trace["samples"][16]["processes"][-1]
    proof = trace["samples"][17]["exit_proofs"][0]
    proof.update(kind="zombie", key_before=list(row["key"]), key_after=list(row["key"]),
                 state_before="Z", state_after="Z", cgroup_before=trace["cgroup"], cgroup_after=trace["cgroup"],
                 procdir_identity=copy.deepcopy(row["binding"]["procdir_identity"]),
                 permissions={key: copy.deepcopy(row[key]) for key in ("uids", "gids", "groups", "nnp", "caps")})
    del proof["proc_missing"]
    return trace


class PinnedTerminalExitControls(unittest.TestCase):
    def reject(self, trace, reason=None):
        actual = assess_observed_trace(trace)
        self.assertIs(actual["passed"], False)
        if reason is not None:
            self.assertEqual(actual["reason"], reason)

    def test_known_same_identity_zombie_with_original_terminal_pidfd(self):
        trace = zombie_fixture()
        original = copy.deepcopy(trace)
        self.assertTrue(assess_observed_trace(trace)["passed"])
        self.assertEqual(trace, original)

    def test_fully_reaped_original_and_partial_z_read_then_reaped(self):
        self.assertTrue(assess_observed_trace(observed_fixture(external_fixture()))["passed"])
        trace = zombie_fixture()
        proof = trace["samples"][17]["exit_proofs"][0]
        proof.update(kind="reaped", proc_missing=True)
        for key in ("key_after", "state_after", "cgroup_after", "procdir_identity"):
            del proof[key]
        self.assertTrue(assess_observed_trace(trace)["passed"])

    def test_live_moved_out_process_remains_fail(self):
        trace = zombie_fixture()
        proof = trace["samples"][17]["exit_proofs"][0]
        proof.update(state_before="S", state_after="S", poll_before=0, poll_after=0,
                     cgroup_before="/foreign", cgroup_after="/foreign")
        self.reject(trace, "original-pidfd-not-terminal")

    def test_z_without_group_terminal_pidfd_is_not_exit(self):
        for events in (0, 16, 8, 32, 9, 33):
            trace = zombie_fixture()
            trace["samples"][17]["exit_proofs"][0]["poll_after"] = events
            self.reject(trace, "original-pidfd-not-terminal")
        trace = zombie_fixture()
        trace["samples"][17]["exit_proofs"][0]["state_after"] = "R"
        self.reject(trace, "unverified-terminal-state")

    def test_terminal_foreign_or_changed_cgroup_is_preserved_as_fail(self):
        for field in ("cgroup_before", "cgroup_after"):
            trace = zombie_fixture()
            trace["samples"][17]["exit_proofs"][0][field] = "/foreign"
            self.reject(trace, "terminal-process-left-container-cgroup")
        trace = zombie_fixture()
        proof = trace["samples"][17]["exit_proofs"][0]
        proof.update(kind="reaped", proc_missing=True, cgroup_before="/foreign")
        self.reject(trace, "terminal-process-left-container-cgroup")

    def test_pid_or_procdir_reuse_cannot_silently_close_original(self):
        for field in ("key_before", "key_after"):
            trace = zombie_fixture()
            trace["samples"][17]["exit_proofs"][0][field][1] += 1
            self.reject(trace)
        trace = zombie_fixture()
        trace["samples"][17]["exit_proofs"][0]["procdir_identity"][1] += 1
        self.reject(trace, "terminal-procdir-reused")
        trace = observed_fixture(external_fixture())
        trace["samples"][17]["exit_proofs"][0]["replacement_key"] = [200, 10170]
        self.reject(trace, "silent-pid-reuse")

    def test_new_missing_or_changed_binding_and_missing_exit_proof_fail(self):
        trace = zombie_fixture()
        trace["samples"][17]["exit_proofs"] = []
        self.reject(trace, "missing-exit-proof")
        trace = zombie_fixture()
        del trace["samples"][16]["processes"][-1]["binding"]
        self.reject(trace)
        trace = zombie_fixture()
        binding = trace["samples"][16]["processes"][-1]["binding"]
        binding["procdir_identity"][1] += 1
        binding["procdir_identity_after"][1] += 1
        self.reject(trace, "process-binding-changed")
        trace = zombie_fixture()
        trace["samples"][17]["exit_proofs"][0]["binding"]["key_after"][1] += 1
        self.reject(trace)

    def test_terminal_permissions_are_still_checked(self):
        for field, value in (("uids", [0] * 4), ("uids", [51000, 51000, 0, 51000]),
                             ("gids", [0] * 4), ("groups", [999]), ("nnp", 0)):
            trace = zombie_fixture()
            trace["samples"][17]["exit_proofs"][0]["permissions"][field] = value
            self.reject(trace)
        for field in ("inh", "prm", "eff", "bnd", "amb"):
            trace = zombie_fixture()
            trace["samples"][17]["exit_proofs"][0]["permissions"]["caps"][field] = 1 << 21
            self.reject(trace)
        trace = zombie_fixture()
        proof = trace["samples"][17]["exit_proofs"][0]
        proof.update(kind="reaped", proc_missing=True)
        proof["permissions"]["caps"]["bnd"] = 1
        self.reject(trace)

    def test_collector_retains_live_foreign_state_and_cgroup_in_failed_proof(self):
        trace = zombie_fixture()
        row = trace["samples"][16]["processes"][-1]
        handle = {"key": tuple(row["key"]), "directory": 11, "pidfd": 12, "evidence": row["binding"]}
        inode = row["binding"]["procdir_identity"]
        with mock.patch.object(collector, "clock", return_value=101.7), \
             mock.patch.object(collector, "pidfd_events", return_value=0), \
             mock.patch.object(collector, "stat_detail_at", return_value=(tuple(row["key"]), 90, "S")), \
             mock.patch.object(collector, "cgroup_at", return_value="/foreign"), \
             mock.patch.object(collector, "permissions_at", return_value=trace["samples"][17]["exit_proofs"][0]["permissions"]), \
             mock.patch.object(collector.os, "fstat", return_value=SimpleNamespace(st_dev=inode[0], st_ino=inode[1])):
            proof = collector.terminal_exit(handle)
        self.assertEqual((proof["state_before"], proof["state_after"]), ("S", "S"))
        self.assertEqual((proof["cgroup_before"], proof["cgroup_after"]), ("/foreign", "/foreign"))
        trace["samples"][17]["exit_proofs"] = [proof]
        self.reject(trace, "original-pidfd-not-terminal")

    def test_terminal_permissionerror_is_never_converted_to_reaped(self):
        trace = zombie_fixture()
        row = trace["samples"][16]["processes"][-1]
        handle = {"key": tuple(row["key"]), "directory": 11, "pidfd": 12, "evidence": row["binding"]}
        with mock.patch.object(collector, "pidfd_events", return_value=1), \
             mock.patch.object(collector, "stat_detail_at", return_value=(tuple(row["key"]), 90, "Z")), \
             mock.patch.object(collector, "cgroup_at", return_value=trace["cgroup"]), \
             mock.patch.object(collector, "permissions_at", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                collector.terminal_exit(handle)
        with mock.patch.object(collector, "pidfd_events", return_value=1), \
             mock.patch.object(collector, "stat_detail_at", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                collector.terminal_exit(handle)

    def test_disappearance_of_one_field_is_not_reaped_while_stat_still_exists(self):
        trace = zombie_fixture()
        row = trace["samples"][16]["processes"][-1]
        handle = {"key": tuple(row["key"]), "directory": 11, "pidfd": 12, "evidence": row["binding"]}
        with mock.patch.object(collector, "pidfd_events", return_value=1), \
             mock.patch.object(collector, "stat_detail_at", return_value=(tuple(row["key"]), 90, "Z")), \
             mock.patch.object(collector, "cgroup_at", side_effect=FileNotFoundError()):
            with self.assertRaisesRegex(collector.EvidenceError, "terminal-field-missing-before-reap"):
                collector.terminal_exit(handle)

    def test_permissionerror_in_membership_read_remains_incomplete_even_if_exit_later_proven(self):
        trace = zombie_fixture()
        row = trace["samples"][16]["processes"][-1]
        key = tuple(row["key"])
        handle = {"key": key, "directory": 11, "pidfd": 12, "evidence": row["binding"]}
        proof = trace["samples"][17]["exit_proofs"][0]
        with mock.patch.object(collector, "clock", return_value=101.7), \
             mock.patch.object(collector, "members", side_effect=[{200}, set()]), \
             mock.patch.object(collector, "proc_stat", side_effect=lambda pid: (key if pid == 200 else tuple(INIT), 90)), \
             mock.patch.object(collector, "process", side_effect=PermissionError("denied")), \
             mock.patch.object(collector, "terminal_exit", return_value=proof), \
             mock.patch.object(collector, "shim", return_value=trace["samples"][17]["shim"]), \
             mock.patch.object(collector, "cgroup_path", return_value=trace["cgroup"]), \
             mock.patch.object(collector, "close_binding"):
            actual = collector.sample(99, trace["cgroup"], tuple(INIT), 90, CID, {key: row},
                                      {}, {key: handle}, 101.6)
        self.assertIs(actual["complete"], False)
        self.assertTrue(any(item["reason"] == "proc-read-or-schema-failed" for item in actual["failures"]))


class CapturedPermissionExitControls(unittest.TestCase):
    def collect_partial_exit(self, previous, permissions):
        trace = zombie_fixture()
        key = tuple(previous["key"])
        proof = copy.deepcopy(trace["samples"][17]["exit_proofs"][0])
        proof.update(kind="reaped", proc_missing=True)
        handle = {"key": key, "directory": 11, "pidfd": 12, "evidence": previous["binding"]}
        lines = [name + ":\t" + " ".join(str(v) for v in permissions[field]) for name, field in
                 (("Uid", "uids"), ("Gid", "gids"), ("Groups", "groups"))]
        lines.append("NoNewPrivs:\t" + str(permissions["nnp"]))
        lines.extend(name + ":\t" + format(permissions["caps"][field], "x") for name, field in
                     (("CapInh", "inh"), ("CapPrm", "prm"), ("CapEff", "eff"), ("CapBnd", "bnd"), ("CapAmb", "amb")))
        status = ("\n".join(lines) + "\n").encode("ascii")

        def current_stat(pid):
            return (key if pid == 200 else tuple(SHIM) if pid == 90 else tuple(INIT), 90)

        def current_cgroup(pid):
            if pid == 200:
                raise FileNotFoundError("controlled reap immediately after captured status")
            return trace["cgroup"]

        with mock.patch.object(collector, "clock", return_value=101.7), \
             mock.patch.object(collector, "members", side_effect=[{200}, set()]), \
             mock.patch.object(collector, "proc_stat", side_effect=current_stat), \
             mock.patch.object(collector, "check_binding"), \
             mock.patch.object(collector, "command", return_value=tuple(HEALTH)), \
             mock.patch.object(collector, "identity_maps"), \
             mock.patch.object(collector, "read_at", return_value=status), \
             mock.patch.object(collector, "cgroup_path", side_effect=current_cgroup), \
             mock.patch.object(collector, "terminal_exit", return_value=proof), \
             mock.patch.object(collector, "shim", return_value=trace["samples"][17]["shim"]), \
             mock.patch.object(collector, "close_binding"):
            return collector.sample(99, trace["cgroup"], tuple(INIT), 90, CID, {key: previous},
                                    {}, {key: handle}, 101.6)

    def test_bad_captured_status_cannot_be_erased_by_later_enoent_and_valid_reaped_pidfd(self):
        trace = zombie_fixture()
        previous = trace["samples"][16]["processes"][-1]
        good = {key: copy.deepcopy(previous[key]) for key in ("uids", "gids", "groups", "nnp", "caps")}
        cases = [("uids", [0] * 4), ("uids", [51000, 51000, 0, 51000]),
                 ("uids", [51001] * 4), ("gids", [0] * 4), ("gids", [51000, 0, 51000, 51000]),
                 ("groups", [999]), ("nnp", 0)]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                permissions = copy.deepcopy(good)
                permissions[field] = value
                actual = self.collect_partial_exit(previous, permissions)
                self.assertIs(actual["complete"], False)
                self.assertTrue(any(item["reason"].startswith("observed-profile-") for item in actual["failures"]))
        for field in ("inh", "prm", "eff", "bnd", "amb"):
            with self.subTest(capability=field):
                permissions = copy.deepcopy(good)
                permissions["caps"][field] = 1 << 21
                actual = self.collect_partial_exit(previous, permissions)
                self.assertIs(actual["complete"], False)
                self.assertTrue(any(item["reason"].startswith("observed-profile-") for item in actual["failures"]))

    def test_valid_captured_profile_and_root_to_demote_partial_still_allow_pinned_reap(self):
        trace = zombie_fixture()
        current = trace["samples"][16]["processes"][-1]
        permissions = {key: copy.deepcopy(current[key]) for key in ("uids", "gids", "groups", "nnp", "caps")}
        for previous in (current, trace["samples"][14]["processes"][-1]):
            with self.subTest(previous_uid=previous["uids"][0]):
                actual = self.collect_partial_exit(previous, permissions)
                self.assertIs(actual["complete"], True)
                self.assertEqual(actual["exited"], [[200, 10100]])

    def test_shared_observation_command_uid_and_prior_transition_contract(self):
        commands = [(SERVE := ["/usr/local/bin/python", "/usr/local/bin/netops", "serve"], {51000}),
                    (["/usr/local/bin/python", "-m", "netops", "worker", "helper"], {51001}),
                    (["/usr/local/bin/python", "-m", "netops", "worker", "auditor"], {51002}),
                    (["/usr/local/bin/python", "-m", "netops", "worker", "admin"], {51003}),
                    (HEALTH, {0, 51000}), (["runc", "init"], {0})]
        for command, accepted in commands:
            for uid in (0, 51000, 51001, 51002, 51003, 999):
                row = process(200, 10100, uid, command, SHIM)
                if uid in accepted:
                    observed_permissions(row, command)
                else:
                    with self.assertRaises(InvalidProfile):
                        observed_permissions(row, command)
        previous = process(200, 10100, 51000, HEALTH, SHIM)
        with self.assertRaises(InvalidProfile):
            observed_permissions(root_health(), HEALTH, previous)
        previous = root_health()
        observed_permissions(process(200, 10100, 51000, HEALTH, SHIM), HEALTH, previous)
        observed_permissions(process(200, 10100, 51000, HEALTH, SHIM), HEALTH,
                             root_health(argv=["runc", "init"]))
        with self.assertRaises(InvalidProfile):
            observed_permissions(root_health(argv=["runc", "init"]), ["runc", "init"], previous)
        with self.assertRaises(InvalidProfile):
            observed_permissions(process(200, 10100, 51000, SERVE, SHIM), SERVE, previous)


def trusted_fixture():
    trace = observed_fixture(external_fixture())
    for sample in trace["samples"][11:13]:
        row = sample["processes"][-1]
        row["nnp"] = 0
        row["caps"].update(eff=(1 << 41) - 1, prm=(1 << 41) - 1, bnd=(1 << 41) - 1)
    return trace


class TrustedRuntimeControls(unittest.TestCase):
    def reject(self, trace, reason=None):
        actual = assess_observed_trace(trace)
        self.assertIs(actual["passed"], False)
        if reason is not None:
            self.assertEqual(actual["reason"], reason)

    def test_product_groups_must_be_empty_in_roles_demoted_health_and_terminal_reap(self):
        for index, uid in enumerate((51000, 51001, 51002, 51003)):
            with self.subTest(role=index):
                trace = observed_fixture(fixture())
                trace["samples"][700]["processes"][index]["groups"] = [uid]
                self.reject(trace)
        trace = trusted_fixture()
        trace["samples"][15]["processes"][-1]["groups"] = [51000]
        self.reject(trace)
        trace = zombie_fixture()
        proof = trace["samples"][17]["exit_proofs"][0]
        proof.update(kind="reaped", proc_missing=True)
        proof["permissions"]["groups"] = [51000]
        self.reject(trace, "unsafe-terminal-identity")
        previous = trusted_fixture()["samples"][16]["processes"][-1]
        permissions = {key: copy.deepcopy(previous[key]) for key in ("uids", "gids", "groups", "nnp", "caps")}
        permissions["groups"] = [51000]
        actual = CapturedPermissionExitControls().collect_partial_exit(previous, permissions)
        self.assertIs(actual["complete"], False)
        self.assertTrue(any(item["reason"].startswith("observed-profile-") for item in actual["failures"]))

    def test_full_host_caps_nnp_zero_and_different_child_device_then_health(self):
        trace = trusted_fixture()
        original = copy.deepcopy(trace)
        child = external_row(trace)["runtime_executable"]["file"]
        host = trace["runtime"]["binary"]
        self.assertNotEqual(child["stat_before"][0], host["stat_before"][0])
        self.assertEqual(child["sha256"], host["sha256"])
        self.assertTrue(assess_observed_trace(trace)["passed"])
        self.assertEqual(trace, original)
        for row in [trace["samples"][11]["processes"][-1], trace["samples"][12]["processes"][-1]]:
            row["nnp"] = 1
            row["caps"]["bnd"] = 0x1cb
        self.assertTrue(assess_observed_trace(trace)["passed"])

    def test_runtime_then_actual_health_may_use_original_pinned_exit_without_demote(self):
        trace = external_fixture()
        for sample in trace["samples"][15:17]:
            sample["processes"][-1] = root_health()
        trace = observed_fixture(trace)
        for sample in trace["samples"][11:13]:
            sample["processes"][-1]["nnp"] = 0
            sample["processes"][-1]["caps"].update(eff=(1 << 41) - 1, prm=(1 << 41) - 1, bnd=(1 << 41) - 1)
        self.assertTrue(assess_observed_trace(trace)["passed"])

    def test_foreign_executable_even_same_inode_or_digest_prefix_fails(self):
        for digest in ("e" * 64, "d" * 16 + "e" * 48):
            trace = trusted_fixture()
            file = external_row(trace)["runtime_executable"]["file"]
            file["sha256"] = digest
            file["stat_before"][0] = file["stat_after"][0] = 8
            self.reject(trace, "runtime-content-mismatch")

    def test_forged_runc_command_without_complete_stable_exe_and_permissionerror_fails(self):
        for variant in ("missing", "short", "unstable", "host-writable", "host-after-window"):
            trace = trusted_fixture()
            proof = external_row(trace)["runtime_executable"]
            if variant == "missing":
                del external_row(trace)["runtime_executable"]
            elif variant == "short":
                proof["file"]["bytes_hashed"] -= 1
            elif variant == "unstable":
                proof["file"]["stat_after"][6] += 1
            elif variant == "host-writable":
                for field in ("stat_before", "stat_after"):
                    trace["runtime"]["binary"][field][2] |= 0o002
            else:
                trace["runtime"]["binary"]["read_finished_at"] = 101
            self.reject(trace)
        trace = trusted_fixture()
        row = external_row(trace)
        handle = {"key": tuple(row["key"]), "directory": 11, "pidfd": 12, "evidence": row["binding"]}
        with mock.patch.object(collector, "check_binding"), \
             mock.patch.object(collector, "proc_stat", return_value=(tuple(row["key"]), 95)), \
             mock.patch.object(collector, "command", return_value=("runc", "init")), \
             mock.patch.object(collector.os, "open", side_effect=PermissionError("denied")), \
             mock.patch.object(collector, "runtime_parent_after_enoent") as retry:
            with self.assertRaises(PermissionError):
                collector.process(200, trace["cgroup"], 90, CID, trace["runtime"], handle)
            retry.assert_not_called()

    def test_foreign_missing_stale_reused_runtime_or_shim_origin_fails(self):
        for variant in ("missing", "cid", "exe", "parent-key", "shim-key", "stale"):
            trace = trusted_fixture()
            row = external_row(trace)
            if variant == "missing":
                del row["runtime_parent"]
            elif variant == "cid":
                row["runtime_parent"]["argv"][-1] = "b" * 64
            elif variant == "exe":
                row["runtime_parent"]["exe_identity"][1] += 1
            elif variant == "parent-key":
                row["runtime_parent"]["key_after"][1] += 1
            elif variant == "shim-key":
                row["runtime_parent"]["parent_after"][1] += 1
            else:
                row["runtime_parent"]["read_started_at"] -= 1
            self.reject(trace)

    def test_child_reuse_or_cgroup_escape_cannot_borrow_runtime_proof(self):
        for variant in ("key", "procdir", "before", "after"):
            trace = trusted_fixture()
            proof = external_row(trace)["runtime_executable"]
            if variant == "key":
                proof["key_after"][1] += 1
            elif variant == "procdir":
                proof["procdir_identity"][1] += 1
            else:
                proof["cgroup_" + variant] = "/foreign"
            self.reject(trace)

    def test_runtime_exit_or_different_future_key_without_actual_health_fails(self):
        trace = external_fixture()
        for sample in trace["samples"][13:17]:
            sample["processes"][-1]["argv"] = ["runc", "init"]
            sample["processes"][-1]["uids"] = [0] * 4
            sample["processes"][-1]["gids"] = [0] * 4
        self.reject(observed_fixture(trace), "runc-exit-without-health-proof")
        trace = external_fixture()
        for sample in trace["samples"][13:17]:
            sample["processes"][-1]["key"][1] = 10130
        trace["samples"][13]["exited"] = [[200, 10100]]
        trace["samples"][17]["exited"] = [[200, 10130]]
        self.reject(observed_fixture(trace), "runc-exit-without-health-proof")

    def test_runtime_bound_is_kernel_birth_not_first_read(self):
        trace = fixture()
        row = root_health(argv=["runc", "init"])
        row["nnp"] = 0
        row["caps"].update(eff=(1 << 41) - 1, prm=(1 << 41) - 1, bnd=(1 << 41) - 1)
        insert(trace, 10, 112, row)
        insert(trace, 112, 114, root_health())
        trace["samples"][114]["exited"] = [[200, 10100]]
        self.reject(observed_fixture(trace), "bootstrap-exceeded-health-timeout")

    def test_runtime_trust_never_exempts_product_permissions_or_reescalation(self):
        cases = [("uids", [0, 0, 1, 0]), ("gids", [0, 0, 1, 0]), ("groups", [999]), ("nnp", 0)]
        for field, value in cases:
            trace = trusted_fixture()
            trace["samples"][13]["processes"][-1][field] = value
            self.reject(trace)
        for field in ("inh", "prm", "eff", "bnd", "amb"):
            trace = trusted_fixture()
            trace["samples"][13]["processes"][-1]["caps"][field] |= 1 << 21
            self.reject(trace)
            trace = trusted_fixture()
            trace["samples"][20]["processes"][0]["caps"][field] = 1
            trace["samples"][20]["processes"][0]["runtime_executable"] = copy.deepcopy(external_row(trace)["runtime_executable"])
            self.reject(trace)
        trace = trusted_fixture()
        trace["samples"][14]["processes"][-1]["argv"] = ["runc", "init"]
        trace = observed_fixture(trace)
        self.reject(trace, "health-reverted-to-runtime")
        trace = trusted_fixture()
        trace["samples"][16]["processes"][-1] = copy.deepcopy(trace["samples"][14]["processes"][-1])
        self.reject(trace)

    def test_captured_bad_product_status_then_reap_is_not_hidden_by_runtime_proof(self):
        trace = trusted_fixture()
        previous = copy.deepcopy(trace["samples"][16]["processes"][-1])
        previous["runtime_executable"] = copy.deepcopy(external_row(trace)["runtime_executable"])
        permissions = {key: copy.deepcopy(previous[key]) for key in ("uids", "gids", "groups", "nnp", "caps")}
        permissions["nnp"] = 0
        actual = CapturedPermissionExitControls().collect_partial_exit(previous, permissions)
        self.assertIs(actual["complete"], False)
        self.assertTrue(any(item["reason"].startswith("observed-profile-") for item in actual["failures"]))

    def test_parent_enoent_retry_is_bounded_and_requires_fresh_child_exe_cgroup(self):
        trace = trusted_fixture()
        row = external_row(trace)
        key = tuple(row["key"])
        handle = {"key": key, "directory": 11, "pidfd": 12, "evidence": row["binding"]}
        inode = SimpleNamespace(st_dev=88, st_ino=1002)
        with mock.patch.object(collector, "clock", return_value=101.09), \
             mock.patch.object(collector, "check_binding"), \
             mock.patch.object(collector, "stat_at", return_value=(key, 90)), \
             mock.patch.object(collector.os, "stat", return_value=inode), \
             mock.patch.object(collector, "command", return_value=("runc", "init")), \
             mock.patch.object(collector, "cgroup_at", return_value=trace["cgroup"]), \
             mock.patch.object(collector, "identity_maps"), \
             mock.patch.object(collector, "shim", return_value=trace["samples"][11]["shim"]):
            actual = collector.runtime_parent_after_enoent(handle, key, 90, CID, trace["runtime"], trace["cgroup"], [88, 1002])
            self.assertEqual(actual[:3], (90, tuple(SHIM), None))
            self.assertEqual(len(actual[3]["reads"]), 1)
            with mock.patch.object(collector.os, "stat", return_value=SimpleNamespace(st_dev=88, st_ino=999)):
                with self.assertRaises(collector.EvidenceError):
                    collector.runtime_parent_after_enoent(handle, key, 90, CID, trace["runtime"], trace["cgroup"], [88, 1002])
            with mock.patch.object(collector, "stat_at", return_value=(key, 95)), \
                 mock.patch.object(collector, "runtime_parent", side_effect=FileNotFoundError()) as parent:
                with self.assertRaisesRegex(collector.EvidenceError, "runtime-parent-retry-exhausted"):
                    collector.runtime_parent_after_enoent(handle, key, 90, CID, trace["runtime"], trace["cgroup"], [88, 1002])
                self.assertEqual(parent.call_count, 3)
                parent.side_effect = collector.EvidenceError("unverified-runtime-command")
                with self.assertRaisesRegex(collector.EvidenceError, "unverified-runtime-command"):
                    collector.runtime_parent_after_enoent(handle, key, 90, CID, trace["runtime"], trace["cgroup"], [88, 1002])
            with mock.patch.object(collector, "clock", side_effect=[101.0, 101.051]):
                with self.assertRaisesRegex(collector.EvidenceError, "runtime-parent-retry-exhausted"):
                    collector.runtime_parent_after_enoent(handle, key, 90, CID, trace["runtime"], trace["cgroup"], [88, 1002])

    def test_readable_foreign_parent_is_not_retried_and_current_exe_fd_closes(self):
        trace = trusted_fixture()
        row = external_row(trace)
        key = tuple(row["key"])
        handle = {"key": key, "directory": 11, "pidfd": 12, "evidence": row["binding"]}
        info = SimpleNamespace(st_dev=88, st_ino=1002, st_mode=0o100755, st_uid=0,
                               st_size=32, st_mtime_ns=1000000000, st_ctime_ns=1000000000)
        with mock.patch.object(collector, "check_binding"), \
             mock.patch.object(collector, "proc_stat", return_value=(key, 95)), \
             mock.patch.object(collector, "command", return_value=("runc", "init")), \
             mock.patch.object(collector.os, "open", return_value=47) as opened, \
             mock.patch.object(collector.os, "fstat", return_value=info), \
             mock.patch.object(collector.os, "close") as closed, \
             mock.patch.object(collector, "cgroup_at", return_value=trace["cgroup"]), \
             mock.patch.object(collector, "permissions_at", return_value=row), \
             mock.patch.object(collector, "runtime_parent", side_effect=collector.EvidenceError("unverified-runtime-command")), \
             mock.patch.object(collector, "runtime_parent_after_enoent") as retry, \
             mock.patch.object(collector, "hash_executable") as hashed:
            with self.assertRaisesRegex(collector.EvidenceError, "unverified-runtime-command"):
                collector.process(200, trace["cgroup"], 90, CID, trace["runtime"], handle)
            opened.assert_called_once()
            closed.assert_called_once_with(47)
            retry.assert_not_called()
            hashed.assert_not_called()


class KnownHealthEmptyCommandExitControls(unittest.TestCase):
    def sample_read(self, data=b"", *, prior_change=None, known=True, proof_change=None,
                    terminal_error=False, live=False):
        trace = observed_fixture(external_fixture())
        previous = copy.deepcopy(trace["samples"][16]["processes"][-1])
        if prior_change:
            previous.update(copy.deepcopy(prior_change))
        key = tuple(previous["key"])
        proof = copy.deepcopy(trace["samples"][17]["exit_proofs"][0])
        proof.update(kind="reaped", proc_missing=True)
        if proof_change:
            proof.update(copy.deepcopy(proof_change))
        handle = {"key": key, "directory": 11, "pidfd": 12, "evidence": previous["binding"]}
        def current_stat(pid):
            return (key if pid == 200 else tuple(INIT), 90)
        with mock.patch.object(collector, "clock", return_value=101.7), \
             mock.patch.object(collector, "members", side_effect=[{200}, {200} if live else set()]), \
             mock.patch.object(collector, "proc_stat", side_effect=current_stat), \
             mock.patch.object(collector, "check_binding"), \
             mock.patch.object(collector, "read", return_value=data) as read, \
             mock.patch.object(collector, "terminal_exit", return_value=proof,
                               side_effect=collector.EvidenceError("controlled-no-terminal-proof") if terminal_error else None) as terminal, \
             mock.patch.object(collector, "shim", return_value=trace["samples"][17]["shim"]), \
             mock.patch.object(collector, "cgroup_path", return_value=trace["cgroup"]), \
             mock.patch.object(collector, "close_binding"):
            actual = collector.sample(99, trace["cgroup"], tuple(INIT), 90, CID,
                                      {key: previous} if known else {}, {}, {key: handle}, 101.6)
        read.assert_called_once_with("/proc/200/cmdline")
        return actual, terminal.call_count

    def test_empty_command_of_demoted_health_requires_real_sampler_terminal_closure(self):
        actual, calls = self.sample_read()
        self.assertIs(actual["complete"], True)
        self.assertEqual(actual["failures"], [])
        self.assertEqual(actual["exited"], [[200, 10100]])
        self.assertEqual(actual["exit_proofs"][0]["kind"], "reaped")
        self.assertGreaterEqual(calls, 1)

    def test_empty_command_with_wrong_key_or_binding_or_missing_proof_is_incomplete(self):
        trace = zombie_fixture()
        wrong = copy.deepcopy(trace["samples"][16]["processes"][-1]["binding"])
        wrong["procdir_identity"] = wrong["procdir_identity_after"] = [9, 999]
        for change, missing in (({"key": [200, 10101]}, False), ({"binding": wrong}, False), (None, True)):
            with self.subTest(change=change, missing=missing):
                actual, _ = self.sample_read(proof_change=change, terminal_error=missing)
                self.assertIs(actual["complete"], False)
                self.assertTrue(actual["failures"])

    def test_nonempty_malformed_or_unknown_command_cannot_borrow_prior_health_exit(self):
        for data in (b"malformed", b"unknown\x00command\x00"):
            with self.subTest(data=data):
                actual, _ = self.sample_read(data)
                self.assertIs(actual["complete"], False)
                self.assertTrue(actual["failures"])

    def test_previous_root_or_unknown_command_or_unsafe_permissions_do_not_qualify(self):
        for change in ({"uids": [0] * 4, "gids": [0] * 4},
                       {"argv": ["unknown"]}, {"argv": list(collector.SERVE)},
                       {"groups": [51000]}, {"nnp": 0}):
            with self.subTest(change=change):
                actual, _ = self.sample_read(prior_change=change)
                self.assertIs(actual["complete"], False)
                self.assertTrue(actual["failures"])

    def test_live_known_health_empty_command_without_terminal_proof_is_incomplete(self):
        actual, _ = self.sample_read(live=True, terminal_error=True)
        self.assertIs(actual["complete"], False)
        self.assertEqual(actual["exit_proofs"], [])

    def test_unclassified_identity_empty_command_is_not_a_known_health_exit(self):
        actual, _ = self.sample_read(known=False)
        self.assertIs(actual["complete"], False)
        self.assertTrue(actual["failures"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
