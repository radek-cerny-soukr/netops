import copy
import hashlib
import json
import pathlib
import tempfile
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collect_health_bootstrap_trace as col
import test_health_bootstrap_profile as base
from health_bootstrap_profile import assess_trace

CID = base.CID
KEY = (200, 10100)
CGROUP = "/qa/docker-" + CID + ".scope"
SHIM = {"key": [90, 900], "exe": "/usr/bin/containerd-shim-runc-v2", "exe_identity": [8, 1001],
        "argv": ["/usr/bin/containerd-shim-runc-v2", "-namespace", "moby", "-id", CID,
                 "-address", "/run/containerd/containerd.sock"]}
ROOT_RUNTIME = {"uids": [0] * 4, "gids": [0] * 4, "groups": [], "nnp": 0,
                "caps": {"inh": 0, "prm": (1 << 41) - 1, "eff": (1 << 41) - 1, "bnd": (1 << 41) - 1, "amb": 0}}


def runc_rows(trace):
    return [row for sample in trace["samples"] for row in sample["processes"] if row["argv"] == ["runc", "init"]]


def direct_shim_runtime_trace():
    trace = base.fixture()
    base.insert(trace, 10, 13, base.root_health(argv=["runc", "init"]))
    base.insert(trace, 13, 17, base.process(200, 10100, 51000, base.HEALTH, base.SHIM))
    trace["samples"][17]["exited"] = [[200, 10100]]
    return base.observed_fixture(trace)


def retry_read(time, **changes):
    read = {"key_before": list(KEY), "key_after": list(KEY), "exe_identity_before": [88, 1002],
            "exe_identity_after": [88, 1002], "cgroup_before": CGROUP, "cgroup_after": CGROUP,
            "argv": ["runc", "init"], "time": time}
    read.update(changes)
    return read


def retry_trace(**retry_changes):
    trace = base.external_fixture()
    row = trace["samples"][12]["processes"][-1]
    row["read_started_at"], row["read_finished_at"] = 101.12, 101.19
    trace = base.observed_fixture(trace)
    retry = {"reason": "parent-ENOENT", "read_started_at": 101.125, "read_finished_at": 101.165,
             "reads": [retry_read(101.13)]}
    retry.update(retry_changes)
    trace["samples"][12]["processes"][-1]["parent_retry"] = retry
    return trace


class Base(unittest.TestCase):
    def accept(self, trace):
        actual = assess_trace(trace)
        self.assertIs(actual["passed"], True, actual)

    def reject(self, trace, reason):
        actual = assess_trace(trace)
        self.assertIs(actual["passed"], False, actual)
        self.assertEqual(actual["reason"], reason)


class RuntimeExecutableProof(Base):
    def test_direct_shim_runtime_fixture_is_accepted(self):
        self.accept(direct_shim_runtime_trace())

    def test_short_digest_on_both_sides_is_rejected(self):
        trace = base.trusted_fixture()
        trace["runtime"]["binary"]["sha256"] = "d" * 16
        for row in runc_rows(trace):
            row["runtime_executable"]["file"]["sha256"] = "d" * 16
        self.reject(trace, "invalid-runtime-digest")

    def test_host_binary_identity_must_match_docker_runtime_path(self):
        trace = direct_shim_runtime_trace()
        trace["runtime"]["exe_identity"] = [8, 9999]
        self.reject(trace, "unverified-host-runtime-pin")

    def test_executable_hash_finished_after_sample_time_is_rejected(self):
        trace = base.trusted_fixture()
        file = base.external_row(trace)["runtime_executable"]["file"]
        file["read_started_at"] = file["read_finished_at"] = 101.15
        self.reject(trace, "stale-runtime-executable-proof")

    def test_executable_fd_opened_before_child_read_is_rejected(self):
        trace = base.trusted_fixture()
        base.external_row(trace)["runtime_executable"]["file"]["opened_at"] = 101.07
        self.reject(trace, "stale-runtime-executable-proof")

    def test_runtime_groups_zero_is_accepted(self):
        trace = base.trusted_fixture()
        for row in runc_rows(trace):
            row["groups"] = [0]
        self.accept(trace)


class ParentRetryProof(Base):
    def test_bounded_retry_proof_is_accepted(self):
        self.accept(retry_trace())

    def test_more_than_three_reads_rejected(self):
        reads = [retry_read(t) for t in (101.13, 101.14, 101.15, 101.16)]
        self.reject(retry_trace(reads=reads), "unbounded-runtime-parent-retry")

    def test_retry_longer_than_50ms_rejected(self):
        self.reject(retry_trace(read_finished_at=101.185), "unbounded-runtime-parent-retry")

    def test_retry_read_with_other_starttime_rejected(self):
        self.reject(retry_trace(reads=[retry_read(101.13, key_after=[200, 10101])]), "unverified-runtime-parent-retry")

    def test_retry_read_with_other_executable_rejected(self):
        read = retry_read(101.13, exe_identity_before=[8, 1002], exe_identity_after=[8, 1002])
        self.reject(retry_trace(reads=[read]), "unverified-runtime-parent-retry")

    def test_retry_without_parent_enoent_reason_rejected(self):
        self.reject(retry_trace(reason="parent-EPERM"), "unbounded-runtime-parent-retry")

    def test_retry_read_with_other_command_rejected(self):
        self.reject(retry_trace(reads=[retry_read(101.13, argv=["runc", "init", "--x"])]), "unverified-runtime-parent-retry")

    def test_retry_read_outside_instance_cgroup_rejected(self):
        read = retry_read(101.13, cgroup_before="/foreign", cgroup_after="/foreign")
        self.reject(retry_trace(reads=[read]), "unverified-runtime-parent-retry")


class TimingResolution(Base):
    def test_root_seen_10_01s_after_birth_rejected_even_if_exit_within_10_05s(self):
        trace = base.fixture()
        base.insert(trace, 10, 111, base.root_health())
        trace["samples"][110]["time"] = 111.01
        trace["samples"][111]["time"] = 111.04
        trace["samples"][111]["exited"] = [[200, 10100]]
        self.reject(base.observed_fixture(trace), "bootstrap-exceeded-health-timeout")

    def test_gap_of_220ms_rejected(self):
        trace = base.fixture()
        del trace["samples"][19]
        trace["samples"][19]["time"] = 102.02
        self.reject(base.observed_fixture(trace), "sampling-gap-or-order")


class PinnedExitProof(unittest.TestCase):
    def reject(self, trace, reason):
        actual = assess_trace(trace)
        self.assertIs(actual["passed"], False, actual)
        self.assertEqual(actual["reason"], reason)

    def test_exit_proof_with_other_consistent_binding_rejected(self):
        trace = base.observed_fixture(base.external_fixture())
        binding = trace["samples"][17]["exit_proofs"][0]["binding"]
        binding["procdir_identity"] = [9, 1]
        binding["procdir_identity_after"] = [9, 1]
        self.reject(trace, "exit-binding-mismatch")

    def test_exit_proof_read_before_previous_sample_rejected(self):
        trace = base.observed_fixture(base.external_fixture())
        trace["samples"][17]["exit_proofs"][0]["read_started_at"] = trace["samples"][16]["time"] - 0.05
        self.reject(trace, "stale-exit-proof")

    def test_zombie_with_replacement_identity_rejected(self):
        trace = base.external_fixture()
        base.insert(trace, 17, 19, base.root_health(birth=10170))
        trace["samples"][19]["exited"] = [[200, 10170]]
        trace = base.observed_fixture(trace)
        row = trace["samples"][16]["processes"][-1]
        proof = trace["samples"][17]["exit_proofs"][0]
        self.assertEqual(proof["replacement_key"], [200, 10170])
        proof.update(kind="zombie", key_before=list(row["key"]), key_after=list(row["key"]),
                     state_before="Z", state_after="Z", cgroup_before=trace["cgroup"], cgroup_after=trace["cgroup"],
                     procdir_identity=copy.deepcopy(row["binding"]["procdir_identity"]),
                     permissions={key: copy.deepcopy(row[key]) for key in ("uids", "gids", "groups", "nnp", "caps")})
        del proof["proc_missing"]
        self.reject(trace, "unclassified-terminal-reuse")


class RetryCollector(unittest.TestCase):
    def retry(self, clock=None, stat=(KEY, 90), command=("runc", "init"), cgroup=CGROUP):
        handle = {"key": KEY, "directory": 11, "pidfd": 12, "evidence": {}}
        stat_mock = {"side_effect": stat} if isinstance(stat, list) else {"return_value": stat}
        clock_mock = {"side_effect": clock} if clock else {"return_value": 101.09}
        with mock.patch.object(col, "clock", **clock_mock), \
                mock.patch.object(col, "check_binding"), \
                mock.patch.object(col, "stat_at", **stat_mock), \
                mock.patch.object(col.os, "stat", return_value=SimpleNamespace(st_dev=88, st_ino=1002)), \
                mock.patch.object(col, "command", return_value=command), \
                mock.patch.object(col, "cgroup_at", return_value=cgroup), \
                mock.patch.object(col, "identity_maps"), \
                mock.patch.object(col, "shim", return_value=copy.deepcopy(SHIM)):
            return col.runtime_parent_after_enoent(handle, KEY, 90, CID, base.runtime_fixture(), CGROUP, [88, 1002])

    def expect(self, reason, **kwargs):
        with self.assertRaisesRegex(col.EvidenceError, reason):
            self.retry(**kwargs)

    def test_baseline_retry_returns_current_shim(self):
        self.assertEqual(self.retry()[:3], (90, tuple(SHIM["key"]), None))

    def test_read_finishing_after_50ms_is_exhausted(self):
        self.expect("runtime-parent-retry-exhausted", clock=[101.0, 101.0, 101.01, 101.06])

    def test_child_starttime_change_rejected(self):
        self.expect("runtime-parent-retry-child-changed", stat=((200, 10101), 90))

    def test_child_command_change_rejected(self):
        self.expect("runtime-parent-retry-child-changed", command=("runc", "init", "--x"))

    def test_child_outside_instance_cgroup_rejected(self):
        self.expect("runtime-parent-retry-child-changed", cgroup="/foreign")

    def test_child_parent_change_during_read_rejected(self):
        self.expect("runtime-parent-retry-child-changed", stat=[(KEY, 90), (KEY, 95)])


class RuntimeProcessCollector(unittest.TestCase):
    def run_process(self, parent=90, sha="d" * 64, exe_after=(88, 1002), cgroups=(CGROUP, CGROUP),
                    runtime_parent=None, retry=None):
        handle = {"key": KEY, "directory": 11, "pidfd": 12,
                  "evidence": {"procdir_identity": [9, 1], "method": "procdir+pidfd"}}
        info = SimpleNamespace(st_dev=88, st_ino=1002, st_mode=0o100755, st_uid=0,
                               st_size=32, st_mtime_ns=1000000000, st_ctime_ns=1000000000)
        file = dict(base.runtime_file_fixture(101.0, device=88), sha256=sha)
        runtime = base.runtime_fixture()

        def proc_stat(pid):
            return (KEY, parent) if pid == 200 else ((90, 900), 1)

        with ExitStack() as stack:
            for target, name, kwargs in (
                    (col, "check_binding", {}), (col, "proc_stat", {"side_effect": proc_stat}),
                    (col, "command", {"return_value": ("runc", "init")}),
                    (col.os, "open", {"return_value": 47}), (col.os, "fstat", {"return_value": info}),
                    (col.os, "close", {}), (col.os, "stat", {"return_value": SimpleNamespace(st_dev=exe_after[0], st_ino=exe_after[1])}),
                    (col, "cgroup_at", {"side_effect": list(cgroups)}),
                    (col, "permissions_at", {"return_value": copy.deepcopy(ROOT_RUNTIME)}),
                    (col, "identity_maps", {}), (col, "cgroup_path", {"return_value": CGROUP}),
                    (col, "hash_executable", {"return_value": file}),
                    (col, "runtime_parent", runtime_parent or {}),
                    (col, "runtime_parent_after_enoent", retry or {})):
                stack.enter_context(mock.patch.object(target, name, **kwargs))
            return col.process(200, CGROUP, 90, CID, runtime, handle)

    def test_baseline_direct_shim_runtime_row(self):
        row = self.run_process()
        self.assertEqual(row["runtime_executable"]["file"]["sha256"], "d" * 64)
        self.assertEqual(row["parent"], [90, 900])

    def test_foreign_executable_content_rejected_by_collector(self):
        with self.assertRaisesRegex(col.EvidenceError, "runtime-content-mismatch"):
            self.run_process(sha="e" * 64)

    def test_exe_link_changed_during_snapshot_rejected(self):
        with self.assertRaisesRegex(col.EvidenceError, "runtime-executable-changed-during-snapshot"):
            self.run_process(exe_after=(88, 999))

    def test_runtime_process_left_cgroup_during_snapshot_rejected(self):
        with self.assertRaisesRegex(col.EvidenceError, "runtime-process-left-container-cgroup"):
            self.run_process(cgroups=(CGROUP, "/foreign"))

    def test_readable_foreign_parent_is_never_retried(self):
        retry_value = (90, (90, 900), None, {"reason": "parent-ENOENT", "reads": [], "read_started_at": 0, "read_finished_at": 0})
        with self.assertRaisesRegex(col.EvidenceError, "unverified-runtime-command"):
            self.run_process(parent=95, runtime_parent={"side_effect": col.EvidenceError("unverified-runtime-command")},
                             retry={"return_value": retry_value})


class FileAndPinCollector(unittest.TestCase):
    def test_hash_rejects_fstat_change_during_read(self):
        before = [88, 1002, 0o100755, 0, 32, 1000000000, 1000000000]
        changed = SimpleNamespace(st_dev=88, st_ino=1002, st_mode=0o100755, st_uid=0, st_size=32,
                                  st_mtime_ns=1000000001, st_ctime_ns=1000000000)
        with mock.patch.object(col.os, "pread", side_effect=[b"x" * 32, b""]), \
                mock.patch.object(col.os, "fstat", return_value=changed):
            with self.assertRaisesRegex(col.EvidenceError, "runtime-file-changed-or-incomplete"):
                col.hash_executable(47, before, 101.0)

    def test_host_fd_identity_must_match_docker_runtime_path(self):
        info = SimpleNamespace(st_dev=8, st_ino=9999, st_mode=0o100755, st_uid=0, st_size=32,
                               st_mtime_ns=1000000000, st_ctime_ns=1000000000)
        with mock.patch.object(col.os, "open", return_value=47), mock.patch.object(col.os, "close"), \
                mock.patch.object(col.os, "fstat", return_value=info), \
                mock.patch.object(col, "hash_executable", return_value={}):
            with self.assertRaisesRegex(col.EvidenceError, "unsafe-host-runtime-binary"):
                col.host_binary(base.runtime_fixture())

    def pin(self, state="S", events=0):
        with mock.patch.object(col.os, "open", return_value=47), mock.patch.object(col.os, "close"), \
                mock.patch.object(col.os, "pidfd_open", return_value=48), \
                mock.patch.object(col.os, "fstat", return_value=SimpleNamespace(st_dev=9, st_ino=1)), \
                mock.patch.object(col.os, "stat", return_value=SimpleNamespace(st_dev=9, st_ino=1)), \
                mock.patch.object(col, "stat_detail_at", return_value=(KEY, 90, state)), \
                mock.patch.object(col, "cgroup_at", return_value=CGROUP), \
                mock.patch.object(col, "pidfd_events", return_value=events):
            return col.pin_process(200, CGROUP)

    def test_pin_baseline(self):
        self.assertEqual(self.pin()["key"], KEY)

    def test_pin_rejects_zombie_or_signalled_pidfd(self):
        for state, events in (("Z", 0), ("S", 1)):
            with self.subTest(state=state, events=events):
                with self.assertRaisesRegex(col.EvidenceError, "unverified-initial-process-binding"):
                    self.pin(state, events)

    def test_check_binding_rejects_other_starttime(self):
        handle = {"key": KEY, "directory": 11, "evidence": {"procdir_identity": [9, 1]}}
        with mock.patch.object(col, "stat_detail_at", return_value=((200, 10101), 90, "S")), \
                mock.patch.object(col.os, "stat", return_value=SimpleNamespace(st_dev=9, st_ino=1)):
            with self.assertRaisesRegex(col.EvidenceError, "process-binding-identity-race"):
                col.check_binding(handle)


class CollectTimeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp")
        pathlib.Path(self.tmp.name, CGROUP.lstrip("/")).mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def collect(self, runtime_values, host_values):
        now = [1000.0]
        real_path = col.Path
        runtime = {k: v for k, v in base.runtime_fixture().items() if k != "binary"}

        def path_factory(*args):
            return real_path(self.tmp.name) if args == ("/sys/fs/cgroup",) else real_path(*args)

        def sleep(delay):
            now[0] += delay

        def sample(*args, **kwargs):
            now[0] += 0.005
            return {"time": now[0], "complete": True, "shim": copy.deepcopy(SHIM), "pids": [], "processes": [],
                    "exited": [], "exit_proofs": [], "races": [], "failures": []}

        predicate = real_path(col.__file__).with_name("health_bootstrap_profile.py").read_bytes()
        info = {"id": CID, "image": "sha256:" + "0" * 64, "pid": 100, "running": True, "restarts": 0, "runtime": "runc"}
        with ExitStack() as stack:
            for target, name, kwargs in (
                    (col.os, "geteuid", {"return_value": 0}),
                    (col, "PREDICATE_SHA", {"new": hashlib.sha256(predicate).hexdigest()}),
                    (col, "inspect", {"side_effect": lambda cid: dict(info)}),
                    (col, "runtime_metadata", {"side_effect": [dict(runtime, **v) for v in runtime_values]}),
                    (col, "host_binary", {"side_effect": host_values}),
                    (col, "proc_stat", {"return_value": ((100, 1000), 90)}),
                    (col, "identity_maps", {"return_value": None}),
                    (col, "cgroup_path", {"return_value": CGROUP}),
                    (col, "Path", {"side_effect": path_factory}),
                    (col, "members", {"return_value": {100}}),
                    (col, "shim", {"side_effect": lambda pid, cid: copy.deepcopy(SHIM)}),
                    (col, "sample", {"side_effect": sample}),
                    (col, "NamespaceScope", {"return_value": SimpleNamespace(header={}, close=lambda: None)}),
                    (col, "clock", {"side_effect": lambda: now[0]}),
                    (col.time, "sleep", {"side_effect": sleep})):
                stack.enter_context(mock.patch.object(target, name, **kwargs))
            return col.collect(CID)

    def same_host(self):
        return [base.runtime_file_fixture(), base.runtime_file_fixture()]

    def test_samples_are_taken_every_100ms(self):
        trace = self.collect([{}, {}], self.same_host())
        self.assertIsNone(trace.get("collector_error"))
        times = [row["time"] for row in trace["samples"]]
        self.assertGreaterEqual(len(times), 840)
        self.assertLessEqual(max(b - a for a, b in zip(times, times[1:])), 0.2)

    def test_runtime_metadata_change_by_end_is_collector_error(self):
        trace = self.collect([{}, {"exe_identity": [8, 1003]}], self.same_host())
        self.assertEqual(trace.get("collector_error"), True)
        self.assertEqual(trace["assessment"], {"passed": False, "reason": "container-or-runtime-changed-during-observation"})

    def test_host_binary_change_by_end_is_collector_error(self):
        changed = dict(base.runtime_file_fixture(), sha256="e" * 64)
        trace = self.collect([{}, {}], [base.runtime_file_fixture(), changed])
        self.assertEqual(trace.get("collector_error"), True)
        self.assertEqual(trace["assessment"], {"passed": False, "reason": "host-runtime-changed-during-observation"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
