import contextlib
import copy
import errno
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collect_health_bootstrap_trace as col
import health_bootstrap_profile as profile
import test_health_bootstrap_profile as base
import test_health_bootstrap_namespace_scope as scope_base

CID = base.CID
KEY = (200, 10100)
CGROUP = "/qa/docker-" + CID + ".scope"
HEALTH = tuple(base.HEALTH)
SHIM = {"key": [90, 900], "exe": "/usr/bin/containerd-shim-runc-v2", "exe_identity": [8, 1001],
        "argv": ["/usr/bin/containerd-shim-runc-v2", "-namespace", "moby", "-id", CID,
                 "-address", "/run/containerd/containerd.sock"]}
HOST, OWN = [5, 4026531836], [5, 4026532585]
TRANSITION = getattr(col, "RuntimeExecTransition", col.EvidenceError)
SAME_EXE = ((88, 1002), (88, 1002))
FACTS = {"key": list(KEY), "cgroup": CGROUP, "first_argv": ["runc", "init"], "second_argv": list(HEALTH)}


@contextlib.contextmanager
def raises(test, kind):
    caught = SimpleNamespace(exception=None)
    try:
        yield caught
    except Exception as error:
        test.assertIsInstance(error, kind)
        caught.exception = error
    else:
        test.fail("%s not raised" % kind.__name__)



class ExecTransitionDuringRetry(unittest.TestCase):
    def retry(self, *, commands=(("runc", "init"), HEALTH), stats=((KEY, 95), (KEY, 95)),
              cgroups=(CGROUP, CGROUP), exe=((88, 1002), (88, 5555))):
        handle = {"key": KEY, "directory": 11, "pidfd": 12, "evidence": {}}
        identities = [SimpleNamespace(st_dev=dev, st_ino=ino) for dev, ino in exe]
        with mock.patch.object(col, "clock", return_value=101.09), \
                mock.patch.object(col, "check_binding"), \
                mock.patch.object(col, "stat_at", side_effect=list(stats)), \
                mock.patch.object(col.os, "stat", side_effect=identities), \
                mock.patch.object(col, "command", side_effect=list(commands)), \
                mock.patch.object(col, "cgroup_at", side_effect=list(cgroups)), \
                mock.patch.object(col, "identity_maps"), \
                mock.patch.object(col, "shim", return_value=copy.deepcopy(SHIM)), \
                mock.patch.object(col, "runtime_parent", side_effect=FileNotFoundError(errno.ENOENT, "parent")):
            return col.runtime_parent_after_enoent(handle, KEY, 90, CID, base.runtime_fixture(), CGROUP, [88, 1002])

    def original_error(self, **kwargs):
        with raises(self, col.EvidenceError) as caught:
            self.retry(**kwargs)
        self.assertNotIsInstance(caught.exception, getattr(col, "RuntimeExecTransition", ()))
        self.assertEqual(caught.exception.args, ("runtime-parent-retry-child-changed",))

    def test_same_key_and_cgroup_exec_into_health_is_transition(self):
        with raises(self, col.RuntimeExecTransition) as caught:
            self.retry()
        self.assertEqual(caught.exception.args, ("runtime-exec-transition-during-retry", {"key": list(KEY), "cgroup": CGROUP,
                                                                                          "first_argv": ["runc", "init"],
                                                                                          "second_argv": list(HEALTH)}))
        self.assertIsInstance(caught.exception, col.EvidenceError)

    def test_every_known_product_command_is_transition_and_runtime_is_not(self):
        commands = [base.HEALTH, ["/usr/local/bin/python", "/usr/local/bin/netops", "serve"]]
        commands += [["/usr/local/bin/python", "-m", "netops", "worker", role] for role in ("helper", "auditor", "admin")]
        for argv in commands:
            with self.subTest(argv=argv):
                self.assertTrue(col.product_command(tuple(argv)))
                if argv == base.HEALTH:
                    with raises(self, col.RuntimeExecTransition):
                        self.retry(commands=(("runc", "init"), tuple(argv)))
                else:
                    self.original_error(commands=(("runc", "init"), tuple(argv)), exe=SAME_EXE)
        for argv in (("runc", "init"), ("/usr/local/bin/python", "-m", "netops", "worker", "root"),
                     ("sh", "-c", "id"), tuple(base.HEALTH) + ("--x",)):
            with self.subTest(argv=argv):
                self.assertFalse(col.product_command(argv))

    def test_unknown_command_after_retry_keeps_original_error(self):
        self.original_error(commands=(("runc", "init"), ("sh", "-c", "id")), exe=SAME_EXE)

    def test_changed_key_keeps_original_error(self):
        self.original_error(stats=((KEY, 95), ((200, 10101), 95)), exe=SAME_EXE)

    def test_changed_cgroup_keeps_original_error(self):
        self.original_error(cgroups=(CGROUP, "/foreign"), exe=SAME_EXE)

    def test_unchanged_runc_init_still_retries_until_exhausted(self):
        handle_retry = dict(commands=[("runc", "init")] * 6, stats=[(KEY, 95)] * 6,
                            cgroups=[CGROUP] * 6, exe=[(88, 1002)] * 6)
        with self.assertRaisesRegex(col.EvidenceError, "runtime-parent-retry-exhausted"):
            self.retry(**handle_retry)


class ExecTransitionCapture(unittest.TestCase):
    def capture(self, outcomes):
        handle = {"key": KEY, "directory": 11, "pidfd": 12, "evidence": {"synthetic": True}}
        health = base.root_health()
        health.update(read_started_at=100.0, read_finished_at=100.0, binding=handle["evidence"])
        calls = []

        def read_process(pid, path, shim_pid, cid, runtime, bound, previous, partial):
            calls.append((pid, bound, partial, dict(partial)))
            partial.update(key=list(KEY), argv=["runc", "init"])
            if len(calls) > len(outcomes):
                raise AssertionError("unexpected re-read %d" % len(calls))
            outcome = outcomes[len(calls) - 1]
            if isinstance(outcome, BaseException):
                raise outcome
            return copy.deepcopy(health)

        with mock.patch.object(col, "members", return_value={200}), \
                mock.patch.object(col, "proc_stat", return_value=(KEY, 90)), \
                mock.patch.object(col, "process", side_effect=read_process), \
                mock.patch.object(col, "shim", return_value=copy.deepcopy(SHIM)), \
                mock.patch.object(col, "cgroup_path", return_value=CGROUP):
            result = col.sample(None, CGROUP, KEY, 90, CID, {}, base.runtime_fixture(), {KEY: handle}, 99.9)
        return result, calls, handle

    def test_transition_is_read_again_exactly_once_with_same_handle(self):
        result, calls, handle = self.capture([TRANSITION("runtime-exec-transition-during-retry"), None])
        self.assertEqual(len(calls), 2)
        self.assertIs(calls[0][1], handle)
        self.assertIs(calls[1][1], handle)
        self.assertIsNot(calls[0][2], calls[1][2])
        self.assertEqual(calls[1][3], {"pid": 200})
        self.assertEqual(result["failures"], [])
        self.assertIs(result["complete"], True)
        self.assertEqual([row["argv"] for row in result["processes"]], [list(HEALTH)])

    def test_up_to_three_rereads_are_recorded(self):
        result, calls, handle = self.capture([TRANSITION("runtime-exec-transition-during-retry", FACTS)] * 3 + [None])
        self.assertEqual(len(calls), 4)
        self.assertIs(result["complete"], True)
        self.assertEqual([item["binding"] for item in result["processes"][0].get("exec_transitions", [])], [handle["evidence"]] * 3)
        self.assertEqual([item["facts"] for item in result["processes"][0].get("exec_transitions", [])], [FACTS] * 3)
        self.assertEqual([item["reason"] for item in result["processes"][0].get("exec_transitions", [])],
                         ["runtime-exec-transition-during-retry"] * 3)

    def test_fourth_transition_is_failure(self):
        result, calls, _ = self.capture([TRANSITION("runtime-exec-transition-during-retry")] * 4)
        self.assertIs(result["complete"], False)
        self.assertEqual(result["processes"], [])
        self.assertEqual([item["reason"] for item in result["failures"]], ["runtime-exec-transition-limit"])
        self.assertEqual(result["failures"][0]["pid"], 200)
        self.assertEqual(len(result["failures"][0].get("attempts", [])), 4)
        self.assertEqual(result["failures"][0].get("attempts", [{}])[0].get("partial", {}).get("pid"), 200)

    def test_fourth_transition_is_not_retried_again(self):
        _, calls, _ = self.capture([col.RuntimeExecTransition("runtime-exec-transition-during-retry")] * 6)
        self.assertEqual(len(calls), 4)

    def test_other_error_on_second_read_is_handled_as_before(self):
        result, calls, _ = self.capture([TRANSITION("runtime-exec-transition-during-retry"),
                                         col.EvidenceError("observed-profile-extra-terminal-capability")])
        self.assertIs(result["complete"], False)
        self.assertIn("observed-profile-extra-terminal-capability", [item["reason"] for item in result["failures"]])
        self.assertNotIn("runtime-exec-transition-during-retry", [item["reason"] for item in result["failures"]])
        failure = [item for item in result["failures"] if item["reason"] == "observed-profile-extra-terminal-capability"][0]
        self.assertEqual([item["reason"] for item in failure.get("attempts", [])], ["runtime-exec-transition-during-retry"])

    def test_plain_evidence_error_is_never_retried(self):
        result, calls, _ = self.capture([col.EvidenceError("runtime-parent-retry-child-changed"), None])
        self.assertEqual(len(calls), 1)
        self.assertIs(result["complete"], False)
        self.assertEqual([item["reason"] for item in result["failures"]], ["runtime-parent-retry-child-changed"])


class VanishedDuringInventory(unittest.TestCase):
    def inventory(self, *, raw, after_error, end, pin_errors, inside_seen=((100, 1000), (101, 1000), (102, 1000), (103, 1000), (104, 1000))):
        scope = col.NamespaceScope.__new__(col.NamespaceScope)
        scope.path, scope.ownproc, scope.ownns = "/container", 333, 444
        scope.host_identity, scope.own_identity = list(HOST), list(OWN)
        scope.inside_seen, scope.outside_seen = set(inside_seen), set()
        locals_ = {100: 1, 101: 8, 102: 9, 103: 10, 104: 11}
        scope.inside_locals = {key: locals_[key[0]] for key in inside_seen}
        scope.handles = {key: {"key": key, "pidfd": 50 + key[0] - 100, "directory": 60 + key[0] - 100} for key in inside_seen}
        scope.identities, scope.context, scope.parents, scope.hostproc = {}, (90, CID, base.runtime_fixture()), {}, 222
        scope.parent_pins, scope.links, scope.unlinked, scope.child_reads = {}, {}, {}, {}
        pins = []

        def pin(pid, path):
            pins.append(pid)
            if pid in pin_errors:
                raise pin_errors[pid]
            raise AssertionError("unexpected pin %d" % pid)

        def ioctl(fd, operation, pid):
            self.assertEqual(operation, 0x8004b706)
            return {1: 100, 8: 101, 9: 102, 10: 103}[pid]

        def first_read(pid):
            if pid in pin_errors and pid in {key[0] for key in inside_seen}:
                raise pin_errors[pid]
            return (pid, 1000), 90

        scope.pin = mock.Mock(side_effect=pin)
        scope.live = mock.Mock()
        scope.namespace = mock.Mock(return_value=list(HOST))
        scope.verify_authority = mock.Mock(return_value={"fixed": True})
        scope.inside = mock.Mock(side_effect=lambda local, host: {"key": [host, 1000], "local_pid": local})
        scope.ioctl = mock.Mock(side_effect=ioctl)
        sequence = [set(raw)] + [set(item) for item in after_error] + [set(end)]
        with mock.patch.object(col, "members", side_effect=sequence) as members, \
                mock.patch.object(col.os, "listdir", return_value=["1", "8", "9", "10"]), \
                mock.patch.object(col, "pidfd_events", return_value=1), \
                mock.patch.object(col, "stat_detail_at", side_effect=FileNotFoundError(errno.ENOENT, "synthetic")), \
                mock.patch.object(col, "proc_stat", side_effect=lambda pid: first_read(pid)), \
                mock.patch.object(col.os, "open", side_effect=FileNotFoundError(errno.ENOENT, "synthetic")), \
                mock.patch.object(col, "runtime_parent", side_effect=col.EvidenceError("runtime-parent-foreign-shim")), \
                mock.patch.object(col.os, "stat", side_effect=FileNotFoundError(errno.ENOENT, "synthetic")), \
                mock.patch.object(col, "clock", return_value=100.0):
            result = scope.inventory(None)
        return result, pins, members

    def test_known_inside_pid_vanished_before_classification_is_recorded(self):
        stable = {100, 101, 102, 103}
        result, pins, members = self.inventory(raw=stable | {104}, after_error=[stable], end=stable,
                                               pin_errors={104: ProcessLookupError(errno.ESRCH, "synthetic")})
        self.assertIs(result["complete"], True)
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["vanished"], [{"pid": 104, "key": [104, 1000], "local_pid": 11, "stage": "classify-host",
                                               "error": "ProcessLookupError", "errno": errno.ESRCH, "verified_absent_at": 100.0}])
        self.assertEqual(result["cgroup_pids"], [100, 101, 102, 103, 104])
        self.assertEqual(result["end_cgroup_pids"], [100, 101, 102, 103])
        self.assertIs(result["stable"], False)
        self.assertEqual(members.call_count, 3)
        self.assertEqual(pins, [])

    def test_new_pid_vanished_in_first_loop_is_failure(self):
        stable = {100, 101, 102, 103}
        result, pins, members = self.inventory(raw=stable | {700}, after_error=[stable], end=stable,
                                               pin_errors={700: FileNotFoundError(errno.ENOENT, "synthetic")})
        self.assertIs(result["complete"], False)
        self.assertEqual(result["vanished"], [])
        self.assertEqual(result["failures"], [{"reason": "proc-read-or-schema-failed", "error": "FileNotFoundError", "errno": errno.ENOENT,
                                               "diagnostic": {"stage": "classify-host-first", "pid": 700, "point": "retire-no-parent-link",
                                                              "operation": None}}])
        self.assertEqual(pins, [700])
        self.assertEqual(result["excluded"], [])

    def test_pid_still_member_after_error_remains_failure(self):
        stable = {100, 101, 102, 103}
        result, _, members = self.inventory(raw=stable | {104}, after_error=[stable | {104}], end=stable,
                                            pin_errors={104: ProcessLookupError(errno.ESRCH, "synthetic")})
        self.assertIs(result["complete"], False)
        self.assertTrue(result["failures"])
        self.assertEqual(result.get("vanished", []), [])

    def test_permission_error_is_not_vanished(self):
        stable = {100, 101, 102, 103}
        result, _, members = self.inventory(raw=stable | {104}, after_error=[], end=stable,
                                            pin_errors={104: PermissionError(errno.EACCES, "synthetic")})
        self.assertIs(result["complete"], False)
        self.assertTrue(result["failures"])
        self.assertEqual(result.get("vanished", []), [])
        self.assertEqual(members.call_count, 1)

    def test_evidence_error_is_not_vanished(self):
        stable = {100, 101, 102, 103}
        result, _, members = self.inventory(raw=stable | {104}, after_error=[], end=stable,
                                            pin_errors={104: col.EvidenceError("namespace-process-reused-during-pin")})
        self.assertIs(result["complete"], False)
        self.assertEqual(result["failures"], [{"reason": "namespace-process-reused-during-pin",
                                               "diagnostic": {"stage": "classify-host-second", "pid": 104, "point": None, "operation": None}}])
        self.assertEqual(result.get("vanished", []), [])
        self.assertEqual(members.call_count, 1)




def vanished_fixture():
    trace = base.fixture()
    base.insert(trace, 10, 13, base.root_health(argv=["runc", "init"]))
    base.insert(trace, 13, 17, base.process(200, 10100, 51000, base.HEALTH, base.SHIM))
    trace["samples"][17]["exited"] = [[200, 10100]]
    legacy = base.observed_fixture(trace)
    scoped = scope_base.scope_fixture(legacy, outside=True)
    sample = scoped["samples"][17]
    first = sample["scope"]["inventories"][0]
    first["cgroup_pids"] = sorted(first["cgroup_pids"] + [200])
    first["stable"] = False
    first["vanished"] = [{"pid": 200, "key": [200, 10100], "local_pid": 200, "stage": "classify-host",
                          "error": "ProcessLookupError", "errno": errno.ESRCH, "verified_absent_at": sample["time"]}]
    return legacy, scoped


FIXED = hasattr(col, "RuntimeExecTransition")


class VanishedProfile(unittest.TestCase):
    def assess(self, trace):
        return profile.assess_trace(trace, require_scope=True)

    def reject(self, trace, reason="unproven-vanished-cgroup-process"):
        result = self.assess(trace)
        self.assertIs(result["passed"], False)
        if FIXED:
            self.assertEqual(result["reason"], reason)

    def first(self, trace):
        return trace["samples"][17]["scope"]["inventories"][0]

    def item(self, trace):
        return self.first(trace)["vanished"][0]

    def add_exit_proof(self, trace, key):
        sample = trace["samples"][17]
        sample["exit_proofs"].append(dict(copy.deepcopy(sample["exit_proofs"][0]), key=list(key)))

    def test_proven_vanished_pid_passes_like_legacy(self):
        legacy, scoped = vanished_fixture()
        self.assertEqual([proof["key"] for proof in scoped["samples"][17]["exit_proofs"]], [[200, 10100]])
        expected = profile.assess_trace(legacy)
        self.assertIs(expected["passed"], True)
        self.assertEqual(self.assess(scoped), expected)

    def test_unlisted_vanished_pid_is_still_unclassified(self):
        _, scoped = vanished_fixture()
        del self.first(scoped)["vanished"]
        self.reject(scoped, "cgroup-process-unclassified")

    def test_vanished_without_exit_proof_is_rejected(self):
        _, scoped = vanished_fixture()
        scoped["samples"][17]["exit_proofs"] = []
        self.reject(scoped)
        _, scoped = vanished_fixture()
        self.item(scoped)["pid"] = 104
        self.first(scoped)["cgroup_pids"] = sorted(self.first(scoped)["cgroup_pids"] + [104])
        self.reject(scoped)

    def test_vanished_pid_still_in_end_membership_is_rejected(self):
        _, scoped = vanished_fixture()
        first = self.first(scoped)
        first["end_cgroup_pids"] = sorted(first["end_cgroup_pids"] + [200])
        self.reject(scoped)

    def test_vanished_in_last_inventory_is_rejected(self):
        _, scoped = vanished_fixture()
        inventories = scoped["samples"][17]["scope"]["inventories"]
        last = inventories[-1]
        last["vanished"] = copy.deepcopy(inventories[0]["vanished"])
        last["cgroup_pids"] = sorted(last["cgroup_pids"] + [200])
        last["stable"] = False
        self.reject(scoped)

    def test_vanished_marker_fields_are_exact(self):
        cases = (("stage", "inside"), ("stage", None), ("error", "PermissionError"), ("error", "OSError"),
                 ("error", None), ("verified_absent_at", 99.0), ("verified_absent_at", 1000.0),
                 ("verified_absent_at", None), ("verified_absent_at", True),
                 ("verified_absent_at", float("nan")), ("pid", "200"), ("pid", True), ("pid", None))
        for field, value in cases:
            with self.subTest(field=field, value=value):
                _, scoped = vanished_fixture()
                if value is None:
                    del self.item(scoped)[field]
                else:
                    self.item(scoped)[field] = value
                self.reject(scoped)
        for value in ("not-a-list", {"pid": 200}, ["entry"], None):
            with self.subTest(vanished=value):
                _, scoped = vanished_fixture()
                self.first(scoped)["vanished"] = value
                self.reject(scoped)

    def test_duplicate_vanished_is_rejected(self):
        _, scoped = vanished_fixture()
        first = self.first(scoped)
        first["vanished"].append(copy.deepcopy(first["vanished"][0]))
        self.reject(scoped)

    def test_vanished_pid_mapped_or_excluded_is_rejected(self):
        for case in ("mapped-role", "mapped-same-key", "excluded"):
            with self.subTest(case=case):
                _, scoped = vanished_fixture()
                first = self.first(scoped)
                if case == "mapped-role":
                    first["vanished"].append(dict(self.item(scoped), pid=101))
                    self.add_exit_proof(scoped, (101, 1000))
                elif case == "excluded":
                    first["vanished"].append(dict(self.item(scoped), pid=700))
                    first["end_cgroup_pids"].remove(700)
                    self.add_exit_proof(scoped, (700, 9900))
                else:
                    row = copy.deepcopy(first["mappings"][1])
                    row.update(key=[200, 10100], local_pid=200, from_namespace=200, in_namespace=200)
                    row["binding"] = copy.deepcopy(scoped["samples"][16]["processes"][-1]["binding"])
                    first["mappings"].append(row)
                    first["visible_pids"] = sorted(first["visible_pids"] + [200])
                self.reject(scoped)


if __name__ == "__main__":
    unittest.main(verbosity=2)
