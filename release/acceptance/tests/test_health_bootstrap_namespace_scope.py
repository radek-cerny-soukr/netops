import copy
import errno
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collect_health_bootstrap_trace as col
import health_bootstrap_profile as profile
import test_health_bootstrap_profile as base

HOST, OWN, DESCENDANT = [5, 4026531836], [5, 4026532585], [5, 4026532586]


def mount(device):
    return {"identity": [device, 1], "magic": 0x9fa0, "mount_id": device,
            "root": "/", "mountpoint": "/proc", "fstype": "proc", "hidepid": 0,
            "subset": "all", "mount_row_sha256": "e" * 64}


def scope_fixture(trace, outside=False):
    trace = copy.deepcopy(trace)
    trace["collector_schema"] = "health-bootstrap-trace-v5"
    header = {"method": "procfs-nsfs-pidfd-v1", "init": list(trace["init"]),
              "observer": [800, 500], "observer_namespace": list(HOST), "container_namespace": list(OWN),
              "container_parent_namespace": list(HOST), "host_proc": mount(9), "container_proc": mount(78),
              "host_proc_pid1": [1, 1], "host_proc_pid1_namespace": list(HOST),
              "max_capture_passes": 2, "snapshot_budget_seconds": .2}
    trace["scope"] = header
    authority = {"observer": [800, 500], "init": list(trace["init"]),
                 "observer_namespace": list(HOST), "container_namespace": list(OWN),
                 "host_proc_pid1_namespace": list(HOST), "host_proc_pid1": [1, 1],
                 "host_proc_self_pid": 800, "host_proc": header["host_proc"],
                 "container_proc": header["container_proc"], "pid1_host": trace["init"][0], "init_local_pid": 1}
    for sample in trace["samples"]:
        now = sample["time"]
        sample["read_started_at"] = now
        mappings = []
        for row in sample["processes"]:
            pid = row["key"][0]
            local = 1 if pid == trace["init"][0] else pid
            mappings.append({"local_pid": local, "key": list(row["key"]), "active_namespace": list(OWN),
                             "procdir_identity": [78, pid], "procdir_identity_after": [78, pid],
                             "binding": copy.deepcopy(row["binding"]),
                             "from_namespace": pid, "in_namespace": local, "verified_at": now})
        excluded = []
        if outside:
            binding = {"method": "procdir+pidfd", "key_before": [700, 9900], "key_after": [700, 9900],
                       "procdir_identity": [9, 700], "procdir_identity_after": [9, 700],
                       "cgroup": trace["cgroup"], "bound_at": 100.0}
            excluded = [{"key": [700, 9900], "active_namespace_before": list(HOST),
                         "active_namespace_after": list(HOST), "binding": binding,
                         "pidfd_alive_before": True, "pidfd_alive_after": True, "method": "held-active-host-pidns-v1",
                         "read_started_at": now, "read_finished_at": now}]
        raw = sorted(sample["pids"] + ([700] if outside else []))
        visible = sorted(item["local_pid"] for item in mappings)
        inventory = {"read_started_at": now, "read_finished_at": now, "mappings": mappings,
                     "excluded": excluded, "failures": [], "complete": True, "stable": True,
                     "authority_before": copy.deepcopy(authority), "authority_after": copy.deepcopy(authority),
                     "cgroup_pids": raw, "visible_pids": visible,
                     "end_cgroup_pids": list(raw), "end_visible_pids": list(visible)}
        sample["scope"] = {"inventories": [copy.deepcopy(inventory), copy.deepcopy(inventory)],
                           "capture_passes": 0, "observed_processes": copy.deepcopy(sample["processes"]),
                           "observed_failures": [], "closed": True}
    return trace


class ScopePredicate(unittest.TestCase):
    def fixture(self):
        return scope_fixture(base.observed_fixture(base.fixture()), outside=True)

    def assert_reject(self, trace):
        self.assertIs(profile.assess_trace(trace, require_scope=True)["passed"], False)

    def test_positive_host_exclusion_and_legacy_profile_equivalence(self):
        legacy = base.observed_fixture(base.fixture())
        current = scope_fixture(legacy, outside=True)
        self.assertEqual(profile.assess_trace(current, require_scope=True), profile.assess_trace(legacy))
        self.assertEqual(current["samples"][0]["pids"], [100, 101, 102, 103])
        self.assertIn(700, current["samples"][0]["scope"]["inventories"][0]["cgroup_pids"])

    def test_legacy_missing_header_and_downgrade_are_rejected(self):
        self.assert_reject(base.observed_fixture(base.fixture()))
        trace = self.fixture()
        del trace["scope"]
        self.assert_reject(trace)
        trace = self.fixture()
        trace["collector_schema"] = "health-bootstrap-trace-v4"
        self.assert_reject(trace)

    def test_observer_proc_pid1_or_self_mismatch_is_rejected(self):
        for field, value in (("host_proc_pid1_namespace", OWN), ("host_proc_self_pid", 999)):
            with self.subTest(field=field):
                trace = self.fixture()
                trace["samples"][0]["scope"]["inventories"][0]["authority_after"][field] = value
                self.assert_reject(trace)

    def test_namespace_parent_mount_and_hidden_proc_are_rejected(self):
        for change in ("parent", "mount", "hidepid", "subset"):
            with self.subTest(change=change):
                trace = self.fixture()
                if change == "parent":
                    trace["scope"]["container_parent_namespace"] = DESCENDANT
                elif change == "mount":
                    trace["scope"]["container_proc"]["root"] = "/subtree"
                elif change == "hidepid":
                    trace["scope"]["host_proc"]["hidepid"] = 2
                else:
                    trace["scope"]["container_proc"]["subset"] = "pid"
                self.assert_reject(trace)

    def test_descendant_foreign_dead_or_wrong_binding_cannot_be_excluded(self):
        for change in ("own", "descendant", "foreign", "dead", "key", "cgroup"):
            with self.subTest(change=change):
                trace = self.fixture()
                item = trace["samples"][0]["scope"]["inventories"][0]["excluded"][0]
                if change in ("own", "descendant", "foreign"):
                    item["active_namespace_before"] = item["active_namespace_after"] = {
                        "own": OWN, "descendant": DESCENDANT, "foreign": [5, 4026539999]}[change]
                elif change == "dead":
                    item["pidfd_alive_after"] = False
                elif change == "key":
                    item["binding"]["key_after"][1] += 1
                else:
                    item["binding"]["cgroup"] = "/foreign"
                self.assert_reject(trace)

    def test_descendant_inside_mapping_retains_full_permission_checks(self):
        trace = self.fixture()
        for sample in trace["samples"]:
            for inventory in sample["scope"]["inventories"]:
                inventory["mappings"][1]["active_namespace"] = list(DESCENDANT)
        self.assertTrue(profile.assess_trace(trace, require_scope=True)["passed"])
        trace["samples"][10]["processes"][1]["caps"]["eff"] = 1
        trace["samples"][10]["scope"]["observed_processes"][1]["caps"]["eff"] = 1
        self.assert_reject(trace)

    def test_unmapped_visible_unclassified_cgroup_and_reuse_are_rejected(self):
        for change in ("visible", "cgroup", "reuse"):
            with self.subTest(change=change):
                trace = self.fixture()
                inventory = trace["samples"][0]["scope"]["inventories"][0]
                if change == "visible":
                    inventory["visible_pids"].append(999)
                elif change == "cgroup":
                    inventory["cgroup_pids"].append(999)
                else:
                    inventory["mappings"][1]["binding"]["key_after"][1] += 1
                self.assert_reject(trace)

    def test_inside_cannot_later_be_excluded(self):
        trace = self.fixture()
        item = trace["samples"][1]["scope"]["inventories"][0]["excluded"][0]
        item["key"] = [101, 1000]
        self.assert_reject(trace)

    def test_prior_failure_observation_and_third_wave_cannot_be_hidden(self):
        for change in ("failure", "observation", "thirdwave", "budget"):
            with self.subTest(change=change):
                trace = self.fixture()
                sample = trace["samples"][1]
                proof = sample["scope"]
                if change == "failure":
                    proof["observed_failures"].append({"pid": 999, "reason": "unknown-firstseen-vanished"})
                elif change == "observation":
                    proof["observed_processes"].pop()
                elif change == "thirdwave":
                    proof["capture_passes"] = 3
                else:
                    sample["read_started_at"] -= .21
                self.assert_reject(trace)


class ScopeCollection(unittest.TestCase):
    def collect(self, inventories, *, failure=None, scoped=True, elapsed=0, module=None, raw_members=None, raw_sequence=None, vanished=None):
        module = col if module is None else module
        trace = base.observed_fixture(base.fixture())
        rows = {row["key"][0]: row for row in trace["samples"][0]["processes"]}
        host = 700
        for pid in (104, 105, 106, host):
            birth = 9900 if pid == host else 1000
            row = (base.root_health(pid=pid, birth=birth, argv=["runc", "init"]) if pid == host else
                   base.process(pid, birth, 51000, base.HEALTH, base.SHIM))
            binding = {"method": "procdir+pidfd", "key_before": [pid, birth], "key_after": [pid, birth],
                       "procdir_identity": [9, pid], "procdir_identity_after": [9, pid],
                       "cgroup": trace["cgroup"], "bound_at": 100.0}
            row.update(binding=binding, read_started_at=100.0, read_finished_at=100.0)
            rows[pid] = row
        captured = []
        def snapshot(pids, outside=True, stable=True):
            return {"mappings": [{"key": [pid, 1000]} for pid in sorted(pids)],
                    "excluded": [{"key": [host, 9900]}] if outside else [],
                    "failures": [], "complete": True, "stable": stable}
        entries = [entry if isinstance(entry, dict) else snapshot(*entry) if isinstance(entry, tuple) else snapshot(entry) for entry in inventories]
        scope = SimpleNamespace(inventory=mock.Mock(side_effect=entries), release=lambda: None)
        handles = {tuple(row["key"]): {"key": tuple(row["key"]), "evidence": row["binding"]} for row in rows.values()}
        def read_process(pid, *args):
            captured.append(pid)
            self.assertEqual(args[4]["key"], tuple(rows[pid]["key"]))
            self.assertEqual(args[4]["evidence"], rows[pid]["binding"])
            if pid == vanished:
                raise ProcessLookupError(errno.ESRCH, "synthetic")
            if failure is not None and pid == failure:
                raise module.EvidenceError("observed-profile-extra-terminal-capability")
            return copy.deepcopy(rows[pid])
        def stat(pid):
            return (tuple(rows[pid]["key"]), 90)
        times = [100.0]
        def clock():
            now = times[0]
            times[0] += elapsed
            return now
        use_scope = scoped and hasattr(module, "NamespaceScope")
        with mock.patch.object(module, "proc_stat", side_effect=stat), \
                mock.patch.object(module, "process", side_effect=read_process), \
                mock.patch.object(module, "shim", return_value=trace["samples"][0]["shim"]), \
                mock.patch.object(module, "cgroup_path", return_value=trace["cgroup"]), \
                mock.patch.object(module, "members", side_effect=raw_sequence, return_value={100, 101, 102, 103, host} if raw_members is None else raw_members), \
                mock.patch.object(module, "clock", side_effect=clock):
            args = (None, trace["cgroup"], (100, 1000), 90, base.CID, {}, {}, handles, 99.9)
            result = module.sample(*args, **({"scope": scope} if use_scope else {}))
        return result, captured, scope

    def test_positive_host_scope_does_not_capture_cgroup_only_runtime_parent(self):
        result, captured, _ = self.collect([{100, 101, 102, 103}] * 2)
        self.assertTrue(result["complete"])
        self.assertNotIn(700, captured)
        self.assertEqual(result["pids"], [100, 101, 102, 103])

    def test_new_inside_is_captured_same_transaction(self):
        initial = {100, 101, 102, 103}
        result, captured, _ = self.collect([initial, initial | {104}, initial | {104}],
                                             raw_sequence=[initial, initial | {104}])
        self.assertTrue(result["complete"])
        self.assertEqual(captured.count(104), 1)
        self.assertEqual(result["scope"]["capture_passes"], 1)
        self.assertEqual({tuple(row["key"]) for row in result["scope"]["observed_processes"]},
                         {(pid, 1000) for pid in initial | {104}})

    def test_third_inside_wave_is_incomplete(self):
        initial = {100, 101, 102, 103}
        result, _, _ = self.collect([initial, initial | {104}, initial | {104, 105}, initial | {104, 105, 106}])
        self.assertFalse(result["complete"])
        self.assertIn("namespace-discovery-limit", [item["reason"] for item in result["failures"]])
        self.assertEqual(result["scope"]["capture_passes"], 2)

    def test_third_host_only_wave_also_consumes_discovery_budget(self):
        initial = {100, 101, 102, 103}
        entries = [{"mappings": [{"key": [pid, 1000]} for pid in initial],
                    "excluded": [{"key": [700 + i, 9900]} for i in range(count)],
                    "complete": True, "failures": [], "stable": True} for count in (0, 1, 2, 3)]
        result, captured, _ = self.collect(entries)
        self.assertFalse(result["complete"])
        self.assertEqual(result["scope"]["capture_passes"], 2)
        self.assertEqual(captured, [100, 101, 102, 103])
        self.assertIn("namespace-discovery-limit", [item["reason"] for item in result["failures"]])

    def test_unsafe_capture_failure_carries_through_closed_membership(self):
        initial = {100, 101, 102, 103}
        result, _, _ = self.collect([initial, initial | {104}, initial | {104}], failure=104)
        self.assertFalse(result["complete"])
        self.assertEqual(result["failures"][0]["reason"], "observed-profile-extra-terminal-capability")
        self.assertEqual(result["scope"]["observed_failures"][0]["reason"], result["failures"][0]["reason"])

    def test_unknown_first_seen_unreadable_remains_failure(self):
        initial = {100, 101, 102, 103}
        result, _, _ = self.collect([initial, initial | {104}, initial | {104}], vanished=104)
        self.assertFalse(result["complete"])
        self.assertEqual(result["exit_proofs"], [])
        self.assertIn({"pid": 104, "reason": "proc-read-or-schema-failed", "partial_observation": {"pid": 104},
                       "error": "ProcessLookupError", "errno": errno.ESRCH},
                      result["failures"])
        self.assertEqual(result["scope"]["observed_failures"], result["failures"])

    def test_first_seen_vanish_does_not_borrow_exit_proof(self):
        initial = {100, 101, 102, 103}
        result, _, _ = self.collect([initial | {104}, initial])
        self.assertFalse(result["complete"])
        self.assertIn({"pid": 104, "reason": "unclassified-transient-process"}, result["failures"])
        self.assertIn([104, 1000], [row["key"] for row in result["scope"]["observed_processes"]])

    def test_snapshot_budget_remains_two_hundred_ms(self):
        initial = {100, 101, 102, 103}
        result, _, _ = self.collect([initial, initial], elapsed=.21)
        self.assertFalse(result["complete"])
        self.assertIn("namespace-snapshot-budget-exceeded", [item["reason"] for item in result["failures"]])


class ScopeKernelGuards(unittest.TestCase):
    def scope(self):
        scope = col.NamespaceScope.__new__(col.NamespaceScope)
        scope.path, scope.host_identity, scope.own_identity = "/container", list(HOST), list(OWN)
        scope.inside_seen, scope.outside_seen = set(), set()
        handle = {"directory": 11, "key": (700, 9900), "evidence": {"synthetic": True}}
        scope.pin = mock.Mock(return_value=handle)
        scope.live = mock.Mock()
        scope.namespace = mock.Mock(return_value=list(HOST))
        return scope

    def test_outside_requires_same_live_host_namespace_before_after(self):
        scope = self.scope()
        proof = scope.outside(700)
        self.assertTrue(proof["pidfd_alive_before"] and proof["pidfd_alive_after"])
        self.assertEqual(scope.live.call_count, 2)
        for namespaces in ((OWN, OWN), (DESCENDANT, DESCENDANT), (HOST, OWN)):
            with self.subTest(namespaces=namespaces):
                scope = self.scope()
                scope.namespace.side_effect = namespaces
                with self.assertRaises(col.EvidenceError):
                    scope.outside(700)

    def test_host_proc_pid1_namespace_and_numeric_self_are_mandatory(self):
        for kind in ("pid1-namespace", "numeric-self"):
            with self.subTest(kind=kind):
                scope = col.NamespaceScope.__new__(col.NamespaceScope)
                scope.hostproc, scope.host_pid1, scope.ownproc = 222, 111, 333
                scope.host_identity, scope.own_identity = list(HOST), list(OWN)
                scope.observer = {"directory": 555, "key": (800, 500), "evidence": {"cgroup": "/observer"}}
                scope.init_handle, scope.init, scope.path = {"directory": 444}, (100, 1000), "/container"
                scope.host_pid1_key = (1, 1)
                scope.live = mock.Mock()
                scope.identity = mock.Mock(return_value=[9, 1])
                scope.namespace = mock.Mock(side_effect=lambda fd: OWN if fd == 444 or
                                            fd == 111 and kind == "pid1-namespace" else HOST)
                with mock.patch.object(col.os, "stat", return_value=SimpleNamespace(st_dev=9, st_ino=1)), \
                        mock.patch.object(col, "stat_at", return_value=((1, 1), 0)), \
                        mock.patch.object(col.os, "readlink", return_value="999"), \
                        mock.patch.object(col.os, "getpid", return_value=800):
                    with self.assertRaises(col.EvidenceError) as caught:
                        scope.verify_authority()
                self.assertEqual(caught.exception.args[0], "observer-host-proc-pid1-namespace-unbound" if
                                 kind == "pid1-namespace" else "observer-proc-self-unbound")

    def test_unreadable_dead_or_previously_inside_cannot_be_excluded(self):
        for kind in ("denied", "vanished", "inside"):
            with self.subTest(kind=kind):
                scope = self.scope()
                if kind == "denied":
                    scope.namespace.side_effect = PermissionError(errno.EACCES, "synthetic")
                elif kind == "vanished":
                    scope.live.side_effect = ProcessLookupError(errno.ESRCH, "synthetic")
                else:
                    scope.inside_seen.add((700, 9900))
                with self.assertRaises((OSError, col.EvidenceError)):
                    scope.outside(700)


if __name__ == "__main__":
    unittest.main()
