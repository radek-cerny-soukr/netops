import copy
import errno
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if "--old" in sys.argv:
    sys.argv.remove("--old")
    ROOT = ROOT.parent / "old"
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT))
import collect_health_bootstrap_trace as col
import health_bootstrap_profile as profile
import test_health_bootstrap_profile as base
import test_health_bootstrap_namespace_scope as scope_base

HOST, OWN, FOREIGN = [5, 4026531836], [5, 4026532585], [5, 4026539999]


class HeldHostClassification(unittest.TestCase):
    def inventory(self, *, active=HOST, pin_error=None, live_error=None, remap=False, inverse_error=None):
        scope = col.NamespaceScope.__new__(col.NamespaceScope)
        scope.path, scope.ownproc, scope.ownns = "/container", 333, 444
        scope.host_identity, scope.own_identity = list(HOST), list(OWN)
        scope.inside_seen = {(100, 1000), (101, 1000), (102, 1000), (103, 1000)}
        scope.outside_seen, scope.inside_locals, scope.identities, scope.parents = set(), {}, {}, {}
        scope.handles, scope.context, scope.hostproc, scope.parent_pins, scope.links = {}, (90, "a" * 64, {}), 222, {}, {}
        scope.unlinked, scope.child_reads = {}, {}
        scope.identify = mock.Mock()
        state = {"visible_started": False, "pinned_before_visible": False, "inverse": []}
        handle = {"directory": 11, "pidfd": 12, "key": (700, 9900),
                  "evidence": {"method": "procdir+pidfd", "key_before": [700, 9900],
                               "key_after": [700, 9900], "procdir_identity": [9, 700],
                               "procdir_identity_after": [9, 700], "cgroup": "/container",
                               "bound_at": 100.0}}
        def pin(pid, path):
            self.assertEqual((pid, path), (700, "/container"))
            if pin_error is not None:
                raise pin_error
            state["pinned_before_visible"] = not state["visible_started"]
            return handle
        def inside(local, host):
            state["visible_started"] = True
            return {"key": [host, 1000], "local_pid": local}
        def ioctl(fd, operation, pid):
            if operation == 0x8004b706:
                return {1: 100, 8: 101, 9: 102, 10: 103}[pid]
            self.assertEqual((operation, pid), (0x8004b708, 700))
            state["inverse"].append(pid)
            if inverse_error is not None:
                raise inverse_error
            if active == HOST:
                raise OSError(errno.ENOTTY, "synthetic task vanished before inverse map")
            return 17
        scope.pin = mock.Mock(side_effect=pin)
        scope.live = mock.Mock(side_effect=live_error)
        scope.namespace = mock.Mock(side_effect=[list(active), list(active), list(OWN)] if remap else None,
                                    return_value=list(active))
        scope.verify_authority = mock.Mock(return_value={"fixed": True})
        scope.inside = mock.Mock(side_effect=inside)
        scope.ioctl = mock.Mock(side_effect=ioctl)
        with mock.patch.object(col, "members", return_value={100, 101, 102, 103, 700}), \
                mock.patch.object(col, "proc_stat", return_value=((700, 9900), 95)), \
                mock.patch.object(col.os, "listdir", return_value=["1", "8", "9", "10"]), \
                mock.patch.object(col, "clock", return_value=100.0):
            result = scope.inventory(None)
        return result, scope, state

    def test_new_host_is_proved_before_visible_mappings_without_inverse(self):
        result, scope, state = self.inventory()
        self.assertIs(result["complete"], True)
        self.assertEqual(result["failures"], [])
        self.assertTrue(state["pinned_before_visible"])
        self.assertEqual(state["inverse"], [])
        self.assertEqual(len(result["excluded"]), 1)
        proof = result["excluded"][0]
        self.assertEqual(proof["method"], "held-active-host-pidns-v1")
        self.assertEqual(proof["key"], [700, 9900])
        self.assertNotIn("in_namespace_errno", proof)
        self.assertEqual(proof["active_namespace_before"], HOST)
        self.assertEqual(proof["active_namespace_after"], HOST)
        self.assertIs(proof["pidfd_alive_before"], True)
        self.assertIs(proof["pidfd_alive_after"], True)
        scope.inside.assert_any_call(1, 100)

    def test_inside_cgroup_only_is_mapped_and_not_dropped(self):
        result, scope, state = self.inventory(active=OWN)
        self.assertIs(result["complete"], True)
        self.assertEqual(result["excluded"], [])
        self.assertEqual(state["inverse"], [700])
        scope.inside.assert_any_call(17, 700)
        self.assertIn([700, 1000], [row["key"] for row in result["mappings"]])

    def test_foreign_namespace_unknown_is_failure_not_outside(self):
        result, _, _ = self.inventory(active=FOREIGN, inverse_error=OSError(errno.ENOTTY, "synthetic"))
        self.assertIs(result["complete"], False)
        self.assertEqual(result["excluded"], [])
        self.assertTrue(result["failures"])

    def test_dead_remapped_denied_or_unknown_cannot_be_excluded(self):
        cases = ({"pin_error": PermissionError(errno.EACCES, "synthetic")},
                 {"pin_error": ProcessLookupError(errno.ESRCH, "synthetic")},
                 {"live_error": ProcessLookupError(errno.ESRCH, "synthetic")},
                 {"live_error": col.EvidenceError("process-reused-during-binding")},
                 {"remap": True})
        for case in cases:
            with self.subTest(case=tuple(case)):
                result, _, _ = self.inventory(**case)
                self.assertIs(result["complete"], False)
                self.assertEqual(result["excluded"], [])
                self.assertTrue(result["failures"])

    def fixture(self):
        return scope_base.scope_fixture(base.observed_fixture(base.fixture()), outside=True)

    def test_valid_marker_is_required_and_errno_cannot_substitute(self):
        valid = self.fixture()
        self.assertIs(profile.assess_trace(valid, require_scope=True)["passed"], True)
        for change in ("missing", "legacy", "boolean", "wrong"):
            with self.subTest(change=change):
                trace = copy.deepcopy(valid)
                item = trace["samples"][0]["scope"]["inventories"][0]["excluded"][0]
                if change in ("missing", "legacy"):
                    del item["method"]
                    if change == "legacy":
                        item["in_namespace_errno"] = 3
                else:
                    item["method"] = True if change == "boolean" else "other"
                self.assertIs(profile.assess_trace(trace, require_scope=True)["passed"], False)

    def test_marker_does_not_waive_ns_key_liveness_or_product_permissions(self):
        valid = self.fixture()
        self.assertIs(profile.assess_trace(valid, require_scope=True)["passed"], True)
        for change in ("own", "foreign", "dead", "key", "root-product"):
            with self.subTest(change=change):
                trace = copy.deepcopy(valid)
                item = trace["samples"][0]["scope"]["inventories"][0]["excluded"][0]
                if change in ("own", "foreign"):
                    item["active_namespace_before"] = item["active_namespace_after"] = list(OWN if change == "own" else FOREIGN)
                elif change == "dead":
                    item["pidfd_alive_after"] = False
                elif change == "key":
                    item["binding"]["key_after"][1] += 1
                else:
                    row = trace["samples"][0]["processes"][1]
                    row["uids"] = [0] * 4
                    trace["samples"][0]["scope"]["observed_processes"][1]["uids"] = [0] * 4
                self.assertIs(profile.assess_trace(trace, require_scope=True)["passed"], False)


if __name__ == "__main__":
    unittest.main()
