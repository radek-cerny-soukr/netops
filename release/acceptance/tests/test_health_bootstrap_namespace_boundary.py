import ctypes
import errno
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collect_health_bootstrap_trace as col

HOST = [5, 4026531836]
OWN = [5, 4026532585]
DESCENDANT = [5, 4026532586]


class NamespaceBoundary(unittest.TestCase):
    def test_mount_requires_authoritative_unrestricted_task_mount(self):
        scope = col.NamespaceScope.__new__(col.NamespaceScope)
        scope.ctypes = ctypes
        scope.identity = mock.Mock(return_value=[9, 1])
        def fstatfs(fd, buffer):
            ctypes.c_long.from_buffer(buffer).value = 0x9fa0
            return 0
        valid = b"42 1 0:9 / /proc rw,nosuid - proc proc rw\n"
        cases = ((b"mnt_id:\t42\n", valid, None),
                 (b"pos:\t0\n", valid, "procfs-mount-id-unavailable"),
                 (b"mnt_id:\t43\n", valid, "procfs-mount-not-bound-to-task-view"),
                 (b"mnt_id:\t42\n", valid.replace(b"rw,nosuid", b"rw,hidepid=2"), "restricted-or-unbound-procfs-view"),
                 (b"mnt_id:\t42\n", valid.replace(b"rw,nosuid", b"rw,subset=pid"), "restricted-or-unbound-procfs-view"),
                 (b"mnt_id:\t42\n", valid.replace(b"/ /proc", b"/subtree /proc"), "restricted-or-unbound-procfs-view"),
                 (b"mnt_id:\t42\n", valid.replace(b"- proc proc", b"- tmpfs proc"), "restricted-or-unbound-procfs-view"))
        for fdinfo, mountinfo, reason in cases:
            with self.subTest(reason=reason), mock.patch.object(ctypes, "CDLL", return_value=SimpleNamespace(fstatfs=fstatfs)), \
                    mock.patch.object(col, "read", return_value=fdinfo), \
                    mock.patch.object(col, "read_at", return_value=mountinfo):
                if reason is None:
                    proof = scope.mount(222, 11)
                    self.assertEqual((proof["magic"], proof["mount_id"], proof["root"], proof["hidepid"]), (0x9fa0, 42, "/", 0))
                else:
                    with self.assertRaises(col.EvidenceError) as caught:
                        scope.mount(222, 11)
                    self.assertEqual(caught.exception.args, (reason,))

    def test_inside_mapping_requires_matching_start_reverse_map_and_current_cgroup(self):
        for change in (None, "start", "reverse", "cgroup"):
            with self.subTest(change=change):
                scope = col.NamespaceScope.__new__(col.NamespaceScope)
                scope.host_identity, scope.ownproc, scope.ownns, scope.path = HOST, 333, 444, "/container"
                scope.inside_seen, scope.outside_seen, scope.inside_locals = set(), set(), {}
                handle = {"directory": 11, "pidfd": 12, "key": (700, 1000),
                          "evidence": {"procdir_identity": [9, 700]}}
                scope.pin = mock.Mock(return_value=handle)
                scope.namespace = mock.Mock(return_value=DESCENDANT)
                scope.ioctl = mock.Mock(side_effect=lambda fd, operation, pid: 700 if operation == 0x8004b706 else (18 if change == "reverse" else 17))
                def current_stat(path, *, dir_fd=None, follow_symlinks=True):
                    return SimpleNamespace(st_dev=78 if dir_fd == 333 else 9, st_ino=17 if dir_fd == 333 else 700)
                with mock.patch.object(col.os, "open", return_value=22), mock.patch.object(col.os, "close"), \
                        mock.patch.object(col.os, "fstat", return_value=SimpleNamespace(st_dev=78, st_ino=17)), \
                        mock.patch.object(col.os, "stat", side_effect=current_stat), \
                        mock.patch.object(col, "stat_at", return_value=((17, 1001 if change == "start" else 1000), 90)), \
                        mock.patch.object(col, "stat_detail_at", return_value=((700, 1000), 90, "R")), \
                        mock.patch.object(col, "pidfd_events", return_value=0), \
                        mock.patch.object(col, "cgroup_at", return_value="/foreign" if change == "cgroup" else "/container"):
                    if change is None:
                        proof = scope.inside(17, 700)
                        self.assertEqual((proof["key"], proof["local_pid"], proof["active_namespace"]), ([700, 1000], 17, DESCENDANT))
                    else:
                        with self.assertRaises(col.EvidenceError) as caught:
                            scope.inside(17, 700)
                        self.assertEqual(caught.exception.args, ("namespace-process-not-live-or-cgroup-changed" if change == "cgroup" else "inside-namespace-mapping-unstable",))
                        self.assertEqual(scope.inside_seen, set())

    def test_inventory_read_or_mapping_error_cannot_qualify_partial_sample(self):
        for change in (None, "list-denied", "mapping-vanished", "inside-denied"):
            with self.subTest(change=change):
                scope = col.NamespaceScope.__new__(col.NamespaceScope)
                scope.ownproc, scope.ownns = 333, 444
                scope.inside_seen, scope.inside_locals = {(100, 1000)}, {(100, 1000): 1}
                scope.parent_pins, scope.links, scope.unlinked, scope.child_reads = {}, {}, {}, {}
                scope.verify_authority = mock.Mock(return_value={"fixed": True})
                scope.inside = mock.Mock(return_value={"key": [100, 1000]})
                scope.ioctl = mock.Mock(return_value=100)
                if change == "mapping-vanished":
                    scope.ioctl.side_effect = ProcessLookupError(errno.ESRCH, "synthetic")
                if change == "inside-denied":
                    scope.inside.side_effect = PermissionError(errno.EACCES, "synthetic")
                with mock.patch.object(col.os, "listdir", side_effect=PermissionError(errno.EACCES, "synthetic") if change == "list-denied" else None, return_value=["1"]), \
                        mock.patch.object(col, "members", return_value={100}), mock.patch.object(col, "clock", return_value=100.0):
                    inventory = scope.inventory(None)
                    if change is None:
                        self.assertIs(inventory["complete"], True)
                        self.assertEqual(inventory["failures"], [])
                        continue
                    self.assertIs(inventory["complete"], False)
                    self.assertEqual([item["reason"] for item in inventory["failures"]], ["proc-read-or-schema-failed"])
                    with mock.patch.object(col, "process") as process, \
                            mock.patch.object(col, "shim", return_value={"fixed": True}), \
                            mock.patch.object(col, "proc_stat", return_value=((100, 1000), 90)), \
                            mock.patch.object(col, "cgroup_path", return_value="/container"):
                        sample = col.sample(None, "/container", (100, 1000), 90, "a" * 64, {}, {}, {}, 99.9, scope=scope)
                    process.assert_not_called()
                    self.assertIs(sample["complete"], False)
                    self.assertIs(sample["scope"]["closed"], False)
                    self.assertTrue(sample["failures"])
                    self.assertTrue(sample["scope"]["observed_failures"])


if __name__ == "__main__":
    unittest.main()
