from pathlib import Path
import hashlib
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collect_health_bootstrap_trace as col
import test_health_bootstrap_profile as base

CID = "a" * 64
HEALTH = ("/usr/local/bin/python", "/usr/local/bin/netops", "health")
TASK = "/run/containerd/io.containerd.runtime.v2.task/moby/" + CID
EXEC_ARGV = ["runc", "--root", "/var/run/docker/runtime-runc/moby", "--log", TASK + "/log.json",
             "--log-format", "json", "--systemd-cgroup", "exec", "--process", "/tmp/runc-process484860385",
             "--detach", "--pid-file", TASK + "/" + "c" * 64 + ".pid", CID]
SHIM = {"key": [90, 900], "exe": "/usr/bin/containerd-shim-runc-v2",
        "argv": ["/usr/bin/containerd-shim-runc-v2", "-namespace", "moby", "-id", CID,
                 "-address", "/run/containerd/containerd.sock"], "exe_identity": [8, 1001]}
RUNTIME = {"path": "/usr/bin/runc", "exe_identity": [8, 1002], "origin": "explicit-host-runc",
           "docker_runtime": "runc", "docker_configured_path": "", "docker_runtime_type": "io.containerd.runc.v2"}
STATUS = ("Name:\tpython\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\nNoNewPrivs:\t1\n"
          "CapInh:\t0000000000000000\nCapPrm:\t00000000000001cb\nCapEff:\t00000000000001cb\n"
          "CapBnd:\t00000000000001cb\nCapAmb:\t0000000000000000\n").encode("ascii")


def ident(dev, ino):
    return SimpleNamespace(st_dev=dev, st_ino=ino)


class IdentityMaps(unittest.TestCase):
    def test_identity_map_is_accepted(self):
        with mock.patch.object(col, "read", return_value=b"         0          0 4294967295\n"):
            col.identity_maps(1)

    def test_rootless_or_remapped_namespace_is_unsupported(self):
        for data in (b"0 100000 65536\n", b"0 1000 1\n1 100000 65536\n"):
            with self.subTest(data=data), mock.patch.object(col, "read", return_value=data):
                with self.assertRaises(col.EvidenceError) as ctx:
                    col.identity_maps(1)
                self.assertEqual(ctx.exception.args[0], "nonidentity-user-or-group-map-unsupported")


class MainExitCode(unittest.TestCase):
    def run_main(self, collect):
        out = io.StringIO()
        with mock.patch.object(col, "collect", collect), mock.patch.object(sys, "argv", ["collector", CID]), \
                redirect_stdout(out):
            rc = col.main()
        return rc, json.loads(out.getvalue())

    def test_unsupported_rootless_before_trace_is_rc2_not_product_fail(self):
        out = io.StringIO()
        info = {"id": CID, "image": "sha256:" + "0" * 64, "pid": 100,
                "running": True, "restarts": 0, "runtime": "runc"}
        with mock.patch.object(col.os, "geteuid", return_value=0), \
                mock.patch.object(col, "inspect", return_value=info), \
                mock.patch.object(col, "runtime_metadata", return_value=dict(RUNTIME)), \
                mock.patch.object(col, "host_binary", side_effect=lambda runtime: base.runtime_file_fixture()), \
                mock.patch.object(col, "proc_stat", return_value=((100, 1000), 90)), \
                mock.patch.object(col, "read", return_value=b"0 100000 65536\n"), \
                mock.patch.object(sys, "argv", ["collector", CID]), redirect_stdout(out):
            rc = col.main()
        result = json.loads(out.getvalue())
        self.assertEqual(rc, 2)
        self.assertIs(result["collector_error"], True)
        self.assertIs(result["assessment"]["passed"], False)
        self.assertEqual(result["assessment"]["reason"], "nonidentity-user-or-group-map-unsupported")

    def test_collector_error_inside_trace_is_rc2(self):
        rc, _ = self.run_main(mock.Mock(return_value={"collector_error": True,
                                                      "assessment": {"passed": False, "reason": "x"}}))
        self.assertEqual(rc, 2)

    def test_product_fail_rc1_and_pass_rc0(self):
        for passed, expected in ((False, 1), (True, 0)):
            with self.subTest(passed=passed):
                rc, _ = self.run_main(mock.Mock(return_value={"assessment": {"passed": passed, "reason": "x"}}))
                self.assertEqual(rc, expected)


class CollectLoop(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp")
        self.cgroup = "/system.slice/docker-" + CID + ".scope"
        pathlib.Path(self.tmp.name, self.cgroup.lstrip("/")).mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def collect(self, sample, runtime_values):
        real_path = col.Path
        fake_base = self.tmp.name
        now = [1000.0]

        def path_factory(*args):
            return real_path(fake_base) if args == ("/sys/fs/cgroup",) else real_path(*args)

        def clock():
            now[0] += 0.5
            return now[0]

        predicate = real_path(col.__file__).with_name("health_bootstrap_profile.py").read_bytes()
        info = {"id": CID, "image": "sha256:" + "0" * 64, "pid": 100, "running": True, "restarts": 0, "runtime": "runc"}
        with ExitStack() as stack:
            for target, name, kwargs in (
                    (col.os, "geteuid", {"return_value": 0}),
                    (col, "PREDICATE_SHA", {"new": hashlib.sha256(predicate).hexdigest()}),
                    (col, "inspect", {"side_effect": lambda cid: dict(info)}),
                    (col, "runtime_metadata", {"side_effect": runtime_values}),
                    (col, "host_binary", {"side_effect": lambda runtime: base.runtime_file_fixture()}),
                    (col, "proc_stat", {"return_value": ((100, 1000), 90)}),
                    (col, "identity_maps", {"return_value": None}),
                    (col, "cgroup_path", {"return_value": self.cgroup}),
                    (col, "Path", {"side_effect": path_factory}),
                    (col, "members", {"return_value": {100}}),
                    (col, "shim", {"side_effect": lambda pid, cid: json.loads(json.dumps(SHIM))}),
                    (col, "sample", {"side_effect": sample}),
                    (col, "NamespaceScope", {"return_value": SimpleNamespace(header={}, close=lambda: None)}),
                    (col, "clock", {"side_effect": clock}),
                    (col.time, "sleep", {"return_value": None})):
                stack.enter_context(mock.patch.object(target, name, **kwargs))
            return col.collect(CID)

    @staticmethod
    def empty_sample(*args, **kwargs):
        return {"time": col.clock(), "complete": True, "shim": json.loads(json.dumps(SHIM)), "pids": [],
                "processes": [], "exited": [], "races": [], "failures": []}

    def test_harness_reaches_assessment_without_collector_error(self):
        trace = self.collect(self.empty_sample, [dict(RUNTIME), dict(RUNTIME)])
        self.assertNotIn("collector_error", trace)
        self.assertIs(trace["assessment"]["passed"], False)

    def test_error_during_sampling_is_never_silent_pass(self):
        trace = self.collect(col.EvidenceError("process-race"), [dict(RUNTIME)])
        self.assertIs(trace["collector_error"], True)
        self.assertIs(trace["assessment"]["passed"], False)
        self.assertEqual(trace["assessment"]["reason"], "process-race")

    def test_shim_changed_after_initial_read_marks_samples_incomplete(self):
        def changed_shim_sample(*args, **kwargs):
            row = self.empty_sample()
            row["shim"]["key"] = [90, 901]
            return row
        trace = self.collect(changed_shim_sample, [dict(RUNTIME), dict(RUNTIME)])
        self.assertTrue(trace["samples"])
        self.assertTrue(all(row["complete"] is False for row in trace["samples"]))
        self.assertTrue(all({"reason": "shim-identity-changed"} in row["failures"] for row in trace["samples"]))
        self.assertIs(trace["assessment"]["passed"], False)

    def test_runtime_changed_by_end_is_collector_error(self):
        changed = dict(RUNTIME, exe_identity=[8, 1003])
        trace = self.collect(self.empty_sample, [dict(RUNTIME), changed])
        self.assertIs(trace["collector_error"], True)
        self.assertEqual(trace["assessment"]["reason"], "container-or-runtime-changed-during-observation")


class SampleCompleteness(unittest.TestCase):
    def test_shim_read_failure_makes_sample_incomplete(self):
        row = {"key": [100, 1000], "parent": [90, 900], "argv": ["x"], "uids": [51000] * 4}
        handle = {"key": (100, 1000), "directory": 11, "pidfd": 12, "evidence": {}}
        with mock.patch.object(col, "members", return_value={100}), \
                mock.patch.object(col, "proc_stat", return_value=((100, 1000), 90)), \
                mock.patch.object(col, "pin_process", return_value=handle), \
                mock.patch.object(col, "process", return_value=row), \
                mock.patch.object(col, "shim", side_effect=col.EvidenceError("unverified-container-shim")):
            result = col.sample(None, "/cg", (100, 1000), 90, CID, {}, RUNTIME, {}, 100.0)
        self.assertEqual(result["pids"], [100])
        self.assertIs(result["complete"], False)


class ProcessRead(unittest.TestCase):
    def read_process(self, stats, commands):
        with mock.patch.object(col, "proc_stat", side_effect=stats), \
                mock.patch.object(col, "command", side_effect=commands), \
                mock.patch.object(col, "identity_maps", return_value=None), \
                mock.patch.object(col, "read_at", return_value=STATUS), \
                mock.patch.object(col, "check_binding"), \
                mock.patch.object(col, "cgroup_path", return_value="/cg"):
            handle = {"key": (200, 10100), "directory": 11, "pidfd": 12, "evidence": {}}
            return col.process(200, "/cg", 90, CID, RUNTIME, handle)

    def good_stats(self):
        return [((200, 10100), 90), ((90, 900), 1), ((200, 10100), 90)]

    def test_baseline_root_health_row(self):
        row = self.read_process(self.good_stats(), [HEALTH, HEALTH])
        self.assertEqual(row["parent"], [90, 900])
        self.assertEqual(row["caps"]["eff"], 0x1CB)

    def test_parent_change_during_read_rejected(self):
        stats = self.good_stats()
        stats[2] = ((200, 10100), 95)
        with self.assertRaises(col.EvidenceError) as ctx:
            self.read_process(stats, [HEALTH, HEALTH])
        self.assertEqual(ctx.exception.args[0], "process-identity-or-parent-race")

    def test_command_change_during_read_rejected(self):
        with self.assertRaises(col.EvidenceError) as ctx:
            self.read_process(self.good_stats(), [HEALTH, ("runc", "init")])
        self.assertEqual(ctx.exception.args[0], "process-identity-or-parent-race")

    def test_unknown_command_suppressed_and_fatal(self):
        with self.assertRaises(col.EvidenceError) as ctx:
            self.read_process(self.good_stats(), [("sh", "-c", "id"), ("sh", "-c", "id")])
        self.assertEqual(ctx.exception.args[0], "unknown-process-command-suppressed")


class FakeOS:
    O_RDONLY, O_DIRECTORY, O_NOFOLLOW = os.O_RDONLY, os.O_DIRECTORY, os.O_NOFOLLOW
    path = os.path

    def __init__(self, exe_ids):
        self.exe_ids = list(exe_ids)

    def open(self, *args, **kwargs):
        return 1007

    def pidfd_open(self, pid, flags):
        return 1008

    def fstat(self, fd):
        return ident(9, 2020)

    def readlink(self, name, dir_fd=None):
        return "/usr/bin/runc"

    def stat(self, name, dir_fd=None, follow_symlinks=True):
        return self.exe_ids.pop(0) if name == "exe" else ident(9, 2020)

    def close(self, fd):
        pass


class FakePoll:
    def __init__(self, events):
        self.events = events

    def register(self, *args):
        pass

    def poll(self, timeout):
        return self.events


class RuntimeParentProof(unittest.TestCase):
    def prove(self, child=(200, 10100), exe_ids=((8, 1002), (8, 1002)), after_parent=(90, 900),
              shims=None, events=()):
        shims = shims or [json.loads(json.dumps(SHIM)), json.loads(json.dumps(SHIM))]
        raw = b"\0".join(part.encode() for part in EXEC_ARGV) + b"\0"
        fake_select = SimpleNamespace(poll=lambda: FakePoll(list(events)), POLLIN=1)
        with mock.patch.object(col, "os", FakeOS([ident(*x) for x in exe_ids])), \
                mock.patch.object(col, "select", fake_select), \
                mock.patch.object(col, "stat_at", side_effect=[((95, 10099), 90), ((95, 10099), 90)]), \
                mock.patch.object(col, "read_at", return_value=raw), \
                mock.patch.object(col, "shim", side_effect=shims), \
                mock.patch.object(col, "proc_stat", side_effect=[(tuple(after_parent), 1), ((95, 10099), 90)]):
            return col.runtime_parent(95, child, 90, CID, RUNTIME)

    def expect(self, reason, **kwargs):
        with self.assertRaises(col.EvidenceError) as ctx:
            self.prove(**kwargs)
        self.assertEqual(ctx.exception.args[0], reason)

    def test_baseline_proof(self):
        proof = self.prove()
        self.assertEqual(proof["key"], [95, 10099])
        self.assertEqual(proof["parent_after"], [90, 900])
        self.assertEqual(proof["exe_identity_after"], [8, 1002])

    def test_runtime_exe_replaced_during_proof(self):
        self.expect("runtime-parent-identity-race", exe_ids=((8, 1002), (8, 1003)))

    def test_parent_exit_signalled_by_pidfd(self):
        self.expect("runtime-parent-exited-during-proof", events=[(1008, 1)])

    def test_grandparent_after_is_not_shim(self):
        self.expect("runtime-parent-identity-race", after_parent=(90, 901))

    def test_shim_changed_during_proof(self):
        changed = json.loads(json.dumps(SHIM))
        changed["key"] = [90, 901]
        self.expect("runtime-parent-shim-race", shims=[json.loads(json.dumps(SHIM)), changed])

    def test_parent_born_after_child(self):
        self.expect("runtime-parent-born-after-child", child=(200, 10098))

    def test_parent_exe_identity_differs_from_runtime(self):
        self.expect("runtime-executable-mismatch", exe_ids=((8, 9999), (8, 9999)))


class RuntimeMetadata(unittest.TestCase):
    def metadata(self, runtimes, explicit, mode=stat.S_IFREG | 0o755, uid=0):
        fake_os = SimpleNamespace(path=SimpleNamespace(realpath=lambda p, strict=False: p, basename=os.path.basename),
                                  stat=lambda p: SimpleNamespace(st_mode=mode, st_uid=uid, st_dev=8, st_ino=1002))
        done = SimpleNamespace(returncode=0, stdout=json.dumps({"default": "runc", "runtimes": runtimes}))
        with mock.patch.object(col, "os", fake_os), mock.patch.object(col.subprocess, "run", return_value=done):
            return col.runtime_metadata("runc", explicit)

    def expect(self, reason, *args, **kwargs):
        with self.assertRaises(col.EvidenceError) as ctx:
            self.metadata(*args, **kwargs)
        self.assertEqual(ctx.exception.args[0], reason)

    def test_abstract_runtime_with_explicit_runc(self):
        result = self.metadata({"runc": {"path": "runc"}}, "/usr/bin/runc")
        self.assertEqual((result["origin"], result["exe_identity"]), ("explicit-host-runc", [8, 1002]))

    def test_unsafe_runtime_binary_rejected(self):
        for mode, uid in ((stat.S_IFREG | 0o777, 0), (stat.S_IFREG | 0o775, 0), (stat.S_IFREG | 0o755, 1000)):
            with self.subTest(mode=oct(mode), uid=uid):
                self.expect("unsafe-host-runtime-binary", {"runc": {"path": "runc"}}, "/usr/bin/runc", mode=mode, uid=uid)

    def test_explicit_path_conflicting_with_docker_rejected(self):
        self.expect("explicit-runtime-conflicts-with-docker", {"runc": {"path": "/opt/other/runc"}}, "/usr/bin/runc")

    def test_abstract_runtime_without_explicit_path_rejected(self):
        self.expect("abstract-docker-runtime-needs-explicit-host-runc", {"runc": {"path": "runc"}}, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
