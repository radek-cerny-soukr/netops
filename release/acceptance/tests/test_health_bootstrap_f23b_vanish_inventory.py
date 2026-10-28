import contextlib
import copy
import errno
import hashlib
import sys
from contextlib import ExitStack
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
import test_health_bootstrap_mutation_controls as controls
import test_health_bootstrap_collector as collector_tests

CID = base.CID
HOST, OWN = [5, 4026531836], [5, 4026532585]
OWNPROC, OWNNS, HOSTPROC, PATH = 333, 444, 222, "/container"
EXITED = getattr(col, "RuntimeParentExited", None)
RETRIABLE = tuple(item for item in (FileNotFoundError, ProcessLookupError, EXITED) if item is not None)
ERRNO = {"FileNotFoundError": errno.ENOENT, "ProcessLookupError": errno.ESRCH, "ProcessExited": None, "OSError": errno.ENOTTY}
INIT, WORKERS = (100, 1000), ((101, 1000, 7), (102, 1000, 8), (103, 1000, 9))
KNOWN, NEW, OUTSIDE, HELPER, HELPER2 = (200, 10100), (300, 10200), (700, 9900), (600, 9500), (601, 9510)
RUNC_PARENT = (95, 9000)
SHIM_CGROUP = "/system.slice/containerd.service"
SHIM_RECORD = {"key": [90, 900], "exe": "/usr/bin/containerd-shim-runc-v2", "argv": ["/usr/bin/containerd-shim-runc-v2"],
               "exe_identity": [8, 1001]}
HELPER3, OTHER_PARENT = (602, 9520), (96, 9000)


def injected(mode):
    return (FileNotFoundError(errno.ENOENT, "injected") if mode == "enoent" else
            ProcessLookupError(errno.ESRCH, "injected"))



def assessed(trace, **kwargs):
    try:
        return profile.assess_trace(trace, **kwargs)
    except Exception as error:
        raise AssertionError("profile raised %r" % (error,)) from error

class Kernel:
    def __init__(self, target, mode=None, at=0, extra=()):
        self.procs = {INIT[0]: {"key": INIT, "local": 1, "ns": OWN, "known": True}}
        for pid, start, local in WORKERS:
            self.procs[pid] = {"key": (pid, start), "local": local, "ns": OWN, "known": True}
        catalog = {"known": (KNOWN, 32, OWN, True), "new": (NEW, 40, OWN, False), "outside": (OUTSIDE, None, HOST, True),
                   "helper": (HELPER, None, HOST, False), "helper2": (HELPER2, None, HOST, False),
                   "helper3": (HELPER3, None, HOST, False)}
        for name in extra:
            key, local, ns, known = catalog[name]
            self.procs[key[0]] = {"key": key, "local": local, "ns": ns, "known": known}
        for item in self.procs.values():
            item.update(state="live", uid=0 if item["ns"] == HOST else 51000, content="d" * 64, parent=None)
        for pid in (HELPER[0], HELPER2[0], HELPER3[0]):
            if pid in self.procs:
                self.procs[pid]["parent"] = RUNC_PARENT
                self.procs[RUNC_PARENT[0]] = {"key": RUNC_PARENT, "local": None, "ns": HOST, "known": False, "state": "live",
                                              "uid": 0, "content": "d" * 64, "parent": None, "outside_cgroup": True,
                                              "cgroup": SHIM_CGROUP}
        if OUTSIDE[0] in self.procs:
            self.procs[OUTSIDE[0]]["content"] = "e" * 64
        self.target, self.mode, self.at, self.touches, self.fired, self.points = target, mode, at, 0, None, []
        self.when, self.enotty, self.kill_parent, self.parent_gone, self.in_link = None, False, False, False, False
        self.fds, self.next, self.role_refusals = {}, 1000, []
        self.handles = {item["key"]: self.handle(pid) for pid, item in self.procs.items() if item["known"]}

    def fd(self, kind, pid):
        self.next += 1
        self.fds[self.next] = (kind, pid)
        return self.next

    def handle(self, pid):
        key = self.procs[pid]["key"]
        return {"directory": self.fd("dir", pid), "pidfd": self.fd("pidfd", pid), "key": key,
                "evidence": {"method": "procdir+pidfd", "key_before": list(key), "key_after": list(key),
                             "procdir_identity": [9, pid], "procdir_identity_after": [9, pid],
                             "cgroup": PATH, "bound_at": 1.0}}

    def touch(self, pid, name, raising=True):
        if pid != self.target and raising:
            return
        if self.mode in ("enoent", "esrch") and not raising:
            return
        self.touches += 1
        self.points.append(name)
        if self.touches != self.at and not (self.when == name and pid == self.target and self.fired is None):
            return
        self.fired = ("link:" if self.in_link else "") + name
        self.parent_gone = self.kill_parent
        if self.kill_parent and RUNC_PARENT[0] in self.procs:
            self.procs[RUNC_PARENT[0]]["state"] = "gone"
        if self.mode == "reaped":
            self.procs[self.target]["state"] = "gone"
        elif self.mode == "zombie":
            self.procs[self.target]["state"] = "zombie"
        else:
            raise injected(self.mode)

    def alive(self, pid, name, error=FileNotFoundError):
        if pid not in self.procs:
            raise error(errno.ENOENT if error is FileNotFoundError else errno.ESRCH, "absent")
        self.touch(pid, name)
        if self.procs[pid]["state"] == "gone":
            raise error(errno.ENOENT if error is FileNotFoundError else errno.ESRCH, "reaped")
        return self.procs[pid]

    def owner(self, local, error=FileNotFoundError):
        found = [pid for pid, item in self.procs.items() if item["local"] == local]
        if not found:
            raise error(errno.ENOENT if error is FileNotFoundError else errno.ESRCH, "absent")
        return found[0]

    def members(self, directory):
        self.touch(None, "members", raising=False)
        return {pid for pid, item in self.procs.items() if item["state"] == "live" and not item.get("outside_cgroup")}

    def listdir(self, fd):
        assert fd == OWNPROC
        self.touch(None, "listdir", raising=False)
        return [str(item["local"]) for item in self.procs.values()
                if item["local"] is not None and item["state"] != "gone"]

    def proc_stat(self, pid):
        item = self.alive(pid, "proc_stat")
        return item["key"], (item["parent"] or (90,))[0]

    def pin_process(self, pid, path):
        item = self.alive(pid, "pin_process")
        if item["state"] == "zombie":
            raise col.EvidenceError("unverified-initial-process-binding")
        return self.handle(pid)

    def check_binding(self, handle):
        self.alive(self.fds[handle["directory"]][1], "check_binding")

    def pidfd_events(self, fd):
        pid = self.fds[fd][1]
        self.touch(pid, "pidfd_events", raising=False)
        return 0 if self.procs[pid]["state"] == "live" else 1

    def cgroup_at(self, fd):
        return self.alive(self.fds[fd][1], "cgroup_at").get("cgroup", PATH)

    def cgroup_path(self, pid):
        return SHIM_CGROUP if pid == 90 else self.alive(pid, "cgroup_path").get("cgroup", PATH)

    def shim(self, pid, cid):
        return copy.deepcopy(SHIM_RECORD)

    def stat_at(self, fd, pid):
        kind, owner = self.fds[fd]
        item = self.alive(owner, "stat_at")
        return (item["key"] if kind == "dir" else (item["local"], item["key"][1])), (item["parent"] or (90,))[0]

    def stat_detail_at(self, fd, pid):
        kind, owner = self.fds[fd]
        item = self.alive(owner, "stat_detail_at")
        state = "Z" if item["state"] == "zombie" else "S"
        return (item["key"] if kind == "dir" else (item["local"], item["key"][1])), 90, state

    def permissions_at(self, fd):
        item = self.alive(self.fds[fd][1], "permissions_at")
        return {"uids": [item["uid"]] * 4, "gids": [item["uid"]] * 4, "groups": [], "nnp": 0,
                "caps": dict.fromkeys(("inh", "prm", "eff", "bnd", "amb"), 0)}

    def runtime_parent(self, pid, child, shim_pid, cid, runtime):
        item = self.procs[child[0]]
        self.touch(child[0], "runtime_parent", raising=False)
        if (item["parent"] is None or pid != item["parent"][0] or item.get("foreign") or self.parent_gone or
                self.procs[pid]["state"] != "live"):
            raise col.EvidenceError("runtime-parent-foreign-shim")
        argv = list(self.procs[pid].get("argv", RUNC_ARGV))
        try:
            col.runtime_exec_argv(argv, cid)
        except profile.InvalidProfile as error:
            self.role_refusals.append(error.args[0])
            raise col.EvidenceError(error.args[0]) from None
        return {"key": list(item["parent"]), "key_after": list(item["parent"]), "parent": [90, 900], "parent_after": [90, 900],
                "shim": copy.deepcopy(SHIM_RECORD), "argv": argv, "read_started_at": 100.0, "read_finished_at": 100.0,
                "procdir_identity": [78, pid], "procdir_identity_after": [78, pid]}

    def hash_executable(self, fd, before, opened_at):
        return {"stat_before": before, "stat_after": before, "opened_at": opened_at, "read_started_at": 100.0,
                "read_finished_at": 100.0, "sha256": self.procs[self.fds[fd][1]]["content"], "bytes_hashed": 32,
                "method": "bytes-equal-to-verified-reference"}

    def open(self, name, flags, dir_fd=None):
        if dir_fd is None and name.startswith("/proc/"):
            pid = int(name.split("/")[2])
            self.alive(pid, "open-parent")
            return self.fd("dir", pid)
        if dir_fd == HOSTPROC:
            item = self.alive(int(name), "open-host")
            return self.fd("dir", int(name))
        if dir_fd == OWNPROC:
            pid = self.owner(int(name))
            self.alive(pid, "open-local")
            return self.fd("local", pid)
        pid = self.fds[dir_fd][1]
        if name == "exe":
            item = self.alive(pid, "open-exe")
            if item["state"] == "zombie":
                raise FileNotFoundError(errno.ENOENT, "exiting")
            return self.fd("exe", pid)
        assert name == "ns/pid", name
        self.alive(pid, "open-ns")
        return self.fd("ns", pid)

    def close(self, fd):
        getattr(self, "closer", []).append(fd)

    def pidfd_open(self, pid, flags):
        self.alive(pid, "pidfd-open")
        return self.fd("pidfd", pid)

    def fstat(self, fd):
        kind, pid = self.fds[fd]
        if kind == "ns":
            return SimpleNamespace(st_dev=self.procs[pid]["ns"][0], st_ino=self.procs[pid]["ns"][1])
        if kind == "exe":
            return SimpleNamespace(st_dev=58, st_ino=97, st_mode=0o100755, st_uid=0, st_size=32, st_mtime_ns=1, st_ctime_ns=1)
        return SimpleNamespace(st_dev=78, st_ino=pid)

    def stat(self, name, *, dir_fd=None, follow_symlinks=True):
        if dir_fd == HOSTPROC:
            self.alive(int(name), "stat-host")
            return SimpleNamespace(st_dev=9, st_ino=int(name))
        assert dir_fd == OWNPROC
        pid = self.owner(int(name))
        self.alive(pid, "stat-local")
        return SimpleNamespace(st_dev=78, st_ino=pid)

    def ioctl(self, fd, operation, arg=None):
        try:
            return self.translate(fd, operation, arg)
        except ProcessLookupError:
            if self.enotty and operation != 0xb703:
                raise OSError(errno.ENOTTY, "kernel 6.19 nsfs") from None
            raise

    def translate(self, fd, operation, arg=None):
        if operation == 0xb703:
            return 0x20000000
        if operation == 0x8004b706:
            pid = self.owner(arg, ProcessLookupError)
            self.alive(pid, "ioctl-host-pid", ProcessLookupError)
            return pid
        assert operation == 0x8004b708
        item = self.alive(arg, "ioctl-local-pid", ProcessLookupError)
        if item["local"] is None:
            raise ProcessLookupError(errno.ESRCH, "not in namespace")
        return item["local"]

    def scope(self):
        scope = col.NamespaceScope.__new__(col.NamespaceScope)
        scope.path, scope.ownproc, scope.ownns = PATH, OWNPROC, OWNNS
        scope.host_identity, scope.own_identity = list(HOST), list(OWN)
        inside = {item["key"]: item["local"] for item in self.procs.values() if item["known"] and item["ns"] == OWN}
        scope.inside_seen, scope.inside_locals = set(inside), dict(inside)
        scope.outside_seen = {item["key"] for item in self.procs.values() if item["known"] and item["ns"] == HOST}
        scope.handles, scope.ioctl = self.handles, self.ioctl
        scope.context, scope.identities, scope.parents, scope.hostproc = (90, CID, base.runtime_fixture()), {}, {}, HOSTPROC
        scope.parent_pins, scope.links, scope.unlinked, scope.child_reads = {}, {}, {}, {}
        scope.link = lambda *args: self.linking(scope, *args)
        scope.verify_authority = mock.Mock(return_value={"fixed": True})
        return scope

    def linking(self, scope, *args):
        self.in_link = True
        try:
            return col.NamespaceScope.link(scope, *args)
        finally:
            self.in_link = False

    def inventory(self, scope=None):
        scope = self.scope() if scope is None else scope
        with ExitStack() as stack:
            for target, name, value in ((col, "members", self.members), (col, "proc_stat", self.proc_stat),
                                        (col, "pin_process", self.pin_process), (col, "check_binding", self.check_binding),
                                        (col, "pidfd_events", self.pidfd_events), (col, "cgroup_at", self.cgroup_at),
                                        (col, "stat_at", self.stat_at), (col.os, "open", self.open),
                                        (col, "stat_detail_at", self.stat_detail_at), (col, "permissions_at", self.permissions_at),
                                        (col, "runtime_parent", self.runtime_parent), (col, "hash_executable", self.hash_executable),
                                        (col.os, "fstat", self.fstat), (col.os, "stat", self.stat),
                                        (col.os, "listdir", self.listdir), (col.os, "close", self.close),
                                        (col.os, "pidfd_open", self.pidfd_open), (col, "cgroup_path", self.cgroup_path),
                                        (col, "shim", self.shim)):
                stack.enter_context(mock.patch.object(target, name, side_effect=value))
            stack.enter_context(mock.patch.object(col, "clock", **({"side_effect": self.tick} if hasattr(self, "tick") else
                                                                   {"return_value": 100.0})))
            try:
                return scope.inventory(None)
            except Exception as error:
                raise AssertionError("inventory raised %r" % (error,)) from error


SCENARIOS = {"known": (KNOWN, 32, ("known",)), "new": (NEW, 40, ("new",)),
             "outside": (OUTSIDE, None, ("outside",)), "init": (INIT, 1, ()), "helper": (HELPER, None, ("helper",))}


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



class SystematicInventoryInjection(unittest.TestCase):
    def runs(self, scenario, mode, change=None):
        key, _, extra = SCENARIOS[scenario]
        clean = Kernel(key[0], mode, 0, extra)
        if change:
            change(clean)
        result = clean.inventory()
        self.assertIs(result["complete"], True, result["failures"])
        self.assertTrue(clean.touches > 0)
        for at in range(1, clean.touches + 1):
            kernel = Kernel(key[0], mode, at, extra)
            if change:
                change(kernel)
            result = kernel.inventory()
            self.assertIsNotNone(kernel.fired)
            yield at, kernel.fired, result

    def seen(self, result, key, local):
        return key[0] in result.get("cgroup_pids", []) or (local is not None and local in result.get("visible_pids", []))

    def mapped(self, result, key):
        return [key[0], key[1]] in [item["key"] for item in result["mappings"]]

    def excluded(self, result, key):
        return [key[0], key[1]] in [item["key"] for item in result["excluded"]]

    def test_known_inside_process_reaped_at_every_read_is_proven_or_mapped(self):
        stages = set()
        for at, point, result in self.runs("known", "reaped"):
            with self.subTest(at=at, point=point):
                self.assertIs(result["complete"], True, result["failures"])
                self.assertEqual(result["failures"], [])
                entries = [item for item in result["vanished"] if item.get("pid") == KNOWN[0]]
                self.assertEqual(len(result["vanished"]), len(entries))
                if self.mapped(result, KNOWN):
                    self.assertEqual(entries, [])
                    continue
                if not self.seen(result, KNOWN, 32):
                    self.assertEqual(entries, [])
                    continue
                self.assertEqual(len(entries), 1)
                entry = entries[0]
                stage = "inside-mapping" if 32 in result["visible_pids"] else "classify-host"
                self.assertEqual({key: entry.get(key) for key in ("pid", "key", "local_pid", "stage", "verified_absent_at")},
                                 {"pid": KNOWN[0], "key": list(KNOWN), "local_pid": 32, "stage": stage,
                                  "verified_absent_at": 100.0})
                self.assertEqual(ERRNO[entry["error"]], entry["errno"])
                if stage == "classify-host":
                    self.assertIn(KNOWN[0], result["cgroup_pids"])
                self.assertNotIn(KNOWN[0], result["end_cgroup_pids"])
                self.assertNotIn(32, result["end_visible_pids"])
                self.assertIs(result["stable"], False)
                stages.add(stage)
        self.assertEqual(stages, {"inside-mapping", "classify-host"})

    def test_known_zombie_at_every_read_is_proven_mapped_or_unseen(self):
        zombies = 0
        for at, point, result in self.runs("known", "zombie"):
            with self.subTest(at=at, point=point):
                self.assertIs(result["complete"], True, result["failures"])
                if self.mapped(result, KNOWN) or not self.seen(result, KNOWN, 32):
                    self.assertEqual(result["vanished"], [])
                    continue
                self.assertEqual(len(result["vanished"]), 1)
                entry = result["vanished"][0]
                self.assertEqual((entry["key"], entry["local_pid"], entry["stage"]), (list(KNOWN), 32, "inside-mapping"))
                self.assertEqual(entry["zombie"], {"pidfd_events": 1, "key": list(KNOWN), "state": "Z",
                                                   "local_key": [32, KNOWN[1]], "local_state": "Z", "verified_at": 100.0})
                self.assertNotIn(KNOWN[0], result["end_cgroup_pids"])
                self.assertIs(result["stable"], False)
                zombies += 1
        self.assertTrue(zombies > 0)

    def test_other_zombies_during_inventory_are_never_vanished(self):
        for scenario in ("new", "outside", "init"):
            key, local, _ = SCENARIOS[scenario]
            failed = 0
            for at, point, result in self.runs(scenario, "zombie"):
                with self.subTest(scenario=scenario, at=at, point=point):
                    self.assertEqual(result["vanished"], [])
                    self.assertEqual(result["exited_helpers"], [])
                    if result["complete"]:
                        self.assertTrue(self.mapped(result, key) or self.excluded(result, key) or
                                        not self.seen(result, key, local))
                    else:
                        failed += 1
                        self.assertTrue(result["failures"])
            self.assertTrue(failed > 0, scenario)

    def test_enotty_kernel_reaped_known_process_is_proven(self):
        errors = set()
        clean = Kernel(KNOWN[0], "reaped", 0, ("known",))
        clean.enotty = True
        self.assertIs(clean.inventory()["complete"], True)
        for at in range(1, clean.touches + 1):
            kernel = Kernel(KNOWN[0], "reaped", at, ("known",))
            kernel.enotty = True
            result = kernel.inventory()
            with self.subTest(at=at, point=kernel.fired):
                self.assertIs(result["complete"], True, result["failures"])
                for entry in result["vanished"]:
                    self.assertEqual((entry["key"], entry["local_pid"]), (list(KNOWN), 32))
                    self.assertEqual(ERRNO[entry["error"]], entry["errno"])
                    errors.add(entry["error"])
        self.assertIn("OSError", errors)

    def test_enotty_while_process_lives_or_other_errno_is_failure(self):
        for code in (errno.ENOTTY, errno.EINVAL):
            with self.subTest(code=code):
                kernel = Kernel(KNOWN[0], None, 0, ("known",))
                ioctl = kernel.ioctl

                def failing(fd, operation, arg=None):
                    if operation == 0x8004b706 and arg == 32:
                        raise OSError(code, "synthetic")
                    return ioctl(fd, operation, arg)

                kernel.ioctl = failing
                result = kernel.inventory()
                self.assertIs(result["complete"], False)
                self.assertEqual(result["vanished"], [])
        kernel = Kernel(KNOWN[0], None, 0, ("known",))
        kernel.procs[KNOWN[0]]["state"] = "gone"
        listdir = kernel.listdir
        kernel.listdir = lambda fd: listdir(fd) + ["32"]
        ioctl = kernel.ioctl

        def invalid(fd, operation, arg=None):
            if operation == 0x8004b706 and arg == 32:
                raise OSError(errno.EINVAL, "synthetic")
            return ioctl(fd, operation, arg)

        kernel.ioctl = invalid
        result = kernel.inventory()
        self.assertIs(result["complete"], False)
        self.assertEqual(result["vanished"], [])

    def test_zombie_with_live_pidfd_or_other_start_is_failure(self):
        for change in ("pidfd", "start", "local-start", "host-state", "local-state"):
            with self.subTest(change=change):
                kernel = Kernel(KNOWN[0], None, 0, ("known",))
                kernel.procs[KNOWN[0]]["state"] = "zombie"
                if change == "pidfd":
                    kernel.pidfd_events = lambda fd: 0
                    ioctl = kernel.ioctl

                    def failing(fd, operation, arg=None):
                        if operation == 0x8004b706 and arg == 32:
                            raise ProcessLookupError(errno.ESRCH, "synthetic")
                        return ioctl(fd, operation, arg)

                    kernel.ioctl = failing
                else:
                    detail = kernel.stat_detail_at

                    def other(fd, pid):
                        key, parent, state = detail(fd, pid)
                        kind = kernel.fds[fd][0]
                        if (change == "start" and kind == "dir") or (change == "local-start" and kind == "local"):
                            key = (key[0], key[1] + 1)
                        if (change == "host-state" and kind == "dir") or (change == "local-state" and kind == "local"):
                            state = "S"
                        return key, parent, state

                    kernel.stat_detail_at = other
                result = kernel.inventory()
                self.assertIs(result["complete"], False)
                self.assertEqual(result["vanished"], [])

    def test_transient_error_while_process_exists_is_failure(self):
        for scenario in SCENARIOS:
            key = SCENARIOS[scenario][0]
            for mode in ("enoent", "esrch"):
                for at, point, result in self.runs(scenario, mode):
                    with self.subTest(scenario=scenario, mode=mode, at=at, point=point):
                        self.assertEqual(result["vanished"], [])
                        self.assertEqual(result["exited_helpers"], [])
                        if scenario in ("outside", "helper") and point in ("open-exe", "permissions_at") or point.startswith("link:"):
                            self.assertIs(result["complete"], True)
                            self.assertTrue(self.excluded(result, key))
                            continue
                        self.assertIs(result["complete"], False)
                        self.assertTrue(result["failures"])

    def test_unknown_outside_or_init_reaped_is_never_vanished(self):
        unobserved = 0
        for scenario in ("new", "outside", "init"):
            key, local, _ = SCENARIOS[scenario]
            failed = 0
            for at, point, result in self.runs(scenario, "reaped"):
                with self.subTest(scenario=scenario, at=at, point=point):
                    self.assertEqual(result["vanished"], [])
                    self.assertEqual(result["exited_helpers"], [])
                    if result["unobserved"]:
                        self.assertEqual((scenario, point), ("new", "proc_stat"))
                        self.assertEqual(result["unobserved"], [{"pid": NEW[0], "stage": "classify-host", "error": "FileNotFoundError",
                                                                 "errno": errno.ENOENT, "verified_absent_at": 100.0}])
                        self.assertIs(result["complete"], True)
                        unobserved += 1
                        continue
                    if result["complete"]:
                        self.assertTrue(self.mapped(result, key) or self.excluded(result, key) or
                                        not self.seen(result, key, local))
                    else:
                        failed += 1
            self.assertTrue(failed > 0, scenario)
        self.assertTrue(unobserved > 0)

    def test_known_reaped_but_cgroup_still_lists_pid_is_failure(self):
        kernel = Kernel(KNOWN[0], "reaped", 0, ("known",))
        kernel.procs[KNOWN[0]]["state"] = "gone"
        members = kernel.members
        kernel.members = lambda directory: members(directory) | {KNOWN[0]}
        result = kernel.inventory()
        self.assertIs(result["complete"], False)
        self.assertEqual(result["vanished"], [])

    def test_identified_runtime_helper_exit_is_recorded_only_after_identification(self):
        outcomes = set()
        for mode in ("reaped", "zombie"):
            for at, point, result in self.runs("helper", mode):
                with self.subTest(mode=mode, at=at, point=point):
                    self.assertEqual(result["vanished"], [])
                    helpers = result["exited_helpers"]
                    if helpers and helpers[0]["reason"] == "reaped-before-restat":
                        self.assertIs(result["complete"], True, result["failures"])
                        self.assertEqual((mode, len(helpers), helpers[0]["key"], helpers[0]["unlinked"]["stage"]),
                                         ("reaped", 1, list(HELPER), "link-child-restat"))
                        self.assertTrue(point.startswith("link:"), point)
                        outcomes.add("helper-reaped-before-restat")
                        continue
                    if mode == "reaped" and point.startswith("link:") and not result["complete"]:
                        self.assertEqual(helpers, [])
                        self.assertEqual(result["failures"], [{"reason": "proc-read-or-schema-failed", "error": "FileNotFoundError",
                                                               "errno": errno.ENOENT,
                                                               "diagnostic": {"stage": "classify-host-first", "pid": HELPER[0],
                                                                              "point": "retire-no-parent-link", "operation": None}}])
                        outcomes.add("no-link")
                        continue
                    self.assertIs(result["complete"], True, result["failures"])
                    if result["unobserved"]:
                        self.assertEqual((mode, point, [item["pid"] for item in result["unobserved"]]), ("reaped", "proc_stat", [HELPER[0]]))
                        outcomes.add("unobserved")
                    elif helpers:
                        self.assertEqual(len(helpers), 1)
                        item = helpers[0]
                        self.assertEqual((item["key"], item["stage"], item["parent_pid"], item["runtime_parent"]["key"],
                                          item["exit"]),
                                         (list(HELPER), "classify-host", RUNC_PARENT[0], list(RUNC_PARENT),
                                          "zombie" if mode == "zombie" else "reaped"))
                        self.assertEqual(item.get("active_namespace", HOST), HOST)
                        self.assertEqual(item.get("permissions", {"uids": [0] * 4})["uids"], [0] * 4)
                        self.assertEqual(item.get("file", {"sha256": "d" * 64})["sha256"], "d" * 64)
                        self.assertEqual(item["reason"], "identified" if "permissions" in item else "parent-verified")
                        if item["error"] == "EvidenceError":
                            self.assertEqual((item["errno"], mode), (None, "zombie"))
                        else:
                            self.assertEqual(ERRNO[item["error"]], item["errno"])
                        self.assertIn(HELPER[0], result["cgroup_pids"])
                        self.assertNotIn(HELPER[0], result["end_cgroup_pids"])
                        self.assertFalse(self.excluded(result, HELPER))
                        outcomes.add("helper-" + item["reason"])
                    elif self.excluded(result, HELPER):
                        outcomes.add("excluded")
                    else:
                        self.assertFalse(self.seen(result, HELPER, None))
                        outcomes.add("unseen")
        self.assertEqual(outcomes - {"no-link"}, {"unobserved", "helper-identified", "helper-parent-verified", "excluded", "unseen",
                                                  "helper-reaped-before-restat"})

    def test_helper_exe_descriptor_is_always_closed(self):
        for mode in ("reaped", None):
            for at in range(0, 40):
                kernel = Kernel(HELPER[0], mode, at, ("helper",))
                closed = []
                kernel.closer = closed
                result = kernel.inventory()
                opened = [fd for fd, (kind, pid) in kernel.fds.items() if kind == "exe" and pid == HELPER[0]]
                with self.subTest(mode=mode, at=at):
                    self.assertTrue(set(opened) <= set(closed), (opened, closed))
                if mode is None:
                    self.assertTrue(opened)
                    break

    def test_unidentified_runtime_helper_exit_is_failure(self):
        changes = {"content": lambda k: k.procs[HELPER[0]].update(content="e" * 64),
                   "parent": lambda k: k.procs[HELPER[0]].update(foreign=True),
                   "uid": lambda k: k.procs[HELPER[0]].update(uid=51000),
                   "inside": lambda k: k.procs[HELPER[0]].update(ns=OWN, local=41)}
        contradicted = {"content": "file", "uid": "permissions", "inside": "active_namespace", "parent": "key"}
        for name, change in changes.items():
            failed = 0
            for at, point, result in self.runs("helper", "reaped", change):
                with self.subTest(change=name, at=at, point=point):
                    self.assertEqual([item for item in result["exited_helpers"] if contradicted[name] in item], [])
                    if result["complete"] and (result["exited_helpers"] or result["unobserved"]):
                        continue
                    if result["complete"]:
                        self.assertTrue(self.excluded(result, HELPER) or self.mapped(result, HELPER) or
                                        not self.seen(result, HELPER, 41 if name == "inside" else None))
                    else:
                        failed += 1
            self.assertTrue(failed > 0, name)

    def test_parent_proof_taken_while_alive_is_reused_after_parent_exit(self):
        outcomes = set()
        for at, point, result in self.runs("helper", "reaped", lambda kernel: setattr(kernel, "kill_parent", True)):
            with self.subTest(at=at, point=point):
                if result["exited_helpers"]:
                    self.assertIs(result["complete"], True)
                    self.assertEqual(result["exited_helpers"][0]["runtime_parent"]["key"], list(RUNC_PARENT))
                    outcomes.add("helper")
                elif not result["complete"]:
                    outcomes.add("fail")
        self.assertEqual(outcomes, {"helper", "fail"})

    def test_link_uses_only_pin_of_own_parent(self):
        kernel = Kernel(HELPER3[0], "reaped", 0, ("helper", "helper2", "helper3"))
        kernel.procs[HELPER2[0]]["parent"] = OTHER_PARENT
        kernel.procs[OTHER_PARENT[0]] = dict(kernel.procs[RUNC_PARENT[0]], key=OTHER_PARENT)
        kernel.when = "pin_process"
        result = kernel.inventory()
        self.assertEqual(kernel.fired, "pin_process")
        self.assertIs(result["complete"], True, result["failures"])
        item = result["exited_helpers"][0]
        self.assertEqual((item["key"], item["parent_pid"], item["runtime_parent"]["key"], item["parent_link"]["key"]),
                         (list(HELPER3), RUNC_PARENT[0], list(RUNC_PARENT), list(RUNC_PARENT)))

    def test_sibling_uses_parent_pinned_while_alive(self):
        kernel = Kernel(HELPER2[0], "reaped", 0, ("helper", "helper2"))
        kernel.when, kernel.kill_parent = "pin_process", True
        result = kernel.inventory()
        self.assertEqual(kernel.fired, "pin_process")
        self.assertIs(result["complete"], True, result["failures"])
        item = result["exited_helpers"][0]
        self.assertEqual((item["key"], item["reason"], item["runtime_parent"]["key"], item["parent_link"]["key"]),
                         (list(HELPER2), "parent-verified", list(RUNC_PARENT), list(RUNC_PARENT)))
        self.assertLessEqual(item["parent_link"]["child_stat_at"], item["parent_link"]["child_restat_at"])
        self.assertLessEqual(item["parent_link"]["child_restat_at"], item["parent_link"]["parent_alive_at"])
        self.assertEqual((item["parent_link"]["child_restat_key"], item["parent_link"]["child_restat_parent"]),
                         (list(HELPER2), RUNC_PARENT[0]))

    def test_child_ppid_changed_before_link_is_failure(self):
        kernel = Kernel(HELPER[0], "reaped", 0, ("helper",))
        kernel.when = "pin_process"
        proc_stat, calls = kernel.proc_stat, []

        def moved(pid):
            key, parent = proc_stat(pid)
            if pid == HELPER[0]:
                calls.append(pid)
                if len(calls) == 2:
                    parent = 90
            return key, parent

        kernel.proc_stat = moved
        result = kernel.inventory()
        self.assertEqual(kernel.fired, "pin_process")
        self.assertIs(result["complete"], False)
        self.assertEqual(result["exited_helpers"], [])

    def test_parent_dead_before_child_stat_or_reused_pid_is_failure(self):
        kernel = Kernel(HELPER2[0], "reaped", 0, ("helper2",))
        kernel.when = "pin_process"
        kernel.procs[RUNC_PARENT[0]]["state"] = "gone"
        result = kernel.inventory()
        self.assertEqual(kernel.fired, "pin_process")
        self.assertIs(result["complete"], False)
        self.assertEqual(result["exited_helpers"], [])
        for case in ("terminal", "younger"):
            with self.subTest(case=case):
                kernel = Kernel(HELPER2[0], "reaped", 0, ("helper2",))
                kernel.when = "pin_process"
                scope = kernel.scope()
                stale = (RUNC_PARENT[0], 8000 if case == "terminal" else HELPER2[1] + 10)
                kernel.procs[777] = {"key": stale, "local": None, "ns": HOST, "known": False, "state": "gone" if case == "terminal" else "live",
                                     "uid": 0, "content": "d" * 64, "parent": None, "outside_cgroup": True}
                scope.parent_pins[stale] = {"directory": kernel.fd("dir", 777), "pidfd": kernel.fd("pidfd", 777),
                                            "proof": {"key": list(stale)}}
                result = kernel.inventory(scope)
                self.assertEqual(kernel.fired, "pin_process")
                self.assertIs(result["complete"], False)
                self.assertEqual(result["exited_helpers"], [])

    def test_parent_pins_are_released_at_sample_end(self):
        released = []
        scope = SimpleNamespace(inventory=mock.Mock(side_effect=[
            {"mappings": [{"key": [100, 1000]}], "excluded": [], "failures": [], "complete": True, "stable": True}] * 2),
            release=lambda: released.append(True))
        with mock.patch.object(col, "proc_stat", side_effect=lambda pid: ((pid, 1000), 90)), \
                mock.patch.object(col, "process", side_effect=lambda pid, *args: {"key": [pid, 1000]}), \
                mock.patch.object(col, "shim", return_value={}), mock.patch.object(col, "cgroup_path", return_value="/c"), \
                mock.patch.object(col, "clock", return_value=100.0):
            col.sample(None, "/c", (100, 1000), 90, CID, {}, {}, {(100, 1000): {"key": (100, 1000), "evidence": {}}}, 99.9,
                       scope=scope)
        self.assertEqual(released, [True])
        kernel = Kernel(HELPER[0], None, 0, ("helper",))
        scope = kernel.scope()
        closed = []
        kernel.closer = closed
        with mock.patch.object(col.os, "close", side_effect=kernel.close):
            kernel.inventory(scope)
            pins = dict(scope.parent_pins)
            self.assertEqual(list(pins), [RUNC_PARENT])
            scope.release()
        self.assertEqual((scope.parent_pins, scope.links), ({}, {}))
        self.assertTrue({pins[RUNC_PARENT]["directory"], pins[RUNC_PARENT]["pidfd"], pins[RUNC_PARENT]["facts"]["fd"]} <= set(closed))

    def test_pin_identity_or_cgroup_mismatch_is_never_a_helper(self):
        for code in ("initial-process-key-changed", "initial-procdir-identity-changed", "initial-process-cgroup-mismatch"):
            with self.subTest(code=code):
                kernel = Kernel(HELPER[0], None, 0, ("helper",))
                pin_process, members, calls = kernel.pin_process, kernel.members, []

                def mismatch(pid, path, code=code):
                    if pid == HELPER[0]:
                        kernel.procs[HELPER[0]]["state"] = "gone"
                        raise col.EvidenceError(code)
                    return pin_process(pid, path)

                kernel.pin_process = mismatch
                result = kernel.inventory()
                self.assertIs(result["complete"], False)
                self.assertEqual(result["exited_helpers"], [])
                self.assertEqual(result["failures"], [{"reason": code, "diagnostic": {"stage": "classify-host-first", "pid": HELPER[0],
                                                                                      "point": None, "operation": None}}])

    def test_live_process_outside_cgroup_after_pin_failure_is_not_exited(self):
        kernel = Kernel(HELPER[0], None, 0, ("helper",))
        pin_process, members, calls = kernel.pin_process, kernel.members, []

        def zombie_pin(pid, path):
            if pid == HELPER[0]:
                raise col.EvidenceError("unverified-initial-process-binding")
            return pin_process(pid, path)

        def listed(directory):
            calls.append(directory)
            return members(directory) - (set() if len(calls) == 1 else {HELPER[0]})

        kernel.pin_process, kernel.members = zombie_pin, listed
        result = kernel.inventory()
        self.assertIs(result["complete"], False)
        self.assertEqual(result["exited_helpers"], [])
        kernel = Kernel(HELPER[0], None, 0, ("helper",))
        kernel.procs[HELPER[0]]["state"] = "zombie"
        kernel.members = lambda directory, members=kernel.members, calls=[]: (calls.append(1), members(directory) | ({HELPER[0]} if len(calls) == 1 else set()))[1]
        result = kernel.inventory()
        self.assertIs(result["complete"], True, result["failures"])
        self.assertEqual([(item["key"], item["exit"]) for item in result["exited_helpers"]], [(list(HELPER), "zombie")])

    def test_zombie_entry_with_other_starttime_is_not_exited(self):
        kernel = Kernel(HELPER[0], None, 0, ("helper",))
        kernel.procs[HELPER[0]]["state"] = "zombie"
        detail, members, calls = kernel.stat_detail_at, kernel.members, []

        def reused(fd, pid):
            key, parent, state = detail(fd, pid)
            return ((key[0], key[1] + 1) if pid == HELPER[0] else key), parent, state

        def listed(directory):
            calls.append(directory)
            return members(directory) | ({HELPER[0]} if len(calls) == 1 else set())

        kernel.stat_detail_at, kernel.members = reused, listed
        result = kernel.inventory()
        self.assertIs(result["complete"], False)
        self.assertEqual(result["exited_helpers"], [])

    def test_zombie_entry_in_other_cgroup_is_not_exited(self):
        kernel = Kernel(HELPER[0], None, 0, ("helper",))
        kernel.procs[HELPER[0]]["state"] = "zombie"
        cgroup, members, calls = kernel.cgroup_at, kernel.members, []

        def moved(fd):
            value = cgroup(fd)
            return "/elsewhere" if kernel.fds[fd][1] == HELPER[0] else value

        def listed(directory):
            calls.append(directory)
            return members(directory) | ({HELPER[0]} if len(calls) == 1 else set())

        kernel.cgroup_at, kernel.members = moved, listed
        result = kernel.inventory()
        self.assertIs(result["complete"], False)
        self.assertEqual(result["exited_helpers"], [])

    def test_process_seen_in_container_namespace_is_never_a_helper(self):
        clean = Kernel(HELPER[0], "reaped", 0, ("helper",))
        clean.procs[HELPER[0]].update(ns=OWN, local=41)
        clean.inventory()
        checked = 0
        for at in range(1, clean.touches + 1):
            kernel = Kernel(HELPER[0], "reaped", at, ("helper",))
            kernel.procs[HELPER[0]].update(ns=OWN, local=41)
            result = kernel.inventory()
            if "open-ns" in kernel.points[:at - 1]:
                checked += 1
                with self.subTest(at=at, point=kernel.fired):
                    self.assertEqual(result["exited_helpers"], [])
        self.assertTrue(checked > 0)

    def test_tracked_key_that_was_never_excluded_is_not_retired(self):
        kernel = Kernel(HELPER[0], "reaped", 0, ("helper",))
        kernel.when = "proc_stat"
        scope = kernel.scope()
        kernel.handles[HELPER] = kernel.handle(HELPER[0])
        scope.parents[HELPER] = RUNC_PARENT[0]
        scope.parent_pins[RUNC_PARENT] = {"directory": kernel.fd("dir", RUNC_PARENT[0]), "pidfd": kernel.fd("pidfd", RUNC_PARENT[0]),
                                          "proof": {"key": list(RUNC_PARENT)}}
        scope.links[HELPER] = {"key": list(RUNC_PARENT), "child_stat_at": 99.0, "child_restat_at": 99.0,
                               "child_restat_key": list(HELPER), "child_restat_parent": RUNC_PARENT[0], "parent_alive_at": 99.0}
        result = kernel.inventory(scope)
        self.assertEqual(kernel.fired, "proc_stat")
        self.assertIs(result["complete"], False)
        self.assertEqual((result["exited_helpers"], result["unobserved"]), ([], []))

    def test_link_of_other_parent_is_never_used(self):
        kernel = Kernel(HELPER[0], "reaped", 0, ("helper",))
        kernel.when = "proc_stat"
        scope = kernel.scope()
        kernel.handles[HELPER] = kernel.handle(HELPER[0])
        scope.outside_seen.add(HELPER)
        scope.parents[HELPER] = RUNC_PARENT[0]
        scope.parent_pins[OTHER_PARENT] = {"directory": kernel.fd("dir", OTHER_PARENT[0]), "pidfd": kernel.fd("pidfd", OTHER_PARENT[0]),
                                           "proof": {"key": list(OTHER_PARENT)}}
        scope.links[HELPER] = {"key": list(OTHER_PARENT), "child_stat_at": 99.0, "child_restat_at": 99.0,
                               "child_restat_key": list(HELPER), "child_restat_parent": OTHER_PARENT[0], "parent_alive_at": 99.0}
        result = kernel.inventory(scope)
        self.assertEqual(kernel.fired, "proc_stat")
        self.assertEqual(result["exited_helpers"], [])
        self.assertIs(result["complete"], False)

    def test_parent_proof_of_other_identity_is_not_pinned(self):
        kernel = Kernel(HELPER[0], "reaped", 0, ("helper",))
        kernel.when = "pin_process"
        runtime_parent = kernel.runtime_parent

        def foreign(*args):
            proof = runtime_parent(*args)
            return dict(proof, key=[RUNC_PARENT[0], RUNC_PARENT[1] + 1], key_after=[RUNC_PARENT[0], RUNC_PARENT[1] + 1])

        kernel.runtime_parent = foreign
        result = kernel.inventory()
        self.assertEqual(kernel.fired, "pin_process")
        self.assertEqual(result["exited_helpers"], [])
        self.assertIs(result["complete"], False)

    def test_known_inside_key_exiting_in_classify_is_never_a_helper(self):
        kernel = Kernel(KNOWN[0], None, 0, ("known",))
        kernel.procs[KNOWN[0]].update(state="zombie", parent=RUNC_PARENT)
        listdir, members, calls = kernel.listdir, kernel.members, []

        def hidden(fd):
            return [name for name in listdir(fd) if name != "32"]

        def listed(directory):
            calls.append(directory)
            return members(directory) | ({KNOWN[0]} if len(calls) == 1 else set())

        kernel.listdir, kernel.members = hidden, listed
        result = kernel.inventory()
        self.assertIs(result["complete"], False)
        self.assertEqual((result["exited_helpers"], result["vanished"]), ([], []))

    def test_known_inside_key_under_runc_parent_reaped_in_classify_is_never_a_helper(self):
        for point in ("check_binding", "stat_at", "open-ns"):
            with self.subTest(point=point):
                kernel = Kernel(KNOWN[0], "reaped", 0, ("known",))
                kernel.procs[KNOWN[0]].update(parent=RUNC_PARENT, uid=0)
                kernel.procs[RUNC_PARENT[0]] = {"key": RUNC_PARENT, "local": None, "ns": HOST, "known": False, "state": "live",
                                                "uid": 0, "content": "d" * 64, "parent": None, "outside_cgroup": True}
                kernel.when = point
                listdir = kernel.listdir
                kernel.listdir = lambda fd: [name for name in listdir(fd) if name != "32"]
                result = kernel.inventory()
                self.assertIsNotNone(kernel.fired)
                self.assertEqual(result["exited_helpers"], [])
                self.assertTrue(result["complete"] is False or
                                [item for item in result["vanished"] if item["key"] == list(KNOWN)], result)

    def test_helper_still_in_cgroup_or_with_live_pidfd_is_failure(self):
        for change in ("members", "pidfd"):
            with self.subTest(change=change):
                kernel = Kernel(HELPER[0], "reaped", 0, ("helper",))
                kernel.when = "check_binding"
                if change == "members":
                    members = kernel.members
                    kernel.members = lambda directory: members(directory) | {HELPER[0]}
                else:
                    kernel.pidfd_events = lambda fd: 0
                result = kernel.inventory()
                self.assertIsNotNone(kernel.fired)
                self.assertIs(result["complete"], False)
                self.assertEqual(result["exited_helpers"], [])

    def test_known_live_process_with_mapping_error_is_failure(self):
        kernel = Kernel(KNOWN[0], None, 0, ("known",))
        calls = []
        ioctl = kernel.ioctl

        def failing(fd, operation, arg=None):
            if operation == 0x8004b706 and arg == 32:
                calls.append(arg)
                raise ProcessLookupError(errno.ESRCH, "synthetic")
            return ioctl(fd, operation, arg)

        kernel.ioctl = failing
        result = kernel.inventory()
        self.assertEqual(calls, [32])
        self.assertIs(result["complete"], False)
        self.assertEqual(result["vanished"], [])

    def test_ambiguous_or_mismatched_known_key_is_failure(self):
        for change in ("two-keys", "other-host-pid"):
            with self.subTest(change=change):
                kernel = Kernel(KNOWN[0], "reaped", 0, ("known",))
                scope = kernel.scope

                def patched():
                    value = scope()
                    if change == "two-keys":
                        value.inside_locals[(KNOWN[0], KNOWN[1] - 50)] = 32
                        value.handles[(KNOWN[0], KNOWN[1] - 50)] = kernel.handle(KNOWN[0])
                    else:
                        value.inside_locals[KNOWN] = 33
                        value.inside_locals[(201, 10100)] = 32
                        value.handles[(201, 10100)] = kernel.handle(KNOWN[0])
                    return value

                kernel.scope = patched
                kernel.when = "ioctl-host-pid" if change == "two-keys" else "open-local"
                result = kernel.inventory()
                self.assertEqual(kernel.fired, kernel.when)
                self.assertEqual(result["vanished"], [])
                self.assertIs(result["complete"], False)

    def test_retired_key_with_same_pid_and_local_does_not_block_proof(self):
        kernel = Kernel(KNOWN[0], "reaped", 0, ("known",))
        kernel.when = "ioctl-host-pid"
        scope = kernel.scope()
        scope.inside_locals[(KNOWN[0], KNOWN[1] - 50)] = 32
        result = kernel.inventory(scope)
        self.assertEqual(kernel.fired, "ioctl-host-pid")
        self.assertIs(result["complete"], True, result["failures"])
        self.assertEqual([(item["key"], item["local_pid"], item["stage"]) for item in result["vanished"]],
                         [([KNOWN[0], KNOWN[1]], 32, "inside-mapping")])

    def test_unreadable_local_procfs_entry_is_not_absence(self):
        kernel = Kernel(KNOWN[0], "reaped", 0, ("known",))
        kernel.when = "ioctl-host-pid"
        stat = kernel.stat

        def denied(name, *, dir_fd=None, follow_symlinks=True):
            if name == "32" and kernel.procs[KNOWN[0]]["state"] == "gone":
                raise PermissionError(errno.EACCES, "synthetic")
            return stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

        kernel.stat = denied
        result = kernel.inventory()
        self.assertEqual(kernel.fired, "ioctl-host-pid")
        self.assertIs(result["complete"], False)
        self.assertEqual(result["vanished"], [])

    def test_process_mapped_in_earlier_inventory_becomes_known(self):
        kernel = Kernel(NEW[0], None, 0, ("new",))
        scope = kernel.scope()
        first = kernel.inventory(scope)
        self.assertIs(first["complete"], True)
        self.assertIn([NEW[0], NEW[1]], [item["key"] for item in first["mappings"]])
        kernel.mode, kernel.when = "reaped", "ioctl-host-pid"
        second = kernel.inventory(scope)
        self.assertEqual(kernel.fired, "ioctl-host-pid")
        self.assertIs(second["complete"], True, second["failures"])
        self.assertEqual([(item["key"], item["local_pid"], item["stage"]) for item in second["vanished"]],
                         [([NEW[0], NEW[1]], 40, "inside-mapping")])

    def test_new_process_transiently_not_live_in_first_loop_is_failure(self):
        for point in ("pidfd_events", "cgroup_at"):
            with self.subTest(point=point):
                kernel = Kernel(NEW[0], None, 0, ("new",))
                pidfd, cgroup, seen = kernel.pidfd_events, kernel.cgroup_at, []

                def events(fd):
                    value = pidfd(fd)
                    if point == "pidfd_events" and kernel.fds[fd][1] == NEW[0] and not seen:
                        seen.append(fd)
                        return 1
                    return value

                def group(fd):
                    value = cgroup(fd)
                    if point == "cgroup_at" and kernel.fds[fd][1] == NEW[0] and not seen:
                        seen.append(fd)
                        return "/elsewhere"
                    return value

                kernel.pidfd_events, kernel.cgroup_at = events, group
                result = kernel.inventory()
                self.assertTrue(seen)
                self.assertIs(result["complete"], False)
                self.assertEqual(result["vanished"], [])
                self.assertNotIn("visible_pids", result)
                self.assertEqual(result["failures"], [{"reason": "namespace-process-exited" if point == "pidfd_events" else
                                                       "namespace-process-not-live-or-cgroup-changed",
                                                       "diagnostic": {"stage": "classify-host-first", "pid": NEW[0],
                                                                      "point": "retire-still-member" if point == "pidfd_events" else None,
                                                                      "operation": None}}])

    def test_permission_denied_during_mapping_is_not_vanished(self):
        kernel = Kernel(KNOWN[0], None, 0, ("known",))
        kernel.procs[KNOWN[0]]["state"] = "gone"
        ioctl = kernel.ioctl

        def denied(fd, operation, arg=None):
            if operation == 0x8004b706 and arg == 32:
                raise PermissionError(errno.EACCES, "synthetic")
            return ioctl(fd, operation, arg)

        kernel.ioctl = denied
        listdir = kernel.listdir
        kernel.listdir = lambda fd: listdir(fd) + ["32"]
        result = kernel.inventory()
        self.assertIs(result["complete"], False)
        self.assertEqual(result["vanished"], [])


class Proc:
    def __init__(self, target, mode, at, *, uid=51000, argv=base.HEALTH, state="S"):
        self.target, self.mode, self.at, self.calls, self.fired, self.points = target, mode, at, 0, None, []
        self.gone, self.uid, self.argv, self.state = False, uid, list(argv), state
        self.keys = {100: INIT, 101: (101, 1000), 102: (102, 1000), 103: (103, 1000), 200: KNOWN, 90: (90, 900)}

    def hit(self, pid, name, empty=False):
        if pid != self.target:
            return False
        if self.mode == "empty" and not empty:
            return False
        self.calls += 1
        self.points.append(name)
        if self.calls == self.at:
            self.fired = name
            if self.mode == "empty":
                return True
            if self.mode != "reaped":
                raise injected(self.mode)
            self.gone = True
        if self.gone:
            raise FileNotFoundError(errno.ENOENT, "reaped")
        return False

    def field(self, pid, name):
        key = self.keys[pid]
        uid = self.uid if pid == self.target else 51000
        if name == "stat":
            state = self.state if pid == self.target else "S"
            ppid = 90 if pid in (100, 200) else 100
            return (f"{pid} (python) {state} {ppid} " + " ".join(["0"] * 17) + f" {key[1]}\n").encode()
        if name == "cmdline":
            argv = self.argv if pid == self.target else ["x"]
            return b"\0".join(item.encode() for item in argv) + b"\0"
        if name in ("uid_map", "gid_map"):
            return b"0 0 4294967295\n"
        if name == "cgroup":
            return ("0::" + PATH + "\n").encode()
        assert name == "status", name
        caps = "".join(f"{field}:\t0000000000000000\n" for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        ids = "\t".join([str(uid)] * 4)
        return f"Uid:\t{ids}\nGid:\t{ids}\nGroups:\t\nNoNewPrivs:\t1\n{caps}".encode()

    def read(self, path, limit=65536):
        _, _, pid, name = path.split("/")
        pid = int(pid)
        if self.hit(pid, "read-" + name, empty=name == "cmdline"):
            return b""
        return self.field(pid, name)

    def read_at(self, directory, name):
        pid = directory
        if self.hit(pid, "read_at-" + name, empty=name == "cmdline"):
            return b""
        return self.field(pid, name)

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        pid = int(path.split("/")[2])
        self.hit(pid, "stat-procdir")
        return SimpleNamespace(st_dev=9, st_ino=pid)


class SystematicCaptureInjection(unittest.TestCase):
    def sample(self, proc, *, final_has_target=False):
        rows = {}
        for key in (INIT, (101, 1000), (102, 1000), (103, 1000), KNOWN):
            argv = (["/usr/local/bin/python", "/usr/local/bin/netops", "serve"] if key == INIT else
                    proc.argv if key == KNOWN else ["x"])
            row = base.process(key[0], key[1], 51000 if key != KNOWN else proc.uid, argv, [90, 900] if key in (INIT, KNOWN) else INIT)
            row["binding"] = {"procdir_identity": [9, key[0]], "key": list(key)}
            rows[key] = row
        handles = {key: {"key": key, "directory": key[0], "pidfd": 7, "evidence": rows[key]["binding"]} for key in rows}
        original = col.process

        def process(pid, *args, **kwargs):
            if pid != KNOWN[0]:
                return copy.deepcopy(rows[proc.keys[pid]])
            return original(pid, *args, **kwargs)

        first = {"mappings": [{"key": list(key)} for key in rows], "excluded": [], "failures": [], "complete": True, "stable": True}
        last_keys = [key for key in rows if key != KNOWN or final_has_target]
        last = {"mappings": [{"key": list(key)} for key in last_keys], "excluded": [], "failures": [], "complete": True, "stable": True}
        scope = SimpleNamespace(inventory=mock.Mock(side_effect=[first, last]), release=lambda: None)
        proof = {"kind": "reaped", "replacement_key": None}
        times = [100.0]

        def clock():
            times[0] += .0001
            return times[0]

        with ExitStack() as stack:
            for target, name, kwargs in ((col, "read", {"side_effect": proc.read}), (col, "read_at", {"side_effect": proc.read_at}),
                                         (col.os, "stat", {"side_effect": proc.stat}), (col, "process", {"side_effect": process}),
                                         (col, "terminal_exit", {"return_value": proof}), (col, "verified_exit", {"return_value": KNOWN}),
                                         (col, "close_binding", {}), (col, "shim", {"return_value": {"fixed": True}}),
                                         (col, "clock", {"side_effect": clock})):
                stack.enter_context(mock.patch.object(target, name, **kwargs))
            return col.sample(None, PATH, INIT, 90, CID, {key: copy.deepcopy(row) for key, row in rows.items()},
                              base.runtime_fixture(), handles, 99.0, scope=scope)

    def runs(self, mode, **kwargs):
        clean = Proc(KNOWN[0], mode, 0, **kwargs)
        result = self.sample(clean)
        self.assertIs(result["complete"], True, result["failures"])
        self.assertTrue(clean.calls > 0)
        for at in range(1, clean.calls + 1):
            proc = Proc(KNOWN[0], mode, at, **kwargs)
            yield at, proc

    def test_known_health_vanishing_at_every_read_is_proven_by_exit(self):
        for mode in ("enoent", "esrch", "reaped", "empty"):
            for at, proc in self.runs(mode):
                result = self.sample(proc)
                with self.subTest(mode=mode, at=at, point=proc.fired):
                    self.assertIsNotNone(proc.fired)
                    self.assertIs(result["complete"], True, result["failures"])
                    self.assertEqual(result["exited"], [list(KNOWN)])
                    self.assertIn({"kind": "verified-known-exit-during-snapshot", "key": list(KNOWN)}, result["races"])
                    reasons = {item["reason"] for item in result["scope"]["observed_failures"] if item.get("pid") == KNOWN[0]}
                    self.assertTrue(reasons <= {"proc-read-or-schema-failed", "empty-process-command"}, reasons)

    def test_vanishing_read_while_process_stays_is_failure(self):
        for mode in ("enoent", "esrch", "empty"):
            for at, proc in self.runs(mode):
                result = self.sample(proc, final_has_target=True)
                with self.subTest(mode=mode, at=at, point=proc.fired):
                    self.assertIsNotNone(proc.fired)
                    self.assertIs(result["complete"], False)
                    self.assertTrue([item for item in result["failures"] if item.get("pid") == KNOWN[0]])

    def test_empty_command_of_root_health_is_failure(self):
        for at, proc in self.runs("empty", uid=0):
            result = self.sample(proc)
            with self.subTest(at=at, point=proc.fired):
                self.assertIs(result["complete"], False)
                self.assertIn("empty-process-command", [item["reason"] for item in result["failures"]])


class TerminalInjection(unittest.TestCase):
    def proof(self, mode, at):
        proc = Proc(KNOWN[0], mode, at, state="Z")
        handle = {"key": KNOWN, "directory": KNOWN[0], "pidfd": 7,
                  "evidence": {"method": "procdir+pidfd", "key_before": list(KNOWN), "key_after": list(KNOWN),
                               "procdir_identity": [9, KNOWN[0]], "procdir_identity_after": [9, KNOWN[0]],
                               "cgroup": PATH, "bound_at": 99.0}}
        previous = base.process(KNOWN[0], KNOWN[1], 51000, base.HEALTH, [90, 900])
        previous.update(binding=handle["evidence"], read_started_at=99.5, read_finished_at=99.6)
        times = [100.0]

        def clock():
            times[0] += .0001
            return times[0]

        with mock.patch.object(col, "read", side_effect=proc.read), mock.patch.object(col, "read_at", side_effect=proc.read_at), \
                mock.patch.object(col.os, "fstat", return_value=SimpleNamespace(st_dev=9, st_ino=KNOWN[0])), \
                mock.patch.object(col, "pidfd_events", return_value=17), mock.patch.object(col, "clock", side_effect=clock):
            try:
                value = col.terminal_exit(handle)
            except col.EvidenceError as error:
                return proc, error, None
        return proc, value, profile.verified_exit(value, previous, PATH, 101.0, 99.9)

    def test_reap_at_every_terminal_read_gives_verified_reaped_proof(self):
        clean, value, verified = self.proof("reaped", 0)
        self.assertEqual((value["kind"], verified), ("zombie", KNOWN))
        for at in range(1, clean.calls + 1):
            proc, value, verified = self.proof("reaped", at)
            with self.subTest(at=at, point=proc.fired):
                self.assertEqual(value["kind"], "reaped")
                self.assertIs(value["proc_missing"], True)
                self.assertEqual(verified, KNOWN)

    def test_transient_terminal_read_error_is_failure(self):
        clean, _, _ = self.proof("enoent", 0)
        self.assertTrue(clean.calls > 0)
        for mode in ("enoent", "esrch"):
            for at in range(1, clean.calls + 1):
                proc, value, verified = self.proof(mode, at)
                with self.subTest(mode=mode, at=at, point=proc.fired):
                    self.assertIsNotNone(proc.fired)
                    self.assertIsInstance(value, col.EvidenceError)
                    self.assertEqual(value.args, ("terminal-field-missing-before-reap",))


RUNC_ARGV = ["runc", "--root", "/var/run/docker/runtime-runc/moby", "--log",
             "/run/containerd/io.containerd.runtime.v2.task/moby/" + CID + "/log.json",
             "--log-format", "json", "--systemd-cgroup", "exec", "--process", "/tmp/runc-process12",
             "--detach", "--pid-file", "/run/containerd/io.containerd.runtime.v2.task/moby/" + CID + "/" + "b" * 64 + ".pid", CID]


class Parent:
    def __init__(self, mode=None, at=0):
        self.mode, self.at, self.calls, self.fired, self.state = mode, at, 0, None, "live"

    def hit(self, name, raising=True):
        self.calls += 1
        if self.calls == self.at:
            self.fired = name
            self.state = self.mode
        if self.state == "reaped" and raising:
            raise (ProcessLookupError(errno.ESRCH, "reaped") if name in ("pidfd_open", "read_at-stat-open")
                   else FileNotFoundError(errno.ENOENT, "reaped"))

    def open(self, path, flags):
        self.hit("open")
        return 95

    def pidfd_open(self, pid, flags):
        self.hit("pidfd_open")
        return 96

    def fstat(self, fd):
        return SimpleNamespace(st_dev=9, st_ino=95)

    def read_at(self, directory, name):
        self.hit("read_at-" + name)
        if name == "stat":
            state = "Z" if self.state == "zombie" else "S"
            return (f"95 (runc) {state} 90 " + " ".join(["0"] * 17) + " 10050\n").encode()
        if self.state == "zombie":
            return b""
        return b"\0".join(item.encode() for item in RUNC_ARGV) + b"\0"

    def readlink(self, name, *, dir_fd=None):
        self.hit("readlink-exe")
        if self.state == "zombie":
            raise FileNotFoundError(errno.ENOENT, "exiting")
        return "/usr/bin/runc"

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        if path == "exe":
            self.hit("stat-exe")
            if self.state == "zombie":
                raise FileNotFoundError(errno.ENOENT, "exiting")
            return SimpleNamespace(st_dev=8, st_ino=1002)
        if path == "/proc/95":
            self.hit("stat-procdir")
            return SimpleNamespace(st_dev=9, st_ino=95)
        raise AssertionError(path)

    def proc_stat(self, pid):
        if pid == 90:
            return (90, 900), 1
        self.hit("proc_stat")
        return (95, 10050), 90

    def poll(self):
        parent = self

        class Poller:
            def register(self, fd, events):
                pass

            def poll(self, timeout):
                parent.hit("poll", raising=False)
                return [] if parent.state == "live" else [(96, 1)]

        return Poller()

    def run(self):
        origin = {"key": [90, 900], "exe": "/usr/bin/containerd-shim-runc-v2", "argv": [], "exe_identity": [8, 1001]}
        with ExitStack() as stack:
            for target, name, value in ((col.os, "open", self.open), (col.os, "pidfd_open", self.pidfd_open),
                                        (col.os, "fstat", self.fstat), (col, "read_at", self.read_at),
                                        (col.os, "readlink", self.readlink), (col.os, "stat", self.stat),
                                        (col, "proc_stat", self.proc_stat), (col.select, "poll", self.poll),
                                        (col, "shim", lambda pid, cid: copy.deepcopy(origin)),
                                        (col.os, "close", lambda fd: None), (col, "clock", lambda: 100.0)):
                stack.enter_context(mock.patch.object(target, name, side_effect=value))
            return col.runtime_parent(95, (200, 10100), 90, CID, base.runtime_fixture())


class SystematicRuntimeParentInjection(unittest.TestCase):
    def test_parent_reaped_or_exiting_at_every_read_is_retriable(self):
        clean = Parent()
        self.assertEqual(clean.run()["key"], [95, 10050])
        self.assertIsNotNone(EXITED)
        points = []
        for mode in ("reaped", "zombie"):
            for at in range(1, clean.calls + 1):
                parent = Parent(mode, at)
                with self.subTest(mode=mode, at=at):
                    try:
                        proof = parent.run()
                    except Exception as error:
                        self.assertIsInstance(error, RETRIABLE, error)
                    else:
                        self.assertEqual(mode, "zombie")
                        self.assertIn(parent.fired, ("proc_stat", "stat-procdir"))
                        self.assertEqual(proof["key"], [95, 10050])
                    self.assertIsNotNone(parent.fired)
                    points.append(parent.fired)
        self.assertTrue({"open", "pidfd_open", "read_at-stat", "read_at-cmdline", "readlink-exe", "stat-exe", "poll",
                         "proc_stat", "stat-procdir"} <= set(points), points)

    def test_exited_parent_is_an_evidence_error(self):
        self.assertIsNotNone(EXITED)
        self.assertTrue(issubclass(EXITED, col.EvidenceError))


class RuntimeParentRetryReason(unittest.TestCase):
    def process(self, error):
        trace = base.trusted_fixture()
        row = base.external_row(trace)
        key = tuple(row["key"])
        handle = {"key": key, "directory": 11, "pidfd": 12, "evidence": row["binding"]}
        info = SimpleNamespace(st_dev=88, st_ino=1002, st_mode=0o100755, st_uid=0,
                               st_size=32, st_mtime_ns=1000000000, st_ctime_ns=1000000000)
        retry_value = (90, (90, 900), None, {"reason": "x", "reads": [], "read_started_at": 0, "read_finished_at": 0})
        with mock.patch.object(col, "check_binding"), \
             mock.patch.object(col, "proc_stat", side_effect=[(key, 95), (key, 90)]), \
             mock.patch.object(col, "command", return_value=("runc", "init")), \
             mock.patch.object(col.os, "open", return_value=47), \
             mock.patch.object(col.os, "fstat", return_value=info), \
             mock.patch.object(col.os, "close"), \
             mock.patch.object(col, "cgroup_at", return_value=trace["cgroup"]), \
             mock.patch.object(col, "permissions_at", return_value=copy.deepcopy(controls.ROOT_RUNTIME)), \
             mock.patch.object(col, "runtime_parent", side_effect=error), \
             mock.patch.object(col, "runtime_parent_after_enoent", return_value=retry_value) as retry, \
             mock.patch.object(col, "identity_maps"), mock.patch.object(col, "cgroup_path", return_value=trace["cgroup"]), \
             mock.patch.object(col.os, "stat", return_value=SimpleNamespace(st_dev=88, st_ino=1002)), \
             mock.patch.object(col, "hash_executable", return_value={"sha256": "d" * 64}):
            try:
                col.process(200, trace["cgroup"], 90, CID, trace["runtime"], handle)
            except col.EvidenceError as failure:
                return retry, failure
        return retry, None

    def test_enoent_esrch_and_exited_parent_retry_with_their_reason(self):
        self.assertIsNotNone(EXITED)
        for error, reason in ((FileNotFoundError(errno.ENOENT, "x"), "parent-ENOENT"),
                              (ProcessLookupError(errno.ESRCH, "x"), "parent-ESRCH"),
                              (EXITED("runtime-parent-exited") if EXITED else None, "parent-exited")):
            with self.subTest(reason=reason):
                retry, failure = self.process(error)
                self.assertIsNone(failure)
                retry.assert_called_once()
                self.assertEqual(retry.call_args.kwargs.get("reason"), reason)

    def test_other_parent_errors_are_not_retried(self):
        for error in (col.EvidenceError("unverified-runtime-command"), col.EvidenceError("runtime-parent-identity-race")):
            with self.subTest(error=error.args):
                retry, failure = self.process(error)
                retry.assert_not_called()
                self.assertEqual(failure.args, error.args)
        with self.assertRaises(PermissionError):
            self.process(PermissionError(errno.EACCES, "x"))

    def test_retry_continues_after_esrch_or_exited_parent_and_records_reason(self):
        self.assertIsNotNone(EXITED)
        trace = base.trusted_fixture()
        row = base.external_row(trace)
        key = tuple(row["key"])
        handle = {"key": key, "directory": 11, "pidfd": 12, "evidence": row["binding"]}
        inode = SimpleNamespace(st_dev=88, st_ino=1002)
        for error, reason in ((ProcessLookupError(errno.ESRCH, "x"), "parent-ESRCH"), (EXITED("runtime-parent-exited"), "parent-exited")):
            with self.subTest(reason=reason), \
                    mock.patch.object(col, "clock", return_value=101.09), \
                    mock.patch.object(col, "check_binding"), \
                    mock.patch.object(col, "stat_at", side_effect=[(key, 95), (key, 95), (key, 90), (key, 90)]), \
                    mock.patch.object(col.os, "stat", return_value=inode), \
                    mock.patch.object(col, "command", return_value=("runc", "init")), \
                    mock.patch.object(col, "cgroup_at", return_value=trace["cgroup"]), \
                    mock.patch.object(col, "identity_maps"), \
                    mock.patch.object(col, "shim", return_value=trace["samples"][11]["shim"]), \
                    mock.patch.object(col, "runtime_parent", side_effect=error) as parent:
                actual = col.runtime_parent_after_enoent(handle, key, 90, CID, trace["runtime"], trace["cgroup"], [88, 1002],
                                                         reason=reason)
                self.assertEqual(parent.call_count, 1)
                self.assertEqual(actual[0], 90)
                self.assertEqual(actual[3]["reason"], reason)
                self.assertEqual(len(actual[3]["reads"]), 2)


class PinReasons(unittest.TestCase):
    def pin(self, stats=None, identities=None, cgroup="/c", state="S", events=0):
        stats = stats or [((200, 10100), 90, state), ((200, 10100), 90, state)]
        identities = identities or [SimpleNamespace(st_dev=9, st_ino=1), SimpleNamespace(st_dev=9, st_ino=1)]
        with mock.patch.object(col.os, "open", return_value=47), mock.patch.object(col.os, "close"), \
                mock.patch.object(col.os, "pidfd_open", return_value=48), \
                mock.patch.object(col.os, "fstat", return_value=identities[0]), \
                mock.patch.object(col.os, "stat", return_value=identities[1]), \
                mock.patch.object(col, "stat_detail_at", side_effect=list(stats)), \
                mock.patch.object(col, "cgroup_at", return_value=cgroup), \
                mock.patch.object(col, "pidfd_events", return_value=events):
            return col.pin_process(200, "/c")

    def test_each_mismatch_has_its_own_code_before_exit(self):
        cases = (({"stats": [((200, 10100), 90, "Z"), ((200, 10101), 90, "Z")]}, "initial-process-key-changed"),
                 ({"identities": [SimpleNamespace(st_dev=9, st_ino=1), SimpleNamespace(st_dev=9, st_ino=2)], "state": "Z"},
                  "initial-procdir-identity-changed"),
                 ({"cgroup": "/other", "state": "Z", "events": 1}, "initial-process-cgroup-mismatch"),
                 ({"state": "Z"}, "unverified-initial-process-binding"),
                 ({"events": 1}, "unverified-initial-process-binding"))
        for kwargs, code in cases:
            with self.subTest(code=code, kwargs=kwargs):
                with raises(self, col.EvidenceError) as caught:
                    self.pin(**kwargs)
                self.assertEqual(caught.exception.args, (code,))
        self.assertEqual(self.pin()["key"], (200, 10100))


class ReferenceContent(unittest.TestCase):
    STAT = [88, 1002, 0o100755, 0, 32, 1000000000, 1000000000]

    def read(self, data, reference=b"r" * 32, size=32, changed=False):
        before = list(self.STAT)
        before[4] = size
        info = SimpleNamespace(st_dev=88, st_ino=1002, st_mode=0o100755, st_uid=0, st_size=size,
                               st_mtime_ns=1000000001 if changed else 1000000000, st_ctime_ns=1000000000)
        blocks = [data[i:i + 7] for i in range(0, len(data), 7)] + [b""]
        with mock.patch.dict(col.REFERENCE, {"sha256": "f" * 64, "data": reference} if reference is not None else {}, clear=True), \
                mock.patch.object(col.os, "pread", side_effect=blocks), mock.patch.object(col.os, "fstat", return_value=info):
            return col.hash_executable(47, before, 101.0)

    def test_equal_bytes_give_reference_digest_and_method(self):
        record = self.read(b"r" * 32)
        self.assertEqual((record.get("sha256"), record.get("bytes_hashed"), record.get("method")),
                         ("f" * 64, 32, "bytes-equal-to-verified-reference"))

    def test_any_difference_truncation_or_missing_reference_fails(self):
        for name, kwargs in (("byte", {"data": b"r" * 31 + b"x"}), ("shorter", {"data": b"r" * 31, "size": 31}),
                             ("longer", {"data": b"r" * 33, "size": 33}), ("missing", {"data": b"r" * 32, "reference": None}),
                             ("truncated-read", {"data": b"r" * 31}), ("changed", {"data": b"r" * 32, "changed": True})):
            with self.subTest(case=name):
                with raises(self, col.EvidenceError):
                    self.read(**kwargs)

    def test_host_binary_sets_reference_once_from_its_own_bytes(self):
        info = SimpleNamespace(st_dev=8, st_ino=1002, st_mode=0o100755, st_uid=0, st_size=4,
                               st_mtime_ns=1, st_ctime_ns=1)
        runtime = {"path": "/usr/bin/runc", "exe_identity": [8, 1002]}
        with mock.patch.dict(col.REFERENCE, {}, clear=True), mock.patch.object(col.os, "open", return_value=47), \
                mock.patch.object(col.os, "close"), mock.patch.object(col.os, "fstat", return_value=info), \
                mock.patch.object(col.os, "pread", side_effect=[b"abcd", b"", b"wxyz", b""]):
            first = col.host_binary(runtime)
            reference = dict(col.REFERENCE)
            second = col.host_binary(runtime)
            self.assertEqual(col.REFERENCE, reference)
        self.assertEqual(first["sha256"], hashlib.sha256(b"abcd").hexdigest())
        self.assertEqual(second["sha256"], hashlib.sha256(b"wxyz").hexdigest())
        self.assertEqual(reference, {"sha256": first["sha256"], "data": b"abcd"})
        self.assertNotIn("method", first)

    def test_profile_requires_reference_method_for_runtime_executable(self):
        trace = base.trusted_fixture()
        self.assertIs(assessed(trace)["passed"], True)
        for value in (None, "sha256"):
            with self.subTest(method=value):
                trace = base.trusted_fixture()
                for sample in trace["samples"]:
                    for row in sample["processes"]:
                        if "runtime_executable" in row:
                            if value is None:
                                row["runtime_executable"]["file"].pop("method")
                            else:
                                row["runtime_executable"]["file"]["method"] = value
                self.assertEqual(assessed(trace), {"passed": False, "reason": "runtime-content-mismatch"})


class ExecTransitionPoints(unittest.TestCase):
    CGROUP = "/qa/docker-" + CID + ".scope"

    def run_process(self, argv, *, commands=(), stats=(), cgroups=(), parent=None, parent_pid=95, previous=None, uid=0,
                    exe_after=None, partial=None):
        handle = {"key": KNOWN, "directory": 11, "pidfd": 12, "evidence": {"procdir_identity": [9, 200]}}
        own, path, said = list(stats), list(cgroups), [tuple(argv)] + list(commands)
        permissions = {"uids": [uid] * 4, "gids": [uid] * 4, "groups": [], "nnp": 1,
                       "caps": dict.fromkeys(("inh", "prm", "eff", "bnd", "amb"), 0)}
        info = SimpleNamespace(st_dev=88, st_ino=1002, st_mode=0o100755, st_uid=0, st_size=32,
                               st_mtime_ns=1000000000, st_ctime_ns=1000000000)
        runtime = base.runtime_fixture()

        def proc_stat(pid):
            if pid == KNOWN[0]:
                return own.pop(0) if own else (KNOWN, parent_pid)
            if parent is not None:
                raise parent
            return ((pid, 10050), 90)

        def command(pid):
            value = said.pop(0) if said else tuple(argv)
            if isinstance(value, BaseException):
                raise value
            return value

        with ExitStack() as stack:
            for target, name, kwargs in (
                    (col, "check_binding", {}), (col, "proc_stat", {"side_effect": proc_stat}),
                    (col, "runtime_parent", {"side_effect": lambda pid, *args: {"key": list(proc_stat(pid)[0])}}),
                    (col, "command", {"side_effect": command}), (col, "permissions_at", {"return_value": permissions}),
                    (col, "identity_maps", {}), (col, "cgroup_path", {"side_effect": lambda pid: path.pop(0) if path else self.CGROUP}),
                    (col.os, "open", {"return_value": 47}), (col.os, "fstat", {"return_value": info}), (col.os, "close", {}),
                    (col.os, "stat", {"return_value": info if exe_after is None else exe_after}),
                    (col, "cgroup_at", {"return_value": self.CGROUP}),
                    (col, "hash_executable", {"return_value": {"sha256": runtime["binary"]["sha256"]}})):
                stack.enter_context(mock.patch.object(target, name, **kwargs))
            return col.process(KNOWN[0], self.CGROUP, 90, CID, runtime, handle, previous, {} if partial is None else partial)

    def transition(self, reason, **kwargs):
        with raises(self, col.RuntimeExecTransition) as caught:
            self.run_process(**kwargs)
        self.assertEqual(caught.exception.args[0], reason)
        self.assertEqual({name: caught.exception.args[1][name] for name in ("key", "cgroup")}, {"key": list(KNOWN), "cgroup": self.CGROUP})
        return caught.exception.args[1]

    def original(self, error, **kwargs):
        with self.assertRaises(Exception) as caught:
            self.run_process(**kwargs)
        self.assertNotIsInstance(caught.exception, col.RuntimeExecTransition)
        if isinstance(error, type):
            self.assertIsInstance(caught.exception, error)
        else:
            self.assertEqual(caught.exception.args, (error,))

    def test_baseline_rows_are_complete(self):
        self.assertEqual(self.run_process(base.HEALTH, parent_pid=90)["parent"], [90, 10050])
        self.assertEqual(self.run_process(["runc", "init"], parent_pid=90)["argv"], ["runc", "init"])

    def test_health_with_exited_runtime_parent_is_transition(self):
        gone = FileNotFoundError(errno.ENOENT, "runc exec exited")
        self.transition("runtime-exec-transition-parent-exited", argv=base.HEALTH, parent=gone)
        self.transition("runtime-exec-transition-parent-exited", argv=base.HEALTH, parent=ProcessLookupError(errno.ESRCH, "x"))
        self.original(FileNotFoundError, argv=base.HEALTH, parent=gone, stats=[(KNOWN, 95), ((200, 10101), 95)])
        self.original(FileNotFoundError, argv=base.HEALTH, parent=gone, cgroups=[self.CGROUP + "x"])
        self.original(FileNotFoundError, argv=base.HEALTH, parent=gone, parent_pid=90)
        self.original(FileNotFoundError, argv=["/usr/local/bin/python", "/usr/local/bin/netops", "serve"], parent=gone, uid=51000)
        self.original(PermissionError, argv=base.HEALTH, parent=PermissionError(errno.EACCES, "x"))

    def test_parent_changed_to_shim_or_runtime_execed_into_product_is_transition(self):
        self.transition("runtime-exec-transition-during-snapshot", argv=base.HEALTH, stats=[(KNOWN, 95), (KNOWN, 90)])
        self.original("process-parent-changed-during-snapshot", argv=base.HEALTH, stats=[(KNOWN, 95), (KNOWN, 91)])
        self.original("process-key-changed-during-snapshot", argv=base.HEALTH, stats=[(KNOWN, 95), ((200, 10101), 90)])
        self.original("process-parent-changed-during-snapshot", argv=base.HEALTH, stats=[(KNOWN, 95), (KNOWN, 90), (KNOWN, 90)],
                      cgroups=[self.CGROUP, self.CGROUP + "x"])
        facts = self.transition("runtime-exec-transition-during-snapshot", argv=["runc", "init"], parent_pid=90,
                                commands=[tuple(base.HEALTH)])
        self.assertEqual((facts.get("first_argv"), facts.get("second_argv")), (["runc", "init"], list(base.HEALTH)))
        for after in (("/usr/local/bin/python", "/usr/local/bin/netops", "serve"),
                      ("/usr/local/bin/python", "-m", "netops", "worker", "helper")):
            with self.subTest(after=after):
                self.original("process-command-changed-during-snapshot", argv=["runc", "init"], parent_pid=90, commands=[after])
        worker = ["/usr/local/bin/python", "-m", "netops", "worker", "helper"]
        self.original("process-parent-changed-during-snapshot", argv=worker, uid=51001, stats=[(KNOWN, 95), (KNOWN, 90)])
        self.original("process-command-changed-during-snapshot", argv=["runc", "init"], parent_pid=90, commands=[("sh", "-c", "id")])
        self.original("process-command-changed-during-snapshot", argv=base.HEALTH, parent_pid=90,
                      commands=[("/usr/local/bin/python", "/usr/local/bin/netops", "serve")])
        self.original("process-key-changed-during-snapshot", argv=["runc", "init"], parent_pid=90, commands=[tuple(base.HEALTH)],
                      stats=[(KNOWN, 90), ((200, 10101), 90)])

    def test_runtime_transition_carries_content_proof_of_pinned_exe(self):
        partial = {}
        handle = {"key": KNOWN, "directory": 11, "pidfd": 12, "evidence": {"procdir_identity": [9, 200]}}
        runtime = base.runtime_fixture()
        said = [("runc", "init"), tuple(base.HEALTH)]
        info = SimpleNamespace(st_dev=88, st_ino=1002, st_mode=0o100755, st_uid=0, st_size=32,
                               st_mtime_ns=1000000000, st_ctime_ns=1000000000)
        permissions = {"uids": [0] * 4, "gids": [0] * 4, "groups": [], "nnp": 1,
                       "caps": dict.fromkeys(("inh", "prm", "eff", "bnd", "amb"), 0)}
        for content in ({"sha256": runtime["binary"]["sha256"], "method": "bytes-equal-to-verified-reference"},
                        col.EvidenceError("runtime-content-mismatch")):
            with self.subTest(content=content):
                partial, commands = {}, list(said)
                with ExitStack() as stack:
                    for target, name, kwargs in (
                            (col, "check_binding", {}), (col, "proc_stat", {"return_value": (KNOWN, 90)}),
                            (col, "command", {"side_effect": lambda pid: commands.pop(0)}),
                            (col, "permissions_at", {"return_value": permissions}), (col, "identity_maps", {}),
                            (col, "cgroup_path", {"return_value": self.CGROUP}), (col.os, "open", {"return_value": 47}),
                            (col.os, "fstat", {"return_value": info}), (col.os, "close", {}), (col.os, "stat", {"return_value": info}),
                            (col, "cgroup_at", {"return_value": self.CGROUP}),
                            (col, "hash_executable", {"side_effect": content} if isinstance(content, BaseException) else {"return_value": content})):
                        stack.enter_context(mock.patch.object(target, name, **kwargs))
                    if isinstance(content, BaseException):
                        with raises(self, col.EvidenceError) as caught:
                            col.process(KNOWN[0], self.CGROUP, 90, CID, runtime, handle, None, partial)
                        self.assertEqual(caught.exception.args, ("runtime-content-mismatch",))
                    else:
                        with raises(self, col.RuntimeExecTransition):
                            col.process(KNOWN[0], self.CGROUP, 90, CID, runtime, handle, None, partial)
                        self.assertEqual(partial.get("runtime_executable", {}).get("file"), content)
                        self.assertEqual(partial["argv"], ["runc", "init"])

    def test_empty_command_during_exec_is_transition(self):
        empty = col.EvidenceError("empty-process-command")
        runc = {"argv": ["runc", "init"], "uids": [0] * 4}
        with raises(self, col.RuntimeExecTransition) as caught:
            self.run_first_empty(previous=runc)
        self.assertEqual(caught.exception.args[0], "runtime-exec-transition-empty-command")
        for previous in (None, {"argv": list(base.HEALTH), "uids": [51000] * 4}):
            with self.subTest(previous=previous), raises(self, col.EvidenceError) as caught:
                self.run_first_empty(previous=previous)
            self.assertEqual(caught.exception.args, ("empty-process-command",))
        with raises(self, col.EvidenceError) as caught:
            self.run_first_empty(previous=runc, stats=[(KNOWN, 90), ((200, 10101), 90)])
        self.assertEqual(caught.exception.args, ("empty-process-command",))
        self.transition("runtime-exec-transition-empty-command", argv=["runc", "init"], parent_pid=90, commands=[empty])
        self.original("empty-process-command", argv=base.HEALTH, parent_pid=90, commands=[empty])
        self.original("empty-process-command", argv=["runc", "init"], parent_pid=90, commands=[empty],
                      cgroups=[self.CGROUP, self.CGROUP + "x"])

    def run_first_empty(self, previous, stats=()):
        empty = col.EvidenceError("empty-process-command")
        handle = {"key": KNOWN, "directory": 11, "pidfd": 12, "evidence": {}}
        own = list(stats)
        with mock.patch.object(col, "check_binding"), \
                mock.patch.object(col, "proc_stat", side_effect=lambda pid: own.pop(0) if own else (KNOWN, 90)), \
                mock.patch.object(col, "command", side_effect=empty), \
                mock.patch.object(col, "cgroup_path", return_value=self.CGROUP):
            return col.process(KNOWN[0], self.CGROUP, 90, CID, base.runtime_fixture(), handle, previous, {})


class FailureCause(unittest.TestCase):
    def test_cause_and_enotty_stage_are_recorded(self):
        error = OSError(errno.ENOTTY, "x")
        error.netops_stage = "inside-mapping"
        self.assertEqual(col.failure(error), {"reason": "proc-read-or-schema-failed", "error": "OSError", "errno": errno.ENOTTY,
                                              "stage": "inside-mapping"})
        self.assertEqual(col.failure(ValueError("x"), pid=1), {"reason": "proc-read-or-schema-failed", "error": "ValueError",
                                                               "errno": None, "pid": 1})
        self.assertEqual(col.failure(col.EvidenceError("x"), pid=1), {"reason": "x", "pid": 1})


TCGROUP = "/qa/docker-" + CID + ".scope"
ROOT_PERMISSIONS = {"uids": [0] * 4, "gids": [0] * 4, "groups": [], "nnp": 1, "caps": dict.fromkeys(("inh", "prm", "eff", "bnd", "amb"), 0)}
HEALTH_PERMISSIONS = dict(ROOT_PERMISSIONS, uids=[51000] * 4, gids=[51000] * 4)


def health_trace(first=13, last=17, born=10100):
    trace = base.fixture()
    if first == 13:
        base.insert(trace, 10, 13, base.root_health(argv=["runc", "init"]))
    base.insert(trace, first, last, base.process(200, born, 51000, base.HEALTH, base.SHIM))
    trace["samples"][last]["exited"] = [[200, born]]
    return base.observed_fixture(trace)


def runc_proof(**changes):
    return {"pin": "opened-current-exe", "procdir_identity": [9, 1],
            "file": {**base.runtime_file_fixture(), "method": "bytes-equal-to-verified-reference", **changes}}


def attempt(trace, index=13, reason="runtime-exec-transition-during-retry", facts=None, partial=None, **changes):
    row = trace["samples"][index]["processes"][-1]
    item = {"reason": reason,
            "facts": dict({"key": [200, 10100], "cgroup": TCGROUP, "first_argv": ["runc", "init"], "second_argv": list(base.HEALTH)}, **(facts or {})),
            "partial": dict({"pid": 200, "key": [200, 10100], "argv": ["runc", "init"], "permissions": ROOT_PERMISSIONS,
                             "cgroup_before": TCGROUP, "runtime_executable": runc_proof()}, **(partial or {})),
            "binding": row["binding"], "time": row["read_started_at"]}
    item.update(changes)
    return item


def with_attempts(trace, attempts, index=13):
    trace["samples"][index]["processes"][-1]["exec_transitions"] = attempts
    return trace


class TransitionProfile(unittest.TestCase):
    def assess(self, trace):
        return assessed(trace)

    def test_documented_transitions_pass(self):
        variants = {
            "retry": lambda t: [attempt(t)],
            "three": lambda t: [attempt(t)] * 3,
            "parent-exited": lambda t: [attempt(t, reason="runtime-exec-transition-parent-exited",
                                                facts={"first_argv": list(base.HEALTH), "first_parent": 95, "second_argv": None},
                                                partial={"argv": list(base.HEALTH), "permissions": ROOT_PERMISSIONS, "runtime_executable": None})],
            "empty": lambda t: [attempt(t, reason="runtime-exec-transition-empty-command", facts={"empty": True, "second_argv": None},
                                        partial={"argv": ["runc", "init"]})],
            "snapshot-health": lambda t: [attempt(t, reason="runtime-exec-transition-during-snapshot",
                                                  partial={"second_argv": list(base.HEALTH)})],
            "snapshot-shim": lambda t: [attempt(t, reason="runtime-exec-transition-during-snapshot",
                                                facts={"first_argv": list(base.HEALTH), "second_argv": list(base.HEALTH),
                                                       "first_parent": 95, "second_parent": 90},
                                                partial={"argv": list(base.HEALTH), "permissions": ROOT_PERMISSIONS, "runtime_executable": None,
                                                         "second_argv": list(base.HEALTH), "second_parent": 90})],
        }
        for name, build in variants.items():
            with self.subTest(variant=name):
                trace = health_trace()
                attempts = build(trace)
                for item in attempts:
                    item["partial"] = {k: v for k, v in item["partial"].items() if v is not None}
                    item["facts"] = {k: v for k, v in item["facts"].items() if v is not None}
                self.assertIs(self.assess(with_attempts(trace, attempts))["passed"], True, name)

    def test_undocumented_transitions_and_facts_are_rejected(self):
        worker = ["/usr/local/bin/python", "-m", "netops", "worker", "helper"]
        serve = ["/usr/local/bin/python", "/usr/local/bin/netops", "serve"]
        cases = {
            "worker-to-worker": lambda t: attempt(t, reason="runtime-exec-transition-during-snapshot",
                                                  facts={"first_argv": worker, "second_argv": worker}),
            "runc-to-serve": lambda t: attempt(t, facts={"second_argv": serve}),
            "snapshot-runc-to-serve": lambda t: attempt(t, reason="runtime-exec-transition-during-snapshot", facts={"second_argv": serve}),
            "shim-for-worker": lambda t: attempt(t, reason="runtime-exec-transition-during-snapshot",
                                                 facts={"first_argv": worker, "second_argv": worker, "first_parent": 95, "second_parent": 90},
                                                 partial={"argv": worker, "permissions": dict(HEALTH_PERMISSIONS, uids=[51001] * 4, gids=[51001] * 4),
                                                          "runtime_executable": None, "second_argv": worker, "second_parent": 90}),
            "runc-proof-pin": lambda t: attempt(t, partial={"runtime_executable": dict(runc_proof(), pin="other")}),
            "second-parent-not-facts": lambda t: attempt(t, reason="runtime-exec-transition-during-snapshot",
                                                         facts={"first_argv": list(base.HEALTH), "second_argv": list(base.HEALTH),
                                                                "first_parent": 95, "second_parent": 90},
                                                         partial={"argv": list(base.HEALTH), "permissions": ROOT_PERMISSIONS,
                                                                  "runtime_executable": None, "second_argv": list(base.HEALTH),
                                                                  "second_parent": 91}),
            "snapshot-shim-back-to-runc": lambda t: attempt(t, reason="runtime-exec-transition-during-snapshot",
                                                            facts={"first_argv": list(base.HEALTH), "second_argv": ["runc", "init"],
                                                                   "first_parent": 95, "second_parent": 90},
                                                            partial={"argv": list(base.HEALTH), "permissions": ROOT_PERMISSIONS,
                                                                     "runtime_executable": None, "second_argv": ["runc", "init"],
                                                                     "second_parent": 90}),
            "shim-other-parent": lambda t: attempt(t, reason="runtime-exec-transition-during-snapshot",
                                                   facts={"first_argv": list(base.HEALTH), "second_argv": list(base.HEALTH),
                                                          "first_parent": 95, "second_parent": 91},
                                                   partial={"argv": list(base.HEALTH), "permissions": ROOT_PERMISSIONS,
                                                            "runtime_executable": None, "second_argv": list(base.HEALTH),
                                                            "second_parent": 91}),
            "runc-proof-missing": lambda t: attempt(t, partial={"runtime_executable": None}),
            "reason-without-facts": lambda t: attempt(t, facts={"first_argv": None, "second_argv": None}),
            "empty-without-flag": lambda t: attempt(t, reason="runtime-exec-transition-empty-command", facts={"second_argv": None}),
            "parent-exited-at-shim": lambda t: attempt(t, reason="runtime-exec-transition-parent-exited",
                                                       facts={"first_argv": list(base.HEALTH), "first_parent": 90}),
            "unknown-reason": lambda t: attempt(t, reason="runtime-exec-transition-anything"),
            "facts-key": lambda t: attempt(t, facts={"key": [200, 10101]}),
            "facts-cgroup": lambda t: attempt(t, facts={"cgroup": "/other"}),
            "binding": lambda t: attempt(t, binding={"other": True}),
            "time-after-row": lambda t: attempt(t, time=t["samples"][13]["processes"][-1]["read_started_at"] + 1),
            "partial-key": lambda t: attempt(t, partial={"key": [200, 10101]}),
            "partial-second-key": lambda t: attempt(t, partial={"second_key": [200, 10101]}),
            "partial-argv-not-facts": lambda t: attempt(t, partial={"argv": list(base.HEALTH), "runtime_executable": None}),
            "runc-without-proof": lambda t: attempt(t, partial={"runtime_executable": {"pin": "opened-current-exe"}}),
            "runc-proof-sha": lambda t: attempt(t, partial={"runtime_executable": runc_proof(sha256="e" * 64)}),
            "runc-proof-method": lambda t: attempt(t, partial={"runtime_executable": runc_proof(method="sha256")}),
            "second-exe": lambda t: attempt(t, partial={"second_exe": [1, 2]}),
            "runc-permissions": lambda t: attempt(t, partial={"permissions": HEALTH_PERMISSIONS}),
            "second-argv-not-facts": lambda t: attempt(t, partial={"second_argv": serve}),
        }
        for name, build in cases.items():
            with self.subTest(case=name):
                trace = health_trace()
                item = build(trace)
                item["partial"] = {k: v for k, v in item["partial"].items() if v is not None}
                item["facts"] = {k: v for k, v in item["facts"].items() if v is not None}
                actual = self.assess(with_attempts(trace, [item]))
                self.assertIs(actual["passed"], False, name)
                if name in ("second-argv-not-facts", "runc-proof-missing", "shim-for-worker", "runc-proof-pin"):
                    self.assertEqual(actual["reason"], "unverified-exec-transition", name)
        trace = health_trace()
        self.assertIs(self.assess(with_attempts(trace, [attempt(trace)] * 4))["passed"], False)

    def test_observations_are_chronological_with_previous_row(self):
        trace = health_trace()
        later = attempt(trace, index=14)
        self.assertEqual(self.assess(with_attempts(trace, [later], index=14)),
                         {"passed": False, "reason": "health-reverted-to-runtime"})
        trace = health_trace()
        demoted = attempt(trace, reason="runtime-exec-transition-parent-exited",
                          facts={"first_argv": list(base.HEALTH), "first_parent": 95},
                          partial={"argv": list(base.HEALTH), "permissions": HEALTH_PERMISSIONS})
        demoted["partial"].pop("runtime_executable")
        demoted["facts"].pop("second_argv")
        root = copy.deepcopy(demoted)
        root["partial"]["permissions"] = ROOT_PERMISSIONS
        self.assertEqual(self.assess(with_attempts(trace, [demoted, root])),
                         {"passed": False, "reason": "exec-transition-not-monotonic"})
        trace = health_trace()
        self.assertEqual(self.assess(with_attempts(trace, [demoted, attempt(trace)])),
                         {"passed": False, "reason": "exec-transition-not-monotonic"})
        trace = health_trace()
        self.assertEqual(self.assess(with_attempts(trace, [root, attempt(trace)])),
                         {"passed": False, "reason": "exec-transition-not-monotonic"})
        trace = health_trace()
        later = attempt(trace, index=14, partial={"permissions": None})
        later["partial"].pop("permissions")
        self.assertEqual(self.assess(with_attempts(trace, [later], index=14)),
                         {"passed": False, "reason": "exec-transition-not-monotonic"})

    def test_root_seen_only_in_partial_enters_bootstrap_closure(self):
        trace = health_trace(first=200, last=210)
        root = attempt(trace, index=200, reason="runtime-exec-transition-parent-exited",
                       facts={"first_argv": list(base.HEALTH), "first_parent": 95},
                       partial={"argv": list(base.HEALTH), "permissions": ROOT_PERMISSIONS})
        root["partial"].pop("runtime_executable")
        root["facts"].pop("second_argv")
        self.assertIs(self.assess(health_trace(first=200, last=210))["passed"], True)
        self.assertEqual(self.assess(with_attempts(trace, [root], index=200)),
                         {"passed": False, "reason": "bootstrap-exceeded-health-timeout"})

    def test_failure_attempts_are_verified(self):
        trace = scope_base.scope_fixture(base.observed_fixture(base.fixture()), outside=True)
        good = {"reason": "runtime-exec-transition-during-retry",
                "facts": {"key": [101, 1000], "cgroup": trace["cgroup"], "first_argv": ["runc", "init"], "second_argv": list(base.HEALTH)},
                "partial": {"pid": 101}, "binding": {}, "time": 0}
        trace["samples"][5]["scope"]["observed_failures"].append({"pid": 101, "reason": "proc-read-or-schema-failed", "attempts": [good]})
        self.assertEqual(assessed(trace, require_scope=True),
                         {"passed": False, "reason": "unresolved-earlier-namespace-observation-failure"})


def failure_trace(partial=None, attempts=None):
    trace = health_trace()
    failure = {"pid": 200, "reason": "proc-read-or-schema-failed"}
    if partial is not None:
        failure["partial_observation"] = dict({"pid": 200, "key": [200, 10100]}, **partial)
    if attempts is not None:
        failure["attempts"] = attempts
    trace["samples"][17]["scope"] = {"observed_failures": [failure]}
    return trace


def failure_attempt(trace, **changes):
    item = attempt(trace, index=16, reason="runtime-exec-transition-parent-exited",
                   facts={"first_argv": list(base.HEALTH), "first_parent": 95},
                   partial={"argv": list(base.HEALTH), "permissions": HEALTH_PERMISSIONS})
    item["partial"].pop("runtime_executable")
    item["facts"].pop("second_argv")
    item["time"] = trace["samples"][17]["time"]
    for name, value in changes.items():
        if name in ("facts", "partial"):
            item[name].update(value)
        else:
            item[name] = value
    return item


class KnownExitFailureProfile(unittest.TestCase):
    def assess(self, trace):
        return assessed(trace)

    def test_safe_partial_and_attempts_of_known_exit_pass(self):
        trace = failure_trace({"argv": list(base.HEALTH), "permissions": HEALTH_PERMISSIONS, "second_key": [200, 10100],
                               "second_parent": 90, "second_argv": list(base.HEALTH)})
        self.assertIs(self.assess(trace)["passed"], True)
        trace = failure_trace({"argv": list(base.HEALTH)})
        trace["samples"][17]["scope"]["observed_failures"][0]["attempts"] = [failure_attempt(trace)] * 4
        self.assertIs(self.assess(trace)["passed"], True)
        self.assertIs(self.assess(failure_trace({}))["passed"], True)

    def test_generic_partial_without_attempts_is_verified(self):
        worker = ["/usr/local/bin/python", "-m", "netops", "worker", "helper"]
        cases = {
            "key": {"key": [200, 10101]},
            "second-key": {"second_key": [200, 10101]},
            "runc-after-health": {"argv": ["runc", "init"], "permissions": ROOT_PERMISSIONS},
            "runc-after-health-no-permissions": {"argv": ["runc", "init"]},
            "root-health-after-demotion": {"argv": list(base.HEALTH), "permissions": ROOT_PERMISSIONS},
            "other-command": {"argv": worker, "permissions": dict(HEALTH_PERMISSIONS, uids=[51001] * 4, gids=[51001] * 4)},
            "unknown-command": {"argv": ["x"]},
            "second-argv-changed": {"argv": list(base.HEALTH), "second_argv": ["runc", "init"]},
            "unknown-second-argv": {"second_argv": ["x"]},
            "other-command-no-permissions": {"argv": worker},
            "extra-capability": {"argv": list(base.HEALTH), "permissions": dict(HEALTH_PERMISSIONS, caps=dict(HEALTH_PERMISSIONS["caps"], eff=1))},
        }
        reasons = {"unknown-command": "unknown-observed-command", "unknown-second-argv": "unknown-observed-command",
                   "other-command-no-permissions": "exec-transition-not-monotonic",
                   "runc-after-health-no-permissions": "unverified-exec-transition",
                   "second-argv-changed": "unverified-exec-transition"}
        for name, partial in cases.items():
            with self.subTest(case=name):
                actual = self.assess(failure_trace(partial))
                self.assertIs(actual["passed"], False, name)
                if name in reasons:
                    self.assertEqual(actual["reason"], reasons[name], name)
                if name == "root-health-after-demotion":
                    self.assertNotEqual(actual["reason"], "exec-transition-not-monotonic", name)

    def test_failure_attempts_use_binding_time_and_previous_row(self):
        cases = {
            "binding": lambda t: failure_attempt(t, binding={"other": True}),
            "time-after-sample": lambda t: failure_attempt(t, time=t["samples"][17]["time"] + .001),
            "time-before-binding": lambda t: failure_attempt(t, time=-1),
            "root-after-demotion": lambda t: failure_attempt(t, partial={"permissions": ROOT_PERMISSIONS}),
            "runc-after-health": lambda t: attempt(t, index=16, time=t["samples"][17]["time"]),
            "facts-key": lambda t: failure_attempt(t, facts={"key": [200, 10101]}),
            "shim-parent": lambda t: failure_attempt(t, facts={"first_parent": 90}),
        }
        for name, build in cases.items():
            with self.subTest(case=name):
                trace = failure_trace({"argv": list(base.HEALTH)})
                trace["samples"][17]["scope"]["observed_failures"][0]["attempts"] = [build(trace)]
                actual = self.assess(trace)
                self.assertIs(actual["passed"], False, name)
                if name in ("runc-after-health", "root-after-demotion"):
                    self.assertNotEqual(actual["reason"], "exec-transition-not-monotonic", name)
        trace = failure_trace({"argv": list(base.HEALTH)})
        trace["samples"][17]["scope"]["observed_failures"][0]["attempts"] = [failure_attempt(trace)] * 5
        self.assertIs(self.assess(trace)["passed"], False)

    def test_failure_of_key_that_did_not_exit_is_rejected(self):
        trace = failure_trace({})
        trace["samples"][17]["scope"]["observed_failures"][0]["pid"] = 101
        self.assertEqual(self.assess(trace), {"passed": False, "reason": "unresolved-earlier-namespace-observation-failure"})

    def test_root_seen_in_failure_enters_bootstrap_closure(self):
        trace = base.fixture()
        base.insert(trace, 10, 13, base.root_health(argv=["runc", "init"]))
        trace["samples"][13]["exited"] = [[200, 10100]]
        trace = base.observed_fixture(trace)
        root = {"argv": ["runc", "init"], "permissions": ROOT_PERMISSIONS, "cgroup_before": TCGROUP}
        trace["samples"][13]["scope"] = {"observed_failures": [{"pid": 200, "reason": "proc-read-or-schema-failed",
                                                                "partial_observation": dict({"pid": 200, "key": [200, 10100]}, **root)}]}
        self.assertEqual(self.assess(trace), {"passed": False, "reason": "runc-exit-without-health-proof"})


class RetryReasonProfile(unittest.TestCase):
    def test_parent_retry_reason_set_is_exact(self):
        for reason in ("parent-ENOENT", "parent-ESRCH", "parent-exited"):
            with self.subTest(reason=reason):
                actual = assessed(controls.retry_trace(reason=reason))
                self.assertIs(actual["passed"], True, actual)
        for reason in ("parent-EACCES", "parent-", "ENOENT", None, "parent-exited-during-proof"):
            with self.subTest(reason=reason):
                actual = assessed(controls.retry_trace(reason=reason))
                self.assertEqual(actual, {"passed": False, "reason": "unbounded-runtime-parent-retry"})


def scoped_vanish(stage="inside-mapping", *, in_raw=False):
    trace = base.fixture()
    base.insert(trace, 10, 13, base.root_health(argv=["runc", "init"]))
    base.insert(trace, 13, 17, base.process(200, 10100, 51000, base.HEALTH, base.SHIM))
    trace["samples"][17]["exited"] = [[200, 10100]]
    legacy = base.observed_fixture(trace)
    scoped = scope_base.scope_fixture(legacy, outside=True)
    sample = scoped["samples"][17]
    first = sample["scope"]["inventories"][0]
    if stage == "inside-mapping":
        first["visible_pids"] = sorted(first["visible_pids"] + [200])
    if stage == "classify-host" or in_raw:
        first["cgroup_pids"] = sorted(first["cgroup_pids"] + [200])
    first["stable"] = False
    first["vanished"] = [{"pid": 200, "key": [200, 10100], "local_pid": 200, "stage": stage,
                          "error": "ProcessLookupError", "errno": errno.ESRCH, "verified_absent_at": sample["time"]}]
    return legacy, scoped


class VanishedProfileBinding(unittest.TestCase):
    def assess(self, trace):
        return assessed(trace, require_scope=True)

    def first(self, trace):
        return trace["samples"][17]["scope"]["inventories"][0]

    def item(self, trace):
        return self.first(trace)["vanished"][0]

    def reject(self, trace, reason="unproven-vanished-cgroup-process"):
        actual = self.assess(trace)
        self.assertEqual(actual, {"passed": False, "reason": reason})

    def test_inside_mapping_and_classify_host_vanish_pass_like_legacy(self):
        for stage, in_raw in (("inside-mapping", False), ("inside-mapping", True), ("classify-host", True)):
            with self.subTest(stage=stage, in_raw=in_raw):
                legacy, scoped = scoped_vanish(stage, in_raw=in_raw)
                expected = assessed(legacy)
                self.assertIs(expected["passed"], True)
                self.assertEqual(self.assess(scoped), expected)

    def test_visible_unmapped_local_without_vanish_is_rejected(self):
        _, scoped = scoped_vanish()
        self.first(scoped)["vanished"] = []
        self.reject(scoped, "visible-container-process-unmapped")

    def test_every_binding_field_is_required(self):
        cases = {
            "key-missing": lambda item, first, trace: item.pop("key"),
            "key-other-start": lambda item, first, trace: item.update(key=[200, 10101]),
            "key-other-pid": lambda item, first, trace: item.update(key=[201, 10100]),
            "key-bool": lambda item, first, trace: item.update(key=[200, True]),
            "key-float": lambda item, first, trace: item.update(key=[200, 10100.0]),
            "key-tuple": lambda item, first, trace: item.update(key=(200, 10100)),
            "key-long": lambda item, first, trace: item.update(key=[200, 10100, 1]),
            "local-missing": lambda item, first, trace: item.pop("local_pid"),
            "local-float": lambda item, first, trace: item.update(local_pid=200.0),
            "local-other": lambda item, first, trace: (item.update(local_pid=201), first.update(visible_pids=sorted(first["visible_pids"] + [201]))),
            "local-init": lambda item, first, trace: item.update(local_pid=1),
            "pid-other": lambda item, first, trace: item.update(pid=201),
            "pid-bool": lambda item, first, trace: item.update(pid=True),
            "pid-float": lambda item, first, trace: item.update(pid=200.0),
            "errno-float": lambda item, first, trace: item.update(errno=3.0),
            "errno-bool-exited": lambda item, first, trace: item.update(error="ProcessExited", errno=False),
            "exited-with-errno": lambda item, first, trace: item.update(error="ProcessExited", errno=3),
            "oserror-other-errno": lambda item, first, trace: item.update(error="OSError", errno=errno.EINVAL),
            "oserror-no-errno": lambda item, first, trace: item.update(error="OSError", errno=None),
            "errno-swapped": lambda item, first, trace: item.update(errno=errno.ENOENT),
            "errno-missing": lambda item, first, trace: item.pop("errno"),
            "error-other": lambda item, first, trace: item.update(error="PermissionError", errno=errno.EACCES),
            "stage-other": lambda item, first, trace: item.update(stage="inside"),
            "stage-classify-visible": lambda item, first, trace: (item.update(stage="classify-host"),
                                                                  first.update(cgroup_pids=sorted(first["cgroup_pids"] + [200]))),
            "time-before": lambda item, first, trace: item.update(verified_absent_at=first["read_started_at"] - 1),
            "time-nan": lambda item, first, trace: item.update(verified_absent_at=float("nan")),
            "end-visible": lambda item, first, trace: first.update(end_visible_pids=sorted(first["end_visible_pids"] + [200])),
            "end-cgroup": lambda item, first, trace: first.update(end_cgroup_pids=sorted(first["end_cgroup_pids"] + [200])),
            "not-exited": lambda item, first, trace: trace["samples"][17].update(exit_proofs=[]),
            "not-dict": lambda item, first, trace: first.update(vanished=[200]),
        }
        for name, change in cases.items():
            with self.subTest(change=name):
                _, scoped = scoped_vanish()
                change(self.item(scoped), self.first(scoped), scoped)
                actual = self.assess(scoped)
                self.assertIs(actual["passed"], False, actual)
                if name not in ("not-exited",):
                    self.assertEqual(actual["reason"], "unproven-vanished-cgroup-process")

    def test_classify_host_requires_raw_and_hidden_local(self):
        _, scoped = scoped_vanish("classify-host", in_raw=True)
        first = self.first(scoped)
        first["cgroup_pids"].remove(200)
        self.reject(scoped)
        _, scoped = scoped_vanish("classify-host", in_raw=True)
        self.first(scoped)["visible_pids"] = sorted(self.first(scoped)["visible_pids"] + [200])
        self.reject(scoped)

    def test_inside_mapping_requires_visible_local(self):
        _, scoped = scoped_vanish("inside-mapping", in_raw=True)
        self.first(scoped)["visible_pids"].remove(200)
        self.reject(scoped)

    def test_key_must_be_mapped_earlier_to_same_local(self):
        _, scoped = scoped_vanish()
        for sample in scoped["samples"][10:17]:
            for inventory in sample["scope"]["inventories"]:
                for item in inventory["mappings"]:
                    if item["key"] == [200, 10100]:
                        item["local_pid"] = item["in_namespace"] = 201
                inventory["visible_pids"] = sorted(201 if pid == 200 else pid for pid in inventory["visible_pids"])
                inventory["end_visible_pids"] = list(inventory["visible_pids"])
        self.reject(scoped)

    def test_enotty_trigger_is_accepted(self):
        legacy, scoped = scoped_vanish()
        self.item(scoped).update(error="OSError", errno=errno.ENOTTY)
        self.assertEqual(self.assess(scoped), assessed(legacy))

    def test_enotty_is_only_accepted_for_inside_mapping(self):
        _, scoped = scoped_vanish("classify-host")
        self.item(scoped).update(error="OSError", errno=errno.ENOTTY)
        self.reject(scoped)

    def test_exited_trigger_without_errno_is_accepted(self):
        legacy, scoped = scoped_vanish()
        self.item(scoped).update(error="ProcessExited", errno=None)
        self.assertEqual(self.assess(scoped), assessed(legacy))

    def test_duplicate_vanish_is_rejected(self):
        _, scoped = scoped_vanish()
        first = self.first(scoped)
        first["vanished"].append(copy.deepcopy(first["vanished"][0]))
        self.reject(scoped)

    def mapping(self, scoped, key, local):
        row = copy.deepcopy(self.first(scoped)["mappings"][1])
        row.update(key=list(key), local_pid=local, from_namespace=key[0], in_namespace=local)
        row["binding"].update(key_before=list(key), key_after=list(key))
        return row

    def test_vanish_without_exit_in_same_sample_is_rejected(self):
        _, scoped = scoped_vanish()
        sample = scoped["samples"][16]
        first = sample["scope"]["inventories"][0]
        first["mappings"] = [item for item in first["mappings"] if item["key"] != [200, 10100]]
        first["end_visible_pids"].remove(200)
        first["end_cgroup_pids"].remove(200)
        first["stable"] = False
        first["vanished"] = [{"pid": 200, "key": [200, 10100], "local_pid": 200, "stage": "inside-mapping",
                              "error": "ProcessLookupError", "errno": errno.ESRCH, "verified_absent_at": sample["time"]}]
        self.reject(scoped)

    def test_pid_or_local_reused_by_mapping_in_same_inventory_is_rejected(self):
        _, scoped = scoped_vanish()
        self.first(scoped)["mappings"].append(self.mapping(scoped, (200, 10150), 250))
        self.reject(scoped)
        _, scoped = scoped_vanish()
        self.first(scoped)["mappings"].append(self.mapping(scoped, (201, 10150), 200))
        self.reject(scoped)

    def test_vanish_in_last_inventory_or_of_mapped_key_is_rejected(self):
        _, scoped = scoped_vanish()
        last = scoped["samples"][17]["scope"]["inventories"][-1]
        last["vanished"] = copy.deepcopy(self.first(scoped)["vanished"])
        last["visible_pids"] = sorted(last["visible_pids"] + [200])
        last["stable"] = False
        self.reject(scoped)
        _, scoped = scoped_vanish()
        first = self.first(scoped)
        row = copy.deepcopy(first["mappings"][1])
        row.update(key=[200, 10100], local_pid=200, from_namespace=200, in_namespace=200)
        row["binding"] = copy.deepcopy(scoped["samples"][16]["processes"][-1]["binding"])
        first["mappings"].append(row)
        actual = self.assess(scoped)
        self.assertIs(actual["passed"], False)


def scoped_unobserved(count=1, where=0):
    legacy = base.observed_fixture(base.fixture())
    scoped = scope_base.scope_fixture(legacy, outside=True)
    sample = scoped["samples"][17]
    inventory = sample["scope"]["inventories"][where]
    pids = [600 + index for index in range(count)]
    inventory["cgroup_pids"] = sorted(inventory["cgroup_pids"] + pids)
    inventory["stable"] = False
    inventory["unobserved"] = [{"pid": pid, "stage": "classify-host", "error": "FileNotFoundError", "errno": errno.ENOENT,
                                "verified_absent_at": sample["time"]} for pid in pids]
    return legacy, scoped


class UnobservedProfile(unittest.TestCase):
    def assess(self, trace):
        return assessed(trace, require_scope=True)

    def first(self, trace):
        return trace["samples"][17]["scope"]["inventories"][0]

    def reject(self, trace):
        self.assertEqual(self.assess(trace), {"passed": False, "reason": "unproven-unobserved-transient"})

    def test_up_to_four_unobserved_pass_like_legacy(self):
        for count in (1, 4):
            with self.subTest(count=count):
                legacy, scoped = scoped_unobserved(count)
                self.assertEqual(self.assess(scoped), assessed(legacy))

    def test_more_than_four_in_sample_is_rejected(self):
        _, scoped = scoped_unobserved(5)
        self.reject(scoped)
        _, scoped = scoped_unobserved(3)
        sample = scoped["samples"][17]
        inventories = sample["scope"]["inventories"]
        inventories.insert(1, copy.deepcopy(inventories[0]))
        inventories[1]["unobserved"] = [dict(item, pid=item["pid"] + 10) for item in inventories[1]["unobserved"][:2]]
        inventories[1]["cgroup_pids"] = sorted(set(inventories[1]["cgroup_pids"]) - {600, 601, 602} | {610, 611})
        sample["scope"]["capture_passes"] = 1
        self.reject(scoped)

    def test_every_field_is_exact(self):
        cases = {"extra-field": lambda item, first: item.update(key=[600, 10150]),
                 "extra-argv": lambda item, first: item.update(argv=["runc"]),
                 "missing": lambda item, first: item.pop("errno"),
                 "pid-text": lambda item, first: item.update(pid="600"),
                 "pid-bool": lambda item, first: item.update(pid=True),
                 "stage": lambda item, first: item.update(stage="inside-mapping"),
                 "error": lambda item, first: item.update(error="ProcessExited", errno=None),
                 "enotty": lambda item, first: item.update(error="OSError", errno=errno.ENOTTY),
                 "errno-swap": lambda item, first: item.update(errno=errno.ESRCH),
                 "errno-float": lambda item, first: item.update(errno=2.0),
                 "pid-float": lambda item, first: item.update(pid=600.0),
                 "time": lambda item, first: item.update(verified_absent_at=10 ** 6),
                 "not-raw": lambda item, first: first.update(cgroup_pids=[pid for pid in first["cgroup_pids"] if pid != 600]),
                 "end-cgroup": lambda item, first: first.update(end_cgroup_pids=sorted(first["end_cgroup_pids"] + [600])),
                 "excluded-pid": lambda item, first: item.update(pid=700),
                 "mapped-pid": lambda item, first: item.update(pid=101),
                 "duplicate": lambda item, first: first["unobserved"].append(copy.deepcopy(item)),
                 "not-dict": lambda item, first: first.update(unobserved=[600]),
                 "not-list": lambda item, first: first.update(unobserved={})}
        for name, change in cases.items():
            with self.subTest(change=name):
                _, scoped = scoped_unobserved()
                first = self.first(scoped)
                change(first["unobserved"][0], first)
                actual = self.assess(scoped)
                self.assertIs(actual["passed"], False, actual)
                if name not in ("not-raw",):
                    self.assertEqual(actual["reason"], "unproven-unobserved-transient")

    def test_pid_seen_elsewhere_in_sample_or_known_is_rejected(self):
        for where in ("later-mapping", "later-excluded", "known-key", "last-inventory"):
            with self.subTest(where=where):
                _, scoped = scoped_unobserved()
                inventories = scoped["samples"][17]["scope"]["inventories"]
                last = inventories[-1]
                if where == "later-mapping":
                    row = copy.deepcopy(last["mappings"][1])
                    row.update(key=[600, 10150], local_pid=600, from_namespace=600, in_namespace=600)
                    row["binding"].update(key_before=[600, 10150], key_after=[600, 10150])
                    last["mappings"].append(row)
                    last["visible_pids"] = sorted(last["visible_pids"] + [600])
                    last["cgroup_pids"] = sorted(last["cgroup_pids"] + [600])
                elif where == "later-excluded":
                    row = copy.deepcopy(last["excluded"][0])
                    row.update(key=[600, 9900])
                    row["binding"] = dict(row["binding"], key_before=[600, 9900], key_after=[600, 9900])
                    last["excluded"].append(row)
                    last["cgroup_pids"] = sorted(last["cgroup_pids"] + [600])
                elif where == "known-key":
                    self.first(scoped)["unobserved"][0]["pid"] = 700
                    self.first(scoped)["cgroup_pids"] = sorted(set(self.first(scoped)["cgroup_pids"]) - {600})
                    self.first(scoped)["excluded"] = []
                else:
                    last["unobserved"] = copy.deepcopy(self.first(scoped)["unobserved"])
                    last["cgroup_pids"] = sorted(last["cgroup_pids"] + [600])
                last["end_cgroup_pids"] = list(last["cgroup_pids"])
                last["end_visible_pids"] = list(last["visible_pids"])
                actual = self.assess(scoped)
                self.assertIs(actual["passed"], False, actual)


class UnobservedSampleProfile(unittest.TestCase):
    def assess(self, trace):
        return assessed(trace, require_scope=True)

    def three(self, scoped):
        sample = scoped["samples"][17]
        inventories = sample["scope"]["inventories"]
        middle = copy.deepcopy(inventories[-1])
        middle["stable"] = False
        inventories.insert(1, middle)
        sample["scope"]["capture_passes"] = 1
        return inventories

    def test_three_inventory_baseline_passes(self):
        legacy, scoped = scoped_unobserved()
        self.three(scoped)
        self.assertEqual(self.assess(scoped), assessed(legacy))

    def test_same_pid_unobserved_in_two_inventories_is_rejected(self):
        _, scoped = scoped_unobserved()
        inventories = self.three(scoped)
        inventories[1]["unobserved"] = copy.deepcopy(inventories[0]["unobserved"])
        inventories[1]["cgroup_pids"] = sorted(inventories[1]["cgroup_pids"] + [600])
        self.assertEqual(self.assess(scoped), {"passed": False, "reason": "unproven-unobserved-transient"})

    def test_unobserved_pid_classified_later_in_sample_is_rejected(self):
        _, scoped = scoped_unobserved()
        inventories = self.three(scoped)
        for inventory in inventories[1:]:
            row = copy.deepcopy(inventory["excluded"][0])
            row.update(key=[600, 9900])
            row["binding"] = dict(row["binding"], key_before=[600, 9900], key_after=[600, 9900])
            inventory["excluded"].append(row)
            inventory["cgroup_pids"] = sorted(inventory["cgroup_pids"] + [600])
        inventories[-1]["end_cgroup_pids"] = list(inventories[-1]["cgroup_pids"])
        self.assertEqual(self.assess(scoped), {"passed": False, "reason": "unproven-unobserved-transient"})

    def test_unobserved_in_last_inventory_is_rejected_by_its_own_rule(self):
        _, scoped = scoped_unobserved()
        last = scoped["samples"][17]["scope"]["inventories"][-1]
        last["unobserved"] = copy.deepcopy(scoped["samples"][17]["scope"]["inventories"][0]["unobserved"])
        last["cgroup_pids"] = sorted(last["cgroup_pids"] + [600])
        self.assertEqual(self.assess(scoped), {"passed": False, "reason": "unproven-unobserved-transient"})

    def test_pid_of_key_known_from_earlier_sample_is_rejected(self):
        legacy = base.fixture()
        base.insert(legacy, 10, 12, base.process(650, 10100, 51000, base.HEALTH, base.SHIM), exited=True)
        legacy = base.observed_fixture(legacy)
        scoped = scope_base.scope_fixture(legacy, outside=True)
        self.assertEqual(self.assess(scoped), assessed(legacy))
        self.assertIs(assessed(legacy)["passed"], True)
        sample = scoped["samples"][17]
        inventory = sample["scope"]["inventories"][0]
        inventory["cgroup_pids"] = sorted(inventory["cgroup_pids"] + [650])
        inventory["stable"] = False
        inventory["unobserved"] = [{"pid": 650, "stage": "classify-host", "error": "FileNotFoundError", "errno": errno.ENOENT,
                                    "verified_absent_at": sample["time"]}]
        self.assertEqual(self.assess(scoped), {"passed": False, "reason": "unproven-unobserved-transient"})


class CollectorMutantGaps(unittest.TestCase):
    def test_collect_clears_reference_before_first_runtime_read(self):
        harness = collector_tests.CollectLoop("test_harness_reaches_assessment_without_collector_error")
        harness.setUp()
        self.addCleanup(harness.tearDown)
        seen, fixture = [], collector_tests.base.runtime_file_fixture

        def recorded(*args, **kwargs):
            seen.append(dict(col.REFERENCE))
            return fixture(*args, **kwargs)

        with mock.patch.dict(col.REFERENCE, {"sha256": "e" * 64, "data": b"stale"}, clear=True), \
                mock.patch.object(collector_tests.base, "runtime_file_fixture", side_effect=recorded):
            harness.collect(harness.empty_sample, [dict(collector_tests.RUNTIME), dict(collector_tests.RUNTIME)])
        self.assertTrue(seen)
        self.assertEqual(seen[0], {})

    def test_host_binary_short_read_is_incomplete(self):
        info = SimpleNamespace(st_dev=8, st_ino=1002, st_mode=0o100755, st_uid=0, st_size=4, st_mtime_ns=1, st_ctime_ns=1)
        runtime = {"path": "/usr/bin/runc", "exe_identity": [8, 1002]}
        with mock.patch.dict(col.REFERENCE, {}, clear=True), mock.patch.object(col.os, "open", return_value=47), \
                mock.patch.object(col.os, "close"), mock.patch.object(col.os, "fstat", return_value=info), \
                mock.patch.object(col.os, "pread", side_effect=[b"abc", b""]):
            with raises(self, col.EvidenceError) as caught:
                col.host_binary(runtime)
            self.assertEqual(col.REFERENCE, {})
        self.assertEqual(caught.exception.args, ("runtime-file-changed-or-incomplete",))

    def test_only_empty_command_after_runtime_is_a_transition(self):
        for error in ("unknown-process-command", "invalid-process-command"):
            with self.subTest(error=error), mock.patch.object(col, "command", side_effect=col.EvidenceError(error)), \
                    mock.patch.object(col, "exec_transition") as transition:
                with raises(self, col.EvidenceError) as caught:
                    col.exec_command(200, KNOWN, "/qa", True)
                self.assertEqual(caught.exception.args, (error,))
                transition.assert_not_called()

    def test_runtime_exe_changed_during_snapshot_is_failure_with_second_read(self):
        points = ExecTransitionPoints()
        changed = SimpleNamespace(st_dev=88, st_ino=1003, st_mode=0o100755, st_uid=0, st_size=32,
                                  st_mtime_ns=1000000000, st_ctime_ns=1000000000)
        partial = {}
        with raises(self, col.EvidenceError) as caught:
            points.run_process(["runc", "init"], parent_pid=90, exe_after=changed, partial=partial)
        self.assertEqual(caught.exception.args, ("runtime-executable-changed-during-snapshot",))
        self.assertEqual((partial.get("second_key"), partial.get("second_parent"), partial.get("second_exe")), (list(KNOWN), 90, [88, 1003]))
        partial = {}
        with raises(self, col.EvidenceError) as caught:
            points.run_process(base.HEALTH, stats=[(KNOWN, 95), (KNOWN, 91)], partial=partial)
        self.assertEqual(caught.exception.args, ("process-parent-changed-during-snapshot",))
        self.assertEqual((partial.get("second_key"), partial.get("second_parent")), (list(KNOWN), 91))


class UnobservedCollector(unittest.TestCase):
    def test_new_pid_failing_first_read_is_unobserved_only_when_absent(self):
        for change in (None, "cgroup", "hostproc", "esrch"):
            with self.subTest(change=change):
                kernel = Kernel(NEW[0], "reaped", 0, ("new",))
                kernel.when = "proc_stat"
                if change == "cgroup":
                    members = kernel.members
                    kernel.members = lambda directory: members(directory) | {NEW[0]} if kernel.fired else members(directory)
                elif change == "hostproc":
                    stat = kernel.stat

                    def present(name, *, dir_fd=None, follow_symlinks=True):
                        if dir_fd == HOSTPROC and name == str(NEW[0]):
                            return SimpleNamespace(st_dev=9, st_ino=NEW[0])
                        return stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

                    kernel.stat = present
                elif change == "esrch":
                    proc_stat = kernel.proc_stat

                    def esrch(pid):
                        if pid == NEW[0] and kernel.procs[NEW[0]]["state"] == "live":
                            kernel.procs[NEW[0]]["state"] = "gone"
                            kernel.fired = "proc_stat"
                            raise ProcessLookupError(errno.ESRCH, "synthetic")
                        return proc_stat(pid)

                    kernel.proc_stat = esrch
                result = kernel.inventory()
                self.assertEqual(kernel.fired, "proc_stat")
                if change in ("cgroup", "hostproc"):
                    self.assertIs(result["complete"], False)
                    self.assertEqual(result["unobserved"], [])
                else:
                    self.assertIs(result["complete"], True, result["failures"])
                    self.assertEqual([item["pid"] for item in result["unobserved"]], [NEW[0]])
                    self.assertEqual(set(result["unobserved"][0]), {"pid", "stage", "error", "errno", "verified_absent_at"})

    def sample(self, counts):
        initial = {100, 101, 102, 103}
        entries = []
        for index, count in enumerate(counts):
            entries.append({"mappings": [{"key": [pid, 1000]} for pid in sorted(initial)], "excluded": [], "failures": [],
                            "complete": True, "stable": index == len(counts) - 1,
                            "unobserved": [{"pid": 600 + index * 10 + n} for n in range(count)]})
        trace = base.observed_fixture(base.fixture())
        rows = {row["key"][0]: row for row in trace["samples"][0]["processes"]}
        handles = {tuple(row["key"]): {"key": tuple(row["key"]), "evidence": row["binding"]} for row in rows.values()}
        scope = SimpleNamespace(inventory=mock.Mock(side_effect=entries), release=lambda: None)
        with mock.patch.object(col, "proc_stat", side_effect=lambda pid: (tuple(rows[pid]["key"]), 90)), \
                mock.patch.object(col, "process", side_effect=lambda pid, *args: copy.deepcopy(rows[pid])), \
                mock.patch.object(col, "shim", return_value=trace["samples"][0]["shim"]), \
                mock.patch.object(col, "cgroup_path", return_value=trace["cgroup"]), \
                mock.patch.object(col, "members", return_value=initial), \
                mock.patch.object(col, "clock", return_value=100.0):
            return col.sample(None, trace["cgroup"], (100, 1000), 90, CID, {}, {}, handles, 99.9, scope=scope)

    def test_sample_limit_of_four_unobserved(self):
        self.assertIs(self.sample([2, 2])["complete"], True)
        result = self.sample([3, 2])
        self.assertIs(result["complete"], False)
        self.assertIn({"reason": "unobserved-transient-limit"}, result["failures"])


def scoped_zombie():
    legacy, scoped = scoped_vanish()
    first = scoped["samples"][17]["scope"]["inventories"][0]
    item = first["vanished"][0]
    item.update(error="ProcessExited", errno=None,
                zombie={"pidfd_events": 17, "key": [200, 10100], "state": "Z", "local_key": [200, 10100],
                        "local_state": "Z", "verified_at": item["verified_absent_at"]})
    first["end_visible_pids"] = sorted(first["end_visible_pids"] + [200])
    return legacy, scoped


class ZombieProfile(unittest.TestCase):
    def item(self, trace):
        return trace["samples"][17]["scope"]["inventories"][0]["vanished"][0]

    def test_proven_zombie_passes_like_legacy(self):
        legacy, scoped = scoped_zombie()
        expected = assessed(legacy)
        self.assertIs(expected["passed"], True)
        self.assertEqual(assessed(scoped, require_scope=True), expected)

    def test_every_zombie_field_is_required(self):
        cases = {"state": ("state", "S"), "local-state": ("local_state", "R"), "key": ("key", [200, 10101]),
                 "local-key": ("local_key", [200, 10101]), "local-pid": ("local_key", [201, 10100]),
                 "pidfd-live": ("pidfd_events", 0), "pidfd-bool": ("pidfd_events", True), "pidfd-hup": ("pidfd_events", 16),
                 "time-after": ("verified_at", 10 ** 6), "time-before": ("verified_at", 0.0), "time-text": ("verified_at", "x")}
        for name, (field, value) in cases.items():
            with self.subTest(change=name):
                _, scoped = scoped_zombie()
                self.item(scoped)["zombie"][field] = value
                actual = assessed(scoped, require_scope=True)
                self.assertEqual(actual, {"passed": False, "reason": "unproven-vanished-cgroup-process"})
        for name in ("missing-field", "not-dict", "classify-stage"):
            with self.subTest(change=name):
                _, scoped = scoped_zombie()
                item = self.item(scoped)
                first = scoped["samples"][17]["scope"]["inventories"][0]
                if name == "missing-field":
                    del item["zombie"]["local_state"]
                elif name == "not-dict":
                    item["zombie"] = ["Z"]
                else:
                    item["stage"] = "classify-host"
                    first["cgroup_pids"] = sorted(first["cgroup_pids"] + [200])
                    first["visible_pids"].remove(200)
                    first["end_visible_pids"].remove(200)
                actual = assessed(scoped, require_scope=True)
                self.assertEqual(actual, {"passed": False, "reason": "unproven-vanished-cgroup-process"})

    def test_zombie_still_in_cgroup_is_rejected(self):
        _, scoped = scoped_zombie()
        first = scoped["samples"][17]["scope"]["inventories"][0]
        first["end_cgroup_pids"] = sorted(first["end_cgroup_pids"] + [200])
        self.assertEqual(assessed(scoped, require_scope=True),
                         {"passed": False, "reason": "unproven-vanished-cgroup-process"})


def scoped_helper():
    legacy = base.observed_fixture(base.fixture())
    scoped = scope_base.scope_fixture(legacy, outside=True)
    sample = scoped["samples"][17]
    now = sample["time"]
    first = sample["scope"]["inventories"][0]
    first["cgroup_pids"] = sorted(first["cgroup_pids"] + [600])
    first["stable"] = False
    first["exited_helpers"] = [{
        "key": [600, 10150], "stage": "classify-host", "active_namespace": list(HOST),
        "binding": {"method": "procdir+pidfd", "key_before": [600, 10150], "key_after": [600, 10150],
                    "procdir_identity": [9, 600], "procdir_identity_after": [9, 600], "cgroup": scoped["cgroup"], "bound_at": now},
        "permissions": {"uids": [0] * 4, "gids": [0] * 4, "groups": [], "nnp": 0,
                        "caps": dict.fromkeys(("inh", "prm", "eff", "bnd", "amb"), 0)},
        "runtime_parent": {"key": [95, 10050], "key_after": [95, 10050], "parent": [90, 900], "parent_after": [90, 900],
                           "shim": copy.deepcopy(sample["shim"]), "exe": "/usr/bin/runc", "exe_identity": [8, 1002],
                           "exe_identity_after": [8, 1002], "argv": list(RUNC_ARGV), "pin": "procdir+pidfd",
                           "alive_after": True, "read_started_at": now, "read_finished_at": now},
        "file": dict(base.runtime_file_fixture(now, device=58), method="bytes-equal-to-verified-reference"), "parent_pid": 95,
        "parent_link": {"key": [95, 10050], "child_stat_at": now, "child_restat_at": now, "child_restat_key": [600, 10150],
                        "child_restat_parent": 95, "parent_alive_at": now}, "exit": "reaped", "reason": "identified",
        "error": "ProcessLookupError", "errno": errno.ESRCH, "verified_absent_at": now}]
    return legacy, scoped


class ExitedHelperProfile(unittest.TestCase):
    def assess(self, trace):
        return assessed(trace, require_scope=True)

    def item(self, trace):
        return trace["samples"][17]["scope"]["inventories"][0]["exited_helpers"][0]

    def test_identified_helper_exit_passes_like_legacy(self):
        legacy, scoped = scoped_helper()
        expected = assessed(legacy)
        self.assertIs(expected["passed"], True)
        self.assertEqual(self.assess(scoped), expected)

    def test_unlisted_helper_pid_is_unclassified(self):
        _, scoped = scoped_helper()
        scoped["samples"][17]["scope"]["inventories"][0]["exited_helpers"] = []
        self.assertEqual(self.assess(scoped), {"passed": False, "reason": "cgroup-process-unclassified"})

    def test_every_identity_field_is_required(self):
        def parent(field, value):
            return lambda item, first, trace: item["runtime_parent"].update({field: value})
        cases = {
            "sha": (lambda item, first, trace: item["file"].update(sha256="e" * 64), "runtime-helper-content-mismatch"),
            "method-missing": (lambda item, first, trace: item["file"].pop("method"), "runtime-helper-content-mismatch"),
            "method-other": (lambda item, first, trace: item["file"].update(method="sha256"), "runtime-helper-content-mismatch"),
            "bytes": (lambda item, first, trace: item["file"].update(bytes_hashed=31, stat_before=item["file"]["stat_before"][:4] + [31] + item["file"]["stat_before"][5:],
                                                                     stat_after=item["file"]["stat_after"][:4] + [31] + item["file"]["stat_after"][5:]),
                      "runtime-helper-content-mismatch"),
            "file-unstable": (lambda item, first, trace: item["file"].update(stat_after=item["file"]["stat_after"][:6] + [item["file"]["stat_after"][6] + 1]),
                              "unstable-runtime-file"),
            "uid": (lambda item, first, trace: item["permissions"].update(uids=[51000] * 4), "unproven-exited-runtime-helper"),
            "own-ns": (lambda item, first, trace: item.update(active_namespace=list(OWN)), "unproven-exited-runtime-helper"),
            "parent-shim": (parent("parent", [91, 900]), "unproven-exited-runtime-helper"),
            "parent-shim-after": (parent("parent_after", [90, 901]), "unproven-exited-runtime-helper"),
            "shim-record": (parent("shim", {"key": [90, 900]}), "unproven-exited-runtime-helper"),
            "parent-key-after": (parent("key_after", [95, 10051]), "unproven-exited-runtime-helper"),
            "parent-younger": (lambda item, first, trace: (item["runtime_parent"].update(key=[95, 10600], key_after=[95, 10600]),
                                                           item["parent_link"].update(key=[95, 10600])),
                               "unproven-exited-runtime-helper"),
            "parent-self": (lambda item, first, trace: (item["runtime_parent"].update(key=[600, 10150], key_after=[600, 10150]),
                                                        item["parent_link"].update(key=[600, 10150], child_restat_parent=600),
                                                        item.update(parent_pid=600)),
                            "unproven-exited-runtime-helper"),
            "exe": (parent("exe", "/tmp/runc"), "unproven-exited-runtime-helper"),
            "exe-identity": (parent("exe_identity", [8, 1003]), "unproven-exited-runtime-helper"),
            "exe-identity-after": (parent("exe_identity_after", [8, 1003]), "unproven-exited-runtime-helper"),
            "pin": (parent("pin", "procdir"), "unproven-exited-runtime-helper"),
            "alive": (parent("alive_after", False), "unproven-exited-runtime-helper"),
            "argv": (parent("argv", list(RUNC_ARGV[:-1]) + ["b" * 64]), "unverified-runtime-command"),
            "stage": (lambda item, first, trace: item.update(stage="inside-mapping"), "unproven-exited-runtime-helper"),
            "errno": (lambda item, first, trace: item.update(errno=errno.ENOENT), "unproven-exited-runtime-helper"),
            "error": (lambda item, first, trace: item.update(error="PermissionError", errno=errno.EACCES), "unproven-exited-runtime-helper"),
            "parent-before-sample": (lambda item, first, trace: item["runtime_parent"].update(read_started_at=item["verified_absent_at"] - 1),
                                     "unproven-exited-runtime-helper"),
            "parent-after-absent": (lambda item, first, trace: item["runtime_parent"].update(read_finished_at=item["verified_absent_at"] + 1),
                                    "unproven-exited-runtime-helper"),
            "file-after-absent": (lambda item, first, trace: item["file"].update(read_finished_at=item["verified_absent_at"] + 1),
                                  "unproven-exited-runtime-helper"),
            "bound-late": (lambda item, first, trace: item["binding"].update(bound_at=item["verified_absent_at"] + 1),
                           "unproven-exited-runtime-helper"),
            "parent-pid": (lambda item, first, trace: item.update(parent_pid=96), "unproven-exited-runtime-helper"),
            "parent-pid-text": (lambda item, first, trace: item.update(parent_pid="95"), "unproven-exited-runtime-helper"),
            "parent-pid-float": (lambda item, first, trace: item.update(parent_pid=95.0), "unproven-exited-runtime-helper"),
            "parent-pid-other": (lambda item, first, trace: (item.update(parent_pid=96), item["parent_link"].update(child_restat_parent=96)),
                                 "unproven-exited-runtime-helper"),
            "exit": (lambda item, first, trace: item.update(exit="running"), "unproven-exited-runtime-helper"),
            "reason": (lambda item, first, trace: item.update(reason="other"), "unproven-exited-runtime-helper"),
            "identified-without-file": (lambda item, first, trace: item.pop("file"), "unproven-exited-runtime-helper"),
            "identified-without-binding": (lambda item, first, trace: item.pop("binding"), "unproven-exited-runtime-helper"),
            "evidence-error-with-errno": (lambda item, first, trace: item.update(error="EvidenceError", errno=3),
                                          "unproven-exited-runtime-helper"),
            "enotty": (lambda item, first, trace: item.update(error="OSError", errno=errno.ENOTTY), "unproven-exited-runtime-helper"),
            "link-missing": (lambda item, first, trace: item.pop("parent_link"), "unproven-exited-runtime-helper"),
            "link-other-start": (lambda item, first, trace: item["parent_link"].update(key=[95, 10051]), "unproven-exited-runtime-helper"),
            "link-order": (lambda item, first, trace: item["parent_link"].update(child_stat_at=item["verified_absent_at"] + 1),
                           "unproven-exited-runtime-helper"),
            "link-before-sample": (lambda item, first, trace: item["parent_link"].update(child_stat_at=item["verified_absent_at"] - 1),
                                   "unproven-exited-runtime-helper"),
            "link-after-absent": (lambda item, first, trace: item["parent_link"].update(parent_alive_at=item["verified_absent_at"] + 1),
                                  "unproven-exited-runtime-helper"),
            "restat-missing": (lambda item, first, trace: item["parent_link"].pop("child_restat_at"), "invalid-namespace-trace-schema"),
            "restat-key-missing": (lambda item, first, trace: item["parent_link"].pop("child_restat_key"), "invalid-namespace-trace-schema"),
            "restat-parent-missing": (lambda item, first, trace: item["parent_link"].pop("child_restat_parent"),
                                      "invalid-namespace-trace-schema"),
            "restat-before-child-stat": (lambda item, first, trace: item["parent_link"].update(
                child_stat_at=item["verified_absent_at"], child_restat_at=item["verified_absent_at"] - .001,
                parent_alive_at=item["verified_absent_at"]), "unproven-exited-runtime-helper"),
            "restat-before-parent-read": (lambda item, first, trace: (
                item["runtime_parent"].update(read_started_at=item["verified_absent_at"], read_finished_at=item["verified_absent_at"]),
                item["parent_link"].update(child_stat_at=item["verified_absent_at"] - .002, child_restat_at=item["verified_absent_at"] - .001)),
                "unproven-exited-runtime-helper"),
            "restat-before-parent-read-in-window": (lambda item, first, trace: (
                trace["samples"][17].update(read_started_at=item["verified_absent_at"] - .01),
                item["parent_link"].update(child_stat_at=item["verified_absent_at"] - .005,
                                           child_restat_at=item["verified_absent_at"] - .005),
                item["runtime_parent"].update(read_started_at=item["verified_absent_at"] - .002,
                                              read_finished_at=item["verified_absent_at"] - .002)),
                "unproven-exited-runtime-helper"),
            "restat-after-alive": (lambda item, first, trace: item["parent_link"].update(
                child_restat_at=item["verified_absent_at"], parent_alive_at=item["verified_absent_at"] - .001),
                "unproven-exited-runtime-helper"),
            "restat-other-key": (lambda item, first, trace: item["parent_link"].update(child_restat_key=[600, 10151]),
                                 "unproven-exited-runtime-helper"),
            "restat-ppid-changed": (lambda item, first, trace: item["parent_link"].update(child_restat_parent=90),
                                    "unproven-exited-runtime-helper"),
            "restat-ppid-text": (lambda item, first, trace: item["parent_link"].update(child_restat_parent="95"),
                                 "unproven-exited-runtime-helper"),
            "restat-ppid-float": (lambda item, first, trace: item["parent_link"].update(child_restat_parent=95.0),
                                  "unproven-exited-runtime-helper"),
            "time-outside": (lambda item, first, trace: item.update(verified_absent_at=10 ** 6), "unproven-exited-runtime-helper"),
            "binding-cgroup": (lambda item, first, trace: item["binding"].update(cgroup="/foreign"), "unverified-process-binding"),
            "end-cgroup": (lambda item, first, trace: first.update(end_cgroup_pids=sorted(first["end_cgroup_pids"] + [600])),
                           "unproven-exited-runtime-helper"),
            "not-raw": (lambda item, first, trace: first.update(cgroup_pids=[pid for pid in first["cgroup_pids"] if pid != 600]),
                        "unproven-exited-runtime-helper"),
            "duplicate": (lambda item, first, trace: first["exited_helpers"].append(copy.deepcopy(item)), "unproven-exited-runtime-helper"),
            "not-list": (lambda item, first, trace: first.update(exited_helpers={}), "unproven-exited-runtime-helper"),
        }
        for name, (change, reason) in cases.items():
            with self.subTest(change=name):
                _, scoped = scoped_helper()
                first = scoped["samples"][17]["scope"]["inventories"][0]
                change(self.item(scoped), first, scoped)
                actual = self.assess(scoped)
                self.assertIs(actual["passed"], False, actual)
                if reason:
                    self.assertEqual(actual["reason"], reason)

    def test_parent_verified_minimal_and_pin_zombie_records_pass(self):
        for variant in ("minimal", "zombie-pin", "uid-only", "file-only"):
            with self.subTest(variant=variant):
                legacy, scoped = scoped_helper()
                item = self.item(scoped)
                item["reason"] = "parent-verified"
                if variant == "minimal":
                    for name in ("binding", "permissions", "active_namespace", "file"):
                        del item[name]
                elif variant == "zombie-pin":
                    for name in ("binding", "permissions", "file"):
                        del item[name]
                    item.update(error="EvidenceError", errno=None, exit="zombie")
                elif variant == "uid-only":
                    del item["file"]
                else:
                    del item["permissions"]
                self.assertEqual(self.assess(scoped), assessed(legacy))

    def test_partial_read_contradiction_is_rejected(self):
        for name, change in (("uid", lambda item: item["permissions"].update(uids=[0, 0, 0, 1])),
                             ("ns", lambda item: item.update(active_namespace=list(OWN))),
                             ("file", lambda item: item["file"].update(sha256="e" * 64))):
            with self.subTest(read=name):
                _, scoped = scoped_helper()
                item = self.item(scoped)
                item["reason"] = "parent-verified"
                change(item)
                self.assertIs(self.assess(scoped)["passed"], False)

    def test_helper_in_last_inventory_is_rejected(self):
        _, scoped = scoped_helper()
        inventories = scoped["samples"][17]["scope"]["inventories"]
        inventories[-1]["exited_helpers"] = copy.deepcopy(inventories[0]["exited_helpers"])
        inventories[-1]["cgroup_pids"] = sorted(inventories[-1]["cgroup_pids"] + [600])
        self.assertEqual(self.assess(scoped), {"passed": False, "reason": "unproven-exited-runtime-helper"})

    def test_retired_helper_cannot_reappear_excluded_or_mapped(self):
        for where in ("excluded", "mapped", "previously-inside"):
            with self.subTest(where=where):
                _, scoped = scoped_helper()
                helper = self.item(scoped)
                if where == "previously-inside":
                    target = scoped["samples"][16]["scope"]["inventories"][0]
                    row = copy.deepcopy(target["mappings"][1])
                    row.update(key=[600, 10150], local_pid=600, from_namespace=600, in_namespace=600,
                               binding=copy.deepcopy(helper["binding"]))
                    row["binding"]["bound_at"] = row["verified_at"]
                    target["mappings"].append(row)
                    target["visible_pids"] = sorted(target["visible_pids"] + [600])
                    target["end_visible_pids"] = list(target["visible_pids"])
                else:
                    target = scoped["samples"][60]["scope"]["inventories"][0]
                    if where == "excluded":
                        row = copy.deepcopy(target["excluded"][0])
                        row.update(key=[600, 10150], binding=copy.deepcopy(helper["binding"]))
                        target["excluded"].append(row)
                    else:
                        row = copy.deepcopy(target["mappings"][1])
                        row.update(key=[600, 10150], local_pid=600, from_namespace=600, in_namespace=600,
                                   binding=copy.deepcopy(helper["binding"]))
                        target["mappings"].append(row)
                        target["visible_pids"] = sorted(target["visible_pids"] + [600])
                    target["cgroup_pids"] = sorted(target["cgroup_pids"] + [600])
                    target["end_cgroup_pids"] = sorted(target["end_cgroup_pids"] + [600])
                actual = self.assess(scoped)
                self.assertIs(actual["passed"], False, actual)
                if where == "excluded":
                    self.assertEqual(actual["reason"], "unproven-cgroup-only-host-exclusion")
                elif where == "mapped":
                    self.assertEqual(actual["reason"], "inside-namespace-mapping-unbound")

    def test_helper_key_mapped_inside_earlier_in_sample_is_rejected(self):
        _, scoped = scoped_helper()
        sample = scoped["samples"][17]
        inventories = sample["scope"]["inventories"]
        earlier = copy.deepcopy(inventories[0])
        earlier.pop("exited_helpers")
        row = copy.deepcopy(earlier["mappings"][1])
        row.update(key=[600, 10150], local_pid=600, from_namespace=600, in_namespace=600,
                   binding=copy.deepcopy(inventories[0]["exited_helpers"][0]["binding"]))
        earlier["mappings"].append(row)
        earlier["visible_pids"] = sorted(earlier["visible_pids"] + [600])
        earlier["end_visible_pids"] = list(earlier["visible_pids"])
        earlier["end_cgroup_pids"] = list(earlier["cgroup_pids"])
        inventories.insert(0, earlier)
        sample["scope"]["capture_passes"] = 1
        self.assertEqual(self.assess(scoped), {"passed": False, "reason": "unproven-exited-runtime-helper"})


EMPTY = col.EvidenceError("empty-process-command")
RUNC = ("runc", "init")
RETRY_KEY = (200, 10100)
RETRY_CGROUP = "/qa/docker-" + CID + ".scope"
HEALTH_ARGV = tuple(base.HEALTH)
SERVE_ARGV = ["/usr/local/bin/python", "/usr/local/bin/netops", "serve"]


def repeating(values):
    values, index = list(values), [0]

    def next_value(*args, **kwargs):
        value = values[min(index[0], len(values) - 1)]
        index[0] += 1
        if isinstance(value, BaseException):
            raise value
        return value
    return next_value


class RetryEmptyCommand(unittest.TestCase):
    def retry(self, *, commands=(RUNC, EMPTY), stats=((RETRY_KEY, 95), (RETRY_KEY, 95)), cgroups=(RETRY_CGROUP, RETRY_CGROUP),
              exe=((88, 1002), (88, 1002)), fresh=(RETRY_KEY, RETRY_CGROUP), start=101.09, read_delay=0.0, fresh_delay=0.0):
        handle = {"key": RETRY_KEY, "directory": 11, "pidfd": 12, "evidence": {}}
        identities = repeating(SimpleNamespace(st_dev=dev, st_ino=ino) for dev, ino in exe)
        stat_values, now, self.fresh_reads, self.stat_reads = repeating(stats), [start], [], [0]

        def stat_at(directory, pid):
            self.stat_reads[0] += 1
            now[0] += read_delay
            return stat_values()

        def proc_stat(pid):
            self.fresh_reads.append(pid)
            now[0] += fresh_delay
            return fresh[0], 90

        with ExitStack() as stack:
            for target, name, kwargs in (
                    (col, "clock", {"side_effect": lambda: now[0]}),
                    (col, "check_binding", {}), (col, "stat_at", {"side_effect": stat_at}),
                    (col.os, "stat", {"side_effect": identities}), (col, "command", {"side_effect": repeating(commands)}),
                    (col, "cgroup_at", {"side_effect": repeating(cgroups)}), (col, "identity_maps", {}),
                    (col, "shim", {"return_value": {"key": [90, 900]}}),
                    (col, "runtime_parent", {"side_effect": FileNotFoundError(errno.ENOENT, "parent")}),
                    (col, "proc_stat", {"side_effect": proc_stat}), (col, "cgroup_path", {"return_value": fresh[1]})):
                stack.enter_context(mock.patch.object(target, name, **kwargs))
            return col.runtime_parent_after_enoent(handle, RETRY_KEY, 90, CID, base.runtime_fixture(), RETRY_CGROUP, [88, 1002])

    def refused(self, code, **kwargs):
        with raises(self, col.EvidenceError) as caught:
            self.retry(**kwargs)
        self.assertNotIsInstance(caught.exception, col.RuntimeExecTransition)
        self.assertEqual(caught.exception.args, (code,))
        return caught.exception

    def accepted(self, **kwargs):
        with raises(self, col.RuntimeExecTransition) as caught:
            self.retry(**kwargs)
        self.assertEqual(caught.exception.args[0], "runtime-exec-transition-retry-empty-command")
        self.assertEqual((self.stat_reads[0], self.fresh_reads), (2, [RETRY_KEY[0]]))
        self.assertIn("retry_read", caught.exception.args[1], "accepted transition must keep the read facts")
        return caught.exception.args[1]

    def test_empty_second_read_after_verified_runc_init_is_transition_with_kept_facts(self):
        facts = self.accepted()
        read = {"key_before": list(RETRY_KEY), "key_after": list(RETRY_KEY), "argv": ["runc", "init"],
                "exe_identity_before": [88, 1002], "exe_identity_after": [88, 1002],
                "cgroup_before": RETRY_CGROUP, "cgroup_after": RETRY_CGROUP, "parent_pid_before": 95, "parent_pid_after": 95,
                "read_started_at": 101.09, "time": 101.09, "fresh_finished_at": 101.09}
        self.assertEqual(facts, {"key": list(RETRY_KEY), "cgroup": RETRY_CGROUP, "first_argv": ["runc", "init"],
                                 "empty": True, "retry_read": read})

    def test_observed_cgroup_mismatch_is_cgroup_failure_and_fresh_state_is_not_consulted(self):
        for cgroups in (("/foreign", RETRY_CGROUP), (RETRY_CGROUP, "/foreign"), ("/foreign", "/foreign")):
            with self.subTest(cgroups=cgroups):
                self.refused("runtime-parent-retry-cgroup-changed", cgroups=cgroups)
                self.assertEqual(self.fresh_reads, [])

    def test_observed_key_exe_or_parent_mismatch_is_child_changed(self):
        other = (200, 10101)
        cases = {"key-before": dict(stats=((other, 95), (RETRY_KEY, 95))), "key-after": dict(stats=((RETRY_KEY, 95), (other, 95))),
                 "exe-before": dict(exe=((88, 1003), (88, 1002))), "exe-after": dict(exe=((88, 1002), (88, 1003))),
                 "parent": dict(stats=((RETRY_KEY, 95), (RETRY_KEY, 90)))}
        for name, kwargs in cases.items():
            with self.subTest(case=name):
                self.refused("runtime-parent-retry-child-changed", **kwargs)
                self.assertEqual(self.fresh_reads, [])

    def test_fresh_key_or_cgroup_mismatch_keeps_empty_error(self):
        for fresh in (((200, 10101), RETRY_CGROUP), (RETRY_KEY, "/foreign")):
            with self.subTest(fresh=fresh):
                self.refused("empty-process-command", fresh=fresh)
                self.assertEqual(self.fresh_reads, [RETRY_KEY[0]])

    def test_empty_after_other_first_read_or_on_first_read_keeps_error(self):
        self.refused("empty-process-command", commands=(HEALTH_ARGV, EMPTY))
        self.assertEqual(self.fresh_reads, [])
        self.refused("empty-process-command", commands=(EMPTY,))
        self.assertEqual(self.fresh_reads, [])

    def test_other_command_error_is_unchanged(self):
        self.refused("unreadable-process-command", commands=(RUNC, col.EvidenceError("unreadable-process-command")))
        self.assertEqual(self.fresh_reads, [])

    def test_budget_before_fresh_reads_counts_from_iteration_start(self):
        for delay in (.03125, .02734375):
            with self.subTest(read_delay=delay):
                self.refused("runtime-parent-retry-exhausted", start=100.0, read_delay=delay)
                self.assertEqual((self.stat_reads[0], self.fresh_reads), (2, []), "fresh state must not be read after the budget")
        facts = self.accepted(start=100.0, read_delay=.0234375)
        self.assertEqual(facts["retry_read"]["time"], 100.046875)

    def test_kept_times_are_iteration_start_read_time_and_fresh_end(self):
        facts = self.accepted(start=100.0, read_delay=.0078125, fresh_delay=.03125)
        self.assertEqual({name: facts["retry_read"][name] for name in ("read_started_at", "time", "fresh_finished_at")},
                         {"read_started_at": 100.0, "time": 100.015625, "fresh_finished_at": 100.046875})

    def test_duration_of_fresh_reads_counts_toward_budget(self):
        self.refused("runtime-parent-retry-exhausted", start=100.0, read_delay=.0078125, fresh_delay=.0390625)
        self.assertEqual((self.stat_reads[0], self.fresh_reads), (2, [RETRY_KEY[0]]))
        self.refused("runtime-parent-retry-exhausted", start=100.0, fresh_delay=.0501)
        facts = self.accepted(start=100.0, fresh_delay=.046875)
        self.assertEqual(facts["retry_read"]["fresh_finished_at"], 100.046875)

    def test_fresh_mismatch_keeps_empty_error_even_when_late(self):
        self.refused("empty-process-command", start=100.0, fresh_delay=.0625, fresh=(RETRY_KEY, "/foreign"))


def retry_empty(trace, index=13, **read_changes):
    row = trace["samples"][index]["processes"][-1]
    proof = runc_proof()
    exe = proof["file"]["stat_before"][:2]
    read = {"key_before": [200, 10100], "key_after": [200, 10100], "argv": ["runc", "init"],
            "exe_identity_before": list(exe), "exe_identity_after": list(exe), "cgroup_before": TCGROUP, "cgroup_after": TCGROUP,
            "parent_pid_before": 95, "parent_pid_after": 95, "read_started_at": row["read_started_at"] - .01,
            "time": row["read_started_at"] - .005, "fresh_finished_at": row["read_started_at"]}
    read.update(read_changes)
    item = attempt(trace, index, reason="runtime-exec-transition-retry-empty-command",
                   facts={"empty": True, "retry_read": read}, partial={"runtime_executable": proof})
    item["facts"].pop("second_argv")
    return item


class RetryEmptyProfile(unittest.TestCase):
    def test_kept_facts_pass(self):
        trace = health_trace()
        self.assertIs(assessed(with_attempts(trace, [retry_empty(trace)]))["passed"], True)

    def test_every_kept_fact_is_verified(self):
        def changed(**changes):
            return lambda t: retry_empty(t, **changes)

        def edit(change):
            def build(t):
                item = retry_empty(t)
                change(item)
                return item
            return build

        def proof_stat(item):
            file = item["partial"]["runtime_executable"]["file"]
            file["stat_before"] = [1, 2] + file["stat_before"][2:]

        def late(item):
            item["facts"]["retry_read"].update(fresh_finished_at=item["time"] + .001)

        def fresh_budget(item):
            item["facts"]["retry_read"].update(read_started_at=item["time"] - .0501, time=item["time"] - .045)

        def fresh_before_time(item):
            read = item["facts"]["retry_read"]
            read["fresh_finished_at"] = read["time"] - .001

        def budget(item):
            read = item["facts"]["retry_read"]
            read["read_started_at"] = read["time"] - .0501
            read["fresh_finished_at"] = read["time"]

        def negative(item):
            read = item["facts"]["retry_read"]
            read["read_started_at"] = read["time"] + .001

        cases = {
            "no-read": (edit(lambda item: item["facts"].pop("retry_read")), "unverified-exec-transition"),
            "read-not-dict": (edit(lambda item: item["facts"].update(retry_read=[])), "unverified-exec-transition"),
            "argv": (changed(argv=list(base.HEALTH)), "unverified-exec-transition"),
            "key-before": (changed(key_before=[200, 10101]), "unverified-exec-transition"),
            "key-after": (changed(key_after=[200, 10101]), "unverified-exec-transition"),
            "cgroup-before": (changed(cgroup_before="/foreign"), "unverified-exec-transition"),
            "cgroup-after": (changed(cgroup_after="/foreign"), "unverified-exec-transition"),
            "exe-after": (changed(exe_identity_after=[8, 1003]), "unverified-exec-transition"),
            "exe-both-other": (changed(exe_identity_before=[8, 1003], exe_identity_after=[8, 1003]), "unverified-exec-transition"),
            "proof-stat": (edit(proof_stat), "unverified-exec-transition"),
            "no-proof": (edit(lambda item: item["partial"].pop("runtime_executable")), "unverified-exec-transition"),
            "parent": (changed(parent_pid_after=90), "unverified-exec-transition"),
            "parent-text": (changed(parent_pid_before="95", parent_pid_after="95"), "unverified-exec-transition"),
            "budget": (edit(budget), "unverified-exec-transition"),
            "negative-duration": (edit(negative), "unverified-exec-transition"),
            "after-attempt": (edit(late), "unverified-exec-transition"),
            "fresh-budget": (edit(fresh_budget), "unverified-exec-transition"),
            "fresh-before-time": (edit(fresh_before_time), "unverified-exec-transition"),
            "no-fresh-time": (edit(lambda item: item["facts"]["retry_read"].pop("fresh_finished_at")), "invalid-clock"),
            "before-binding": (edit(lambda item: item["facts"]["retry_read"].update(read_started_at=item["binding"]["bound_at"] - .001,
                                                                                    time=item["binding"]["bound_at"] + .001,
                                                                                    fresh_finished_at=item["binding"]["bound_at"] + .002)),
                               "unverified-exec-transition"),
            "not-empty": (edit(lambda item: item["facts"].update(empty=False)), "unverified-exec-transition"),
            "first-health": (edit(lambda item: item["facts"].update(first_argv=list(base.HEALTH))), "unverified-exec-transition"),
            "first-health-partial-health": (edit(lambda item: (item["facts"].update(first_argv=list(base.HEALTH)),
                                                               item["partial"].update(argv=list(base.HEALTH)))),
                                            "unverified-exec-transition"),
            "no-key": (edit(lambda item: item["facts"]["retry_read"].pop("key_before")), "invalid-identity"),
            "no-time": (edit(lambda item: item["facts"]["retry_read"].pop("time")), "invalid-clock"),
        }
        for name, (build, reason) in cases.items():
            with self.subTest(case=name):
                trace = health_trace()
                actual = assessed(with_attempts(trace, [build(trace)]))
                self.assertEqual(actual, {"passed": False, "reason": reason}, name)

    def test_retry_reason_needs_kept_facts_but_plain_empty_reason_does_not(self):
        trace = health_trace()
        plain = retry_empty(trace)
        plain["reason"] = "runtime-exec-transition-empty-command"
        self.assertIs(assessed(with_attempts(trace, [plain]))["passed"], True)


class InventoryDiagnostic(unittest.TestCase):
    def failure_of(self, kernel):
        result = kernel.inventory()
        self.assertIs(result["complete"], False)
        self.assertEqual(len(result["failures"]), 1)
        return result["failures"][0]

    def test_refusal_point_stage_and_pid_are_recorded(self):
        kernel = Kernel(NEW[0], "enoent", 1, ("new",))
        self.assertEqual(self.failure_of(kernel),
                         {"reason": "proc-read-or-schema-failed", "error": "FileNotFoundError", "errno": errno.ENOENT,
                          "diagnostic": {"stage": "classify-host-first", "pid": NEW[0], "point": "unobserved-still-member",
                                         "operation": None}})
        kernel = Kernel(NEW[0], "enoent", 1, ("new",))
        members, calls = kernel.members, []

        def listed(directory):
            calls.append(directory)
            return members(directory) - (set() if len(calls) == 1 else {NEW[0]})

        kernel.members = listed
        self.assertEqual(self.failure_of(kernel)["diagnostic"]["point"], "unobserved-hostproc-present")

    def test_helper_failure_records_stage_pid_and_point(self):
        points = {}
        for change in (None, lambda k: k.procs[HELPER[0]].update(foreign=True)):
            for at, point, result in SystematicInventoryInjection.runs(self, "helper", "reaped", change):
                if not result["complete"]:
                    item = result["failures"][0]
                    self.assertTrue(set(item) in ({"reason", "error", "errno", "diagnostic"}, {"reason", "diagnostic"}), item)
                    self.assertEqual((item["diagnostic"]["stage"], item["diagnostic"]["pid"]), ("classify-host-first", HELPER[0]), item)
                    points.setdefault(item["diagnostic"]["point"], []).append(point)
        self.assertIn("retire-no-parent-link", points)

    def denied(self, path, raised=PermissionError):
        kernel = Kernel(KNOWN[0], None, 0, ("known",))
        opened = kernel.open

        def failing(name, flags, dir_fd=None):
            if dir_fd == OWNPROC and name == "32":
                raise raised(errno.EACCES, "denied", path)
            return opened(name, flags, dir_fd)

        kernel.open = failing
        return self.failure_of(kernel)

    def test_inside_mapping_records_host_pid_once_known(self):
        self.assertEqual(self.denied("32")["diagnostic"], {"stage": "inside-mapping", "local_pid": 32, "pid": KNOWN[0], "point": None,
                                                           "operation": "32"})
        kernel = Kernel(KNOWN[0], None, 0, ("known",))
        ioctl = kernel.ioctl

        def failing(fd, operation, arg=None):
            if operation == 0x8004b706 and arg == 32:
                raise OSError(errno.EINVAL, "synthetic")
            return ioctl(fd, operation, arg)

        kernel.ioctl = failing
        self.assertEqual(self.failure_of(kernel)["diagnostic"], {"stage": "inside-mapping", "local_pid": 32, "point": None,
                                                                   "operation": None})

    def test_operation_names_outside_procfs_are_not_recorded(self):
        cases = {"/proc/200/stat": "/proc/200/stat", "stat": "stat", "ns/pid": "ns/pid", "32": "32", "cgroup.procs": "cgroup.procs",
                 "/etc/netops/env": "other", "/proc/../etc/passwd": "other", "/proc/1/" + "a" * 33: "other",
                 "/run/secrets/x": "other", "config": "other", "/proc/1/../../root/x": "other", "/proc": "other",
                 "1" * 11: "other"}
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(self.denied(path)["diagnostic"]["operation"], expected)
        for value, expected in ((None, None), (b"/proc/1/stat", None), (5, None), ("/proc/1/status", "/proc/1/status")):
            with self.subTest(value=value):
                self.assertEqual(col.proc_operation(value), expected)

    def test_listing_failure_records_stage_without_pid(self):
        kernel = Kernel(KNOWN[0], None, 0, ("known",))

        def gone(fd):
            raise FileNotFoundError(errno.ENOENT, "gone", "/proc/100/root/proc")

        kernel.listdir = gone
        self.assertEqual(self.failure_of(kernel)["diagnostic"], {"stage": "container-procfs-list", "point": None,
                                                                   "operation": "/proc/100/root/proc"})

    def test_complete_inventory_has_no_failure(self):
        result = Kernel(KNOWN[0], None, 0, ("known",)).inventory()
        self.assertEqual((result["complete"], result["failures"]), (True, []))


class SurvivorKillers(unittest.TestCase):
    def serve_child(self, attempts):
        trace = base.fixture()
        base.insert(trace, 13, 17, base.process(210, 10100, 51000, SERVE_ARGV, base.INIT))
        trace["samples"][17]["exited"] = [[210, 10100]]
        trace = base.observed_fixture(trace)
        row = trace["samples"][13]["processes"][-1]
        if attempts:
            row["exec_transitions"] = [{"reason": "runtime-exec-transition-empty-command",
                                        "facts": {"key": [210, 10100], "cgroup": TCGROUP, "first_argv": ["runc", "init"], "empty": True},
                                        "partial": {"pid": 210, "key": [210, 10100], "argv": ["runc", "init"],
                                                    "runtime_executable": runc_proof()},
                                        "binding": row["binding"], "time": row["read_started_at"]}]
        return trace

    def test_runtime_to_unrolled_serve_child_is_not_monotonic(self):
        self.assertIs(assessed(self.serve_child(False))["passed"], True)
        self.assertEqual(assessed(self.serve_child(True)), {"passed": False, "reason": "exec-transition-not-monotonic"})


class OuterCgroupFact(unittest.TestCase):
    def run_process(self, *, commands, outer="/qa/docker-" + CID + ".scope", parent_pid=95):
        handle = {"key": KNOWN, "directory": 11, "pidfd": 12, "evidence": {"procdir_identity": [9, 200]}}
        info = SimpleNamespace(st_dev=88, st_ino=1002, st_mode=0o100755, st_uid=0, st_size=32,
                               st_mtime_ns=1000000000, st_ctime_ns=1000000000)
        runtime, partial = base.runtime_fixture(), {}
        groups = repeating([outer, TCGROUP])
        with ExitStack() as stack:
            for target, name, kwargs in (
                    (col, "clock", {"return_value": 100.0}), (col, "check_binding", {}),
                    (col, "proc_stat", {"side_effect": lambda pid: (KNOWN, parent_pid) if pid == KNOWN[0] else ((pid, 10050), 90)}),
                    (col, "stat_at", {"return_value": (KNOWN, parent_pid)}),
                    (col, "command", {"side_effect": repeating(commands)}), (col, "permissions_at", {"return_value": ROOT_PERMISSIONS}),
                    (col, "identity_maps", {}), (col, "cgroup_path", {"return_value": TCGROUP}), (col, "cgroup_at", {"side_effect": groups}),
                    (col.os, "open", {"return_value": 47}), (col.os, "fstat", {"return_value": info}), (col.os, "close", {}),
                    (col.os, "stat", {"return_value": info}), (col, "shim", {"return_value": {"key": [90, 900]}}),
                    (col, "runtime_parent", {"side_effect": FileNotFoundError(errno.ENOENT, "parent")}),
                    (col, "hash_executable", {"return_value": {"sha256": runtime["binary"]["sha256"]}})):
                stack.enter_context(mock.patch.object(target, name, **kwargs))
            try:
                col.process(KNOWN[0], TCGROUP, 90, CID, runtime, handle, None, partial)
            except Exception as error:
                return error, partial
        self.fail("process() returned a row")

    def test_outer_cgroup_mismatch_before_helper_empty_command_is_failure_and_kept(self):
        error, partial = self.run_process(commands=[RUNC, RUNC, EMPTY], outer="/foreign")
        self.assertIs(type(error), col.EvidenceError)
        self.assertEqual(error.args, ("runtime-process-left-container-cgroup",))
        self.assertEqual((partial.get("cgroup_before"), partial.get("argv")), ("/foreign", ["runc", "init"]))
        self.assertNotIn("runtime_executable", partial)
        error, partial = self.run_process(commands=[RUNC, RUNC, EMPTY])
        self.assertIs(type(error), col.RuntimeExecTransition)
        self.assertEqual(error.args[0], "runtime-exec-transition-retry-empty-command")
        self.assertEqual(partial.get("cgroup_before"), TCGROUP)
        self.assertIn("runtime_executable", partial)

    def test_outer_cgroup_mismatch_before_any_accepted_transition_is_failure(self):
        cases = {"retry-health": dict(commands=[RUNC, RUNC, HEALTH_ARGV]),
                 "snapshot-health": dict(commands=[RUNC, HEALTH_ARGV], parent_pid=90),
                 "snapshot-empty": dict(commands=[RUNC, EMPTY], parent_pid=90)}
        for name, kwargs in cases.items():
            with self.subTest(case=name):
                error, partial = self.run_process(outer="/foreign", **kwargs)
                self.assertEqual((type(error), error.args), (col.EvidenceError, ("runtime-process-left-container-cgroup",)))
                self.assertEqual(partial.get("cgroup_before"), "/foreign")
                error, partial = self.run_process(**kwargs)
                self.assertIs(type(error), col.RuntimeExecTransition)
                self.assertEqual(partial.get("cgroup_before"), TCGROUP)


class OuterCgroupProfile(unittest.TestCase):
    def test_kept_outer_cgroup_is_verified_on_every_path(self):
        trace = health_trace()
        self.assertIs(assessed(with_attempts(trace, [attempt(trace)]))["passed"], True)
        trace = health_trace()
        self.assertEqual(assessed(with_attempts(trace, [attempt(trace, partial={"cgroup_before": "/foreign"})])),
                         {"passed": False, "reason": "unverified-exec-transition"})
        trace = health_trace()
        missing = attempt(trace)
        missing["partial"].pop("cgroup_before")
        self.assertEqual(assessed(with_attempts(trace, [missing])), {"passed": False, "reason": "unverified-exec-transition"})
        trace = health_trace()
        item = retry_empty(trace)
        item["partial"]["cgroup_before"] = "/foreign"
        self.assertEqual(assessed(with_attempts(trace, [item])), {"passed": False, "reason": "unverified-exec-transition"})

    def test_kept_outer_cgroup_of_known_exit_failure_is_verified(self):
        good = failure_trace({"argv": list(base.HEALTH), "cgroup_before": TCGROUP})
        self.assertIs(assessed(good)["passed"], True)
        self.assertEqual(assessed(failure_trace({"argv": list(base.HEALTH), "cgroup_before": "/foreign"})),
                         {"passed": False, "reason": "unverified-exec-transition"})
        trace = failure_trace({"argv": list(base.HEALTH)})
        trace["samples"][17]["scope"]["observed_failures"][0]["attempts"] = [failure_attempt(trace, partial={"cgroup_before": "/foreign"})]
        self.assertEqual(assessed(trace), {"passed": False, "reason": "unverified-exec-transition"})

    def test_retry_read_numbers_are_typed_independently(self):
        cases = {"parent-after-bool": dict(parent_pid_before=1, parent_pid_after=True),
                 "parent-before-bool": dict(parent_pid_before=True, parent_pid_after=1),
                 "parent-after-float": dict(parent_pid_after=95.0), "parent-before-float": dict(parent_pid_before=95.0),
                 "parent-after-text": dict(parent_pid_after="95"), "parent-zero": dict(parent_pid_before=0, parent_pid_after=0),
                 "key-float": dict(key_before=[200, 10100.0]), "key-bool": dict(key_after=[True, 10100]),
                 "exe-float": dict(exe_identity_after=[58.0, 97]), "exe-bool": dict(exe_identity_before=[58, True])}
        for name, changes in cases.items():
            with self.subTest(case=name):
                trace = health_trace()
                actual = assessed(with_attempts(trace, [retry_empty(trace, **changes)]))
                self.assertIs(actual["passed"], False, name)
        for field in ("read_started_at", "time", "fresh_finished_at"):
            for value in (True, "1.0", 101):
                with self.subTest(field=field, value=value):
                    trace = health_trace()
                    actual = assessed(with_attempts(trace, [retry_empty(trace, **{field: value})]))
                    self.assertEqual(actual, {"passed": False, "reason": "invalid-clock"}, (field, value))


def reaped_kernel(change=None, restat_error=None, state="gone"):
    """The helper is reaped exactly at its restat in link(); restat_error replaces the kernel's ENOENT."""
    kernel = Kernel(HELPER[0], None, 0, ("helper",))
    if change:
        change(kernel)
    proc_stat, calls = kernel.proc_stat, []

    def restat(pid):
        if pid == HELPER[0]:
            calls.append(pid)
            if len(calls) == 2:
                kernel.procs[HELPER[0]]["state"] = state
                if restat_error is not None:
                    raise restat_error
        return proc_stat(pid)

    kernel.proc_stat = restat
    return kernel


class ReapedBeforeRestat(unittest.TestCase):
    def refused(self, kernel, point=None):
        result = kernel.inventory()
        self.assertIs(result["complete"], False, result["exited_helpers"])
        self.assertEqual(result["exited_helpers"], [])
        if point is not None:
            self.assertEqual(result["failures"][0]["diagnostic"]["point"], point)
        return result

    def test_helper_reaped_between_first_stat_and_restat_is_recorded(self):
        result = reaped_kernel().inventory()
        self.assertIs(result["complete"], True, result["failures"])
        self.assertEqual(len(result["exited_helpers"]), 1)
        item = result["exited_helpers"][0]
        self.assertEqual((item["key"], item["reason"], item["exit"], item["parent_pid"], item["error"], item["errno"]),
                         (list(HELPER), "reaped-before-restat", "reaped", RUNC_PARENT[0], "FileNotFoundError", errno.ENOENT))
        self.assertEqual(item["child_stat"], {"key": list(HELPER), "parent_pid": RUNC_PARENT[0], "at": 100.0})
        self.assertEqual((item["child_reads"], item["namespace_absence_errno"]), ([], errno.ESRCH))
        self.assertEqual({name: item["unlinked"][name] for name in ("parent_key", "restat_error", "restat_errno", "stage")},
                         {"parent_key": list(RUNC_PARENT), "restat_error": "FileNotFoundError", "restat_errno": errno.ENOENT,
                          "stage": "link-child-restat"})
        pin = item["parent_pin"]
        self.assertEqual((pin["alive_at_pin_basis"], pin["alive_polled_at"]), ("outer-pidfd-poll-after-role-proof", 100.0))
        self.assertEqual((pin["key"], pin["alive_at_pin"], pin["cgroup"], pin["shim_cgroup"], pin["shim"], pin["permissions"]["uids"],
                          pin["active_namespace"], pin["file"]["sha256"]),
                         (list(RUNC_PARENT), True, SHIM_CGROUP, SHIM_CGROUP, SHIM_RECORD, [0] * 4, list(HOST), "d" * 64))
        self.assertEqual(item["runtime_parent"]["key"], list(RUNC_PARENT))
        self.assertNotIn("parent_link", item)
        self.assertNotIn(HELPER[0], result["end_cgroup_pids"])

    def test_each_condition_is_required(self):
        def field(name, value, pid=RUNC_PARENT[0]):
            return lambda kernel: kernel.procs[pid].update({name: value})

        def shim_cgroup(value):
            def change(kernel):
                original = kernel.cgroup_path
                kernel.cgroup_path = lambda pid: value if pid == 90 else original(pid)
            return change

        def parent_container(kernel):
            kernel.procs[RUNC_PARENT[0]]["cgroup"] = PATH
            shim_cgroup(PATH)(kernel)

        def same_start(kernel):
            kernel.procs[HELPER[0]]["key"] = (HELPER[0], RUNC_PARENT[1])

        def still_member(kernel):
            members = kernel.members
            kernel.members = lambda directory: members(directory) | {HELPER[0]}

        def visible(kernel):
            translate = kernel.translate

            def mapped(fd, operation, arg=None):
                if operation == 0x8004b708 and arg == HELPER[0]:
                    return 41
                return translate(fd, operation, arg)
            kernel.translate = mapped

        def parent_dead_after_proof(kernel):
            proof = kernel.runtime_parent

            def die(*args):
                result = proof(*args)
                kernel.procs[RUNC_PARENT[0]]["state"] = "gone"
                return result
            kernel.runtime_parent = die

        def failing(method, name):
            def change(kernel):
                original = getattr(kernel, method)

                def broken(*args, **kwargs):
                    if name(kernel, *args):
                        raise FileNotFoundError(errno.ENOENT, "parent read")
                    return original(*args, **kwargs)
                setattr(kernel, method, broken)
            return change

        def content_mismatch(kernel):
            original = kernel.hash_executable

            def other(fd, before, opened_at):
                proof = original(fd, before, opened_at)
                return dict(proof, sha256="e" * 64) if kernel.fds[fd][1] == RUNC_PARENT[0] else proof
            kernel.hash_executable = other

        def h1_error(kernel):
            original = kernel.hash_executable

            def broken(fd, before, opened_at):
                if kernel.fds[fd][1] == RUNC_PARENT[0]:
                    raise FileNotFoundError(errno.ENOENT, "parent exe")
                return original(fd, before, opened_at)
            kernel.hash_executable = broken

        def stale_pins(starts):
            def change(kernel):
                original = kernel.scope

                def scope():
                    made = original()
                    for number, start in enumerate(starts):
                        stale, pid = (RUNC_PARENT[0], start), 777 + number
                        kernel.procs[pid] = dict(kernel.procs[RUNC_PARENT[0]], key=stale, state="live")
                        made.parent_pins[stale] = {"directory": kernel.fd("dir", pid), "pidfd": kernel.fd("pidfd", pid),
                                                   "proof": {"key": list(stale)}, "pinned_at": 100.0}
                    return made
                kernel.scope = scope
            return change

        def back_in_cgroup_after_h1(kernel):
            original, members, seen = kernel.hash_executable, kernel.members, []

            def hashed(fd, before, opened_at):
                if kernel.fds[fd][1] == RUNC_PARENT[0]:
                    seen.append(fd)
                return original(fd, before, opened_at)

            kernel.hash_executable = hashed
            kernel.members = lambda directory: members(directory) | ({HELPER[0]} if seen else set())

        def known_outside(kernel):
            original = kernel.scope

            def scope():
                made = original()
                made.outside_seen.add(HELPER)
                return made
            kernel.scope = scope

        cases = {
            "parent-cgroup-not-shim": (field("cgroup", "/system.slice/other.service"), "retire-reaped-parent-facts"),
            "parent-cgroup-container": (parent_container, "retire-reaped-parent-facts"),
            "parent-uid": (field("uid", 51000), "retire-reaped-parent-facts"),
            "parent-ns": (field("ns", OWN), "retire-reaped-parent-facts"),
            "parent-same-start": (same_start, "retire-reaped-parent-not-older"),
            "parent-content": (content_mismatch, "retire-reaped-parent-content"),
            "parent-h1-enoent": (h1_error, "retire-reaped-parent-content"),
            "parent-fact-enoent": (failing("permissions_at", lambda k, fd: k.fds[fd][1] == RUNC_PARENT[0]), "retire-reaped-parent-facts"),
            "shim-cgroup-enoent": (failing("cgroup_path", lambda k, pid: pid == 90), "retire-reaped-parent-facts"),
            "parent-dead-after-proof": (parent_dead_after_proof, "retire-no-parent-link"),
            "child-still-member": (still_member, "retire-still-member"),
            "child-in-cgroup-after-h1": (back_in_cgroup_after_h1, "retire-reaped-still-member"),
            "child-visible-in-namespace": (visible, "retire-reaped-visible-in-namespace"),
            "parent-pin-ambiguous": (stale_pins((8000, 8100)), "retire-reaped-identity"),
            "parent-pin-without-facts": (stale_pins((8000,)), "retire-reaped-parent-facts"),
            "child-known": (known_outside, None),
        }
        for name, (change, point) in cases.items():
            with self.subTest(case=name):
                self.refused(reaped_kernel(change), point)

    def test_restat_error_other_than_enoent_esrch_is_failure(self):
        for error in (PermissionError(errno.EACCES, "denied"), FileNotFoundError(errno.EACCES, "odd"), OSError(errno.EIO, "io")):
            with self.subTest(error=error):
                self.refused(reaped_kernel(restat_error=error), "retire-no-parent-link")
        result = reaped_kernel(restat_error=ProcessLookupError(errno.ESRCH, "gone")).inventory()
        self.assertIs(result["complete"], True, result["failures"])
        self.assertEqual((result["exited_helpers"][0]["unlinked"]["restat_error"], result["exited_helpers"][0]["unlinked"]["restat_errno"]),
                         ("ProcessLookupError", errno.ESRCH))

    def test_reused_pin_needs_a_fresh_alive_poll_for_each_child(self):
        kernel = Kernel(HELPER2[0], None, 0, ("helper", "helper2"))
        proc_stat, calls = kernel.proc_stat, []

        def staged(pid):
            if pid == HELPER2[0]:
                calls.append(pid)
                if len(calls) == 1:
                    kernel.procs[RUNC_PARENT[0]]["state"] = "gone"
                elif len(calls) == 2:
                    kernel.procs[HELPER2[0]]["state"] = "gone"
            return proc_stat(pid)

        kernel.proc_stat = staged
        result = self.refused(kernel, "retire-no-parent-link")
        self.assertEqual(len(calls), 3)
        self.assertTrue(any(item["key"] == list(HELPER) for item in result["excluded"]))

    def test_child_zombie_is_not_reaped(self):
        def enoent_pin(kernel):
            original = kernel.pin_process

            def pin(pid, path):
                if pid == HELPER[0]:
                    raise FileNotFoundError(errno.ENOENT, "pin")
                return original(pid, path)
            kernel.pin_process = pin
        kernel = reaped_kernel(enoent_pin, restat_error=FileNotFoundError(errno.ENOENT, "restat"), state="zombie")
        self.refused(kernel, "retire-reaped-not-reaped")

    def test_child_pinned_after_restat_error_is_not_reaped_before_restat(self):
        def die_after_pin(kernel):
            pin_process = kernel.pin_process

            def pin(pid, path):
                handle = pin_process(pid, path)
                if pid == HELPER[0]:
                    kernel.procs[HELPER[0]]["state"] = "gone"
                return handle
            kernel.pin_process = pin
        kernel = reaped_kernel(die_after_pin, restat_error=FileNotFoundError(errno.ENOENT, "restat"), state="live")
        self.refused(kernel, "retire-reaped-child-pinned")

    def test_shim_record_of_pin_must_equal_proof(self):
        def other_shim(kernel):
            kernel.shim = lambda pid, cid: dict(SHIM_RECORD, exe_identity=[8, 1009])
        self.refused(reaped_kernel(other_shim), "retire-reaped-parent-facts")

    def test_classify_error_must_be_enoent_or_esrch(self):
        def odd_classify_read(kernel):
            original, calls = kernel.proc_stat, []

            def read(pid):
                if pid == HELPER[0]:
                    calls.append(pid)
                    if len(calls) == 3:
                        raise FileNotFoundError(errno.EIO, "odd")
                return original(pid)
            kernel.proc_stat = read
        self.refused(reaped_kernel(odd_classify_read), "retire-reaped-error")

    def test_derived_parent_liveness_is_the_poll_after_the_role_proof(self):
        kernel = reaped_kernel()
        ticks = iter(range(1, 10000))
        kernel.tick = lambda: 100.0 + next(ticks) / 1000
        proof = kernel.runtime_parent

        def timed(*args):
            started = col.clock()
            result = proof(*args)
            result.update(read_started_at=started, read_finished_at=col.clock())
            return result
        kernel.runtime_parent = timed
        result = kernel.inventory()
        self.assertIs(result["complete"], True, result["failures"])
        item = result["exited_helpers"][0]
        pin, proof_record = item["parent_pin"], item["runtime_parent"]
        self.assertLess(pin["pinned_at"], proof_record["read_started_at"])
        self.assertLess(proof_record["read_finished_at"], pin["alive_polled_at"])
        self.assertLessEqual(pin["alive_polled_at"], item["unlinked"]["parent_alive_at"])

    def test_foreign_role_with_full_parent_facts_is_refused(self):
        other = "c" * 64
        facts_read = []

        def foreign_role(kernel):
            kernel.procs[RUNC_PARENT[0]]["argv"] = [part.replace(CID, other) for part in RUNC_ARGV]
            permissions = kernel.permissions_at

            def read(fd):
                if kernel.fds[fd][1] == RUNC_PARENT[0]:
                    facts_read.append(fd)
                return permissions(fd)
            kernel.permissions_at = read

        kernel = reaped_kernel(foreign_role)
        self.refused(kernel, "retire-no-parent-link")
        self.assertEqual((len(facts_read), kernel.role_refusals), (1, ["unverified-runtime-command"]))
        self.assertIs(reaped_kernel().inventory()["complete"], True)

    def test_namespace_translation_error_must_mean_absence(self):
        def translation(code):
            def change(kernel):
                translate = kernel.translate

                def failing(fd, operation, arg=None):
                    if operation == 0x8004b708 and arg == HELPER[0]:
                        raise OSError(code, "synthetic")
                    return translate(fd, operation, arg)
                kernel.translate = failing
            return change

        for code in (errno.EIO, errno.EPERM, errno.EBADF, errno.ENOENT):
            with self.subTest(errno=code):
                self.refused(reaped_kernel(translation(code)), "retire-reaped-namespace-unknown")
        for code in (errno.ESRCH, errno.ENOTTY):
            with self.subTest(errno=code):
                result = reaped_kernel(translation(code)).inventory()
                self.assertIs(result["complete"], True, result["failures"])
                self.assertEqual(result["exited_helpers"][0]["namespace_absence_errno"], code)

    def test_child_read_contradiction_survives_late_absence(self):
        def late(contradiction):
            def change(kernel):
                proc_stat, pin_process, calls = kernel.proc_stat, kernel.pin_process, []

                def read(pid):
                    if pid == HELPER[0]:
                        calls.append(pid)
                        if len(calls) == 3:
                            return contradiction[0], RUNC_PARENT[0]
                    return proc_stat(pid)

                def pin(pid, path):
                    try:
                        return pin_process(pid, path)
                    except FileNotFoundError as error:
                        error.netops_child_reads = contradiction[1]
                        raise
                kernel.proc_stat, kernel.pin_process = read, pin
            return change

        cases = {"pin-key": ((HELPER[0], HELPER[1] + 1), []),
                 "pin-process-ppid": (HELPER, [[list(HELPER), 96]]),
                 "pin-process-key": (HELPER, [[[HELPER[0], HELPER[1] + 1], RUNC_PARENT[0]]])}
        for name, contradiction in cases.items():
            with self.subTest(case=name):
                self.refused(reaped_kernel(late(contradiction)), "retire-reaped-child-read-contradiction")
        result = reaped_kernel(late((HELPER, [[list(HELPER), RUNC_PARENT[0]]]))).inventory()
        self.assertIs(result["complete"], True, result["failures"])
        self.assertEqual(result["exited_helpers"][0]["child_reads"], [[list(HELPER), RUNC_PARENT[0]], [list(HELPER), RUNC_PARENT[0]]])

    def test_two_children_of_one_pin_reread_the_same_held_exe_fd(self):
        import os as real_os
        import tempfile
        real_fstat, data = real_os.fstat, b"runc-bytes-" * 3
        with tempfile.NamedTemporaryFile() as stream:
            stream.write(data)
            stream.flush()
            held = real_os.open(stream.name, real_os.O_RDONLY)
            try:
                kernel = Kernel(HELPER2[0], None, 0, ("helper", "helper2"))
                proc_stat, calls, polls = kernel.proc_stat, {}, []

                def restat(pid):
                    if pid in (HELPER[0], HELPER2[0]):
                        calls[pid] = calls.get(pid, 0) + 1
                        if calls[pid] == 2:
                            kernel.procs[pid]["state"] = "gone"
                    return proc_stat(pid)

                events = kernel.pidfd_events

                def poll(fd):
                    if kernel.fds[fd] == ("pidfd", RUNC_PARENT[0]):
                        polls.append(dict(calls))
                    return events(fd)

                def held_hash(fd, before, opened_at):
                    with mock.patch.object(col.os, "fstat", real_fstat):
                        return real_hash(held, col.file_stat(real_fstat(held)), opened_at)

                original_scope = kernel.scope

                def scope():
                    made = original_scope()
                    runtime = dict(made.context[2], binary=dict(made.context[2]["binary"], sha256=hashlib.sha256(data).hexdigest(),
                                                                bytes_hashed=len(data)))
                    made.context = (made.context[0], made.context[1], runtime)
                    return made

                real_hash = col.hash_executable
                kernel.proc_stat, kernel.pidfd_events, kernel.scope = restat, poll, scope
                kernel.hash_executable = held_hash
                with mock.patch.dict(col.REFERENCE, {"sha256": hashlib.sha256(data).hexdigest(), "data": data}, clear=True):
                    result = kernel.inventory()
            finally:
                real_os.close(held)
        self.assertIs(result["complete"], True, result["failures"])
        self.assertEqual([(item["key"], item["reason"]) for item in result["exited_helpers"]],
                         [(list(HELPER), "reaped-before-restat"), (list(HELPER2), "reaped-before-restat")])
        self.assertEqual([item["parent_pin"]["file"]["bytes_hashed"] for item in result["exited_helpers"]], [len(data)] * 2)
        self.assertEqual(polls, [{HELPER[0]: 1}, {HELPER[0]: 1}, {HELPER[0]: 3, HELPER2[0]: 1}])

    def test_parent_proof_enoent_is_not_a_reaped_child(self):
        kernel = reaped_kernel(lambda k: k.procs[HELPER[0]].update(foreign=True))
        self.refused(kernel, "retire-no-parent-link")


def scoped_reaped():
    legacy, scoped = scoped_helper()
    sample = scoped["samples"][17]
    item = sample["scope"]["inventories"][0]["exited_helpers"][0]
    now = sample["time"]
    item.pop("parent_link")
    item.update(reason="reaped-before-restat", error="FileNotFoundError", errno=errno.ENOENT,
                child_stat={"key": [600, 10150], "parent_pid": 95, "at": now},
                parent_pin={"key": [95, 10050], "pinned_at": now, "alive_at_pin": True,
                            "alive_at_pin_basis": "outer-pidfd-poll-after-role-proof", "alive_polled_at": now, "cgroup": SHIM_CGROUP, "shim_cgroup": SHIM_CGROUP,
                            "shim": copy.deepcopy(sample["shim"]), "permissions": {"uids": [0] * 4, "gids": [0] * 4, "groups": [], "nnp": 0,
                                                                                  "caps": dict.fromkeys(("inh", "prm", "eff", "bnd", "amb"), 0)},
                            "active_namespace": list(HOST),
                            "file": dict(base.runtime_file_fixture(now, device=58), method="bytes-equal-to-verified-reference")},
                unlinked={"parent_key": [95, 10050], "parent_alive_at": now, "restat_error": "FileNotFoundError",
                          "restat_errno": errno.ENOENT, "restat_at": now, "stage": "link-child-restat"},
                child_reads=[], namespace_absence_errno=errno.ESRCH)
    return legacy, scoped


def minimal_reaped():
    legacy, scoped = scoped_reaped()
    item = scoped["samples"][17]["scope"]["inventories"][0]["exited_helpers"][0]
    for name in ("binding", "permissions", "active_namespace", "file"):
        item.pop(name)
    return legacy, scoped


class ReapedBeforeRestatProfile(unittest.TestCase):
    def item(self, trace):
        return trace["samples"][17]["scope"]["inventories"][0]["exited_helpers"][0]

    def test_complete_record_passes_like_legacy(self):
        legacy, scoped = scoped_reaped()
        self.assertEqual(assessed(scoped, require_scope=True), assessed(legacy))
        self.assertIs(assessed(legacy)["passed"], True)

    def test_every_fact_is_verified(self):
        def pin(**changes):
            return lambda item: item["parent_pin"].update(changes)

        def lost(**changes):
            return lambda item: item["unlinked"].update(changes)

        def child(**changes):
            return lambda item: item["child_stat"].update(changes)

        def drop(part, name):
            return lambda item: item[part].pop(name)

        cases = {
            "parent-cgroup-not-shim": pin(cgroup="/system.slice/other.service"),
            "parent-cgroup-container": pin(cgroup="/qa/docker-" + CID + ".scope", shim_cgroup="/qa/docker-" + CID + ".scope"),
            "shim-record": pin(shim={"key": [90, 900]}),
            "parent-uid": pin(permissions={"uids": [0, 0, 0, 1]}),
            "parent-uid-bool": pin(permissions={"uids": [False] * 4}),
            "parent-ns": pin(active_namespace=list(OWN)),
            "parent-not-alive": pin(alive_at_pin=1),
            "alive-basis": pin(alive_at_pin_basis="measured-at-pin"),
            "alive-polled-before-proof": lambda item: item["parent_pin"].update(alive_polled_at=item["runtime_parent"]["read_finished_at"] - .001),
            "alive-polled-after-child-poll": lambda item: item["parent_pin"].update(alive_polled_at=item["unlinked"]["parent_alive_at"] + .001),
            "proof-key": lambda item: item["runtime_parent"].update(key=[95, 10049], key_after=[95, 10049]),
            "parent-key": pin(key=[95, 10051]),
            "unlinked-key": lost(parent_key=[95, 10051]),
            "parent-same-start": lambda item: (item["parent_pin"].update(key=[95, 10150]), item["unlinked"].update(parent_key=[95, 10150]),
                                               item["runtime_parent"].update(key=[95, 10150], key_after=[95, 10150])),
            "child-key": child(key=[600, 10151]),
            "child-parent": child(parent_pid=96),
            "child-parent-bool": child(parent_pid=True),
            "child-parent-float": child(parent_pid=95.0),
            "child-parent-text": child(parent_pid="95"),
            "restat-error": lost(restat_error="PermissionError", restat_errno=errno.EACCES),
            "restat-errno-float": lost(restat_errno=2.0),
            "restat-stage": lost(stage="classify-host"),
            "error-evidence": lambda item: item.update(error="EvidenceError", errno=None),
            "exit-zombie": lambda item: item.update(exit="zombie"),
            "file-sha": lambda item: item["parent_pin"]["file"].update(sha256="e" * 64),
            "file-method": lambda item: item["parent_pin"]["file"].update(method="sha256"),
            "pinned-before-sample": pin(pinned_at=-1.0),
            "pinned-after-proof": lambda item: item["parent_pin"].update(pinned_at=item["runtime_parent"]["read_started_at"] + .001),
            "alive-before-proof": lambda item: (item["child_stat"].update(at=item["runtime_parent"]["read_finished_at"] - .002),
                                                item["unlinked"].update(parent_alive_at=item["runtime_parent"]["read_finished_at"] - .001)),
            "alive-before-child-stat": lambda item: item["child_stat"].update(at=item["unlinked"]["parent_alive_at"] + .001),
            "restat-before-alive": lambda item: item["unlinked"].update(restat_at=item["unlinked"]["parent_alive_at"] - .001),
            "restat-after-absent": lambda item: item["unlinked"].update(restat_at=item["verified_absent_at"] + .001),
            "time-text": lost(parent_alive_at="101.7"),
            "time-bool": child(at=True),
        }
        for part, names in (("parent_pin", ("key", "pinned_at", "alive_at_pin", "alive_at_pin_basis", "alive_polled_at", "cgroup", "shim_cgroup", "shim", "permissions",
                                            "active_namespace", "file")),
                            ("child_stat", ("key", "parent_pid", "at")),
                            ("unlinked", ("parent_key", "parent_alive_at", "restat_error", "restat_errno", "restat_at", "stage"))):
            for name in names:
                cases["missing-%s-%s" % (part, name)] = drop(part, name)
        for name in ("parent_pin", "child_stat", "unlinked"):
            cases["missing-" + name] = lambda item, name=name: item.pop(name)
        for name, change in cases.items():
            with self.subTest(case=name):
                _, scoped = scoped_reaped()
                change(self.item(scoped))
                actual = assessed(scoped, require_scope=True)
                self.assertIs(actual["passed"], False, (name, actual))

    def test_times_must_be_float(self):
        def check(**ints):
            _, scoped = scoped_reaped()
            item = self.item(scoped)
            parent = item["runtime_parent"]
            values = {"pinned_at": 100.0, "at": 101.0, "alive_polled_at": 101.5, "parent_alive_at": 102.0, "restat_at": 103.0,
                      "role_started": 100.0, "role_finished": 100.0, "absent": 103.0, "file_opened": 100.0, "file_started": 100.0,
                      "file_finished": 100.0}
            values.update(ints)
            parent.update(read_started_at=values["role_started"], read_finished_at=values["role_finished"])
            item["parent_pin"]["file"].update(opened_at=values["file_opened"], read_started_at=values["file_started"],
                                             read_finished_at=values["file_finished"])
            item["parent_pin"]["pinned_at"], item["child_stat"]["at"] = values["pinned_at"], values["at"]
            item["parent_pin"]["alive_polled_at"] = values["alive_polled_at"]
            item["unlinked"].update(parent_alive_at=values["parent_alive_at"], restat_at=values["restat_at"])
            host = scoped["scope"]["observer_namespace"]
            profile.reaped_before_restat(item, tuple(item["key"]), tuple(parent["key"]), parent, scoped,
                                         scoped["samples"][17]["shim"], tuple(host), 100.0, values["absent"])
        check()
        for name, value in (("pinned_at", 100), ("at", 101), ("alive_polled_at", 101), ("parent_alive_at", 102), ("restat_at", 103),
                            ("role_started", 100), ("role_finished", 100), ("absent", 103), ("file_opened", 100),
                            ("file_started", 100), ("file_finished", 100)):
            with self.subTest(field=name):
                with self.assertRaises(profile.InvalidProfile) as caught:
                    check(**{name: value})
                self.assertEqual(caught.exception.args, ("invalid-clock",))

    def test_minimal_record_without_optional_child_facts_passes(self):
        legacy, scoped = minimal_reaped()
        self.assertEqual(assessed(scoped, require_scope=True), assessed(legacy))

    def test_explicit_child_facts_are_typed_and_verified(self):
        legacy, scoped = scoped_reaped()
        self.assertEqual(assessed(scoped, require_scope=True), assessed(legacy))
        cases = {"child-ns-container": lambda item: item.update(active_namespace=list(OWN)),
                 "child-uid-bool": lambda item: item["permissions"].update(uids=[False] * 4),
                 "child-uid-float": lambda item: item["permissions"].update(uids=[0.0] * 4),
                 "child-read-other-key": lambda item: item.update(child_reads=[[[600, 10151], 95]]),
                 "child-read-other-parent": lambda item: item.update(child_reads=[[[600, 10150], 96]]),
                 "child-read-bool-parent": lambda item: item.update(child_reads=[[[600, 10150], True]]),
                 "child-read-float-parent": lambda item: item.update(child_reads=[[[600, 10150], 95.0]]),
                 "child-reads-missing": lambda item: item.pop("child_reads"),
                 "namespace-errno-other": lambda item: item.update(namespace_absence_errno=errno.EIO),
                 "namespace-errno-missing": lambda item: item.pop("namespace_absence_errno"),
                 "file-opened-before-pin": lambda item: item["parent_pin"]["file"].update(opened_at=item["parent_pin"]["pinned_at"] - .001),
                 "file-opened-after-role": lambda item: item["parent_pin"]["file"].update(
                     opened_at=item["runtime_parent"]["read_started_at"] + .001)}
        for name, change in cases.items():
            with self.subTest(case=name):
                _, scoped = scoped_reaped()
                change(self.item(scoped))
                self.assertIs(assessed(scoped, require_scope=True)["passed"], False, name)
        _, scoped = scoped_reaped()
        self.item(scoped)["child_reads"] = [[[600, 10150], 95]]
        self.assertIs(assessed(scoped, require_scope=True)["passed"], True)

    def test_parent_exe_opened_between_pin_and_role_proof(self):
        def timeline(opened):
            _, scoped = scoped_reaped()
            sample = scoped["samples"][17]
            item = self.item(scoped)
            now = sample["time"]
            sample["read_started_at"] = now - .05
            item["parent_pin"]["pinned_at"] = now - .04
            item["runtime_parent"].update(read_started_at=now - .01, read_finished_at=now - .009)
            item["parent_pin"]["file"].update(opened_at=now - opened, read_started_at=now - .004, read_finished_at=now - .004)
            return assessed(scoped, require_scope=True)
        self.assertIs(timeline(.03)["passed"], True)
        self.assertEqual(timeline(.005), {"passed": False, "reason": "unproven-exited-runtime-helper"})
        self.assertEqual(timeline(.045), {"passed": False, "reason": "unproven-exited-runtime-helper"})

    def test_limit_is_summed_over_inventories(self):
        for split, passed in (((2, 2), True), ((2, 3), False)):
            with self.subTest(split=split):
                _, scoped = scoped_reaped()
                sample = scoped["samples"][17]
                inventories = sample["scope"]["inventories"]
                template = inventories[0]["exited_helpers"][0]
                second = copy.deepcopy(inventories[0])
                inventories.insert(1, second)
                sample["scope"]["capture_passes"] = 1
                pid = 600
                for inventory, count in zip(inventories[:2], split):
                    inventory["exited_helpers"] = []
                    inventory["cgroup_pids"] = [value for value in inventory["cgroup_pids"] if value != 600]
                    for _ in range(count):
                        item = copy.deepcopy(template)
                        item["key"] = [pid, 10150]
                        item["child_stat"]["key"] = [pid, 10150]
                        item["binding"].update(key_before=[pid, 10150], key_after=[pid, 10150], procdir_identity=[9, pid],
                                               procdir_identity_after=[9, pid])
                        inventory["exited_helpers"].append(item)
                        inventory["cgroup_pids"] = sorted(set(inventory["cgroup_pids"]) | {pid})
                        pid += 1
                actual = assessed(scoped, require_scope=True)
                if passed:
                    self.assertIs(actual["passed"], True, actual)
                else:
                    self.assertEqual(actual, {"passed": False, "reason": "reaped-before-restat-limit"})

    def test_more_than_four_per_sample_is_rejected(self):
        for count, passed in ((4, True), (5, False)):
            with self.subTest(count=count):
                _, scoped = scoped_reaped()
                first = scoped["samples"][17]["scope"]["inventories"][0]
                template = first["exited_helpers"][0]
                first["exited_helpers"] = []
                for offset in range(count):
                    item = copy.deepcopy(template)
                    pid = 600 + offset
                    item["key"] = [pid, 10150]
                    item["child_stat"]["key"] = [pid, 10150]
                    item["binding"].update(key_before=[pid, 10150], key_after=[pid, 10150], procdir_identity=[9, pid],
                                           procdir_identity_after=[9, pid])
                    first["exited_helpers"].append(item)
                first["cgroup_pids"] = sorted(set(first["cgroup_pids"]) | {600 + offset for offset in range(count)})
                actual = assessed(scoped, require_scope=True)
                if passed:
                    self.assertIs(actual["passed"], True, actual)
                else:
                    self.assertEqual(actual, {"passed": False, "reason": "reaped-before-restat-limit"})

    def test_role_proof_mismatch_with_full_pin_facts_is_refused(self):
        _, scoped = scoped_reaped()
        self.item(scoped)["runtime_parent"]["argv"] = [part.replace(CID, "c" * 64) for part in RUNC_ARGV]
        self.assertEqual(assessed(scoped, require_scope=True), {"passed": False, "reason": "unverified-runtime-command"})
        _, scoped = scoped_reaped()
        self.item(scoped)["runtime_parent"]["shim"] = {"key": [90, 900]}
        self.assertEqual(assessed(scoped, require_scope=True), {"passed": False, "reason": "unproven-exited-runtime-helper"})
        _, scoped = scoped_reaped()
        self.item(scoped)["parent_pin"]["file"]["sha256"] = "e" * 64
        self.assertEqual(assessed(scoped, require_scope=True), {"passed": False, "reason": "runtime-helper-content-mismatch"})

    def test_key_seen_outside_earlier_is_not_new(self):
        _, scoped = scoped_reaped()
        helper = self.item(scoped)
        target = scoped["samples"][16]["scope"]["inventories"][0]
        row = copy.deepcopy(target["excluded"][0])
        row.update(key=[600, 10150], binding=copy.deepcopy(helper["binding"]))
        row["binding"]["bound_at"] = row["read_started_at"]
        target["excluded"].append(row)
        target["cgroup_pids"] = sorted(target["cgroup_pids"] + [600])
        target["end_cgroup_pids"] = sorted(target["end_cgroup_pids"] + [600])
        self.assertEqual(assessed(scoped, require_scope=True), {"passed": False, "reason": "unproven-exited-runtime-helper"})

    def test_linked_reasons_still_need_parent_link(self):
        _, scoped = scoped_reaped()
        self.item(scoped)["reason"] = "parent-verified"
        self.assertIs(assessed(scoped, require_scope=True)["passed"], False)




class EarlyParentLinkControls(unittest.TestCase):
    def test_child_reaped_during_parent_proof_keeps_proven_link(self):
        kernel = Kernel(HELPER[0], None, 0, ("helper",))
        kernel.procs[RUNC_PARENT[0]]["key"] = (RUNC_PARENT[0], HELPER[1])
        kernel.procs[HELPER[0]]["parent"] = (RUNC_PARENT[0], HELPER[1])
        original = kernel.runtime_parent
        def reap(*args):
            result = original(*args)
            kernel.procs[HELPER[0]]["state"] = "gone"
            return result
        kernel.runtime_parent = reap
        result = kernel.inventory()
        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(len(result["exited_helpers"]), 1)
        link = result["exited_helpers"][0]["parent_link"]
        self.assertEqual(link["method"], "child-restat-under-pinned-parent")
        self.assertTrue(link["parent_pin"]["alive_after_proof"])

    def linked(self):
        legacy, scoped = scoped_helper()
        sample = scoped["samples"][17]
        item = sample["scope"]["inventories"][0]["exited_helpers"][0]
        proof, link = item["runtime_parent"], item["parent_link"]
        proof["procdir_identity"] = proof["procdir_identity_after"] = [78, 95]
        link["method"] = "child-restat-under-pinned-parent"
        link["parent_pin"] = {"key": list(proof["key"]), "method": "procdir+pidfd",
                              "procdir_identity": list(proof["procdir_identity"]),
                              "pinned_at": link["child_stat_at"], "alive_after_proof": True,
                              "alive_polled_at": link["parent_alive_at"]}
        return scoped, item

    def test_early_link_is_verified_and_each_fact_is_required(self):
        trace, item = self.linked()
        self.assertTrue(assessed(trace, require_scope=True)["passed"])
        for field, value in (("method", "pid-only"), ("alive_after_proof", False),
                             ("key", [95, 1]), ("procdir_identity", [0, 0]),
                             ("pinned_at", 999.0), ("alive_polled_at", 0.0)):
            with self.subTest(field=field):
                trace, item = self.linked()
                item["parent_link"]["parent_pin"][field] = value
                self.assertFalse(assessed(trace, require_scope=True)["passed"])
        trace, item = self.linked()
        item["parent_link"]["method"] = "unknown"
        self.assertFalse(assessed(trace, require_scope=True)["passed"])


class StableRetryHealthControls(unittest.TestCase):
    def collect_facts(self, trace, *, parent=90, after_parent=None, after_inode=1003, after_key=None, group=None):
        row = trace["samples"][13]["processes"][-1]
        key = tuple(row["key"])
        handle = {"key": key, "directory": 11, "pidfd": 12, "evidence": row["binding"]}
        before = SimpleNamespace(st_dev=88, st_ino=1003)
        after = SimpleNamespace(st_dev=88, st_ino=after_inode)
        with mock.patch.object(col, "clock", return_value=row["read_started_at"]), \
             mock.patch.object(col, "check_binding"), \
             mock.patch.object(col, "stat_at", side_effect=[(key, parent), (after_key or key, parent if after_parent is None else after_parent)]), \
             mock.patch.object(col.os, "stat", side_effect=[before, after]), \
             mock.patch.object(col, "command", return_value=tuple(base.HEALTH)), \
             mock.patch.object(col, "cgroup_at", return_value=trace["cgroup"] if group is None else group), \
             mock.patch.object(col, "identity_maps"), \
             mock.patch.object(col, "runtime_parent", return_value={"key": [parent, 10050]}), \
             mock.patch.object(col, "shim", return_value=trace["samples"][13]["shim"]):
            try:
                col.runtime_parent_after_enoent(handle, key, 90, CID, trace["runtime"], trace["cgroup"], [88, 1002])
            except col.RuntimeExecTransition as error:
                self.assertEqual(error.args[0], "runtime-exec-transition-during-retry")
                return error.args[1]
        self.fail("Expected a bounded transition followed by a fresh snapshot")

    def prepared(self):
        trace = health_trace()
        item = attempt(trace, facts=self.collect_facts(trace))
        return with_attempts(trace, [item]), item

    def test_actual_collector_stable_health_facts_pass_the_profile(self):
        trace, item = self.prepared()
        result = assessed(trace)
        self.assertIs(result["passed"], True, result)

    def test_each_stable_retry_fact_is_required(self):
        for field, value in (("key_before", [200, 1]), ("key_after", [200, 1]),
                             ("parent_pid_before", 95), ("parent_pid_after", 95),
                             ("exe_identity_after", [88, 999]), ("cgroup_after", "/foreign"),
                             ("read_started_at", 0.0), ("time", 999.0)):
            with self.subTest(field=field):
                trace, item = self.prepared()
                item["facts"]["retry_read"][field] = value
                self.assertFalse(assessed(trace)["passed"])
        for mode in ("missing-read", "missing-proof", "no-runtime-partial", "late-read", "wrong-reason"):
            with self.subTest(mode=mode):
                trace, item = self.prepared()
                if mode == "missing-read":
                    del item["facts"]["retry_read"]
                elif mode == "missing-proof":
                    del item["partial"]["runtime_executable"]
                elif mode == "no-runtime-partial":
                    item["partial"]["argv"] = list(base.HEALTH)
                elif mode == "wrong-reason":
                    item["reason"] = "runtime-exec-transition-during-snapshot"
                    item["facts"].update(first_parent=95, second_parent=90)
                else:
                    item["facts"]["retry_read"]["time"] += .051
                    item["time"] += .051
                self.assertFalse(assessed(trace)["passed"])

    def test_collector_refuses_unstable_or_foreign_stable_health(self):
        for changes in ({"parent": 95}, {"after_parent": 91}, {"after_inode": 999},
                        {"after_key": (200, 10101)}, {"group": "/foreign"}):
            with self.subTest(changes=changes):
                try:
                    self.collect_facts(health_trace(), **changes)
                except col.EvidenceError as error:
                    self.assertIsNot(type(error), col.RuntimeExecTransition)
                else:
                    self.fail("Unstable or foreign retry was accepted")


if __name__ == "__main__":
    unittest.main(verbosity=2)
