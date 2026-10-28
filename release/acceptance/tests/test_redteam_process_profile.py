import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import redteam
from test_health_bootstrap_namespace_scope import scope_fixture

CID = "a" * 64
IMAGE = "sha256:" + "b" * 64
INDEX = "sha256:" + "d" * 64
ORIGINAL = {"id": CID, "image": IMAGE, "pid": 100, "running": True, "restarts": 0, "runtime": "runc"}
SECRET = "SYNTHETIC_PRIVATE_STDERR_MUST_NOT_BE_REPORTED"


def valid_trace(cycles=2):
    cgroup = "/docker/" + CID
    rows = []
    for pid, uid, argv, parent in ((100, 51000, ["/usr/local/bin/python", "/usr/local/bin/netops", "serve"], [90, 900]),
                                   (101, 51001, ["/usr/local/bin/python", "-m", "netops", "worker", "helper"], [100, 1000]),
                                   (102, 51002, ["/usr/local/bin/python", "-m", "netops", "worker", "auditor"], [100, 1000]),
                                   (103, 51003, ["/usr/local/bin/python", "-m", "netops", "worker", "admin"], [100, 1000])):
        binding = {"method": "procdir+pidfd", "key_before": [pid, 1000], "key_after": [pid, 1000],
                   "procdir_identity": [9, pid], "procdir_identity_after": [9, pid], "cgroup": cgroup, "bound_at": 100.0}
        rows.append({"key": [pid, 1000], "parent": parent, "argv": argv, "binding": binding,
                     "uids": [uid] * 4, "gids": [uid] * 4, "groups": [], "nnp": 1,
                     "caps": dict.fromkeys(("inh", "prm", "eff", "bnd", "amb"), 0)})
    shim = {"key": [90, 900], "exe_identity": [8, 1001], "exe": "/usr/bin/containerd-shim-runc-v2",
            "argv": ["/usr/bin/containerd-shim-runc-v2", "-namespace", "moby", "-id", CID, "-address", "synthetic-socket"]}
    samples = []
    for index in range(851):
        now = 100 + index / 10
        observed = copy.deepcopy(rows)
        for row in observed:
            row.update(read_started_at=now, read_finished_at=now)
        samples.append({"time": now, "complete": True, "shim": copy.deepcopy(shim), "pids": [100, 101, 102, 103],
                        "processes": observed, "exited": [], "exit_proofs": [], "races": [], "failures": []})
    for first, pid in ((100, 200), (400, 201))[:cycles]:
        birth = int(samples[first]["time"] * 100)
        binding = {"method": "procdir+pidfd", "key_before": [pid, birth], "key_after": [pid, birth],
                   "procdir_identity": [9, pid], "procdir_identity_after": [9, pid], "cgroup": cgroup,
                   "bound_at": samples[first]["time"]}
        health = {"key": [pid, birth], "parent": [90, 900],
                  "argv": ["/usr/local/bin/python", "/usr/local/bin/netops", "health"],
                  "binding": binding, "uids": [51000] * 4, "gids": [51000] * 4,
                  "groups": [], "nnp": 1, "caps": dict.fromkeys(("inh", "prm", "eff", "bnd", "amb"), 0)}
        for sample in samples[first:first + 3]:
            row = copy.deepcopy(health)
            row.update(read_started_at=sample["time"], read_finished_at=sample["time"])
            sample["processes"].append(row)
            sample["pids"].append(pid)
        ended = samples[first + 3]
        ended["exited"] = [[pid, birth]]
        ended["exit_proofs"] = [{"kind": "reaped", "key": [pid, birth], "binding": copy.deepcopy(binding),
                                 "proc_missing": True, "poll_before": 17, "poll_after": 17, "replacement_key": None,
                                 "read_started_at": ended["time"], "read_finished_at": ended["time"]}]
    predicate_sha = hashlib.sha256(Path(redteam.__file__).with_name("health_bootstrap_profile.py").read_bytes()).hexdigest()
    trace = {"collector_schema": "health-bootstrap-trace-v4", "predicate_sha256": predicate_sha, "container_id": CID, "clock": "CLOCK_BOOTTIME",
            "uid_namespace": "container", "ticks_per_second": 100, "health_interval": 30, "health_timeout": 10,
            "begin": 100.0, "end": 185.0, "init": [100, 1000], "cgroup": cgroup, "samples": samples,
            "initial_metadata": copy.deepcopy(ORIGINAL), "final_metadata": copy.deepcopy(ORIGINAL),
            "assessment": {"passed": True}}
    return scope_fixture(trace)


class Context:
    def __init__(self):
        self.items, self.calls = [], []
        self.args = SimpleNamespace(image_digest=None)
        self.source_image = "synthetic/netops:local"
        self.resolved_image = IMAGE
        self.resolved_rc = 0
        self.endpoint = "unix:///var/run/docker.sock"
        self.security = ["name=seccomp,profile=builtin"]
        self.runtime = {"path": "/usr/bin/runc"}

    def container(self):
        return CID

    def docker(self, *args):
        self.calls.append(args)
        if args[0] == "context":
            value = self.endpoint
        elif args[0] == "info":
            value = {"security": self.security, "default": "runc", "runtimes": {"runc": self.runtime}}
        elif args[0] == "image":
            return SimpleNamespace(returncode=self.resolved_rc, stdout=self.resolved_image + "\n", stderr=SECRET)
        elif args[0] == "inspect":
            value = {**ORIGINAL, "source_image": self.source_image}
        else:
            raise AssertionError("Unexpected Docker operation")
        return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr=SECRET)

    def add(self, *item):
        self.items.append(item)


class ProcessProfileInvocation(unittest.TestCase):
    def invoke(self, trace=None, *, rc=0, uid=0, environment=None, context=None, output=None, error=None):
        ctx = context or Context()
        result = SimpleNamespace(returncode=rc, stdout=json.dumps(trace if trace is not None else valid_trace()) if output is None else output, stderr=SECRET)
        capture = tempfile.TemporaryDirectory()
        self.addCleanup(capture.cleanup)
        with mock.patch.dict(os.environ, environment or {"HOME": "/synthetic/root"}, clear=True), \
             mock.patch.object(redteam.sys, "platform", "linux"), mock.patch.object(redteam.os, "geteuid", return_value=uid), \
             mock.patch.object(redteam.subprocess, "run", return_value=result, side_effect=error) as run:
            ctx.args.process_profile_dir = os.path.join(capture.name, "process-profile-collector")
            ctx.process_profile_token = "T" * 64
            before = dict(os.environ)
            redteam.check_processes(ctx)
            self.assertEqual(dict(os.environ), before)
        self.assertEqual(len(ctx.items), 1)
        self.assertEqual(ctx.items[0][:2], ("process-profile", "F16/F23"))
        self.assertNotIn(SECRET, str(ctx.items))
        return ctx.items[0], run

    def test_rejected_collector_profile_reports_bounded_reason(self):
        for reason in ("namespace-snapshot-budget-or-closure", "root-in-role-tree"):
            with self.subTest(reason=reason):
                item, _ = self.invoke({"assessment": {"passed": False, "reason": reason},
                                       "private": SECRET}, rc=1)
                self.assertEqual(item[2], "FAIL")
                self.assertTrue(item[3].endswith("; reason=" + reason), item[3])

    def test_invalid_collector_failure_cannot_inject_a_detail(self):
        for reason in (None, 17, [], {}, "", "a" * 81, "private output",
                       "unsafe\nreason", "unsafe_reason", "é", SECRET):
            with self.subTest(reason=reason):
                item, _ = self.invoke({"assessment": {"passed": False, "reason": reason}}, rc=1)
                self.assertEqual(item[2], "FAIL")
                self.assertNotIn("; reason=", item[3])
        for rc, output in ((2, '{"assessment":{"passed":false,"reason":"namespace-snapshot-budget-or-closure"}}'),
                           (1, "invalid JSON"), (1, "[]"), (1, '{"assessment":[]}'),
                           (1, '{"assessment":{"passed":true,"reason":"namespace-snapshot-budget-or-closure"}}')):
            with self.subTest(rc=rc, output=output):
                item, _ = self.invoke(rc=rc, output=output)
                self.assertEqual(item[2], "FAIL")
                self.assertNotIn("; reason=", item[3])

    def test_rootful_control_uses_canonical_collector_and_sanitized_summary(self):
        item, run = self.invoke()
        self.assertEqual(item[2], "PASS")
        args = run.call_args.args[0]
        self.assertEqual(args[:2], [sys.executable, "-B"])
        self.assertEqual(Path(args[2]).name, "collect_health_bootstrap_trace.py")
        self.assertEqual(args[3:], [CID])
        self.assertEqual(run.call_args.kwargs["timeout"], 150)
        summary = json.loads(item[3])
        self.assertEqual(summary["samples"], 851)
        self.assertEqual(summary["health_processes"], 2)
        self.assertEqual(summary["root_samples"], 0)
        self.assertEqual(summary["role_uids"], {"gateway": 51000, "helper": 51001, "auditor": 51002, "admin": 51003})
        self.assertNotIn(CID, item[3])
        self.assertNotIn("argv", item[3])

    def test_legacy_header_cannot_downgrade_canonical_scope(self):
        trace = valid_trace()
        trace["collector_schema"] = "health-bootstrap-trace-v4"
        del trace["scope"]
        item, _ = self.invoke(trace)
        self.assertEqual(item[2], "FAIL")

    def test_missing_scope_cannot_reuse_collector_pass_assessment(self):
        trace = valid_trace()
        del trace["scope"]
        item, _ = self.invoke(trace)
        self.assertEqual(item[2], "FAIL")

    def test_nonroot_actions_preserves_home_host_and_implicit_config(self):
        env = {"HOME": "/synthetic/runner", "DOCKER_HOST": "unix:///synthetic/docker.sock"}
        item, run = self.invoke(uid=1001, environment=env)
        self.assertEqual(item[2], "PASS")
        args = run.call_args.args[0]
        self.assertEqual(args[:2], ["sudo", "-n"])
        self.assertIn("HOME", args[2])
        child = run.call_args.kwargs["env"]
        self.assertEqual(child["HOME"], env["HOME"])
        self.assertEqual(child["DOCKER_HOST"], env["DOCKER_HOST"])
        self.assertEqual(child["DOCKER_CONFIG"], "/synthetic/runner/.docker")
        self.assertNotIn(env["DOCKER_HOST"], " ".join(args))

    def test_context_precedence_and_explicit_config_are_preserved(self):
        env = {"HOME": "/synthetic/runner", "DOCKER_CONTEXT": "synthetic-context",
               "DOCKER_HOST": "tcp://unused.invalid:1234", "DOCKER_CONFIG": "/synthetic/custom-config"}
        ctx = Context()
        item, run = self.invoke(uid=1001, environment=env, context=ctx)
        self.assertEqual(item[2], "PASS")
        self.assertEqual(ctx.calls[0][0], "context")
        for field, value in env.items():
            self.assertEqual(run.call_args.kwargs["env"][field], value)

    def test_rootless_never_sudos_or_claims_product_failure(self):
        ctx = Context()
        ctx.security.append("name=rootless")
        item, run = self.invoke(uid=1001, context=ctx)
        self.assertEqual(item[2], "NOT RUN")
        self.assertIn("QA unsupported", item[3])
        self.assertIn("product profile not evaluated", item[3])
        run.assert_not_called()

    def test_remote_transport_is_unsupported_without_contacting_it(self):
        ctx = Context()
        ctx.endpoint = "ssh://synthetic.invalid"
        item, run = self.invoke(context=ctx)
        self.assertEqual(item[2], "NOT RUN")
        self.assertEqual(len(ctx.calls), 1)
        run.assert_not_called()

    def test_unknown_endpoint_and_daemon_schema_fail_closed(self):
        for endpoint in (None, "", "unverified-transport"):
            ctx = Context()
            ctx.endpoint = endpoint
            item, run = self.invoke(context=ctx)
            self.assertEqual(item[2], "FAIL")
            run.assert_not_called()
        ctx = Context()
        ctx.security = None
        item, run = self.invoke(context=ctx)
        self.assertEqual(item[2], "FAIL")
        run.assert_not_called()

    def test_zero_or_one_distinct_health_identity_cannot_pass(self):
        for cycles in (0, 1):
            item, _ = self.invoke(valid_trace(cycles=cycles))
            self.assertEqual(item[2], "FAIL")

    def test_nonzero_rc_cannot_promote_valid_looking_trace(self):
        item, _ = self.invoke(rc=1)
        self.assertEqual(item[2], "FAIL")

    def test_malformed_unknown_and_incomplete_trace_cannot_pass(self):
        for value in ("not-json", "{}", "[]"):
            item, _ = self.invoke(output=value)
            self.assertEqual(item[2], "FAIL")
        for mutate in (lambda row: row.update(collector_error=True),
                       lambda row: row["assessment"].update(passed=False),
                       lambda row: row.update(collector_schema="unknown"),
                       lambda row: row.pop("predicate_sha256"),
                       lambda row: row.update(predicate_sha256="0" * 64),
                       lambda row: row["samples"][10].update(complete=False),
                       lambda row: row["samples"][10]["processes"].pop(),
                       lambda row: row["samples"][10]["processes"][0]["caps"].update(eff=1),
                       lambda row: (row["samples"].pop(), row.update(end=184.9))):
            trace = valid_trace()
            mutate(trace)
            item, _ = self.invoke(trace)
            self.assertEqual(item[2], "FAIL")

    def test_original_container_image_pid_or_restart_change_fails(self):
        for field, value in (("id", "c" * 64), ("image", "sha256:" + "c" * 64), ("pid", 200), ("restarts", 1)):
            for where in ("initial_metadata", "final_metadata"):
                trace = valid_trace()
                trace[where][field] = value
                item, _ = self.invoke(trace)
                self.assertEqual(item[2], "FAIL")

    def test_index_reference_binds_to_a_different_config_image_id(self):
        ctx = Context()
        ctx.args.image_digest = INDEX
        ctx.source_image = "synthetic/netops@" + INDEX
        item, _ = self.invoke(context=ctx)
        self.assertEqual(item[2], "PASS")
        self.assertIn(("image", "inspect", "--format", "{{.Id}}", ctx.source_image), ctx.calls)
        self.assertNotEqual(INDEX, IMAGE)
        self.assertEqual(ctx.args.image_digest, INDEX)

    def test_local_config_id_binding_accepts_a_tag_without_retargeting_it(self):
        ctx = Context()
        ctx.args.image_digest = IMAGE
        item, _ = self.invoke(context=ctx)
        self.assertEqual(item[2], "PASS")
        self.assertIn(("image", "inspect", "--format", "{{.Id}}", IMAGE), ctx.calls)
        self.assertNotIn(("image", "inspect", "--format", "{{.Id}}", ctx.source_image), ctx.calls)
        ctx = Context()
        ctx.args.image_digest = INDEX
        ctx.source_image = INDEX
        item, _ = self.invoke(context=ctx)
        self.assertEqual(item[2], "PASS")

    def test_wrong_expected_digest_reference_retarget_or_malformed_binding_fails(self):
        for expected, reference, resolved in ((INDEX, "synthetic/netops:local", IMAGE),
                                               (INDEX, "synthetic/netops@" + IMAGE, IMAGE),
                                               (INDEX, "synthetic/netops@" + INDEX, "sha256:" + "c" * 64),
                                               (INDEX, "@" + INDEX, IMAGE),
                                               ("invalid", "synthetic/netops:local", IMAGE),
                                               ("", "synthetic/netops:local", IMAGE),
                                               (17, "synthetic/netops:local", IMAGE)):
            ctx = Context()
            ctx.args.image_digest, ctx.source_image, ctx.resolved_image = expected, reference, resolved
            item, run = self.invoke(context=ctx)
            self.assertEqual(item[2], "FAIL")
            run.assert_not_called()

        ctx = Context()
        ctx.args.image_digest, ctx.resolved_rc = IMAGE, 1
        item, run = self.invoke(context=ctx)
        self.assertEqual(item[2], "FAIL")
        run.assert_not_called()

    def test_host_runc_fallback_is_guarded_and_explicit(self):
        for owner, mode, expected in ((0, 0o755, "PASS"), (1000, 0o755, "FAIL"), (0, 0o777, "FAIL")):
            ctx = Context()
            ctx.runtime = {"path": "runc"}
            with mock.patch("shutil.which", return_value="/synthetic/runc"), \
                 mock.patch.object(redteam.os.path, "realpath", return_value="/synthetic/runc"), \
                 mock.patch.object(redteam.os, "stat", return_value=SimpleNamespace(st_uid=owner, st_mode=stat.S_IFREG | mode)):
                item, run = self.invoke(context=ctx)
            self.assertEqual(item[2], expected)
            if expected == "PASS":
                self.assertEqual(run.call_args.args[0][-2:], ["--runtime-path", "/synthetic/runc"])
            else:
                run.assert_not_called()

    def test_timeout_or_permission_exception_is_a_fixed_failure(self):
        for error in (subprocess.TimeoutExpired("synthetic", 150), PermissionError(SECRET)):
            item, _ = self.invoke(error=error)
            self.assertEqual(item[2], "FAIL")


if __name__ == "__main__":
    unittest.main()
