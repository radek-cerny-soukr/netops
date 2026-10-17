import copy
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest import mock

import test_health_bootstrap_profile as base

collector = base.collector


class TerminalWaitControls(unittest.TestCase):
    def capture(self, *, finished=True, prior_change=None, foreign=False,
                bad_terminal=False, known=True, binding_change=False, exit_index=17):
        raw = base.external_fixture()
        if exit_index != 17:
            raw["samples"][17]["exited"] = []
            base.insert(raw, 17, exit_index, base.process(200, 10100, 51000, base.HEALTH, base.SHIM))
            raw["samples"][exit_index]["exited"] = [[200, 10100]]
        trace = base.observed_fixture(raw)
        prior = {tuple(row["key"]): copy.deepcopy(row)
                 for row in trace["samples"][exit_index - 1]["processes"]}
        key = (200, 10100)
        current = copy.deepcopy(prior)
        if prior_change:
            prior[key].update(copy.deepcopy(prior_change))
        handles = {k: {"key": k, "directory": k[0] + 1000, "pidfd": k[0] + 2000,
                       "evidence": copy.deepcopy(row["binding"])} for k, row in current.items()}
        if binding_change:
            handles[key]["evidence"]["procdir_identity"] = [9, 99999]
        by_pid = {k[0]: row for k, row in current.items()}
        ready, waits = [False], []
        test = self

        class Poll:
            def register(self, fd, events):
                test.assertEqual((fd, events), (2200, collector.select.POLLIN))

            def poll(self, milliseconds):
                test.assertIs(type(milliseconds), int)
                test.assertGreaterEqual(milliseconds, 0, "unbounded terminal wait")
                test.assertLessEqual(milliseconds, 20, "terminal wait exceeds budget")
                test.assertLess(len(waits), 6, "unbounded repeated polling")
                waits.append(milliseconds)
                if milliseconds:
                    test.assertEqual(milliseconds, 20)
                    ready[0] = finished
                return [(2200, collector.select.POLLIN)] if ready[0] else []

        def proc_stat(pid):
            if pid == 90:
                return tuple(base.SHIM), 1
            row = by_pid[pid]
            return tuple(row["key"]), row["parent"][0]

        def permissions(directory):
            row = by_pid[directory - 1000]
            result = {name: copy.deepcopy(row[name]) for name in ("uids", "gids", "groups", "nnp", "caps")}
            if directory == 1200 and ready[0] and bad_terminal:
                result["caps"]["eff"] = 1
            return result

        pin = current[key]["binding"]["procdir_identity"]
        with ExitStack() as stack:
            patches = {
                "clock": mock.Mock(return_value=trace["samples"][exit_index]["time"]),
                "members": mock.Mock(side_effect=[set(by_pid), set(by_pid) - {200}]),
                "proc_stat": mock.Mock(side_effect=proc_stat),
                "check_binding": mock.Mock(),
                "command": mock.Mock(side_effect=lambda pid: tuple(by_pid[pid]["argv"])),
                "permissions_at": mock.Mock(side_effect=permissions),
                "identity_maps": mock.Mock(),
                "cgroup_path": mock.Mock(return_value=trace["cgroup"]),
                "stat_detail_at": mock.Mock(side_effect=lambda directory, pid:
                    (key, 90, "Z" if ready[0] else "R")),
                "cgroup_at": mock.Mock(side_effect=lambda directory:
                    "/foreign" if foreign and ready[0] else trace["cgroup"]),
                "shim": mock.Mock(return_value=trace["samples"][exit_index]["shim"]),
                "close_binding": mock.Mock(),
            }
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(collector, name, value))
            stack.enter_context(mock.patch.object(collector.select, "poll", Poll))
            stack.enter_context(mock.patch.object(collector.os, "fstat",
                return_value=SimpleNamespace(st_dev=pin[0], st_ino=pin[1])))
            actual = collector.sample(99, trace["cgroup"], tuple(base.INIT), 90, base.CID,
                prior if known else {k: v for k, v in prior.items() if k != key},
                {}, handles, trace["samples"][exit_index - 1]["time"])
        trace["samples"][exit_index] = actual
        return trace, actual, waits

    def test_real_sampler_waits_before_terminal_proof_and_preserves_full_trace(self):
        trace, actual, waits = self.capture()
        self.assertIs(actual["complete"], True)
        self.assertEqual(actual["failures"], [])
        self.assertEqual(waits, [20, 0, 0])
        proof = actual["exit_proofs"][0]
        self.assertEqual((proof["state_before"], proof["state_after"]), ("Z", "Z"))
        self.assertEqual((proof["poll_before"], proof["poll_after"]), (1, 1))
        self.assertEqual(proof["terminal_wait"], {"requested_seconds": .020, "elapsed_seconds": 0})
        self.assertEqual(actual["exited"], [[200, 10100]])
        self.assertEqual(len(actual["processes"]), 4)
        self.assertTrue(base.assess_observed_trace(trace)["passed"])

    def test_timeout_keeps_original_live_observation_and_failure(self):
        _, actual, waits = self.capture(finished=False)
        self.assertIn(20, waits)
        self.assertFalse(actual["complete"])
        self.assertEqual(actual["exit_proofs"], [])
        observed = actual["failures"][0]["exit_observation"]
        self.assertEqual((observed["poll_before"], observed["state_before"]), (0, "R"))
        self.assertTrue(any(row["key"] == [200, 10100] for row in actual["processes"]))

    def test_unsafe_or_nonhealth_prior_never_gets_terminal_wait(self):
        for change in ({"argv": list(collector.SERVE)},
                       {"argv": list(collector.WORKER) + ["helper"]},
                       {"argv": list(collector.WORKER) + ["helper"], "uids": [51001] * 4, "gids": [51001] * 4},
                       {"argv": ["unknown"]}, {"uids": [0] * 4, "gids": [0] * 4},
                       {"groups": [51000]}, {"nnp": 0}, {"caps": dict.fromkeys(("inh", "prm", "eff", "bnd", "amb"), 1)}):
            with self.subTest(change=change):
                _, actual, waits = self.capture(prior_change=change)
                self.assertFalse(actual["complete"])
                self.assertNotIn(20, waits)

    def test_unknown_key_or_mismatched_binding_cannot_borrow_health_wait(self):
        for options in ({"known": False}, {"binding_change": True},
                        {"prior_change": {"key": [200, 10101]}}):
            with self.subTest(options=options):
                _, actual, waits = self.capture(**options)
                self.assertFalse(actual["complete"])
                self.assertNotIn(20, waits)

    def test_foreign_or_unsafe_terminal_observation_still_fails(self):
        for options in ({"foreign": True}, {"bad_terminal": True}):
            with self.subTest(options=options):
                _, actual, waits = self.capture(**options)
                self.assertIn(20, waits)
                self.assertFalse(actual["complete"])
                self.assertEqual(actual["exit_proofs"], [])

    def test_terminal_wait_preserves_prior_overdue_root_bootstrap_failure(self):
        trace, actual, _ = self.capture(exit_index=112)
        self.assertTrue(actual["complete"])
        self.assertTrue(base.assess_observed_trace(trace)["passed"])
        overdue_root = copy.deepcopy(trace)
        for sample in overdue_root["samples"][:112]:
            for row in sample["processes"]:
                if row["key"] == [200, 10100]:
                    row["uids"] = row["gids"] = [0] * 4
        assessed = base.assess_observed_trace(overdue_root)
        self.assertFalse(assessed["passed"])
        self.assertEqual(assessed["reason"], "bootstrap-exceeded-health-timeout")

    def test_wait_telemetry_measures_actual_poll_and_default_has_no_extra_key(self):
        trace = base.zombie_fixture()
        row = trace["samples"][16]["processes"][-1]
        key = tuple(row["key"])
        handle = {"key": key, "directory": 11, "pidfd": 12, "evidence": row["binding"]}
        pin = row["binding"]["procdir_identity"]
        permissions = {name: row[name] for name in ("uids", "gids", "groups", "nnp", "caps")}
        for timeout in (0, .020):
            with self.subTest(timeout=timeout), ExitStack() as stack:
                clock = stack.enter_context(mock.patch.object(collector, "clock",
                    side_effect=[101.7, 101.72] if not timeout else [101.7, 101.701, 101.718, 101.72]))
                poll = stack.enter_context(mock.patch.object(collector.select, "poll"))
                poll.return_value.poll.return_value = [(12, 1)]
                stack.enter_context(mock.patch.object(collector, "stat_detail_at", return_value=(key, 90, "Z")))
                stack.enter_context(mock.patch.object(collector, "cgroup_at", return_value=trace["cgroup"]))
                stack.enter_context(mock.patch.object(collector, "permissions_at", return_value=permissions))
                stack.enter_context(mock.patch.object(collector.os, "fstat",
                    return_value=SimpleNamespace(st_dev=pin[0], st_ino=pin[1])))
                proof = collector.terminal_exit(handle, timeout=timeout)
                base.collector.verified_exit(proof, row, trace["cgroup"], 101.8, 101.6)
                if timeout:
                    self.assertAlmostEqual(proof["terminal_wait"]["elapsed_seconds"], .017)
                    self.assertEqual(proof["terminal_wait"]["requested_seconds"], .020)
                    poll.return_value.poll.assert_has_calls([mock.call(20), mock.call(0), mock.call(0)])
                else:
                    self.assertNotIn("terminal_wait", proof)
                    self.assertEqual(poll.return_value.poll.call_args_list, [mock.call(0), mock.call(0)])
                self.assertEqual(clock.call_count, 4 if timeout else 2)

    def test_invalid_wait_parameter_is_rejected_before_any_poll(self):
        for timeout in (-1, .020001, 1, True, None, "0.02", float("inf"), float("nan")):
            with self.subTest(timeout=timeout), mock.patch.object(collector.select, "poll") as poll:
                with self.assertRaises(collector.EvidenceError):
                    collector.terminal_exit({}, timeout=timeout)
                poll.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
