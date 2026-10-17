import sys
from pathlib import Path
import copy
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_health_bootstrap_profile as base
from test_health_bootstrap_profile import assess_trace

CID = base.CID
HEALTH = base.HEALTH
PIDFILE = "/run/containerd/io.containerd.runtime.v2.task/moby/" + CID + "/"


def set_external_parent(trace, parent):
    row = base.external_row(trace)
    row["parent"] = list(parent)
    row["runtime_parent"]["key"] = list(parent)
    row["runtime_parent"]["key_after"] = list(parent)


class Base(unittest.TestCase):
    def accept(self, trace):
        actual = assess_trace(trace)
        self.assertIs(actual["passed"], True, actual)

    def reject(self, trace, reason=None):
        actual = assess_trace(trace)
        self.assertIs(actual["passed"], False, actual)
        if reason is not None:
            self.assertEqual(actual["reason"], reason)


class SamplingAndTraceHeader(Base):
    def test_gap_300ms_between_samples_rejected(self):
        trace = base.fixture()
        del trace["samples"][20:22]
        self.reject(trace, "sampling-gap-or-order")

    def test_tail_gap_after_last_sample_rejected(self):
        trace = base.fixture()
        trace["end"] = 185.5
        self.reject(trace, "sampling-tail-gap")

    def test_clock_must_be_boottime(self):
        trace = base.fixture()
        trace["clock"] = "CLOCK_MONOTONIC"
        self.reject(trace, "unknown-clock-or-identity-namespace")

    def test_health_configuration_must_be_reviewed_values(self):
        for field, value in (("health_interval", 60), ("health_timeout", 30)):
            with self.subTest(field=field):
                trace = base.fixture()
                trace[field] = value
                self.reject(trace, "unreviewed-health-configuration")

    def test_observation_window_shorter_than_60s_rejected(self):
        trace = base.fixture()
        trace["samples"] = trace["samples"][:501]
        trace["end"] = 150.0
        self.reject(trace, "insufficient-observation-window")

    def test_trace_cid_must_be_lowercase_64hex(self):
        trace = base.fixture()
        upper = "A" * 64
        trace["container_id"] = upper
        for sample in trace["samples"]:
            sample["shim"]["argv"][4] = upper
        self.reject(trace, "invalid-container-id")

    def test_shim_identity_must_not_change_mid_trace(self):
        for field, value in (("key", [90, 901]), ("exe_identity", [8, 1003])):
            with self.subTest(field=field):
                trace = base.fixture()
                trace["samples"][400]["shim"][field] = value
                self.reject(trace, "shim-identity-changed")

    def test_retired_identity_cannot_reappear(self):
        trace = base.fixture()
        base.insert(trace, 10, 12, base.root_health())
        trace["samples"][12]["exited"] = [[200, 10100]]
        base.insert(trace, 14, 15, base.root_health())
        trace["samples"][15]["exited"] = [[200, 10100]]
        self.reject(trace, "duplicate-or-retired-identity")

    def test_process_born_after_sample_time_rejected(self):
        trace = base.fixture()
        base.insert(trace, 10, 11, base.root_health(birth=10200), exited=True)
        self.reject(trace, "process-born-after-sample")


class RootBootstrapTiming(Base):
    def test_exit_exactly_at_ten_seconds_is_accepted(self):
        trace = base.fixture()
        base.insert(trace, 10, 110, base.root_health())
        trace["samples"][110]["exited"] = [[200, 10100]]
        self.accept(trace)

    def test_exit_observed_after_ten_seconds_rejected(self):
        trace = base.fixture()
        base.insert(trace, 10, 111, base.root_health())
        trace["samples"][111]["exited"] = [[200, 10100]]
        self.reject(trace, "bootstrap-exceeded-health-timeout")

    def test_demote_observed_after_ten_seconds_rejected(self):
        trace = base.fixture()
        base.insert(trace, 10, 111, base.root_health())
        base.insert(trace, 111, 113, base.process(200, 10100, 51000, HEALTH, base.SHIM))
        trace["samples"][113]["exited"] = [[200, 10100]]
        self.reject(trace, "bootstrap-exceeded-health-timeout")

    def test_root_far_beyond_limit_then_exit_rejected(self):
        for last in (260, 450):
            with self.subTest(root_seconds=(last - 10) / 10):
                trace = base.fixture()
                base.insert(trace, 10, last, base.root_health())
                trace["samples"][last]["exited"] = [[200, 10100]]
                self.reject(trace, "bootstrap-exceeded-health-timeout")


class PermissionInvariants(Base):
    def test_bootstrap_every_capability_outside_0x1cb_rejected(self):
        self.assertTrue(assess_trace(base.fixture())["passed"])
        for field in ("eff", "prm", "bnd"):
            for bit in range(41):
                if 0x1CB >> bit & 1:
                    continue
                with self.subTest(field=field, bit=bit):
                    trace = base.fixture()
                    row = base.root_health()
                    row["caps"][field] |= 1 << bit
                    base.insert(trace, 10, 11, row, exited=True)
                    self.reject(trace, "extra-terminal-capability")

    def test_gateway_and_roles_every_capability_set_must_be_zero(self):
        for index in range(4):
            for field in ("inh", "prm", "eff", "bnd", "amb"):
                with self.subTest(index=index, field=field):
                    trace = base.fixture()
                    trace["samples"][700]["processes"][index]["caps"][field] = 1
                    self.reject(trace, "unsafe-terminal-identity")

    def test_gateway_and_roles_supplementary_group_root_rejected(self):
        for index in range(4):
            with self.subTest(index=index):
                trace = base.fixture()
                trace["samples"][700]["processes"][index]["groups"] = [0]
                self.reject(trace, "unsafe-terminal-identity")


class ProcessTree(Base):
    def test_gateway_must_be_direct_shim_child(self):
        trace = base.fixture()
        trace["samples"][300]["processes"][0]["parent"] = [91, 900]
        self.reject(trace, "missing-or-changed-gateway")

    def test_role_must_be_direct_gateway_child(self):
        trace = base.fixture()
        trace["samples"][300]["processes"][1]["parent"] = [95, 950]
        self.reject(trace, "missing-or-duplicate-role")

    def test_role_restart_with_new_identity_rejected(self):
        trace = base.fixture()
        for sample in trace["samples"][400:]:
            sample["processes"][1]["key"] = [104, 13990]
            sample["pids"][1] = 104
        trace["samples"][400]["exited"] = [[101, 1000]]
        self.reject(trace, "role-identity-changed")


class ExternalParentProof(Base):
    def test_proof_inside_old_child_read_is_stale(self):
        trace = base.external_fixture()
        row = base.external_row(trace)
        row["read_started_at"], row["read_finished_at"] = 100.85, 100.87
        row["runtime_parent"]["read_started_at"] = 100.851
        row["runtime_parent"]["read_finished_at"] = 100.86
        self.reject(trace, "stale-runtime-parent-proof")

    def test_proof_started_before_child_read_rejected(self):
        trace = base.external_fixture()
        base.external_row(trace)["runtime_parent"]["read_started_at"] = 101.07
        self.reject(trace, "stale-runtime-parent-proof")

    def test_parent_born_after_child_rejected(self):
        trace = base.external_fixture()
        set_external_parent(trace, [95, 10101])
        self.reject(trace, "runtime-parent-not-external")

    def test_parent_born_before_shim_rejected(self):
        trace = base.external_fixture()
        set_external_parent(trace, [95, 800])
        self.reject(trace, "runtime-parent-not-external")

    def test_parent_pid_inside_container_set_rejected(self):
        trace = base.external_fixture()
        set_external_parent(trace, [101, 1001])
        self.reject(trace, "runtime-parent-not-external")

    def test_exec_id_in_pidfile_must_be_64hex(self):
        for value in (PIDFILE + "c" * 12 + ".pid", PIDFILE + "c" * 64 + ".pid.x"):
            with self.subTest(value=value):
                trace = base.external_fixture()
                base.external_row(trace)["runtime_parent"]["argv"][13] = value
                self.reject(trace, "unverified-runtime-command")

    def test_process_file_needs_digits(self):
        trace = base.external_fixture()
        base.external_row(trace)["runtime_parent"]["argv"][10] = "/tmp/runc-process"
        self.reject(trace, "unverified-runtime-command")


if __name__ == "__main__":
    unittest.main(verbosity=2)
