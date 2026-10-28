import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from netops import operator, state
from netops.files import UIDS, write_private

class StateCompatibility(unittest.TestCase):
    def fixture(self, root, document=None):
        gateway = root / "gateway"
        gateway.mkdir(mode=0o700)
        data = {"version": 1, "product_version": "1.0.4", "audit": {"mode": "local"}}
        if document is not None:
            data = document
        write_private(gateway / "config.json", json.dumps(data).encode())
        return data

    def test_only_exact_current_product_and_schema_are_accepted(self):
        current = {"version": 1, "product_version": "1.0.4"}
        self.assertIs(state.check_state_version(current), current)
        for document in ({"version": 1, "product_version": "1.0.5"},
                         {"version": 1, "product_version": "0.3.12"},
                         {"version": 1, "product_version": "CANARY_PRIVATE_VALUE"},
                         {"version": 2, "product_version": "1.0.4"},
                         {"version": True, "product_version": "1.0.4"},
                         {"version": 1}, [], None):
            with self.subTest(document=document), self.assertRaises(state.StateCompatibilityError) as caught:
                state.check_state_version(document)
            self.assertNotIn("CANARY_PRIVATE_VALUE", str(caught.exception))

    def test_invalid_version_refuses_before_creating_lock_or_changing_data(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(UIDS, {"gateway": os.geteuid()}):
            root = Path(temp)
            self.fixture(root, {"version": 1, "product_version": "1.0.5"})
            before = (root / "gateway/config.json").read_bytes()
            with patch.object(operator, "STATE", root), self.assertRaises(state.StateCompatibilityError):
                operator.acquire_state()
            self.assertEqual((root / "gateway/config.json").read_bytes(), before)
            self.assertEqual([p.name for p in (root / "gateway").iterdir()], ["config.json"])

    def test_state_json_is_private_regular_strict_and_nonfinite_refused(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(UIDS, {"gateway": os.geteuid()}):
            root = Path(temp)
            self.fixture(root)
            path = root / "gateway/config.json"
            self.assertEqual(state.read_state_settings(root)["product_version"], "1.0.4")
            for bad in (b'{"version":1,"product_version":"1.0.5","product_version":"1.0.4"}',
                        b'{"version":1,"product_version":"1.0.4","value":NaN}', b'{'):
                with self.subTest(bad=bad):
                    write_private(path, bad, replace=True)
                    with self.assertRaises(state.StateCompatibilityError):
                        state.read_state_settings(root)
            write_private(path, b'{"version":1,"product_version":"1.0.4"}', replace=True)
            path.chmod(0o644)
            with self.assertRaises(state.StateCompatibilityError):
                state.read_state_settings(root)

    def test_compatibility_is_rechecked_under_lock_and_descriptor_closed_on_refusal(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(UIDS, {"gateway": os.geteuid()}):
            root = Path(temp)
            settings = self.fixture(root)
            before = len(os.listdir("/proc/self/fd"))
            with patch.object(operator, "STATE", root), \
                 patch.object(operator, "read_state_settings", side_effect=[settings, state.StateCompatibilityError("refused")]), \
                 self.assertRaises(state.StateCompatibilityError):
                operator.acquire_state()
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)
            with patch.object(operator, "STATE", root):
                descriptor = operator.acquire_state()
                os.close(descriptor)

    def test_serve_refuses_future_state_before_prepare_or_child_start(self):
        from netops import bootstrap
        with tempfile.TemporaryDirectory() as temp, patch.dict(UIDS, {"gateway": os.geteuid()}):
            root = Path(temp)
            self.fixture(root, {"version": 1, "product_version": "1.0.5"})
            with patch.object(bootstrap, "STATE", root), patch.object(bootstrap, "prepare") as prepare, \
                 patch.object(bootstrap.subprocess, "Popen") as child:
                with self.assertRaises(state.StateCompatibilityError):
                    bootstrap.serve()
            prepare.assert_not_called()
            child.assert_not_called()

    def test_cli_displays_static_compatibility_reason_for_role_command(self):
        import contextlib
        import sys
        from netops import cli
        errors = io.StringIO()
        with patch.object(sys, "argv", ["netops", "auditor", "status"]), \
             patch.object(operator, "role_cli", side_effect=state.StateCompatibilityError("Automatic downgrade refused")), \
             contextlib.redirect_stderr(errors):
            self.assertEqual(cli.main(), 2)
        self.assertIn("Automatic downgrade refused", errors.getvalue())

    def test_all_configure_paths_refuse_failed_gateway_audit_before_reading_inputs(self):
        from types import SimpleNamespace
        class NoRead:
            def read(self, size):
                raise AssertionError("Rejected configure must not read inputs")
        for role, audit_role in (("helper", "helper"), ("admin", "admin"), ("auditor", "auditor")):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as temp, \
                 patch.dict(UIDS, {"gateway": os.geteuid()}):
                root = Path(temp)
                self.fixture(root)
                with patch.object(operator, "STATE", root), patch.object(operator.os, "geteuid", return_value=0), \
                     patch.object(operator, "_operator_audit_preflight", side_effect=ValueError("Mandatory audit unavailable")) as audit, \
                     patch.object(operator.sys, "stdin", SimpleNamespace(buffer=NoRead())):
                    with self.assertRaisesRegex(ValueError, "Mandatory audit unavailable"):
                        operator.configure(role)
                audit.assert_called_once_with(audit_role, "configure")
                self.assertFalse(any(path.name in ("helper", "auditor", "admin") for path in root.iterdir()))

    def test_operator_audit_metadata_rejects_arbitrary_values_before_fork(self):
        with patch.object(operator.os, "fork") as fork:
            for role, action in (("CANARY_PRIVATE_VALUE", "configure"), ("auditor", "CANARY_PRIVATE_VALUE")):
                with self.assertRaisesRegex(ValueError, "Unsupported operator audit metadata"):
                    operator._operator_audit_preflight(role, action)
        fork.assert_not_called()

    def test_nonroot_operator_refusals_are_readable_without_input_values(self):
        import contextlib
        import sys
        from netops import cli
        for arguments in (["token", "show"], ["token", "rotate"], ["configure", "helper"],
                          ["configure", "admin"], ["configure", "auditor"], ["admin", "doctor"],
                          ["auditor", "import-snapshot", "--name", "CANARY_PRIVATE_VALUE"]):
            with self.subTest(arguments=arguments), patch.object(sys, "argv", ["netops", *arguments]), \
                 patch.object(operator.os, "geteuid", return_value=1000):
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    self.assertEqual(cli.main(), 2)
                self.assertIn("default container user", errors.getvalue())
                self.assertNotIn("CANARY_PRIVATE_VALUE", errors.getvalue())
