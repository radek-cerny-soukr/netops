import asyncio
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from netops import files, worker
from netops.files import UIDS, write_private
import test_upgrade_previous_release as previous


GUARDED_ROOTS = ("netops_auditor", "netops_admin", "netops_helper", "fastmcp")
ADMIN_INIT = {"version": 1, "state_dir": "/synthetic/admin/changes", "audit_file": "/synthetic/admin/operations.jsonl", "devices": {}}


class WorkerStarted(Exception):
    pass


class RoleConfigAdmission(unittest.TestCase):
    store = previous.PreviousReleaseUpgrade.store
    start = previous.PreviousReleaseUpgrade.start

    def setUp(self):
        previous.PreviousReleaseUpgrade.setUp(self)
        write_private(self.path.parent / "instance.lock", b"", UIDS["gateway"])
        self.auditor = self.root / "auditor" / "config.json"
        self.admin = self.root / "admin" / "config.json"
        self.own = os.geteuid()

    def snapshot(self):
        result = {}
        for path in self.root.rglob("*"):
            if path.is_file():
                info = path.stat()
                try:
                    data = path.read_bytes()
                except PermissionError:
                    data = None
                result[str(path.relative_to(self.root))] = (data, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
        return result

    def roles_owned_by_caller(self):
        return patch.dict(UIDS, {"auditor": self.own, "admin": self.own})

    def put(self, path, data, mode=None):
        if path.is_symlink() or path.exists():
            path.unlink()
        if data is not None:
            write_private(path, data if isinstance(data, bytes) else json.dumps(data).encode())
            if mode is not None:
                os.chmod(path, mode)

    def dangle(self, path):
        self.put(path, None)
        path.symlink_to(path.parent / "missing-role-config-target")

    def upgrade(self, admin_enabled=False, product_version="1.0.1"):
        self.store(dict(self.settings, admin_enabled=admin_enabled, product_version=product_version))
        self.children.reset_mock()
        self.gateway_start.reset_mock()

    def refuses(self, expected, message=None):
        before = self.snapshot()
        caught = None
        with patch.object(files, "write_private", wraps=files.write_private) as writing, \
             patch.object(Path, "mkdir", autospec=True) as creating:
            try:
                self.start()
            except Exception as exc:
                caught = exc
        writing.assert_not_called()
        creating.assert_not_called()
        self.assertIsInstance(caught, expected, "role config refusal did not happen before the upgrade commit")
        if message is not None:
            self.assertEqual(str(caught), message)
        self.assertEqual(self.snapshot(), before, "refused upgrade changed existing state")
        self.children.assert_not_called()
        self.gateway_start.assert_not_called()

    def admits(self, description):
        before = self.snapshot()
        guarded = {name: None for name in list(sys.modules) if name.split(".")[0] in GUARDED_ROOTS}
        guarded.update({name: None for name in GUARDED_ROOTS + ("netops.worker",)})
        with patch.dict(sys.modules, guarded):
            try:
                self.start()
            except (ValueError, OSError, TypeError, KeyError, AttributeError, ImportError) as exc:
                self.fail(description + " was refused: " + type(exc).__name__ + ": " + str(exc))
        after = self.snapshot()
        self.assertEqual(set(after), set(before))
        for name in before:
            if name != "gateway/config.json":
                self.assertEqual(after[name], before[name], name)
        self.assertEqual(json.loads(self.path.read_bytes())["product_version"], "1.0.2")
        self.gateway_start.assert_called_once()

    def test_upgrade_refuses_corrupt_auditor_config_before_commit(self):
        unreadable = ValueError if self.own == 0 else PermissionError
        cases = [("json", b'{"tenant":', None, json.JSONDecodeError, None),
                 ("array", [], None, TypeError, None),
                 ("missing-catalog", {"tenant": "default"}, None, KeyError, None),
                 ("tenant-number", {"tenant": 5, "catalog": "fortios"}, None, TypeError, None),
                 ("catalog-null", {"tenant": "default", "catalog": None}, None, TypeError, None),
                 ("group-readable", {"tenant": "default", "catalog": "fortios"}, 0o640, ValueError, "Private file permissions are required"),
                 ("owner-unreadable", {"tenant": "default", "catalog": "fortios"}, 0o200, unreadable, None),
                 ("dangling-symlink", None, None, OSError, None)]
        with self.roles_owned_by_caller():
            for name, data, mode, expected, message in cases:
                with self.subTest(case=name):
                    self.upgrade()
                    if name == "dangling-symlink":
                        self.dangle(self.auditor)
                    else:
                        self.put(self.auditor, data, mode)
                    try:
                        self.refuses(expected, message)
                    finally:
                        if self.auditor.exists():
                            os.chmod(self.auditor, 0o600)
                    if name == "dangling-symlink":
                        self.assertTrue(self.auditor.is_symlink())

    def test_upgrade_refuses_auditor_config_of_another_owner(self):
        self.assertNotEqual(UIDS["auditor"], self.own)
        self.upgrade()
        self.put(self.auditor, {"tenant": "default", "catalog": "fortios"})
        self.refuses(ValueError, "Unexpected file owner")

    def test_upgrade_with_enabled_admin_refuses_missing_or_corrupt_config(self):
        cases = [("missing", None, None, FileNotFoundError, None, True),
                 ("json", b'{"devices":', None, json.JSONDecodeError, None, True),
                 ("array", [], None, AttributeError, None, True),
                 ("group-readable", ADMIN_INIT, 0o640, ValueError, "Private file permissions are required", True),
                 ("other-owner", ADMIN_INIT, None, ValueError, "Unexpected file owner", False)]
        for name, data, mode, expected, message, owned in cases:
            with self.subTest(case=name), patch.dict(UIDS, {"admin": self.own} if owned else {}):
                self.upgrade(admin_enabled=True)
                self.put(self.auditor, None)
                self.put(self.admin, data, mode)
                self.refuses(expected, message)

    def test_upgrade_admits_absent_or_valid_role_configs(self):
        cases = [("auditor-absent", None, False, None),
                 ("auditor-init", {"tenant": "default", "catalog": "fortios"}, False, None),
                 ("auditor-custom-extra", {"tenant": "tenant-a", "catalog": "exos", "note": "kept"}, False, None),
                 ("admin-enabled-init", {"tenant": "default", "catalog": "fortios"}, True, ADMIN_INIT)]
        with self.roles_owned_by_caller():
            for name, auditor, admin_enabled, admin in cases:
                with self.subTest(case=name):
                    self.upgrade(admin_enabled=admin_enabled)
                    self.put(self.auditor, auditor)
                    self.put(self.admin, admin)
                    self.admits("Valid or absent role config " + name)

    def test_upgrade_does_not_judge_disabled_admin_or_lazy_role_files(self):
        cases = [("admin-disabled-json", b'{"devices":', None),
                 ("admin-disabled-missing", None, None),
                 ("helper-lazy-files", ADMIN_INIT, b'{"devices":')]
        with self.roles_owned_by_caller():
            for name, admin, helper in cases:
                with self.subTest(case=name):
                    self.upgrade(admin_enabled=False)
                    self.put(self.auditor, None)
                    self.put(self.admin, admin)
                    if helper is not None:
                        for item in ("inventory.json", "vault.json"):
                            self.put(self.root / "helper" / item, helper)
                    self.admits("Disabled admin or lazy helper file " + name)

    def test_upgrade_leaves_role_values_and_admin_schema_to_the_worker(self):
        cases = [("auditor-unknown-catalog", {"tenant": "default", "catalog": "synthetic-unknown-platform"}, False, None),
                 ("admin-devices-schema", None, True, {"devices": {"synthetic-device": {}}})]
        with self.roles_owned_by_caller():
            for name, auditor, admin_enabled, admin in cases:
                with self.subTest(case=name):
                    self.upgrade(admin_enabled=admin_enabled)
                    self.put(self.auditor, auditor)
                    self.put(self.admin, admin)
                    self.admits("Out of scope role value " + name)

    def test_current_start_keeps_role_config_refusal_in_the_worker(self):
        with self.roles_owned_by_caller():
            self.upgrade(product_version="1.0.2")
            self.put(self.auditor, b'{"tenant":')
            try:
                self.start()
            except (ValueError, OSError, TypeError, KeyError, AttributeError) as exc:
                self.fail("current start judged role config in bootstrap: " + type(exc).__name__ + ": " + str(exc))
        self.assertEqual(self.children.call_count, 2)
        self.gateway_start.assert_called_once()

    def run_worker(self):
        module = SimpleNamespace(configure=lambda **options: None)
        with patch.object(worker.os, "geteuid", return_value=UIDS["auditor"]), \
             patch.object(worker.os, "getegid", return_value=UIDS["auditor"]), \
             patch.object(worker, "role_environment", return_value=self.auditor.parent), \
             patch.object(worker, "importlib", SimpleNamespace(import_module=lambda name: module)), \
             patch.object(worker.asyncio, "start_unix_server", side_effect=WorkerStarted), \
             patch.dict(os.environ, {}):
            try:
                asyncio.run(worker.run("auditor"))
            except WorkerStarted:
                return (os.environ.get("NETOPS_AUDITOR_TENANT"), os.environ.get("NETOPS_AUDITOR_CATALOG"))
            except Exception as exc:
                return exc
        return None

    def test_worker_shares_auditor_absence_and_shape_predicate(self):
        cases = [("absent", None, ("default", "fortios")),
                 ("custom", {"tenant": "tenant-a", "catalog": "exos"}, ("tenant-a", "exos")),
                 ("dangling-symlink", None, OSError),
                 ("tenant-number", {"tenant": 5, "catalog": "fortios"}, TypeError)]
        with self.roles_owned_by_caller():
            for name, data, expected in cases:
                with self.subTest(case=name):
                    if name == "dangling-symlink":
                        self.dangle(self.auditor)
                    else:
                        self.put(self.auditor, data)
                    outcome = self.run_worker()
                    if isinstance(expected, tuple):
                        self.assertEqual(outcome, expected, "worker auditor environment differs")
                    else:
                        self.assertIsInstance(outcome, expected, "worker treated a non-ENOENT auditor config error as absence or accepted a non-text value")
