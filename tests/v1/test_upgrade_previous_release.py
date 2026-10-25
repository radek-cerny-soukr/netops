import asyncio
import contextlib
from datetime import datetime, timedelta, timezone
from contextlib import ExitStack
import fcntl
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from netops import bootstrap, certificates, cli, files, gateway, init, operator, state
from netops.files import UIDS, write_private


ORIGINAL_GATEWAY_SERVE = gateway.serve

PREVIOUS_STATE_HINT = 'State belongs to NetOps 1.0.1; start NetOps 1.0.2 to upgrade it before running this command. Do not reinitialize existing state'


class PreviousReleaseUpgrade(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.root = directory / "state"
        self.root.mkdir(mode=0o700)
        self.runtime = directory / "runtime"
        self.runtime.mkdir()
        self.path = self.root / "gateway/config.json"
        self.path.parent.mkdir(mode=0o700)
        self.stack.enter_context(patch.dict(UIDS, {"gateway": os.geteuid()}))
        self.stack.enter_context(patch.object(state, "__version__", "1.0.2"))
        self.stack.enter_context(patch.object(bootstrap, "__version__", "1.0.2", create=True))
        self.stack.enter_context(patch.object(gateway, "__version__", "1.0.2"))
        for module in (bootstrap, cli, init, operator, gateway):
            self.stack.enter_context(patch.object(module, "STATE", self.root))
        self.stack.enter_context(patch.object(bootstrap, "RUNTIME", self.runtime))
        self.stack.enter_context(patch.object(bootstrap, "stop_requested", return_value=False))
        self.prepare = self.stack.enter_context(patch.object(bootstrap, "prepare"))
        self.stack.enter_context(patch.object(bootstrap, "demote"))
        self.stack.enter_context(patch.object(bootstrap, "role_environment"))
        self.children = self.stack.enter_context(patch.object(bootstrap.subprocess, "Popen"))
        self.children.return_value.poll.return_value = None
        self.children.return_value.pid = 123456
        self.stack.enter_context(patch.object(bootstrap.os, "kill"))
        self.gateway_start = self.stack.enter_context(patch.object(gateway, "serve"))
        self.settings = {
            "version": 1, "product_version": "1.0.1",
            "server_name": "upgrade.example.invalid", "external_port": 8443,
            "admin_enabled": False,
            "audit": {"mode": "local", "budget_bytes": 16777216,
                      "segment_bytes": 4194304, "retention_seconds": 604800},
            "preserved_extension": {"values": [0, False, None, "synthetic-preserved"]},
        }
        self.store(self.settings)
        self.stack.enter_context(patch.dict(os.environ, {"NETOPS_SERVER_NAME": self.settings["server_name"]}))
        self.stack.enter_context(patch.object(certificates, "DIRECTORY", self.path.parent))
        certificates.create_ca(self.settings["server_name"])
        certificates.renew(self.settings["server_name"])
        for name in ("gateway/token",
                     "helper/inventory.json", "helper/vault.json",
                     "auditor/store.sqlite", "admin/operations.jsonl"):
            path = self.root / name
            path.parent.mkdir(mode=0o700, exist_ok=True)
            write_private(path, ("synthetic-existing-" + name + "\n").encode())

    def store(self, settings):
        write_private(self.path, (json.dumps(settings, indent=2) + "\n").encode(),
                      UIDS["gateway"], replace=self.path.exists())

    def snapshot(self):
        result = {}
        for path in self.root.rglob("*"):
            if path.is_file():
                info = path.stat()
                result[str(path.relative_to(self.root))] = (
                    path.read_bytes(), info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
        return result

    def start(self):
        opened = []
        original_open = os.open

        def tracked_open(path, *args, **kwargs):
            descriptor = original_open(path, *args, **kwargs)
            if Path(path) == self.path.parent / "instance.lock":
                opened.append(descriptor)
            return descriptor

        try:
            with patch.object(bootstrap.os, "open", side_effect=tracked_open):
                bootstrap.serve()
        finally:
            for descriptor in opened:
                with contextlib.suppress(OSError):
                    os.close(descriptor)

    def test_previous_release_changes_only_product_metadata_under_exclusive_lock(self):
        before = self.snapshot()
        original_replace = os.replace
        observed = []

        def replacing(source, target):
            if Path(target) == self.path:
                self.assertEqual(Path(source).parent, self.path.parent)
                self.assertEqual(stat.S_IMODE(Path(source).stat().st_mode), 0o600)
                descriptor = os.open(self.path.parent / "instance.lock", os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(descriptor)
                observed.append(json.loads(Path(source).read_bytes()))
            return original_replace(source, target)

        with patch.object(files.os, "replace", side_effect=replacing):
            self.start()
        expected = dict(self.settings, product_version="1.0.2")
        self.assertEqual(json.loads(self.path.read_bytes()), expected)
        self.assertEqual(observed, [expected])
        after = self.snapshot()
        self.assertEqual(after["gateway/config.json"][1:], before["gateway/config.json"][1:])
        for name, value in before.items():
            if name != "gateway/config.json":
                self.assertEqual(after[name], value, name)
        self.assertEqual(set(after) - set(before), {"gateway/instance.lock"})
        self.assertEqual(self.gateway_start.call_args.args[0], expected)
        self.assertEqual(self.gateway_start.call_args.kwargs, {"upgraded_from": "1.0.1"})

    def test_strict_reader_never_implicitly_converts_previous_state(self):
        before = self.snapshot()
        with self.assertRaises(state.StateCompatibilityError) as caught:
            state.read_state_settings(self.root)
        self.assertEqual(str(caught.exception), PREVIOUS_STATE_HINT)
        self.assertEqual(self.snapshot(), before)

    def test_only_exact_previous_software_schema_tuple_is_admitted(self):
        cases = [
            ("1.0.2", {"version": 1, "product_version": "1.0.3"}),
            ("1.0.2", {"version": 1, "product_version": "0.3.12"}),
            ("1.0.2", {"version": 1, "product_version": "SYNTHETIC_UNSUPPORTED"}),
            ("1.0.2", {"version": True, "product_version": "1.0.1"}),
            ("1.0.2", {"version": 2, "product_version": "1.0.1"}),
            ("1.0.2", {"version": 1}),
            ("1.0.3", {"version": 1, "product_version": "1.0.1"}),
            ("1.0.2", {"version": 1, "product_version": "1.0.0"}),
        ]
        for software, settings in cases:
            with self.subTest(software=software, settings=settings):
                self.store(settings)
                before = self.snapshot()
                self.prepare.reset_mock()
                with patch.object(state, "__version__", software), \
                     self.assertRaises(state.StateCompatibilityError):
                    self.start()
                self.assertEqual(self.snapshot(), before)
                self.prepare.assert_not_called()
        self.children.assert_not_called()
        self.gateway_start.assert_not_called()

    def test_same_version_start_is_byte_idempotent_and_has_no_upgrade_claim(self):
        self.store(dict(self.settings, product_version="1.0.2"))
        before = self.path.read_bytes()
        with patch.object(files.os, "replace", wraps=os.replace) as replacing:
            self.start()
            self.start()
        self.assertEqual(self.path.read_bytes(), before)
        replacing.assert_not_called()
        self.assertEqual(self.gateway_start.call_count, 2)
        for call in self.gateway_start.call_args_list:
            self.assertIsNone(call.kwargs.get("upgraded_from"))
            self.assertEqual(call.args[3:], ())

    def test_running_old_instance_refuses_start_by_lock_without_conversion(self):
        path = self.path.parent / "instance.lock"
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = self.snapshot()
            with self.assertRaisesRegex(ValueError, "existing instance"):
                self.start()
            self.assertEqual(self.snapshot(), before)
            self.children.assert_not_called()
        finally:
            os.close(descriptor)

    def test_start_rereads_state_after_lock_before_any_conversion(self):
        original_lock = fcntl.flock
        changed = dict(self.settings, product_version="1.0.3")
        touched = []

        def acquire(descriptor, operation):
            result = original_lock(descriptor, operation)
            if not touched:
                self.store(changed)
                touched.append(True)
            return result

        with patch.object(fcntl, "flock", side_effect=acquire), \
             self.assertRaises(state.StateCompatibilityError):
            self.start()
        self.assertEqual(touched, [True])
        self.assertEqual(json.loads(self.path.read_bytes()), changed)
        self.children.assert_not_called()
        self.gateway_start.assert_not_called()

    def test_failure_before_replace_keeps_complete_old_config(self):
        before = self.path.read_bytes()
        with patch.object(files.os, "replace", side_effect=OSError("synthetic-before-replace")), \
             self.assertRaisesRegex(OSError, "synthetic-before-replace"):
            self.start()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.path.parent.glob(".netops-*")), [])
        self.children.assert_not_called()
        self.gateway_start.assert_not_called()

    def test_file_fsync_failure_keeps_old_config_and_no_completed_start(self):
        original_sync = os.fsync
        failed = []

        def syncing(descriptor):
            if stat.S_ISREG(os.fstat(descriptor).st_mode) and not failed:
                failed.append(True)
                raise OSError("synthetic-file-fsync")
            return original_sync(descriptor)

        before = self.path.read_bytes()
        with patch.object(files.os, "fsync", side_effect=syncing), \
             self.assertRaisesRegex(OSError, "synthetic-file-fsync"):
            self.start()
        self.assertEqual(failed, [True])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.path.parent.glob(".netops-*")), [])
        self.gateway_start.assert_not_called()

    def test_post_replace_sync_failure_leaves_new_config_and_retry_does_not_reconvert(self):
        original_sync = files.sync_directory
        failed = []

        def syncing(path):
            if not failed:
                failed.append(True)
                raise OSError("synthetic-directory-fsync")
            return original_sync(path)

        with patch.object(files, "sync_directory", side_effect=syncing), \
             self.assertRaisesRegex(OSError, "synthetic-directory-fsync"):
            self.start()
        self.assertEqual(failed, [True])
        self.assertEqual(json.loads(self.path.read_bytes()),
                         dict(self.settings, product_version="1.0.2"))
        self.gateway_start.assert_not_called()
        committed = self.path.read_bytes()
        self.start()
        self.assertEqual(self.path.read_bytes(), committed)
        self.assertIsNone(self.gateway_start.call_args.kwargs.get("upgraded_from"))

    def test_operator_on_running_old_state_reports_lock_and_never_converts(self):
        path = self.path.parent / "instance.lock"
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = self.snapshot()
            with self.assertRaisesRegex(state.OperatorAccessError, "Stop the running instance"):
                operator.acquire_state()
            self.assertEqual(self.snapshot(), before)
        finally:
            os.close(descriptor)

    def test_operator_on_stopped_old_state_refuses_without_conversion(self):
        before = self.path.read_bytes()
        with self.assertRaises(state.StateCompatibilityError) as caught:
            operator.acquire_state()
        self.assertEqual(str(caught.exception), PREVIOUS_STATE_HINT)
        self.assertEqual(self.path.read_bytes(), before)

    def test_repeat_init_refuses_other_version_before_prepare_and_identity_changes(self):
        before = self.snapshot()
        args = SimpleNamespace(audit_budget=16777216, syslog_port=6514)
        with patch.dict(os.environ, {"NETOPS_BIND_IP": "127.0.0.1",
                                     "NETOPS_SERVER_NAME": self.settings["server_name"],
                                     "NETOPS_PORT": "8443"}), \
             patch.object(init.os, "geteuid", return_value=0), \
             patch.object(init, "prepare") as prepare, \
             patch.object(init, "connection") as connection, \
             contextlib.redirect_stdout(io.StringIO()) as out, \
             self.assertRaises(state.StateCompatibilityError) as caught:
            init.initialize(args)
        self.assertEqual(str(caught.exception), PREVIOUS_STATE_HINT)
        self.assertEqual(out.getvalue(), "")
        prepare.assert_not_called()
        connection.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_repeat_init_current_state_preserves_data(self):
        current = dict(self.settings, product_version="1.0.2")
        self.store(current)
        before = self.snapshot()
        args = SimpleNamespace(audit_budget=16777216, syslog_port=6514)
        with patch.dict(os.environ, {"NETOPS_BIND_IP": "127.0.0.1",
                                     "NETOPS_SERVER_NAME": self.settings["server_name"],
                                     "NETOPS_PORT": "8443"}), \
             patch.object(init.os, "geteuid", return_value=0), \
             patch.object(init, "prepare") as prepare, \
             patch.object(init, "connection") as connection, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            result = init.initialize(args)
        self.assertEqual(result, 0)
        self.assertEqual(out.getvalue(), "Already initialized; CA, token and data preserved.\n")
        prepare.assert_not_called()
        connection.assert_called_once_with(current)
        self.assertEqual(self.snapshot(), before)

    def test_token_rotation_refuses_old_state_without_changing_token(self):
        before = self.snapshot()
        errors = io.StringIO()
        with patch.object(sys, "argv", ["netops", "token", "rotate"]), \
             patch.object(cli.os, "geteuid", return_value=0), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
            self.assertEqual(cli.main(), 2)
        self.assertEqual(self.snapshot(), before)
        self.assertIn(PREVIOUS_STATE_HINT, errors.getvalue())

    def test_token_rotation_on_current_state_remains_online(self):
        self.store(dict(self.settings, product_version="1.0.2"))
        path = self.path.parent / "instance.lock"
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        original = (self.path.parent / "token").read_bytes()
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(sys, "argv", ["netops", "token", "rotate"]), \
                 patch.object(cli.os, "geteuid", return_value=0), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(), 0)
            self.assertNotEqual((self.path.parent / "token").read_bytes(), original)
        finally:
            os.close(descriptor)

    def test_upgrade_audit_is_durable_after_metadata_commit(self):
        from starlette.applications import Starlette

        observed = []
        original_record = gateway.Audit.record

        async def recording(audit, direction, payload, *args, **kwargs):
            result = await original_record(audit, direction, payload, *args, **kwargs)
            if direction == "instance_start":
                observed.append(("durable-start", self.path.read_bytes()))
            return result

        async def record_lifecycle(settings, roles, children, upgraded_from=None):
            inner = Starlette()
            with patch.object(gateway.FastMCP, "http_app", return_value=inner), \
                 patch.object(gateway, "startup_rpc", new=AsyncMock(return_value={"tools": []})), \
                 patch.object(gateway.Audit, "record", new=recording):
                await gateway.application(settings, roles, children, upgraded_from=upgraded_from)
                async with inner.router.lifespan_context(inner):
                    observed.append(("entered", None))

        self.gateway_start.side_effect = lambda *args, **kw: asyncio.run(record_lifecycle(*args, **kw))
        self.start()
        self.assertEqual(self.gateway_start.call_count, 1)
        self.assertEqual([event for event, _ in observed], ["durable-start", "entered"])
        self.assertEqual(json.loads(observed[0][1])["product_version"], "1.0.2")
        records = [json.loads(line) for path in (self.path.parent / "audit").glob("*.jsonl")
                   for line in path.read_text().splitlines()]
        starts = [record for record in records if record["direction"] == "instance_start"]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0]["payload"]["version"], "1.0.2")
        self.assertEqual(starts[0]["payload"]["upgrade"], {"from": "1.0.1", "to": "1.0.2"})

    def test_failed_audit_start_never_enters_lifespan(self):
        from starlette.applications import Starlette

        entered = []
        original_record = gateway.Audit.record

        async def failing_start(audit, direction, payload, *args, **kwargs):
            if direction == "instance_start":
                raise OSError("synthetic-audit-start")
            return await original_record(audit, direction, payload, *args, **kwargs)

        async def scenario():
            inner = Starlette()
            with patch.object(gateway.FastMCP, "http_app", return_value=inner):
                await gateway.application(dict(self.settings, product_version="1.0.2"),
                                          [], [], upgraded_from="1.0.1")
                with patch.object(gateway.Audit, "record", new=failing_start):
                    async with inner.router.lifespan_context(inner):
                        entered.append(True)

        with self.assertRaisesRegex(OSError, "synthetic-audit-start"):
            asyncio.run(scenario())
        self.assertEqual(entered, [])

    def assert_process_exit_at_writer_boundary(self, point):
        before = self.path.read_bytes()
        expected = json.dumps(dict(self.settings, product_version="1.0.2")).encode()
        original_temp = files.tempfile.mkstemp
        original_write = files.os.write
        original_sync = files.os.fsync
        child = os.fork()
        if child == 0:
            try:
                with ExitStack() as hooks:
                    if point == "created":
                        def created(*args, **kwargs):
                            result = original_temp(*args, **kwargs)
                            os._exit(73)
                        hooks.enter_context(patch.object(files.tempfile, "mkstemp", side_effect=created))
                    elif point == "partial":
                        def writing(descriptor, data):
                            original_write(descriptor, data[:max(1, len(data) // 2)])
                            os._exit(73)
                        hooks.enter_context(patch.object(files.os, "write", side_effect=writing))
                    elif point == "synced":
                        def syncing(descriptor):
                            result = original_sync(descriptor)
                            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                                os._exit(73)
                            return result
                        hooks.enter_context(patch.object(files.os, "fsync", side_effect=syncing))
                    else:
                        os._exit(77)
                    self.start()
            except state.StateCompatibilityError:
                os._exit(74)
            except BaseException:
                os._exit(75)
            os._exit(76)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 73,
                         "74 means admission blocked the writer; 75 unexpected child error; 76 missed hook")
        self.assertEqual(self.path.read_bytes(), before)
        orphans = list(self.path.parent.glob(".netops-*"))
        self.assertEqual(len(orphans), 1)
        orphan = orphans[0]
        info = orphan.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink),
                         (os.geteuid(), os.getegid(), 0o600, 1))
        payload = orphan.read_bytes()
        self.assertTrue(expected.startswith(payload))
        if point == "created":
            self.assertEqual(payload, b"")
        elif point == "partial":
            self.assertTrue(0 < len(payload) < len(expected))
        else:
            self.assertEqual(payload, expected)
        custody = (payload, info.st_uid, info.st_gid, info.st_mode, info.st_ino)
        self.start()
        self.assertEqual(json.loads(self.path.read_bytes()),
                         dict(self.settings, product_version="1.0.2"))
        after = orphan.lstat()
        self.assertEqual((orphan.read_bytes(), after.st_uid, after.st_gid, after.st_mode, after.st_ino),
                         custody)
        self.assertEqual(list(self.path.parent.glob(".netops-*")), [orphan])

    def test_process_exit_after_temp_creation_retains_private_empty_orphan(self):
        self.assert_process_exit_at_writer_boundary("created")

    def test_process_exit_after_partial_write_retains_private_prefix_orphan(self):
        self.assert_process_exit_at_writer_boundary("partial")

    def test_process_exit_after_file_fsync_retains_complete_uncommitted_orphan(self):
        self.assert_process_exit_at_writer_boundary("synced")

    def admission_cases(self):
        product = "State belongs to another product version; automatic upgrade or downgrade is refused. Use the verified release procedure"
        schema = "Unsupported state schema; use the matching NetOps release and its verified recovery procedure"
        unreadable = "Initialized private state cannot be read safely; initialize a new instance or use the matching release to inspect existing state"
        cases = [(name, dict(self.settings, product_version=value), product) for name, value in (
            ("T03", "1.0.3"), ("T03-canary", "1.0.3-SYNTHETIC_ADMISSION_CANARY"),
            ("T04", "1.1.0"), ("T05", "0.3.12"), ("T06", "1.0"),
            ("T07", "1.0.1 "), ("T08", "v1.0.1"), ("T10", None), ("T11", 100))]
        cases.append(("T09", {key: value for key, value in self.settings.items()
                              if key != "product_version"}, product))
        cases.extend((name, dict(self.settings, version=value), schema) for name, value in (
            ("T12", True), ("T13", 1.0), ("T14", "1"), ("T15", 2)))
        cases.append(("T16", {key: value for key, value in self.settings.items()
                              if key != "version"}, schema))
        cases.extend((
            ("T17", b'{"version":1,"product_version":"1.0.2","product_version":"1.0.1"}', unreadable),
            ("T18", b'{"version":1,"product_version":"1.0.1","value":NaN}', unreadable),
            ("T19", b"{", unreadable), ("T20", "mode0644", unreadable),
            ("T22", "symlink", unreadable)))
        return cases

    def put_admission_case(self, value):
        if self.path.is_symlink() or self.path.exists():
            self.path.unlink()
        if value == "mode0644":
            self.store(dict(self.settings))
            self.path.chmod(0o644)
        elif value == "symlink":
            target = self.root / "outside.json"
            if target.exists():
                target.unlink()
            write_private(target, json.dumps(self.settings).encode())
            self.path.symlink_to(target)
        elif isinstance(value, bytes):
            write_private(self.path, value)
        else:
            self.store(value)

    def test_serve_rejects_full_admission_matrix_before_prepare(self):
        for name, value, expected in self.admission_cases():
            with self.subTest(state=name):
                self.put_admission_case(value)
                before = self.snapshot()
                self.prepare.reset_mock()
                with contextlib.redirect_stdout(io.StringIO()) as out, \
                     contextlib.redirect_stderr(io.StringIO()) as err, \
                     self.assertRaises(state.StateCompatibilityError) as caught:
                    self.start()
                self.assertEqual(str(caught.exception), expected)
                self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
                self.prepare.assert_not_called()
                self.assertEqual(self.snapshot(), before)
        self.children.assert_not_called()
        self.gateway_start.assert_not_called()

    def test_operator_rejects_full_admission_matrix_before_lock(self):
        for name, value, expected in self.admission_cases():
            with self.subTest(state=name):
                self.put_admission_case(value)
                before = self.snapshot()
                descriptor = None
                try:
                    with self.assertRaises(state.StateCompatibilityError) as caught:
                        descriptor = operator.acquire_state()
                    self.assertEqual(str(caught.exception), expected)
                    self.assertEqual(self.snapshot(), before)
                    self.assertFalse((self.path.parent / "instance.lock").exists())
                finally:
                    if descriptor is not None:
                        os.close(descriptor)

    def test_init_rejects_full_admission_matrix_as_root_without_writes(self):
        args = SimpleNamespace(audit_budget=16777216, syslog_port=6514)
        for name, value, expected in self.admission_cases():
            with self.subTest(state=name):
                self.put_admission_case(value)
                before = self.snapshot()
                with patch.dict(os.environ, {"NETOPS_BIND_IP": "127.0.0.1",
                                             "NETOPS_SERVER_NAME": self.settings["server_name"],
                                             "NETOPS_PORT": "8443"}), \
                     patch.object(init.os, "geteuid", return_value=0), \
                     patch.object(init, "prepare") as prepare, \
                     patch.object(init, "connection") as connection, \
                     contextlib.redirect_stdout(io.StringIO()) as out, \
                     self.assertRaises(state.StateCompatibilityError) as caught:
                    init.initialize(args)
                self.assertEqual(str(caught.exception), expected)
                self.assertEqual(out.getvalue(), "")
                prepare.assert_not_called()
                connection.assert_not_called()
                self.assertEqual(self.snapshot(), before)

    def test_token_rotation_rejects_full_admission_matrix(self):
        for name, value, expected in self.admission_cases():
            with self.subTest(state=name):
                self.put_admission_case(value)
                before = self.snapshot()
                out, err = io.StringIO(), io.StringIO()
                with patch.object(sys, "argv", ["netops", "token", "rotate"]), \
                     patch.object(cli.os, "geteuid", return_value=0), \
                     contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    result = cli.main()
                self.assertEqual(result, 2)
                self.assertIn(expected, err.getvalue())
                self.assertEqual(out.getvalue(), "")
                self.assertNotIn("SYNTHETIC_ADMISSION_CANARY", err.getvalue())
                self.assertEqual(self.snapshot(), before)

    def after_exclusive_lock(self, change):
        original = fcntl.flock
        touched = []

        def acquire(descriptor, operation):
            result = original(descriptor, operation)
            if operation == fcntl.LOCK_EX | fcntl.LOCK_NB and not touched:
                touched.append(True)
                change()
            return result

        return patch.object(fcntl, "flock", side_effect=acquire), touched

    def test_operator_rereads_after_lock_and_refuses_changed_state(self):
        unreadable = "Initialized private state cannot be read safely; initialize a new instance or use the matching release to inspect existing state"
        product = "State belongs to another product version; automatic upgrade or downgrade is refused. Use the verified release procedure"
        for value, expected in ((dict(self.settings), PREVIOUS_STATE_HINT),
                                (dict(self.settings, product_version="1.0.3"), product),
                                (b"{", unreadable)):
            with self.subTest(after_lock=value):
                self.store(dict(self.settings, product_version="1.0.2"))
                sampled = []

                def change():
                    self.put_admission_case(value)
                    sampled.append(self.path.read_bytes())

                hook, touched = self.after_exclusive_lock(change)
                descriptor = None
                try:
                    with hook, self.assertRaises(state.StateCompatibilityError) as caught:
                        descriptor = operator.acquire_state()
                    self.assertEqual(str(caught.exception), expected)
                    self.assertEqual(touched, [True])
                    self.assertEqual(self.path.read_bytes(), sampled[0])
                finally:
                    if descriptor is not None:
                        os.close(descriptor)

    def test_prelock_previous_postlock_current_does_not_convert(self):
        sampled = []

        def change():
            self.store(dict(self.settings, product_version="1.0.2"))
            sampled.append((self.path.stat().st_ino, self.path.read_bytes()))

        hook, touched = self.after_exclusive_lock(change)
        with hook:
            self.start()
        self.assertEqual(touched, [True])
        self.assertEqual((self.path.stat().st_ino, self.path.read_bytes()), sampled[0])
        self.assertEqual(self.gateway_start.call_count, 1)
        self.assertIsNone(self.gateway_start.call_args.kwargs.get("upgraded_from"))
        self.assertEqual(self.gateway_start.call_args.args[3:], ())

    def test_prelock_current_postlock_previous_converts(self):
        self.store(dict(self.settings, product_version="1.0.2"))
        hook, touched = self.after_exclusive_lock(lambda: self.store(dict(self.settings)))
        with hook:
            self.start()
        self.assertEqual(touched, [True])
        self.assertEqual(json.loads(self.path.read_bytes()),
                         dict(self.settings, product_version="1.0.2"))
        self.assertEqual(self.gateway_start.call_count, 1)
        self.assertEqual(self.gateway_start.call_args.kwargs, {"upgraded_from": "1.0.1"})

    def test_postlock_unreadable_and_symlink_are_not_read_unsafe(self):
        unreadable = "Initialized private state cannot be read safely; initialize a new instance or use the matching release to inspect existing state"
        for value in (b"{", "symlink"):
            with self.subTest(after_lock=value):
                self.put_admission_case(dict(self.settings))
                hook, touched = self.after_exclusive_lock(lambda: self.put_admission_case(value))
                with hook, self.assertRaises(state.StateCompatibilityError) as caught:
                    self.start()
                self.assertEqual(str(caught.exception), unreadable)
                self.assertEqual(touched, [True])
                self.gateway_start.assert_not_called()
                if value == "symlink":
                    self.assertTrue(self.path.is_symlink())
                    self.assertEqual(json.loads((self.root / "outside.json").read_bytes()), self.settings)
                else:
                    self.assertEqual(self.path.read_bytes(), b"{")

    def test_conversion_preserves_serialized_types_and_key_order(self):
        old = json.dumps(self.settings).encode()
        write_private(self.path, old, replace=True)
        self.start()
        expected = json.dumps(dict(self.settings, product_version="1.0.2")).encode()
        self.assertEqual(self.path.read_bytes(), expected)

    def test_conversion_uses_gateway_owner_and_single_replace(self):
        original_chown = os.fchown
        original_replace = os.replace
        ownership = []
        replacements = []

        def changing_owner(descriptor, uid, gid):
            path = Path(os.readlink("/proc/self/fd/" + str(descriptor)))
            result = original_chown(descriptor, uid, gid)
            if path.parent == self.path.parent and path.name.startswith(".netops-"):
                info = os.fstat(descriptor)
                ownership.append((uid, gid, info.st_dev, info.st_ino))
            return result

        def replacing(source, target):
            if Path(target) == self.path:
                source = Path(source)
                info = source.stat()
                replacements.append((source.parent, source.name, info.st_dev, info.st_ino))
            return original_replace(source, target)

        with patch.object(files.os, "fchown", side_effect=changing_owner), \
             patch.object(files.os, "replace", side_effect=replacing):
            self.start()
        self.assertEqual(len(ownership), 1)
        self.assertEqual(ownership[0][:2], (os.geteuid(), os.geteuid()))
        self.assertEqual(len(replacements), 1)
        self.assertEqual(replacements[0][0], self.path.parent)
        self.assertTrue(replacements[0][1].startswith(".netops-"))
        self.assertEqual(ownership[0][2:], replacements[0][2:])
        info = self.path.stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                         (os.geteuid(), os.geteuid(), 0o600))

    def test_later_gateway_start_has_no_upgrade_field(self):
        self.store(dict(self.settings, product_version="1.0.2"))
        from starlette.applications import Starlette

        async def one(previous):
            inner = Starlette()
            with patch.object(gateway.FastMCP, "http_app", return_value=inner):
                await gateway.application(dict(self.settings, product_version="1.0.2"),
                                          [], [], upgraded_from=previous)
                async with inner.router.lifespan_context(inner):
                    pass

        async def scenario():
            await one("1.0.1")
            await one(None)

        asyncio.run(scenario())
        records = [json.loads(line) for path in (self.path.parent / "audit").glob("*.jsonl")
                   for line in path.read_text().splitlines()]
        starts = [record["payload"] for record in records if record["direction"] == "instance_start"]
        self.assertEqual(len(starts), 2)
        self.assertEqual(starts[0].get("upgrade"), {"from": "1.0.1", "to": "1.0.2"})
        self.assertNotIn("upgrade", starts[1])

    def test_read_only_previous_state_matches_nonempty_exact_controls(self):
        audit = gateway.Audit(self.path.parent / "audit", self.settings["audit"])
        asyncio.run(audit.record("synthetic_control", {"marker": "read-only-control"},
                                 "synthetic-read-only-correlation"))
        records = [json.loads(line) for line in audit.current.read_text().splitlines()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["payload"], {"marker": "read-only-control"})
        expected_export = "".join(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n"
                                  for record in records)
        expected = ((self.path.parent / "ca.pem").read_text(),
                    (self.path.parent / "token").read_text(), expected_export)
        commands = (["netops", "ca"], ["netops", "token", "show"],
                    ["netops", "audit", "export"])

        def check():
            before = self.snapshot()
            for argv, wanted in zip(commands, expected):
                out, err = io.StringIO(), io.StringIO()
                with patch.object(sys, "argv", argv), patch.object(cli.os, "geteuid", return_value=0), \
                     contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    result = cli.main()
                self.assertEqual(result, 0)
                self.assertNotEqual(wanted, "")
                self.assertEqual(out.getvalue(), wanted)
            self.assertEqual(self.snapshot(), before)

        check()
        self.store(dict(self.settings, product_version="1.0.2"))
        check()

    def test_init_nonroot_refuses_previous_and_current_without_prepare(self):
        args = SimpleNamespace(audit_budget=16777216, syslog_port=6514)
        message = "Initialization and the short start bootstrap require the declared container user and capabilities"
        for version in ("1.0.1", "1.0.2"):
            for uid in (1000, 51000, 51001, 51002, 51003):
                with self.subTest(version=version, uid=uid):
                    self.store(dict(self.settings, product_version=version))
                    before = self.snapshot()
                    with patch.dict(os.environ, {"NETOPS_BIND_IP": "127.0.0.1",
                                                 "NETOPS_SERVER_NAME": self.settings["server_name"],
                                                 "NETOPS_PORT": "8443"}), \
                         patch.object(init.os, "geteuid", return_value=uid), \
                         patch.object(init, "prepare") as prepare, \
                         patch.object(init, "connection") as connection, \
                         contextlib.redirect_stdout(io.StringIO()) as out, \
                         self.assertRaises(ValueError) as caught:
                        init.initialize(args)
                    self.assertEqual(str(caught.exception), message)
                    self.assertEqual(out.getvalue(), "")
                    prepare.assert_not_called()
                    connection.assert_not_called()
                    self.assertEqual(self.snapshot(), before)

    def test_postlock_current_symlink_is_refused_before_dispatch(self):
        current = dict(self.settings, product_version="1.0.2")
        self.store(current)
        target = self.root / "outside-current.json"
        write_private(target, json.dumps(current).encode(), UIDS["gateway"])

        def snapshot_target():
            info = target.lstat()
            return (target.read_bytes(), info.st_uid, info.st_gid,
                    stat.S_IMODE(info.st_mode), info.st_ino, info.st_nlink)

        before = snapshot_target()
        links = []

        def change():
            self.path.unlink()
            self.path.symlink_to(target)
            links.append(self.path.lstat().st_ino)

        hook, touched = self.after_exclusive_lock(change)
        with hook, self.assertRaises(state.StateCompatibilityError) as caught:
            self.start()
        self.assertEqual(str(caught.exception),
                         "Initialized private state cannot be read safely; initialize a new instance or use the matching release to inspect existing state")
        self.assertEqual(touched, [True])
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(self.path.lstat().st_ino, links[0])
        self.assertEqual(os.readlink(self.path), str(target))
        self.assertEqual(snapshot_target(), before)
        self.children.assert_not_called()
        self.gateway_start.assert_not_called()

    def test_incomplete_local_audit_refused_before_conversion(self):
        directory = self.path.parent / "audit"
        directory.mkdir(mode=0o700)
        write_private(directory / "current.jsonl", b'{"direction":"synthetic"')
        before = self.path.read_bytes()
        self.gateway_start.side_effect = ORIGINAL_GATEWAY_SERVE
        with self.assertRaisesRegex(ValueError, "Incomplete final audit record"):
            self.start()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.path.parent.glob(".netops-*")))
        self.children.assert_not_called()

    def test_changed_identity_refused_before_conversion(self):
        before = self.path.read_bytes()
        self.gateway_start.side_effect = ORIGINAL_GATEWAY_SERVE
        with patch.dict(os.environ, {"NETOPS_SERVER_NAME": "other.example.invalid"}), \
             self.assertRaisesRegex(ValueError, "NETOPS_SERVER_NAME is"):
            self.start()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.path.parent.glob(".netops-*")))
        self.children.assert_not_called()

    def test_inconsistent_certificate_pair_refused_before_conversion(self):
        write_private(self.path.parent / "server.key", b"synthetic-invalid-key", UIDS["gateway"], replace=True)
        before = self.path.read_bytes()
        self.gateway_start.side_effect = ORIGINAL_GATEWAY_SERVE
        with self.assertRaisesRegex(ValueError, "certificate files are missing or do not match"):
            self.start()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.path.parent.glob(".netops-*")))
        self.children.assert_not_called()

    def renewal_views(self, leaf_days, ca_days):
        now = datetime.now(timezone.utc)
        leaf = (self.path.parent / "server.pem").read_bytes()
        ca = (self.path.parent / "ca.pem").read_bytes()
        def view(payload):
            if payload == leaf:
                return SimpleNamespace(not_valid_after_utc=now + timedelta(days=leaf_days))
            if payload == ca:
                return SimpleNamespace(not_valid_after_utc=now + timedelta(days=ca_days))
            raise AssertionError("Unexpected synthetic certificate input")
        return view, now

    def test_unrenewable_leaf_refused_before_conversion(self):
        before = self.path.read_bytes()
        self.gateway_start.side_effect = ORIGINAL_GATEWAY_SERVE
        view, now = self.renewal_views(2, 7)
        with patch.object(certificates, "datetime") as clock, patch.object(certificates.x509, "load_pem_x509_certificate", side_effect=view), \
             patch.object(certificates, "verify_pairs"):
            clock.now.return_value = now
            with self.assertRaisesRegex(ValueError, "expires within 7 days"):
                self.start()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.path.parent.glob(".netops-*")))
        self.children.assert_not_called()

    def test_fresh_leaf_does_not_require_renewal_from_near_expiry_ca(self):
        view, now = self.renewal_views(2.5, 6)
        with patch.object(certificates, "datetime") as clock, patch.object(certificates.x509, "load_pem_x509_certificate", side_effect=view), \
             patch.object(certificates, "verify_pairs"):
            clock.now.return_value = now
            try:
                self.start()
            except ValueError as exc:
                self.fail("Valid fresh leaf refused: " + type(exc).__name__)
        self.assertEqual(json.loads(self.path.read_bytes())["product_version"], "1.0.2")
        self.gateway_start.assert_called_once()

    def test_missing_unreadable_and_malformed_leaf_refused_before_conversion(self):
        leaf = self.path.parent / "server.pem"
        saved = leaf.read_bytes()
        self.gateway_start.side_effect = ORIGINAL_GATEWAY_SERVE
        for fault in ("missing", "unreadable", "malformed"):
            with self.subTest(fault=fault):
                self.store(self.settings)
                before = self.path.read_bytes()
                try:
                    if fault == "missing":
                        leaf.unlink()
                    elif fault == "unreadable":
                        leaf.chmod(0)
                    else:
                        write_private(leaf, b"synthetic-invalid-certificate", UIDS["gateway"], replace=True)
                    with self.assertRaisesRegex(ValueError, "certificate files are missing or do not match"):
                        self.start()
                    self.assertEqual(self.path.read_bytes(), before)
                    self.children.assert_not_called()
                finally:
                    if leaf.exists():
                        leaf.chmod(0o600)
                    write_private(leaf, saved, UIDS["gateway"], replace=leaf.exists())
