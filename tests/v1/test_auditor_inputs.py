import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from netops import auditor_inputs
from netops.files import UIDS

CANARY = "SYNTHETIC_SECRET_MUST_NOT_BE_PRINTED"


class AuditorImports(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identities = patch.dict(UIDS, {"auditor": os.geteuid()})
        self.identities.start()
        self.addCleanup(self.identities.stop)
        self.addCleanup(self.temporary.cleanup)

    def invoke(self, kind, data=b"", name="example", options=()):
        output, errors = io.StringIO(), io.StringIO()
        args = [kind, "--name", name, *options]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = auditor_inputs.main(self.root, args, io.BytesIO(data))
        self.assertNotIn(CANARY, output.getvalue() + errors.getvalue())
        return code, output.getvalue(), errors.getvalue()

    def policy(self, platform="fortios"):
        return json.dumps({"version": 1, "platform": platform,
                           "required_rules": ["address-policy"], "address_networks": ["192.0.2.0/24"]}).encode()

    def assert_clean_staging(self):
        self.assertEqual(list(self.root.rglob(".import-*")), [])

    def test_snapshot_is_byte_exact_private_and_persistent(self):
        data = b"# synthetic snapshot\n" + CANARY.encode() + b"\n"
        code, output, errors = self.invoke("import-snapshot", data)
        self.assertEqual((code, errors), (0, ""))
        path = self.root / "inputs/example.conf"
        self.assertEqual(output, str(path) + "\n")
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_uid, os.geteuid())
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.invoke("import-snapshot", b"changed")[0], 2)
        self.assertEqual(path.read_bytes(), data)
        self.assert_clean_staging()

    def test_validated_policy_is_private_and_create_only(self):
        from netops_auditor.management import load_policy
        code, output, errors = self.invoke("import-policy", self.policy(), options=("--platform", "fortios"))
        self.assertEqual((code, errors), (0, ""))
        path = Path(output.strip())
        self.assertEqual(load_policy(path, "fortios")["required_rules"], ["address-policy"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.invoke("import-policy", b"changed", options=("--platform", "fortios"))[0], 2)
        self.assertEqual(path.read_bytes(), self.policy())
        self.assert_clean_staging()

    def test_file_collect_and_policy_run_use_actual_imported_inputs(self):
        from netops_auditor import cli
        snapshot_data = b'config firewall address\n edit "host-example"\n set subnet 192.0.2.20 255.255.255.255\n next\nend\n'
        policy_data = json.dumps({"version": 1, "platform": "fortios",
                                  "address_networks": ["198.51.100.0/24"]}).encode()
        self.assertEqual(self.invoke("import-snapshot", snapshot_data)[0], 0)
        self.assertEqual(self.invoke("import-policy", policy_data, options=("--platform", "fortios"))[0], 0)
        snapshot = self.root / "inputs/example.conf"
        policy = self.root / "inputs/example.policy.json"
        entry = {"name": "example-device", "platform": "fortios", "address": None, "port": None,
                 "role": "perimeter", "credential": None, "host_key_fingerprint": None, "legacy_ssh": None,
                 "auditor": {"channel": "file", "source": str(snapshot),
                             "required_sections": ["firewall address"], "tls_fingerprint": None}, "helper": None}
        inventory = self.root / "inventory.json"
        inventory.write_text(json.dumps({"version": 2, "devices": [entry]}))
        for command in (
            ["run", "--platform", "fortios", "--config", str(snapshot)],
            ["collect", "--inventory", str(inventory)],
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = cli.main([*command, "--tenant", "example-tenant", "--device", "example-device",
                                 "--policy", str(policy), "--json"])
            self.assertEqual(code, 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["rule_coverage"]["address-policy"], "evaluated")
            self.assertTrue(any(item["rule_id"] == "fortios.management.address-policy" for item in report["findings"]))
            if command[0] == "collect":
                self.assertEqual(report["collection"]["channel"], "file")
                self.assertFalse(any(item["rule_id"].endswith(".snapshot.incomplete") for item in report["findings"]))
        entry["auditor"]["required_sections"].append("system global")
        inventory.write_text(json.dumps({"version": 2, "devices": [entry]}))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main(["collect", "--inventory", str(inventory), "--tenant", "example-tenant",
                             "--device", "example-device", "--json"])
        self.assertEqual(code, 3)
        self.assertTrue(any(item["rule_id"] == "fortios.snapshot.incomplete"
                            for item in json.loads(output.getvalue())["findings"]))

    def test_unsafe_names_and_unknown_arguments_do_not_escape_or_echo(self):
        for name in ("", ".", "..", "../config", "/absolute", "a/b", "a\\b", "a.b",
                     "a\n" + CANARY, "\x00", "\x1b[31m", "é", "a" * 65):
            with self.subTest(name=repr(name)):
                self.assertEqual(self.invoke("import-snapshot", CANARY.encode(), name=name)[0], 2)
        self.assertFalse((self.root / "inputs").exists())
        self.assertEqual(self.invoke("import-snapshot", options=("--replace", CANARY))[0], 2)
        self.assertEqual(self.invoke("import-policy", self.policy(), options=("--platform", CANARY))[0], 2)

    def test_bad_policies_never_publish_and_do_not_echo_payload(self):
        for data, platform in (
            (b'{"version":1,"platform":"fortios","platform":"fortios"}', "fortios"),
            (json.dumps({"version": 1, "platform": "fortios", "unknown": CANARY}).encode(), "fortios"),
            (self.policy(), "exos"), (b'{"' + CANARY.encode() + b'":', "fortios"),
            (b"\xff" + CANARY.encode(), "fortios"),
        ):
            with self.subTest(data=data[:12], platform=platform):
                self.assertEqual(self.invoke("import-policy", data, options=("--platform", platform))[0], 2)
                self.assertFalse((self.root / "inputs/example.policy.json").exists())
                self.assert_clean_staging()

    def test_exact_byte_limits_and_limit_plus_one(self):
        from netops_auditor import collect, management
        for kind, owner, constant, options, data in (
            ("import-snapshot", collect, "MAX_SNAPSHOT_BYTES", (), b"x" * 1024),
            ("import-policy", management, "MAX_POLICY_BYTES", ("--platform", "fortios"),
             self.policy() + b" " * (1024 - len(self.policy()))),
        ):
            with self.subTest(kind=kind), patch.object(owner, constant, 1024):
                self.assertEqual(self.invoke(kind, data, name="exact", options=options)[0], 0)
                self.assertEqual(self.invoke(kind, data + b"x", name="over", options=options)[0], 2)
        self.assert_clean_staging()

    def test_oversize_reads_are_bounded(self):
        from netops_auditor import collect
        class Source:
            def read(self, count):
                if count != 1025:
                    raise AssertionError("unbounded stdin read")
                return b"x" * count
        with patch.object(collect, "MAX_SNAPSHOT_BYTES", 1024), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(auditor_inputs.main(self.root, ["import-snapshot", "--name", "oversize"], Source()), 2)
        self.assertEqual(list((self.root / "inputs").iterdir()), [])

    def test_symlink_parent_wrong_permissions_and_existing_special_files_are_refused(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        inputs = self.root / "inputs"
        inputs.symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.invoke("import-snapshot", b"changed")[0], 2)
        self.assertEqual(list(outside.iterdir()), [])
        inputs.unlink()
        inputs.mkdir(mode=0o755)
        self.assertEqual(self.invoke("import-snapshot", b"changed")[0], 2)
        inputs.chmod(0o700)
        target = inputs / "example.conf"
        victim = outside / "victim"
        victim.write_bytes(b"preserved")
        for kind in ("symlink", "dangling", "fifo", "directory", "hardlink", "regular"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    target.symlink_to(victim)
                elif kind == "dangling":
                    target.symlink_to(outside / "absent")
                elif kind == "fifo":
                    os.mkfifo(target, 0o600)
                elif kind == "directory":
                    target.mkdir()
                elif kind == "hardlink":
                    os.link(victim, target)
                else:
                    target.write_bytes(b"original")
                self.assertEqual(self.invoke("import-snapshot", b"changed")[0], 2)
                self.assertEqual(victim.read_bytes(), b"preserved")
                if target.is_dir():
                    target.rmdir()
                else:
                    target.unlink()
        self.assert_clean_staging()

    def test_pinned_directory_never_follows_exchanged_parent(self):
        for replacement in ("symlink", "directory"):
            with self.subTest(replacement=replacement):
                inputs = self.root / "inputs"
                inputs.mkdir(mode=0o700)
                outside = self.root / ("outside-" + replacement)
                outside.mkdir(mode=0o700)
                pinned = self.root / ("pinned-" + replacement)
                original = os.write
                exchanged = False
                def exchange(fd, data):
                    nonlocal exchanged
                    if not exchanged:
                        exchanged = True
                        inputs.rename(pinned)
                        if replacement == "symlink":
                            inputs.symlink_to(outside, target_is_directory=True)
                        else:
                            inputs.mkdir(mode=0o700)
                    return original(fd, data)
                with patch("netops.auditor_inputs.os.write", exchange):
                    code, output, errors = self.invoke("import-snapshot", b"pinned")
                self.assertEqual((code, output), (2, ""))
                self.assertIn("uncertain", errors)
                self.assertEqual(list(outside.iterdir()), [])
                self.assertEqual((pinned / "example.conf").read_bytes(), b"pinned")
                if inputs.is_symlink():
                    inputs.unlink()
                else:
                    self.assertEqual(list(inputs.iterdir()), [])
                    inputs.rmdir()

    def test_write_and_fsync_failures_do_not_publish(self):
        for function in ("write", "fsync"):
            with self.subTest(function=function):
                (self.root / "inputs").mkdir(mode=0o700, exist_ok=True)
                with patch("netops.auditor_inputs.os." + function, side_effect=OSError(CANARY)):
                    self.assertEqual(self.invoke("import-snapshot", CANARY.encode())[0], 2)
                self.assertFalse((self.root / "inputs/example.conf").exists())
                self.assert_clean_staging()

    def test_post_publish_sync_failure_reports_uncertain_complete_file(self):
        (self.root / "inputs").mkdir(mode=0o700)
        original = os.fsync
        calls = 0
        def fail_directory(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError(CANARY)
            return original(fd)
        with patch("netops.auditor_inputs.os.fsync", fail_directory):
            code, output, errors = self.invoke("import-snapshot", b"complete")
        self.assertEqual((code, output), (2, ""))
        self.assertIn("uncertain", errors)
        self.assertEqual((self.root / "inputs/example.conf").read_bytes(), b"complete")
        self.assertEqual((self.root / "inputs/example.conf").stat().st_nlink, 1)
        self.assert_clean_staging()

    def test_preexisting_staging_collision_is_never_removed(self):
        from types import SimpleNamespace
        inputs = self.root / "inputs"
        inputs.mkdir(mode=0o700)
        collision = inputs / ".import-existing"
        collision.write_bytes(b"preserved")
        with patch("netops.auditor_inputs.uuid.uuid4", return_value=SimpleNamespace(hex="existing")):
            self.assertEqual(self.invoke("import-snapshot", b"changed")[0], 2)
        self.assertEqual(collision.read_bytes(), b"preserved")
        self.assertFalse((inputs / "example.conf").exists())

    def test_foreign_uid_is_refused_before_stdin(self):
        class NoRead:
            def read(self, count):
                raise AssertionError("must not consume stdin")
        with patch.dict(UIDS, {"auditor": os.geteuid() + 1}), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(auditor_inputs.main(self.root, ["import-snapshot", "--name", "example"], NoRead()), 2)

    def test_operator_dispatch_holds_lock_and_demotes_before_import(self):
        from netops import operator
        order = []
        with patch("netops.operator.os.geteuid", return_value=0), \
                patch("netops.operator.acquire_state", side_effect=lambda: order.append("lock") or 99), \
                patch("netops.operator._operator_audit_preflight", side_effect=lambda *_: order.append("audit")), \
                patch("netops.operator.demote", side_effect=lambda _: order.append("demote")), \
                patch("netops.operator.role_environment"), patch("netops.operator.os.close"), \
                patch("netops.auditor_inputs.main", side_effect=lambda *_: order.append("import") or 0):
            self.assertEqual(operator.role_cli("auditor", ["import-snapshot", "--name", "example"]), 0)
        self.assertEqual(order, ["lock", "audit", "demote", "import"])

    def test_auditor_help_discovers_imports(self):
        from netops import operator
        output = io.StringIO()
        with patch("netops.operator.os.geteuid", return_value=0), \
                patch("netops.operator.acquire_state", return_value=99), patch("netops.operator.demote"), \
                patch("netops.operator.role_environment"), patch("netops.operator.os.close"), \
                contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exit_value:
            operator.role_cli("auditor", ["--help"])
        self.assertEqual(exit_value.exception.code, 0)
        self.assertIn("import-snapshot --name", output.getvalue())
        self.assertIn("import-policy --name", output.getvalue())
