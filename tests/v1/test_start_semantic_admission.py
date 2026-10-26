import copy
from datetime import datetime, timedelta, timezone
from contextlib import ExitStack
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from netops import audit, certificates, files, gateway, init, state
from netops.files import MAX_MESSAGE, UIDS, write_private
import test_upgrade_previous_release as previous


class AdmissionBoundaryReached(Exception):
    pass


class SemanticAdmission(unittest.TestCase):
    store = previous.PreviousReleaseUpgrade.store
    snapshot = previous.PreviousReleaseUpgrade.snapshot
    start = previous.PreviousReleaseUpgrade.start
    renewal_views = previous.PreviousReleaseUpgrade.renewal_views

    def setUp(self):
        previous.PreviousReleaseUpgrade.setUp(self)
        self.audit_directory = self.path.parent / "audit"
        self.audit_directory.mkdir(mode=0o700)
        self.rejections = self.audit_directory / "rejections.json"
        write_private(self.path.parent / "instance.lock", b"", UIDS["gateway"])

    def settings_for(self, mode, **audit_changes):
        result = copy.deepcopy(self.settings)
        result["audit"]["mode"] = mode
        if mode == "syslog":
            result["audit"].update(host="collector.example.invalid", port=6514)
        result["audit"].update(audit_changes)
        return result

    def snapshot_counts(self, **changes):
        counts = {"authentication_required": 0, "https_required": 0}
        counts.update(changes)
        return {"counts": counts, "first": None, "last": None, "extra_preserved": True}

    def put_rejections(self, value):
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        write_private(self.rejections, data, UIDS["gateway"], replace=self.rejections.exists())

    def readonly(self, action):
        before = self.snapshot()
        with patch.object(files, "write_private", wraps=files.write_private) as writing, \
             patch.object(Path, "mkdir", autospec=True) as creating, \
             patch.object(audit, "Audit") as constructor:
            try:
                return action()
            finally:
                writing.assert_not_called()
                creating.assert_not_called()
                constructor.assert_not_called()
                self.assertEqual(self.snapshot(), before, "readonly admission changed existing state")

    def admits(self, description, action):
        try:
            return action()
        except (ValueError, OSError) as exc:
            self.fail(description + " was refused: " + type(exc).__name__ + ": " + str(exc))

    def test_check_start_refuses_invalid_audit_limits_in_both_modes(self):
        cases = [("budget_bytes", MAX_MESSAGE * 4 - 1, "Invalid audit disk budget or retention"),
                 ("segment_bytes", MAX_MESSAGE - 1, "Invalid audit disk budget or retention"),
                 ("segment_bytes", MAX_MESSAGE * 4 + 1, "Invalid audit disk budget or retention"),
                 ("retention_seconds", 0, "Invalid audit disk budget or retention"),
                 ("budget_bytes", "not-a-number", "invalid literal")]
        for mode in ("local", "syslog"):
            self.readonly(lambda: self.admits("Valid " + mode + " audit limits",
                                              lambda: init.check_start(self.settings_for(mode), self.root)))
            for name, value, message in cases:
                with self.subTest(mode=mode, setting=name, value=value):
                    settings = self.settings_for(mode, **{name: value})
                    with self.assertRaisesRegex(ValueError, message):
                        self.readonly(lambda: init.check_start(settings, self.root))

    def test_check_start_preserves_audit_defaults_and_int_conversions(self):
        cases = [{}, {"budget_bytes": str(MAX_MESSAGE * 4), "segment_bytes": str(MAX_MESSAGE),
                      "retention_seconds": "1"},
                 {"budget_bytes": MAX_MESSAGE * 4, "segment_bytes": MAX_MESSAGE, "retention_seconds": True}]
        for mode in ("local", "syslog"):
            for values in cases:
                with self.subTest(mode=mode, values=values):
                    settings = self.settings_for(mode)
                    settings["audit"] = {"mode": mode, **({"host": "collector.example.invalid", "port": 6514} if mode == "syslog" else {}), **values}
                    self.readonly(lambda: self.admits("Default or converted audit settings",
                                                      lambda: init.check_start(settings, self.root)))

    def test_check_start_refuses_invalid_rejection_snapshot_in_both_modes(self):
        cases = [(self.snapshot_counts(authentication_required=True), "Invalid rejection summary"),
                 (self.snapshot_counts(https_required=-1), "Invalid rejection summary"),
                 (self.snapshot_counts(authentication_required=9223372036854775808), "Invalid rejection summary"),
                 (b'{"counts":', None)]
        for mode in ("local", "syslog"):
            self.put_rejections(self.snapshot_counts())
            self.readonly(lambda: self.admits("Valid " + mode + " rejection snapshot",
                                              lambda: init.check_start(self.settings_for(mode), self.root)))
            for data, message in cases:
                with self.subTest(mode=mode, data=data):
                    self.put_rejections(data)
                    with self.assertRaises(ValueError) as caught:
                        self.readonly(lambda: init.check_start(self.settings_for(mode), self.root))
                    if message is not None:
                        self.assertEqual(str(caught.exception), message)

    def test_check_start_admits_valid_or_absent_rejection_snapshots_readonly(self):
        for mode in ("local", "syslog"):
            for value in (None, self.snapshot_counts(), self.snapshot_counts(https_required=9223372036854775807)):
                with self.subTest(mode=mode, value=value):
                    if self.rejections.exists():
                        self.rejections.unlink()
                    if value is not None:
                        self.put_rejections(value)
                    self.readonly(lambda: self.admits("Valid or absent rejection snapshot",
                                                      lambda: init.check_start(self.settings_for(mode), self.root)))

    def test_rejection_snapshot_read_uses_gateway_owner_not_caller_uid(self):
        snapshot = self.snapshot_counts()
        self.put_rejections(snapshot)
        gateway_owner = UIDS["gateway"]
        caller_uid = 0 if gateway_owner != 0 else 1
        self.assertEqual(self.rejections.stat().st_uid, gateway_owner)
        self.assertNotEqual(caller_uid, gateway_owner)
        self.assertEqual(json.loads(self.rejections.read_bytes()), snapshot)
        identity = self.rejections.stat()
        original = files.check_regular
        for mode in ("local", "syslog"):
            with self.subTest(mode=mode):
                observed = []
                def checking(descriptor, owner=None):
                    info = os.fstat(descriptor)
                    if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
                        observed.append(owner)
                        self.assertEqual(owner, gateway_owner,
                                         "rejection snapshot fd check did not use explicit gateway owner")
                    return original(descriptor, owner)
                with patch.object(audit.os, "geteuid", return_value=caller_uid), \
                     patch.object(files, "check_regular", side_effect=checking):
                    self.readonly(lambda: self.admits("Valid snapshot read with explicit gateway owner",
                                                      lambda: init.check_start(self.settings_for(mode), self.root)))
                self.assertTrue(observed, "rejection snapshot was not read by admission")

    def test_snapshot_read_errors_are_not_absence(self):
        self.put_rejections(self.snapshot_counts())
        original = audit.read_private
        for mode in ("local", "syslog"):
            for error in (PermissionError("snapshot-denied"), OSError(5, "snapshot-io")):
                with self.subTest(mode=mode, error=type(error).__name__):
                    def reading(path, *args, **kwargs):
                        if Path(path) == self.rejections:
                            raise error
                        return original(path, *args, **kwargs)
                    with patch.object(audit, "read_private", side_effect=reading), self.assertRaises(OSError) as caught:
                        self.readonly(lambda: init.check_start(self.settings_for(mode), self.root))
                    self.assertIs(caught.exception, error)

    def test_existing_dangling_snapshot_symlink_is_not_absence(self):
        self.rejections.symlink_to(self.audit_directory / "missing-snapshot-target")
        for mode in ("local", "syslog"):
            with self.subTest(mode=mode), self.assertRaises(OSError):
                self.readonly(lambda: init.check_start(self.settings_for(mode), self.root))
            self.assertTrue(self.rejections.is_symlink())
            self.assertEqual(os.readlink(self.rejections), str(self.audit_directory / "missing-snapshot-target"))

    def test_bootstrap_refuses_semantics_before_metadata_children_or_gateway(self):
        for mode in ("local", "syslog"):
            for fault in ("budget", "rejections"):
                with self.subTest(mode=mode, fault=fault):
                    settings = self.settings_for(mode)
                    if fault == "budget":
                        settings["audit"]["budget_bytes"] = 1
                    self.put_rejections(self.snapshot_counts(authentication_required=True) if fault == "rejections" else self.snapshot_counts())
                    self.store(settings)
                    self.children.reset_mock()
                    self.gateway_start.reset_mock()
                    with self.assertRaisesRegex(ValueError, "Invalid audit disk budget or retention|Invalid rejection summary"):
                        self.readonly(self.start)
                    self.children.assert_not_called()
                    self.gateway_start.assert_not_called()

    def test_unrenewable_leaf_refusal_uses_inert_gateway_and_named_assertion(self):
        before = self.snapshot()
        view, now = self.renewal_views(2, 7)
        with patch.object(certificates, "datetime") as clock, \
             patch.object(certificates.x509, "load_pem_x509_certificate", side_effect=view), \
             patch.object(certificates, "verify_pairs"):
            clock.now.return_value = now
            with self.assertRaisesRegex(ValueError, "expires within 7 days"):
                self.start()
        self.assertEqual(self.snapshot(), before)
        self.children.assert_not_called()
        self.gateway_start.assert_not_called()

    def assert_metadata_only_conversion(self, before):
        after = self.snapshot()
        self.assertEqual(set(after), set(before))
        self.assertEqual(json.loads(self.path.read_bytes()), dict(self.settings, product_version="1.0.3"))
        for name in before:
            if name != "gateway/config.json":
                self.assertEqual(after[name], before[name], name)
        self.assertEqual(after["gateway/config.json"][1:], before["gateway/config.json"][1:])
        self.gateway_start.assert_called_once()

    def test_renewal_needed_and_possible_with_real_short_leaf_is_admitted(self):
        leaf = x509.load_pem_x509_certificate((self.path.parent / "server.pem").read_bytes())
        ca = x509.load_pem_x509_certificate((self.path.parent / "ca.pem").read_bytes())
        ca_key = serialization.load_pem_private_key((self.path.parent / "ca.key").read_bytes(), password=None)
        now = datetime.now(timezone.utc)
        builder = (x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(ca.subject)
                   .public_key(leaf.public_key()).serial_number(leaf.serial_number)
                   .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=1)))
        for extension in leaf.extensions:
            builder = builder.add_extension(extension.value, extension.critical)
        short = builder.sign(ca_key, hashes.SHA256())
        write_private(self.path.parent / "server.pem", short.public_bytes(serialization.Encoding.PEM), UIDS["gateway"], replace=True)
        before = self.snapshot()
        self.admits("Real short leaf pair", certificates.verify_pairs)
        self.assertIsNotNone(self.admits("Real short leaf renewal inputs",
                                         lambda: certificates.renewal_inputs(self.settings["server_name"])))
        self.assertEqual(self.snapshot(), before)
        with patch.object(certificates, "renew", wraps=certificates.renew) as renew:
            self.admits("Real short leaf bootstrap conversion", self.start)
            renew.assert_not_called()
        self.assert_metadata_only_conversion(before)

    def test_leaf_two_days_ca_seven_and_half_days_is_admitted(self):
        view, now = self.renewal_views(2, 7.5)
        before = self.snapshot()
        with patch.object(certificates, "datetime") as clock, \
             patch.object(certificates.x509, "load_pem_x509_certificate", side_effect=view), \
             patch.object(certificates, "verify_pairs"), \
             patch.object(certificates, "renew", side_effect=AssertionError("readonly admission must not invoke certificates.renew")):
            clock.now.return_value = now
            try:
                self.assertIsNotNone(certificates.renewal_inputs(self.settings["server_name"]))
                self.start()
            except ValueError as exc:
                self.fail("Valid leaf2d/CA7.5d readonly renewal admission was refused: " + str(exc))
        self.assert_metadata_only_conversion(before)

    def current_gateway(self, settings):
        with patch.object(certificates, "renew", return_value=False) as renew, \
             patch.object(gateway, "application", new_callable=AsyncMock, side_effect=AdmissionBoundaryReached) as application, \
             patch.object(gateway.uvicorn, "Config") as config:
            error = None
            try:
                self.readonly(lambda: previous.ORIGINAL_GATEWAY_SERVE(settings, ["helper", "auditor"], []))
            except (ValueError, OSError, AdmissionBoundaryReached) as caught:
                error = caught
            config.assert_not_called()
            return error, renew, application

    def test_current_gateway_refuses_before_renewal_for_tail_identity_or_pair(self):
        original_key = (self.path.parent / "server.key").read_bytes()
        for fault, message in (("tail", "Incomplete final audit record"),
                               ("identity", "NETOPS_SERVER_NAME is"),
                               ("pair", "certificate files are missing or do not match")):
            with self.subTest(fault=fault), ExitStack() as stack:
                settings = dict(self.settings, product_version="1.0.3")
                self.store(settings)
                write_private(self.path.parent / "server.key", original_key, UIDS["gateway"], replace=True)
                tail = self.audit_directory / "current.jsonl"
                if tail.exists():
                    tail.unlink()
                if fault == "tail":
                    write_private(tail, b'{"synthetic":', UIDS["gateway"])
                elif fault == "identity":
                    stack.enter_context(patch.dict(os.environ, {"NETOPS_SERVER_NAME": "other.example.invalid"}))
                else:
                    write_private(self.path.parent / "server.key", b"synthetic-invalid-key", UIDS["gateway"], replace=True)
                error, renew, application = self.current_gateway(settings)
                self.assertIsInstance(error, ValueError, "common gateway admission did not refuse before application boundary")
                self.assertIn(message, str(error))
                renew.assert_not_called()
                application.assert_not_awaited()
                self.children.assert_not_called()

    def test_valid_current_gateway_reaches_only_the_inert_application_boundary(self):
        settings = dict(self.settings, product_version="1.0.3")
        self.store(settings)
        with patch.object(init, "check_start", wraps=init.check_start) as check:
            error, renew, application = self.current_gateway(settings)
        self.assertIsInstance(error, AdmissionBoundaryReached,
                              "valid current gateway admission was refused before the inert application boundary")
        check.assert_called_once_with(settings, self.root)
        renew.assert_called_once_with(settings["server_name"])
        application.assert_awaited_once_with(settings, ["helper", "auditor"], [])
        self.children.assert_not_called()

    def test_current_config_reader_policy_after_successful_privileged_open(self):
        self.store(dict(self.settings, product_version="1.0.3"))
        original_open = os.open
        for mode in (0o200, 0o400, 0o600):
            with self.subTest(mode=oct(mode)):
                self.path.chmod(0o600)
                descriptor = original_open(self.path, os.O_RDONLY)
                before = os.pread(descriptor, self.path.stat().st_size, 0)
                self.path.chmod(mode)
                self.prepare.reset_mock()
                self.children.reset_mock()
                self.gateway_start.reset_mock()
                def opened(path, flags, *args, **kwargs):
                    if Path(path) == self.path and not flags & (os.O_WRONLY | os.O_RDWR):
                        duplicate = os.dup(descriptor)
                        os.lseek(duplicate, 0, os.SEEK_SET)
                        return duplicate
                    return original_open(path, flags, *args, **kwargs)
                try:
                    with patch.object(files.os, "open", side_effect=opened), \
                         patch.object(files, "write_private", wraps=files.write_private) as writing:
                        if mode == 0o200:
                            with self.assertRaisesRegex(state.StateCompatibilityError, "cannot be read safely"):
                                self.start()
                            self.prepare.assert_not_called()
                            self.children.assert_not_called()
                            self.gateway_start.assert_not_called()
                        else:
                            self.admits("Readable current config mode " + oct(mode), self.start)
                            self.gateway_start.assert_called_once()
                        writing.assert_not_called()
                    self.assertEqual(os.pread(descriptor, len(before) + 1, 0), before)
                    self.assertEqual(self.path.stat().st_mode & 0o777, mode)
                finally:
                    self.path.chmod(0o600)
                    os.close(descriptor)
