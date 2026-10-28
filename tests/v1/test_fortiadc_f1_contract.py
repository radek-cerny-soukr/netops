import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from netops_admin import access as admin_access
from netops_admin.errors import Rejected
from netops_core import platforms, schema
from netops_helper import engine, read_policy, schema_read


ADC_STATUS = "Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n"
FORTIOS_STATUS = "Version: FortiGate-VM64-KVM v7.6.7,build3704,release\n"
FORTIOS_IDENTITY = ("FortiGate-VM64-KVM", "7.6.7", "3704")


def malformed_or_duplicate(valid):
    return (
        valid + "Version: malformed\n",
        "Version: malformed\n" + valid,
        valid + "Version:\n",
        "Version:malformed\n" + valid,
        valid + "Version:\tmalformed\n",
        valid + valid,
    )


class FortiAdcF1Contract(unittest.TestCase):
    def require_adc_platform(self):
        try:
            actual = platforms.normalize("fortiadc")
        except platforms.PlatformError as exc:
            self.fail("F1-MISSING-ADC-PLATFORM: %s" % exc)
        self.assertEqual(actual, "fortiadc", "F1-ADC-PLATFORM-MUST-BE-DISTINCT")

    def require_identity_check(self):
        check = getattr(platforms, "require_identity", None)
        self.assertTrue(callable(check), "F1-MISSING-PRODUCT-IDENTITY-CHECK")
        return check

    def require_adc_helper(self):
        try:
            actual = read_policy.normalize_platform("fortiadc")
        except ValueError as exc:
            self.fail("F1-MISSING-ADC-HELPER: %s" % exc)
        self.assertEqual(actual, "fortiadc", "F1-ADC-HELPER-MUST-BE-DISTINCT")
        self.assertIn("fortiadc", read_policy.READ_QUERIES, "F1-MISSING-ADC-QUERY-CATALOG")

    def test_f1_adc_platform_and_existing_alias_are_distinct(self):
        self.require_adc_platform()
        self.assertEqual(platforms.normalize("fortios"), "fortios")
        self.assertEqual(platforms.normalize("fortinet"), "fortios")
        self.assertNotEqual(platforms.normalize("fortiadc"), platforms.normalize("fortinet"))

    def test_f1_fortinet_alias_still_means_fortios(self):
        self.assertEqual(platforms.normalize("fortinet"), "fortios")
        self.assertEqual(read_policy.normalize_platform("fortinet"),
                         read_policy.normalize_platform("fortios"))

    def test_f1_identity_accepts_the_matching_product(self):
        check = self.require_identity_check()
        for selected, status, expected in (
            ("fortiadc", ADC_STATUS, "fortiadc"),
            ("fortios", FORTIOS_STATUS, "fortios"),
            ("fortinet", FORTIOS_STATUS, "fortios"),
            ("FortiADC", ADC_STATUS, "fortiadc"),
            (" FORTIOS ", FORTIOS_STATUS, "fortios"),
            ("fortios", "Version: FortiWiFi-60F v7.6.7,build3704,release\n", "fortios"),
            ("fortios", "Version: FortiGate-VM64-KVM v7.6.7,build3704\n", "fortios"),
            ("fortios", "Firmware Version: FortiADC-KVM\n" + FORTIOS_STATUS, "fortios"),
            ("fortios", " " + ADC_STATUS + FORTIOS_STATUS, "fortios"),
            ("fortios", "\t" + ADC_STATUS + FORTIOS_STATUS, "fortios"),
            ("fortios", "Version: FortiGate-VM64-KVM v7.6.7,build3704\r\n", "fortios"),
            ("fortiadc", "Version: FortiADC-KVM v7.6.7,build0676\r\n", "fortiadc"),
            ("fortiadc", ADC_STATUS.replace("\n", "\r\n"), "fortiadc"),
        ):
            with self.subTest(selected=selected):
                self.assertEqual(check(selected, status), expected)

    def test_f1_identity_rejects_adc_as_fortios_and_fortios_as_adc(self):
        check = self.require_identity_check()
        for selected, status in (
            ("fortios", ADC_STATUS),
            ("fortinet", ADC_STATUS),
            ("fortios", "Hostname: FortiGate-x\n" + ADC_STATUS),
            ("fortiadc", FORTIOS_STATUS),
            ("fortiadc", "Hostname: FortiADC-x\n" + FORTIOS_STATUS),
        ):
            with self.subTest(selected=selected):
                with self.assertRaises(platforms.PlatformError):
                    check(selected, status)

    def test_f1_identity_rejects_missing_or_ambiguous_product(self):
        check = self.require_identity_check()
        for selected in ("fortios", "fortiadc"):
            for status in (
                "", "Hostname: example\n", ADC_STATUS + FORTIOS_STATUS,
                "Hostname: FortiADC-example\n",
                "Version: FortiADCXYZ v7.6.7,build0676,release\n",
            ):
                with self.subTest(selected=selected, status=status):
                    with self.assertRaises(platforms.PlatformError):
                        check(selected, status)

    def test_f1_identity_rejects_malformed_or_duplicate_version_records(self):
        check = self.require_identity_check()
        for selected, valid in (("fortios", FORTIOS_STATUS), ("fortiadc", ADC_STATUS)):
            for status in malformed_or_duplicate(valid):
                with self.subTest(selected=selected, status=status):
                    with self.assertRaises(platforms.PlatformError):
                        check(selected, status)

    def test_f1_identity_rejects_version_records_outside_the_existing_grammar(self):
        check = self.require_identity_check()
        for status in (
            "Version: FortiGate-VM64-KVM v7.6.7,build370,release\n",
            "Version: FortiGate-VM64-KVM v7.6.7,build3704000,release\n",
            "Version: FortiGate-VM64-KVM v7.6,build3704,release\n",
            "Version: FortiGate-VM64-KVM 7.6.7,build3704,release\n",
            "Version: FortiGate-VM64-KVM v7.6.7,build3704x,release\n",
            "Version:\nFortiGate-VM64-KVM v7.6.7,build3704,release\n",
        ):
            with self.subTest(status=status):
                with self.assertRaises(platforms.PlatformError):
                    check("fortios", status)

    def test_f1_identity_matches_the_record_from_the_start_of_its_own_line(self):
        check = self.require_identity_check()
        for selected, status in (
            ("fortios", "Version: malformed " + FORTIOS_STATUS),
            ("fortiadc", "Version: malformed " + ADC_STATUS),
            ("fortios", " " + FORTIOS_STATUS),
            ("fortios", "\t" + FORTIOS_STATUS),
            ("fortiadc", " " + ADC_STATUS),
            ("fortiadc", "\t" + ADC_STATUS),
        ):
            with self.subTest(selected=selected, status=status):
                with self.assertRaises(platforms.PlatformError):
                    check(selected, status)

    def test_f1_identity_lines_end_only_at_line_feed(self):
        check = self.require_identity_check()
        for separator in ("\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " "):
            for selected, valid in (("fortiadc", ADC_STATUS), ("fortios", FORTIOS_STATUS)):
                status = "Hostname: example" + separator + valid
                with self.subTest(selected=selected, separator=hex(ord(separator))):
                    with self.assertRaises(platforms.PlatformError):
                        check(selected, status)
                    with self.assertRaises(platforms.VersionRecordError):
                        platforms.version_record(status)

    def test_f1_identity_rejects_hardware_outside_the_f1_prefixes(self):
        check = self.require_identity_check()
        for selected, status in (
            ("fortios", "Version: FortiGatefoo v7.6.7,build3704,release\n"),
            ("fortios", "Version: FortiWiFifoo v7.6.7,build3704,release\n"),
            ("fortios", "Version: fortigate-VM64-KVM v7.6.7,build3704,release\n"),
            ("fortios", "Version: FORTIWIFI-60F v7.6.7,build3704,release\n"),
            ("fortiadc", "Version: fortiadc-KVM v7.6.7,build0676,260522 (GA.M)\n"),
            ("fortios", "Version: XFortiGate-VM64-KVM v7.6.7,build3704,release\n"),
            ("fortios", "Version: XFortiWiFi-60F v7.6.7,build3704,release\n"),
            ("fortiadc", "Version: XFortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n"),
            ("fortios", "Version: FortiGateRugged-60F v7.6.7,build3704,release\n"),
            ("fortios", "Version: FortiFirewall-4200F v7.6.7,build3704,release\n"),
        ):
            with self.subTest(selected=selected, status=status):
                with self.assertRaises(platforms.PlatformError):
                    check(selected, status)

    def test_f1_schema_read_rejects_malformed_or_duplicate_version_records(self):
        class AcceptMeasuredIdentity:
            def require_identity(self, *_identity):
                return None

        for status in malformed_or_duplicate(FORTIOS_STATUS):
            with self.subTest(status=status):
                with self.assertRaises(schema.SchemaError, msg="F1-TIGHTEN-SCHEMA-READ-VERSION-RECORD"):
                    schema_read.verify_status(
                        AcceptMeasuredIdentity(),
                        status + "Current virtual domain: root\n",
                    )

    def test_f1_schema_read_still_accepts_one_exact_version_record(self):
        identities = []

        class RecordIdentity:
            def require_identity(self, *identity):
                identities.append(identity)

        self.assertEqual(
            schema_read.verify_status(RecordIdentity(), FORTIOS_STATUS + "Current virtual domain: root\n"),
            "root",
        )
        self.assertEqual(identities, [FORTIOS_IDENTITY])

    def test_f1_admin_schema_access_rejects_malformed_or_duplicate_version_records(self):
        for status in malformed_or_duplicate(FORTIOS_STATUS):
            with self.subTest(status=status):
                calls = []
                base = SimpleNamespace(
                    credential=object(),
                    check_credential=object(),
                    query=lambda command: calls.append(command) or status + "Hostname: test-f1-device\n",
                )
                library = SimpleNamespace(require_identity=lambda *_identity: None)
                with patch.object(admin_access.schema_runtime, "policy", return_value=(library, None)), \
                     patch.object(admin_access.schema_runtime.exec_fortios, "prompt_spec", return_value=object()):
                    with self.assertRaises(Rejected, msg="F1-TIGHTEN-ADMIN-VERSION-RECORD"):
                        admin_access.SchemaAccess(base, SimpleNamespace())
                self.assertEqual(calls, ["get system status"])

    def test_f1_admin_schema_access_still_accepts_one_exact_version_record(self):
        calls = []
        identities = []
        base = SimpleNamespace(
            credential=object(),
            check_credential=object(),
            query=lambda command: calls.append(command) or FORTIOS_STATUS + "Hostname: test-f1-device\n",
        )
        library = SimpleNamespace(require_identity=lambda *identity: identities.append(identity))
        with patch.object(admin_access.schema_runtime, "policy", return_value=(library, None)), \
             patch.object(admin_access.schema_runtime.exec_fortios, "prompt_spec", return_value=object()):
            access = admin_access.SchemaAccess(base, SimpleNamespace())
        self.assertEqual(access.hostname, "test-f1-device")
        self.assertEqual(identities, [FORTIOS_IDENTITY])
        self.assertEqual(calls, ["get system status"])

    def test_f1_identity_rejects_unknown_and_unrelated_platforms(self):
        check = self.require_identity_check()
        for selected in ("", "fortiadcx", "exos", "linux"):
            with self.subTest(selected=selected):
                with self.assertRaises(platforms.PlatformError):
                    check(selected, ADC_STATUS)

    def test_f1_helper_exposes_only_the_fixed_system_status_query(self):
        self.require_adc_helper()
        queries = read_policy.READ_QUERIES["fortiadc"]
        self.assertEqual(set(queries), {"system_status"}, "F1-ADC-ONLY-ONE-QUERY")
        self.assertEqual(dict(queries["system_status"].slots), {}, "F1-ADC-NO-COMMAND-PARAMETERS")
        self.assertEqual(
            read_policy.render_read_query("fortiadc", "system_status", {}, {}),
            ("fortiadc", "get system status"),
            "F1-ADC-EXACT-STATUS-COMMAND",
        )

    def test_f1_helper_rejects_arbitrary_command_selectors(self):
        self.require_adc_helper()
        for selector in (
            "get system status", "get system performance", "show full-configuration",
            "execute reboot", "system_status; execute reboot", "system_status\nexecute reboot",
        ):
            with self.subTest(selector=selector):
                with self.assertRaises(ValueError):
                    read_policy.render_read_query("fortiadc", selector, {}, {})

    def test_f1_helper_rejects_command_expanding_parameters(self):
        self.require_adc_helper()
        for parameters in (
            {"command": "execute reboot"}, {"suffix": "; execute reboot"},
            {"filter": "| grep Version"}, {"system_status": "show full-configuration"},
        ):
            with self.subTest(parameters=parameters):
                with self.assertRaises(ValueError):
                    read_policy.render_read_query("fortiadc", "system_status", parameters, {})


class FortiAdcF1Wire(unittest.TestCase):
    ERROR = "The live device did not identify itself as the selected product (%s); no query output was returned"
    LEAK = "Hostname: f1-wire-leak-marker\n"

    def setUp(self):
        self.reads = []
        self.cache = {}
        self.enterContext(patch.object(engine, "_SSH_PAGE_CACHE", self.cache))
        self.auth = SimpleNamespace(alias="f1-wire", secrets=(), legacy_ssh=None)

    def read(self, platform, command, responses, offset=0, snapshot=None, full=False, events=None):
        def device(auth, selected, issued):
            self.reads.append((selected, issued))
            if issued not in responses:
                raise AssertionError("F1-MISSING-WIRE-UNEXPECTED-COMMAND: %s" % issued)
            answer = responses[issued]
            if isinstance(answer, Exception):
                raise answer
            return answer

        state = (platform, command, ("f1-wire", platform, command))
        function = engine.ssh_read if full else engine.ssh_read.__wrapped__
        with patch.object(engine, "_ssh_read_state", return_value=state), \
             patch.object(engine, "read_from_device", side_effect=device), \
             patch.object(engine, "record", side_effect=lambda event, **fields: (events if events is not None else []).append(fields["status"])):
            return function(self.auth, platform, "f1_query", None, offset, 1000, snapshot)

    def assert_identity_refused(self, result, platform):
        self.assertFalse(result["ok"], "F1-MISSING-WIRE-FAIL")
        self.assertEqual(result["error_code"], "product_identity", "F1-MISSING-WIRE-FAIL")
        self.assertEqual(result["error"], self.ERROR % platform)
        self.assertEqual(set(result), {"ok", "target", "platform", "query", "transport", "rc", "error_code", "error"})
        self.assertNotIn("f1-wire-leak-marker", json.dumps(result))
        self.assertEqual(self.cache, {})

    def test_f1_wire_probe_precedes_the_requested_query_and_it_is_sent_once(self):
        command = "diagnose netlink interface list port3"
        result = self.read("fortinet", command, {
            "get system status": (0, FORTIOS_STATUS),
            command: (0, "device answer\n"),
        })
        self.assertEqual(self.reads, [("fortinet", "get system status"), ("fortinet", command)],
                         "F1-MISSING-WIRE-ORDER")
        self.assertTrue(result["ok"])
        self.assertEqual(result["untrusted_device_output"], "device answer\n")

    def test_f1_wire_status_query_is_probe_and_query_in_one_read(self):
        for platform, status in (("fortiadc", ADC_STATUS), ("fortinet", FORTIOS_STATUS)):
            with self.subTest(platform=platform):
                self.reads.clear()
                result = self.read(platform, "get system status", {"get system status": (0, status)})
                self.assertEqual(self.reads, [(platform, "get system status")], "F1-WIRE-SINGLE")
                self.assertTrue(result["ok"])
                self.assertEqual(result["untrusted_device_output"], status)

    def test_f1_wire_wrong_product_is_refused_before_the_requested_query(self):
        command = "diagnose netlink interface list port3"
        shown = {"fortinet": "fortios", "fortiadc": "fortiadc"}
        for platform, wrong in (("fortinet", ADC_STATUS), ("fortiadc", FORTIOS_STATUS)):
            variants = (wrong, "", "Hostname: x\n") + malformed_or_duplicate(
                FORTIOS_STATUS if platform == "fortinet" else ADC_STATUS)
            for status in variants:
                for requested in ("get system status", command):
                    with self.subTest(platform=platform, status=status, requested=requested):
                        self.reads.clear()
                        result = self.read(platform, requested, {"get system status": (0, self.LEAK + status)})
                        self.assertEqual(self.reads, [(platform, "get system status")],
                                         "F1-MISSING-WIRE-ORDER")
                        self.assert_identity_refused(result, shown[platform])

    def test_f1_wire_refused_or_failed_probe_does_not_establish_identity(self):
        command = "diagnose netlink interface list port3"
        for platform, status, rc, shown in (
            ("fortinet", FORTIOS_STATUS, 1, "fortios"),
            ("fortiadc", ADC_STATUS, 255, "fortiadc"),
            ("fortinet", FORTIOS_STATUS + "Command fail. Return code -61\n", 0, "fortios"),
        ):
            for requested in ("get system status", command):
                with self.subTest(platform=platform, rc=rc, requested=requested):
                    self.reads.clear()
                    result = self.read(platform, requested, {"get system status": (rc, self.LEAK + status)})
                    self.assertEqual(self.reads, [(platform, "get system status")], "F1-MISSING-WIRE-FAIL")
                    self.assert_identity_refused(result, shown)
                    self.assertEqual(result["rc"], rc)

    def test_f1_wire_a_failing_probe_read_sends_no_query(self):
        command = "diagnose netlink interface list port3"
        result = self.read("fortinet", command, {"get system status": RuntimeError("probe transport failed")})
        self.assertEqual(self.reads, [("fortinet", "get system status")], "F1-MISSING-WIRE-TRANSPORT")
        self.assertFalse(result["ok"])
        self.assertTrue(result["error"].startswith("RuntimeError"))
        self.assertNotIn("error_code", result)

    def test_f1_wire_a_continuation_makes_no_probe_and_no_read(self):
        command = "diagnose netlink interface list port3"
        body = "x" * 1500
        first = self.read("fortinet", command, {
            "get system status": (0, FORTIOS_STATUS),
            command: (0, body),
        })
        self.assertEqual(len(self.reads), 2, "F1-MISSING-WIRE-ORDER")
        self.assertTrue(first["ok"])
        second = self.read("fortinet", command, {}, offset=first["next_offset"], snapshot=first["content_sha256"])
        self.assertEqual(len(self.reads), 2, "F1-WIRE-CONTINUATION")
        self.assertEqual(second["pagination_source"], "cached")

    def test_f1_wire_other_platforms_are_not_probed(self):
        result = self.read("linux", "hostname", {"hostname": (0, "host\n")})
        self.assertEqual(self.reads, [("linux", "hostname")])
        self.assertTrue(result["ok"])

    def test_f1_wire_refusal_is_audited_failed_and_never_cached(self):
        events = []
        result = self.read("fortiadc", "get system status", {"get system status": (0, FORTIOS_STATUS)},
                           full=True, events=events)
        self.assert_identity_refused(result, "fortiadc")
        self.assertEqual(events, ["started", "failed"], "F1-MISSING-WIRE-FAIL")

    def test_f1_refusal_fortiadc_has_no_borrowed_fortios_classifier(self):
        refusal = "Command fail. Return code -61\n"
        self.assertNotIn("fortiadc", engine._CLI_REFUSALS)
        self.assertFalse(engine._cli_refused("fortiadc", refusal))
        result = self.read("fortiadc", "get system status", {"get system status": (0, refusal)})
        self.assert_identity_refused(result, "fortiadc")

    def test_f1_refusal_fortiadc_valid_record_with_fortios_refusal_text_is_read(self):
        status = ADC_STATUS + "Command fail. Return code -61\n"
        result = self.read("fortiadc", "get system status", {"get system status": (0, status)})
        self.assertEqual(self.reads, [("fortiadc", "get system status")], "F1-WIRE-SINGLE")
        self.assertTrue(result["ok"], "F1-REFUSAL-NONE")
        self.assertEqual(result["untrusted_device_output"], status)


if __name__ == "__main__":
    unittest.main()
