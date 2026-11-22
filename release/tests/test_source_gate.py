import hashlib
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("source_gate", ROOT / "release/check_source.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

VM_FINDING = "lab identifier (vm number)"
SYNTHETIC_HOST = "synthetic-lab-host"
SYNTHETIC_DOMAIN = "synthetic.zone"

def fingerprint(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def synthetic_fingerprints():
    """A test copy of the fingerprint list with neutral tokens that name no real lab."""
    return mock.patch.dict(gate.LAB_IDENTIFIER_FINGERPRINTS,
                           {fingerprint(SYNTHETIC_HOST): "host name", fingerprint(SYNTHETIC_DOMAIN): "domain name"})

class PublicLabIdentifiers(unittest.TestCase):
    def scan_file(self, relative, text):
        with TemporaryDirectory() as directory:
            path = Path(directory) / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            return gate.lab_identifier_errors(relative, path.read_text(encoding="utf-8"))

    def assert_line_findings(self, value, kinds, relative="docs/example.md"):
        findings = self.scan_file(relative, f"heading\n\nexample `{value}` in text\n")
        self.assertEqual(findings, [f"{relative}:3: lab identifier ({kind})" for kind in kinds])
        for finding in findings:
            self.assertNotIn(value.lower(), finding.lower())

    def test_general_lab_shapes_report_only_their_type_and_line(self):
        cases = (
            ("VM987", ("vm number",)), ("vm987", ("vm number",)), ("vm 987", ("vm number",)),
            ("Vm_987", ("vm number",)), ("vM-987", ("vm number",)),
            ("rpi" + "5-test", ("host name",)), ("RPI" + "4-log", ("host name",)),
            ("192.168." + "1.9", ("internal address",)), ("10.255." + "1.9", ("internal address",)),
            ("FGT" + "0AB0000001", ("serial number",)), ("fgt" + "0ab0000001", ("serial number",)),
            ("netops-2026" + "1122-99", ("task reference",)),
            ("netops-t" + "99-example", ("task reference",)), ("Task " + "471-r3", ("task reference",)),
            ("task" + "-557", ("task reference",)), ("task #" + "105", ("task reference",)),
            ("task-" + "evidence/report.json", ("evidence path",)),
            ("VM987 at 192.168." + "1.9", ("vm number", "internal address")),
        )
        for value, kinds in cases:
            with self.subTest(value=value):
                self.assert_line_findings(value, kinds)

    def test_fingerprinted_lab_names_match_whole_tokens_and_their_parts(self):
        with synthetic_fingerprints():
            for value, kinds in (
                (SYNTHETIC_HOST, ("host name",)),
                (SYNTHETIC_HOST.upper(), ("host name",)),
                (SYNTHETIC_HOST + "-wsl", ("host name",)),
                ("node." + SYNTHETIC_HOST + ".", ("host name",)),
                ("nas." + SYNTHETIC_DOMAIN, ("domain name",)),
                (SYNTHETIC_HOST + "." + SYNTHETIC_DOMAIN, ("host name", "domain name")),
            ):
                with self.subTest(value=value):
                    self.assert_line_findings(value, kinds)
            for value in ("x" + SYNTHETIC_HOST, SYNTHETIC_HOST + "x", SYNTHETIC_HOST + "_extra",
                          "synthetic lab host", "synthetic.zones"):
                with self.subTest(value=value):
                    self.assertEqual(self.scan_file("docs/example.md", value), [])

    def test_escaped_identifiers_keep_their_line_number(self):
        escaped = chr(92) + "u0056M987"
        with synthetic_fingerprints():
            host = SYNTHETIC_HOST.replace("h", chr(92) + "x68")
            self.assertEqual(self.scan_file("docs/example.json", '{\n  "a": "' + escaped + '",\n  "b": "' + host + '"\n}\n'),
                             ["docs/example.json:2: " + VM_FINDING, "docs/example.json:3: lab identifier (host name)"])

    def test_fingerprint_list_holds_only_digests_of_known_types(self):
        self.assertTrue(gate.LAB_IDENTIFIER_FINGERPRINTS)
        for digest, kind in gate.LAB_IDENTIFIER_FINGERPRINTS.items():
            with self.subTest(digest=digest):
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
                self.assertIn(kind, {"host name", "lab name", "domain name", "device name", "account name"})

    def test_public_markdown_and_docs_json_are_in_scope(self):
        for relative in ("README.md", "CHANGELOG.md", "release/notes-1.0.9.md", "docs/example.md",
                         "docs/tests/guide.md", "docs/tests/example.json", "docs/fixtures/nested/example.json",
                         "fixtures/example.md", "components/netops-core/docs/guide.md",
                         "components/x/docs/a.json", "components/x/docs/tests/nested/a.json",
                         "docs/example.json", "docs/nested/example.json"):
            with self.subTest(relative=relative):
                self.assertEqual(self.scan_file(relative, '{\n  "device": "VM987"\n}\n'),
                                 [f"{relative}:2: {VM_FINDING}"])

    def test_product_names_models_and_documentation_addresses_are_allowed(self):
        text = ("FG-60F, FortiGate-80F, FortiADC-KVM 7.6.7, X440-G2, 192.0.2.10, 2001:db8::1, VMware\n"
                "XVM987, VM9870, IOSv, IOL-L2 XE 17.18.2, netops-api-ro\n"
                "RPi5 (Raspberry Pi OS 64-bit), Raspberry Pi 5, RPi4, a task list, task 1, the tasks\n")
        self.assertEqual(self.scan_file("docs/example.md", text), [])

    def test_model_abbreviation_passes_the_privacy_check(self):
        rules = gate.legacy(ROOT)
        for text in ("RPi5 (Raspberry Pi OS 64-bit)", "Raspberry Pi 5 with 8 GB RAM"):
            with self.subTest(text=text):
                self.assertEqual(gate.privacy_text(rules, "README.md", text), [])

    def test_tests_fixtures_and_code_are_out_of_scope(self):
        for relative in ("tests/README.md", "tests/unit/fixtures/example.md", "release/tests/example.md",
                         "release/tests/fixtures/example.md", "components/netops-core/tests/example.md",
                         "components/netops-core/tests/fixtures/example.md", "docs/example.py",
                         "release/example.json", "components/x/example.json"):
            with self.subTest(relative=relative):
                self.assertEqual(self.scan_file(relative, '"VM987"\n'), [])

    def test_ip_prefixes_inside_addresses_are_allowed(self):
        for address in ("7." + "10.255.1", "7." + "192.168.1", "110.255." + "1.2", "1192.168." + "1.2"):
            with self.subTest(address=address):
                self.assertEqual(self.scan_file("docs/example.md", address), [])

class Privacy(unittest.TestCase):
    def setUp(self):
        self.rules = gate.legacy(ROOT)
    def test_os_brand_and_official_client_documentation_are_public(self):
        self.assertEqual(gate.privacy_text(self.rules, "README.md", "Raspberry Pi OS 64; https://learn.chatgpt.com/docs/extend/mcp; ghcr.io"), [])
    def test_only_the_discord_webhook_hosts_are_public(self):
        for domain, accepted in (("discord.com", True), ("discordapp.com", True), ("notdiscord.com", False),
                                 ("discord-app.com", False), ("discord.com.lab.lan", False), ("discordapp.net", False)):
            with self.subTest(domain=domain):
                text = "Use an HTTPS webhook on `" + domain + "` with path `/api/webhooks/ID/TOKEN`.\n"
                self.assertEqual(not gate.privacy_text(self.rules, "docs/helper-configuration.md", text), accepted)
    def test_device_identifiers_and_credential_shapes_are_rejected(self):
        material = "-----BEGIN PRIVATE" + " KEY-----" + chr(10) + "MIIA" + "A" * 120 + chr(10) + "-----END PRIVATE" + " KEY-----"
        for text in ("rpi5" + "-master", "Host 10." + "29.41.55", material):
            with self.subTest(text=text):
                self.assertTrue(gate.privacy_text(self.rules, "README.md", text))
    def test_json_escapes_cannot_hide_private_values_or_keys(self):
        import json
        values = ("/"+"home"+"/fixture-owner/private", "rpi"+"5-master", "gh"+"p_"+"A"*36)
        for value in values:
            for is_key in (False, True):
                with self.subTest(value=value, is_key=is_key):
                    document = {value: "neutral"} if is_key else {"detail": value}
                    raw = json.dumps(document)
                    raw = raw.replace("home", "h"+chr(92)+"u006fme")
                    raw = raw.replace("rpi5", "rp"+chr(92)+"u00695")
                    raw = raw.replace("ghp_", "gh"+chr(92)+"u0070_")
                    self.assertTrue(gate.privacy_text(self.rules, "docs/report.json", raw))

    def test_non_json_and_malformed_json_escapes_are_scanned(self):
        for suffix in (".py", ".ps1", ".yaml", ".example", ".md", ".json"):
            for code in ("x70", "u0070", "U00000070"):
                raw = "VALUE=gh" + chr(92) + code + "_" + "A"*36
                with self.subTest(suffix=suffix, code=code):
                    self.assertTrue(gate.privacy_text(self.rules, "fixture"+suffix, raw))

    def test_archived_paths_have_no_escape_exemption(self):
        raw = "VALUE=gh" + chr(92) + "u0070_" + "A"*36
        for relative in ("docs/archive/0.x/standalone-layout/components/netops-helper/tests/test_supply_chain.py",
                         "docs/archive/0.x/fixture.py", "docs/archive/0.x/fixture.json"):
            with self.subTest(relative=relative):
                self.assertTrue(gate.privacy_text(self.rules, relative, raw))

    def test_excessive_escape_nesting_fails_closed(self):
        value = chr(92) + "u0070"
        for _ in range(12):
            value = value.replace(chr(92), chr(92) + "u005c")
        self.assertTrue(gate.privacy_text(self.rules, "docs/deep.txt", "gh"+value+"_"+"A"*36))

    def test_documentation_addresses_are_accepted(self):
        self.assertEqual(gate.privacy_text(self.rules, "README.md", "192.0.2.10; 2001:db8::1; example.invalid"), [])
        for sample in ("198.51.100.7", "203.0.113.9", "127.0.0.11", "255.255.255.0",
                       "fe80::1", "runner.example", "github.com", "Build 1.2.3.4.5 and 33.7.1.6."):
            with self.subTest(sample=sample):
                self.assertEqual(gate.privacy_text(self.rules, "README.md", sample), [])

    def test_protocol_constants_and_derived_solicited_node_groups_are_accepted(self):
        # task 749: constants of the Admin fixtures and tests that are not site material
        for sample in ("ff:ff:ff:ff:ff:ff", "FF:FF:FF:FF:FF:FF", "01:00:5e:90:10:01", "01:00:5E:90:10:FF",
                       "firmware 200.15.6.212 build 27", "permit ip 203.0.113.176 0.0.0.254 any",
                       "FF02::1:FF00:1", "ff02::1:ff00:12", "ff02::1:ff00:0", "FF02::1:FF00:5300"):
            with self.subTest(sample=sample):
                self.assertEqual(gate.privacy_text(self.rules, "fixtures/sample.txt", sample), [])

    def test_other_multicast_versions_masks_and_solicited_node_tails_stay_refused(self):
        # a solicited-node group keeps the low 24 bits of the unicast address: groups whose 24-bit suffix has a
        # non-zero high byte (ff55, fffc, FF12) stay refused, as does the ff05 group outside the solicited-node range
        for sample in ("ff02::1:" + "ff55:0", "ff02::1:" + "fffc:0", "FF02::1:" + "FF12:3456", "ff05::1:" + "ff00:1",
                       "224.0." + "0.9", "01:00:5e:" + "00:00:09", "01:00:5e:" + "90:11:01", "200.15." + "6.213",
                       "0.0." + "0.253", "fe:ff:ff:" + "ff:ff:ff"):
            with self.subTest(sample=sample):
                self.assertIn("network or domain material in fixtures/sample.txt",
                              gate.privacy_text(self.rules, "fixtures/sample.txt", sample))

    def test_source_domains_and_sentence_ending_addresses_are_refused(self):
        relative = "docs/source-gate-fixture.md"
        for payload, marker in (
            ("mail to mail." + "operator-domain.cz\n", "holds a domain outside"),
            ("The management address is 10.0" + ".0.1.\n", "holds an address"),
            ("The peer is fd12:3456" + ":789a::1.\n", "holds an IPv6 address"),
            ("The mirror is operator-domain" + ".cz.\n", "holds a domain outside"),
        ):
            with self.subTest(payload=payload):
                text = "# note\n\n" + payload
                errors = self.rules._address_errors(relative, text, True)
                self.assertTrue(any(marker in error for error in errors), errors)
                self.assertIn("network or domain material in " + relative,
                              gate.privacy_text(self.rules, relative, text))

    def test_every_private_key_pem_header_requires_material_rejection(self):
        relative = "fixture.py"
        payload = "MII" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef" * 2
        for header in ("OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
                       "ENCRYPTED PRIVATE KEY", "PRIVATE KEY"):
            with self.subTest(header=header):
                text = "VALUE = 1\n# -----BEGIN {0}-----\n# {1}\n# -----END {0}-----\n".format(header, payload)
                self.assertIn("private key material in " + relative,
                              gate.privacy_text(self.rules, relative, text))
        self.assertEqual(gate.privacy_text(
            self.rules, relative,
            "VALUE = 1\n# -----BEGIN PRIVATE KEY----- (marker only, no material)\n"), [])

    def test_diagnostic_multicast_exception_requires_its_negative_fixture(self):
        import ipaddress
        relative = "components/netops-helper/tests/test_fortios_diagnostics.py"
        source = (ROOT / relative).read_text(encoding="utf-8")
        self.assertEqual(self.rules._address_errors(relative, source, False), [])
        self.assertTrue(self.rules._address_errors("tests/other.py", source, False))
        for before, after in (
            ("def test_invalid_request(kwargs):", "def test_accepted_request(kwargs):"),
            ("values.update(kwargs)", "pass"),
            ("values.update(kwargs)", "values.update(kwargs)\n    values.clear()"),
            ("pytest.raises(ValueError)", "pytest.raises(AssertionError)"),
            ("d.validate(**values)", "d.authorize(**values)"),
        ):
            with self.subTest(before=before, after=after):
                self.assertIn(before, source)
                self.assertTrue(self.rules._address_errors(
                    relative, source.replace(before, after, 1), False))
        address = str(ipaddress.IPv4Address(0xE0000001))
        self.assertTrue(self.rules._address_errors(
            relative, source + "\nOTHER = " + repr(address) + "\n", False))
        private_source = source.replace(address, str(ipaddress.ip_address(0xC0A80A14)))
        self.assertTrue(self.rules._address_errors(relative, private_source, False))

    def test_real_exos_exceptions_are_bound_to_their_files_and_layouts(self):
        import ipaddress
        version = str(ipaddress.ip_address(0x03000002))
        row = "acl              " + version + "     0    Ready        Mon Oct 19 14:47:28 2026  Vital\n"
        processes = "components/netops-helper/tests/fixtures/real/exos/x435-8p-4s_33.7.1.6/processes.txt"
        self.assertEqual(self.rules._address_errors(processes, row, True), [])
        for relative, text in ((processes.replace("processes", "arp_table"), row),
                               ("components/netops-helper/tests/fixtures/docs/processes.txt", row),
                               (processes, "gateway " + version + "\n")):
            with self.subTest(relative=relative, text=text):
                self.assertTrue(self.rules._address_errors(relative, text, True))
        event = "11/08/2026 22:15:28.34 <Info:HAL.Card.Info> Switch is operational\n"
        log = "components/netops-helper/tests/fixtures/real/exos/exosvm_33.6.1.14/log_messages.txt"
        self.assertEqual(self.rules._address_errors(log, event, True), [])
        self.assertTrue(self.rules._address_errors("docs/example.md", event, True))
        self.assertTrue(self.rules._address_errors(log, "server HAL.Card.Info\n", True))

    def test_bridge_identifiers_pass_only_with_a_documentation_mac(self):
        documented = "BridgeID : 80:00:00:00:5e:00:53:0a\n"
        self.assertEqual(self.rules._address_errors("fixture.txt", documented, True), [])
        private = "BridgeID : 80:00:" + ":".join("%02x" % part for part in (0x3C, 0x2A, 0xF4, 0x11, 0x22, 0x33)) + "\n"
        self.assertTrue(self.rules._address_errors("fixture.txt", private, True))

    def test_only_the_listed_well_known_multicast_groups_are_accepted(self):
        import ipaddress
        for value, accepted in ((0xE0000005, True), (0xE0000006, True), (0xE0000012, True), (0xE0000001, False),
                                (0xE0000007, False), (0xEF010203, False)):
            text = "group " + str(ipaddress.ip_address(value)) + "\n"
            with self.subTest(value=value):
                self.assertEqual(not self.rules._address_errors("fixture.txt", text, True), accepted)

    def test_only_the_broadcast_mac_constant_is_accepted(self):
        for octets, accepted in (((0xFF,) * 6, True), ((0xFF,) * 5 + (0xFE,), False), ((0x7F,) + (0xFF,) * 5, False),
                                 ((0x01, 0x00, 0x5E, 0x00, 0x00, 0x05), False), ((0x33, 0x33, 0, 0, 0, 1), False)):
            value = ":".join("%02x" % octet for octet in octets)
            text = "mac " + value + "\n"
            with self.subTest(value=value):
                self.assertEqual(not self.rules._address_errors("fixture.txt", text, True), accepted)
                self.assertEqual(not gate.privacy_text(self.rules, "fixture.json", '{"mac": "' + value + '"}'), accepted)
                self.assertEqual(not self.rules._address_errors("fixture.txt", text.upper(), True), accepted)

    def test_network_mac_path_and_credential_material_are_refused(self):
        import ipaddress
        values = (
            str(ipaddress.ip_address(0x08080808)),
            str(ipaddress.ip_address(0xC0A80102)),
            str(ipaddress.ip_address(0x64400307)),
            str(ipaddress.ip_address((0xFD12 << 112) + (0x3456 << 96) + 1)),
            str(ipaddress.ip_address((0xFE80 << 112) + (0x1234 << 16) + 0xABCD)),
            ":".join("%02x" % part for part in (0x3C,0x2A,0xF4,0x11,0x22,0x33)),
            "/" + "home" + "/fixture-owner/private",
            "gh" + "p_" + "A" * 36,
        )
        for value in values:
            with self.subTest(value=value):
                self.assertTrue(gate.privacy_text(self.rules, "docs/example.md", value))

    def test_test_kit_name_and_private_evidence_paths_are_refused(self):
        for value in ("IT-" + "kufr", "IT " + "kufr", "it-" + "Kufr", "work/" + "claude-105-x/result.json",
                      "see work/" + "codex-105-x/notes.md"):
            with self.subTest(value=value):
                self.assertTrue(gate.privacy_text(self.rules, "docs/example.md", value))
        self.assertTrue(gate.privacy_text(self.rules, "work/" + "claude-105-x/result.json", "neutral"))
        for value in ("network/claude-client", "the work/ directory", "framework/codex-cli"):
            with self.subTest(value=value):
                self.assertEqual(gate.privacy_text(self.rules, "docs/example.md", value), [])

    def test_repeated_privacy_scan_has_a_bounded_runtime(self):
        import subprocess, sys
        script = (
            "import importlib.util,pathlib,sys;"
            "p=pathlib.Path(sys.argv[1]);"
            "s=importlib.util.spec_from_file_location('public_source',p/'release/check_source.py');"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);r=m.legacy(p);"
            "text='generic Linux ARM64 builder documentation; '+chr(10);"
            "assert all(m.privacy_text(r,'docs/performance.md',text*25000)==[] for _ in range(3))"
        )
        result = subprocess.run([sys.executable,"-B","-c",script,str(ROOT)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

SCHEMA_DIR = "release/schema/cyclonedx-1.7/"
SCHEMA_FILES = ("PROVENANCE.json", "bom-1.7.schema.json", "cryptography-defs.schema.json",
                "jsf-0.82.schema.json", "spdx.schema.json")

class VendoredSchemas(unittest.TestCase):
    def setUp(self):
        self.rules = gate.legacy(ROOT)

    def scan(self, relative, text):
        return gate.privacy_text(self.rules, relative, text)

    def source(self, name):
        return (ROOT / SCHEMA_DIR / name).read_bytes().decode("utf-8")

    def test_pinned_vendored_schemas_pass_only_their_domain_scan(self):
        for name in SCHEMA_FILES:
            with self.subTest(name=name):
                text = self.source(name)
                self.assertTrue(self.rules._address_errors(SCHEMA_DIR + name, text, True))
                self.assertEqual(self.scan(SCHEMA_DIR + name, text), [])

    def test_any_changed_byte_restores_the_domain_scan(self):
        for name in SCHEMA_FILES:
            text = self.source(name)
            index = text.index('"', len(text) // 2)
            for changed in (text + chr(10), text[:-1], text[:index] + "'" + text[index + 1:]):
                with self.subTest(name=name, size=len(changed)):
                    self.assertIn("network or domain material in " + SCHEMA_DIR + name,
                                  self.scan(SCHEMA_DIR + name, changed))

    def test_other_privacy_checks_still_apply_to_vendored_paths(self):
        import hashlib, ipaddress
        from unittest import mock
        relative = SCHEMA_DIR + "spdx.schema.json"
        text = self.source("spdx.schema.json")
        for payload, reason in (
            ('"rpi' + '5-master"', "private marker in "),
            ('"gh' + 'p_' + "A" * 36 + '"', "credential-shaped material in "),
            ('"' + str(ipaddress.ip_address(0xC0A80A14)) + '"', "network or domain material in "),
            ('"' + str(ipaddress.ip_address((0xFD12 << 112) + (0x3456 << 96) + 1)) + '"', "network or domain material in "),
            ('"' + ":".join("%02x" % part for part in (0x3C, 0x2A, 0xF4, 0x11, 0x22, 0x33)) + '"',
             "network or domain material in "),
        ):
            changed = text.replace('"enum": [', '"enum": [' + payload + ", ", 1)
            self.assertNotEqual(changed, text)
            with self.subTest(payload=payload):
                self.assertIn(reason + relative, self.scan(relative, changed))
                repinned = {relative: hashlib.sha256(changed.encode("utf-8")).hexdigest()}
                with mock.patch.dict(gate.VENDORED_SCHEMA_PINS, repinned):
                    self.assertIn(reason + relative, self.scan(relative, changed))
        domain_only = text.replace('"enum": [', '"enum": ["operator-domain' + '.cz", ', 1)
        repinned = {relative: hashlib.sha256(domain_only.encode("utf-8")).hexdigest()}
        with mock.patch.dict(gate.VENDORED_SCHEMA_PINS, repinned):
            self.assertEqual(self.scan(relative, domain_only), [])

    def test_identical_content_outside_the_pinned_paths_is_scanned(self):
        text = self.source("bom-1.7.schema.json")
        for relative in ("docs/bom-1.7.schema.json", SCHEMA_DIR + "copy/bom-1.7.schema.json",
                         SCHEMA_DIR + "extra.schema.json", "release/schema/bom-1.7.schema.json"):
            with self.subTest(relative=relative):
                self.assertIn("network or domain material in " + relative, self.scan(relative, text))
        self.assertIn("network or domain material in docs/source.json",
                      self.scan("docs/source.json", '{"source": "https://operator-domain' + '.cz/x"}'))

    def test_pins_match_provenance_and_the_sbom_gate(self):
        import ast, hashlib, json
        provenance = json.loads(self.source("PROVENANCE.json"))
        recorded = {SCHEMA_DIR + item["file"]: item["sha256"]
                    for item in provenance["files"] if item["file"].endswith(".json")}
        tree = ast.parse((ROOT / "release/sbom_gate.py").read_text())
        pins = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "PINS" for t in node.targets))
        self.assertEqual(recorded, {SCHEMA_DIR + name: sha for name, sha in pins.items()})
        provenance_path = SCHEMA_DIR + "PROVENANCE.json"
        expected = dict(recorded)
        expected[provenance_path] = hashlib.sha256((ROOT / provenance_path).read_bytes()).hexdigest()
        self.assertEqual(gate.VENDORED_SCHEMA_PINS, expected)
        for relative, sha in expected.items():
            self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), sha)

class BuildInputs(unittest.TestCase):

    def test_runtime_bootstrap_source_is_in_the_narrow_build_context(self):
        source = ROOT / "release/start.c"
        self.assertTrue(source.is_file())
        self.assertFalse(source.is_symlink())
        self.assertIn("COPY release/start.c /build/start.c",
                      (ROOT / "Dockerfile").read_text().splitlines())
        self.assertIn("!release/" + chr(10) + "release/**" + chr(10) +
                      "!release/start.c" + chr(10),
                      (ROOT / ".dockerignore").read_text())

    def test_base_image_and_all_build_inputs_are_pinned_with_hashes(self):
        import re
        first = (ROOT / "Dockerfile").read_text().splitlines()[0]
        self.assertRegex(first, r"^FROM python:[^@\s]+@sha256:[0-9a-f]{64} AS base$")
        for name in ("requirements.lock", "build-requirements.lock"):
            with self.subTest(name=name):
                text = (ROOT / name).read_text()
                active = chr(10).join(line for line in text.splitlines()
                                     if not line.lstrip().startswith("#"))
                self.assertIn("--hash=sha256:", active)
                for forbidden in ("--trusted-host", "http://", "file:", "--no-index"):
                    self.assertNotIn(forbidden, active)

    def test_optional_build_ca_reaches_only_the_downloading_steps_as_a_secret(self):
        for name, steps in (("Dockerfile", 4), ("release/engine-regression.Dockerfile", 1)):
            with self.subTest(dockerfile=name):
                self.check_optional_build_ca((ROOT / name).read_text(), steps)

    def check_optional_build_ca(self, text, steps):
        lines = text.splitlines()
        mount = "RUN --mount=type=secret,id=extra_ca,required=false --mount=type=tmpfs,target=/run/netops-ca \\"
        bundle = ("    if [ -s /run/secrets/extra_ca ]; then cat /etc/ssl/certs/ca-certificates.crt /run/secrets/extra_ca"
                  " > /run/netops-ca/ca.pem && export PIP_CERT=/run/netops-ca/ca.pem"
                  " SSL_CERT_FILE=/run/netops-ca/ca.pem; fi \\")
        downloads = [index for index, line in enumerate(lines)
                     if "apk " in line or ("pip install" in line and "--no-index" not in line)]
        self.assertEqual(len(downloads), steps)
        for index in downloads:
            with self.subTest(line=lines[index]):
                self.assertEqual(lines[index - 2:index], [mount, bundle])
                self.assertTrue(lines[index].startswith("    && "))
        self.assertEqual(text.count("extra_ca"), 3 * len(downloads))
        self.assertEqual(text.count("/run/netops-ca/ca.pem"), 3 * len(downloads))
        for line in lines:
            if line.split(" ", 1)[0] in ("COPY", "ADD", "ENV", "ARG"):
                self.assertNotIn("extra_ca", line)
                self.assertNotIn("netops-ca", line)

    def test_wheel_is_built_with_the_commit_time_as_source_date_epoch(self):
        import re
        lines = (ROOT / "Dockerfile").read_text().splitlines()
        builder = lines.index("FROM base AS builder")
        runtime = lines.index("FROM base AS runtime")
        stage = lines[builder:runtime]
        self.assertEqual(stage[1], "ARG SOURCE_DATE_EPOCH")
        wheel = next(index for index, line in enumerate(stage) if "pip wheel" in line)
        guard = max(index for index, line in enumerate(stage[:wheel + 1]) if line.startswith("RUN "))
        self.assertTrue(stage[guard].startswith('RUN case "$SOURCE_DATE_EPOCH" in ""|*[!0-9]*) '))
        self.assertIn("exit 1;; esac", stage[guard])
        commit_time = '--build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"'
        # candidate.yml builds the product once; ci.yml builds it once in every job that tests it
        # (the unit shards and the engine roles run as parallel jobs on separate runners)
        for workflow, build, jobs in (("candidate.yml", "docker buildx build ", ("build",)),
                                      ("ci.yml", "docker build ", ("unit", "engine"))):
            with self.subTest(workflow=workflow):
                text = (ROOT / ".github/workflows" / workflow).read_text().replace("\\\n", " ")
                sections = re.split(r"(?m)^  ([a-z][a-z0-9_-]*):\n", text.split("\njobs:\n", 1)[1])[1:]
                builders = {}
                for job, body in zip(sections[::2], sections[1::2]):
                    calls = [line for line in body.splitlines() if build in line and " -f " not in line]
                    if calls:
                        builders[job] = calls
                self.assertEqual(sorted(builders), sorted(jobs))
                for job, calls in builders.items():
                    with self.subTest(job=job):
                        self.assertEqual(len(calls), 1)
                        self.assertIn(commit_time, calls[0])

class SharedProductBoundaries(unittest.TestCase):
    def setUp(self):
        import tempfile, shutil, subprocess
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        files = ["pyproject.toml", "src/netops/__init__.py", "scripts/check_release.py", "README.md",
                 ".github/workflows/ci.yml", ".github/workflows/candidate.yml", ".github/workflows/codeql.yml"]
        for role in ("core","helper","auditor","admin"):
            files += ["components/netops-"+role+"/pyproject.toml",
                      "components/netops-"+role+"/src/netops_"+role+"/__init__.py"]
        for name in files:
            target=self.root/name
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(ROOT/name,target)
        subprocess.run(["git","init","-q",str(self.root)],check=True,capture_output=True)
        subprocess.run(["git","-C",str(self.root),"add","."],check=True,capture_output=True)
        self.assertEqual(gate.check(self.root),[])

    def test_tracked_public_docs_block_the_source_gate(self):
        import subprocess

        relative = "release/notes-1.0.9.md"
        path = self.root / relative
        path.parent.mkdir()
        path.write_text("# Release note\nVerified VM987.\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", relative], check=True, capture_output=True)
        self.assertEqual(gate.check(self.root), [f"{relative}:2: {VM_FINDING}"])

    def test_only_root_task_artifacts_are_excluded_from_the_lab_identifier_check(self):
        import subprocess

        public = ("docs/TASK.md", "docs/RESULT.md", "docs/ref/review.md")
        for relative in ("TASK.md", "RESULT.md", "ref/review.md", "ref/nested/result.md", *public):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("Verified vm987.\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True, capture_output=True)
        self.assertEqual(gate.check(self.root), [f"{relative}:1: {VM_FINDING}" for relative in sorted(public)])

    def test_task_artifacts_keep_the_other_source_checks(self):
        import subprocess

        (self.root / "ref").mkdir(exist_ok=True)
        (self.root / "ref/invalid.md").write_bytes(b"\xff")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True, capture_output=True)
        self.assertIn("unreadable tracked text: ref/invalid.md", gate.check(self.root))

    def test_single_version_mismatch_blocks_the_source(self):
        p=self.root/"src/netops/__init__.py"
        p.write_text('__version__ = "9.0.0"\n')
        self.assertIn("installed product version differs from project metadata",gate.check(self.root))

    def test_product_version_series(self):
        import re
        metadata = self.root / "pyproject.toml"
        original = metadata.read_text()
        for version, allowed in (("1.0.0", True), ("1.0.11", True),
                                 ("0.9.9", False), ("1.1.0", False), ("2.0.0", False)):
            with self.subTest(version=version):
                metadata.write_text(re.sub(r'(?m)^version = "[^"]+"$',
                                           'version = "' + version + '"', original))
                (self.root / "src/netops/__init__.py").write_text('__version__ = "' + version + '"\n')
                errors = gate.check(self.root)
                self.assertEqual("product version must be 1.0.x" not in errors, allowed)
                self.assertNotIn("installed product version differs from project metadata", errors)

    def test_engines_cannot_declare_separate_distributions(self):
        p=self.root/"components/netops-core/pyproject.toml"
        p.write_text(p.read_text()+'\n[project]\nname = "separate-package"\nversion = "1.0.0"\n')
        self.assertTrue(any("shared engine identity" in e for e in gate.check(self.root)))

    def test_core_remains_standard_library_only(self):
        p=self.root/"components/netops-core/src/netops_core/__init__.py"
        p.write_text(p.read_text()+"\nimport requests\n")
        self.assertTrue(any("unexpected Core dependency" in e for e in gate.check(self.root)))

    def test_nested_core_modules_cannot_import_third_party_packages(self):
        p=self.root/"components/netops-core/src/netops_core/nested/added.py"
        p.parent.mkdir()
        p.write_text("import requests"+chr(10))
        self.assertTrue(any("unexpected Core dependency" in e for e in gate.check(self.root)))

    def test_core_cannot_import_the_gateway_via_the_shared_product(self):
        p=self.root/"components/netops-core/src/netops_core/__init__.py"
        p.write_text(p.read_text()+chr(10)+"from netops import gateway"+chr(10))
        self.assertIn("Core may import only the shared product version",gate.check(self.root))

    def test_all_engine_versions_come_from_the_product(self):
        p=self.root/"components/netops-helper/src/netops_helper/__init__.py"
        p.write_text('__version__ = "1.0.0"\n')
        self.assertIn("component does not import product version: helper",gate.check(self.root))

    def test_clean_tree_with_vendored_schemas_passes_and_a_changed_byte_fails(self):
        import shutil, subprocess
        for name in SCHEMA_FILES:
            target = self.root / SCHEMA_DIR / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / SCHEMA_DIR / name, target)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True, capture_output=True)
        self.assertEqual(gate.check(self.root), [])
        target = self.root / SCHEMA_DIR / "jsf-0.82.schema.json"
        target.write_bytes(target.read_bytes() + b"\n")
        self.assertEqual(gate.check(self.root),
                         ["network or domain material in " + SCHEMA_DIR + "jsf-0.82.schema.json"])
        shutil.copy2(ROOT / SCHEMA_DIR / "jsf-0.82.schema.json", target)
        self.assertEqual(gate.check(self.root), [])
        provenance = self.root / SCHEMA_DIR / "PROVENANCE.json"
        provenance.write_bytes(provenance.read_bytes().replace(b'"unmodified": true', b'"unmodified": false'))
        self.assertEqual(gate.check(self.root),
                         ["network or domain material in " + SCHEMA_DIR + "PROVENANCE.json"])
        shutil.copy2(ROOT / SCHEMA_DIR / "PROVENANCE.json", provenance)
        for extra in (SCHEMA_DIR + "bom-1.8.schema.json", "docs/bom-1.7.schema.json"):
            path = self.root / extra
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / SCHEMA_DIR / "bom-1.7.schema.json", path)
            subprocess.run(["git", "-C", str(self.root), "add", extra], check=True, capture_output=True)
            with self.subTest(extra=extra):
                self.assertEqual(gate.check(self.root), ["network or domain material in " + extra])
            subprocess.run(["git", "-C", str(self.root), "rm", "-q", "--cached", extra], check=True, capture_output=True)
            path.unlink()
        self.assertEqual(gate.check(self.root), [])
        outside = self.root / "outside-bom.json"
        shutil.copy2(ROOT / SCHEMA_DIR / "bom-1.7.schema.json", outside)
        linked = self.root / SCHEMA_DIR / "bom-1.7.schema.json"
        linked.unlink()
        linked.symlink_to(outside)
        errors = gate.check(self.root)
        self.assertIn("tracked path is not a single regular file: " + SCHEMA_DIR + "bom-1.7.schema.json", errors)
        self.assertTrue(errors)

    def test_tracked_source_refuses_symlinks_nul_and_invalid_utf8(self):
        import ipaddress, subprocess
        relative = "docs/source-gate-fixture.md"
        path = self.root / relative
        path.parent.mkdir()
        path.write_text("# public fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", relative],
                       check=True, capture_output=True)
        self.assertEqual(gate.check(self.root), [])
        target = self.root / "src/netops/__init__.py"
        before = target.read_bytes()
        path.unlink()
        path.symlink_to(target)
        try:
            self.assertIn("tracked path is not a single regular file: " + relative,
                          gate.check(self.root))
        finally:
            path.unlink()
        self.assertEqual(target.read_bytes(), before)
        address = str(ipaddress.ip_address(0xC0A80A14))
        for label, data, reason in (
            ("NUL", ("VALUE = 1  # {0}\n".format(address)).encode("utf-16-le"), "NUL in text: "),
            ("UTF8", b"\xff\xfe", "unreadable tracked text: "),
        ):
            with self.subTest(kind=label):
                path.write_bytes(data)
                self.assertIn(reason + relative, gate.check(self.root))
        path.write_text("# public fixture\n", encoding="utf-8")
        self.assertEqual(gate.check(self.root), [])

class ReleaseVersionText(unittest.TestCase):
    def setUp(self):
        import tomllib
        self.version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
        self.readme = (ROOT / "README.md").read_text(encoding="utf-8")
    def test_current_readme_matches_the_version(self):
        self.assertEqual(gate.readme_version_errors(self.readme, self.version), [])
    def test_readme_of_another_release_is_refused(self):
        v = self.version
        for old, new in (("This README describes NetOps " + v + ",", "This README describes NetOps 0.9.9,"),
                         ("releases/download/v" + v + "/", "releases/download/v0.9.9/"),
                         ("netops-" + v + "-SHA256SUMS ", "netops-0.9.9-SHA256SUMS "),
                         ("**Acceptance of " + v + ":**", "**Acceptance of 0.9.9:**")):
            with self.subTest(old=old):
                self.assertIn(old, self.readme)
                self.assertTrue(gate.readme_version_errors(self.readme.replace(old, new, 1), v))

TESTED = ("**Tested for NetOps %s (2026-01-02)** against a build.\n\n| Client | Version | Platform | Model | Result |\n"
          "|---|---|---|---|---|\n| Codex CLI | 1 | Linux | default | PASS |\n")
PENDING = ("**NetOps %s:** the client acceptance (Codex CLI and Claude Code) runs once on the signed release candidate image; "
           "its results are in the [release notes](release/notes-%s.md#acceptance).\n")

class ReleaseSupportText(unittest.TestCase):
    def setUp(self):
        import re
        self.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.verified = (ROOT / "docs/verified-support.md").read_text(encoding="utf-8")
        self.version = re.search(r"^Live verification of NetOps (\d+\.\d+\.\d+) on ", self.readme, re.M).group(1)
        self.line = next(line for line in self.readme.splitlines() if line.startswith("Live verification of NetOps "))
        # as check_source.check: the pending-acceptance line is accepted only when the release notes exist
        self.notes_exist = (ROOT / f"release/notes-{self.version}.md").is_file()
    def test_current_support_text_names_the_live_verification(self):
        self.assertEqual(gate.support_errors(self.readme, self.verified, self.version, self.notes_exist), [])
    def test_stale_or_incomplete_support_text_is_refused(self):
        # A synthetic section, so that the mutations do not depend on how many live lines and platforms
        # the current README names; the current README itself is checked by the test above.
        v = self.version
        line = "Live verification of NetOps %s on 2026-01-02: FortiOS 8.0.2 build0251 and FortiADC 7.6.7 build0676." % v
        readme = ("## Supported devices and firmware\n\n| Platform | Documented scope |\n|---|---|\n"
                  "| FortiOS | 8.0.2 build0251 |\n| FortiADC | FortiADC-KVM 7.6.7 build0676 |\n\n" + line + "\n\n"
                  "## Next\n\n#### Tested MCP clients\n\n" + TESTED % v)
        verified = "Live verification of NetOps %s." % v
        self.assertEqual(gate.support_errors(readme, verified, v), [])
        build, first, last = "build0251", "8.0.2 build0251", "7.6.7 build0676"
        mcp = readme.index("#### Tested MCP clients")
        for label, changed, verified_text in (
                ("no live line", readme.replace(line + "\n", "", 1), verified),
                ("other release", readme.replace(line, line.replace(v, "0.9.9", 1), 1), verified),
                ("build outside table", readme.replace(line, line.replace(build, "build99999", 1), 1), verified),
                ("wrong version same build", readme.replace(line, line.replace(first, "9.9.9 " + build, 1), 1), verified),
                ("build of another platform", readme.replace(line, line.replace(last, last.split()[0] + " " + build, 1), 1), verified),
                ("build without version", readme.replace(line, line.replace(first, build, 1), 1), verified),
                ("verified-support stale", readme, verified.replace("NetOps " + v, "NetOps 0.9.9")),
                ("MCP clients stale", readme[:mcp] + readme[mcp:].replace("NetOps " + v, "NetOps 0.9.9"), verified)):
            with self.subTest(label=label):
                self.assertNotEqual(changed + verified_text, readme + verified)
                self.assertTrue(gate.support_errors(changed, verified_text, v))
    def test_client_acceptance_states(self):
        v = self.version
        base = ("## Supported devices and firmware\n\n| Platform | Documented scope |\n|---|---|\n"
                "| FortiOS | 8.0.2 build0251 |\n\n"
                "Live verification of NetOps %s on 2026-01-02: FortiOS 8.0.2 build0251.\n\n## Next\n\n#### Tested MCP clients\n\n" % v)
        verified = "Live verification of NetOps %s." % v
        def errors(clients, notes=True, version=v):
            return gate.support_errors(base + clients, verified, version, notes)
        for label, clients, notes, ok in (
                ("result table", TESTED % v, False, True),
                ("pending line", PENDING % (v, v), True, True),
                ("pending line, no notes file", PENDING % (v, v), False, False),
                ("both", TESTED % v + "\n" + PENDING % (v, v), True, False),
                ("neither", "For NetOps %s, no client application was tested.\n" % v, True, False),
                ("table without result row", TESTED.split("|---")[0] % v, True, False),
                ("pending line of another version", PENDING % ("0.9.9", "0.9.9"), True, False),
                ("pending line altered", (PENDING % (v, v)).replace("runs once", "ran"), True, False),
                ("empty Result cell", (TESTED % v).replace("| PASS |", "| |"), True, False),
                ("row of empty cells only", (TESTED % v).replace("| Codex CLI | 1 | Linux | default | PASS |", "| | | | | |"), True, False),
                ("result not PASS or FAIL", (TESTED % v).replace("| PASS |", "| skipped |"), True, False),
                ("result only outside the Result column", (TESTED % v).replace("| Codex CLI | 1 | Linux | default | PASS |",
                                                                               "| PASS | 1 | Linux | default | |"), True, False),
                ("Result column moved, filled", (TESTED % v).replace("| Client | Version | Platform | Model | Result |",
                    "| Result | Client | Version | Platform | Model |").replace("| Codex CLI | 1 | Linux | default | PASS |",
                    "| PASS: 9 calls | Codex CLI | 1 | Linux | default |"), True, True),
                ("Result PASS with detail", (TESTED % v).replace("| PASS |", "| PASS: Helper role, 9 calls matched |"), True, True),
                ("Result FAIL", (TESTED % v).replace("| PASS |", "| FAIL: wrong token accepted |"), True, True),
                ("one filled row among empty ones", (TESTED % v) + "| Claude Code | 2 | Linux | default | |\n", True, True),
                ("table without Result column", (TESTED % v).replace("| Result |", "| Outcome |"), True, False)):
            with self.subTest(label=label):
                result = errors(clients, notes)
                self.assertEqual(result == [], ok, result)
        self.assertTrue(any("claims and defers" in e for e in errors(TESTED % v + PENDING % (v, v))))
        self.assertIn("README Tested MCP clients for " + v + " has no client result",
                      errors((TESTED % v).replace("| PASS |", "| |")))
    def test_current_readme_has_a_client_result(self):
        import re
        clients = gate.section(self.readme, "#### Tested MCP clients")
        self.assertEqual(gate.client_acceptance_errors(clients, self.version, self.notes_exist), [])
        # either a result table with a PASS or FAIL result, or the exact pending-acceptance line with existing notes
        results = gate.tested_client_results(clients, self.version)
        pending = (PENDING % (self.version, self.version)).rstrip("\n") in clients.splitlines()
        if results is not None:
            self.assertFalse(pending)
            self.assertTrue(any(re.match(r"(PASS|FAIL)\b", r) for r in results), results)
        else:
            self.assertTrue(pending)
            self.assertTrue(self.notes_exist)
    def test_every_live_line_of_the_current_release_is_checked(self):
        import re
        lines = [line for line in self.readme.splitlines() if line.startswith("Live verification of NetOps %s " % self.version)]
        self.assertTrue(lines)
        for line in lines:
            with self.subTest(line=line[:60]):
                stale = (self.readme.replace(line, re.sub(r"\bbuild(\d+)", r"build9\1", line, count=1), 1)
                         if re.search(r"\bbuild\d+", line) else None)
                if stale is not None:
                    self.assertTrue(gate.support_errors(stale, self.verified, self.version))
    def test_support_text_is_checked_only_for_a_release(self):
        import shutil, subprocess, tempfile
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        files = ["pyproject.toml", "src/netops/__init__.py", "scripts/check_release.py", "README.md", "docs/verified-support.md",
                 ".github/workflows/ci.yml", ".github/workflows/candidate.yml", ".github/workflows/codeql.yml"]
        for role in ("core", "helper", "auditor", "admin"):
            files += ["components/netops-" + role + "/pyproject.toml", "components/netops-" + role + "/src/netops_" + role + "/__init__.py"]
        for name in files:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, root / name)
        clients = gate.section(self.readme, "#### Tested MCP clients")
        self.assertTrue(clients)
        (root / "README.md").write_text(self.readme.replace(clients, ""), encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(root), "add", "."], check=True, capture_output=True)
        section_errors = lambda errors: [e for e in errors if "Tested MCP clients" in e]
        self.assertEqual(section_errors(gate.check(root, release=False)), [])
        self.assertTrue(section_errors(gate.check(root, release=True)))

class CandidateBranchTriggers(unittest.TestCase):
    def setUp(self):
        import tomllib
        self.version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
        self.texts = {name: (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
                      for name in ("ci.yml", "candidate.yml", "codeql.yml")}
    def test_current_workflow_triggers(self):
        self.assertEqual(gate.workflow_branch_errors(self.texts, self.version), [])
    def test_wildcard_or_stale_candidate_branch_is_refused(self):
        branch = "release/" + self.version + "-candidate"
        for name in ("candidate.yml", "codeql.yml"):
            for replacement in ("release/*-candidate", "release/0.9.9-candidate", "main"):
                with self.subTest(name=name, replacement=replacement):
                    self.assertIn(branch, self.texts[name])
                    texts = dict(self.texts, **{name: self.texts[name].replace(branch, replacement)})
                    errors = gate.workflow_branch_errors(texts, self.version)
                    self.assertTrue(any(error.startswith(name + " ") for error in errors))
    def test_ci_must_include_every_branch(self):
        branches = '    branches:\n      - "**"\n'
        for replacement in ('    branches-ignore:\n      - "release/*-candidate"\n',
                            branches + '\n      - "!release/*-candidate"\n',
                            '    branches:\n      - "main"\n', ""):
            with self.subTest(replacement=replacement):
                self.assertIn(branches, self.texts["ci.yml"])
                texts = dict(self.texts, **{"ci.yml": self.texts["ci.yml"].replace(branches, replacement)})
                self.assertEqual(gate.workflow_branch_errors(texts, self.version),
                                 ["ci.yml must run on pushes to all branches and tags"])

if __name__ == "__main__":
    unittest.main()
