import importlib.util
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("source_gate", ROOT / "release/check_source.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class Privacy(unittest.TestCase):
    def setUp(self):
        self.rules = gate.legacy(ROOT)
    def test_os_brand_and_official_client_documentation_are_public(self):
        self.assertEqual(gate.privacy_text(self.rules, "README.md", "Raspberry Pi OS 64; https://learn.chatgpt.com/docs/extend/mcp; ghcr.io"), [])
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

class SharedProductBoundaries(unittest.TestCase):
    def setUp(self):
        import tempfile, shutil, subprocess
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        files = ["pyproject.toml", "src/netops/__init__.py", "scripts/check_release.py"]
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

    def test_single_version_mismatch_blocks_the_source(self):
        p=self.root/"src/netops/__init__.py"
        p.write_text('__version__ = "9.0.0"\n')
        self.assertIn("installed product version differs from project metadata",gate.check(self.root))

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

if __name__ == "__main__":
    unittest.main()
