import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

DOT, COLON = ".", ":"
PRIVATE_V4 = DOT.join(("10", "20", "30", "40"))
OTHER_V4 = DOT.join(("172", "16", "5", "9"))
ULA_V6 = COLON.join(("fd00", "", "7"))
PUBLIC_V6 = COLON.join(("2a00", "", "1"))
MAC_ADDRESS = COLON.join(("02", "00", "5e", "10", "20", "30"))
HOME_PATH = "/" + "home" + "/operator/bundle"
RUNNER_PATH = "/" + "home" + "/runner/.cache/grype/db"

GATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "report_gate.py")


def report(detail):
    return {"schema": "netops-acceptance-blackbox/1", "candidate_commit": "a" * 40, "candidate_image": "sha256:" + "1" * 64,
            "summary": {"PASS": 1}, "checks": [{"check": "x", "spec": "F31", "status": "PASS", "detail": detail}]}


class ReportGate(unittest.TestCase):
    def run_gate(self, files):
        with tempfile.TemporaryDirectory() as directory:
            for name, content in files.items():
                with open(os.path.join(directory, name), "w", encoding="utf-8") as stream:
                    stream.write(content if isinstance(content, str) else json.dumps(content))
            proc = subprocess.run([sys.executable, "-B", GATE, directory], capture_output=True, text=True)
        return proc.returncode, proc.stdout

    def clean(self):
        return {"acceptance-ubuntu-amd64-blackbox.json": report("https://localhost:8443/mcp answered over TLS 1.3 at 127.0.0.1; listed in netops-1.0.0-manifest.json"),
                "env.example": "NETOPS_IMAGE=ghcr.io/radek-cerny-soukr/netops@sha256:" + "1" * 64 + "\nNETOPS_BIND_IP=127.0.0.1\n",
                "netops-1.0.0-vulnerability-assessments.json": [{"reasoning": "the module is not among the loaded modules"}],
                "netops-1.0.0-linux-amd64.cdx.json": {"bomFormat": "CycloneDX", "components": [{"name": "/usr/share/zoneinfo/America/Lima", "version": "1.2.3"}]},
                "netops-1.0.0-linux-amd64-grype.json": {"matches": [], "descriptor": {"name": "grype", "db": {"status": {"path": "/tmp/grype-db/6/vulnerability.db"}}}},
                "netops-1.0.0-manifest.json": {"image": {"name": "ghcr.io/radek-cerny-soukr/netops"}}}

    def test_clean_assets_pass(self):
        rc, out = self.run_gate(self.clean())
        self.assertEqual(rc, 0, out)
        self.assertIn("report_gate=PASS", out)

    def test_seven_layer_reports_in_the_signing_format_pass(self):
        files = self.clean()
        base = {"candidate_commit": "a" * 40, "candidate_image": "sha256:" + "1" * 64}
        upgrade = ("kroky-postupu", "bezi-verze-TO", "health-ready", "obnova-manifest-shodny", "CA-klic-token-beze-zmeny",
                   "konfigurace-beze-zmeny", "data-roli-beze-zmeny", "audit-prefix", "audit-zaznam-upgrade", "mcp-tools-list",
                   "mcp-odpovedi-roli", "token-plati-bez-tokenu-401", "connection-shodne", "druhy-start-nic-nemeni",
                   "token-ani-heslo-v-logs", "rollback-FROM", "FROM-nedotcena-do-rollbacku")
        files["acceptance-upgrade-fedora-amd64.json"] = dict(base, checks=[{"check": c, "status": "PASS"} for c in upgrade])
        files["acceptance-fedora-arm64-rootless.json"] = dict(base, checks=[{"check": "selinux-enforcing", "status": "PASS"}])
        files["acceptance-rpios-arm64-rootful.json"] = dict(base, checks=[{"check": "quickstart", "status": "PASS"}])
        files["acceptance-syslog-load.json"] = dict(base, protocol_sha256="3" * 64, checks=[{"check": "p6", "status": "PASS"}])
        files["acceptance-code-review.json"] = dict(base, protocol_sha256="4" * 64, checks=[{"check": "review", "status": "PASS"}])
        files["acceptance-codex-cli-e2e.json"] = dict(base, checks=[{"check": "helper_status", "status": "NOT RUN", "detail": "no Codex tokens available"}])
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 0, out)
        self.assertIn("report_gate=PASS", out)

    def test_laboratory_wording_fails(self):
        for detail in ("fresh Ubuntu VM on VMware ESXi", "original clean snapshot", "through an SSH tunnel", "Proxmox host", "Lima instance", "hypervisor KVM"):
            files = self.clean()
            files["acceptance-ubuntu-amd64-blackbox.json"] = report(detail)
            rc, out = self.run_gate(files)
            self.assertEqual(rc, 1, detail)
            self.assertIn("laboratory wording", out)

    def test_private_addresses_hosts_and_paths_fail(self):
        for detail, expected in (("server at " + PRIVATE_V4, "network address"), ("listener " + OTHER_V4, "network address"), ("host fw.example-site" + DOT + "local", "host name"),
                                 ("node fixture-node" + DOT + "lan", "host name"), ("bundle in " + HOME_PATH, "private path"), ("copied to C:\\Users\\Operator", "private path")):
            files = self.clean()
            files["acceptance-ubuntu-amd64-blackbox.json"] = report(detail)
            rc, out = self.run_gate(files)
            self.assertEqual(rc, 1, detail)
            self.assertIn(expected, out)

    def test_runner_home_in_scan_fails(self):
        files = self.clean()
        files["netops-1.0.0-linux-amd64-grype.json"] = {"matches": [], "descriptor": {"name": "grype", "db": {"status": {"path": RUNNER_PATH}}}}
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)
        self.assertIn("private path", out)

    def test_lab_word_in_a_key_fails(self):
        files = self.clean()
        files["acceptance-codex-cli-e2e.json"] = dict(report("ok"), evidence={"esxi-server-binding.json": "0" * 64})
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)


    def test_ipv6_unknown_tld_and_mac_fail_without_printing_values(self):
        for detail, kind in (("listener " + ULA_V6, "network address"), ("peer " + PUBLIC_V6, "network address"), ("node fixture-host.example" + DOT + "xyz", "host name"),
                             ("box fixture-host" + DOT + "home", "host name"), ("nic " + MAC_ADDRESS, "hardware address")):
            files = self.clean()
            files["acceptance-ubuntu-amd64-blackbox.json"] = report(detail)
            rc, out = self.run_gate(files)
            self.assertEqual(rc, 1, detail)
            self.assertIn(kind, out)
            self.assertNotIn(detail.split()[-1], out)

    def test_only_loopback_registry_and_asset_names_are_allowed(self):
        files = self.clean()
        files["acceptance-ubuntu-amd64-blackbox.json"] = report("server ::1 and 127.0.0.1 at 2026-10-15T02:20:50Z, see netops-1.0.0-manifest.json and ghcr.io")
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 0, out)
        for detail, kind in (("server " + DOT.join(("192", "0", "2", "10")), "network address"), ("server " + COLON.join(("2001", "db8", "", "5")), "network address"),
                             ("target node" + DOT + "example" + DOT + "invalid", "host name"), ("see sys" + DOT + "modules", "host name"),
                             ("file other-name" + DOT + "json", "host name")):
            files = self.clean()
            files["acceptance-ubuntu-amd64-blackbox.json"] = report(detail)
            rc, out = self.run_gate(files)
            self.assertEqual(rc, 1, detail)
            self.assertIn(kind, out)

    def test_links_directories_and_bad_encoding_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, content in self.clean().items():
                with open(os.path.join(directory, name), "w", encoding="utf-8") as stream:
                    stream.write(content if isinstance(content, str) else json.dumps(content))
            cases = (("symlink", lambda: os.symlink(os.path.join(directory, "acceptance-ubuntu-amd64-blackbox.json"), os.path.join(directory, "acceptance-linked.json"))),
                     ("directory", lambda: os.mkdir(os.path.join(directory, "nested"))),
                     ("utf8", lambda: pathlib.Path(directory, "acceptance-bad-utf.json").write_bytes(b"\xff\xfe")),
                     ("json", lambda: pathlib.Path(directory, "acceptance-bad-json.json").write_text("{")))
            for label, make in cases:
                make()
                proc = subprocess.run([sys.executable, "-B", GATE, directory], capture_output=True, text=True)
                self.assertEqual(proc.returncode, 1, label)
                expected = {"symlink": "not a regular file", "directory": "not a regular file", "utf8": "invalid UTF-8", "json": "invalid JSON"}[label]
                self.assertIn(expected, proc.stdout, label)
                self.assertNotIn("Traceback", proc.stderr, label)
                for leftover in ("acceptance-linked.json", "nested", "acceptance-bad-utf.json", "acceptance-bad-json.json"):
                    path = os.path.join(directory, leftover)
                    if os.path.islink(path) or os.path.isfile(path):
                        os.remove(path)
                    elif os.path.isdir(path):
                        os.rmdir(path)

    def test_vendor_exception_needs_the_vendor_schema(self):
        files = self.clean()
        files["netops-1.0.0-linux-amd64.cdx.json"] = {"note": "copied from a VM on ESXi"}
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)
        self.assertIn("laboratory wording", out)


    def test_forged_vendor_files_cannot_switch_rules_off(self):
        host = "fixture-host" + DOT + "home"
        forged = {"netops-1.0.0-linux-amd64.cdx.json": {"bomFormat": "CycloneDX", "private_hostname": host},
                  "netops-1.0.0-linux-amd64-grype.json": {"matches": [], "descriptor": {"name": "grype"}, "private_hostname": host}}
        for name, content in forged.items():
            files = self.clean()
            files[name] = content
            rc, out = self.run_gate(files)
            self.assertEqual(rc, 1, name)
            self.assertIn("unexpected vendor field", out)
        files = self.clean()
        files["netops-1.0.0-linux-amd64-grype.json"] = {"matches": [], "descriptor": {"name": "grype", "db": {"status": {"path": "/" + "home" + "/operator/db"}}}}
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)
        self.assertIn("private path", out)

    def test_underscore_is_not_a_code_exemption(self):
        files = self.clean()
        files["acceptance-ubuntu-amd64-blackbox.json"] = report("router fixture_router" + DOT + "internal answered")
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)
        self.assertIn("host name", out)


    def test_nested_vendor_values_are_checked(self):
        host = "fixture-host" + DOT + "home"
        cases = (("netops-1.0.0-linux-amd64.cdx.json", {"bomFormat": "CycloneDX", "components": [{"name": "pkg", "private_hostname": host}]}, "unexpected vendor field"),
                 ("netops-1.0.0-linux-amd64.cdx.json", {"bomFormat": "CycloneDX", "components": [{"name": "pkg", "description": "tested on VMware ESXi guest"}]}, "laboratory wording"),
                 ("netops-1.0.0-linux-amd64-grype.json", {"matches": [{"private_hostname": host}], "descriptor": {"name": "grype"}}, "unexpected vendor field"))
        for name, content, kind in cases:
            files = self.clean()
            files[name] = content
            rc, out = self.run_gate(files)
            self.assertEqual(rc, 1, (name, kind))
            self.assertIn(kind, out)

    def test_a_planted_file_name_cannot_allow_a_host(self):
        host = "fixture-host" + DOT + "home"
        files = self.clean()
        files[host] = ""
        files["acceptance-ubuntu-amd64-blackbox.json"] = report("peer " + host)
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)
        self.assertIn("unexpected file name", out)
        self.assertIn("host name", out)
        self.assertNotIn(host, out)


    def test_json_escapes_do_not_hide_private_values(self):
        token = "gh" + "p_" + "A" * 36
        for raw in ("/h\\u006fme/operator/private", "rp\\u0069" + "5-master", "gh\\u0070_" + "A" * 36):
            files = self.clean()
            files["acceptance-ubuntu-amd64-blackbox.json"] = json.dumps(report("PLACEHOLDER")).replace("PLACEHOLDER", raw)
            rc, out = self.run_gate(files)
            self.assertEqual(rc, 1, raw)
            self.assertNotIn(token, out)

    def test_vendor_free_text_and_url_fields_are_strict(self):
        host = "fixture-host" + DOT + "home"
        cases = (("netops-1.0.0-linux-amd64.cdx.json", {"bomFormat": "CycloneDX", "components": [{"name": "pkg", "description": "see " + host}]}, "host name"),
                 ("netops-1.0.0-linux-amd64-grype.json", {"matches": [{"vulnerability": {"description": "affects " + host}}], "descriptor": {"name": "grype"}}, "host name"),
                 ("netops-1.0.0-linux-amd64-grype.json", {"matches": [{"vulnerability": {"description": "affects shutil" + DOT + "rmtree"}}], "descriptor": {"name": "grype"}}, None),
                 ("netops-1.0.0-linux-amd64-grype.json", {"matches": [{"vulnerability": {"dataSource": "see " + host}}], "descriptor": {"name": "grype"}}, "not a URL"))
        for name, content, kind in cases:
            files = self.clean()
            files[name] = content
            rc, out = self.run_gate(files)
            if kind is None:
                self.assertEqual(rc, 0, out)
            else:
                self.assertEqual(rc, 1, (name, kind))
                self.assertIn(kind, out)
                self.assertNotIn(host, out)


    def test_vendor_hosts_must_be_listed(self):
        host = "fixture-host" + DOT + "home"
        cases = ((["components", 0, "name"], host, "host name"),
                 (["components", 0, "externalReferences", 0, "url"], "https://" + host + "/docs", "host name"),
                 (["components", 0, "author"], "Fixture Owner <fixture-owner@" + host + ">", "host name"))
        for path, value, kind in cases:
            component = {"name": "pkg", "externalReferences": [{"url": "https://www.openssl.org/"}], "author": "Dev <dev@python.org>"}
            component[path[2]] = value if len(path) == 3 else [{"url": value}]
            files = self.clean()
            files["netops-1.0.0-linux-amd64.cdx.json"] = {"bomFormat": "CycloneDX", "components": [component]}
            rc, out = self.run_gate(files)
            self.assertEqual(rc, 1, path)
            self.assertIn(kind, out)
            self.assertNotIn(host, out)
        files = self.clean()
        files["netops-1.0.0-linux-amd64.cdx.json"] = {"bomFormat": "CycloneDX", "components": [{"name": "zlib.so", "externalReferences": [{"url": "https://www.openssl.org/"}], "author": "Dev <dev@python.org>"}]}
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 0, out)

    def test_escapes_in_plain_text_files_are_decoded(self):
        files = self.clean()
        files["env.example"] = files["env.example"] + "VALUE=gh\\u0070_" + "A" * 36 + "\n"
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)
        self.assertIn("private marker", out)

    def test_nested_and_percent_escapes_are_decoded_in_every_value(self):
        token = "gh" + "p_" + "A" * 36
        host = "fixture-host" + DOT + "home"
        nested = "gh" + chr(92) + "u005cu0070_" + "A" * 36
        hidden_host = "fixture-host" + chr(92) + "u002ehome"
        cases = (("env.example", self.clean()["env.example"] + "VALUE=" + nested + "\n", "private marker"),
                 ("env.example", self.clean()["env.example"] + "PEER=fixture-host%2ehome\n", "host name"),
                 ("acceptance-ubuntu-amd64-blackbox.json", report(nested), "private marker"),
                 ("acceptance-ubuntu-amd64-blackbox.json", report("peer " + hidden_host), "host name"),
                 ("acceptance-ubuntu-amd64-blackbox.json", report("peer fixture-host" + chr(92) + "u005cu002ehome"), "host name"),
                 ("netops-1.0.0-linux-amd64.cdx.json", {"bomFormat": "CycloneDX", "components": [{"name": hidden_host}]}, "host name"),
                 ("netops-1.0.0-linux-amd64.cdx.json", {"bomFormat": "CycloneDX", "components": [{"name": "pkg", "externalReferences": [{"url": "https://" + hidden_host + "/docs"}]}]}, "host name"),
                 ("netops-1.0.0-linux-amd64-grype.json", {"matches": [{"vulnerability": {"description": "affects " + hidden_host}}], "descriptor": {"name": "grype"}}, "host name"))
        for name, content, kind in cases:
            with self.subTest(name=name, kind=kind):
                files = self.clean()
                files[name] = content
                rc, out = self.run_gate(files)
                self.assertEqual(rc, 1, out)
                self.assertIn(kind, out)
                self.assertNotIn(token, out)
                self.assertNotIn(host, out)

    def test_escape_nesting_beyond_the_limit_fails_closed(self):
        value = chr(92) + "u0070"
        for _ in range(12):
            value = value.replace(chr(92), chr(92) + "u005c", 1)
        for name, content in (("env.example", self.clean()["env.example"] + "VALUE=gh" + value + "_" + "A" * 36 + "\n"),
                              ("acceptance-ubuntu-amd64-blackbox.json", report("gh" + value + "_" + "A" * 36))):
            with self.subTest(name=name):
                files = self.clean()
                files[name] = content
                rc, out = self.run_gate(files)
                self.assertEqual(rc, 1, out)
                self.assertIn("unusable text escape", out)


    def related_scan(self):
        return {"matches": [{"matchDetails": [{"searchedBy": {"language": "python"}}],
                "relatedVulnerabilities": [{
                    "id": "CVE-2026-59951", "namespace": "nvd:cpe", "severity": "Medium",
                    "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2026-59951",
                    "urls": ["https://github.com/advisories/GHSA-84m7-p3x7-pcfv"],
                    "description": "A stateful HTTP transport can retain connections",
                    "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                              "metrics": {"baseScore": 7.5}, "source": "security-advisories@github.com",
                              "type": "Primary", "vendorMetadata": {}}],
                    "cwes": [{"cve": "CVE-2026-59951", "cwe": "CWE-400",
                              "source": "security-advisories@github.com", "type": "Primary"}],
                    "epss": [{"cve": "CVE-2026-59951", "date": "2026-10-16",
                              "epss": 0.1, "percentile": 0.2}]
                }]}], "descriptor": {"name": "grype"}}

    def test_nonempty_related_vulnerability_metadata_passes(self):
        files = self.clean()
        files["netops-1.0.0-linux-amd64-grype.json"] = self.related_scan()
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 0, out)
        self.assertIn("report_gate=PASS", out)

    def test_related_vendor_fields_keep_privacy_and_exact_key_guards(self):
        host = "fixture-host" + DOT + "home"
        cases = ((None, "dataSource", "https://" + host + "/docs", "host name"),
                 (None, "urls", ["https://" + host + "/docs"], "host name"),
                 ("cvss", "source", "owner@" + host, "host name"),
                 ("cwes", "source", "owner@" + host, "host name"),
                 (None, "description", "peer " + host, "host name"),
                 (None, "description", "stored in " + HOME_PATH, "private path"),
                 (None, "description", "peer " + PRIVATE_V4, "network address"),
                 (None, "description", "peer fixture-host%2ehome", "host name"),
                 ("cvss", "vendorMetadata", {"x": "safe"}, "unexpected vendor field"),
                 (None, "namespace", "peer " + host, "host name"),
                 (None, "unexpected_vendor_key", "safe-looking text", "unexpected vendor field"))
        for section, key, value, expected in cases:
            with self.subTest(section=section, key=key, expected=expected):
                files = self.clean()
                scan = self.related_scan()
                related = scan["matches"][0]["relatedVulnerabilities"][0]
                (related if section is None else related[section][0])[key] = value
                files["netops-1.0.0-linux-amd64-grype.json"] = scan
                rc, out = self.run_gate(files)
                self.assertEqual(rc, 1, out)
                self.assertIn(expected, out)
                self.assertNotIn(host, out)

    def test_actual_assessment_evidence_passes_without_a_filename_host_exemption(self):
        files = self.clean()
        path = pathlib.Path(GATE).with_name("vulnerability-assessments.json")
        files["netops-1.0.0-vulnerability-assessments.json"] = json.loads(path.read_text(encoding="utf-8"))
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 0, out)
        self.assertIn("report_gate=PASS", out)
        files["acceptance-ubuntu-amd64-blackbox.json"] = report("peer gateway" + DOT + "py")
        rc, out = self.run_gate(files)
        self.assertEqual(rc, 1, out)
        self.assertIn("host name", out)


if __name__ == "__main__":
    unittest.main()
