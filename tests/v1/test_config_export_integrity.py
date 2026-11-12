"""A configuration export read through engine, proxy and worker: the declared hash and size describe the joined pages.

The engine applies the response redaction of proxy and worker (byte-identical to 1.0.6 but for
`unset password`) to the whole text before it computes the hash, the size and the pages.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from netops import worker
from netops.files import write_private
from netops_core.audit import Recorder
from netops_auditor import cli as auditor_cli
from netops_helper import audit as helper_audit, configuration, engine, proxy, server

from test_config_fortiadc import STATUS, config, live, profile_lines, READ


class ConfigurationExportIntegrity(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        helper = self.state / "helper"
        helper.mkdir(mode=0o700)
        section = {"account_role": "read-only", "ssh_platform": "fortiadc",
                   "enabled_queries": ["system_status"],
                   "read_inventory": {"config_access": ["read"]},
                   "rate_limit": {"requests": 60, "window_seconds": 1},
                   "egress": {"addresses": ["192.0.2.40"], "tcp_ports": [22],
                              "udp_ports": [], "tcp_port_ranges": [], "udp_port_ranges": [],
                              "allow_icmp": False, "allow_dns": False, "tls_server_names": []}}
        device = {"name": "adc-a", "platform": "fortiadc", "address": "192.0.2.40",
                  "port": 22, "role": "lab", "credential": "fixture-ro",
                  "host_key_fingerprint": "SHA256:" + "A" * 43, "legacy_ssh": None, "auditor": None,
                  "helper": section}
        write_private(helper / "inventory.json", json.dumps({"version": 2, "devices": [device]}).encode())
        write_private(helper / "vault.json", json.dumps({"version": 2, "credentials": {
            "fixture-ro": {"kind": "password", "login": "netops-read",
                           "value": "synthetic-export-password-only"}}}).encode())
        self.enterContext(patch.object(worker, "STATE", self.state))
        self.enterContext(patch.object(proxy, "INVENTORY", helper / "inventory.json"))
        self.enterContext(patch.object(helper_audit, "_RECORDER", Recorder(helper / "operations.jsonl", "helper")))
        configuration._SNAPSHOTS.clear()
        self.addCleanup(configuration._SNAPSHOTS.clear)
        self.bridge = worker.HelperBridge()
        await self.bridge.tools(server.mcp)
        self.enterContext(patch.object(self.bridge.proxy, "_consume_rate_limit"))

    async def pages(self, name, arguments, raw=None):
        def wire(auth, platform, command, **kwargs):
            if command == "get system status":
                return 0, STATUS
            kwargs["stdout_consumer"](raw.encode())
            return 0, ""

        pages = []
        with patch.object(engine, "read_from_device", side_effect=wire):
            while True:
                result = await self.bridge.call(server.mcp, name, arguments)
                self.assertFalse(result["isError"], result)
                page = result["structuredContent"]
                # Both representations carry the same text and metadata.
                wire_page = json.loads(result["content"][0]["text"])
                for field in ("untrusted_device_output", "content_sha256", "total_bytes", "returned_bytes",
                              "offset", "next_offset"):
                    self.assertEqual(wire_page[field], page[field], field)
                self.assertEqual(page["returned_bytes"], len(page["untrusted_device_output"].encode()))
                self.assertEqual(page["offset"], sum(item["returned_bytes"] for item in pages))
                pages.append(page)
                if page["next_offset"] is None:
                    break
                arguments = dict(arguments, offset=page["next_offset"])
                if name == "config_read":
                    arguments["snapshot_id"] = page["snapshot_id"]
        joined = "".join(page["untrusted_device_output"] for page in pages).encode()
        self.assertEqual({page["total_bytes"] for page in pages}, {len(joined)})
        self.assertEqual({page["content_sha256"] for page in pages}, {hashlib.sha256(joined).hexdigest()})
        return joined, pages

    def body(self, hostname="ADC-LAB"):
        # Lines that the proxy or worker rules rewrite: `set password` with its value, `unset password`
        # before the next line, a public value with `token:` and a value that holds the known login secret.
        admins = "".join('  edit "op%d"\n    set access-profile "netops-read"\n'
                         '    set password ENC SECRET-%d\n    unset password\n    set x-unmapped-%d "v"\n  next\n'
                         % (index, index, index % 3) for index in range(400))
        admins += ('  edit "netops-read"\n    set access-profile "netops-read"\n'
                   '    set accprofile-override disable\n    set password ENC SECRET-OWN\n  next\n')
        text = config(profiles=profile_lines(rights=READ), admins=admins)
        return text.replace("set hostname ADC-LAB", "set hostname " + json.dumps(hostname))

    async def test_joined_pages_match_declared_hash_and_size(self):
        for hostname in ("ADC-LAB", "lab token: synthetic-public-word", "synthetic-export-password-only"):
            for include_defaults in (False, True):
                for limit in (1000, 4096, 48000):
                    with self.subTest(hostname=hostname, include_defaults=include_defaults, limit=limit):
                        arguments = {"target": "adc-a", "platform": "fortiadc", "section": "all",
                                     "include_all": True, "redaction": "full",
                                     "include_defaults": include_defaults, "limit": limit}
                        joined, pages = await self.pages("config_read", arguments, live(self.body(hostname)))
                        self.assertGreater(len(joined), 48000)
                        self.assertGreater(len(pages), 1)
                        self.assertNotIn(b"SECRET-", joined)
                        self.assertNotIn(b"synthetic-public-word", joined)
                        self.assertNotIn(b"synthetic-export-password-only", joined)
                        # As in 1.0.6, the response redaction replaces each `set password` line; it no
                        # longer takes the line after a value-less `unset password`.
                        self.assertRegex(joined, rb"(?m)^[+-]? *set password \[REDACTED\]$")
                        self.assertEqual(joined.count(b"\n    set password [REDACTED]\n"), 402)
                        self.assertEqual(joined.count(b"    unset password\n    set x-unmapped-"), 400)
                        self.assertIn(b"set hostname " + (b"ADC-LAB" if hostname == "ADC-LAB" else
                                                          b"<REDACTED:credential#" if "password" in hostname
                                                          else b'"lab [REDACTED]'), joined)
                        self.assertEqual(pages[0]["credential_redactions"], 402 + ("password" in hostname))
                        for page in pages[:-1]:
                            self.assertTrue(page["untrusted_device_output"].endswith("\n"))

    async def test_live_fortiadc_export_pages_join_to_the_hash_and_audit_with_exit_0(self):
        # The live FortiADC-KVM 7.6.7 export (see test_fortiadc_live_export) read again as device output.
        export = (Path(__file__).parent / "fixtures" / "fortiadc_7_6_7_full_export.conf").read_text()
        # The live capture used the system administrator `admin`, which sees every area.
        write_private(self.state / "helper" / "vault.json", json.dumps({"version": 2, "credentials": {
            "fixture-ro": {"kind": "password", "login": "admin",
                           "value": "synthetic-export-password-only"}}}).encode(), replace=True)
        arguments = {"target": "adc-a", "platform": "fortiadc", "section": "all", "include_all": True,
                     "redaction": "full", "include_defaults": True}
        reference, pages = await self.pages("config_read", dict(arguments, limit=48000), live(export))
        text = reference.decode()
        hidden = [match.start() for match in re.finditer(r"(?m)^    set password \[REDACTED\]\n", text)]
        self.assertEqual(len(hidden), 3)
        self.assertRegex(text, r"(?m)^ *set password \[REDACTED\]$")
        self.assertEqual(text.count("    unset password\n"), export.count("    unset password\n"))
        for line in re.findall(r"    unset password\n.*\n", export):
            self.assertIn(line, text)
        # Limits whose byte cut falls inside each hidden password line, so a page ends right before it.
        limits = {1000, 1777, 4096}
        for start in hidden:
            limits.add(next(limit for limit in range(1000, 48001) if cut_inside(text, limit, start, start + len("    set password [REDACTED]\n"))))
        for limit in sorted(limits):
            with self.subTest(limit=limit):
                joined, pages = await self.pages("config_read", dict(arguments, limit=limit), live(export))
                self.assertEqual(joined, reference)
        metadata = {name: value for name, value in pages[0].items() if name not in PAGE_FIELDS}
        self.assertEqual(metadata["visibility_limitations"], ["schema-fields-unverified"])
        self.assertEqual(metadata["credential_redactions"], 5)
        with tempfile.TemporaryDirectory() as directory:
            snapshot, meta = Path(directory) / "snapshot.conf", Path(directory) / "meta.json"
            snapshot.write_bytes(reference)
            meta.write_text(json.dumps(metadata))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = auditor_cli.main(["run", "--platform", "fortiadc", "--tenant", "t", "--device", "d",
                                         "--config", str(snapshot), "--snapshot-meta", str(meta), "--json"])
        self.assertEqual((code, err.getvalue()), (auditor_cli.EXIT_OK, ""))
        coverage = json.loads(out.getvalue())["coverage"]
        self.assertEqual(coverage["actionable_gaps"], [])
        self.assertEqual([gap["reason"] for gap in coverage["inherent_gaps"]], ["factory-provenance-unproven"])

    async def test_a_page_that_a_later_layer_changes_is_withheld(self):
        arguments = {"target": "adc-a", "platform": "fortiadc", "section": "all", "include_all": True,
                     "redaction": "full", "limit": 48000}
        first = (await self.pages("config_read", arguments, live(self.body())))[1][0]
        text = first["untrusted_device_output"]
        # A caller offset inside a line: the page starts with `password` followed by the next line,
        # which the proxy takes as a password value; the worker withholds the page.
        offset = text.index("    unset password\n") + len("    unset ")
        result = await self.bridge.call(server.mcp, "config_read", dict(
            arguments, snapshot_id=first["snapshot_id"], offset=offset, limit=80))
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["error_code"], "page_changed_by_redaction")
        self.assertNotIn("untrusted_device_output", result["structuredContent"])

    async def test_joined_diff_pages_match_declared_hash_and_size(self):
        arguments = {"target": "adc-a", "platform": "fortiadc", "section": "all", "include_all": True,
                     "redaction": "full", "limit": 48000}
        snapshots = []
        for hostname in ("ADC-LAB", "ADC-OTHER"):
            body = self.body(hostname)
            if hostname == "ADC-OTHER":
                # Same counts (a diff compares captures of one shape), moved password lines.
                for index in range(60):
                    body = body.replace('    set password ENC SECRET-%d\n    unset password\n' % index,
                                        '    unset password\n    set password ENC NEW-%d\n' % index)
            snapshots.append((await self.pages("config_read", arguments, live(body)))[1][0]["snapshot_id"])
        section = json.loads((self.state / "helper" / "inventory.json").read_text())
        section["devices"][0]["helper"]["read_inventory"]["config_access"] = ["read", "compare"]
        write_private(self.state / "helper" / "inventory.json", json.dumps(section).encode(), replace=True)
        for limit in (1000, 48000):
            with self.subTest(limit=limit):
                joined, pages = await self.pages("config_diff", {
                    "target": "adc-a", "platform": "fortiadc", "base_snapshot": snapshots[0],
                    "other_snapshot": snapshots[1], "limit": limit})
                self.assertIn(b"-    set password [REDACTED]\n+    unset password\n", joined)
                self.assertIn(b"ADC-OTHER", joined)
                self.assertNotIn(b"NEW-", joined)
                self.assertRegex(joined, rb"(?m)^[+-]? *set password \[REDACTED\]$")
                self.assertEqual(len(pages) > 1, limit == 1000)


PAGE_FIELDS = ("untrusted_device_output", "offset", "returned_bytes", "next_offset", "total_bytes", "ok", "target",
               "snapshot_id", "device_output_trust")


def cut_inside(text, limit, start, end):
    """True when paging `text` by `limit` makes a byte cut inside [start, end)."""
    offset = 0
    while offset + limit < len(text):
        cut = offset + limit
        if start < cut < end:
            return True
        offset = text.rfind("\n", offset, cut) + 1 or cut
    return False


if __name__ == "__main__":
    unittest.main()
