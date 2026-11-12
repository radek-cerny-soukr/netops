"""The Helper export of a live FortiADC-KVM 7.6.7 build0676 (`show full-configuration`) audited end to end.

The fixture is the text the Helper engine redacted for a system administrator, anonymised with
components/netops-helper/tests/support/anonymize_fixture.py (addresses in the RFC 5737 ranges, the
collector account name, the support contract identifier and two vendor default domains replaced).
The client receives it after the response redaction of proxy and worker, which the engine applies
before it hashes the text: each `set password <REDACTED:credential#N>` line becomes `set password [REDACTED]`.
"""
from dataclasses import replace
import contextlib
import hashlib
import io
import json
import re
import tempfile
from pathlib import Path
from unittest import TestCase

from netops.redaction import redact
from netops_auditor import checks_fortiadc, cli, l1_fortios
from netops_helper.proxy_sanitize import sanitize_object

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE = (FIXTURES / "fortiadc_7_6_7_full_export.conf").read_text()
CAPTURE_METADATA = json.loads((FIXTURES / "fortiadc_7_6_7_full_export.meta.json").read_text())
# The text and metadata the client receives: the response redaction is applied once, and settles.
EXPORT = redact(sanitize_object(CAPTURE, ()), ())[0]
DIGEST = hashlib.sha256(EXPORT.encode()).hexdigest()
METADATA = dict(CAPTURE_METADATA, content_sha256=DIGEST, snapshot_sha256=DIGEST)
FACTORY = "fortiadc.tls.factory-certificate"


def audit(text, metadata, *extra):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        snapshot, meta = root / "snapshot.conf", root / "meta.json"
        snapshot.write_text(text)
        meta.write_text(json.dumps(metadata))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["run", "--platform", "fortiadc", "--tenant", "t", "--device", "d", "--config",
                             str(snapshot), "--snapshot-meta", str(meta), *extra])
    return code, out.getvalue(), err.getvalue()


class LiveFortiADCExport(TestCase):
    def test_metadata_describes_exactly_this_text(self):
        digest = hashlib.sha256(CAPTURE.encode()).hexdigest()
        self.assertEqual((CAPTURE_METADATA["content_sha256"], CAPTURE_METADATA["snapshot_sha256"]), (digest, digest))
        self.assertEqual(METADATA["visibility_limitations"], ["schema-fields-unverified"])
        self.assertFalse(METADATA["configuration_complete"])
        self.assertTrue(METADATA["include_defaults"])

    def test_response_redaction_replaces_password_values_and_keeps_the_line_after_unset_password(self):
        # The text the Helper hashes is the text the client receives through proxy and worker.
        self.assertEqual(redact(sanitize_object(EXPORT, ()), ()), (EXPORT, []))
        self.assertEqual(CAPTURE.count("    set password <REDACTED:credential#"), 3)
        self.assertEqual(EXPORT.count("\n    set password [REDACTED]\n"), 3)
        self.assertNotIn("credential#", "\n".join(line for line in EXPORT.splitlines() if line.startswith("    set password ")))
        unset = re.findall(r"    unset password\n.*\n", CAPTURE)
        self.assertEqual(len(unset), 8)
        for lines in unset:
            self.assertIn(lines, EXPORT)
        # Everything else is the captured text, line by line.
        self.assertEqual([line for line in CAPTURE.splitlines() if not re.match(r"    set (?:password|auth-pwd|priv-pwd) ", line)],
                         [line for line in EXPORT.splitlines() if not re.match(r"    set (?:password|auth-pwd|priv-pwd) ", line)])

    def test_export_parses(self):
        tree = l1_fortios.parse(EXPORT)
        self.assertIsNotNone(tree.section("system interface"))
        self.assertIsNotNone(tree.section("load-balance pool"))
        # Redacted password values remain explicit attributes in the parsed configuration.
        admin = tree.section("system admin").entries["admin"]
        captured = l1_fortios.parse(CAPTURE).section("system admin").entries["admin"]
        self.assertIn("password", captured.attrs)
        self.assertEqual(admin.attrs, {name: (replace(value, values=('[REDACTED]',)) if name == 'password' else value) for name, value in captured.attrs.items()})

    def test_json_sarif_and_text_runs_exit_0_with_only_the_inherent_factory_gap(self):
        for mode in ((), ("--json",), ("--sarif",)):
            with self.subTest(mode=mode):
                code, out, err = audit(EXPORT, METADATA, *mode)
                self.assertEqual((code, err), (cli.EXIT_OK, ""))
                if mode == ("--json",):
                    report = json.loads(out)
                    self.assertEqual(report["coverage"]["actionable_gaps"], [])
                    self.assertEqual([(gap["rule_id"], gap["reason"]) for gap in report["coverage"]["inherent_gaps"]],
                                     [(FACTORY, "factory-provenance-unproven")])
                    self.assertFalse(report["evaluation_complete"])
                    self.assertEqual(sorted(finding["rule_id"] for finding in report["findings"]),
                                     ["fortiadc.lb.pool-single-member", "fortiadc.mgmt.trusted-hosts-open"])

    def test_original_metadata_of_another_text_is_refused(self):
        code, _, err = audit(EXPORT + "\n", METADATA, "--json")
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("snapshot metadata belongs to another snapshot", err)

    def test_every_helper_limitation_name_is_known(self):
        for name in ("schema-fields-unverified", "formats-not-verified", "requested-section-only",
                     "access-profile-unverified", "vdom-unverified", "vdom-override-unverified", "networking"):
            with self.subTest(name=name):
                context = checks_fortiadc.from_helper_metadata(
                    dict(METADATA, visibility_limitations=[name]), METADATA["content_sha256"])
                self.assertEqual(checks_fortiadc.build_context(context, METADATA["content_sha256"]).limitations,
                                 frozenset((name,)))

    def test_value_limitations_block_no_rule_and_a_section_export_blocks_every_rule(self):
        for names in (["formats-not-verified"], ["formats-not-verified", "schema-fields-unverified"]):
            with self.subTest(names=names):
                code, out, _ = audit(EXPORT, dict(METADATA, visibility_limitations=names), "--json")
                self.assertEqual(code, cli.EXIT_OK)
                self.assertEqual(json.loads(out)["coverage"]["actionable_gaps"], [])
        code, out, _ = audit(EXPORT, dict(METADATA, visibility_limitations=["requested-section-only"]), "--json")
        self.assertEqual(code, cli.EXIT_INCOMPLETE)
        gaps = json.loads(out)["coverage"]["actionable_gaps"]
        self.assertTrue(gaps)
        self.assertEqual({gap["reason"] for gap in gaps}, {"visibility:requested-section-only"})

    def test_a_marked_attribute_stays_an_actionable_gap(self):
        marked = EXPORT.replace("    set allowaccess https ping ssh snmp\n",
                                "    set allowaccess <UNVERIFIED:unclassified-field>\n", 1)
        self.assertNotEqual(marked, EXPORT)
        digest = hashlib.sha256(marked.encode()).hexdigest()
        code, out, _ = audit(marked, dict(METADATA, content_sha256=digest, snapshot_sha256=digest), "--json")
        self.assertEqual(code, cli.EXIT_INCOMPLETE)
        self.assertIn({"rule_id": "fortiadc.mgmt.plaintext-admin-access", "reason": "redacted-or-unverified-value"},
                      json.loads(out)["coverage"]["actionable_gaps"])
