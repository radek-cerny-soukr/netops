import contextlib
import hashlib
import io
import json
import tempfile
from pathlib import Path
from unittest import TestCase

from netops_auditor import cli
from test_config_fortiadc import READ, RIGHTS, capture, config, live, profile_lines

SNAPSHOT = (
    'config system admin\n    edit "admin"\n        set trusted-hosts 192.0.2.0/24\n    next\nend\n'
    'config system interface\n    edit "port1"\n        set allowaccess https ping ssh\n    next\nend\n'
    'config load-balance client-ssl-profile\n    edit "csp1"\n        set ssl-allowed-versions tlsv1.2 tlsv1.3\n    next\nend\n'
    'config load-balance pool\n    edit "pool1"\n        set health-check-ctrl enable\n'
    '        config pool_member\n            edit 1\n                set ip 192.0.2.10\n            next\n'
    '            edit 2\n                set ip 192.0.2.11\n            next\n        end\n    next\nend\n'
)
FACTORY = 'fortiadc.tls.factory-certificate'
PLAIN = 'fortiadc.mgmt.plaintext-admin-access'


class CollectorProfileCoverage(TestCase):
    def audit(self, rights, text=SNAPSHOT):
        scope = capture(live(config(profiles=profile_lines(rights=rights))))[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, metadata = root / 'snapshot.conf', root / 'meta.json'
            snapshot.write_text(text)
            metadata.write_text(json.dumps({
                'firmware': {'model': 'FortiADC-KVM', 'version': '7.6.7', 'build': '0676'},
                'config_scope': scope['config_scope'], 'configuration_complete': scope['configuration_complete'],
                'visibility_limitations': scope['visibility_limitations'], 'content_sha256': hashlib.sha256(text.encode()).hexdigest(),
                'unverified_count': 0, 'unsupported_format_count': 0}))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.main(['run', '--platform', 'fortiadc', '--tenant', 't', '--device', 'd', '--config', str(snapshot),
                                 '--snapshot-meta', str(metadata), '--json'])
        return scope, code, json.loads(out.getvalue())

    def test_a_profile_without_networking_read_is_an_actionable_gap(self):
        scope, code, report = self.audit(RIGHTS)
        self.assertIn('networking', scope['visibility_limitations'])
        self.assertEqual(code, cli.EXIT_INCOMPLETE)
        self.assertIn(PLAIN, {gap['rule_id'] for gap in report['coverage']['actionable_gaps']})
        self.assertEqual([gap['rule_id'] for gap in report['coverage']['inherent_gaps']], [FACTORY])

    def test_a_full_read_only_profile_leaves_only_the_factory_certificate(self):
        scope, code, report = self.audit(READ)
        self.assertEqual(scope['visibility_limitations'], [])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['coverage']['actionable_gaps'], [])
        self.assertEqual([gap['rule_id'] for gap in report['coverage']['inherent_gaps']], [FACTORY])
        self.assertFalse(report['evaluation_complete'])

    def test_unset_allowaccess_of_the_defaults_export_is_an_empty_list(self):
        # `show full-configuration` writes `unset allowaccess` for an interface without administrative access.
        unset = SNAPSHOT.replace('    next\nend\nconfig load-balance client-ssl-profile',
                                 '    next\n    edit "port4"\n        unset allowaccess\n    next\nend\n'
                                 'config load-balance client-ssl-profile', 1)
        self.assertIn('unset allowaccess', unset)
        _, code, report = self.audit(READ, unset)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(report['coverage']['actionable_gaps'], [])
        missing = unset.replace('        unset allowaccess\n', '')
        _, code, report = self.audit(READ, missing)
        self.assertEqual(code, cli.EXIT_INCOMPLETE)
        self.assertEqual(report['coverage']['actionable_gaps'], [{'rule_id': PLAIN, 'reason': 'default-undocumented'}])
        # Only allowaccess has a stated meaning when unset; unset trusted hosts stay undocumented.
        hosts = SNAPSHOT.replace('        set trusted-hosts 192.0.2.0/24\n', '        unset trusted-hosts\n')
        _, code, report = self.audit(READ, hosts)
        self.assertEqual(code, cli.EXIT_INCOMPLETE)
        self.assertEqual(report['coverage']['actionable_gaps'],
                         [{'rule_id': 'fortiadc.mgmt.trusted-hosts-open', 'reason': 'default-undocumented'}])
