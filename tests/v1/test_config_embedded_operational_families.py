import hashlib
import json
from unittest import TestCase

from netops_helper import configuration as c, config_fortios

from test_config_embedded_operational import CHUNKS, FIRMWARES, EmbeddedOperationalCLI


LIVE_FAMILIES = (
    'diagnose sys session stat\n'
    'diag sys session6 stat\n'
    'diagnose sys vd list\n'
    'diagnose sys cmdb info\n'
    'diagnose hardware sysinfo memory\n'
    'diag hardware sysinfo slab\n'
    'diagnose sys mpstat\n'
    'diagnose sys mpstat 5\n'
    'diagnose sys mpstat 5 20\n'
    'diagnose sys top-mem\n'
    'diagnose sys top-mem 10\n'
    'diag sys top-fd\n'
    'diagnose sys top-fd 10\n'
    'diagnose sys profile cpumask\n'
    'diagnose sys profile module\n'
    'diagnose sys profile show\n'
    'diagnose sys profile start\n'
    'diagnose sys profile stop\n'
    'diagnose sys profile sysmap\n'
    'fnsysctl date\n')

UNSUPPORTED = (
    'diagnose sys session\n',
    'diagnose sys session stat fixture-extra\n',
    'diagnose sys vd list fixture-extra\n',
    'diagnose sys cmdb\n',
    'diagnose hardware sysinfo slab fixture-extra\n',
    'diagnose sys mpstat 5 20 1\n',
    'diagnose sys mpstat fixture-extra\n',
    'diagnose sys top-mem 10 20\n',
    'diagnose sys top-fd fixture-extra\n',
    'diagnose sys profile\n',
    'diagnose sys profile fixture-extra\n',
    'diagnose sys profile show detail\n',
    'diagnose sys profile step\n',
    'diagnose sys profile step 2\n',
    'diagnose sys profile status\n',
    'fnsysctl date fixture-extra\n',
    'fnsysctl\n',
)


class EmbeddedOperationalLiveFamilies(TestCase):
    render = EmbeddedOperationalCLI.render

    def test_live_families_are_shown_with_real_arguments(self):
        for firmware in FIRMWARES:
            for chunk in CHUNKS:
                with self.subTest(firmware=firmware, chunk=chunk):
                    output, summary = self.render(LIVE_FAMILIES, chunk, firmware)
                    for line in LIVE_FAMILIES.splitlines():
                        self.assertIn(line, output)
                    self.assertEqual(summary['unverified_count'], 0)
                    self.assertEqual(summary['unsupported_format_count'], 0)

    def test_nearest_invalid_arity_and_unknown_words_are_not_shown(self):
        for script in UNSUPPORTED:
            for firmware in FIRMWARES:
                for chunk in CHUNKS:
                    with self.subTest(script=script, firmware=firmware, chunk=chunk):
                        output, summary = self.render('diagnose sys vd list\n' + script, chunk, firmware)
                        self.assertNotIn(script.strip(), output)
                        self.assertNotIn('fixture-extra', output)
                        self.assertGreater(summary['unsupported_format_count'], 0)

    def test_known_secret_as_numeric_argument_is_redacted_in_place(self):
        cases = (('diagnose sys top-mem 1234\n', 'diagnose sys top-mem <REDACTED:credential#1>'),
                 ('diagnose sys top-fd 1234\n', 'diagnose sys top-fd <REDACTED:credential#1>'),
                 ('diagnose sys mpstat 5 1234\n', 'diagnose sys mpstat 5 <REDACTED:credential#1>'))
        for script, expected in cases:
            for firmware in FIRMWARES:
                for chunk in CHUNKS:
                    with self.subTest(script=script, firmware=firmware, chunk=chunk):
                        output, summary = self.render(script, chunk, firmware, ('1234',))
                        self.assertNotIn('1234', output)
                        self.assertIn(expected, output)
                        self.assertEqual(summary['credential_redactions'], 1)
                        self.assertEqual(summary['unverified_count'], 0)

    def test_known_secret_inside_fixed_words_is_never_rendered(self):
        cases = (('diagnose hardware sysinfo slab\n', 'slab'), ('diagnose sys profile sysmap\n', 'sysmap'),
                 ('diagnose sys session6 stat\n', 'session6'), ('fnsysctl date\n', 'date'))
        for script, secret in cases:
            for firmware in FIRMWARES:
                with self.subTest(script=script, firmware=firmware):
                    stream = c.StreamRedactor((secret,), 'all', policy=config_fortios.policy_for(firmware))
                    try:
                        self.assertIsNone(stream._embedded_cli([script]))
                    finally:
                        stream.close()
                    stream = c.StreamRedactor((), 'all', policy=config_fortios.policy_for(firmware))
                    try:
                        self.assertEqual(stream._embedded_cli([script]).strip(), script.strip())
                    finally:
                        stream.close()

    def test_live_families_are_not_accepted_as_top_level_configuration(self):
        for firmware in FIRMWARES:
            with self.subTest(firmware=firmware):
                stream = c.StreamRedactor((), 'all', policy=config_fortios.policy_for(firmware))
                try:
                    with self.assertRaises(c.ConfigurationRedactionError):
                        stream.feed(LIVE_FAMILIES.encode())
                        stream.finish()
                finally:
                    stream.close()

    def test_policy_identifier_changes_with_embedded_cli_semantics(self):
        for firmware in FIRMWARES:
            with self.subTest(firmware=firmware):
                policy = config_fortios.policy_for(firmware)
                material = (policy.platform, sorted(policy.public_fields), sorted(policy.public_edit_sections),
                            sorted(policy.opaque_sections), sorted(policy.header_keys), policy.allow_vdom,
                            sorted(policy.secret_fields), sorted(policy.unverified_fields), 'embedded-cli-6',
                            sorted(policy.inline_header_fields), sorted(policy.sibling_header_fields))
                digest = hashlib.sha256(json.dumps(material, separators=(',', ':')).encode()).hexdigest()
                self.assertEqual(policy.identifier, policy.platform + '-full-2:' + digest)
