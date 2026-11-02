import hashlib
import json
from unittest import TestCase

from netops_helper import configuration as c, config_fortios

from test_config_embedded_operational import CHUNKS, FIRMWARES, EmbeddedOperationalCLI


ACTUAL_802 = (
    'get system ha status\n'
    'get sys ha status\n'
    'diagnose test application hasync 2\n'
    'diag test app hasync 3\n'
    'diagnose sys profile report\n'
    'diag sys profile report\n')

UNSUPPORTED = (
    'get sys ha status fixture-extra\n',
    'get system ha\n',
    'diag test app hasync\n',
    'diag test app hasync 3 4\n',
    'diag test app hasync fixture-extra\n',
    'diag test app wad 3\n',
    'diag test ap hasync 3\n',
    'diag sys profile report fixture-extra\n',
    'diag sys prof report\n',
)


class EmbeddedOperationalActual802(TestCase):
    render = EmbeddedOperationalCLI.render

    def test_actual_802_forms_are_shown_as_stored(self):
        for firmware in FIRMWARES:
            for chunk in CHUNKS:
                with self.subTest(firmware=firmware, chunk=chunk):
                    output, summary = self.render(ACTUAL_802, chunk, firmware)
                    for line in ACTUAL_802.splitlines():
                        self.assertIn(line, output)
                    self.assertEqual(summary['unverified_count'], 0)
                    self.assertEqual(summary['unsupported_format_count'], 0)

    def test_nearest_invalid_forms_are_not_shown(self):
        for script in UNSUPPORTED:
            for firmware in FIRMWARES:
                with self.subTest(script=script, firmware=firmware):
                    output, summary = self.render('diagnose sys vd list\n' + script, 7, firmware)
                    self.assertNotIn(script.strip(), output)
                    self.assertNotIn('fixture-extra', output)
                    self.assertGreater(summary['unsupported_format_count'], 0)

    def test_known_secret_in_stored_words_is_never_rendered(self):
        cases = (('get sys ha status\n', 'sys'), ('diag test app hasync 3\n', 'app'),
                 ('diag sys profile report\n', 'report'))
        for script, secret in cases:
            for firmware in FIRMWARES:
                with self.subTest(script=script, firmware=firmware):
                    stream = c.StreamRedactor((secret,), 'all', policy=config_fortios.policy_for(firmware))
                    try:
                        self.assertIsNone(stream._embedded_cli([script]))
                    finally:
                        stream.close()

    def test_known_secret_as_test_level_is_redacted_in_place(self):
        for firmware in FIRMWARES:
            with self.subTest(firmware=firmware):
                output, summary = self.render('diag test app hasync 1234\n', 7, firmware, ('1234',))
                self.assertNotIn('1234', output)
                self.assertIn('diag test app hasync <REDACTED:credential#1>', output)
                self.assertEqual(summary['credential_redactions'], 1)

    def test_actual_802_forms_are_not_accepted_as_top_level_configuration(self):
        for firmware in FIRMWARES:
            with self.subTest(firmware=firmware):
                stream = c.StreamRedactor((), 'all', policy=config_fortios.policy_for(firmware))
                try:
                    with self.assertRaises(c.ConfigurationRedactionError):
                        stream.feed(ACTUAL_802.encode())
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
