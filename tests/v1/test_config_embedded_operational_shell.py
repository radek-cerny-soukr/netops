import hashlib
import json
from unittest import TestCase

from netops_helper import configuration as c, config_fortios

from test_config_embedded_operational import CHUNKS, FIRMWARES, EmbeddedOperationalCLI


LIVE_SHELL = (
    'diagnose test application hasync 1\n'
    'diag test application hasync 4\n'
    'fnsysctl ps\n'
    'fnsysctl df\n'
    'fnsysctl df -h\n'
    'fnsysctl du /tmp\n'
    'fnsysctl du -s /var/log\n'
    'fnsysctl du -h -d 1 /data2\n'
    'fnsysctl du -a -h --max-depth=2 /var/spool\n'
    'fnsysctl du -s ./node_modules+old ../log-2.1\n')

UNSUPPORTED = (
    'diagnose test application hasync\n',
    'diagnose test application hasync 1 2\n',
    'diagnose test application hasync x\n',
    'diagnose test application hasync -1\n',
    'diagnose test application fixture-extra 1\n',
    'fnsysctl ps aux\n',
    'fnsysctl df -h /tmp\n',
    'fnsysctl du\n',
    'fnsysctl du -a -h -s -c /tmp\n',
    'fnsysctl cat /tmp/fixture-extra\n',
    'fnsysctl du /tmp|fixture-extra\n',
    'fnsysctl du "/tmp;fixture-extra"\n',
    'fnsysctl du "/tmp>fixture-extra"\n',
    'fnsysctl du "/tmp&fixture-extra"\n',
    'fnsysctl du "$(fixture-extra)"\n',
    'fnsysctl du "`fixture-extra`"\n',
    'fnsysctl du "/tmp fixture-extra"\n',
    'fnsysctl du "/tmp\\tfixture-extra"\n',
    'fnsysctl du "~fixture-extra"\n',
    'fnsysctl du "*fixture-extra"\n',
    'fnsysctl du "/tmp/fixture-extra=x=y"\n',
    'fnsysctl du "=fixture-extra"\n',
    'fnsysctl du "' + 'fixture-extra/' * 74 + '"\n',
)


class EmbeddedOperationalShell(TestCase):
    render = EmbeddedOperationalCLI.render

    def test_live_shell_and_hasync_are_shown_with_real_arguments(self):
        for firmware in FIRMWARES:
            for chunk in CHUNKS:
                with self.subTest(firmware=firmware, chunk=chunk):
                    output, summary = self.render(LIVE_SHELL, chunk, firmware)
                    for line in LIVE_SHELL.splitlines():
                        self.assertIn(line, output)
                    self.assertEqual(summary['unverified_count'], 0)
                    self.assertEqual(summary['unsupported_format_count'], 0)

    def test_longest_public_path_is_shown(self):
        path = '/' + 'a' * 1023
        for firmware in FIRMWARES:
            with self.subTest(firmware=firmware):
                output, summary = self.render('fnsysctl du ' + path + '\n', 65536, firmware)
                self.assertIn('fnsysctl du ' + path, output)
                self.assertEqual(summary['unsupported_format_count'], 0)

    def test_nearest_invalid_arity_and_metacharacters_are_not_shown(self):
        for script in UNSUPPORTED:
            for firmware in FIRMWARES:
                for chunk in CHUNKS:
                    with self.subTest(script=script, firmware=firmware, chunk=chunk):
                        output, summary = self.render('diagnose sys vd list\n' + script, chunk, firmware)
                        self.assertNotIn('fixture-extra', output)
                        self.assertNotIn(script.strip(), output)
                        self.assertGreater(summary['unsupported_format_count'], 0)

    def test_known_secret_argument_is_redacted_and_neighbours_are_kept(self):
        cases = (('diagnose test application hasync 1234\n', 'diagnose test application hasync <REDACTED:credential#1>'),
                 ('fnsysctl df fixture-secret\n', 'fnsysctl df <REDACTED:credential#1>'),
                 ('fnsysctl du -s fixture-secret /var/log\n', 'fnsysctl du -s <REDACTED:credential#1> /var/log'),
                 ('fnsysctl du -h /data/fixture-secret/x -d 1\n', 'fnsysctl du -h <REDACTED:credential#1> -d 1'))
        for script, expected in cases:
            secret = '1234' if '1234' in script else 'fixture-secret'
            for firmware in FIRMWARES:
                for chunk in CHUNKS:
                    with self.subTest(script=script, firmware=firmware, chunk=chunk):
                        output, summary = self.render(script, chunk, firmware, (secret,))
                        self.assertNotIn(secret, output)
                        self.assertIn(expected, output)
                        self.assertEqual(summary['credential_redactions'], 1)
                        self.assertEqual(summary['unverified_count'], 0)

    def test_known_secret_inside_fixed_words_is_never_rendered(self):
        cases = (('diagnose test application hasync 1\n', 'hasync'), ('fnsysctl ps\n', 'ps'),
                 ('fnsysctl df -h\n', 'df'), ('fnsysctl du /tmp\n', 'du'))
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

    def test_shell_lines_are_not_accepted_as_top_level_configuration(self):
        for firmware in FIRMWARES:
            with self.subTest(firmware=firmware):
                stream = c.StreamRedactor((), 'all', policy=config_fortios.policy_for(firmware))
                try:
                    with self.assertRaises(c.ConfigurationRedactionError):
                        stream.feed(LIVE_SHELL.encode())
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
