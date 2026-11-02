from unittest import TestCase

from netops_helper import configuration as c, config_fortios
from test_config_embedded_operational import CHUNKS, FIRMWARES, EmbeddedOperationalCLI


class EmbeddedOperationalGetAliases(TestCase):
    render = EmbeddedOperationalCLI.render

    def test_verified_get_shapes_keep_the_stored_abbreviations(self):
        script = ('get system perf stat\nget sys performance status\n'
                  'get sys stat\nget system a\n')
        for firmware in FIRMWARES:
            for chunk in CHUNKS:
                with self.subTest(firmware=firmware, chunk=chunk):
                    output, summary = self.render(script, chunk, firmware)
                    for line in script.splitlines():
                        self.assertIn(line, output)
                    self.assertEqual(summary['unsupported_format_count'], 0)
                    self.assertEqual(summary['credential_redactions'], 0)

    def test_unknown_incomplete_extra_and_nonprefix_words_stay_unsupported(self):
        for script in ('get sys\n', 'get system perf\n', 'get system performance status extra\n',
                       'get system fixture-unknown status\n', 'get system perfx status\n',
                       'get sys stat extra\n', 'get system arpx\n', 'g system status\n'):
            for firmware in FIRMWARES:
                with self.subTest(script=script, firmware=firmware):
                    output, summary = self.render('get system status\n' + script, 7, firmware)
                    self.assertIn('<UNVERIFIED:unsupported-format>', output)
                    self.assertGreater(summary['unsupported_format_count'], 0)

    def test_known_secret_in_stored_abbreviation_is_not_published(self):
        for firmware in FIRMWARES:
            with self.subTest(firmware=firmware):
                stream = c.StreamRedactor(('perf',), 'all', policy=config_fortios.policy_for(firmware))
                try:
                    self.assertIsNone(stream._embedded_cli(['get system perf stat\n']))
                finally:
                    stream.close()
