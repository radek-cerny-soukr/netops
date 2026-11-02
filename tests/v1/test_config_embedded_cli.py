import shlex
from unittest import TestCase

from netops_helper import configuration as c, config_fortios


class EmbeddedCLIConfiguration(TestCase):
    def render(self, script, chunk=7, firmware=('FortiGate-60F', '7.6.8', '3744')):
        raw = 'config system auto-script\nedit diagnostic\nset script ' + shlex.quote(script) + '\nnext\nend\n'
        stream = c.StreamRedactor((), 'all', policy=config_fortios.policy_for(firmware))
        try:
            data = raw.encode()
            for index in range(0, len(data), chunk):
                stream.feed(data[index:index + chunk])
            content, hidden, count = stream.finish()
            return content.page(0, content.total)[0], stream.summary()
        finally:
            stream.close()

    def test_network_script_keeps_routes_and_redacts_actual_credentials(self):
        script = ('config vpn ipsec phase1-interface\nedit branch\n'
                  'set interface wan1\nset remote-gw 192.0.2.7\n'
                  'set psksecret fixture-private-psk\nnext\nend\n')
        for firmware in (('FortiGate-60F', '7.6.8', '3744'), ('FortiGate-VM64', '8.0.2', '0251')):
            for chunk in (1, 7, 65536):
                with self.subTest(firmware=firmware, chunk=chunk):
                    output, summary = self.render(script, chunk, firmware)
                    self.assertIn('set remote-gw 192.0.2.7', output)
                    self.assertIn('set interface wan1', output)
                    self.assertNotIn('fixture-private-psk', output)
                    self.assertIn('REDACTED:credential#1', output)
                    self.assertEqual(summary['credential_redactions'], 1)
                    self.assertEqual(summary['unverified_count'], 0)

    def test_unrecognized_commands_do_not_escape_the_configuration_parser(self):
        for script in ('execute reboot', 'set password fixture-private', 'config system global\nset unclassified fixture-private\nend'):
            with self.subTest(script=script):
                output, summary = self.render(script)
                self.assertIn('UNVERIFIED:unsupported-format', output)
                self.assertNotIn('fixture-private', output)
                self.assertEqual(summary['unsupported_format_count'], 1)

    def test_nested_scripts_are_bounded(self):
        script = 'config system interface\nedit wan1\nset ip 192.0.2.1 255.255.255.0\nnext\nend'
        for unused in range(4):
            script = 'config system auto-script\nedit nested\nset script ' + shlex.quote(script) + '\nnext\nend'
        output, summary = self.render(script, 1)
        self.assertIn('UNVERIFIED:unsupported-format', output)
        self.assertEqual(summary['unsupported_format_count'], 1)

    def test_embedded_script_does_not_strip_ssh_prompt_like_text(self):
        output, summary = self.render('FG # config system global\nend\n', 1)
        self.assertIn('UNVERIFIED:unsupported-format', output)
        self.assertEqual(summary['unsupported_format_count'], 1)
