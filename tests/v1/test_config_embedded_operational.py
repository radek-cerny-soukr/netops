import shlex
from unittest import TestCase

from netops_helper import configuration as c, config_fortios


FIRMWARES = (('FortiGate-60F', '7.6.8', '3744'), ('FortiGate-VM64', '8.0.2', '0251'))
CHUNKS = (1, 7, 65536)
class EmbeddedOperationalCLI(TestCase):
    def render(self, script, chunk=7, firmware=FIRMWARES[0], forbidden=()):
        raw = 'config system auto-script\nedit diagnostic\nset script ' + shlex.quote(script) + '\nnext\nend\n'
        stream = c.StreamRedactor(forbidden, 'all', policy=config_fortios.policy_for(firmware))
        try:
            data = raw.encode()
            for index in range(0, len(data), chunk):
                stream.feed(data[index:index + chunk])
            content, hidden, count = stream.finish()
            return content.page(0, content.total)[0], stream.summary()
        finally:
            stream.close()

    def test_operational_script_is_also_shown_in_automation_action(self):
        raw = ('config system automation-action\nedit run-diag\nset action-type cli-script\n'
               'set script ' + shlex.quote(CODEX_PAYLOAD) + '\nnext\nend\n')
        for firmware in FIRMWARES:
            with self.subTest(firmware=firmware):
                stream = c.StreamRedactor((), 'all', policy=config_fortios.policy_for(firmware))
                try:
                    stream.feed(raw.encode())
                    content, hidden, count = stream.finish()
                    output = content.page(0, content.total)[0]
                    summary = stream.summary()
                finally:
                    stream.close()
                self.assertIn('diag sys top 5 20', output)
                self.assertIn('get system arp', output)
                self.assertEqual(summary['unverified_count'], 0)

    def test_credential_argument_not_known_to_the_redactor_never_appears(self):
        scripts = (
            'diag sys top 5 20\ndiagnose test authserver ldap srv1 jdoe fixture-unknown-pass\n',
            'get system arp\nexecute restore config ftp cfg.conf 192.0.2.5 backup fixture-unknown-pass\n',
            'get system status\nexecute ssh admin@192.0.2.9\nexecute ssh-options password fixture-unknown-pass\n',
            'diag sys top 5 20\ndiagnose test authserver tacacs+ srv1 jdoe fixture-unknown-pass\nget system arp\n',
            'diag sys top 5 20\ndiagnose debug black-box upload breached-file sftp 192.0.2.8 backup fixture-unknown-pass /logs/f.log 20261029\n',
        )
        for script in scripts:
            for chunk in CHUNKS:
                with self.subTest(script=script, chunk=chunk):
                    output, summary = self.render(script, chunk)
                    self.assertNotIn('fixture-unknown-pass', output)
                    self.assertGreater(summary['unsupported_format_count'], 0)

    def test_forbidden_secret_as_operational_argument_never_appears(self):
        secret = 'fixture-forbidden-secret'
        scripts = ('diag sys top 5 ' + secret + '\n',
                   'get system arp ' + secret + '\n',
                   'diag sys top 5 20\ndiagnose debug enable ' + secret + '\n')
        for script in scripts:
            for chunk in CHUNKS:
                for firmware in FIRMWARES:
                    with self.subTest(script=script, chunk=chunk, firmware=firmware):
                        output, summary = self.render(script, chunk, firmware, (secret,))
                        self.assertNotIn(secret, output)

    def test_known_secret_argument_is_redacted_without_hiding_public_arguments(self):
        for firmware in FIRMWARES:
            for chunk in CHUNKS:
                with self.subTest(firmware=firmware, chunk=chunk):
                    output, summary = self.render('diag sys top 1 1234 20\n', chunk, firmware, ('1234',))
                    self.assertNotIn('1234', output)
                    self.assertIn('diag sys top 1 <REDACTED:credential#1> 20', output)
                    self.assertEqual(summary['credential_redactions'], 1)
                    self.assertEqual(summary['unverified_count'], 0)

    def test_known_secret_inside_fixed_prefix_is_never_rendered(self):
        for firmware in FIRMWARES:
            for chunk in CHUNKS:
                with self.subTest(firmware=firmware, chunk=chunk, secret='status'):
                    output, summary = self.render('get system status\n', chunk, firmware, ('status',))
                    self.assertNotIn('status', output)
                    self.assertTrue('<UNVERIFIED:' in output or '<REDACTED:' in output)
            with self.subTest(firmware=firmware, secret='system'):
                for forbidden in ((), ('system',)):
                    stream = c.StreamRedactor(forbidden, 'all', policy=config_fortios.policy_for(firmware))
                    try:
                        text = stream._embedded_cli(['get system status\n'])
                    finally:
                        stream.close()
                    if forbidden:
                        self.assertIsNone(text)
                    else:
                        self.assertEqual(text.strip(), 'get system status')


CODEX_PAYLOAD = (
    'get system status\n'
    'get system performance status\n'
    'get system arp\n'
    'diag sys top 5 20\n'
    'diagnose sys top\n'
    'diagnose sys top 5\n'
    'diagnose sys top 5 20\n'
    'diagnose sys top 5 20 1\n'
    'diag sys process pidof sshd\n')


class EmbeddedOperationalPayloadAndTopLevel(TestCase):
    render = EmbeddedOperationalCLI.render

    def test_pure_operational_payload_is_shown_with_real_arguments(self):
        for firmware in FIRMWARES:
            for chunk in CHUNKS:
                with self.subTest(firmware=firmware, chunk=chunk):
                    output, summary = self.render(CODEX_PAYLOAD, chunk, firmware)
                    for line in CODEX_PAYLOAD.splitlines():
                        self.assertIn(line, output)
                    self.assertEqual(summary['unverified_count'], 0)
                    self.assertEqual(summary['unsupported_format_count'], 0)

    def test_same_operational_lines_are_not_accepted_as_top_level_configuration(self):
        for firmware in FIRMWARES:
            for chunk in CHUNKS:
                with self.subTest(firmware=firmware, chunk=chunk):
                    stream = c.StreamRedactor((), 'all', policy=config_fortios.policy_for(firmware))
                    try:
                        data = CODEX_PAYLOAD.encode()
                        with self.assertRaises(c.ConfigurationRedactionError):
                            for index in range(0, len(data), chunk):
                                stream.feed(data[index:index + chunk])
                            stream.finish()
                    finally:
                        stream.close()

    def test_policy_identifier_changes_with_embedded_cli_semantics(self):
        import hashlib
        import json
        for firmware in FIRMWARES:
            with self.subTest(firmware=firmware):
                policy = config_fortios.policy_for(firmware)
                material = (policy.platform, sorted(policy.public_fields), sorted(policy.public_edit_sections),
                            sorted(policy.opaque_sections), sorted(policy.header_keys), policy.allow_vdom,
                            sorted(policy.secret_fields), sorted(policy.unverified_fields), 'embedded-cli-6',
                            sorted(policy.inline_header_fields), sorted(policy.sibling_header_fields))
                digest = hashlib.sha256(json.dumps(material, separators=(',', ':')).encode()).hexdigest()
                self.assertEqual(policy.identifier, policy.platform + '-full-2:' + digest)
