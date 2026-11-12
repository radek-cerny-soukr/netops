import dataclasses
import json
from types import SimpleNamespace
from unittest import TestCase
from netops_helper import configuration as c
from netops_helper import config_fortios
from netops_helper.config_limits import ConfigurationLimits


FW = ('FortiGate-VM64', '7.6.8', '3744')


def policy(platform='fortios', fields=(), edits=(), opaque=(), headers=(), vdom=False, private=()):
    return c.FullConfigPolicy(platform, frozenset(fields), frozenset(edits),
                              frozenset(opaque), frozenset(headers), vdom, secret_fields=frozenset(private))


def auth(platform='fortinet'):
    return SimpleNamespace(alias='fixture', host='192.0.2.20', port=22, login='reader',
                           host_key_fingerprint='SHA256:fixture', credential_kind='password',
                           secret='AUTH-SENTINEL', secrets=('AUTH-SENTINEL',), ssh_platform=platform,
                           configuration_limits=ConfigurationLimits())


def render(raw, selected, chunk=7, forbidden=()):
    stream = c.StreamRedactor(forbidden, 'all', policy=selected)
    data = raw.encode()
    for start in range(0, len(data), chunk):
        stream.feed(data[start:start + chunk])
    return stream.finish()


def text(content):
    return content.page(0, content.total)[0]


class FullConfigurationRedaction(TestCase):
    def setUp(self):
        c._SNAPSHOTS.clear()
        c._DIFFS.clear()
        self.addCleanup(c._SNAPSHOTS.clear)
        self.addCleanup(c._DIFFS.clear)

    def test_network_values_object_names_references_and_unknown_values(self):
        fields = [(('system interface',), key) for key in ('ip', 'allowaccess', 'status')]
        selected = policy(fields=fields, edits=[('system interface',)])
        raw = ('config system interface\n edit "WAN 1"\n'
               ' set ip 192.0.2.1 255.255.255.0\n set allowaccess ping https ssh\n'
               ' set status up\n set unknown "PRIVATE-UNKNOWN"\n next\nend\n')
        result, hidden, count = render(raw, selected)
        visible = text(result)
        self.assertIn('edit "WAN 1"', visible)
        self.assertIn('set ip 192.0.2.1 255.255.255.0', visible)
        self.assertIn('set allowaccess ping https ssh', visible)
        self.assertIn('set status up', visible)
        self.assertIn('set unknown <UNVERIFIED:unclassified-field>', visible)
        self.assertNotIn('PRIVATE-UNKNOWN', visible)
        self.assertEqual((len(hidden), count), (0, 1))

        fortios_policy = config_fortios.policy_for(('FortiGate-60F', '7.6.8', '3744'))
        port_raw = ('config switch-controller managed-switch\n edit "SYNTHETIC-SWITCH"\n'
                    ' config ports\n edit "port1"\n set dsl-profile default\n'
                    ' next\n end\n next\nend\n')
        port_result, port_hidden, port_count = render(port_raw, fortios_policy)
        self.assertIn('set dsl-profile default', text(port_result))
        self.assertEqual((len(port_hidden), port_count), (0, 0))

    def test_exact_credentials_override_public_map_and_diagnostic_names_survive(self):
        private = ('password', 'api-key', 'secret', 'psksecret', 'private-key', 'token')
        public = ('hash', 'salt', 'community', 'script', 'comment')
        selected = policy(fields=[(('system global',), field) for field in private + public],
                          private=[(('system global',), field) for field in private])
        body = ''.join(' set ' + field + ' "fixture-' + field + '"\n' for field in private + public)
        result, hidden, count = render('config system global\n' + body + 'end\n', selected)
        self.assertEqual(count, len(private))
        for field in private:
            self.assertNotIn('fixture-' + field, text(result))
        for field in public:
            self.assertIn('set ' + field + ' fixture-' + field, text(result))
        self.assertEqual(len(hidden.data), 0)

    def test_sensitive_values_across_chunks_and_multiline_are_never_persisted(self):
        selected = policy(fields=[(('system global',), 'hostname')])
        for value in ('ENC PRIVATE-ENC', '$6$PRIVATE-HASH', '$2b$PRIVATE-HASH',
                      '-----BEGIN PRIVATE KEY-----\nPRIVATE-PEM\n-----END PRIVATE KEY-----',
                      'PRIVATE-FORBIDDEN'):
            serialized = value if value.startswith('ENC ') else '"' + value + '"'
            raw = 'config system global\n set hostname ' + serialized + '\nend\n'
            for size in (1, 7, 65536):
                with self.subTest(value=value[:12], chunk=size):
                    result, hidden, count = render(raw, selected, size, ('PRIVATE-FORBIDDEN',))
                    self.assertEqual(text(result), 'config system global\n    set hostname <REDACTED:credential#1>\nend\n')
                    self.assertFalse(hidden.data)
                    self.assertEqual(count, 1)

    def test_diagnostic_multiline_value_is_not_a_credential_by_itself(self):
        selected = policy(fields=[(('system global',), 'hostname')])
        for value in ('one\nPUBLIC-MULTILINE', 'ENC means encryption here'):
            with self.subTest(value=value):
                result, hidden, count = render('config system global\n set hostname "' + value + '"\nend\n', selected, 1)
                self.assertIn('PUBLIC-MULTILINE' if 'PUBLIC-MULTILINE' in value else value, text(result))
                self.assertEqual((len(hidden), count), (0, 0))

    def test_full_snapshot_and_diff_do_not_cache_credential_fingerprints(self):
        selected = policy(fields=[(('system global',), 'hostname')], private=[(('system global',), 'password')])
        snapshots = []
        for secret in ('PRIVATE-PASSWORD-A', 'PRIVATE-PASSWORD-B'):
            result = render('config system global\n set hostname router\n set password "' + secret + '"\nend\n', selected)
            snapshots.append(c.store(auth(), *result, 'all', FW, profile=selected.identifier))
        left, right = [c.get_snapshot(auth(), item, 'all', profile=selected.identifier) for item in snapshots]
        self.assertEqual(left.text, right.text)
        self.assertFalse(left.hidden.data)
        self.assertFalse(right.hidden.data)
        compared, changes, identical = c.compare(auth(), *snapshots)
        self.assertTrue(identical)
        self.assertEqual(text(compared), '')
        self.assertEqual(len(changes), 0)
        self.assertNotIn('PRIVATE-PASSWORD', repr(c._SNAPSHOTS))

    def test_profiles_are_vendor_and_policy_bound_and_cannot_mix(self):
        one = policy(fields=[(('system global',), 'hostname')])
        two = policy(fields=[(('system global',), 'hostname'), (('system global',), 'timezone')])
        adc = policy('fortiadc', fields=[(('system global',), 'hostname')])
        self.assertEqual(one.identifier, policy(fields=[(('system global',), 'hostname')]).identifier)
        self.assertEqual(len({one.identifier, two.identifier, adc.identifier}), 3)
        ids = []
        for selected in (one, two):
            out = render('config system global\n set hostname router\nend\n', selected)
            ids.append(c.store(auth(), *out, 'all', FW, profile=selected.identifier))
        with self.assertRaisesRegex(ValueError, 'profile mismatch'):
            c.compare(auth(), *ids)
        with self.assertRaises(ValueError):
            c.get_snapshot(auth(), ids[0], 'all')
        with self.assertRaises(ValueError):
            out = render('config system global\nend\n', adc)
            c.store(auth('fortiadc'), *out, 'all', FW, platform='fortiadc', profile=one.identifier)

    def test_adc_underscores_status_and_unterminated_prompt(self):
        selected = policy('fortiadc', fields=[
            (('load-balance pool', 'pool_member'), 'pool_member_service_port'),
            (('load-balance pool', 'pool_member'), 'status')],
            edits=[('load-balance pool',), ('load-balance pool', 'pool_member')])
        raw = ('ADC # config load-balance pool\n edit "pool-1"\n config pool_member\n'
               ' edit "backend-1"\n set pool_member_service_port 8443\n'
               ' set status enable\n next\n end\n next\nend\nADC # ')
        for size in (1, 7, 65536):
            out, hidden, count = render(raw, selected, size)
            self.assertIn('set pool_member_service_port 8443', text(out))
            self.assertIn('set status enable', text(out))
            self.assertNotIn('ADC #', text(out))
            self.assertEqual((len(hidden), count), (0, 0))
        minimal, _, _ = c.redact('config system global\n set bad_field value\nend\n', (), 'all')
        self.assertIn('set bad_field <REDACTED>', text(minimal))
        with self.assertRaises(ValueError):
            policy(fields=[(('system global',), 'bad;field')])

    def test_full_path_nested_sections_and_opaque_prefix(self):
        selected = policy('fortiadc', fields=[(('outer', 'inner'), 'value'),
                                             (('other', 'inner'), 'value')],
                          edits=[('outer',)], opaque=[('other',)])
        raw = ('config outer\n edit a\n config inner\n set value visible\nend\nnext\nend\n'
               'config other\n config inner\n set value PRIVATE-OPAQUE\nend\nend\n'
               'config inner\n set value PRIVATE-WRONG-CONTEXT\nend\n')
        out, hidden, count = render(raw, selected)
        self.assertIn('set value visible', text(out))
        self.assertNotIn('PRIVATE-', text(out))
        self.assertEqual((len(hidden), count), (0, 2))

    def test_header_and_vdom_admission_are_explicit(self):
        raw = '#config-version=PRIVATE-HEADER\nconfig system global\nend\n'
        with self.assertRaises(ValueError):
            render(raw, policy('fortiadc'))
        out, _, _ = render(raw, policy(headers=['config-version']))
        self.assertIn('#config-version=PRIVATE-HEADER', text(out))
        raw = 'config vdom\n edit tenant\n config system global\nend\nnext\nend\n'
        with self.assertRaises(ValueError):
            render(raw, policy())
        out, _, _ = render(raw, policy(vdom=True, edits=[('vdom',)]))
        self.assertIn('edit tenant', text(out))

    def test_cert_reference_is_public_only_in_exact_path_and_material_never_is(self):
        selected = policy('fortiadc', fields=[(('load-balance client-ssl-profile',), 'local-cert')])
        raw = ('config load-balance client-ssl-profile\n set local-cert "cert-production"\nend\n'
               'config other\n set local-cert "PRIVATE-UNLISTED"\nend\n')
        out, _, _ = render(raw, selected)
        self.assertIn('set local-cert cert-production', text(out))
        self.assertNotIn('PRIVATE-UNLISTED', text(out))

    def test_legacy_redaction_remains_conservative_and_records_changes(self):
        raw = 'config system interface\n edit "PRIVATE-OBJECT"\n set ip 192.0.2.1 255.255.255.0\n set status up\nnext\nend\n'
        out, hidden, count = c.redact(raw, (), 'all')
        self.assertNotIn('PRIVATE-OBJECT', text(out))
        self.assertNotIn('192.0.2.1', text(out))
        self.assertIn('set status up', text(out))
        self.assertEqual((len(hidden), count), (2, 2))

    def test_truncated_malformed_policy_and_multiline_object_never_leak(self):
        for raw in ('config system global\n set hostname "unfinished',
                    'config system global\n set hostname router\n',
                    'config system global\nend\nexecute unsafe\n'):
            with self.assertRaises(ValueError):
                render(raw, policy(fields=[(('system global',), 'hostname')]))
        with self.assertRaises(ValueError):
            c.FullConfigPolicy('fortios', set())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy().platform = 'fortiadc'

    def test_adc_mixed_case_config_and_fields_preserve_documented_names(self):
        selected = policy('fortiadc', fields=[
            (('system certificate OCSP_stapling',), 'baseDN'),
            (('system certificate OCSP_stapling',), 'timeout_tcp_session_after_FIN')])
        out, hidden, count = render(
            'config system certificate OCSP_stapling\n set baseDN "dc=example,dc=test"\n'
            ' set timeout_tcp_session_after_FIN 30\nend\n', selected, 1)
        self.assertIn('set baseDN "dc=example,dc=test"', text(out))
        self.assertIn('set timeout_tcp_session_after_FIN 30', text(out))
        self.assertEqual((len(hidden), count), (0, 0))
        with self.assertRaises(ValueError):
            policy(fields=[(('system global',), 'base;DN')])

    def test_compound_and_mixed_case_credentials_override_public_map(self):
        for fields in (('aws-secretkey',), ('bindPassword', 'accessToken', 'KSK-KEY', 'apiCredential')):
            with self.subTest(fields=fields):
                selected = policy('fortiadc', fields=[(('system global',), field) for field in fields],
                                  private=[(('system global',), field) for field in fields])
                out, hidden, count = render('config system global\n' +
                    ''.join(' set ' + field + ' PRIVATE-COMPOUND\n' for field in fields) + 'end\n', selected)
                self.assertEqual(count, len(fields))
                self.assertNotIn('PRIVATE-COMPOUND', text(out))
                self.assertFalse(hidden.data)

    def test_fortios_full_accepts_documented_names_and_protects_mixed_case_secret(self):
        selected = policy('fortios', fields=[
            (('alertemail setting',), 'FIPS-CC-errors'),
            (('wireless-controller wids-profile',), 'block_ack-flood'),
            (('icap profile',), '204-response'),
            (('system global',), 'adminPassword')],
            private=[(('system global',), 'adminPassword')])
        raw = ('config alertemail setting\n set FIPS-CC-errors enable\nend\n'
               'config wireless-controller wids-profile\n set block_ack-flood enable\nend\n'
               'config icap profile\n set 204-response enable\nend\n'
               'config user tacacs+\nend\n'
               'config system global\n set adminPassword PRIVATE-PASSWORD\nend\n')
        out, hidden, count = render(raw, selected, 1)
        for expected in ('set FIPS-CC-errors enable', 'set block_ack-flood enable',
                         'set 204-response enable', 'config user tacacs+'):
            self.assertIn(expected, text(out))
        self.assertNotIn('PRIVATE-PASSWORD', text(out))
        self.assertEqual((len(hidden), count), (0, 1))
