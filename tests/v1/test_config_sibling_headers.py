import json
from dataclasses import replace
from unittest import TestCase, mock

from netops_helper import configuration as c, config_fortios, config_fortiadc, engine
from test_config_block import enrolled

FG_PATH = ('system automation-action', 'http-headers')
ADC_PATH = ('security waf api-gateway-rule', 'attach-http-header')
FIRMWARES = (
    ('fortios', ('FortiGate-VM64', '7.6.8', '3744'), FG_PATH, 'key', 'value'),
    ('fortios', ('FortiGate-VM64', '8.0.2', '0251'), FG_PATH, 'key', 'value'),
    ('fortiadc', config_fortiadc.SUPPORTED, ADC_PATH, 'http-header-name', 'http-header-value'),
)


def selected(platform, firmware):
    return (config_fortios if platform == 'fortios' else config_fortiadc).policy_for(firmware)


def config(path, entries):
    return ('config ' + path[0] + '\nedit diagnostic-action\nconfig ' + path[1] + '\n' +
            ''.join('edit ' + str(n) + '\n' + body + 'next\n' for n, body in enumerate(entries, 1)) +
            'end\nnext\nend\n')


def pair(name_field, value_field, name, value, reverse=False):
    rows = [('set ' + name_field + ' ' + json.dumps(name) + '\n'),
            ('set ' + value_field + ' ' + json.dumps(value) + '\n')]
    return ''.join(reversed(rows) if reverse else rows)


def render(raw, policy, chunk=7):
    stream = c.StreamRedactor((), 'all', policy=policy)
    data = raw.encode()
    for start in range(0, len(data), chunk):
        stream.feed(data[start:start + chunk])
    content, hidden, count = stream.finish()
    return content.page(0, content.total)[0], hidden, count, stream.summary()


class SiblingHeaders(TestCase):
    def test_value_before_name_keeps_public_diagnostics_and_hides_credentials(self):
        for platform, firmware, path, name_field, value_field in FIRMWARES:
            for reverse in (True, False):
                for chunk in (1, 7, 65536):
                    with self.subTest(firmware=firmware, reverse=reverse, chunk=chunk):
                        entries = [
                            pair(name_field, value_field, 'X-Trace-Key', 'public route 42', reverse),
                            pair(name_field, value_field, 'Authorization', 'Bearer PAIR-AUTH-PRIVATE', reverse),
                            pair(name_field, value_field, 'Proxy-Authorization', 'Basic PAIR-PROXY-PRIVATE', reverse),
                            pair(name_field, value_field, 'X-API-Key', 'scheme PAIR-API-PRIVATE', reverse),
                            pair(name_field, value_field, 'auth-token-cookie-session', 'public diagnostic', reverse),
                        ]
                        output, hidden, count, summary = render(config(path, entries), selected(platform, firmware), chunk)
                        self.assertIn('public route 42', output)
                        self.assertIn('public diagnostic', output)
                        positions = (output.index('set ' + name_field + ' X-Trace-Key'),
                                     output.index('set ' + value_field + ' "public route 42"'))
                        self.assertEqual(positions[1] < positions[0], reverse)
                        for name in ('X-Trace-Key', 'Authorization', 'Proxy-Authorization', 'X-API-Key'):
                            self.assertIn(name, output)
                        self.assertNotIn('PAIR-', output)
                        self.assertNotIn('scheme ', output)
                        self.assertIn('Bearer <REDACTED:credential#', output)
                        self.assertIn('Basic <REDACTED:credential#', output)
                        self.assertEqual((count, len(hidden), summary['credential_redactions'], summary['unverified_count']),
                                         (3, 0, 3, 0))

    def test_state_is_reset_for_next_end_and_another_config(self):
        for platform, firmware, path, name_field, value_field in FIRMWARES:
            with self.subTest(firmware=firmware):
                first = pair(name_field, value_field, 'X-Trace-Key', 'first public')
                missing = 'set ' + value_field + ' "PAIR-MISSING-PRIVATE"\n'
                credential = pair(name_field, value_field, 'Authorization', 'Bearer PAIR-RESET-PRIVATE', True)
                raw = config(path, [first, missing, credential]) + config(path, [missing])
                output, hidden, count, summary = render(raw, selected(platform, firmware), 1)
                self.assertIn('first public', output)
                self.assertNotIn('PAIR-', output)
                self.assertEqual(summary['unsupported_format_count'], 2)
                self.assertEqual(summary['credential_redactions'], 1)
                self.assertEqual((len(hidden), count), (0, 3))

    def test_nested_context_boundary_cannot_reuse_a_parent_header_name(self):
        for platform, firmware, path, name_field, value_field in FIRMWARES:
            body = ('set ' + name_field + ' X-Trace-Key\nconfig unsupported-nested-context\nend\n' +
                    'set ' + value_field + ' "PAIR-NESTED-PRIVATE"\n')
            output, hidden, count, summary = render(config(path, [body]), selected(platform, firmware), 1)
            self.assertNotIn('PAIR-', output)
            self.assertEqual((summary['credential_redactions'], summary['unsupported_format_count']), (0, 1))

    def test_duplicate_malformed_and_unset_names_or_values_are_unverified(self):
        for platform, firmware, path, name_field, value_field in FIRMWARES:
            for body in (
                'set {v} "PAIR-AMBIGUOUS-PRIVATE"\n',
                'set {n} "Authorization"\nset {v} "PAIR-AMBIGUOUS-PRIVATE"\nset {n} "X-Trace-Key"\n',
                'set {n} "bad name"\nset {v} "PAIR-AMBIGUOUS-PRIVATE"\n',
                'set {n} "Authorization" "extra"\nset {v} "PAIR-AMBIGUOUS-PRIVATE"\n',
                'set {n} "X-Trace-Key"\nset {v} "PAIR-AMBIGUOUS-PRIVATE"\nunset {n}\n',
                'set {n} "X-Trace-Key"\nset {v} "PAIR-AMBIGUOUS-PRIVATE"\nunset {v}\n',
                'set {n} "X-Trace-Key"\nset {v} "PAIR-AMBIGUOUS-PRIVATE"\nset {v} "PAIR-DUPLICATE-PRIVATE"\n',
                'set {n} "Authorization"\nset {v} "PAIR-AMBIGUOUS-PRIVATE" "extra"\n',
            ):
                with self.subTest(firmware=firmware, body=body):
                    output, hidden, count, summary = render(config(path, [body.format(n=name_field, v=value_field)]),
                                                            selected(platform, firmware), 1)
                    self.assertNotIn('PAIR-', output)
                    self.assertIn('UNVERIFIED:unsupported-format', output)
                    self.assertEqual(summary['credential_redactions'], 0)
                    self.assertGreaterEqual(summary['unsupported_format_count'], 1)
                    self.assertFalse(hidden.data)

    def test_empty_known_value_and_secret_priority(self):
        for platform, firmware, path, name_field, value_field in FIRMWARES:
            policy = selected(platform, firmware)
            empty = config(path, ['set ' + value_field + ' ""\n',
                                  pair(name_field, value_field, 'Authorization', '')])
            output, hidden, count, summary = render(empty, policy, 1)
            self.assertEqual(output.count('set ' + value_field + ' ""'), 2)
            self.assertEqual((count, summary['unverified_count'], summary['credential_redactions']), (0, 0, 0))
            private = replace(policy, secret_fields=policy.secret_fields | frozenset(((path, value_field),)))
            output, hidden, count, summary = render(empty, private, 1)
            self.assertEqual(summary['credential_redactions'], 2)
            self.assertEqual(summary['unverified_count'], 0)
            self.assertNotIn('set ' + value_field + ' ""', output)
            private_name = replace(policy, secret_fields=policy.secret_fields | frozenset(((path, name_field),)))
            output, hidden, count, summary = render(
                config(path, [pair(name_field, value_field, 'X-Trace-Key', 'PAIR-UNKNOWN-NAME-PRIVATE')]), private_name, 1)
            self.assertNotIn('PAIR-', output)
            self.assertNotIn('X-Trace-Key', output)
            self.assertEqual((summary['credential_redactions'], summary['unsupported_format_count']), (1, 1))

    def test_exact_declarations_and_unclassified_context(self):
        for platform, firmware, path, name_field, value_field in FIRMWARES:
            policy = selected(platform, firmware)
            self.assertIn((path, name_field, value_field), policy.sibling_header_fields)
            self.assertNotEqual(policy.identifier, replace(policy, sibling_header_fields=frozenset()).identifier)
            unknown = (path[0], 'unverified-headers')
            output, hidden, count, summary = render(
                config(unknown, [pair(name_field, value_field, 'Authorization', 'PAIR-UNKNOWN-CONTEXT-PRIVATE')]), policy, 1)
            self.assertNotIn('PAIR-', output)
            self.assertEqual(summary['credential_redactions'], 0)
            self.assertGreater(summary['unverified_count'], 0)
        for prefix in (('global',), ('vdom',)):
            policy = config_fortios.policy_for(FIRMWARES[0][1])
            self.assertIn((prefix + FG_PATH, 'key', 'value'), policy.sibling_header_fields)

    def test_bounded_pending_headers_fail_closed(self):
        platform, firmware, path, name_field, value_field = FIRMWARES[0]
        body = pair(name_field, value_field, 'X-Trace-Key', 'public')
        body += ''.join('set ' + name_field + ' ' + json.dumps('x' * 60000) + '\n' for unused in range(25))
        stream = c.StreamRedactor((), 'all', policy=selected(platform, firmware))
        with self.assertRaises(c.ConfigurationRedactionError):
            stream.feed(config(path, [body]).encode())
        self.assertTrue(stream.closed)

    def test_unsupported_pair_makes_engine_result_and_cache_incomplete(self):
        c._SNAPSHOTS.clear()
        c._DIFFS.clear()
        self.addCleanup(c._SNAPSHOTS.clear)
        self.addCleanup(c._DIFFS.clear)
        firmware = FIRMWARES[0][1]
        raw = config(FG_PATH, ['set value "PAIR-ENGINE-PRIVATE"\n'])
        policy = selected('fortios', firmware)
        def wire(auth, platform, command, **kwargs):
            if command == 'get system status':
                return 0, 'Version: FortiGate-VM64 v7.6.8,build3744,260101 (GA)\nVirtual domain configuration: disable\n'
            kwargs['stdout_consumer'](raw.encode())
            return 0, ''
        with mock.patch.object(engine, 'record'), mock.patch.object(config_fortios, 'policy_for', return_value=policy), mock.patch.object(engine, 'read_from_device', side_effect=wire):
            result = engine.config_read(enrolled(), 'fortios', 'all', True, redaction='full')
        self.assertFalse(result['configuration_complete'])
        self.assertIn('formats-not-verified', result['visibility_limitations'])
        self.assertEqual(result['unsupported_format_count'], 1)
        with mock.patch.object(engine, 'record'), mock.patch.object(config_fortios, 'policy_for', return_value=policy), mock.patch.object(engine, 'read_from_device', side_effect=AssertionError('no SSH')):
            cached = engine.config_read(enrolled(), 'fortios', 'all', True, redaction='full', snapshot_id=result['snapshot_id'])
        self.assertFalse(cached['configuration_complete'])
        self.assertNotIn('PAIR-', json.dumps(cached))
