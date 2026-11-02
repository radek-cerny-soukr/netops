from dataclasses import replace
from unittest import TestCase, mock
import hashlib
import inspect
import json

from netops_helper import engine, configuration as c
from test_config_block import enrolled
import test_config_full_engine as full
from test_config_fortiadc import STATUS as ADC_STATUS, config, profile_lines, READ, live

UNVERIFIED_EXTRA = ('config load-balance profile\n  edit "LB_PROF_LIVE"\n'
                    '    set future-decode-mode DECODE-FIXTURE\n  next\nend\n')
CERT_EXTRA = ('config certificate local\n edit "SSL-PUBLIC"\n'
              ' set certificate "-----BEGIN CERTIFICATE-----\nPUBLIC-CERT-FIXTURE\n-----END CERTIFICATE-----"\n'
              ' set private-key ENC fixture-private-key\n next\nend\n')
ADC_CERT = ('config system certificate intermediate_ca\n  edit "CA_PUBLIC"\n'
            '    set certificate "-----BEGIN CERTIFICATE-----\nPUBLIC-ADC-CERT\n-----END CERTIFICATE-----"\n'
            '  next\nend\n')
FIELDS = ('total_lines', 'matched_lines', 'filter_sha256', 'snapshot_sha256', 'content_sha256')


def wire(raw, status):
    def read(auth, platform, command, **kwargs):
        if command == 'get system status':
            return 0, status
        if command not in ('show', 'show full-configuration'):
            raise AssertionError('unexpected device command')
        data = raw.encode()
        for i in range(0, len(data), 3):
            kwargs['stdout_consumer'](data[i:i + 3])
        return 0, ''
    return read


def expected(text, needle, context):
    lines = text.splitlines(True)
    hits = [i for i, line in enumerate(lines) if needle in line]
    keep = sorted({j for i in hits for j in range(max(0, i - context), min(len(lines), i + context + 1))})
    return ''.join(lines[j] for j in keep), len(lines), len(hits)


class FullConfigurationFilter(TestCase):
    def setUp(self):
        parameters = inspect.signature(engine.config_read).parameters
        for name in ('contains', 'context', 'content_sha256', 'filter_sha256'):
            self.assertIn(name, parameters, 'H5_MISSING_FILTER_ARGUMENT')
        patch = mock.patch.object(engine, 'record')
        self.events = patch.start()
        self.addCleanup(patch.stop)
        with c._LOCK:
            c._SNAPSHOTS.clear()
            c._DIFFS.clear()

    def fortios(self, auth=None, **kwargs):
        return engine.config_read(auth or enrolled(), 'fortios', 'all', True, redaction='full', **kwargs)

    def fortiadc(self, **kwargs):
        auth = replace(enrolled(), ssh_platform='fortiadc', login='netops-read')
        return engine.config_read(auth, 'fortiadc', 'all', True, redaction='full', **kwargs)

    def fields(self, response):
        for name in FIELDS:
            self.assertIn(name, response)
        self.assertRegex(response['filter_sha256'], '^[0-9a-f]{64}$')
        self.assertRegex(response['snapshot_sha256'], '^[0-9a-f]{64}$')

    def collect(self, call, first, limit, **binding):
        self.fields(first)
        parts, page = [first['untrusted_device_output']], first
        while page['next_offset'] is not None:
            page = call(snapshot_id=first['snapshot_id'], offset=page['next_offset'], limit=limit,
                        content_sha256=first['content_sha256'], filter_sha256=first['filter_sha256'], **binding)
            for name in FIELDS:
                self.assertEqual(page[name], first[name])
            parts.append(page['untrusted_device_output'])
        return parts

    def test_fortios_filter_returns_redacted_matches_and_pages_without_ssh(self):
        for defaults in (False, True):
            with self.subTest(include_defaults=defaults), mock.patch.object(
                    engine, 'read_from_device', side_effect=wire(full.FW_CONFIG + CERT_EXTRA, full.STATUS)) as device:
                first = self.fortios(include_defaults=defaults, contains='set', context=0, limit=16)
                self.assertEqual(device.call_count, 2)
                self.assertEqual(device.call_args_list[-1].args[2], 'show full-configuration' if defaults else 'show')
                parts = self.collect(self.fortios, first, 16, include_defaults=defaults, contains='set', context=0)
                reference = self.fortios(snapshot_id=first['snapshot_id'], include_defaults=defaults)
                around = self.fortios(snapshot_id=first['snapshot_id'], include_defaults=defaults,
                                      contains='password', context=1)
                secret = self.fortios(snapshot_id=first['snapshot_id'], include_defaults=defaults,
                                      contains='fixture-password')
                cert = self.fortios(snapshot_id=first['snapshot_id'], include_defaults=defaults,
                                    contains='PUBLIC-CERT-FIXTURE', context=1)
                key = self.fortios(snapshot_id=first['snapshot_id'], include_defaults=defaults,
                                   contains='fixture-private-key')
                self.assertEqual(device.call_count, 2)
                self.assertGreater(len(parts), 1)
                self.assertIsNone(reference['next_offset'])
                source = reference['untrusted_device_output']
                text, total, matched = expected(source, 'set', 0)
                self.assertEqual(''.join(parts), text)
                self.assertEqual((first['total_lines'], first['matched_lines']), (total, matched))
                self.assertGreater(matched, 0)
                self.assertIn('set password ', text)
                self.assertEqual(first['content_sha256'], hashlib.sha256(text.encode()).hexdigest())
                self.assertEqual(first['snapshot_sha256'], reference['snapshot_sha256'])
                self.assertNotEqual(first['content_sha256'], first['snapshot_sha256'])
                self.assertEqual(first['include_defaults'], defaults)
                self.fields(around)
                self.assertEqual(around['untrusted_device_output'], expected(source, 'password', 1)[0])
                self.assertNotEqual(around['filter_sha256'], first['filter_sha256'])
                self.assertEqual((secret['matched_lines'], secret['untrusted_device_output']), (0, ''))
                self.assertIn('set certificate "-----BEGIN CERTIFICATE-----\\nPUBLIC-CERT-FIXTURE\\n', source)
                self.assertEqual((cert['matched_lines'], cert['untrusted_device_output']),
                                 (1, expected(source, 'PUBLIC-CERT-FIXTURE', 1)[0]))
                self.assertIn('set certificate "-----BEGIN CERTIFICATE-----', cert['untrusted_device_output'])
                self.assertIn('set private-key <REDACTED:', source)
                self.assertEqual((key['matched_lines'], key['untrusted_device_output']), (0, ''))
                rendered = json.dumps([first, reference, around, secret, cert, key]) + repr(c._SNAPSHOTS)
                for value in ('fixture-password', 'fixture-private-key'):
                    self.assertNotIn(value, rendered + repr(self.events.call_args_list))

    def test_fortios_continuation_binding_refused_without_ssh(self):
        with mock.patch.object(engine, 'read_from_device', side_effect=wire(full.FW_CONFIG, full.STATUS)):
            first = self.fortios(contains='set', context=0, limit=16)
        self.assertIsNotNone(first['next_offset'])
        binding = dict(snapshot_id=first['snapshot_id'], offset=first['next_offset'], limit=16,
                       contains='set', context=0, content_sha256=first['content_sha256'],
                       filter_sha256=first['filter_sha256'])
        with mock.patch.object(engine, 'read_from_device', side_effect=wire(full.FW_CONFIG, full.STATUS)) as device:
            page = self.fortios(**binding)
            self.assertEqual(page['filter_sha256'], first['filter_sha256'])
            refused = (
                lambda: self.fortios(include_defaults=True, **binding),
                lambda: engine.config_read(enrolled(), 'fortios', 'system interface', True, redaction='full', **binding),
                lambda: engine.config_read(enrolled(), 'fortiadc', 'all', True, redaction='full', **binding),
                lambda: engine.config_read(enrolled(), 'fortios', 'all', True, **binding),
                lambda: self.fortios(**(binding | {'contains': 'password'})),
                lambda: self.fortios(**(binding | {'contains': None})),
                lambda: self.fortios(**(binding | {'context': 1})),
                lambda: self.fortios(**(binding | {'content_sha256': '0' * 64})),
                lambda: self.fortios(**(binding | {'filter_sha256': '0' * 64})),
                lambda: self.fortios(**{k: v for k, v in binding.items() if k != 'filter_sha256'}),
                lambda: self.fortios(**{k: v for k, v in binding.items() if k != 'content_sha256'}),
                lambda: self.fortios(contains='set', content_sha256=first['content_sha256'],
                                     filter_sha256=first['filter_sha256']),
            )
            for number, call in enumerate(refused):
                with self.subTest(case=number), self.assertRaises(ValueError):
                    call()
            self.assertEqual(device.call_count, 0)

    def test_fortiadc_filter_hides_secrets_and_unverified_values(self):
        raw = live(config(profiles=profile_lines(rights=READ)) + UNVERIFIED_EXTRA + ADC_CERT)
        with mock.patch.object(engine, 'read_from_device', side_effect=wire(raw, ADC_STATUS)) as device:
            first = self.fortiadc(contains='password', context=1, limit=24)
            self.assertEqual(device.call_count, 2)
            parts = self.collect(self.fortiadc, first, 24, contains='password', context=1)
            reference = self.fortiadc(snapshot_id=first['snapshot_id'])
            marked = self.fortiadc(snapshot_id=first['snapshot_id'], contains='<UNVERIFIED', context=0)
            field = self.fortiadc(snapshot_id=first['snapshot_id'], contains='future-decode-mode', context=0)
            cert = self.fortiadc(snapshot_id=first['snapshot_id'], contains='PUBLIC-ADC-CERT', context=1)
            hidden = [self.fortiadc(snapshot_id=first['snapshot_id'], contains=value)
                      for value in ('SECRET-FIXTURE', 'ADMIN-FIXTURE', 'DECODE-FIXTURE', '--More--')]
            self.assertEqual(device.call_count, 2)
        self.assertGreater(len(parts), 1)
        self.assertIsNone(reference['next_offset'])
        source = reference['untrusted_device_output']
        text, total, matched = expected(source, 'password', 1)
        self.assertEqual(''.join(parts), text)
        self.assertEqual((first['total_lines'], first['matched_lines']), (total, matched))
        self.assertGreaterEqual(matched, 2)
        self.assertEqual(first['platform'], 'fortiadc')
        self.assertEqual(first['snapshot_sha256'], reference['snapshot_sha256'])
        self.assertEqual(first['content_sha256'], hashlib.sha256(text.encode()).hexdigest())
        for response in (marked, field):
            self.fields(response)
            self.assertEqual(response['matched_lines'], 1)
            self.assertEqual(response['untrusted_device_output'],
                             '    set future-decode-mode <UNVERIFIED:unclassified-field>\n')
        self.assertNotEqual(marked['filter_sha256'], field['filter_sha256'])
        self.assertIn('-----BEGIN CERTIFICATE-----', source)
        self.assertEqual((cert['matched_lines'], cert['untrusted_device_output']),
                         (1, expected(source, 'PUBLIC-ADC-CERT', 1)[0]))
        self.assertIn('-----BEGIN CERTIFICATE-----', cert['untrusted_device_output'])
        for response in hidden:
            self.assertEqual((response['matched_lines'], response['untrusted_device_output']), (0, ''))
        rendered = json.dumps([first, reference, marked, field] + hidden) + repr(c._SNAPSHOTS)
        for value in ('SECRET-FIXTURE', 'ADMIN-FIXTURE', 'DECODE-FIXTURE', '--More--', '\r'):
            self.assertNotIn(value, rendered)
        for value in ('SECRET-FIXTURE', 'DECODE-FIXTURE', 'future-decode-mode'):
            self.assertNotIn(value, repr(self.events.call_args_list))

    def test_fortiadc_continuation_binding_refused_without_ssh(self):
        auth = replace(enrolled(), ssh_platform='fortiadc', login='netops-read')
        raw = live(config(profiles=profile_lines(rights=READ)))
        with mock.patch.object(engine, 'read_from_device', side_effect=wire(raw, ADC_STATUS)):
            first = self.fortiadc(contains='set', context=0, limit=24)
        self.assertIsNotNone(first['next_offset'])
        binding = dict(snapshot_id=first['snapshot_id'], offset=first['next_offset'], limit=24,
                       contains='set', context=0, content_sha256=first['content_sha256'],
                       filter_sha256=first['filter_sha256'])
        with mock.patch.object(engine, 'read_from_device', side_effect=wire(raw, ADC_STATUS)) as device:
            self.assertEqual(self.fortiadc(**binding)['filter_sha256'], first['filter_sha256'])
            refused = (
                lambda: self.fortiadc(include_defaults=True, **binding),
                lambda: engine.config_read(auth, 'fortiadc', 'system interface', True, redaction='full', **binding),
                lambda: engine.config_read(auth, 'fortios', 'all', True, redaction='full', **binding),
                lambda: self.fortiadc(**(binding | {'contains': 'password'})),
                lambda: self.fortiadc(**(binding | {'filter_sha256': '0' * 64})),
                lambda: self.fortiadc(**(binding | {'content_sha256': '0' * 64})),
            )
            for number, call in enumerate(refused):
                with self.subTest(case=number), self.assertRaises(ValueError):
                    call()
            self.assertEqual(device.call_count, 0)


if __name__ == '__main__':
    import unittest
    unittest.main()
