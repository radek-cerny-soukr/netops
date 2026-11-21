"""FortiOS and FortiADC configuration reads on a version outside the tested ones (G00-2, decision of 2026-11-17).

Since 1.0.12 an untested version or build is not refused: the read returns the data with firmware_support
"untested", one warnings[] item and the field policy of the nearest tested version (policy_firmware). The
redaction stays fail-closed: a field outside that policy is hidden. Only an unreadable identity or another product
is still refused before any configuration command.
"""
from dataclasses import replace
import json
from unittest import TestCase, mock

from netops_helper import configuration as c, config_fortios, config_fortiadc, engine
from test_config_block import enrolled
from test_config_full_engine import STATUS as FG_STATUS, FW_CONFIG
from test_config_fortiadc import STATUS as ADC_STATUS, config, live, profile_lines, READ


class UntestedFirmwareConfiguration(TestCase):
    def setUp(self):
        c._SNAPSHOTS.clear()
        c._DIFFS.clear()
        self.addCleanup(c._SNAPSHOTS.clear)
        self.addCleanup(c._DIFFS.clear)
        patch = mock.patch.object(engine, 'record')
        patch.start()
        self.addCleanup(patch.stop)

    def auth(self, platform):
        return replace(enrolled(), ssh_platform='fortiadc', login='netops-read') if platform == 'fortiadc' else enrolled()

    def raw(self, platform):
        return live(config(profiles=profile_lines(rights=READ))) if platform == 'fortiadc' else FW_CONFIG

    def read(self, platform, status, raw=None):
        raw = self.raw(platform) if raw is None else raw

        def wire(auth, wire_platform, command, **kwargs):
            if command == 'get system status':
                return 0, status
            self.assertEqual(command, 'show')
            kwargs['stdout_consumer'](raw.encode())
            return 0, ''
        with mock.patch.object(engine, 'read_from_device', side_effect=wire) as read:
            result = engine.config_read(self.auth(platform), platform, 'all', True, redaction='full')
        self.assertEqual([call.args[2] for call in read.call_args_list], ['get system status', 'show'])
        return result

    def rejected(self, platform, status):
        auth = self.auth(platform)
        status += '\nN1B-RAW-STATUS-MARKER ' + auth.secret + '\n'

        def wire(auth, wire_platform, command, **kwargs):
            self.assertEqual(command, 'get system status')
            return 0, status
        with mock.patch.object(engine, 'read_from_device', side_effect=wire) as read:
            with self.assertRaises(ValueError) as caught:
                engine.config_read(auth, platform, 'all', True, redaction='full')
        self.assertEqual([call.args[2] for call in read.call_args_list], ['get system status'])
        message = str(caught.exception)
        for private in ('N1B-RAW-STATUS-MARKER', auth.secret, 'FortiGate-', 'FortiADC-', 'Serial-Number', 'Hostname'):
            self.assertNotIn(private, message)
        self.assertFalse(c._SNAPSHOTS)
        return message

    def assert_untested(self, result, platform, version, build, policy):
        name = 'FortiADC' if platform == 'fortiadc' else 'FortiOS'
        self.assertTrue(result['ok'])
        self.assertEqual((result['firmware']['version'], result['firmware']['build']), (version, build))
        support = result['firmware_support']
        self.assertEqual((support['status'], support['platform'], support['device_version']),
                         ('untested', name, version + ' build' + build))
        self.assertTrue(support['message'].startswith(name + ' ' + version + ' build' + build))
        self.assertIn('It may or may not work as designed and tested; check the result.', support['message'])
        self.assertEqual(result['warnings'], [{'code': 'firmware_untested', 'message': support['message']}])
        self.assertEqual(result['policy_firmware'], policy)
        self.assertIn(result['snapshot_id'], c._SNAPSHOTS)

    def test_untested_fortios_version_or_build_returns_data_with_the_nearest_policy(self):
        for version, build, policy in (('7.6.8', '9999', '7.6.8'), ('7.6.9', '3800', '7.6.8'),
                                       ('8.0.3', '0251', '8.0.2'), ('8.0.0', '0167', '8.0.2'),
                                       ('8.2.1', '0400', '8.0.2'), ('7.8.0', '3900', '7.6.8'),
                                       ('7.4.9', '2850', '7.6.8')):
            with self.subTest(version=version, build=build):
                c._SNAPSHOTS.clear()
                status = FG_STATUS.replace('7.6.8', version).replace('3744', build)
                result = self.read('fortios', status)
                self.assert_untested(result, 'fortios', version, build, policy)
                self.assertEqual(result['firmware_support']['tested_versions'], ['7.6.8 build3744', '8.0.2 build0251'])
                self.assertEqual(result['redaction_profile'], config_fortios._policy(policy).identifier)
                self.assertIn('edit port1', result['untrusted_device_output'])
                self.assertNotIn('fixture-password', json.dumps(result) + repr(c._SNAPSHOTS))

    def test_untested_fortiadc_version_or_build_returns_data_with_the_tested_policy(self):
        for version, build in (('7.6.7', '9999'), ('7.6.8', '0676'), ('7.4.2', '0500')):
            with self.subTest(version=version, build=build):
                c._SNAPSHOTS.clear()
                status = ADC_STATUS.replace('7.6.7', version).replace('0676', build)
                result = self.read('fortiadc', status)
                self.assert_untested(result, 'fortiadc', version, build, '7.6.7')
                self.assertEqual(result['firmware_support']['tested_versions'], ['FortiADC-KVM 7.6.7 build0676'])
                self.assertEqual(result['redaction_profile'], config_fortiadc._policy().identifier)
                self.assertIn('config_read for FortiADC was tested on', result['firmware_support']['message'])

    def test_untested_fortiadc_model_is_reported_as_untested(self):
        result = self.read('fortiadc', ADC_STATUS.replace('FortiADC-KVM', 'FortiADC-VM'))
        self.assert_untested(result, 'fortiadc', '7.6.7', '0676', '7.6.7')
        self.assertEqual(result['firmware_support']['model'], 'FortiADC-VM')

    def test_redaction_stays_fail_closed_on_an_untested_version(self):
        raw = FW_CONFIG.replace(' next\nend\n', ' set fixture-new-field fixture-private-new-value\n next\nend\n', 1)
        for status in (FG_STATUS, FG_STATUS.replace('7.6.8', '7.6.9').replace('3744', '3800')):
            with self.subTest(status=status.splitlines()[0]):
                c._SNAPSHOTS.clear()
                result = self.read('fortios', status, raw)
                page = result['untrusted_device_output']
                self.assertIn('<UNVERIFIED:', page)
                for private in ('fixture-private-new-value', 'fixture-password'):
                    self.assertNotIn(private, json.dumps(result) + repr(c._SNAPSHOTS))
                self.assertGreaterEqual(result['unverified_count'], 1)
                self.assertFalse(result['configuration_complete'])

    def test_a_cached_page_of_an_untested_snapshot_repeats_the_warning(self):
        first = self.read('fortios', FG_STATUS.replace('3744', '9999'))
        with mock.patch.object(engine, 'read_from_device', side_effect=AssertionError('cache must not read SSH')):
            page = engine.config_read(enrolled(), 'fortios', 'all', True, snapshot_id=first['snapshot_id'],
                                      redaction='full')
        for key in ('firmware_support', 'warnings', 'policy_firmware', 'redaction_profile'):
            self.assertEqual(page[key], first[key])

    def test_tested_firmware_captures_without_a_warning(self):
        for platform, status, version, build in (('fortios', FG_STATUS, '7.6.8', '3744'),
                                                 ('fortios', FG_STATUS.replace('7.6.8', '8.0.2').replace('3744', '0251'), '8.0.2', '0251'),
                                                 ('fortiadc', ADC_STATUS, '7.6.7', '0676')):
            with self.subTest(platform=platform, version=version):
                result = self.read(platform, status)
                self.assertTrue(result['ok'])
                self.assertEqual((result['firmware']['version'], result['firmware']['build']), (version, build))
                self.assertEqual(result['firmware_support']['status'], 'tested')
                self.assertIsNone(result['firmware_support']['message'])
                self.assertNotIn('warnings', result)
                self.assertNotIn('policy_firmware', result)

    def test_malformed_and_ambiguous_identity_never_echo_numbers_or_status(self):
        for platform, status, version, build in (('fortios', FG_STATUS, '7.6.8', '3744'),
                                                 ('fortiadc', ADC_STATUS, '7.6.7', '0676')):
            for invalid in (status.replace(version, '7.invalid.8'),
                            status.replace('build' + build, 'build123'),
                            status + status,
                            status + ' version: FortiGate-PRIVATE v9.8.7,build9876\n',
                            status.replace(version, '７.６.８'),
                            status.replace(version, '9' * 40 + '.1.1')):
                with self.subTest(platform=platform, invalid=invalid[:50]):
                    self.assertEqual(self.rejected(platform, invalid),
                                     'configuration identity-unverifiable; output withheld')

    def test_another_product_is_still_refused_before_any_configuration_command(self):
        for platform, status in (('fortios', ADC_STATUS), ('fortiadc', FG_STATUS)):
            with self.subTest(platform=platform):
                self.assertEqual(self.rejected(platform, status), 'configuration identity-unverifiable; output withheld')

    def test_adapters_compare_against_the_tested_lists(self):
        fos = config_fortios.verify_identity(FG_STATUS.replace('3744', '9999'))[0]
        self.assertEqual(config_fortios.firmware_support(fos)['status'], 'untested')
        self.assertEqual(config_fortios.policy_firmware(fos), '7.6.8')
        adc = config_fortiadc.verify_identity(ADC_STATUS.replace('0676', '9999'))[0]
        self.assertEqual(config_fortiadc.firmware_support(adc)['status'], 'untested')
        self.assertEqual(config_fortiadc.policy_firmware(adc), '7.6.7')
        for adapter, status in ((config_fortios, 'Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n'),
                                (config_fortiadc, FG_STATUS)):
            with self.assertRaises(c.UnsupportedConfigurationFirmware):
                adapter.verify_identity(status)

    def test_full_capture_enrollment_rejects_before_identity_read(self):
        with mock.patch.object(engine, 'read_from_device', side_effect=AssertionError('no SSH')) as read:
            with self.assertRaises(ValueError):
                engine.config_read(replace(enrolled(), read_inventory={}), 'fortios', 'all', True, redaction='full')
        read.assert_not_called()
