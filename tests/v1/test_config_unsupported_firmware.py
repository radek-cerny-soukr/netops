from dataclasses import replace
from unittest import TestCase, mock

from netops_helper import configuration as c, config_fortios, config_fortiadc, engine
from test_config_block import enrolled
from test_config_full_engine import STATUS as FG_STATUS, FW_CONFIG
from test_config_fortiadc import STATUS as ADC_STATUS, config, live, profile_lines, READ


class UnsupportedFirmwareDiagnostics(TestCase):
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

    def test_actual_detected_fortios_version_and_build_are_distinct_from_supported(self):
        for version, build in (('7.6.8', '9999'), ('8.0.3', '0251')):
            with self.subTest(version=version, build=build):
                status = FG_STATUS.replace('7.6.8', version).replace('3744', build)
                self.assertEqual(self.rejected('fortios', status),
                    'configuration firmware-not-supported for fortios; detected ' + version + ' build ' + build +
                    '; supported 7.6.8 build 3744, 8.0.2 build 0251; output withheld')

    def test_actual_detected_fortiadc_version_and_build_are_distinct_from_supported(self):
        for version, build in (('7.6.7', '9999'), ('7.6.8', '0676')):
            with self.subTest(version=version, build=build):
                status = ADC_STATUS.replace('7.6.7', version).replace('0676', build)
                self.assertEqual(self.rejected('fortiadc', status),
                    'configuration firmware-not-supported for fortiadc; detected ' + version + ' build ' + build +
                    '; supported 7.6.7 build 0676; output withheld')

    def test_malformed_and_ambiguous_identity_never_echo_numbers_or_status(self):
        for platform, status, version, build in (('fortios', FG_STATUS, '7.6.8', '3744'),
                                                 ('fortiadc', ADC_STATUS, '7.6.7', '0676')):
            for invalid in (status.replace(version, '7.invalid.8'),
                            status.replace('build' + build, 'build123'),
                            status + status,
                            status + ' version: FortiGate-PRIVATE v9.8.7,build9876\n',
                            status.replace(version, '\uff17.\uff16.\uff18'),
                            status.replace(version, '9' * 40 + '.1.1')):
                with self.subTest(platform=platform, invalid=invalid[:50]):
                    self.assertEqual(self.rejected(platform, invalid),
                                     'configuration identity-unverifiable; output withheld')

    def test_supported_firmware_still_captures_and_keeps_actual_identity(self):
        for platform, status, version, build in (('fortios', FG_STATUS, '7.6.8', '3744'),
                                                 ('fortios', FG_STATUS.replace('7.6.8', '8.0.2').replace('3744', '0251'), '8.0.2', '0251'),
                                                 ('fortiadc', ADC_STATUS, '7.6.7', '0676')):
            with self.subTest(platform=platform, version=version):
                raw = live(config(profiles=profile_lines(rights=READ))) if platform == 'fortiadc' else FW_CONFIG
                def wire(auth, wire_platform, command, **kwargs):
                    if command == 'get system status':
                        return 0, status
                    self.assertEqual(command, 'show')
                    kwargs['stdout_consumer'](raw.encode())
                    return 0, ''
                with mock.patch.object(engine, 'read_from_device', side_effect=wire) as read:
                    result = engine.config_read(self.auth(platform), platform, 'all', True, redaction='full')
                self.assertTrue(result['ok'])
                self.assertEqual([call.args[2] for call in read.call_args_list], ['get system status', 'show'])
                self.assertEqual((result['firmware']['version'], result['firmware']['build']), (version, build))

    def test_existing_low_level_error_text_is_unchanged(self):
        for adapter, status, message in (
            (config_fortios, FG_STATUS.replace('3744', '9999'), 'config_platform_not_supported: unverified FortiOS firmware'),
            (config_fortiadc, ADC_STATUS.replace('0676', '9999'), 'config_platform_not_supported'),
        ):
            with self.assertRaises(c.UnsupportedConfigurationFirmware) as caught:
                adapter.verify_identity(status)
            self.assertEqual(str(caught.exception), message)

    def test_full_capture_enrollment_rejects_before_identity_read(self):
        with mock.patch.object(engine, 'read_from_device', side_effect=AssertionError('no SSH')) as read:
            with self.assertRaises(ValueError):
                engine.config_read(replace(enrolled(), read_inventory={}), 'fortios', 'all', True, redaction='full')
        read.assert_not_called()
