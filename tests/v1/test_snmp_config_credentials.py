from dataclasses import replace
import json
from unittest import TestCase, mock
from netops_helper import engine, configuration as c, config_fortios, config_fortiadc
from netops_helper.sanitize import redact_response
from test_config_block import enrolled
from test_config_full_engine import STATUS
from test_config_fortiadc import STATUS as ADC_STATUS

RAW = ('config system snmp community\n edit 1\n set name "CANARY-community two"\n next\nend\n'
       'config system snmp user\n edit observer\n set auth-pwd "CANARY-auth two"\n'
       ' set priv-pwd ENC CANARY-priv\n next\nend\n')

class SNMPCredentials(TestCase):
    def setUp(self):
        c._SNAPSHOTS.clear(); c._DIFFS.clear()
        patch = mock.patch.object(engine, 'record'); patch.start(); self.addCleanup(patch.stop)

    def test_all_schema_versions_classify_community_and_usm_credentials(self):
        for policy in (config_fortios.policy_for(('FortiGate-60F','7.6.8','3744')),
                       config_fortios.policy_for(('FortiGate-VM64','8.0.2','0251')),
                       config_fortiadc.policy_for(config_fortiadc.SUPPORTED)):
            for field, path in (('name', ('system snmp community',)),
                                ('auth-pwd', ('system snmp user',)), ('priv-pwd', ('system snmp user',))):
                self.assertIn((path, field), policy.secret_fields)
                self.assertNotIn((path, field), policy.public_fields)

    def test_real_engine_path_full_and_minimal_and_response_chain(self):
        for platform, modes, status in (('fortios', ('minimal','full'), STATUS),
                                        ('fortiadc', ('full',), ADC_STATUS)):
            for mode in modes:
                with self.subTest(platform=platform, mode=mode):
                    auth = replace(enrolled(), ssh_platform='fortiadc' if platform == 'fortiadc' else 'fortinet')
                    def wire(auth, vendor, command, **kwargs):
                        if command == 'get system status': return 0, status
                        for char in RAW.encode(): kwargs['stdout_consumer'](bytes((char,)))
                        return 0, ''
                    with mock.patch.object(engine, 'read_from_device', side_effect=wire):
                        result = engine.config_read(auth, platform, 'all', True, redaction=mode)
                    output = result['untrusted_device_output']
                    self.assertNotIn('CANARY-', json.dumps(result))
                    self.assertIn('set name <REDACTED:credential#1>', output)
                    self.assertEqual(output, redact_response(output))

    def test_fortiadc_health_check_community_is_also_a_credential(self):
        raw = 'config system health-check\n edit probe\n set community CANARY-health\nnext\nend\n'
        policy = config_fortiadc.policy_for(config_fortiadc.SUPPORTED)
        self.assertIn((('system health-check',), 'community'), policy.secret_fields)
        content, _, _ = c.redact(raw, (), 'all', policy=policy)
        output = redact_response(content.page(0,content.total)[0])
        self.assertNotIn('CANARY-', output)
        self.assertIn('set community <REDACTED:credential#1>', output)

    def test_response_redaction_and_exos_equivalents(self):
        for raw in (RAW, RAW.replace('two"', 'two\nthree"'),
                    'configure snmp add community readonly "CANARY-exos two"\n',
                    'configure snmp add community readwrite CANARY-exos\n',
                    'configure snmpv3 add community CANARY-encoded name "CANARY-exos two" user initial\n'):
            output = redact_response(raw)
            self.assertNotIn('CANARY-', output)
            self.assertEqual(output, redact_response(output))
