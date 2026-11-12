import json
import re
from dataclasses import replace
from unittest import TestCase, mock
from netops_helper import configuration as c, engine
from test_config_block import enrolled
from netops_helper import config_fortiadc as f


CREDENTIAL = r'<REDACTED:credential#[0-9]+>'


PROMPT = 'FortiADC-KVM $ '
PAGER = '--More-- \r' + ' ' * 79 + '\r'
RIGHTS = (('system', 'read'), ('networking', 'none'), ('load-balance', 'read'), ('log', 'read'),
          ('link-load-balance', 'read'), ('global-load-balance', 'read'), ('security', 'read'),
          ('share-resource', 'none'), ('user', 'none'))
READ = tuple((name, 'read') for name, level in RIGHTS)
STATUS = (PROMPT + 'Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n'
          'Version:       n/a\n'
          'Serial-Number: FADV-SERIAL-FIXTURE\n'
          'Hostname: ADC-LAB\n' + PROMPT.rstrip() + '\n')


def profile_lines(name='netops-read', rights=RIGHTS, extra=()):
    body = ''.join('    set %s %s\n' % right for right in rights) + ''.join(extra)
    return '  edit "%s"\n%s  next\n' % (name, body)


def admin_lines(name='netops-read', profile='netops-read', extra=('    set accprofile-override disable\n',)):
    return ('  edit "%s"\n    set access-profile "%s"\n%s'
            '    set password ENC SECRET-FIXTURE\n  next\n' % (name, profile, ''.join(extra)))


def config(profiles=None, admins=None, vdom='config system vdom\n  edit root\n  next\nend\n'):
    profiles = profile_lines() if profiles is None else profiles
    admins = admin_lines() if admins is None else admins
    return ('config system global\n    set hostname ADC-LAB\nend\n'
            'config system accprofile\n' + profiles +
            '  edit "other"\n    set system read-write\n  next\nend\n'
            'config system admin\n  edit "admin"\n    set access-profile super_admin_prof\n'
            '    set password ENC ADMIN-FIXTURE\n  next\n' + admins + 'end\n' + vdom)


def live(text):
    lines = text.split('\n')
    paged = '\n'.join((PAGER + line) if index and index % 5 == 0 else line for index, line in enumerate(lines))
    return PROMPT + paged + PROMPT.rstrip() + '\n'


def capture(raw, chunk=7, account='netops-read', maximum=None, forbidden=()):
    stream = c.StreamRedactor(forbidden, 'all', policy=f.policy_for(f.SUPPORTED))
    normalizer = f.Normalizer(stream.feed, stream.maximum if maximum is None else maximum)
    data = raw.encode()
    for start in range(0, len(data), chunk):
        normalizer.feed(data[start:start + chunk])
    normalizer.finish()
    content, hidden, count = stream.finish()
    return content, f.assess(content, account)


def text(content):
    return content.page(0, content.total)[0]


class FortiADCConfiguration(TestCase):
    def test_read_rights_and_one_vdom_are_complete(self):
        for chunk in (1, 7, 4096):
            with self.subTest(chunk=chunk):
                result = capture(live(config(profiles=profile_lines(rights=READ))), chunk)[1]
                self.assertEqual(result, {'config_scope': 'all', 'configuration_complete': True,
                                          'visibility_limitations': []})

    def _engine_vdom_override(self, extra, other=(), defaults=False):
        auth = replace(enrolled(), ssh_platform='fortiadc', login='netops-read')
        admins = admin_lines(extra=('    set accprofile-override disable\n',) + extra)
        if other:
            admins += admin_lines(name='another-account', extra=other)
        raw = live(config(profiles=profile_lines(rights=READ), admins=admins))
        expected = capture(raw, 1)[1]
        command = 'show full-configuration' if defaults else 'show'
        def wire(auth, platform, requested, **kwargs):
            if requested == 'get system status':
                return 0, STATUS
            self.assertEqual(requested, command)
            kwargs['stdout_consumer'](raw.encode())
            return 0, ''
        c._SNAPSHOTS.clear()
        c._DIFFS.clear()
        try:
            with mock.patch.object(engine, 'record'):
                with mock.patch.object(engine, 'read_from_device', side_effect=wire) as read:
                    result = engine.config_read(auth, 'fortiadc', 'all', True, redaction='full', include_defaults=defaults)
                self.assertEqual([call.args[2] for call in read.call_args_list], ['get system status', command])
                with mock.patch.object(engine, 'read_from_device', side_effect=AssertionError('cached page must not SSH')):
                    cached = engine.config_read(auth, 'fortiadc', 'all', True, redaction='full',
                                                include_defaults=defaults, snapshot_id=result['snapshot_id'])
            for key in ('config_scope', 'configuration_complete', 'visibility_limitations'):
                self.assertEqual(result[key], expected[key])
                self.assertEqual(cached[key], result[key])
            self.assertTrue(result['capture_complete'])
            self.assertNotIn('access-profile-unverified', result['visibility_limitations'])
            return result
        finally:
            c._SNAPSHOTS.clear()
            c._DIFFS.clear()

    def test_explicit_vdom_override_is_never_complete_when_scope_is_unverified(self):
        enable = '    set vdom-override enable\n'
        disable = '    set vdom-override disable\n'
        unset = '    unset vdom-override\n'
        cases = ((enable,), (unset,), (disable, disable),
                 ('    set vdom-override unexpected\n',),
                 ('    set vdom-override disable extra\n',),
                 (disable, unset), (unset, disable), (enable, disable), (disable, enable),
                 (disable, disable, unset), (unset, disable, disable))
        for defaults in (False, True):
            for extra in cases:
                with self.subTest(defaults=defaults, extra=extra):
                    result = self._engine_vdom_override(extra, defaults=defaults)
                    self.assertFalse(result['configuration_complete'])
                    self.assertEqual(result['visibility_limitations'], ['vdom-override-unverified'])

    def test_vdom_override_evidence_binds_only_to_the_authenticated_account(self):
        for defaults in (False, True):
            for extra in ((), ('    set vdom-override disable\n',)):
                with self.subTest(defaults=defaults, extra=extra):
                    result = self._engine_vdom_override(extra, other=('    set vdom-override enable\n',), defaults=defaults)
                    self.assertTrue(result['configuration_complete'])
                    self.assertEqual(result['visibility_limitations'], [])
            result = self._engine_vdom_override(('    set vdom-override enable\n',),
                                               other=('    set vdom-override disable\n',), defaults=defaults)
            self.assertFalse(result['configuration_complete'])
            self.assertEqual(result['visibility_limitations'], ['vdom-override-unverified'])

    def test_live_shaped_capture_with_none_rights_is_incomplete(self):
        for chunk in (1, 7, 4096):
            with self.subTest(chunk=chunk):
                content, result = capture(live(config()), chunk)
                self.assertEqual(result, {'config_scope': 'all', 'configuration_complete': False,
                                          'visibility_limitations': ['networking', 'share-resource', 'user']})
                visible = text(content)
                self.assertIn('edit netops-read\n    set access-profile netops-read\n', visible)
                self.assertIn('    set accprofile-override disable\n', visible)
                self.assertIn('    set share-resource none\n', visible)
                self.assertIn('config system global\n    set hostname ADC-LAB\nend\n', visible)
                for leaked in ('SECRET-FIXTURE', 'ADMIN-FIXTURE', '--More--', 'FortiADC-KVM', '\r'):
                    self.assertNotIn(leaked, visible)

    def test_account_name_differs_from_profile_name(self):
        raw = live(config(profiles=profile_lines('ro-profile', READ), admins=admin_lines('auditor', 'ro-profile')))
        self.assertTrue(capture(raw, account='auditor')[1]['configuration_complete'])
        self.assertFalse(capture(raw, account='netops-read')[1]['configuration_complete'])

    def test_unverifiable_profile_binding_is_never_complete(self):
        dropped = tuple(right for right in RIGHTS if right[0] != 'user')
        cases = {
            'override enabled': config(admins=admin_lines(extra=('    set accprofile-override enable\n',))),
            'right missing without defaults': config(profiles=profile_lines(rights=dropped)),
            'right duplicated': config(profiles=profile_lines(extra=('    set log read-write\n',))),
            'unknown right': config(profiles=profile_lines(extra=('    set firewall read\n',))),
            'unknown level': config(profiles=profile_lines(rights=dropped + (('user', 'write'),))),
            'two profile fields': config(admins=admin_lines(extra=('    set access-profile other\n',))),
            'account missing': config(admins=''),
            'account twice': config(admins=admin_lines() + admin_lines()),
            'profile twice': config(profiles=profile_lines() + profile_lines()),
            'profile missing': config(profiles=''),
            'redacted profile name': config(profiles=profile_lines('$1$x'), admins=admin_lines(profile='$1$x')),
            'profile named like a redaction label': config(profiles=profile_lines('<REDACTED:credential#2>', READ),
                                                           admins=admin_lines(profile='$1$x')),
        }
        for name, raw in cases.items():
            with self.subTest(name):
                result = capture(live(raw))[1]
                self.assertFalse(result['configuration_complete'])
                self.assertIn('access-profile-unverified', result['visibility_limitations'])

    def test_system_administrator_without_profile_sees_every_area(self):
        # Live 7.6.7: `admin` carries `set is-system-admin yes` and no access-profile, also with defaults.
        system = '  edit "netops-read"\n    set is-system-admin yes\n    set password ENC SECRET-FIXTURE\n  next\n'
        for profiles in (profile_lines(), ''):
            with self.subTest(profiles=bool(profiles)):
                result = capture(live(config(profiles=profiles, admins=system)))[1]
                self.assertEqual(result, {'config_scope': 'all', 'configuration_complete': True,
                                          'visibility_limitations': []})
        explicit = system.replace('yes\n', 'yes\n    set accprofile-override disable\n')
        self.assertTrue(capture(live(config(admins=explicit)))[1]['configuration_complete'])
        cases = {
            'system administrator with a profile': system.replace('yes\n', 'yes\n    set access-profile "netops-read"\n'),
            'system administrator twice': system.replace('yes\n', 'yes\n    set is-system-admin yes\n'),
            'unexpected value': system.replace('set is-system-admin yes', 'set is-system-admin maybe'),
            'override enabled': system.replace('yes\n', 'yes\n    set accprofile-override enable\n'),
            'another account is the system administrator': admin_lines(profile='missing') + system.replace(
                '"netops-read"', '"other"'),
        }
        for name, admins in cases.items():
            with self.subTest(name):
                result = capture(live(config(admins=admins)))[1]
                self.assertFalse(result['configuration_complete'])
                self.assertIn('access-profile-unverified', result['visibility_limitations'])
        not_system = admin_lines(extra=('    set is-system-admin no\n',))
        result = capture(live(config(profiles=profile_lines(rights=READ), admins=not_system)))[1]
        self.assertTrue(result['configuration_complete'])

    def test_vdom_must_be_exactly_one(self):
        result = capture(live(config(vdom='')))[1]
        self.assertEqual((result['configuration_complete'], result['visibility_limitations']),
                         (False, ['networking', 'share-resource', 'user', 'vdom-unverified']))
        empty = capture(live(config(vdom='config system vdom\nend\n')))[1]
        self.assertIn('vdom-unverified', empty['visibility_limitations'])
        two = 'config system vdom\n  edit root\n  next\n  edit second\n  next\nend\n'
        with self.assertRaisesRegex(ValueError, 'config_platform_not_supported'):
            capture(live(config(vdom=two)))
        with self.assertRaises(ValueError):
            capture(live(config(vdom='config vdom\n  edit root\n  next\nend\n')))

    def test_pager_is_removed_only_in_its_exact_shape(self):
        for spaces in (1, 256):
            with self.subTest(spaces=spaces):
                raw = live(config()).replace(PAGER, '--More-- \r' + ' ' * spaces + '\r')
                self.assertEqual(capture(raw, 1)[1]['visibility_limitations'], ['networking', 'share-resource', 'user'])
        for broken in ('--More-- \r' + ' ' * 257 + '\r', '--More--\r \r', '--More-- \r \n'):
            for chunk in (3, 4096):
                with self.subTest(broken=broken, chunk=chunk):
                    with self.assertRaises(ValueError):
                        capture(live(config()).replace(PAGER, broken), chunk)
        sink = []
        normalizer = f.Normalizer(sink.append, 1024)
        normalizer.feed(b'end\n--More-- \r   ')
        with self.assertRaises(ValueError):
            normalizer.finish()
        self.assertEqual(b''.join(sink), b'end\n')

    def test_carriage_return_outside_the_exact_pager_is_refused(self):
        clean = live(config())
        cases = {
            'crlf': clean.replace('\n', '\r\n'),
            'bare cr': clean.replace('end\nconfig system admin', 'end\rconfig system admin'),
            'cr after pager': clean.replace(PAGER, PAGER + '\r', 1),
            'cr before pager': clean.replace(PAGER, '\r' + PAGER, 1),
            'cr at the end': clean + '\r',
        }
        for name, raw in cases.items():
            for chunk in (1, 3, 4096):
                with self.subTest(name, chunk=chunk):
                    with self.assertRaises(ValueError):
                        capture(raw, chunk)

    def test_raw_limit_counts_pager_bytes(self):
        sink = []
        normalizer = f.Normalizer(sink.append, 30)
        normalizer.feed(b'config a\n' + b'--More-- \r' + b' ' * 10 + b'\r')
        with self.assertRaises(ValueError):
            normalizer.feed(b'end\n')

    def test_identity_accepts_only_the_verified_build(self):
        firmware, metadata = f.verify_identity(STATUS)
        self.assertEqual(firmware, f.SUPPORTED)
        self.assertEqual(metadata, {'product': 'FortiADC-KVM', 'version': '7.6.7', 'build': '0676'})
        self.assertEqual(f.verify_identity(STATUS.replace('\n', '\r\n'))[0], f.SUPPORTED)
        cases = (STATUS.replace('v7.6.7', 'v7.6.6'), STATUS.replace('build0676', 'build0677'),
                 STATUS.replace('FortiADC-KVM v', 'FortiGate-VM64 v'),
                 STATUS.replace('Version:       n/a', 'Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)'),
                 STATUS.replace('Version:       n/a', 'version: FortiGate-VM64 v7.6.8,build3744'),
                 STATUS.replace('Hostname', 'Host\x07name'), STATUS.replace('Version: Forti', 'Release: Forti'),
                 None, 'x' * 70000)
        for status in cases:
            with self.subTest(status=repr(status)[:80]):
                with self.assertRaises(ValueError):
                    f.verify_identity(status)

    def test_read_command_follows_include_defaults(self):
        self.assertEqual(f.read_command('all', True, True), 'show full-configuration')
        self.assertEqual(f.read_command('all', True, False), 'show')
        for arguments in (('all', False, True), ('system admin', True, True), ('all', True, 1), ('all', 1, True)):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    f.read_command(*arguments)

    def test_policy_exists_only_for_the_verified_build(self):
        selected = f.policy_for(f.SUPPORTED)
        self.assertEqual(selected.platform, 'fortiadc')
        self.assertFalse(selected.allow_vdom)
        self.assertTrue(selected.identifier.startswith('fortiadc-full-2:'))
        for firmware in (('FortiADC-KVM', '7.6.6', '0676'), ('FortiGate-VM64', '7.6.8', '3744'), None, list(f.SUPPORTED)):
            with self.subTest(firmware=firmware):
                with self.assertRaises(ValueError):
                    f.policy_for(firmware)


SLB = ('config system health-check\n'
       '  edit "HC-HTTP"\n    set type http\n    set dest-addr 203.0.113.9\n    set port 8080\n'
       '    set interval 10\n    set timeout 3\n    set up-retry 2\n    set hostname app.example.test\n'
       '    set status-code 200\n    set username hc-user-fixture\n    set password ENC HC-SECRET-FIXTURE\n'
       '    set secret-key RADIUS-KEY-FIXTURE\n    set community SNMP-COMMUNITY-FIXTURE\n'
       '    set bindDN cn=bind-fixture\n    set connect-string user/ORACLE-FIXTURE@db\n'
       '    set send-string "GET /health?token=SEND-FIXTURE"\n    set additional-string "Authorization: Basic ADD-FIXTURE"\n'
       '    config snmp-custom\n      edit "oid-1"\n        set oid 1.3.6.1\n        set name SNMP-NAME-FIXTURE\n'
       '        set weight 5\n      next\n    end\n  next\nend\n'
       'config load-balance real-server\n  edit "RS-1"\n    set status enable\n    set ip 198.51.100.11\n  next\nend\n'
       'config load-balance pool\n  edit "POOL-WEB"\n    set health-check-ctrl enable\n'
       '    set health-check-list HC-HTTP\n    set health-check-relation AND\n'
       '    set use-private-addr enable\n    config pool_member\n      edit 1\n        set real-server RS-1\n'
       '        set pool_member_service_port 8080\n        set pool_member_weight 10\n        set status enable\n'
       '        set pool_member_cookie COOKIE-FIXTURE\n      next\n    end\n  next\nend\n'
       'config load-balance virtual-server\n  edit "VS-WEB"\n    set type l7-load-balance\n'
       '    set ip 192.0.2.10\n    set port 443\n    set interface port1\n    set load-balance-pool POOL-WEB\n'
       '    set load-balance-profile LB_PROF_HTTPS\n    set client-ssl-profile SSL-CLIENT\n    set waf-profile WAF-1\n'
       '    set status enable\n    set comments "owner COMMENT-FIXTURE"\n    set error-msg "ERROR-FIXTURE"\n'
       '  next\nend\n')


class FortiADCServerLoadBalancing(TestCase):
    def test_virtual_server_chain_is_visible(self):
        content, _ = capture(live(config() + SLB))
        output = text(content)
        for line in ('edit VS-WEB', 'set load-balance-pool POOL-WEB', 'set ip 192.0.2.10', 'set port 443',
                     'set interface port1', 'set client-ssl-profile SSL-CLIENT', 'set waf-profile WAF-1',
                     'edit POOL-WEB', 'set health-check-list HC-HTTP', 'set health-check-relation AND',
                     'edit 1', 'set real-server RS-1', 'set pool_member_service_port 8080',
                     'set pool_member_weight 10', 'edit RS-1', 'set ip 198.51.100.11', 'edit HC-HTTP',
                     'set type http', 'set dest-addr 203.0.113.9', 'set port 8080', 'set hostname app.example.test',
                     'set status-code 200', 'set oid 1.3.6.1', 'set weight 5'):
            with self.subTest(line=line):
                self.assertIn(line + '\n', output)

    def test_credentials_are_hidden_and_diagnostic_text_is_visible(self):
        content, _ = capture(live(config() + SLB))
        output = text(content)
        for value in ('HC-SECRET', 'RADIUS-KEY', 'ADD-FIXTURE', 'SNMP-COMMUNITY-FIXTURE'):
            with self.subTest(value=value):
                self.assertNotIn(value, output)
        for field in ('password', 'secret-key', 'community'):
            with self.subTest(field=field):
                self.assertRegex(output, 'edit HC-HTTP\n(?:    set .*\n)*    set %s %s\n' % (field, CREDENTIAL))
        self.assertRegex(output, '    set additional-string "Authorization: Basic %s"\n' % CREDENTIAL)
        for line in ('set username hc-user-fixture', 'set bindDN "cn=bind-fixture"',
                     'set connect-string user/ORACLE-FIXTURE@db', 'set send-string "GET /health?token=SEND-FIXTURE"',
                     'edit oid-1', 'set name SNMP-NAME-FIXTURE', 'set pool_member_cookie COOKIE-FIXTURE',
                     'set comments "owner COMMENT-FIXTURE"', 'set error-msg ERROR-FIXTURE', 'set use-private-addr enable'):
            with self.subTest(line=line):
                self.assertIn(line + '\n', output)

    def test_health_check_additional_string_is_one_inline_header(self):
        def run(value):
            extra = ('config system health-check\n  edit "HC-HDR"\n    set type http\n'
                     '    set additional-string %s\n  next\nend\n' % value)
            return text(capture(live(config() + extra))[0])
        self.assertIn('    set additional-string "X-Health-Probe: PUBLIC-VISIBLE"\n', run('"X-Health-Probe: PUBLIC-VISIBLE"'))
        output = run('"Authorization: Bearer HC-TOKEN-FIXTURE"')
        self.assertNotIn('HC-TOKEN-FIXTURE', output)
        self.assertRegex(output, '    set additional-string "Authorization: Bearer %s"\n' % CREDENTIAL)
        for value in ('"X-A: a\\r\\nAuthorization: Basic CRLF-FIXTURE"', '"X-B: b\nAuthorization: Basic NL-FIXTURE"',
                      '"not a header MALFORMED-FIXTURE"', 'Authorization: TWO-FIXTURE'):
            with self.subTest(value=value):
                output = run(value)
                self.assertIn('    set additional-string <UNVERIFIED:unsupported-format>\n', output)
                for fixture in ('CRLF-FIXTURE', 'NL-FIXTURE', 'MALFORMED-FIXTURE', 'TWO-FIXTURE'):
                    self.assertNotIn(fixture, output)

    def test_public_secret_and_unverified_maps_are_disjoint(self):
        selected = f.policy_for(f.SUPPORTED)
        self.assertEqual((len(selected.secret_fields), len(selected.unverified_fields), len(selected.inline_header_fields)),
                         (35, 3, 5))
        self.assertGreaterEqual(len(selected.public_fields), 2069)
        self.assertFalse(selected.public_fields & selected.secret_fields)
        self.assertFalse(selected.public_fields & selected.unverified_fields)
        self.assertFalse(selected.secret_fields & selected.unverified_fields)
        for group in (selected.public_fields, selected.secret_fields, selected.unverified_fields):
            self.assertFalse(group & selected.inline_header_fields)
        self.assertFalse(selected.opaque_sections)
        for item in ((('system health-check',), 'password'), (('system interface',), 'password'),
                     (('system admin',), 'password'), (('user tacacs+',), 'secret')):
            with self.subTest(item=item):
                self.assertIn(item, selected.secret_fields)
        self.assertIn((('load-balance profile', 'server-request-header-insert'), 'string'), selected.inline_header_fields)
        self.assertIn((('system health-check',), 'additional-string'), selected.inline_header_fields)
        self.assertIn(('system health-check', 'snmp-custom'), selected.public_edit_sections)


NETWORK = ('config system interface\n  edit "port1"\n    set ip 192.0.2.1/24\n    set allowaccess https ssh ping\n'
           '    set mtu 1500\n    set mode pppoe\n    set username pppoe-user-fixture\n    set password ENC PPPOE-FIXTURE\n'
           '    config secondary-ip-list\n      edit 1\n        set ip 192.0.2.2/24\n      next\n    end\n'
           '    config trust-ip-list\n      edit "mgmt"\n        set type ip-netmask\n        set ip-network 198.51.100.0/24\n'
           '      next\n    end\n  next\nend\n'
           'config system dns\n  set primary 192.0.2.53\nend\n'
           'config router static\n  edit 1\n    set destination 0.0.0.0/0\n    set gateway 192.0.2.254\n'
           '    set distance 10\n  next\nend\n'
           'config router policy\n  edit 1\n    set source 203.0.113.0/24\n    set gateway 192.0.2.253\n  next\nend\n'
           'config system ha\n  set mode active-passive\n  set group-id 7\n  set hbdev port3\n  set priority 5\n'
           '  set override enable\n  set monitor port1\n  config remote-ip-monitor-list\n    edit "gw"\n'
           '      set remote-address 192.0.2.254\n      set health-check-interval 5\n    next\n  end\nend\n'
           'config log setting remote\n  edit "syslog1"\n    set status enable\n    set server 192.0.2.40\n'
           '    set port 514\n  next\nend\n'
           'config log setting local\n  set status enable\n  set script-log-status enable\nend\n'
           'config log setting fortianalyzer\n  edit 1\n    set status enable\n    set server 192.0.2.41\n  next\nend\n'
           'config load-balance method\n  edit "LB_METHOD_RR"\n    set type round-robin\n  next\nend\n'
           'config load-balance persistence\n  edit "P-COOKIE"\n    set type insert-cookie\n    set keyword SRV\n'
           '    set timeout 600\n    set sess-keyword custom\n    set cookie-custom-attr enable\n'
           '    set cookie-custom-attr-value "PERSIST-ATTR-FIXTURE"\n  next\n  edit "P-HEADER"\n'
           '    set type hash-http-header\n    set keyword "X-HEADER-KEYWORD-FIXTURE"\n  next\nend\n'
           'config load-balance profile\n  edit "LB_PROF_HTTPS"\n    set type https\n    set client-timeout 50\n'
           '    set failed-client-str "FAILED-PAGE-FIXTURE"\n    config server-request-header-insert\n      edit 1\n'
           '        set type insert-if-not-exist\n        set string "Authorization: Bearer HEADER-FIXTURE"\n      next\n    end\n'
           '    config client-request-header-erase\n      edit 1\n        set string X-Debug\n      next\n    end\n  next\nend\n'
           'config load-balance client-ssl-profile\n  edit "SSL-CLIENT"\n    set local-certificate-group LCG-1\n'
           '    set ssl-allowed-versions tlsv1.2 tlsv1.3\n    set client-certificate-verify CV-1\n'
           '    set forward-proxy-resign-cert-rsa-key-size 2048\n    set ssl-customize-ciphers-flag enable\n'
           '    set backend-ssl-customize-ciphers-flag enable\n'
           '    set backend-ssl-customized-ciphers ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES128-GCM-SHA256\n'
           '  next\nend\n'
           'config load-balance real-server-ssl-profile\n  edit "RS-SSL"\n    set ssl enable\n'
           '    set server-cert-verify SCV-1\n  next\nend\n')



class FortiADCNetworkAndProfiles(TestCase):
    def test_network_routing_ha_logging_and_profiles_are_visible(self):
        content, _ = capture(live(config() + NETWORK))
        output = text(content)
        for line in ('edit port1', 'set ip 192.0.2.1/24', 'set allowaccess https ssh ping', 'set mtu 1500',
                     'set ip 192.0.2.2/24', 'edit mgmt', 'set ip-network 198.51.100.0/24', 'set primary 192.0.2.53',
                     'set destination 0.0.0.0/0', 'set gateway 192.0.2.254', 'set distance 10',
                     'set source 203.0.113.0/24', 'set mode active-passive', 'set group-id 7', 'set hbdev port3',
                     'set priority 5', 'set override enable', 'set monitor port1', 'edit gw',
                     'set remote-address 192.0.2.254', 'set health-check-interval 5', 'edit syslog1',
                     'set server 192.0.2.40', 'set port 514', 'set server 192.0.2.41', 'edit LB_METHOD_RR',
                     'set type round-robin', 'edit P-COOKIE', 'set timeout 600',
                     'edit LB_PROF_HTTPS', 'set client-timeout 50', 'set type insert-if-not-exist',
                     'set string X-Debug', 'edit SSL-CLIENT', 'set local-certificate-group LCG-1',
                     'set ssl-allowed-versions tlsv1.2 tlsv1.3', 'set client-certificate-verify CV-1',
                     'edit RS-SSL', 'set server-cert-verify SCV-1', 'set sess-keyword custom', 'set cookie-custom-attr enable',
                     'set username pppoe-user-fixture', 'set cookie-custom-attr-value PERSIST-ATTR-FIXTURE',
                     'set failed-client-str FAILED-PAGE-FIXTURE', 'set script-log-status enable',
                     'set forward-proxy-resign-cert-rsa-key-size 2048',
                     'edit P-HEADER', 'set ssl-customize-ciphers-flag enable', 'set backend-ssl-customize-ciphers-flag enable',
                     'set backend-ssl-customized-ciphers ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES128-GCM-SHA256',
                     'edit P-COOKIE\n    set type insert-cookie\n    set keyword SRV',
                     'edit P-HEADER\n    set type hash-http-header\n    set keyword X-HEADER-KEYWORD-FIXTURE'):
            with self.subTest(line=line):
                self.assertIn(line + '\n', output)

    def test_network_credentials_and_unparsed_headers_stay_hidden(self):
        content, _ = capture(live(config() + NETWORK))
        output = text(content)
        for value in ('PPPOE-FIXTURE', 'HEADER-FIXTURE'):
            with self.subTest(value=value):
                self.assertNotIn(value, output)
        self.assertRegex(output, 'edit port1\n(?:    set .*\n)*    set password %s\n' % CREDENTIAL)
        self.assertRegex(output, '    set string "Authorization: Bearer %s"\n' % CREDENTIAL)

    def test_inline_header_insert_shows_name_and_hides_only_authorization_credentials(self):
        entries = {'client-request': ('Via: SIP/2.0/UDP 203.0.113.100:5060', 'X-Forwarded-For: 198.51.100.7'),
                   'client-response': ('X-Trace-Key: TRACE-VISIBLE', 'Session-Policy: strict'),
                   'server-request': ('Proxy-Authorization: Basic PROXY-FIXTURE', 'authorization: TOKEN-FIXTURE'),
                   'server-response': ('not a header line', 'X-Empty:')}
        extra = 'config load-balance profile\n  edit "LB_PROF_H"\n'
        for name, values in entries.items():
            extra += '    config %s-header-insert\n' % name
            for index, value in enumerate(values, 1):
                extra += '      edit %d\n        set type insert-always\n        set string "%s"\n      next\n' % (index, value)
            extra += '    end\n'
        extra += '  next\nend\n'
        content, _ = capture(live(config() + extra))
        output = text(content)
        for value in ('PROXY-FIXTURE', 'TOKEN-FIXTURE', 'not a header line'):
            with self.subTest(value=value):
                self.assertNotIn(value, output)
        for line in ('set string "Via: SIP/2.0/UDP 203.0.113.100:5060"', 'set string "X-Forwarded-For: 198.51.100.7"',
                     'set string "X-Trace-Key: TRACE-VISIBLE"', 'set string "Session-Policy: strict"',
                     'set string X-Empty:', 'set string <UNVERIFIED:unsupported-format>'):
            with self.subTest(line=line):
                self.assertIn('    ' + line + '\n', output)
        self.assertRegex(output, '    set string "Proxy-Authorization: Basic %s"\n' % CREDENTIAL)
        self.assertRegex(output, '    set string "authorization: %s"\n' % CREDENTIAL)

    def test_inline_header_hides_the_whole_x_api_key_value(self):
        extra = 'config load-balance profile\n  edit "LB_PROF_K"\n    config server-request-header-insert\n'
        for index, value in enumerate(('X-API-Key: APIKEY-FIXTURE', 'x-api-key: SCHEMEFIX APIKEY-TWO-FIXTURE',
                                       'X-Trace-Key: TRACE-VISIBLE'), 1):
            extra += '      edit %d\n        set string "%s"\n      next\n' % (index, value)
        extra += '    end\n  next\nend\n'
        output = text(capture(live(config() + extra))[0])
        for value in ('APIKEY', 'SCHEMEFIX'):
            with self.subTest(value=value):
                self.assertNotIn(value, output)
        self.assertRegex(output, '    set string "X-API-Key: %s"\n' % CREDENTIAL)
        self.assertRegex(output, '    set string "x-api-key: %s"\n' % CREDENTIAL)
        self.assertIn('    set string "X-Trace-Key: TRACE-VISIBLE"\n', output)

    def test_inline_header_empty_value_is_a_known_empty_format(self):
        extra = 'config load-balance profile\n  edit "LB_PROF_E"\n'
        for name in ('client-request', 'client-response', 'server-request', 'server-response'):
            extra += '    config %s-header-insert\n      edit 1\n        set string ""\n      next\n    end\n' % name
        extra += '  next\nend\n'
        content, _ = capture(live(config() + extra))
        output = text(content)
        self.assertEqual([line.strip() for line in output.splitlines()].count('set string ""'), 4)
        self.assertNotIn('set string <UNVERIFIED', output)

    def test_inline_header_requires_a_single_rfc_field_name(self):
        for value in ('Bad Name: x', ': empty-name', 'NoColon MULTI-FIXTURE'):
            with self.subTest(value=value):
                extra = ('config load-balance profile\n  edit "LB_PROF_R"\n    config client-request-header-insert\n'
                         '      edit 1\n        set string "%s"\n      next\n    end\n  next\nend\n' % value)
                output = text(capture(live(config() + extra))[0])
                self.assertIn('    set string <UNVERIFIED:unsupported-format>\n', output)
                self.assertNotIn('MULTI-FIXTURE', output)

    def test_fields_outside_their_mapped_context_are_unclassified(self):
        extra = ('config load-balance profile\n  edit "LB_PROF_X"\n    set sess-keyword custom\n'
                 '    set backend-ssl-customized-ciphers ECDHE-ECDSA-AES256-GCM-SHA384\n    set keyword SRV\n  next\nend\n'
                 'config load-balance client-ssl-profile\n  edit "SSL-OTHER"\n'
                 '    set backend-ssl-customized-ciphers ENC CIPHER-ENC-FIXTURE\n  next\nend\n')
        content, _ = capture(live(config() + NETWORK + extra))
        output = text(content)
        self.assertNotIn('CIPHER-ENC-FIXTURE', output)
        self.assertIn('edit LB_PROF_X\n    set sess-keyword <UNVERIFIED:unclassified-field>\n'
                      '    set backend-ssl-customized-ciphers <UNVERIFIED:unclassified-field>\n'
                      '    set keyword <UNVERIFIED:unclassified-field>\n', output)
        self.assertRegex(output, 'edit SSL-OTHER\n    set backend-ssl-customized-ciphers %s\n' % CREDENTIAL)

    def test_persistence_keyword_is_visible_unless_it_is_a_credential(self):
        shown = ('SRV', 'JSESSIONID', 'X-Forwarded-For', 'session_id', 'KW FIXTURE', 'sid=KW-FIXTURE')
        lines = [('S%d' % n, v) for n, v in enumerate(shown)] + [('H0', 'ENC KW-SECRET'), ('H1', '$1$KW-SECRET')]
        extra = 'config load-balance persistence\n' + ''.join(
            '  edit "%s"\n    set type hash-http-header\n    set keyword %s\n  next\n'
            % (name, value if value.startswith('ENC ') else json.dumps(value)) for name, value in lines) + 'end\n'
        content, _ = capture(live(config() + NETWORK + extra))
        output = text(content)
        for number, value in enumerate(shown):
            with self.subTest(value=value):
                self.assertIn('edit S%d\n    set type hash-http-header\n    set keyword %s\n'
                              % (number, c._quoted_value(value)), output)
        for name in ('H0', 'H1'):
            with self.subTest(name=name):
                self.assertRegex(output, 'edit %s\n    set type hash-http-header\n    set keyword %s\n' % (name, CREDENTIAL))
        self.assertNotIn('KW-SECRET', output)


class FortiADCUserTacacs(TestCase):
    def test_tacacs_plus_section_is_parsed_and_its_secret_hidden(self):
        extra = ('config user tacacs+\n  edit "TAC-1"\n    set server 192.0.2.50\n    set port 49\n'
                 '    set secret TACACS-FIXTURE\n  next\nend\n')
        for chunk in (1, 4096):
            with self.subTest(chunk=chunk):
                content, result = capture(live(config(profiles=profile_lines(rights=READ)) + extra), chunk)
                output = text(content)
                self.assertTrue(result['configuration_complete'])
                self.assertNotIn('TACACS-FIXTURE', output)
                self.assertRegex(output, 'config user tacacs\\+\nedit TAC-1\n    set server 192.0.2.50\n'
                                         '    set port 49\n    set secret %s\n' % CREDENTIAL)


LIVE_VDOM = ('CONCURRENTSESSION', 'INBOUND', 'L4CPS', 'L7CPS', 'L7RPS', 'OUTBOUND', 'SSLCPS', 'SSLTHROUGHPUT',
             'errorpage', 'healthcheck', 'localuser', 'realserver', 'sourcepool', 'usergroup', 'virtualserver')
LIVE_PROFILE = (('http2-profile', 'LB_HTTP2'), ('http3-profile', 'LB_HTTP3'), ('stateless', 'disable'),
                ('timeout', '60'), ('domain-name', 'mail.example.test'), ('disable-command', 'VRFY'),
                ('disable-command-status', 'enable'), ('msg-encode-type', 'ascii'),
                ('length-indicator-type', 'none'), ('length-indicator-size', '4'),
                ('length-indicator-shift', '0'), ('starttls-active-mode', 'require'), ('opt-header-length', '0'))


def live_schema(category='Gambling', sub_category='11', domain='mail.example.test'):
    profile = ''.join('    set %s %s\n' % (name, domain if name == 'domain-name' else value)
                      for name, value in LIVE_PROFILE)
    return ('config load-balance web-category\n  edit "Adult-Content"\n    set id 2\n'
            '    config sub-category-list\n      edit "%s"\n        set sub-category %s\n      next\n    end\n'
            '  next\nend\n'
            'config load-balance web-sub-category\n  edit "%s"\n    set id 11\n  next\nend\n'
            'config system scripting\n  edit "HTTP_REDIRECT"\n  next\nend\n'
            'config load-balance profile\n  edit "LB_PROF_LIVE"\n%s  next\nend\n'
            'config system ha\n    set boot-time 30\n    set l7-persistence-pickup disable\nend\n'
            'config system setting\n    set lldp-transmission disable\nend\n'
            % (category, sub_category, category, profile))


def live_vdom():
    return 'config system vdom\n  edit root\n' + ''.join('    set %s 0\n' % name for name in LIVE_VDOM) + '  next\nend\n'


class FortiADCLiveSchemaCoverage(TestCase):
    def test_reference_fields_seen_on_live_7_6_7_are_visible(self):
        output = text(capture(live(config(vdom=live_vdom()) + live_schema()))[0])
        self.assertNotIn('<UNVERIFIED', output)
        for line in (['edit Adult-Content', 'set id 2', 'edit Gambling', 'set sub-category 11', 'set id 11',
                      'edit HTTP_REDIRECT', 'set boot-time 30', 'set l7-persistence-pickup disable',
                      'set lldp-transmission disable'] +
                     ['set %s %s' % item for item in LIVE_PROFILE] + ['set %s 0' % name for name in LIVE_VDOM]):
            with self.subTest(line=line):
                self.assertRegex(output, '\n *%s\n' % line)

    def test_live_secret_in_newly_visible_fields_stays_hidden(self):
        secret = 'LIVE-SECRET-FIXTURE'
        raw = live(config(vdom=live_vdom()) + live_schema(secret, secret, secret))
        output = text(capture(raw, forbidden=(secret,))[0])
        self.assertNotIn(secret, output)
        for line in ('edit %s' % CREDENTIAL, 'set sub-category %s' % CREDENTIAL, 'set domain-name %s' % CREDENTIAL):
            with self.subTest(line=line):
                self.assertRegex(output, '\n *%s\n' % line)

    def test_unreferenced_live_fields_stay_unverified(self):
        extra = ('config security waf fg-data-type\n  edit "FG-TYPE"\n    set future-pattern TYPE-PATTERN-FIXTURE\n'
                 '  next\nend\n'
                 'config load-balance profile\n  edit "LB_PROF_LIVE"\n    set future-decode-mode DECODE-FIXTURE\n  next\nend\n')
        output = text(capture(live(config() + extra))[0])
        self.assertNotIn('TYPE-PATTERN-FIXTURE', output)
        self.assertNotIn('DECODE-FIXTURE', output)
        self.assertEqual(output.count('<UNVERIFIED:unclassified-field>'), 2)


def live_help(script_type='http', stream='STREAM_LOG'):
    return ('config system global\n    set secure-private-key disable\n    set private-data-encryption disable\nend\n'
            'config global-load-balance setting\n    set user-defined-certificate disable\nend\n'
            'config system scripting\n  edit "HTTP_REDIRECT"\n    set type %s\n  next\nend\n'
            'config system stream_scripting\n  edit "%s"\n  next\nend\n' % (script_type, stream))


class FortiADCLiveHelpCoverage(TestCase):
    def test_fields_typed_by_live_7_6_7_help_are_visible(self):
        output = text(capture(live(config() + live_help()))[0])
        self.assertNotIn('<UNVERIFIED', output)
        for line in ('set secure-private-key disable', 'set private-data-encryption disable',
                     'set user-defined-certificate disable', 'set type http', 'edit STREAM_LOG'):
            with self.subTest(line=line):
                self.assertRegex(output, '\n *%s\n' % line)

    def test_live_secret_in_help_typed_fields_stays_hidden(self):
        secret = 'LIVE-SECRET-FIXTURE'
        output = text(capture(live(config() + live_help(secret, secret)), forbidden=(secret,))[0])
        self.assertNotIn(secret, output)
        for line in ('set type %s' % CREDENTIAL, 'edit %s' % CREDENTIAL):
            with self.subTest(line=line):
                self.assertRegex(output, '\n *%s\n' % line)


def live_reference(port='5858'):
    return ('config system global\n    set lldp-transmission disable\nend\n'
            'config global-load-balance setting\n    set port %s\n    set auth-type none\n    set ca-verify disable\n'
            '    set ipv4-accessed-status enable\n    set ipv6-accessed-status disable\n'
            '    set persistence-mask-length 24\n    set persistence-mask-length6 64\n    set persistence-timeout 60\n'
            '    set proximity-cache-aging-period 7200\n    set proximity-cache-mask-length 24\n'
            '    set proximity-cache-mask-length6 64\n    set proximity-detect-interval 60\n'
            '    set proximity-detect-protocol icmp\n    set proximity-detect-retry-count 3\nend\n'
            'config security dos tcp-synflood-protection\n    set syncookie enable\nend\n'
            % port)


class FortiADCReferenceSyntaxCoverage(TestCase):
    def test_fields_in_exact_7_6_7_reference_syntax_are_visible(self):
        output = text(capture(live(config() + live_reference()))[0])
        self.assertNotIn('<UNVERIFIED', output)
        for line in ('set lldp-transmission disable', 'set port 5858', 'set auth-type none', 'set ca-verify disable',
                     'set ipv4-accessed-status enable', 'set ipv6-accessed-status disable',
                     'set persistence-mask-length 24', 'set persistence-mask-length6 64', 'set persistence-timeout 60',
                     'set proximity-cache-aging-period 7200', 'set proximity-cache-mask-length 24',
                     'set proximity-cache-mask-length6 64', 'set proximity-detect-interval 60',
                     'set proximity-detect-protocol icmp', 'set proximity-detect-retry-count 3', 'set syncookie enable'):
            with self.subTest(line=line):
                self.assertRegex(output, '\n *%s\n' % line)

    def test_neighbours_without_exact_reference_syntax_stay_unverified(self):
        extra = ('config security waf web-attack-signature\n  edit "WAS_LIVE"\n    set future-status STATUS-FIXTURE\n'
                 '  next\nend\n')
        output = text(capture(live(config() + live_reference() + extra))[0])
        for value in ('STATUS-FIXTURE',):
            with self.subTest(value=value):
                self.assertNotIn(value, output)
        self.assertEqual(output.count('<UNVERIFIED:unclassified-field>'), 1)

    def test_waf_profile_heuristic_sql_xss_injection_detect_from_the_7_6_7_reference_is_visible(self):
        raw = 'config security waf profile\n  edit "WAFP_LIVE"\n    set heuristic-sql-xss-injection-detect Alert-Only\n  next\nend\n'
        output = text(capture(live(config() + raw))[0])
        self.assertNotIn('<UNVERIFIED', output)
        self.assertIn('edit WAFP_LIVE\n    set heuristic-sql-xss-injection-detect Alert-Only\n', output)

    def test_live_secret_in_waf_profile_heuristic_sql_xss_injection_detect_stays_hidden(self):
        secret = 'LIVE-SECRET-FIXTURE'
        raw = 'config security waf profile\n  edit "WAFP_LIVE"\n    set heuristic-sql-xss-injection-detect %s\n  next\nend\n' % secret
        output = text(capture(live(config() + raw), forbidden=(secret,))[0])
        self.assertNotIn(secret, output)
        self.assertRegex(output, 'edit WAFP_LIVE\n    set heuristic-sql-xss-injection-detect %s\n' % CREDENTIAL)


def live_backend_versions(versions='sslv3 tlsv1.0 tlsv1.1 tlsv1.2'):
    return ('config load-balance client-ssl-profile\n  edit "SSL-BACKEND"\n'
            '    set backend-ssl-allowed-versions %s\n  next\nend\n' % versions)


class FortiADCClientSSLBackendVersions(TestCase):
    def test_backend_ssl_allowed_versions_from_the_7_6_7_client_ssl_example_are_visible(self):
        output = text(capture(live(config() + live_backend_versions()))[0])
        self.assertNotIn('<UNVERIFIED', output)
        self.assertIn('edit SSL-BACKEND\n    set backend-ssl-allowed-versions sslv3 tlsv1.0 tlsv1.1 tlsv1.2\n', output)

    def test_live_secret_in_backend_ssl_allowed_versions_stays_hidden(self):
        secret = 'LIVE-SECRET-FIXTURE'
        output = text(capture(live(config() + live_backend_versions(secret)), forbidden=(secret,))[0])
        self.assertNotIn(secret, output)
        self.assertRegex(output, 'edit SSL-BACKEND\n    set backend-ssl-allowed-versions %s\n' % CREDENTIAL)


def live_get_examples(listen='enable', sync='disable'):
    return ('config system global\n    set config-sync-enable %s\nend\n'
            'config global-load-balance setting\n    set listen-on-all-interface %s\nend\n' % (sync, listen))


class FortiADCGetExampleFlags(TestCase):
    def test_flags_from_the_7_6_7_get_examples_are_visible(self):
        output = text(capture(live(config() + live_get_examples()))[0])
        self.assertNotIn('<UNVERIFIED', output)
        for line in ('set config-sync-enable disable', 'set listen-on-all-interface enable'):
            with self.subTest(line=line):
                self.assertRegex(output, '\n *%s\n' % line)

    def test_live_secret_in_get_example_flags_stays_hidden(self):
        secret = 'LIVE-SECRET-FIXTURE'
        output = text(capture(live(config() + live_get_examples(secret, secret)), forbidden=(secret,))[0])
        self.assertNotIn(secret, output)
        for field in ('config-sync-enable', 'listen-on-all-interface'):
            with self.subTest(field=field):
                self.assertRegex(output, '\n *set %s %s\n' % (field, CREDENTIAL))


TLS_FIELDS = (('renegotiation', 'disable'), ('renegotiate-size', '1024'), ('renegotiate-period', '300'), ('ssl-tune-record-size', '16384'),
              ('ssl-ciphers-tlsv13', 'TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384'))


def live_tls_tuning(values=None):
    v = dict(TLS_FIELDS)
    if values is not None:
        v = dict.fromkeys(v, values)
    return ('config load-balance real-server-ssl-profile\n  edit "RS_TLS"\n'
            '    set renegotiation %(renegotiation)s\n    set renegotiate-size %(renegotiate-size)s\n'
            '    set renegotiate-period %(renegotiate-period)s\n  next\nend\n'
            'config load-balance client-ssl-profile\n  edit "CS_TLS"\n'
            '    set ssl-tune-record-size %(ssl-tune-record-size)s\n'
            '    set ssl-ciphers-tlsv13 %(ssl-ciphers-tlsv13)s\n  next\nend\n' % v)


def tls_line(name, value):
    profile = 'RS_TLS' if name.startswith('renegotia') else 'CS_TLS'
    return 'edit %s\n(    set .*\n)*    set %s %s\n' % (profile, name, value)


class FortiADCTLSProfileTuning(TestCase):
    def test_tls_tuning_fields_from_the_7_6_7_profiles_are_visible(self):
        output = text(capture(live(config() + live_tls_tuning()))[0])
        self.assertNotIn('<UNVERIFIED', output)
        for name, value in TLS_FIELDS:
            with self.subTest(field=name):
                self.assertRegex(output, tls_line(name, value))

    def test_live_secret_in_tls_tuning_fields_stays_hidden(self):
        secret = 'LIVE-SECRET-FIXTURE'
        output = text(capture(live(config() + live_tls_tuning(secret)), forbidden=(secret,))[0])
        self.assertNotIn(secret, output)
        for name, _ in TLS_FIELDS:
            with self.subTest(field=name):
                self.assertRegex(output, tls_line(name, CREDENTIAL))


TYPED_PROFILE = (('idle-time', '60'), ('ignore-flags-check', 'disable'), ('modify-host-on-nonstandard-rs-port', 'disable'),
                 ('no-server-message', 'disable'), ('source-port', 'disable'))


def live_typed(values=None, rolling='disable'):
    profile = ''.join('    set %s %s\n' % (name, value if values is None else values) for name, value in TYPED_PROFILE)
    return ('config load-balance profile\n  edit "LB_PROF_TYPED"\n%s  next\nend\n'
            'config system alert-policy\n  edit "AP_TYPED"\n    set use-rolling-window %s\n  next\nend\n'
            % (profile, rolling if values is None else values))


class FortiADCLiveTypedProfileAlertFields(TestCase):
    def test_fields_typed_by_the_live_7_6_7_read_are_visible_in_their_sections(self):
        output = text(capture(live(config() + live_typed()))[0])
        self.assertNotIn('<UNVERIFIED', output)
        for name, value in TYPED_PROFILE:
            with self.subTest(field=name):
                self.assertRegex(output, '(?m)^config load-balance profile\nedit LB_PROF_TYPED\n(?:    set [^\n]*\n)*    set %s %s\n' % (name, value))
        self.assertRegex(output, '(?m)^config system alert-policy\nedit AP_TYPED\n    set use-rolling-window disable\n')

    def test_live_secret_in_typed_profile_and_alert_fields_stays_hidden(self):
        secret = 'LIVE-SECRET-FIXTURE'
        output = text(capture(live(config() + live_typed(secret)), forbidden=(secret,))[0])
        self.assertNotIn(secret, output)
        for name, _ in TYPED_PROFILE:
            with self.subTest(field=name):
                self.assertRegex(output, '(?m)^config load-balance profile\nedit LB_PROF_TYPED\n(?:    set [^\n]*\n)*    set %s %s\n' % (name, CREDENTIAL))
        self.assertRegex(output, '(?m)^config system alert-policy\nedit AP_TYPED\n    set use-rolling-window %s\n' % CREDENTIAL)


GLOBAL_FIELDS = (('addrbook', 'disable'), ('admin-maintainer', 'enable'), ('advanced-bot-js-attribute-status', 'disable'),
                 ('auto-reboot', 'disable'), ('debug-memory-interval', '60'), ('debug-sys-file', 'disable'),
                 ('default-admin', 'enable'), ('hsm', 'disable'), ('https-redirect', 'disable'),
                 ('memory-limit', 'enable'), ('minimal-ram-warning', 'disable'), ('netdev_ref_dbg', 'disable'),
                 ('performance-mode', 'disable'), ('slub_debug', 'disable'), ('spectre_v2', 'enable'),
                 ('ssh-hmac-sha1', 'disable'), ('total-sessions', '1000000'), ('use-default-hostname', 'disable'))
WAF_HPC_FIELDS = (('constraint-method-override', 'disable'), ('illegal-multipart-request-check', 'enable'))
WAF_WAS_FIELDS = (('body-length-limit', '1024'),)
VS_FIELDS = (('fortiview', 'enable'), ('ingress-tag', '100'), ('stream-scripting-flag', 'disable'), ('wccp', 'disable'))


def sets(fields):
    return ''.join('    set %s %s\n' % item for item in fields)


def live_global_waf_vs(secret_line=''):
    return ('config system global\n' + sets(GLOBAL_FIELDS) + secret_line + 'end\n'
            'config security waf http-protocol-constraint\n  edit "WAF_HPC"\n' + sets(WAF_HPC_FIELDS) + '  next\nend\n'
            'config security waf web-attack-signature\n  edit "WAF_WAS"\n' + sets(WAF_WAS_FIELDS) + '  next\nend\n'
            'config load-balance virtual-server\n  edit "VS_TYPED"\n' + sets(VS_FIELDS) + '  next\nend\n')


def typed_line(section, edit, name, value):
    head = 'edit %s\n' % edit if edit else 'config %s\n' % section
    return head + '(?:    set .*\n)*    set %s %s\n' % (name, value)


TYPED_BLOCKS = ((('system global', None), GLOBAL_FIELDS),
                (('security waf http-protocol-constraint', 'WAF_HPC'), WAF_HPC_FIELDS),
                (('security waf web-attack-signature', 'WAF_WAS'), WAF_WAS_FIELDS),
                (('load-balance virtual-server', 'VS_TYPED'), VS_FIELDS))


class FortiADCLiveTypedGlobalWafVsFields(TestCase):
    def test_fields_typed_by_the_live_7_6_7_read_are_visible_in_their_blocks(self):
        output = text(capture(live(config() + live_global_waf_vs()))[0])
        self.assertNotIn('<UNVERIFIED', output)
        for (section, edit), fields in TYPED_BLOCKS:
            for name, value in fields:
                with self.subTest(section=section, field=name):
                    self.assertRegex(output, typed_line(section, edit, name, value))

    def test_known_secret_in_the_same_system_global_block_stays_hidden(self):
        raw = live(config() + live_global_waf_vs('    set shell-password SECRET-FIXTURE\n'))
        output = text(capture(raw, forbidden=('SECRET-FIXTURE',))[0])
        self.assertNotIn('SECRET-FIXTURE', output)
        self.assertNotIn('<UNVERIFIED', output)
        self.assertRegex(output, typed_line('system global', None, 'shell-password', CREDENTIAL))
        for (section, edit), fields in TYPED_BLOCKS:
            for name, value in fields:
                with self.subTest(section=section, field=name):
                    self.assertRegex(output, typed_line(section, edit, name, value))


# Fixed canonical CLI fixture: root42 + catalogue/JS4 + contract metadata.
# Synthetic values exercise output handling, not execution of CLI setters.
REMAINING_METADATA = '''config antivirus heuristic
    set mode heuristic-default
end
config global-load-balance servers
edit GLB_META
    set sync-status enable
next
end
config load-balance error-page
edit ERROR_META
    set error-page-file /var/error/meta.html
    set vpath /errors/map
next
end
config load-balance pool
edit POOL_META
    set direct-route-mode enable
config pool_member
edit 1
    set mssql-read-only enable
    set proxy-protocol v1
next
end
next
end
config load-balance profile
edit PROFILE_META
    set decode-mode decode-standard
    set pre-greet enable
next
end
config load-balance real-server-ssl-profile
edit TLS_META
    set secure-renegotiation require
next
end
config log report_queryset
edit REPORT_META
    set traffic_sort_type totalbytes
next
end
config security waf threshold-based-detection
edit THRESHOLD_META
    set comments "metadata threshold"
next
end
config security waf web-attack-signature
edit WAF_META
    set status enable
next
end
config system admin
edit ADMIN_META
    set admin-type local
    set two-factor disable
    set password ENC MAP-ADMIN-PASSWORD
config gui-dashboard
edit 5
    set name "Local dashboard"
    set widget 100
next
end
config global-gui-dashboard
edit 6
    set name "Global dashboard"
    set widget 102
next
end
next
end
config system alert-policy
edit ALERT_META
    set sec_event_filter_scope all
    set sys_event_filter_scope all
next
end
config system console
    set output standard
end
config system disk
    set attack_log enable
    set traffic_log disable
end
config system global
    set advanced-bot-js-attribute data-bot-metadata
    set contract-update undocumented-value
end
config system ips
    set engine-count 4
end
config system oci
    set region-type commercial
end
config system replacemsg admin
edit MESSAGE_META
    set format html
    set header http
next
end
config system setting
    set snat-match-local-traffics enable
    set tcp-timestamps disable
end
config system traffic-group
edit TRAFFIC_META
    set failover-order 1
    set network-failover disable
    set preempt disable
next
end
config system vdom
edit root
    set ocsp-cache-size 100
    set ssl-session-cache-size 200
    set ssl-session-timeout 300
    set status enable
next
end
config security waf fg-data-type
edit uk-iban
    set description "UK IBAN metadata"
    set pattern "^GB[0-9]{2}$"
next
end
config system certificate local
edit CERT_META
    set password MAP-CERT-PASSWORD
    set private-key-file metadata-key.pem
next
end
'''


class FortiADCRemainingMetadata(TestCase):
    def test_all_remaining_metadata_is_visible_in_exact_sections_and_objects(self):
        output = text(capture(live(REMAINING_METADATA))[0])
        expected = re.escape(REMAINING_METADATA)
        expected = expected.replace(re.escape('ENC MAP-ADMIN-PASSWORD'), CREDENTIAL)
        expected = expected.replace(re.escape('MAP-CERT-PASSWORD'), CREDENTIAL)
        self.assertRegex(output, r'\A' + expected + r'\Z')
        self.assertNotIn('<UNVERIFIED', output)
        self.assertNotIn('MAP-ADMIN-PASSWORD', output)
        self.assertNotIn('MAP-CERT-PASSWORD', output)
        self.assertIn('    set private-key-file metadata-key.pem\n', output)

    def test_known_credentials_in_public_metadata_are_hidden_without_losing_public_values(self):
        raw = REMAINING_METADATA.replace(
            'set advanced-bot-js-attribute data-bot-metadata',
            'set advanced-bot-js-attribute MAP-ADMIN-PASSWORD').replace(
            'set name "Local dashboard"', 'set name MAP-ADMIN-PASSWORD').replace(
            'set pattern "^GB[0-9]{2}$"', 'set pattern MAP-CERT-PASSWORD')
        output = text(capture(live(raw),
                              forbidden=('MAP-ADMIN-PASSWORD', 'MAP-CERT-PASSWORD'))[0])
        expected = re.escape(raw)
        expected = expected.replace(re.escape('ENC MAP-ADMIN-PASSWORD'), CREDENTIAL)
        expected = expected.replace(re.escape('MAP-ADMIN-PASSWORD'), CREDENTIAL)
        expected = expected.replace(re.escape('MAP-CERT-PASSWORD'), CREDENTIAL)
        self.assertRegex(output, r'\A' + expected + r'\Z')
        self.assertNotIn('MAP-ADMIN-PASSWORD', output)
        self.assertNotIn('MAP-CERT-PASSWORD', output)
        self.assertNotIn('<UNVERIFIED', output)
        self.assertIn('    set private-key-file metadata-key.pem\n', output)


HPC7_FIELDS = (('illegal-multipart-request-check-action', 'alert'), ('illegal-multipart-request-check-severity', 'high'))
WAS7_FIELDS = (('body-type-limit', 'disable'),)
VS7_FIELDS = (('public-ip', '192.0.2.20'), ('public-ip-type', 'ipv4'))
CERT7_FIELDS = (('acme-status', 'disable'), ('is-hsm', 'disable'))


def live_waf_vs_cert(cert_extra=''):
    return ('config security waf http-protocol-constraint\n  edit "HPC7"\n' + sets(HPC7_FIELDS) + '  next\nend\n'
            'config security waf web-attack-signature\n  edit "WAS7"\n' + sets(WAS7_FIELDS) + '  next\nend\n'
            'config load-balance virtual-server\n  edit "VS7"\n' + sets(VS7_FIELDS) + '  next\nend\n'
            'config system certificate local\n  edit "CERT7"\n' + sets(CERT7_FIELDS) + cert_extra + '  next\nend\n')


TYPED7_BLOCKS = ((('security waf http-protocol-constraint', 'HPC7'), HPC7_FIELDS),
                 (('security waf web-attack-signature', 'WAS7'), WAS7_FIELDS),
                 (('load-balance virtual-server', 'VS7'), VS7_FIELDS),
                 (('system certificate local', 'CERT7'), CERT7_FIELDS))


class FortiADCLiveTypedWafVsCertFields(TestCase):
    def assert_typed7_visible(self, output):
        for (section, edit), fields in TYPED7_BLOCKS:
            for name, value in fields:
                with self.subTest(section=section, field=name):
                    self.assertRegex(output, typed_line(section, edit, name, value))

    def test_fields_typed_by_the_live_7_6_7_read_are_visible_in_their_blocks(self):
        output = text(capture(live(config() + live_waf_vs_cert()))[0])
        self.assertNotIn('<UNVERIFIED', output)
        self.assert_typed7_visible(output)

    def test_known_certificate_password_in_the_same_edit_block_stays_hidden(self):
        raw = live(config() + live_waf_vs_cert('    set password ENC CERT-SECRET-FIXTURE\n'))
        output = text(capture(raw, forbidden=('CERT-SECRET-FIXTURE',))[0])
        self.assertNotIn('CERT-SECRET-FIXTURE', output)
        self.assertNotIn('<UNVERIFIED', output)
        self.assertRegex(output, typed_line('system certificate local', 'CERT7', 'password', CREDENTIAL))
        self.assert_typed7_visible(output)

    def test_unclassified_neighbour_in_the_certificate_block_stays_unverified(self):
        output = text(capture(live(config() + live_waf_vs_cert('    set future-key-type KEYTYPE-FIXTURE\n')))[0])
        self.assertNotIn('KEYTYPE-FIXTURE', output)
        self.assertEqual(output.count('<UNVERIFIED:unclassified-field>'), 1)
        self.assertRegex(output, typed_line('system certificate local', 'CERT7', 'future-key-type',
                                            '<UNVERIFIED:unclassified-field>'))
        self.assert_typed7_visible(output)


OBJECT_VIEWS = (
    ('load-balance virtual-server', 'VS_APP', '    set port 443\n    set load-balance-pool POOL_APP\n'),
    ('load-balance pool', 'POOL_APP', '    set health-check-list HC_APP\n    config pool_member\n      edit 1\n        set real-server RS_APP\n      next\n    end\n'),
    ('system health-check', 'HC_APP', '    set type https\n    set port 443\n    set password OBJECT-SECRET-FIXTURE\n    set secret-key OBJECT-KEY-FIXTURE\n'),
    ('security waf profile', 'WAF_APP', '    set web-attack-signature WAS_APP\n    set description "Application WAF"\n'),
    ('system certificate local_cert_group', 'CERT_GROUP_APP', '    config group_member\n      edit 1\n        set default enable\n        set intermediate-ca-group CA_APP\n        set local-cert CERT_APP\n      next\n    end\n'),
)


TLS_FAMILY = 'load-balance client-ssl-profile'
TLS_GET_FIELDS = (
    ('ssl-allowed-versions', 'tlsv1.2 tlsv1.3'),
    ('ssl-session-cache-flag', 'enable'),
    ('ssl-auto-chain-flag', 'enable'),
    ('use-tls-tickets', 'enable'),
    ('ssl-customize-ciphers-flag', 'disable'),
    ('ssl-ciphers', 'ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES256-SHA384 ECDHE-ECDSA-AES256-SHA ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES128-SHA256 ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-RSA-AES256-SHA DHE-RSA-AES256-GCM-SHA384 DHE-RSA-AES256-SHA256 DHE-RSA-AES256-SHA AES256-GCM-SHA384 AES256-SHA256 AES256-SHA ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-SHA256 DHE-RSA-AES128-GCM-SHA256 DHE-RSA-AES128-SHA256 DHE-RSA-AES128-SHA AES128-GCM-SHA256 AES128-SHA256 AES128-SHA'),
    ('rfc7919-comply', 'disable'),
    ('ssl-ciphers-tlsv13', 'TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256'),
    ('ssl-dh-param-size', '2048bit'),
    ('ssl-dynamic-record-sizing', 'disable'),
    ('forward-proxy', 'disable'),
    ('local-certificate-group', 'CERT_GROUP_APP'),
    ('client-sni-required', 'disable'),
    ('reject-ocsp-stapling-with-missing-nextupdate', 'disable'),
    ('reject-revoked-unknown-ocsp-stapling', 'enable'),
    ('ocsp-stapling-skew-time', '0'),
    ('client-certificate-verify', 'VERIFY_APP'),
    ('renegotiation', 'disable'),
)
TLS_GET_BODY = ''.join(key + ' : ' + value + '\n' for key, value in TLS_GET_FIELDS)
TLS_GET_VIEW = (TLS_FAMILY, 'TLS_APP', TLS_GET_BODY)


class FortiADCObjectConfiguration(TestCase):
    def setUp(self):
        c._SNAPSHOTS.clear()
        c._DIFFS.clear()
        self.addCleanup(c._SNAPSHOTS.clear)
        self.addCleanup(c._DIFFS.clear)
        self.auth = replace(enrolled(), ssh_platform='fortiadc', login='netops-read')

    def wire(self, section, raw, include_defaults=False):
        def read(auth, platform, command, **kwargs):
            self.assertEqual(platform, 'fortiadc')
            if command == 'get system status':
                return 0, STATUS
            prefix = 'get ' if section.startswith(TLS_FAMILY + ' ') else ('show full-configuration ' if include_defaults else 'show ')
            self.assertEqual(command, prefix + section)
            payload = raw.encode() if section.startswith(TLS_FAMILY + ' ') else live(raw).encode()
            if section.startswith(TLS_FAMILY + ' '):
                middle = len(payload) // 2
                payload = payload[:middle] + b'--More-- \r  \r' + payload[middle:]
                for start in range(0, len(payload), 11):
                    kwargs['stdout_consumer'](payload[start:start + 11])
            else:
                kwargs['stdout_consumer'](payload)
            return 0, ''
        return read

    def test_planned_object_views_share_semantic_redaction_pages_and_scope(self):
        for family, name, body in OBJECT_VIEWS + (TLS_GET_VIEW,):
            defaults = (False, True) if family in ('security waf profile', 'system certificate local_cert_group') else (False,)
            for include_defaults in defaults:
                with self.subTest(family=family, include_defaults=include_defaults):
                    section = family + ' ' + name
                    raw = 'config ' + family + '\n  edit ' + name + '\n' + body + '  next\nend\n'
                    if family == TLS_FAMILY:
                        raw = 'SYNTH-ADC-12 # ' + body + 'SYNTH-ADC-12 # '
                    prefix = 'get ' if family == TLS_FAMILY else ('show full-configuration ' if include_defaults else 'show ')
                    with mock.patch.object(engine, 'record'), mock.patch.object(
                            engine, 'read_from_device', side_effect=self.wire(section, raw, include_defaults)) as read:
                        result = engine.config_read(self.auth, 'fortiadc', section, redaction='full', limit=40, include_defaults=include_defaults)
                    self.assertEqual([call.args[2] for call in read.call_args_list],
                                     ['get system status', prefix + section])
                    self.assertTrue(result['capture_complete'])
                    self.assertEqual(result['include_defaults'], include_defaults)
                    self.assertFalse(result['configuration_complete'])
                    self.assertEqual(result['config_scope'], 'device-account-visible')
                    self.assertEqual(result['section'], section)
                    self.assertEqual(result['visibility_limitations'],
                                     ['access-profile-unverified', 'vdom-unverified', 'requested-section-only'])
                    self.assertEqual(result['unverified_count'], 0)
                    if family == TLS_FAMILY:
                        self.assertTrue(result['normalized_from_get'])
                        self.assertEqual(result['command'], 'get ' + section)
                    pages = [result['untrusted_device_output']]
                    current = result
                    with mock.patch.object(engine, 'record'), mock.patch.object(
                            engine, 'read_from_device', side_effect=AssertionError('cached page must not SSH')):
                        while current['next_offset'] is not None:
                            current = engine.config_read(
                                self.auth, 'fortiadc', section, redaction='full', limit=40, include_defaults=include_defaults,
                                snapshot_id=result['snapshot_id'], offset=current['next_offset'])
                            pages.append(current['untrusted_device_output'])
                            if family == TLS_FAMILY:
                                self.assertTrue(current['normalized_from_get'])
                        with self.assertRaises(ValueError):
                            engine.config_read(self.auth, 'fortiadc', family + ' OTHER',
                                               redaction='full', include_defaults=include_defaults, snapshot_id=result['snapshot_id'])
                    output = ''.join(pages)
                    self.assertIn('config ' + family + '\n', output)
                    self.assertIn('edit ' + name + '\n', output)
                    self.assertNotIn('OBJECT-SECRET-FIXTURE', output)
                    self.assertNotIn('OBJECT-KEY-FIXTURE', output)
                    self.assertEqual(result['credential_redactions'], 2 if family == 'system health-check' else 0)
                    if family == TLS_FAMILY:
                        for key, value in TLS_GET_FIELDS:
                            self.assertIn('set ' + key + ' ', output)
                            self.assertIn(value, output)
                    if family == 'load-balance pool':
                        self.assertIn('set real-server RS_APP\n', output)
                    if family == 'system certificate local_cert_group':
                        self.assertIn('config group_member\n', output)
                        for reference in ('set default enable\n', 'set intermediate-ca-group CA_APP\n',
                                          'set local-cert CERT_APP\n'):
                            self.assertIn(reference, output)

    def test_object_view_refuses_unplanned_or_untyped_commands_before_ssh(self):
        invalid = ('load-balance virtual-server', 'load-balance virtual-server bad name',
                   'load-balance virtual-server ../bad', 'load-balance virtual-server A;show',
                   'load-balance virtual-server ' + 'A' * 36,
                   'system certificate local_cert_group', 'load-balance client-ssl-profile bad name', 'system admin admin')
        with mock.patch.object(engine, 'record'), mock.patch.object(engine, 'read_from_device') as read:
            for section in invalid:
                with self.subTest(section=section), self.assertRaises(ValueError):
                    engine.config_read(self.auth, 'fortiadc', section, redaction='full')
            for options in ({'include_all': True}, {'include_defaults': True}, {'redaction': 'minimal'}):
                with self.subTest(options=options), self.assertRaises(ValueError):
                    engine.config_read(self.auth, 'fortiadc', TLS_FAMILY + ' TLS_APP',
                                       **({'redaction': 'full'} | options))
            with self.assertRaises(ValueError):
                engine.config_read(replace(self.auth, read_inventory={'config_access': ()}),
                                   'fortiadc', TLS_FAMILY + ' TLS_APP', redaction='full')
            with self.assertRaises(ValueError):
                engine.config_read(self.auth, 'fortiadc', 'load-balance pool POOL_APP',
                                   redaction='full', include_defaults=1)
            read.assert_not_called()

    def test_object_view_refuses_wrong_or_missing_objects_without_cache(self):
        for family, name, body in OBJECT_VIEWS:
            valid = 'config ' + family + '\n  edit ' + name + '\n' + body + '  next\nend\n'
            cases = (
                valid.replace('edit ' + name + '\n', 'edit OTHER\n', 1),
                'config ' + family + '\nend\n',
            )
            for raw in cases:
                with self.subTest(family=family, raw=raw), mock.patch.object(engine, 'record'), mock.patch.object(
                        engine, 'read_from_device', side_effect=self.wire(family + ' ' + name, raw)):
                    with self.assertRaises(ValueError):
                        engine.config_read(self.auth, 'fortiadc', family + ' ' + name, redaction='full')
                    self.assertFalse(c._SNAPSHOTS)

        section = TLS_FAMILY + ' TLS_APP'
        for raw in ('', 'ssl-ciphers invalid-without-colon\n',
                    'Command fail. Return code is -1 ((null))\n'):
            with self.subTest(tls_refused=raw), mock.patch.object(engine, 'record'), mock.patch.object(
                    engine, 'read_from_device', side_effect=self.wire(section, raw)):
                with self.assertRaises(ValueError):
                    engine.config_read(self.auth, 'fortiadc', section, redaction='full')
                self.assertFalse(c._SNAPSHOTS)


ACCESS_REFUSAL = ("Parsing error at 'health-check'. err=1\n"
                  'Command fail. Return code is -284 (CLI parsing error.)\n\n')


class FortiADCObjectAccessRefusal(TestCase):
    SECTION = 'system health-check HC_APP'
    setUp = FortiADCObjectConfiguration.setUp
    wire = FortiADCObjectConfiguration.wire

    def read(self, raw):
        with mock.patch.object(engine, 'record'), mock.patch.object(
                engine, 'read_from_device', side_effect=self.wire(self.SECTION, raw)):
            with self.assertRaises(ValueError) as caught:
                engine.config_read(self.auth, 'fortiadc', self.SECTION, redaction='full')
        self.assertFalse(c._SNAPSHOTS)
        return str(caught.exception)

    def test_access_profile_refusal_is_reported_as_device_refusal(self):
        message = self.read(ACCESS_REFUSAL)
        self.assertEqual(message, 'configuration device-refused during capture; output withheld')

    def test_secret_after_refusal_or_without_it_stays_withheld(self):
        cases = (
            ACCESS_REFUSAL + '    set password OBJECT-SECRET-FIXTURE\n',
            ACCESS_REFUSAL.replace('\n\n', '\nset secret-key OBJECT-KEY-FIXTURE\n'),
            '    set password OBJECT-SECRET-FIXTURE\n' + ACCESS_REFUSAL,
            "Parsing error at 'OBJECT-SECRET-FIXTURE x'. err=1\n",
            'config system health-check\n  edit HC_APP\n' + ACCESS_REFUSAL +
            '    set password OBJECT-SECRET-FIXTURE\n  next\nend\n',
        )
        for raw in cases:
            with self.subTest(raw=raw):
                message = self.read(raw)
                self.assertIn('redaction-unverifiable', message)
                self.assertNotIn('refused', message)
                self.assertNotIn('OBJECT-SECRET-FIXTURE', message)
                self.assertNotIn('OBJECT-KEY-FIXTURE', message)
