from unittest import TestCase

from netops_helper import configuration as c
from netops_helper import config_fortios as f


FW = ('FortiGate-60F', '7.6.8', '3744')


def render(raw, firmware=FW, size=7):
    stream = c.StreamRedactor((), 'all', policy=f.policy_for(firmware))
    try:
        encoded = raw.encode()
        for index in range(0, len(encoded), size):
            stream.feed(encoded[index:index + size])
        text, hidden, count = stream.finish()
        return text.page(0, text.total)[0], hidden, count
    finally:
        stream.close()


class FortiOSFullConfiguration(TestCase):
    def test_real_reference_policy_retains_network_values_and_hides_credentials(self):
        raw = ('config system interface\n edit "wan1"\n set ip 192.0.2.1 255.255.255.0\n'
               ' set allowaccess ping https ssh\n set status up\n set password "PRIVATE-PASSWORD"\n'
               ' set pin 123456\n set unknown "PRIVATE-UNKNOWN"\n next\nend\n'
               'config vpn ipsec phase1-interface\n edit tunnel-1\n set interface wan1\n'
               ' set remote-gw 198.51.100.4\n set psksecret "PRIVATE-PSK"\nnext\nend\n')
        for firmware in (FW, ('FortiGate-VM64', '8.0.2', '0251')):
            with self.subTest(firmware=firmware):
                visible, hidden, count = render(raw, firmware, 1)
                for expected in ('edit wan1', 'set ip 192.0.2.1 255.255.255.0',
                                 'set allowaccess ping https ssh', 'set status up',
                                 'set interface wan1', 'set remote-gw 198.51.100.4'):
                    self.assertIn(expected, visible)
                self.assertNotIn('PRIVATE-', visible)
                self.assertNotIn('123456', visible)
                self.assertEqual((len(hidden), count), (0, 4))

    def test_reference_mixed_case_underscore_digits_and_plus_are_diagnostic_fields(self):
        raw = ('config alertemail setting\n set FIPS-CC-errors enable\nend\n'
               'config wireless-controller wids-profile\n edit detect\n set block_ack-flood enable\nnext\nend\n'
               'config icap profile\n edit scan\n set 204-response enable\nnext\nend\n'
               'config user tacacs+\n edit tacacs-1\n set server 192.0.2.9\nnext\nend\n'
               'config system global\n set adminPassword PRIVATE-MIXEDCASE\nend\n')
        visible, hidden, count = render(raw)
        for expected in ('set FIPS-CC-errors enable', 'set block_ack-flood enable',
                         'set 204-response enable', 'config user tacacs+'):
            self.assertIn(expected, visible)
        self.assertNotIn('PRIVATE-MIXEDCASE', visible)
        self.assertEqual(len(hidden), 0)
        minimal, _, _ = c.redact(raw, (), 'all')
        self.assertNotIn('PRIVATE-MIXEDCASE', minimal.page(0, minimal.total)[0])

    def test_wrapped_global_and_vdom_keep_values_in_the_same_exact_context(self):
        raw = ('config global\n config system global\n set hostname gateway\nend\nend\n'
               'config vdom\n edit tenant-a\n config firewall address\n edit backend\n'
               ' set subnet 192.0.2.0 255.255.255.0\nnext\nend\nnext\nend\n')
        visible, hidden, count = render(raw, size=1)
        for expected in ('set hostname gateway', 'edit tenant-a', 'edit backend',
                         'set subnet 192.0.2.0 255.255.255.0'):
            self.assertIn(expected, visible)
        self.assertEqual((len(hidden), count), (0, 0))

    def test_firmware_defaults_and_identity_scope_are_explicit(self):
        status = 'Version: FortiGate-60F v7.6.8,build3744,260929 (GA.M)\nVirtual domain configuration: disable\n'
        firmware, metadata = f.verify_identity(status)
        self.assertEqual(firmware, FW)
        self.assertTrue(metadata['identity_scope_verified'])
        self.assertFalse(metadata['configuration_complete'])
        for invalid in (status.replace('3744', '3745'), status.replace('7.6.8', '7.6.7'),
                        status + status, status.replace('FortiGate-', 'FortiADC-')):
            with self.subTest(status=invalid[:60]), self.assertRaises(ValueError):
                f.verify_identity(invalid)
        _, metadata = f.verify_identity(status.replace('disable', 'enable'))
        self.assertFalse(metadata['identity_scope_verified'])
        self.assertIn('vdom-coverage-not-verified', metadata['visibility_limitations'])
        self.assertEqual(f.read_command('all', True, False), 'show')
        self.assertEqual(f.read_command('all', True, True), 'show full-configuration')
        self.assertEqual(f.read_command('system interface', False, True), 'show full-configuration system interface')
        for arguments in (('all', False, False), ('all', True, 1), ('all;execute', True, True)):
            with self.assertRaises(ValueError):
                f.read_command(*arguments)

    def test_vlan_mapping_sections_use_semantic_full_reads(self):
        for section in ('switch-controller managed-switch', 'wireless-controller vap'):
            self.assertEqual(f.read_command(section, False, False), 'show ' + section)
            with self.assertRaises(ValueError):
                f.read_command(section, True, False)
        raw = ('config system interface\n edit client-net\n set vlanid 100\nnext\nend\n'
               'config switch-controller managed-switch\n edit S224EPTF25000000\n'
               ' config ports\n edit port3\n set vlan client-net\n'
               ' set allowed-vlans guest-net\n set untagged-vlans client-net\nnext\nend\nnext\nend\n'
               'config wireless-controller vap\n edit staff-wifi\n set ssid staff-wifi\n'
               ' set vlanid 100\n set local-bridging disable\n'
               ' set passphrase PRIVATE-WIFI-PSK\nnext\nend\n')
        visible, hidden, count = render(raw)
        for expected in ('edit client-net', 'set vlanid 100', 'edit port3',
                         'set vlan client-net', 'set allowed-vlans guest-net',
                         'set untagged-vlans client-net', 'set ssid staff-wifi',
                         'set local-bridging disable'):
            self.assertIn(expected, visible)
        self.assertNotIn('PRIVATE-WIFI-PSK', visible)
        self.assertEqual((len(hidden), count), (0, 1))

    def _wrapped(self, raw, wrapper):
        if wrapper == 'global':
            return 'config global\n' + raw + 'end\n'
        if wrapper == 'vdom':
            return 'config vdom\n edit tenant-a\n' + raw + 'next\nend\n'
        return raw

    def _community(self, context, value):
        return (''.join('config ' + part + '\n edit 1\n' for part in context) +
                ' set name ' + value + '\n' + 'next\nend\n' * len(context))

    def test_snmp_community_values_are_credentials_in_every_documented_context(self):
        contexts = (('system snmp community',), ('switch-controller snmp-community',),
                    ('switch-controller managed-switch', 'snmp-community'),
                    ('wireless-controller snmp', 'community'))
        for firmware in (FW, ('FortiGate-VM64', '8.0.2', '0251')):
            for wrapper in ('root', 'global', 'vdom'):
                for context in contexts:
                    with self.subTest(firmware=firmware, wrapper=wrapper, context=context):
                        raw = self._wrapped(self._community(context, 'PRIVATE-COMMUNITY'), wrapper)
                        visible, hidden, count = render(raw, firmware, 1)
                        self.assertNotIn('PRIVATE-COMMUNITY', visible)
                        self.assertIn('set name <REDACTED:credential#1>', visible)
                        self.assertEqual(len(hidden), 0)

    def test_credential_semantics_override_explicit_public_community_map(self):
        contexts = (('system snmp community',), ('switch-controller snmp-community',),
                    ('switch-controller managed-switch', 'snmp-community'),
                    ('wireless-controller snmp', 'community'))
        for wrapper in ('root', 'global', 'vdom'):
            prefix = () if wrapper == 'root' else (wrapper,)
            for context in contexts:
                with self.subTest(wrapper=wrapper, context=context):
                    selected = c.FullConfigPolicy('fortios',
                        public_fields=frozenset(((prefix + context, 'name'),)), allow_vdom=True)
                    raw = self._wrapped(self._community(context, 'PRIVATE-COMMUNITY'), wrapper)
                    content, hidden, count = c.redact(raw, (), 'all', policy=selected)
                    visible = content.page(0, content.total)[0]
                    self.assertNotIn('PRIVATE-COMMUNITY', visible)
                    self.assertIn('set name <REDACTED:credential#1>', visible)

    def test_guest_identity_recipient_and_all_faz_serial_contexts_remain_visible(self):
        serial_sections = ('log fortianalyzer override-setting', 'log fortianalyzer setting',
            'log fortianalyzer-cloud setting', 'log fortianalyzer2 override-setting',
            'log fortianalyzer2 setting', 'log fortianalyzer3 override-setting',
            'log fortianalyzer3 setting')
        raw = ('config user group\n edit guests\n config guest\n'
               ' edit guest-person@example.test\n set name "PRIVATE-GUEST"\nnext\nend\nnext\nend\n'
               'config system automation-action\n edit notify\n'
               ' set email-to recipient-person@example.test\nnext\nend\n')
        raw += ''.join('config ' + section + '\n set serial PRIVATE-FAZ-SERIAL\nend\n'
                       for section in serial_sections)
        for firmware in (FW, ('FortiGate-VM64', '8.0.2', '0251')):
            for wrapper in ('root', 'global', 'vdom'):
                with self.subTest(firmware=firmware, wrapper=wrapper):
                    visible, hidden, count = render(self._wrapped(raw, wrapper), firmware)
                    for marker in ('PRIVATE-GUEST', 'guest-person@example.test',
                                   'recipient-person@example.test', 'PRIVATE-FAZ-SERIAL'):
                        self.assertIn(marker, visible)
                    self.assertEqual(len(hidden), 0)

    def test_identity_rejects_hidden_or_mixed_case_second_version(self):
        status = 'Version: FortiGate-60F v7.6.8,build3744\nVirtual domain configuration: disable\n'
        for prefix in (' version:', 'version:', '\tVERSION:', ' Version:'):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                f.verify_identity(status + prefix + ' FortiGate-VM64 v8.0.2,build0251\n')

    def test_reference_distinguishes_credential_values_from_key_references(self):
        raw=('config firewall ssh setting\n set hostkey-rsa2048 ssh-certificate\nend\n'
             'config authentication scheme\n edit auth\n set kerberos-keytab keytab-object\nnext\nend\n'
             'config system interface\n edit wifi\n config wifi-networks\n edit 1\n set wifi-private-key certificate-object\nnext\nend\nnext\nend\n'
             'config router route-map\n edit policy\n config rule\n edit 1\n set set-community 65000:10\nnext\nend\nnext\nend\n'
             'config user group\n edit guests\n set password auto-generate\nnext\nend\n')
        for firmware in (FW,('FortiGate-VM64','8.0.2','0251')):
            visible,hidden,count=render(raw,firmware)
            for value in ('ssh-certificate','keytab-object','certificate-object','65000:10','auto-generate'):
                self.assertIn(value,visible)
            self.assertNotIn('<UNVERIFIED:',visible);self.assertEqual(count,0)

    def test_exact_credential_maps_cover_reference_types_and_manual_binary_secrets(self):
        rows=((('system admin',),'password'),(('system snmp user',),'auth-pwd'),
              (('system snmp user',),'priv-pwd'),(('certificate local',),'private-key'),
              (('system acme','accounts'),'privatekey'),
              (('firewall profile-protocol-options','cifs','server-keytab'),'keytab'),
              (('user fortitoken',),'seed'),(('user krb-keytab',),'keytab'),
              (('system sdn-connector',),'secret-token'),(('system modem',),'pin-init'))
        for firmware in (FW,('FortiGate-VM64','8.0.2','0251')):
            selected=f.policy_for(firmware)
            for path,field in rows:
                self.assertIn((path,field),selected.secret_fields)
                self.assertNotIn((path,field),selected.public_fields)
                raw=''.join('config '+part+'\n' for part in path)+' set '+field+' fixture-credential-material\n'+'end\n'*len(path)
                visible,hidden,count=render(raw,firmware)
                self.assertNotIn('fixture-credential-material',visible)
                self.assertIn('<REDACTED:credential#1>',visible)
                self.assertEqual((len(hidden),count),(0,1))
            self.assertFalse(selected.opaque_sections)

    def test_known_unsupported_payload_is_explicitly_unverified_not_secret(self):
        for firmware in (FW,('FortiGate-VM64','8.0.2','0251')):
            raw='config system auto-script\n edit diagnose\n set start manual\n set script "fixture-unknown-operation argument"\nnext\nend\n'
            visible,hidden,count=render(raw,firmware)
            self.assertIn('edit diagnose',visible);self.assertIn('set start manual',visible)
            self.assertIn('set script <UNVERIFIED:',visible);self.assertNotIn('<REDACTED:',visible)

    def test_exact_named_redistribute_and_http_09_fields_are_verified_on_7_6_8(self):
        routes = {'router bgp': (('redistribute', 'redistribute6'), ('connected', 'isis', 'ospf', 'rip', 'static'),
                                 ('route-map', 'status')),
                  'router isis': (('redistribute', 'redistribute6'), ('bgp', 'connected', 'ospf', 'rip', 'static'),
                                  ('level', 'metric', 'metric-type', 'routemap', 'status')),
                  'router ospf': (('redistribute',), ('bgp', 'connected', 'isis', 'rip', 'static'),
                                  ('metric', 'metric-type', 'routemap', 'status', 'tag')),
                  'router ospf6': (('redistribute',), ('bgp', 'connected', 'isis', 'rip', 'static'),
                                   ('metric', 'metric-type', 'routemap', 'status')),
                  'router rip': (('redistribute',), ('bgp', 'connected', 'isis', 'ospf', 'static'),
                                 ('metric', 'routemap', 'status')),
                  'router ripng': (('redistribute',), ('bgp', 'connected', 'isis', 'ospf', 'static'),
                                   ('metric', 'routemap', 'status'))}
        raw, expected = '', ['set http-0.9 allow']
        for router, (sections, protocols, fields) in routes.items():
            raw += 'config %s\n' % router
            for section in sections:
                for protocol in protocols:
                    raw += ' config %s "%s"\n' % (section, protocol)
                    raw += ''.join('  set %s value-%d\n' % (field, len(expected) + i) for i, field in enumerate(fields))
                    expected += ['set %s value-%d' % (field, len(expected) + i) for i, field in enumerate(fields)]
                    raw += ' end\n'
            raw += 'end\n'
        raw += 'config firewall profile-protocol-options\n edit default\n config http\n set http-0.9 allow\n end\nnext\nend\n'
        self.assertEqual(len(expected), 146)
        visible, hidden, count = render(raw)
        for line in expected:
            self.assertIn(line, visible)
        self.assertNotIn('<UNVERIFIED:', visible)
        self.assertEqual((len(hidden), count), (0, 0))
        for near in (' config redistribute "zz"\n  set status enable\n end\n',
                     ' config redistribute "BGP"\n  set status enable\n end\n',
                     ' config redistribute "connected"\n  set route-map-evpn enable\n end\n'):
            with self.subTest(near=near):
                visible, hidden, count = render('config router bgp\n' + near + 'end\n')
                self.assertIn('<UNVERIFIED:', visible)
        visible, hidden, count = render('config firewall profile-protocol-options\n edit default\n config http\n'
                                        ' set http-0 allow\n end\nnext\nend\n')
        self.assertIn('<UNVERIFIED:', visible)

    def test_named_rule_iotd_header_keeps_unicode_name_in_canonical_context(self):
        body = (' set behavior value-1\n set category value-2\n set id 3\n set popularity 4\n set protocol value-5\n'
                ' set risk 6\n set technology value-7\n set vendor value-8\n set weight 9\n'
                ' config metadata\n edit 1\n set metaid 10\n set valueid 11\nnext\n end\n'
                ' config parameters\n edit param-a\n set default value-12\nnext\n end\nend\n')
        fields = ('set behavior value-1', 'set category value-2', 'set id 3', 'set popularity 4',
                  'set protocol value-5', 'set risk 6', 'set technology value-7', 'set vendor value-8',
                  'set weight 9', 'edit 1', 'set metaid 10', 'set valueid 11', 'edit param-a', 'set default value-12')
        names = (('Camera-Čam_(1).x', 'config rule iotd "Camera-\\u010cam_(1).x"'),
                 ('Cam-A1', 'config rule iotd Cam-A1'),
                 ('A' * 62 + 'Ž', 'config rule iotd "' + 'A' * 62 + '\\u017d"'))
        for firmware in (FW, ('FortiGate-VM64', '8.0.2', '0251')):
            for name, header in names:
                for wrap in (('', ''), ('config global\n', 'end\n')):
                    with self.subTest(firmware=firmware, name=name, wrap=wrap):
                        raw = wrap[0] + 'config rule iotd "%s"\n' % name + body + wrap[1]
                        visible, hidden, count = render(raw, firmware, 1)
                        self.assertIn(header, visible)
                        for line in fields:
                            self.assertIn(line, visible)
                        self.assertNotIn('<UNVERIFIED:', visible)
                        self.assertEqual((len(hidden), count), (0, 0))

    def test_named_rule_iotd_rejects_other_families_shapes_and_characters(self):
        for raw in ('config rule otdt "Camera-Čam"\n set id 1\nend\n',
                    'config rule iotd "Camera:Čam"\n set id 1\nend\n',
                    'config rule iotd "Camera Čam"\n set id 1\nend\n',
                    'config rule iotd "Camera\tČam"\n set id 1\nend\n',
                    'config rule iotd "Camera​Čam"\n set id 1\nend\n',
                    'config rule iotd "Camera-Čam" extra\n set id 1\nend\n',
                    'config rule iotd Cam-A1 extra\n set id 1\nend\n',
                    'config rule iotd "' + 'A' * 63 + 'Ž"\n set id 1\nend\n',
                    'config rule iotd "-CameraČam"\n set id 1\nend\n',
                    'config rule iotd ""\n set id 1\nend\n',
                    'config system global\n config rule iotd "Camera-Čam"\n set id 1\n end\nend\n',
                    'config system global\n config rule iotd Cam-A1\n set id 1\n end\nend\n'):
            for firmware in (FW, ('FortiGate-VM64', '8.0.2', '0251')):
                with self.subTest(raw=raw, firmware=firmware):
                    with self.assertRaises(ValueError) as caught:
                        render(raw, firmware, 1)
                    error = str(caught.exception) + repr(getattr(caught.exception, 'context', ()))
                    self.assertNotIn('Camera', error)
                    self.assertNotIn('Cam-A1', error)

    def test_named_rule_iotd_secret_name_and_scope_stay_guarded(self):
        stream = c.StreamRedactor(('SecretČ',), 'all', policy=f.policy_for(FW))
        try:
            stream.feed('config rule iotd "Camera-SecretČ"\n set id 1\nend\n'.encode())
            text, hidden, count = stream.finish()
            visible = text.page(0, text.total)[0]
        finally:
            stream.close()
        self.assertIn('config rule iotd <REDACTED:credential#1>', visible)
        self.assertIn('set id 1', visible)
        self.assertNotIn('Secret', visible + visible.encode().decode('unicode_escape'))
        self.assertEqual(count, 1)
        stream = c.StreamRedactor((), 'rule iotd', policy=f.policy_for(FW))
        try:
            stream.feed('config rule iotd "Camera-Čam"\n set id 1\nend\n'.encode())
            text = stream.finish()[0]
            self.assertIn('set id 1', text.page(0, text.total)[0])
        finally:
            stream.close()
        stream = c.StreamRedactor((), 'system global', policy=f.policy_for(FW))
        try:
            with self.assertRaises(ValueError):
                stream.feed('config rule iotd "Camera-Čam"\n set id 1\nend\n'.encode())
                stream.finish()
        finally:
            stream.close()

    def test_exact_live_replacemsg_redistribute_waf_and_http_09_fields_are_verified_on_8_0_2(self):
        firmware = ('FortiGate-VM64', '8.0.2', '0251')
        replacemsg = {
            'admin': ('post_admin-disclaimer-text', 'pre_admin-disclaimer-text'),
            'alertmail': ('alertmail-block', 'alertmail-crit-event', 'alertmail-disk-full', 'alertmail-nids-event', 'alertmail-virus'),
            'auth': ('auth-block-notification-page', 'auth-cert-passwd-page', 'auth-challenge-page', 'auth-disclaimer-page-1', 'auth-disclaimer-page-2', 'auth-disclaimer-page-3', 'auth-email-failed-page', 'auth-email-harvesting-page', 'auth-email-token-page', 'auth-fortitoken-page', 'auth-guest-email-page', 'auth-guest-print-page', 'auth-keepalive-page', 'auth-login-failed-page', 'auth-login-page', 'auth-next-fortitoken-page', 'auth-password-page', 'auth-portal-page', 'auth-proxy-reject-page', 'auth-qtn-reject-page', 'auth-quarantine-page', 'auth-reject-page', 'auth-saml-page', 'auth-sms-token-page', 'auth-success-msg', 'auth-success-page', 'auth-token-login-failed-page', 'auth-token-login-page'),
            'automation': ('automation-email',),
            'fortiguard-wf': ('ftgd-block', 'ftgd-ovrd', 'ftgd-quota', 'ftgd-warning'),
            'ftp': ('ftp-explicit-banner',),
            'http': ('http-antiphish-block', 'http-contenttypeblock', 'https-blocklisted-cert-block', 'https-clt-blocklist-block', 'https-ech-block', 'https-invalid-cert-block', 'https-untrusted-cert-block', 'infcache-block', 'switching-protocols-block', 'url-block', 'urlfilter-err', 'videofilter-block', 'videofilter-block-text'),
            'icap': ('icap-req-resp',),
            'mail': ('partial',),
            'nac-quar': ('nac-quar-admin', 'nac-quar-app', 'nac-quar-dlp', 'nac-quar-dos', 'nac-quar-ips', 'nac-quar-virus'),
            'spam': ('ipblocklist', 'reversedns', 'smtp-spam-ase', 'smtp-spam-dnsbl', 'smtp-spam-emailblock-from', 'smtp-spam-emailblock-subject', 'smtp-spam-emailblock-to', 'smtp-spam-feip', 'smtp-spam-helo', 'smtp-spam-mimeheader', 'submit'),
            'sslvpn': ('sslvpn-header', 'sslvpn-limit', 'sslvpn-login'),
            'traffic-quota': ('per-ip-shaper-block',),
            'utm': ('appblk-html', 'archive-block-html', 'archive-block-text', 'banned-word-html', 'banned-word-text', 'block-html', 'block-text', 'client-file-size-html', 'client-virus-html', 'decompress-limit-text', 'dlp-html', 'dlp-subject-text', 'dlp-text', 'ems-threat-feed-html', 'ems-threat-feed-text', 'exe-text', 'external-blocklist-html', 'external-blocklist-text', 'file-av-fail-text', 'file-filter-html', 'file-filter-text', 'file-filter-warn-html', 'file-size-html', 'file-size-text', 'fortidata-query-error-html', 'fortidata-query-error-text', 'icap-block-text', 'icap-error-text', 'icap-http-error', 'imagefilter-block-html', 'imagefilter-error-html', 'inline-scan-error-html', 'inline-scan-error-text', 'inline-scan-timeout-html', 'inline-scan-timeout-text', 'internal-error-text', 'ipsblk-html', 'ipsfail-html', 'malware-stream-html', 'malware-stream-text', 'outbreak-prevention-er-html', 'outbreak-prevention-er-text', 'outbreak-prevention-html', 'outbreak-prevention-text', 'outbreak-prevention-to-html', 'outbreak-prevention-to-text', 'transfer-av-fail-text', 'transfer-size-text', 'virpatchblk-html', 'virus-html', 'virus-text', 'waf-html'),
            'webproxy': ('auth-challenge', 'auth-group-info-fail', 'auth-ip-blackout', 'auth-login-fail', 'auth-logout', 'auth-method-unsupported', 'auth-oidc-landing-page', 'auth-proxy-login-page', 'casb-block', 'deny', 'http-err', 'swp-empty-cert', 'swp-invalid-cert', 'swp-manageable-empty-cert', 'user-limit', 'ztna-auth-challenge', 'ztna-auth-fail', 'ztna-cant-find-real-srv', 'ztna-client-cert-revoked', 'ztna-conn-dns-err', 'ztna-conn-err', 'ztna-denied-by-matched-tags', 'ztna-denied-no-matched-tags', 'ztna-dev-is-offline', 'ztna-dev-is-unmanageable', 'ztna-empty-cert', 'ztna-fqdn-dns-failed', 'ztna-invalid-cert', 'ztna-manageable-empty-cert', 'ztna-matched-deny-policy', 'ztna-no-api-gwy-matched', 'ztna-no-dev-info', 'ztna-no-policy-matched', 'ztna-ssl-bookmark-failed'),
        }
        routes = {'router bgp': ((('redistribute',), ('route-map', 'route-map-evpn', 'status', 'status-evpn')),
                                (('redistribute6',), ('route-map', 'status'))),
                  'router isis': ((('redistribute', 'redistribute6'), ('level', 'metric', 'metric-type', 'routemap', 'status')),),
                  'router ospf': ((('redistribute',), ('metric', 'metric-type', 'routemap', 'status', 'tag')),),
                  'router ospf6': ((('redistribute',), ('metric', 'metric-type', 'routemap', 'status')),),
                  'router rip': ((('redistribute',), ('metric', 'routemap', 'status')),),
                  'router ripng': ((('redistribute',), ('metric', 'routemap', 'status')),)}
        protocols = ('bgp', 'connected', 'isis', 'ospf', 'rip', 'static')
        main_classes = (20000000, 30000000, 40000000, 50000000, 60000000, 70000000, 80000000, 90000000, 100000000, 110000000)
        raw, expected = '', []
        for group, kinds in replacemsg.items():
            for kind in kinds:
                raw += 'config system replacemsg %s "%s"\n' % (group, kind)
                block = ['set buffer "<p>blok %d</p>"' % len(expected), 'set header http', 'set format html']
                raw += ''.join('    %s\n' % line for line in block) + 'end\n'
                expected += block
        for router, groups in routes.items():
            raw += 'config %s\n' % router
            for sections, fields in groups:
                for section in sections:
                    for protocol in protocols:
                        if protocol == router.split()[1].rstrip('6').replace('ripng', 'rip'):
                            continue
                        raw += ' config %s "%s"\n' % (section, protocol)
                        block = ['set %s value-%d' % (field, len(expected) + i) for i, field in enumerate(fields)]
                        raw += ''.join('  %s\n' % line for line in block) + ' end\n'
                        expected += block
            raw += 'end\n'
        raw += 'config waf profile\n edit "default"\n  config signature\n'
        for main_class in main_classes:
            raw += '   config main-class %d\n' % main_class
            block = ['set action block', 'set log enable', 'set severity high', 'set status enable']
            raw += ''.join('    %s\n' % line for line in block) + '   end\n'
            expected += block
        raw += '  end\n next\nend\n'
        raw += 'config firewall profile-protocol-options\n edit default\n config http\n set http-0.9 allow\n end\nnext\nend\n'
        expected.append('set http-0.9 allow')
        self.assertEqual((sum(map(len, replacemsg.values())), len(expected)), (163, 489 + 155 + 40 + 1))
        visible, hidden, count = render(raw, firmware)
        for line in expected:
            self.assertIn(line, visible)
        self.assertNotIn('<UNVERIFIED:', visible)
        self.assertEqual((len(hidden), count), (0, 0))
        for near in ('config system replacemsg admin "zz-type"\n set buffer "x"\nend\n',
                     'config system replacemsg alertmail "pre_admin-disclaimer-text"\n set buffer "x"\nend\n',
                     'config system replacemsg admin "pre_admin-disclaimer-text"\n set zz x\nend\n',
                     'config router bgp\n config redistribute "zz"\n set status enable\n end\nend\n',
                     'config router bgp\n config redistribute "BGP"\n set status enable\n end\nend\n',
                     'config router bgp\n config redistribute "bgp"\n set status enable\n end\nend\n',
                     'config router bgp\n config redistribute6 "connected"\n set route-map-evpn x\n end\nend\n',
                     'config router rip\n config redistribute "rip"\n set status enable\n end\nend\n',
                     'config waf profile\n edit "default"\n config signature\n config main-class 12345\n'
                     ' set status enable\n end\n end\n next\nend\n',
                     'config waf profile\n edit "default"\n config signature\n config main-class 30000000\n'
                     ' set zz enable\n end\n end\n next\nend\n',
                     'config firewall profile-protocol-options\n edit default\n config http\n set http-0 allow\n end\nnext\nend\n'):
            with self.subTest(near=near):
                visible, hidden, count = render(near, firmware)
                self.assertIn('<UNVERIFIED:', visible)
        for buffer in ('"<p>PRIVATE-REPLACEMSG</p>"', '"-----BEGIN PRIVATE KEY-----\\nAAAA\\n-----END PRIVATE KEY-----"'):
            with self.subTest(buffer=buffer[:12]):
                stream = c.StreamRedactor(('PRIVATE-REPLACEMSG',), 'all', policy=f.policy_for(firmware))
                try:
                    stream.feed(('config system replacemsg admin "pre_admin-disclaimer-text"\n'
                                 ' set buffer ' + buffer + '\n set format html\nend\n').encode())
                    text, hidden, count = stream.finish()
                    visible = text.page(0, text.total)[0]
                finally:
                    stream.close()
                self.assertNotIn('PRIVATE', visible)
                self.assertIn('set buffer <REDACTED:credential#1>', visible)
                self.assertIn('set format html', visible)
                self.assertEqual(count, 1)
