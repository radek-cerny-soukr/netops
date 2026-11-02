from dataclasses import replace
from unittest import TestCase, mock
import json
from netops_helper import engine, configuration as c, config_fortiadc as adc
from netops_helper.proxy import Proxy, ToolArgumentsError, PolicyScopeError
from test_config_block import enrolled, fixture
from test_config_fortiadc import STATUS as ADC_STATUS, config, profile_lines, READ, live

STATUS = ('Version: FortiGate-VM64-KVM v7.6.8,build3744,260101 (GA)\n'
          'Virtual domain configuration: disable\n')
FW_CONFIG = ('config system interface\n edit port1\n set ip 192.0.2.1 255.255.255.0\n'
             ' set password ENC fixture-password\n next\nend\n')

class FullConfigurationEngine(TestCase):
    def setUp(self):
        patch = mock.patch.object(engine, 'record')
        self.events = patch.start()
        self.addCleanup(patch.stop)
        c._SNAPSHOTS.clear()
        c._DIFFS.clear()
    def wire(self, raw=FW_CONFIG, status=STATUS, rc=0):
        def read(auth, platform, command, **kwargs):
            if command == 'get system status':
                return 0, status
            self.assertIn(command, ('show','show full-configuration'))
            consumer=kwargs['stdout_consumer']
            data=raw.encode()
            for i in range(0,len(data),3):consumer(data[i:i+3])
            return rc,''
        return read
    def read(self, auth=None, **kwargs):
        return engine.config_read(auth or enrolled(), 'fortios','all',True,redaction='full',**kwargs)
    def test_fortios_capture_cache_and_defaults(self):
        for defaults in (False, True):
            with mock.patch.object(engine,'read_from_device',side_effect=self.wire()) as wire:
                first=self.read(include_defaults=defaults,limit=32)
                self.assertEqual(len(wire.call_args_list),2)
                self.assertEqual(wire.call_args_list[-1].args[2],'show full-configuration' if defaults else 'show')
            self.assertTrue(first['capture_complete'])
            self.assertFalse(first['configuration_complete'])
            self.assertIn('account-rights-not-verified',first['visibility_limitations'])
            with mock.patch.object(engine,'read_from_device',side_effect=AssertionError('cache must not read SSH')):
                page=self.read(snapshot_id=first['snapshot_id'],offset=first['next_offset'],include_defaults=defaults)
                self.assertEqual(page['redaction_profile'],first['redaction_profile'])
                self.assertEqual(page['configuration_complete'],first['configuration_complete'])
                with self.assertRaises(ValueError):
                    self.read(snapshot_id=first['snapshot_id'],include_defaults=not defaults)
                with self.assertRaises(ValueError):
                    engine.config_read(enrolled(),'fortios','all',True,snapshot_id=first['snapshot_id'])
            self.assertNotIn('fixture-password',json.dumps(page)+repr(c._SNAPSHOTS)+repr(self.events.call_args_list))
    def test_full_diff_has_no_secret_oracle_and_binds_defaults(self):
        raw = (FW_CONFIG.replace('ENC fixture-password', '"FG-PLAIN-A"') +
               'config system admin\n edit credential-probe\n set password "$6$FG-HASH-A"\n next\nend\n'
               'config certificate local\n edit cert-probe\n set password ENC FG-ENC-A\n'
               ' set private-key "-----BEGIN PRIVATE KEY-----\nFG-PEM-A\n-----END PRIVATE KEY-----"\n next\nend\n')
        changed = raw.replace('FG-PLAIN-A','FG-PLAIN-B').replace('FG-HASH-A','FG-HASH-B').replace(
            'FG-ENC-A','FG-ENC-B').replace('FG-PEM-A','FG-PEM-B')
        with mock.patch.object(engine,'read_from_device',side_effect=self.wire(raw)):
            a=self.read(limit=19);d=self.read(include_defaults=True)
        with mock.patch.object(engine,'read_from_device',side_effect=self.wire(changed)):
            b=self.read(limit=19)
        captures=[]
        with mock.patch.object(engine,'read_from_device',side_effect=AssertionError('cache/diff must not read SSH')) as wire:
            for first in (a,b):
                page=first;parts=[page['untrusted_device_output']]
                while page['next_offset'] is not None:
                    page=self.read(snapshot_id=first['snapshot_id'],offset=page['next_offset'],limit=19)
                    self.assertEqual(page['content_sha256'],first['content_sha256'])
                    parts.append(page['untrusted_device_output'])
                cached=c._SNAPSHOTS[first['snapshot_id']]
                self.assertFalse(cached.hidden.data)
                self.assertEqual(''.join(parts),cached.text.page(0,cached.text.total)[0])
                self.assertIn('edit port1\n    set ip 192.0.2.1 255.255.255.0\n',''.join(parts))
                captures.extend((first,page))
            diff=engine.config_diff(enrolled(),'fortios',a['snapshot_id'],b['snapshot_id'])
            repeated=engine.config_diff(enrolled(),'fortios',a['snapshot_id'],b['snapshot_id'])
            with self.assertRaises(ValueError):
                engine.config_diff(enrolled(),'fortios',a['snapshot_id'],d['snapshot_id'])
            wire.assert_not_called()
        self.assertEqual(c.snapshot_metadata(c._SNAPSHOTS[a['snapshot_id']]),
                         c.snapshot_metadata(c._SNAPSHOTS[b['snapshot_id']]))
        self.assertEqual(a['content_sha256'],b['content_sha256'])
        for response in (diff,repeated):
            self.assertTrue(response['identical'])
            self.assertEqual(response['secrets_changed'],[])
            self.assertEqual(response['untrusted_device_output'],'')
            self.assertIsNone(response['next_offset'])
            for name in ('base_capture', 'other_capture'):
                capture=response[name]
                self.assertTrue(capture['capture_complete'])
                self.assertFalse(capture['configuration_complete'])
                self.assertEqual(capture['config_scope'],'single-vdom-device')
                self.assertIn('account-rights-not-verified',capture['visibility_limitations'])
                self.assertEqual(capture['firmware'],{'model':'FortiGate-VM64-KVM','version':'7.6.8','build':'3744'})
                self.assertFalse(capture['include_defaults'])
        rendered=json.dumps(captures+[d,diff,repeated])+repr(self.events.call_args_list)
        rendered+=''.join(s.text.page(0,s.text.total)[0] for s in c._SNAPSHOTS.values())
        rendered+=''.join(value[0].page(0,value[0].total)[0] for value in c._DIFFS.values())
        for value in ('FG-PLAIN-A','FG-PLAIN-B','FG-HASH-A','FG-HASH-B',
                      'FG-ENC-A','FG-ENC-B','FG-PEM-A','FG-PEM-B',enrolled().secret):
            self.assertNotIn(value,rendered)
    def test_fortiadc_stream_scope_and_visibility(self):
        auth=replace(enrolled(),ssh_platform='fortiadc',login='netops-read')
        for rights, complete in ((READ,True),(adc.RIGHTS,False)):
            raw=config(profiles=profile_lines(rights=READ)) if complete else config()
            raw=raw.replace('ENC ADMIN-FIXTURE','"ADC-PLAIN-A"').replace('SECRET-FIXTURE','ADC-ENC-A')
            raw+=('config system certificate local\n edit cert-probe\n'
                  ' set password "$6$ADC-HASH-A"\n set private-key-file metadata-key.pem\n next\nend\n')
            changed=raw.replace('ADC-PLAIN-A','ADC-PLAIN-B').replace('ADC-ENC-A','ADC-ENC-B').replace('ADC-HASH-A','ADC-HASH-B')
            results=[]
            for body in (raw,changed):
                with mock.patch.object(engine,'read_from_device',side_effect=self.wire(live(body),ADC_STATUS)):
                    results.append(engine.config_read(auth,'fortiadc','all',True,redaction='full',limit=19))
            result,other=results
            captures=[]
            with mock.patch.object(engine,'read_from_device',side_effect=AssertionError('cache/diff must not read SSH')) as wire:
                for first in results:
                    self.assertEqual(first['configuration_complete'],complete)
                    self.assertEqual(first['platform'],'fortiadc')
                    page=first;parts=[page['untrusted_device_output']]
                    while page['next_offset'] is not None:
                        page=engine.config_read(auth,'fortiadc','all',True,redaction='full',
                                                snapshot_id=first['snapshot_id'],offset=page['next_offset'],limit=19)
                        self.assertEqual(page['content_sha256'],first['content_sha256'])
                        self.assertEqual(page['visibility_limitations'],first['visibility_limitations'])
                        parts.append(page['untrusted_device_output'])
                    cached=c._SNAPSHOTS[first['snapshot_id']]
                    self.assertFalse(cached.hidden.data)
                    self.assertEqual(''.join(parts),cached.text.page(0,cached.text.total)[0])
                    self.assertIn('config system global\n    set hostname ADC-LAB\nend\n',''.join(parts))
                    self.assertIn('config system certificate local\nedit cert-probe\n',''.join(parts))
                    self.assertIn('    set private-key-file metadata-key.pem\n',''.join(parts))
                    captures.extend((first,page))
                diffs=[engine.config_diff(auth,'fortiadc',result['snapshot_id'],other['snapshot_id']) for _ in range(2)]
                wire.assert_not_called()
            self.assertEqual(c.snapshot_metadata(c._SNAPSHOTS[result['snapshot_id']]),
                             c.snapshot_metadata(c._SNAPSHOTS[other['snapshot_id']]))
            self.assertEqual(result['content_sha256'],other['content_sha256'])
            for diff in diffs:
                self.assertTrue(diff['identical'])
                self.assertEqual(diff['secrets_changed'],[])
                self.assertEqual(diff['untrusted_device_output'],'')
                self.assertIsNone(diff['next_offset'])
                for name in ('base_capture','other_capture'):
                    self.assertEqual(diff[name]['configuration_complete'],complete)
                    self.assertEqual(diff[name]['config_scope'],'all')
                    self.assertEqual(diff[name]['visibility_limitations'],result['visibility_limitations'])
                    self.assertEqual(diff[name]['firmware'],{'model':'FortiADC-KVM','version':'7.6.7','build':'0676'})
            rendered=json.dumps(captures+diffs)+repr(self.events.call_args_list)
            rendered+=''.join(s.text.page(0,s.text.total)[0] for s in c._SNAPSHOTS.values())
            rendered+=''.join(value[0].page(0,value[0].total)[0] for value in c._DIFFS.values())
            for marker in ('ADC-PLAIN-A','ADC-PLAIN-B','ADC-ENC-A','ADC-ENC-B',
                           'ADC-HASH-A','ADC-HASH-B',auth.secret,'--More--','\r'):
                self.assertNotIn(marker,rendered)
        with self.assertRaises(ValueError):
            engine.config_read(auth,'fortiadc','all',True)
    def test_fortiadc_transport_accepts_bounded_stream(self):
        auth=replace(enrolled(),ssh_platform='fortiadc')
        consumer=mock.Mock()
        with mock.patch.object(engine,'_exec_read',return_value=(0,'')) as wire:
            self.assertEqual(engine.read_from_device(auth,'fortiadc','show',stdout_consumer=consumer),(0,''))
            wire.assert_called_once_with(auth,'fortiadc','show',stdout_consumer=consumer)
    def test_refusal_does_not_cache_partial_capture(self):
        from netops_helper.config_limits import ConfigurationLimits
        for raw, status, rc in ((FW_CONFIG,STATUS,1), (FW_CONFIG,'Version: unsupported\n',0),
                                 ('config system interface\n edit port1\n',STATUS,0)):
            with self.subTest(raw=raw),mock.patch.object(engine,'read_from_device',side_effect=self.wire(raw,status,rc)):
                with self.assertRaises(ValueError):
                    self.read()
                self.assertEqual(len(c._SNAPSHOTS),0)
        limited = ConfigurationLimits(section_bytes=32, all_bytes=32,
                                      physical_line_bytes=32, logical_record_bytes=32)
        for platform, status in (('fortios', STATUS), ('fortiadc', ADC_STATUS)):
            auth = replace(enrolled(), ssh_platform='fortiadc' if platform == 'fortiadc' else 'fortinet',
                           configuration_limits=limited)
            with self.subTest(platform=platform), mock.patch.object(
                    engine, 'read_from_device', side_effect=self.wire(FW_CONFIG, status)):
                with self.assertRaisesRegex(ValueError, 'configuration capture-limit-exceeded; output withheld'):
                    engine.config_read(auth, platform, 'all', True, redaction='full')
                self.assertEqual(len(c._SNAPSHOTS), 0)

        raw = 'config system interface\n edit port1\n set password x\n next\nend\n'
        maximum = len(raw.encode())
        inflated = ConfigurationLimits(section_bytes=maximum, all_bytes=maximum,
                                       physical_line_bytes=maximum, logical_record_bytes=maximum)
        with mock.patch.object(engine,'read_from_device',side_effect=self.wire(raw)):
            with self.assertRaisesRegex(ValueError,'configuration capture-limit-exceeded; output withheld'):
                self.read(auth=replace(enrolled(),configuration_limits=inflated))
        self.assertEqual(len(c._SNAPSHOTS),0)

        raw = 'config system interface\nend'
        maximum = len(raw.encode())
        final_line = ConfigurationLimits(section_bytes=maximum, all_bytes=maximum,
                                         physical_line_bytes=maximum, logical_record_bytes=maximum)
        with mock.patch.object(engine,'read_from_device',side_effect=self.wire(raw)):
            with self.assertRaisesRegex(ValueError,'configuration capture-limit-exceeded') as error:
                self.read(auth=replace(enrolled(),configuration_limits=final_line))
            self.assertTrue(str(error.exception).endswith('; output withheld'))
        self.assertEqual(len(c._SNAPSHOTS),0)

    def test_missing_optin_or_target_permission_refuses_before_ssh(self):
        with mock.patch.object(engine,'read_from_device',side_effect=AssertionError('no SSH')):
            for auth,platform,all_opt,mode in ((enrolled(()),'fortios',True,'full'),
                         (enrolled(),'fortios',False,'full'),(enrolled(),'fortiadc',True,'full'),
                         (enrolled(),'fortios',True,'raw')):
                with self.assertRaises(ValueError):
                    engine.config_read(auth,platform,'all',all_opt,redaction=mode)
    def test_proxy_validates_full_arguments(self):
        for platform in ('fortios','fortinet','fortiadc'):
            args=dict(target='fixture',platform=platform,section='all',include_all=True,
                      redaction='full',include_defaults=True)
            self.assertEqual(Proxy._validate_tool_arguments('config_read',args),args)
        bad=({'redaction':'raw'}, {'include_defaults':1}, {'include_all':False},
             {'section':'all; execute reboot'}, {'platform':'fortiadc','redaction':'minimal'})
        args=dict(target='fixture',platform='fortios',section='all',include_all=True,redaction='full')
        for extra in bad:
            with self.subTest(extra=extra),self.assertRaises(ToolArgumentsError):
                Proxy._validate_tool_arguments('config_read',{**args,**extra})
    def test_cache_scope_rejects_other_account_without_ssh(self):
        with mock.patch.object(engine,'read_from_device',side_effect=self.wire()):
            first=self.read()
        with mock.patch.object(engine,'read_from_device',side_effect=AssertionError('no SSH')):
            with self.assertRaises(ValueError):
                self.read(auth=replace(enrolled(),login='another-reader'),snapshot_id=first['snapshot_id'])
            from netops_helper.config_limits import ConfigurationLimits
            changed = replace(enrolled(), configuration_limits=ConfigurationLimits(total_seconds=300))
            with self.assertRaisesRegex(ValueError, 'snapshot not found or expired'):
                self.read(auth=changed,snapshot_id=first['snapshot_id'])
            with self.assertRaisesRegex(ValueError, 'snapshot not found or expired'):
                engine.config_diff(changed,'fortios',first['snapshot_id'],first['snapshot_id'])

    def test_target_memory_is_isolated_and_changed_policy_reclaims_old_captures(self):
        from netops_helper.config_limits import ConfigurationLimits
        other = replace(enrolled(), alias='other-target')
        auth = replace(enrolled(), configuration_limits=ConfigurationLimits(memory_bytes=64*1024*1024))
        with mock.patch.object(engine,'read_from_device',side_effect=self.wire()):
            large = self.read(auth=other)
        original = c.Snapshot.memory_bytes
        other_scope = c.scope(other)
        def accounted(snapshot):
            return 100*1024*1024 if snapshot.scope[:3] == other_scope[:3] else original.fget(snapshot)
        with mock.patch.object(c.Snapshot,'memory_bytes',property(accounted)):
            with mock.patch.object(engine,'read_from_device',side_effect=self.wire()):
                first = self.read(auth=auth)
            with mock.patch.object(engine,'read_from_device',side_effect=AssertionError('cache must not read SSH')):
                self.assertTrue(engine.config_diff(auth,'fortios',first['snapshot_id'],first['snapshot_id'])['identical'])
            changed = replace(auth, configuration_limits=ConfigurationLimits(memory_bytes=32*1024*1024))
            with mock.patch.object(engine,'read_from_device',side_effect=AssertionError('expired policy must not read SSH')):
                with self.assertRaisesRegex(ValueError,'snapshot not found or expired'):
                    self.read(auth=changed,snapshot_id=first['snapshot_id'])
            self.assertNotIn(first['snapshot_id'],c._SNAPSHOTS)
            self.assertIn(large['snapshot_id'],c._SNAPSHOTS)
            with mock.patch.object(engine,'read_from_device',side_effect=self.wire()):
                current = self.read(auth=changed)
        def over_target(snapshot):
            return 65*1024*1024 if snapshot.scope[:3] == c.scope(changed)[:3] else original.fget(snapshot)
        with mock.patch.object(c.Snapshot,'memory_bytes',property(over_target)), mock.patch.object(
                engine,'read_from_device',side_effect=AssertionError('quota refusal must precede SSH')) as device:
            with self.assertRaisesRegex(ValueError,'configuration memory budget exhausted for target'):
                self.read(auth=changed,snapshot_id=current['snapshot_id'])
            device.assert_not_called()
        self.assertIn(large['snapshot_id'],c._SNAPSHOTS)

    def test_filtered_view_counts_toward_target_memory(self):
        from netops_helper.config_limits import ConfigurationLimits
        limit = 64*1024*1024
        auth = replace(enrolled(), configuration_limits=ConfigurationLimits(memory_bytes=limit))
        with mock.patch.object(engine,'read_from_device',side_effect=self.wire()):
            first = self.read(auth=auth)
        original = c.Snapshot.memory_bytes
        def nearly_full(snapshot):
            return limit - 64 if snapshot.filtered is None else original.fget(snapshot) + limit
        with mock.patch.object(c.Snapshot,'memory_bytes',property(nearly_full)), mock.patch.object(
                engine,'read_from_device',side_effect=AssertionError('filter must not read SSH')):
            with self.assertRaisesRegex(ValueError,'configuration memory budget exhausted for target'):
                self.read(auth=auth,snapshot_id=first['snapshot_id'],contains='port1')
            self.assertEqual(self.read(auth=auth,snapshot_id=first['snapshot_id'])['snapshot_id'],first['snapshot_id'])
        self.assertIsNone(c._SNAPSHOTS[first['snapshot_id']].filtered)
        with mock.patch.object(engine,'read_from_device',side_effect=AssertionError('filter must not read SSH')):
            view = self.read(auth=auth,snapshot_id=first['snapshot_id'],contains='port1')
        self.assertGreater(view['matched_lines'],0)
        self.assertIsNotNone(c._SNAPSHOTS[first['snapshot_id']].filtered)

    def test_memory_quota_refusal_keeps_one_category_in_minimal_and_full(self):
        import contextlib
        import shlex
        import sys
        from netops_core import ssh as core_ssh
        from netops_helper.config_limits import ConfigurationLimits
        from test_config_block import STATUS as MINIMAL_STATUS
        refusal = 'configuration memory budget exhausted for target; output withheld'
        budget_error = getattr(c, 'ConfigurationBudgetError', ValueError)
        def ssh_like(raw, status):
            def read(auth, platform, command, **kwargs):
                if command == 'get system status':
                    return 0, status
                data = raw.encode()
                for i in range(0, len(data), 3):
                    try:
                        kwargs['stdout_consumer'](data[i:i+3])
                    except core_ssh.OutputLimitError:
                        raise
                    except Exception:
                        raise core_ssh.OutputConsumerError() from None
                return 0, ''
            return read
        original = c._budget
        def at_finish(staged=0):
            if sys._getframe(1).f_code.co_name == '_finished':
                raise budget_error(refusal)
            return original(staged)
        nested_hits = []
        def in_nested(staged=0):
            frame = sys._getframe(1)
            if frame.f_code.co_name == '_finished' and frame.f_locals['self']._embedded_depth:
                nested_hits.append(staged)
                raise budget_error(refusal)
            return original(staged)
        script = 'config system interface\nedit port2\nset ip 192.0.2.9 255.255.255.0\nnext\nend\n'
        embedded = FW_CONFIG + 'config system auto-script\nedit quota\nset script ' + shlex.quote(script) + '\nnext\nend\n'
        tiny = replace(enrolled(), configuration_limits=ConfigurationLimits(memory_bytes=1024*1024))
        full = lambda auth: self.read(auth=auth)
        minimal = lambda auth: engine.config_read(auth, 'fortios', 'system interface')
        minimal_raw = fixture('up', 'CANARY-quota-7')
        cases = (('full', 'stream', full, FW_CONFIG, STATUS, tiny, None),
                 ('full', 'finish', full, FW_CONFIG, STATUS, enrolled(), at_finish),
                 ('full', 'nested', full, embedded, STATUS, enrolled(), in_nested),
                 ('minimal', 'stream', minimal, minimal_raw, MINIMAL_STATUS, tiny, None),
                 ('minimal', 'finish', minimal, minimal_raw, MINIMAL_STATUS, enrolled(), at_finish))
        for mode, phase, call, raw, status, auth, budget in cases:
            with self.subTest(mode=mode, phase=phase), mock.patch.object(
                    engine, 'read_from_device', side_effect=ssh_like(raw, status)), (
                    mock.patch.object(c, '_budget', budget) if budget else contextlib.nullcontext()):
                with self.assertRaises(ValueError) as error:
                    call(auth)
                self.assertEqual(str(error.exception), refusal)
                self.assertEqual(len(c._SNAPSHOTS), 0)
        self.assertEqual(len(nested_hits), 1)

    def test_global_and_two_vdoms_stay_visible_with_honest_scope_through_cache_and_diff(self):
        import re
        admin = ('config system admin\n edit reader\n set accprofile diagnostics\n next\nend\n'
                 'config system accprofile\n edit diagnostics\n set scope global\n set cli-show enable\n' +
                 ''.join(' set ' + group + ' read\n' for group in ('authgrp', 'ftviewgrp', 'fwgrp', 'loggrp', 'netgrp',
                         'secfabgrp', 'sysgrp', 'utmgrp', 'vpngrp', 'wanoptgrp', 'wifi')) + ' next\nend\n')
        def tenant(name, net, port, secret):
            return (' edit ' + name + '\n config firewall address\n edit net-' + name + '\n'
                    ' set subnet ' + net + ' 255.255.255.0\n set associated-interface ' + port + '\n next\nend\n'
                    ' config router static\n edit 1\n set gateway ' + net[:-1] + '254\n set device ' + port + '\n next\nend\n'
                    ' config user local\n edit u-' + name + '\n set passwd ENC ' + secret + '\n next\nend\n next\n')
        header = ('#config-version=FGVM64-VERSION-FW-buildBUILD-260101:opmode=0:vdom=1:user=reader\n'
                  '#conf_file_ver=1\n#buildno=BUILD\n#global_vdom=1\n'
                  'config vdom\n edit root\n next\n edit tenant-a\n next\n edit tenant-b\n next\nend\n')
        raw = ('config global\n config system global\n set hostname gw-multi\nend\n' + admin +
               ' config system interface\n edit port1\n set vdom tenant-a\n set ip 192.0.2.1 255.255.255.0\n next\n'
               ' edit port2\n set vdom tenant-b\n set ip 198.51.100.1 255.255.255.0\n next\nend\nend\n'
               'config vdom\n' + tenant('tenant-a', '192.0.2.0', 'port1', 'VDOM-SECRET-A') +
               tenant('tenant-b', '198.51.100.0', 'port2', 'VDOM-SECRET-B') + 'end\n')
        for version, build in (('7.6.8', '3744'), ('8.0.2', '0251')):
            for marker in ('multiple', 'disable'):
                with self.subTest(version=version, marker=marker):
                    c._SNAPSHOTS.clear(); c._DIFFS.clear()
                    status = STATUS.replace('7.6.8', version).replace('3744', build).replace('disable', marker)
                    device = header.replace('VERSION', version).replace('BUILD', build) + raw
                    secrets = iter(range(1, 3))
                    expected = [re.sub(r'^set passwd ENC .*', lambda m: 'set passwd <REDACTED:credential#%d>' % next(secrets),
                                       line.strip()) for line in device.splitlines() if line.strip()]
                    with mock.patch.object(engine, 'read_from_device', side_effect=self.wire(device, status)) as wire:
                        first = self.read(limit=64)
                        other = self.read(include_defaults=False, limit=64)
                        full = self.read(include_defaults=True, limit=64)
                        self.assertEqual([call.args[2] for call in wire.call_args_list],
                                         ['get system status', 'show'] * 2 + ['get system status', 'show full-configuration'])
                    scope = {k: first[k] for k in ('config_scope', 'configuration_complete', 'identity_scope_verified',
                                                    'visibility_limitations', 'unverified_count')}
                    self.assertEqual(scope, {'config_scope': 'device-account-visible', 'configuration_complete': False,
                                             'identity_scope_verified': False,
                                             'visibility_limitations': ['vdom-coverage-not-verified'],
                                             'unverified_count': 0})
                    self.assertEqual(first['credential_redactions'], 2)
                    with mock.patch.object(engine, 'read_from_device',
                                           side_effect=AssertionError('cache/diff must not read SSH')) as cached:
                        texts = []
                        for start in (first, full):
                            page, parts = start, [start['untrusted_device_output']]
                            self.assertEqual({k: start[k] for k in scope}, scope)
                            while page['next_offset'] is not None:
                                page = self.read(snapshot_id=start['snapshot_id'], offset=page['next_offset'], limit=64,
                                                 include_defaults=start['include_defaults'])
                                self.assertEqual({k: page[k] for k in scope}, scope)
                                parts.append(page['untrusted_device_output'])
                            texts.append(''.join(parts))
                        diff = engine.config_diff(enrolled(), 'fortios', first['snapshot_id'], other['snapshot_id'])
                        cached.assert_not_called()
                    for text in texts:
                        self.assertEqual([line.strip() for line in text.splitlines() if line.strip()], expected)
                    text = ''.join(texts)
                    self.assertTrue(diff['identical'])
                    for name in ('base_capture', 'other_capture'):
                        self.assertEqual({k: diff[name][k] for k in scope}, scope)
                    rendered = json.dumps([first, other, full, diff]) + text + repr(c._SNAPSHOTS) + repr(self.events.call_args_list)
                    for value in ('VDOM-SECRET-A', 'VDOM-SECRET-B', enrolled().secret):
                        self.assertNotIn(value, rendered)
    def test_proxy_authorizes_only_matching_platform_and_enrolled_config(self):
        from types import SimpleNamespace
        entry=SimpleNamespace(port=22)
        for requested, actual, rights, allowed in (
                ('fortiadc','fortiadc',('read',),True),
                ('fortios','fortinet',('read',),True),
                ('fortinet','fortinet',('read',),True),
                ('fortiadc','fortinet',('read',),False),
                ('fortios','fortiadc',('read',),False),
                ('fortiadc','fortiadc',(),False)):
            section=SimpleNamespace(catalog_platform=lambda:actual,
                     read_inventory={'config_access':rights},egress={'tcp_ports':[22],'tcp_port_ranges':[]})
            args={'platform':requested}
            with self.subTest(requested=requested,actual=actual,rights=rights):
                if allowed:
                    Proxy._authorize_tool('config_read',args,entry,section)
                else:
                    with self.assertRaises(PolicyScopeError):
                        Proxy._authorize_tool('config_read',args,entry,section)
    def test_mcp_forwards_modes_and_keeps_auth_context_position(self):
        from netops_helper import server
        auth=enrolled()
        tool=getattr(server.config_read,'fn',server.config_read)
        with mock.patch.object(server,'_auth',return_value=auth) as decode, mock.patch.object(server,'engine_config_read',return_value={'ok':True}) as read:
            self.assertEqual(tool('fixture','fortios','all',True,'',0,48000,'context',redaction='full',include_defaults=True),{'ok':True})
            decode.assert_called_once_with('fixture','context')
            read.assert_called_once_with(auth,'fortios','all',True,'',0,48000,'full',True,
                                         contains=None,context=0,content_sha256=None,filter_sha256=None)

    def test_read_failure_categories_are_distinct_and_do_not_echo_values(self):
        cases=((FW_CONFIG,STATUS,1,'device-refused'),
               ('config system interface\n edit port1\n',STATUS,0,'stream-incomplete'),
               ('fixture-private-error-value\n',STATUS,0,'redaction-unverifiable'),
               (FW_CONFIG,STATUS.replace('build3744','build9999'),0,'firmware-not-supported'),
               (FW_CONFIG,'fixture-private-identity-value\n',0,'identity-unverifiable'))
        for raw,status,rc,category in cases:
            with self.subTest(category=category),mock.patch.object(engine,'read_from_device',side_effect=self.wire(raw,status,rc)):
                with self.assertRaises(ValueError) as error:
                    self.read()
                self.assertIn(category,str(error.exception))
                self.assertNotIn('fixture-private-',str(error.exception))
                self.assertEqual(len(c._SNAPSHOTS),0)
    def test_transport_failure_and_unsupported_adc_are_not_redaction_errors(self):
        for phase in ('identity','capture'):
            def fail(auth,platform,command,**kwargs):
                if phase=='capture' and command=='get system status':return 0,STATUS
                raise TimeoutError('fixture-private-transport-value')
            with self.subTest(phase=phase),mock.patch.object(engine,'read_from_device',side_effect=fail):
                with self.assertRaises(ValueError) as error:self.read()
                self.assertIn('transport-failed',str(error.exception))
                self.assertNotIn('fixture-private-',str(error.exception))
        def consumer_failure(auth,platform,command,**kwargs):
            if command == 'get system status':
                return 0, STATUS
            raise engine.core_ssh.OutputConsumerError()
        with mock.patch.object(engine,'read_from_device',side_effect=consumer_failure):
            with self.assertRaisesRegex(ValueError,'configuration redaction-unverifiable; output withheld'):
                self.read()
        self.assertEqual(len(c._SNAPSHOTS),0)
        auth=replace(enrolled(),ssh_platform='fortiadc')
        with mock.patch.object(engine,'read_from_device',side_effect=self.wire(status=ADC_STATUS.replace('build0676','build9999'))):
            with self.assertRaises(ValueError) as error:
                engine.config_read(auth,'fortiadc','all',True,redaction='full')
            self.assertIn('firmware-not-supported',str(error.exception))

    def test_failure_reports_physical_line_and_known_config_without_edit_values(self):
        raw = ('config system interface\nedit fixture-private-object\n'
               'set invalid;field fixture-private-value\nnext\nend\n')
        for wrapped in (False, True):
            wire = self.wire(raw, STATUS, 0)
            def read(*args, **kwargs):
                try:
                    return wire(*args, **kwargs)
                except c.ConfigurationRedactionError:
                    if wrapped:
                        raise engine.core_ssh.OutputConsumerError() from None
                    raise
            with self.subTest(core_wrapped=wrapped), mock.patch.object(
                    engine, 'read_from_device', side_effect=read):
                with self.assertRaises(ValueError) as error:
                    self.read()
                message = str(error.exception)
                self.assertIn('redaction-unverifiable at line 3 in config system interface', message)
                self.assertNotIn('fixture-private', message)
                self.assertEqual(len(c._SNAPSHOTS), 0)

    def test_unknown_section_and_incomplete_capture_have_truthful_safe_location(self):
        cases = (('config fixture-private-section\nexecute fixture-private-value\n',
                  'redaction-unverifiable at line 2', False),
                 ('config system interface\nedit fixture-private-object\n',
                  'stream-incomplete at line 2 in config system interface', True))
        for raw, expected, known in cases:
            with self.subTest(expected=expected), mock.patch.object(
                    engine, 'read_from_device', side_effect=self.wire(raw, STATUS, 0)):
                with self.assertRaises(ValueError) as error:
                    self.read()
                message = str(error.exception)
                self.assertIn(expected, message)
                self.assertNotIn('fixture-private', message)
                if not known:
                    self.assertNotIn(' in config ', message)
                self.assertEqual(len(c._SNAPSHOTS), 0)

    def test_decode_failure_does_not_claim_the_previous_record_line(self):
        selected = c.FullConfigPolicy('fortios', frozenset(((('system interface',), 'ip'),)))
        capture = c.StreamRedactor((), 'all', policy=selected)
        capture.feed(b'config system interface\n')
        with self.assertRaises(c.ConfigurationRedactionError) as error:
            capture.feed(b'\xfffixture-private-invalid-utf8')
        self.assertIsNone(error.exception.line)
        self.assertEqual(error.exception.context, ())
        self.assertNotIn('fixture-private', str(error.exception))
