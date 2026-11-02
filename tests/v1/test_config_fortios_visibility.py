from unittest import TestCase, mock
from netops_helper import configuration as c, config_fortios as f, engine
from test_config_block import enrolled

GROUPS=('authgrp','ftviewgrp','fwgrp','loggrp','netgrp','secfabgrp','sysgrp','utmgrp','vpngrp','wanoptgrp','wifi')
FW=('FortiGate-VM64','7.6.8','3744')

def fixture(account='observer'):
    return ('config system admin\n edit '+account+'\n set accprofile diagnostics\n next\nend\n'
            'config system accprofile\n edit diagnostics\n set scope global\n set cli-show enable\n'+
            ''.join(' set '+group+' read\n' for group in GROUPS)+' next\nend\n')

def assessed(raw,firmware=FW,vdomenabled=False):
    stream=c.StreamRedactor((),'all',policy=f.policy_for(firmware));stream.feed(raw.encode())
    content,hidden,count=stream.finish()
    status='Version: '+firmware[0]+' v'+firmware[1]+',build'+firmware[2]+'\nVirtual domain configuration: '+('enable' if vdomenabled else 'disable')+'\n'
    return f.assess(content,'observer',f.verify_identity(status)[1])

class FortiOSVisibility(TestCase):
    def setUp(self):
        c._SNAPSHOTS.clear();c._DIFFS.clear()
        patch=mock.patch.object(engine,'record');patch.start();self.addCleanup(patch.stop)
    def test_binds_exact_account_to_visible_global_profile_on_both_firmwares(self):
        for firmware in (FW,('FortiGate-VM64','8.0.2','0251')):
            for wrap in (False,True):
                raw=fixture()
                if wrap:raw='config global\n'+raw+'end\n'
                result=assessed(raw,firmware)
                self.assertTrue(result['configuration_complete']);self.assertEqual(result['visibility_limitations'],[])
    def test_refuses_missing_partial_ambiguous_remote_and_custom_rights(self):
        base=fixture()
        cases=(fixture('other-account'),base.replace('set accprofile diagnostics','set accprofile missing'),
               base.replace('set scope global','set scope vdom'),
               base.replace('set cli-show enable','set cli-show disable'),
               base.replace('set netgrp read','set netgrp none'),
               base.replace('set netgrp read','set netgrp custom'),
               base.replace(' set netgrp read\n',''),
               base.replace('set accprofile diagnostics','set accprofile diagnostics\n set accprofile diagnostics'),
               base+base,
               base.replace('set accprofile diagnostics','set accprofile diagnostics\n set remote-auth enable'),
               base.replace('set accprofile diagnostics','set accprofile diagnostics\n set wildcard enable'),
               base.replace('set accprofile diagnostics','set accprofile diagnostics\n set vdom-override enable'),
               base.replace('set accprofile diagnostics','set accprofile diagnostics\n set accprofile-override enable'),
               base.replace(' edit diagnostics',' edit observer'))
        for index,raw in enumerate(cases):
            with self.subTest(case=index):
                result=assessed(raw)
                self.assertFalse(result['configuration_complete'])
                self.assertIn('account-rights-not-verified',result['visibility_limitations'])
    def test_multi_vdom_and_contradictory_capture_never_claim_all(self):
        result=assessed(fixture(),vdomenabled=True)
        self.assertFalse(result['configuration_complete'])
        raw=fixture()+'config vdom\n edit root\n next\n edit tenant-a\n next\nend\n'
        result=assessed(raw)
        self.assertFalse(result['configuration_complete'])
        self.assertFalse(result['identity_scope_verified'])
        self.assertIn('vdom-coverage-not-verified',result['visibility_limitations'])
    def test_engine_captures_rights_once_and_pages_the_same_visibility(self):
        auth=enrolled();raw=fixture(auth.login)
        def wire(auth,platform,command,**kwargs):
            if command=='get system status':return 0,'Version: FortiGate-VM64 v7.6.8,build3744\nVirtual domain configuration: disable\n'
            kwargs['stdout_consumer']((raw if command == 'show' else 'config system interface\n edit port1\n set status up\nnext\nend\n').encode());return 0,''
        with mock.patch.object(engine,'read_from_device',side_effect=wire) as read:
            result=engine.config_read(auth,'fortios','all',True,redaction='full')
            self.assertEqual(read.call_count,2)
        self.assertTrue(result['configuration_complete'])
        with mock.patch.object(engine,'read_from_device',side_effect=AssertionError('page must not SSH')):
            page=engine.config_read(auth,'fortios','all',True,redaction='full',snapshot_id=result['snapshot_id'])
        self.assertTrue(page['configuration_complete'])
        with mock.patch.object(engine,'read_from_device',side_effect=wire):
            section=engine.config_read(auth,'fortios','system interface',False,redaction='full')
        self.assertFalse(section['configuration_complete'])
        self.assertIn('requested-section-only',section['visibility_limitations'])

    def _read_and_cache_visibility(self, raw, defaults):
        auth = enrolled()
        status = ('Version: FortiGate-VM64 v7.6.8,build3744\n'
                  'Virtual domain configuration: disable\n')
        command = 'show full-configuration' if defaults else 'show'
        def wire(auth, platform, requested, **kwargs):
            if requested == 'get system status':
                return 0, status
            self.assertEqual(requested, command)
            kwargs['stdout_consumer'](raw.encode())
            return 0, ''
        with mock.patch.object(engine, 'read_from_device', side_effect=wire) as read:
            result = engine.config_read(auth, 'fortios', 'all', True, redaction='full', include_defaults=defaults)
        self.assertEqual([call.args[2] for call in read.call_args_list], ['get system status', command])
        with mock.patch.object(engine, 'read_from_device', side_effect=AssertionError('cached page must not SSH')):
            cached = engine.config_read(auth, 'fortios', 'all', True, redaction='full',
                                        include_defaults=defaults, snapshot_id=result['snapshot_id'])
        self.assertEqual(cached['configuration_complete'], result['configuration_complete'])
        self.assertEqual(cached['visibility_limitations'], result['visibility_limitations'])
        self.assertEqual(cached['include_defaults'], defaults)
        c._SNAPSHOTS.clear()
        return result

    def test_engine_relevant_unsets_never_preserve_old_or_assumed_rights(self):
        auth = enrolled()
        fields = {'cli-show': 'enable', 'netgrp': 'read', 'scope': 'global', 'accprofile': 'diagnostics'}
        fields.update({field: 'disable' for field in ('accprofile-override', 'vdom-override', 'wildcard', 'remote-auth')})
        for defaults in (False, True):
            for field, value in fields.items():
                original = ' set ' + field + ' ' + value + '\n'
                unset = ' unset ' + field + '\n'
                base = fixture(auth.login)
                if field not in ('cli-show', 'netgrp', 'scope', 'accprofile'):
                    anchor = ' set accprofile diagnostics\n'
                    base = base.replace(anchor, anchor + original)
                for order, replacement in (('set-unset', original + unset),
                                           ('unset-set', unset + original),
                                           ('duplicate-unset', original + original + unset)):
                    with self.subTest(defaults=defaults, field=field, order=order):
                        result = self._read_and_cache_visibility(base.replace(original, replacement), defaults)
                        self.assertTrue(result['capture_complete'])
                        self.assertFalse(result['configuration_complete'])
                        self.assertIn('account-rights-not-verified', result['visibility_limitations'])
                        self.assertEqual(result['unverified_count'], 0)

    def test_engine_fully_readable_profile_remains_complete_for_show_and_defaults(self):
        for defaults in (False, True):
            with self.subTest(defaults=defaults):
                result = self._read_and_cache_visibility(fixture(enrolled().login), defaults)
                self.assertTrue(result['configuration_complete'])
                self.assertEqual(result['visibility_limitations'], [])
