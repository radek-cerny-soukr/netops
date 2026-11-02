from dataclasses import replace
import json
from unittest import TestCase,mock
from netops_helper import configuration as c, engine, config_fortios
from test_config_block import enrolled

FW=('FortiGate-VM64','7.6.8','3744')

def policy(platform='fortios',public=(),private=(),edits=()):
    extra={'secret_fields':frozenset(private)} if private else {}
    return c.FullConfigPolicy(platform,frozenset(public),frozenset(edits),**extra)

def render(raw,p,chunk=7,forbidden=()):
    stream=c.StreamRedactor(forbidden,'all',policy=p)
    data=raw.encode()
    for start in range(0,len(data),chunk):stream.feed(data[start:start+chunk])
    content,hidden,count=stream.finish()
    return content.page(0,content.total)[0],hidden,count,getattr(stream,'summary',lambda:{})()

class SemanticRedaction(TestCase):
    def setUp(self):
        c._SNAPSHOTS.clear();c._DIFFS.clear()
        patch=mock.patch.object(engine,'record');patch.start();self.addCleanup(patch.stop)
    def test_network_meaning_is_preserved_despite_old_name_substrings(self):
        fields=('key','community','password-type','custom-profile','private-address','description','uuid','hash')
        p=policy('fortiadc',public=[(('load-balance profile',),field) for field in fields],edits=[('load-balance profile',)])
        values=('account_id','monitoring team','chap-password','custom-http','192.0.2.4','to application pool','fixture-uuid','fixture-file-checksum')
        raw='config load-balance profile\n edit MYSQL\n'+''.join(' set '+f+' '+json.dumps(v)+'\n' for f,v in zip(fields,values))+' next\nend\n'
        output,hidden,count,summary=render(raw,p)
        for v in values:self.assertIn(v,output)
        self.assertEqual(count,0);self.assertFalse(hidden.data);self.assertEqual(summary['unverified_count'],0)
    def test_snmp_name_and_bgp_community_and_routes_are_visible(self):
        p=policy(public=[(('system snmp community',),'name'),(('router route-map','rule'),'set-community'),
                         (('router bgp','neighbor'),'route-map-in')],edits=[('system snmp community',),('router route-map',),('router route-map','rule'),('router bgp','neighbor')])
        raw=('config system snmp community\n edit 1\n set name "monitoring ro"\n next\nend\n'
             'config router route-map\n edit POLICY\n config rule\n edit 1\n set set-community 65000:10\n next\nend\n next\nend\n'
             'config router bgp\n config neighbor\n edit 192.0.2.9\n set route-map-in POLICY\n next\nend\nend\n')
        output,*_=render(raw,p)
        for v in ('set name "monitoring ro"','set set-community 65000:10','set route-map-in POLICY'):self.assertIn(v,output)
    def test_credential_semantics_override_even_a_bad_public_map(self):
        path=('system global',);fields=('password','auth-pwd','priv-pwd','private-key')
        p=policy(public=[(path,x) for x in fields]+[(('user group',),'password')],
                 private=[(path,x) for x in fields])
        raw='config system global\n'+''.join(' set '+x+' fixture-private-'+x+'\n' for x in fields)+'end\nconfig user group\n set password auto-generate\nend\n'
        output,hidden,count,summary=render(raw,p)
        self.assertNotIn('fixture-private-',output);self.assertIn('set password auto-generate',output)
        self.assertEqual(count,4);self.assertEqual(summary['credential_redactions'],4);self.assertFalse(hidden.data)
        for n in range(1,5):self.assertIn('credential#'+str(n),output)
    def test_public_certificate_multiline_description_and_enc_named_object_survive(self):
        path=('certificate local',)
        p=policy(public=[(path,'certificate'),(path,'comments'),(path,'fingerprint')],edits=[path])
        cert='-----BEGIN CERTIFICATE-----\nPUBLIC-CERT-FIXTURE\n-----END CERTIFICATE-----'
        raw='config certificate local\n edit SSL-ENC\n set certificate '+json.dumps(cert)+'\n set comments '+json.dumps('line one\nENC means encryption here')+'\n set fingerprint sha256:0123456789\n next\nend\n'
        for chunk in (1,7,65536):
            output,hidden,count,_=render(raw,p,chunk)
            self.assertIn('edit SSL-ENC',output);self.assertIn('PUBLIC-CERT-FIXTURE',output)
            self.assertIn('ENC means encryption here',output);self.assertIn('sha256:0123456789',output)
            self.assertEqual(count,0);self.assertFalse(hidden.data)
        ids=[]
        for suffix in ('A','B'):
            stream=c.StreamRedactor((),'all',policy=p)
            stream.feed(raw.replace('PUBLIC-CERT-FIXTURE','PUBLIC-CERT-FIXTURE-'+suffix).encode())
            content,hidden,count=stream.finish()
            ids.append(c.store(enrolled(),content,hidden,count,'all',FW,profile=p.identifier))
        diff,changed,identical=c.compare(enrolled(),*ids)
        self.assertFalse(identical);self.assertEqual(len(changed),0)
        self.assertIn('PUBLIC-CERT-FIXTURE-B',diff.page(0,diff.total)[0])
    def test_proven_serialized_secrets_and_private_pem_are_hidden_in_any_field(self):
        path=('system global',);p=policy(public=[(path,'description')])
        for val in ('ENC fixture-private-encoded','$6$fixture-private-hash','-----BEGIN RSA PRIVATE KEY-----\nfixture-private-pem\n-----END RSA PRIVATE KEY-----',
                    '-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture-private-pgp\n-----END PGP PRIVATE KEY BLOCK-----'):
            raw='config system global\n set description '+(val if val.startswith('ENC ') else json.dumps(val))+'\nend\n'
            output,hidden,count,_=render(raw,p,1)
            self.assertNotIn('fixture-private-',output);self.assertIn('<REDACTED:credential#1>',output)
            self.assertEqual(count,1);self.assertFalse(hidden.data)
    def test_unknown_is_unverified_with_bounded_value_free_summary(self):
        raw='config system global\n'+''.join(' set new-field-'+str(n)+' fixture-unknown-value-'+str(n)+'\n' for n in range(40))+'end\n'
        output,hidden,count,summary=render(raw,policy())
        self.assertNotIn('fixture-unknown-value-',output);self.assertIn('<UNVERIFIED:',output)
        self.assertNotIn('<REDACTED:',output);self.assertEqual(summary['unverified_count'],40)
        self.assertEqual(len(summary['unverified_fields']),32);self.assertTrue(summary['unverified_truncated'])
        self.assertNotIn('fixture-unknown-value-',json.dumps(summary));self.assertEqual(count,40)
    def test_full_profile_binds_secret_classification_without_secret_fingerprints(self):
        path=('system global',);secret=(path,'password')
        p=policy(private=[secret]);other=policy(public=[secret])
        self.assertNotEqual(p.identifier,other.identifier);self.assertIn('-full-2:',p.identifier)
        snapshots=[]
        for value in ('fixture-first-password','fixture-second-password'):
            stream=c.StreamRedactor((),'all',policy=p);stream.feed(('config system global\n set password '+value+'\nend\n').encode())
            text,hidden,count=stream.finish();snapshots.append(c.store(enrolled(),text,hidden,count,'all',FW,profile=p.identifier))
            self.assertFalse(hidden.data)
        text,changed,identical=c.compare(enrolled(),*snapshots)
        self.assertTrue(identical);self.assertEqual(len(changed),0)
    def test_engine_shows_explicit_community_and_keeps_unknown_summary_in_cache(self):
        auth=enrolled()
        selected=policy(public=[(('system snmp community',),'name')],edits=[('system snmp community',)])
        raw='config system snmp community\n edit 1\n set name monitoring\n set new-field fixture-unclassified\n next\nend\n'
        def wire(auth,platform,command,**kwargs):
            if command=='get system status':return 0,'Version: FortiGate-VM64 v7.6.8,build3744,260101 (GA)\nVirtual domain configuration: disable\n'
            kwargs['stdout_consumer'](raw.encode());return 0,''
        with mock.patch.object(config_fortios,'policy_for',return_value=selected),mock.patch.object(engine,'read_from_device',side_effect=wire):
            result=engine.config_read(auth,'fortios','all',True,redaction='full')
        self.assertIn('set name monitoring',result['untrusted_device_output']);self.assertEqual(result['unverified_count'],1)
        self.assertIn('schema-fields-unverified',result['visibility_limitations']);self.assertFalse(result['configuration_complete'])
        with mock.patch.object(config_fortios,'policy_for',return_value=selected),mock.patch.object(engine,'read_from_device',side_effect=AssertionError('no SSH')):
            cached=engine.config_read(auth,'fortios','all',True,redaction='full',snapshot_id=result['snapshot_id'])
        self.assertEqual(cached['unverified_fields'],result['unverified_fields'])
        self.assertNotIn('fixture-unclassified',json.dumps(cached))

    def test_unsupported_format_keeps_object_names_and_has_own_visibility_reason(self):
        path=('system auto-script',)
        selected=c.FullConfigPolicy('fortios',public_fields=frozenset(((path,'start'),)),
                    public_edit_sections=frozenset((path,)),unverified_fields=frozenset(((path,'script'),)))
        raw='config system auto-script\n edit inspect-status\n set start manual\n set script "fixture-unknown-operation argument"\nnext\nend\n'
        output,hidden,count,summary=render(raw,selected,1)
        self.assertIn('edit inspect-status',output);self.assertIn('set start manual',output)
        self.assertIn('<UNVERIFIED:unsupported-format>',output)
        self.assertEqual(summary['unverified_count'],1);self.assertEqual(summary['unsupported_format_count'],1)
        opaque=c.FullConfigPolicy('fortios',public_edit_sections=frozenset((path,)),opaque_sections=frozenset((path,)))
        output,*_=render(raw,opaque)
        self.assertIn('edit inspect-status',output);self.assertIn('<UNVERIFIED:unsupported-format>',output)
        self.assertNotIn('<REDACTED:',output)
        def wire(auth,platform,command,**kwargs):
            if command=='get system status':return 0,'Version: FortiGate-VM64 v7.6.8,build3744,260101 (GA)\nVirtual domain configuration: disable\n'
            kwargs['stdout_consumer'](raw.encode());return 0,''
        with mock.patch.object(config_fortios,'policy_for',return_value=selected),mock.patch.object(engine,'read_from_device',side_effect=wire):
            result=engine.config_read(enrolled(),'fortios','all',True,redaction='full')
        self.assertEqual(result['unsupported_format_count'],1)
        self.assertIn('formats-not-verified',result['visibility_limitations'])
        self.assertNotIn('schema-fields-unverified',result['visibility_limitations'])
        self.assertFalse(result['configuration_complete'])

    def test_known_unparsed_empty_values_are_visible_without_claiming_a_payload(self):
        path = ('system sdn-connector',)
        selected = c.FullConfigPolicy('fortiadc', unverified_fields=frozenset(((path, 'oci-cert'),)))
        output, hidden, count, summary = render('config system sdn-connector\nset oci-cert ""\nend\n', selected, 1)
        self.assertIn('set oci-cert ""', output)
        self.assertEqual((len(hidden), count, summary['unverified_count']), (0, 0, 0))
        output, hidden, count, summary = render('config system sdn-connector\nset oci-cert "fixture-payload"\nend\n', selected, 1)
        self.assertIn('UNVERIFIED:unsupported-format', output)
        self.assertNotIn('fixture-payload', output)
        self.assertEqual(summary['unsupported_format_count'], 1)

    def test_empty_values_do_not_bypass_credential_or_unknown_schema_classification(self):
        path = ('system global',)
        selected = c.FullConfigPolicy('fortios',
                                     secret_fields=frozenset(((path, 'password'),)),
                                     unverified_fields=frozenset(((path, 'password'),)))
        output, hidden, count, summary = render('config system global\nset password ""\nset unknown ""\nend\n', selected, 1)
        self.assertIn('set password <REDACTED:credential#1>', output)
        self.assertIn('set unknown <UNVERIFIED:unclassified-field>', output)
        self.assertEqual(summary['credential_redactions'], 1)
        self.assertEqual(summary['unverified_count'], 1)

    def test_fortios_empty_script_defaults_are_not_unsupported_payloads(self):
        for firmware in (('FortiGate-60F', '7.6.8', '3744'), ('FortiGate-VM64', '8.0.2', '0251')):
            with self.subTest(firmware=firmware):
                output, hidden, count, summary = render(
                    'config system automation-action\nedit unused\nset script ""\nnext\nend\n',
                    config_fortios.policy_for(firmware), 1)
                self.assertIn('set script ""', output)
                self.assertEqual((count, summary['unverified_count']), (0, 0))
