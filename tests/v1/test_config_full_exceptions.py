from unittest import TestCase
from netops_helper import configuration as c, config_fortios

CASES = ((('load-balance persistence',),'sess-keyword','custom'),
         (('load-balance persistence',),'cookie-custom-attr','enable'),
         (('load-balance client-ssl-profile',),'ssl-customize-ciphers-flag','enable'),
         (('load-balance client-ssl-profile',),'backend-ssl-customize-ciphers-flag','enable'),
         (('load-balance client-ssl-profile',),'backend-ssl-customized-ciphers','ECDHE-ECDSA-AES256-GCM-SHA384'))

class ExactPublicFieldExceptions(TestCase):
    def render(self,platform,path,field,value,*,public_path=None,selected=None):
        policy=selected or c.FullConfigPolicy(platform,frozenset((((public_path or path),field),)))
        raw='config '+path[0]+'\n set '+field+' '+value+'\nend\n'
        text,hidden,count=c.redact(raw,(),'all',policy=policy)
        self.assertEqual(len(hidden),0)
        return text.page(0,text.total)[0]
    def test_semantic_public_fields_are_exact_path_and_firmware_bound(self):
        fortios = config_fortios.policy_for(('FortiGate-60F', '7.6.8', '3744'))
        for path,field,value in CASES:
            with self.subTest(field=field):
                self.assertIn('set '+field+' '+value+'\n',self.render('fortiadc',path,field,value))
                self.assertIn('set '+field+' <UNVERIFIED:unclassified-field>\n',
                              self.render('fortiadc',('load-balance profile',),field,value,public_path=path))
                self.assertIn('set '+field+' <UNVERIFIED:unclassified-field>\n',
                              self.render('fortios',path,field,value,selected=fortios))
    def test_proven_serialized_credential_is_hidden_even_in_public_diagnostic_field(self):
        for path,field,value in CASES:
            with self.subTest(field=field):
                self.assertIn('set '+field+' <REDACTED:credential#1>\n',
                              self.render('fortiadc',path,field,'ENC fixture-hidden'))
    def test_public_selector_patterns_are_not_actual_authentication_headers(self):
        persistence=('load-balance persistence',)
        for value in ('SRV', '"Authorization: Bearer fixture-visible-pattern"', '"sid=fixture-visible-pattern"'):
            with self.subTest(value=value):
                output=self.render('fortiadc',persistence,'keyword',value)
                self.assertIn('fixture-visible-pattern' if 'fixture-visible-pattern' in value else 'set keyword SRV',output)
                self.assertNotIn('REDACTED',output)
                self.assertNotIn('UNVERIFIED',output)
