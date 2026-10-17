import importlib.util
import io
import json
from pathlib import Path
import random
import unittest
from unittest.mock import patch
from netops import redaction

spec=importlib.util.spec_from_file_location("redaction_candidate_baseline",
                                           Path(__file__).parent/"fixtures"/"redaction_reference.py")
baseline=importlib.util.module_from_spec(spec);spec.loader.exec_module(baseline)

class RedactionCandidateContract(unittest.TestCase):
    def test_encoded_field_names_and_normalized_variants_are_redacted(self):
        for name in ("API-KEY","Set_Cookie","URL-QUERY","mcp-session-id","to\u212aen"):
            for ascii_only in (False,True):
                source=json.dumps({name:"canary"},ensure_ascii=ascii_only)
                self.assertEqual(redaction.redact(source),
                                 (json.dumps({name:"[REDACTED]"},separators=(",",":"),ensure_ascii=False),
                                  [["$json",name],[]]))
        self.assertEqual(redaction.redact(r'{"to\u006ben":"v"}'),
                         ('{"token":"[REDACTED]"}',[["$json","token"],[]]))
    def test_escaped_known_secret_and_nested_json_are_redacted(self):
        self.assertEqual(redaction.redact(r'{"safe":"a\"b"}',('a"b',)),
                         ('{"safe":"[REDACTED]"}',[["$json","safe"],[]]))
        source='{"inner":"{\\"to\\\\u006ben\\":\\"v\\"}"}'
        expected='{"inner":"{\\"token\\":\\"[REDACTED]\\"}"}'
        self.assertEqual(redaction.redact(source),
                         (expected,[["$json","inner","$json","token"],["$json","inner"],[]]))
    def test_text_patterns_and_unterminated_pem_keep_their_semantics(self):
        for text in ("token=a","ſecret=x","set password x"):
            self.assertEqual(redaction.redact(text),("[REDACTED]",[[]]))
        text="-----BEGIN PRIVATE KEY-----unfinished"
        self.assertEqual(redaction.redact(text),(text,[]))
        text="a-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----z"
        self.assertEqual(redaction.redact(text),("a[REDACTED]z",[[]]))
        for text in ("[x]","[xxxxx]",'{"a":0}',"z"*4096,"passwordx","token:"):
            self.assertEqual(redaction.redact(text),(text,[]))
    def test_short_long_unicode_and_subclass_secrets_are_preserved(self):
        for secret in ("abc","x","ž","long-known-canary"):
            self.assertEqual(redaction.redact("."+secret+".",(secret,)),
                             (".[REDACTED].",[[]]))
        class Secret(str):
            def __len__(self):return 1000
        class Text(str):
            def __len__(self):return 0
        self.assertEqual(redaction.redact("abc",(Secret("abc"),)),("[REDACTED]",[[]]))
        self.assertEqual(redaction.redact(Text("token=a")),("[REDACTED]",[[]]))
    def test_differential_text_json_unicode_and_known_secrets(self):
        rng=random.Random(20261015)
        fragments=("[x]","[xxxxx]",'{"a":0}',"passwordx","token=a","ſecret=x",
                   "toKen","API-KEY","Set_Cookie","URL-QUERY","mcp-session-id",
                   "\\u006b","\\\"","\\\\","abc","ž","long-known-canary",
                   "-----BEGIN PRIVATE KEY-----","-----END PRIVATE KEY-----",
                   "[","]","{","}",'"',":",","," ","\n","null","NaN","Infinity")
        corpus=[json.dumps({"inner":json.dumps({key:"abc"})}) for key in ("API-KEY","Set_Cookie","token")]
        corpus += ["".join(rng.choice(fragments) for _ in range(rng.randrange(15))) for _ in range(5000)]
        for secrets in ((),("abc",),("ž","long-known-canary")):
            for value in corpus:
                self.assertEqual(redaction.redact(value,secrets),baseline.redact(value,secrets),repr(value))
    def test_gate_refuses_a_mutant_that_skips_real_redaction(self):
        suite=unittest.TestSuite(RedactionCandidateContract(name) for name in (
            "test_encoded_field_names_and_normalized_variants_are_redacted",
            "test_escaped_known_secret_and_nested_json_are_redacted"))
        with patch.object(redaction,"redact",side_effect=lambda value,secrets=():(value,[])):
            result=unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        self.assertEqual(result.testsRun,2)
        self.assertGreaterEqual(len(result.failures),2)
        self.assertEqual((len(result.errors),len(result.skipped)),(0,0))
