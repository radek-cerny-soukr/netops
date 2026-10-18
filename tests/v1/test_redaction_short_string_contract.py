import importlib.util,itertools
from pathlib import Path
import unittest
from netops import redaction

spec=importlib.util.spec_from_file_location("reference",Path(__file__).parent/"fixtures"/"redaction_reference.py")
reference=importlib.util.module_from_spec(spec);spec.loader.exec_module(reference)

class ShortStringContract(unittest.TestCase):
    def test_short_candidate_decisions_match_the_compiled_regex(self):
        alphabet="pintoke\\[]Kſ"
        count=0
        for length in range(6):
            for letters in itertools.product(alphabet,repeat=length):
                text="".join(letters)
                self.assertEqual(redaction.has_candidate(text),redaction.CANDIDATE.search(text) is not None,text)
                count+=1
        self.assertGreater(count,200000)
    def test_short_known_literals_keep_values_and_exact_redaction_paths(self):
        for secret in ("a","xy","xyz","wxyz","é","K","\\","[]"):
            value={"ordinary":[secret,"pre"+secret+"post"],"cookie":secret}
            self.assertEqual(redaction.redact(value,(secret,)),reference.redact(value,(secret,)))
            cleaned,paths=redaction.redact(value,(secret,))
            self.assertEqual(cleaned["ordinary"],["[REDACTED]","pre[REDACTED]post"])
            self.assertEqual(paths,[["ordinary","0"],["ordinary","1"],["cookie"]])
    def test_secret_named_fields_remain_authoritative_for_tiny_values(self):
        for field in redaction.SECRET_FIELDS:
            for name in (field,field.replace("_","-").upper()):
                for value in ("","x","[]","é",None):
                    actual=redaction.redact({name:value})
                    self.assertEqual(actual,reference.redact({name:value}))
                    self.assertEqual(actual,({name:value},[]) if value is None else ({name:"[REDACTED]"},[[name]]))
    def test_string_subclasses_retain_the_reference_fallback(self):
        class Text(str):pass
        for value in (Text("x"),Text("[x]"),Text("token=a"),Text('{"token":"a"}')):
            self.assertEqual(redaction.redact([value],("x",)),reference.redact([value],("x",)))
        class RequiresFallback(str):
            def lstrip(self):raise RuntimeError("synthetic fallback observed")
        for function in (redaction.redact,reference.redact):
            with self.assertRaisesRegex(RuntimeError,"synthetic fallback observed"):
                function(RequiresFallback("tiny"))
    def test_nested_short_values_and_structural_copy_contract_match_reference(self):
        source=["[x]",0,False,None,["x","é"],{"ordinary":"{}", "token":"x"}]
        expected=reference.redact(source)
        actual=redaction.redact(source)
        self.assertEqual(actual,expected)
        self.assertEqual(source[-1]["token"],"x")
        self.assertIsNot(actual[0],source)
        self.assertIsNot(actual[0][4],source[4])
