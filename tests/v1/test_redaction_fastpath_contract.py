import unittest

from netops.redaction import redact


class RedactionFastpathContract(unittest.TestCase):
    def test_mixed_list_keeps_original_indices_and_scalar_identity(self):
        class Integer(int):
            pass
        sentinel = object()
        number = Integer(7)
        opaque = ("password=untouched",)
        blob = b"token=untouched"
        source = [None, False, number, 1.5, sentinel, opaque, blob,
                  "secret=hidden", {"token": "hidden"}, [0, "community=hidden"]]
        expected = [None, False, number, 1.5, sentinel, opaque, blob,
                    "[REDACTED]", {"token": "[REDACTED]"}, [0, "[REDACTED]"]]
        cleaned, paths = redact(source)
        self.assertEqual((cleaned, paths),
                         (expected, [["7"], ["8", "token"], ["9", "1"]]))
        for index in (2, 4, 5, 6):
            self.assertIs(cleaned[index], source[index])
        self.assertEqual(source[7:], ["secret=hidden", {"token": "hidden"},
                                      [0, "community=hidden"]])

    def test_container_and_string_subclasses_follow_public_contract(self):
        class Sequence(list):
            pass
        class Mapping(dict):
            pass
        class Text(str):
            pass
        source = Sequence([Mapping({"PASSWORD": Text("hidden")}), Text("token=hidden")])
        self.assertEqual(redact(source),
                         ([{"PASSWORD": "[REDACTED]"}, "[REDACTED]"],
                          [["0", "PASSWORD"], ["1"]]))

    def test_tail_guard_does_not_call_new_subclass_methods(self):
        class RaisingRstrip(str):
            def rstrip(self, *args):
                raise AssertionError("new virtual rstrip call")
        class ShadowedRstrip(str):
            rstrip = None
        for cls in (RaisingRstrip, ShadowedRstrip):
            for text in (' [0,{"password":"hidden"}] \n', "[not-json"):
                with self.subTest(cls=cls.__name__, text=text):
                    expected = ('[0,{"password":"[REDACTED]"}]',
                                [["$json", "1", "password"], []])
                    if text == "[not-json":
                        expected = (text, [])
                    self.assertEqual(redact(cls(text)), expected)

    def test_secret_field_normalization_none_and_depth_first_paths(self):
        source = {"X-Api-Key": 0, "password": None, "credentials": [],
                  "Token": False, 7: {"secret": "hidden"}}
        expected = {"X-Api-Key": "[REDACTED]", "password": None,
                    "credentials": "[REDACTED]", "Token": "[REDACTED]",
                    7: {"secret": "[REDACTED]"}}
        self.assertEqual(redact(source), (expected, [["X-Api-Key"], ["credentials"],
                                                    ["Token"], ["7", "secret"]]))

    def test_known_secrets_longest_first_and_nonstring_entries_ignored(self):
        source = ["abcdef abc", {"safe": "abcdef", "token": "abc"}, "unrelated"]
        self.assertEqual(redact(source, ("abc", "abcdef", "", None, 42)),
                         (["[REDACTED] [REDACTED]",
                           {"safe": "[REDACTED]", "token": "[REDACTED]"}, "unrelated"],
                          [["0"], ["1", "safe"], ["1", "token"]]))

    def test_embedded_json_paths_precede_containing_string_paths(self):
        source = {"wire": ' \t[null,{"password":"hidden","note":"visible"}]\r\n',
                  "nested": '{"inner":"{\\"token\\":\\"hidden\\"}"}'}
        expected = {"wire": '[null,{"password":"[REDACTED]","note":"visible"}]',
                    "nested": '{"inner":"{\\"token\\":\\"[REDACTED]\\"}"}'}
        self.assertEqual(redact(source), (expected,
                         [["wire", "$json", "1", "password"], ["wire"],
                          ["nested", "$json", "inner", "$json", "token"],
                          ["nested", "$json", "inner"], ["nested"]]))

    def test_unchanged_json_keeps_original_whitespace_and_unicode(self):
        for text in (' \t[null,1,true,"žluťoučký"]\r\n', ' { "safe" : [] } ', "[]"):
            with self.subTest(text=text):
                self.assertEqual(redact(text), (text, []))

    def test_malformed_json_still_applies_text_and_known_secret_redaction(self):
        cases = [("[token=hidden", "[[REDACTED]"),
                 ('{"safe":"canary"}tail', '{"safe":"[REDACTED]"}tail'),
                 ('["canary"}', '["[REDACTED]"}'),
                 ('{"safe":"canary"}\u00a0', '{"safe":"[REDACTED]"}\u00a0')]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(redact(source, ("canary",)), (expected, [[]]))
        self.assertEqual(redact("[x]"), ("[x]", []))

    def test_pem_blocks_and_cli_patterns_keep_path_order(self):
        source = ["a-----BEGIN PRIVATE KEY-----hidden-----END PRIVATE KEY-----z",
                  "set password hidden\nplain", {"note": "secret=hidden; token=hidden"}]
        self.assertEqual(redact(source),
                         (["a[REDACTED]z", "[REDACTED]\nplain",
                           {"note": "[REDACTED]; [REDACTED]"}],
                          [["0"], ["1"], ["2", "note"]]))


if __name__ == "__main__":
    unittest.main()
