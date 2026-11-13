"""Credential ranges follow the JSON serializer's actual key/container order."""
import json
import unittest

from netops.redaction_spans import Marked, dumps, loads, mask


class RedactionSpansSerialization(unittest.TestCase):
    def check_round_trip(self, value, expected, **options):
        encoded = dumps(value, **options)
        self.assertEqual(str(encoded), json.dumps(value, **options))
        self.assertEqual(json.loads(mask(encoded)), expected)
        self.assertEqual(self.mask_strings(loads(encoded)), expected)

    def mask_strings(self, value):
        if isinstance(value, str):
            return mask(value)
        if isinstance(value, dict):
            return {mask(key): self.mask_strings(child) for key, child in value.items()}
        if isinstance(value, list):
            return [self.mask_strings(child) for child in value]
        return value

    def test_sorted_keys_keep_credentials_attached_to_their_values(self):
        value = {'z_output': Marked('CNRY-secret', [(0, 11)]), 'a_public': 'port 1 up'}
        self.check_round_trip(value, {'z_output': '<REDACTED:credential#1>', 'a_public': 'port 1 up'},
                             sort_keys=True)

    def test_tuple_values_preserve_ranges_and_following_siblings(self):
        value = {'output': (Marked('CNRY-secret', [(0, 11)]), 'port 1 up'), 'summary': 'ok'}
        self.check_round_trip(value, {'output': ['<REDACTED:credential#1>', 'port 1 up'], 'summary': 'ok'})

    def test_nested_sorted_tuples_translate_escaped_offsets(self):
        secret = 'prefix \U0001f512 "CNRY-secret" suffix'
        value = {'z_output': ({'z': Marked(secret, [(10, 21)]), 'a': 'public'},), 'a': 'summary'}
        expected = {'z_output': [{'z': 'prefix \U0001f512 "<REDACTED:credential#1>" suffix', 'a': 'public'}],
                    'a': 'summary'}
        for ascii_only in (True, False):
            with self.subTest(ensure_ascii=ascii_only):
                self.check_round_trip(value, expected, sort_keys=True, ensure_ascii=ascii_only, indent=2)

    def test_unmarked_tuple_matches_standard_json(self):
        self.assertEqual(dumps(('public', {'z': 1, 'a': 2}), sort_keys=True),
                         json.dumps(('public', {'z': 1, 'a': 2}), sort_keys=True))


if __name__ == '__main__':
    unittest.main()
