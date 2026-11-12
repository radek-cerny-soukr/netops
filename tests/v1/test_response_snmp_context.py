"""SNMP response masking preserves complete values and original command context."""
import unittest

from netops.redaction import redact as worker_redact
from netops_helper.sanitize import redact_response
from netops_helper.proxy_sanitize import sanitize_object


def paths(text):
    return (redact_response(text), worker_redact(sanitize_object(text))[0])


class SnmpResponseContext(unittest.TestCase):
    def test_unquoted_values_and_marker_suffix_are_hidden_to_end_of_line(self):
        for value in ('word CANARY', '<REDACTED:credential#1> CANARY'):
            for text in ('set community %s\n' % value, 'prefix\rset community %s\r' % value,
                         'config system snmp community\nedit 1\nset name %s\nnext\nend\n' % value):
                for output in paths(text):
                    self.assertNotIn('CANARY', output)
                    self.assertEqual(worker_redact(sanitize_object(output))[0], output)

    def test_value_free_community_marker_survives(self):
        text = 'set community <REDACTED:credential#1>\n'
        for output in paths(text):
            self.assertEqual(output, text)

    def test_original_context_survives_line_endings_and_legacy_quote_consumption(self):
        import json
        blocks = ('config system snmp community\nedit 1\nset name "ENC first"\nnext\nend\n'
                  'config switch-controller managed-switch\nedit "S1"\nconfig snmp-community\n'
                  'edit 1\nset name "CANARY2"\nnext\nend\nnext\nend\n')
        for prefix in ('', 'config unrelated\n', 'end\n', 'snmp-server community "ENC X"\n'):
            for ending in ('\n', '\r\n', '\r'):
                text = (prefix + blocks).replace('\n', ending)
                for value in (text, {'output': text}, json.dumps({'output': text}),
                              {'content': [{'text': json.dumps({'output': text})}]}):
                    output = worker_redact(sanitize_object(value))[0]
                    self.assertNotIn('CANARY2', json.dumps(output))
                    self.assertEqual(worker_redact(sanitize_object(output))[0], output)
                self.assertNotIn('CANARY2', redact_response(text))

    def test_names_outside_snmp_keep_their_values(self):
        text = ('config unrelated\nset name "public-name"\nend\n'
                'config system snmp community\nset name "CANARY"\nend\n')
        for output in paths(text):
            self.assertIn('"public-name"', output)
            self.assertNotIn('CANARY', output)

    def test_noncredential_snmp_blocks_do_not_trigger_context_pass(self):
        from netops_helper.proxy_sanitize import _contains_snmp
        self.assertFalse(_contains_snmp('config system snmp sysinfo\nset status enable\nend\n'))
        self.assertFalse(_contains_snmp('description config system snmp community\n'))
        self.assertTrue(_contains_snmp('config system snmp community\rset name x\rend\r'))

    def test_clean_response_does_not_repeat_the_whole_chain(self):
        from unittest.mock import patch
        from netops_helper import sanitize
        original = sanitize._settle_response
        with patch.object(sanitize, '_settle_response', wraps=original) as settle:
            self.assertEqual(redact_response('ordinary diagnostic output\n'), 'ordinary diagnostic output\n')
            self.assertEqual(settle.call_count, 1)

    def test_ansi_prefix_does_not_hide_the_original_exos_context(self):
        for text in ('\x1b[0m configure snmp add community readonly "CANARY"\n',
                     '\x1b[0mconfig system snmp community\nset name "CANARY"\nend\n'):
            for output in paths(text):
                self.assertNotIn('CANARY', output)

    def test_numbered_marker_and_nested_json_escaping_survive_range_tracking(self):
        import json
        text = 'config system snmp community\nset name "CANARY \\" 🐾"\nend\n'
        for ascii_only in (False, True):
            value = json.dumps({'nested': json.dumps({'output': text}, ensure_ascii=ascii_only)},
                               ensure_ascii=ascii_only)
            output = sanitize_object(value)
            self.assertNotIn('CANARY', output)
            self.assertEqual(worker_redact(sanitize_object(output))[0], output)
        self.assertIn('set name <REDACTED:credential#1>', redact_response(text))

    def test_wire_fast_path_keeps_cross_line_worker_anchors(self):
        from netops_helper.sanitize import _needs_worker_before_mask
        from netops.redaction_spans import Marked
        for value in ('set', 'sunset', 'password', 'mycommunity', 'set password', 'ENC word',
                      '"token"', 'word\nnext', '<REDACTED>'):
            self.assertTrue(_needs_worker_before_mask(Marked(value, [(0, len(value))]), ()))
        text = 'config system snmp community\nset name community-one\nend\n'
        for output in paths(text):
            self.assertNotIn('community-one', output)
        for value in ('set password', 'password:'):
            raw = 'config system snmp community\nset name %s\nCANARY\nend\n' % value
            self.assertNotIn('CANARY', worker_redact(sanitize_object(raw))[0])

    def test_complete_result_is_stable_when_enc_consumes_the_next_line(self):
        text = ('config system snmp community\nset name first\nset name ENC\nCANARY\nend\n'
                'configure snmp add community readonly second\n'
                'configure snmp add community readwrite third\n')
        output = redact_response(text)
        self.assertNotIn('CANARY', output)
        self.assertEqual(worker_redact(sanitize_object(output))[0], output)

    def test_quoted_name_also_hides_trailing_words(self):
        for output in paths('config system snmp community\nset name "word" CANARY\nend\n'):
            self.assertNotIn('CANARY', output)

    def test_complete_community_mask_preserves_the_original_worker_floor(self):
        import json
        for ending in ('\n', '\r\n', '\r'):
            text = ('set community <REDACTED:credential#1> set password\nCANARY\n').replace('\n', ending)
            self.assertNotIn('CANARY', redact_response(text))
            for value in (text, {'output': text}, json.dumps({'output': text})):
                self.assertNotIn('CANARY', json.dumps(worker_redact(sanitize_object(value))[0]))

    def test_legacy_cr_consumption_rechecks_the_complete_community_line(self):
        text = ('config system snmp community\nset name ordinary\nend\n'
                'set community ENC\rCANARY\tset comments "public"\n')
        for output in paths(text):
            self.assertNotIn('CANARY', output)
            self.assertEqual(worker_redact(sanitize_object(output))[0], output)

    def test_snmp_user_also_settles_legacy_marker_rewrites(self):
        text = ('config system snmp user\nset auth-pwd CANARY\nend\n'
                'password first\nset password second\n')
        for output in paths(text):
            self.assertNotIn('CANARY', output)
            self.assertEqual(worker_redact(sanitize_object(output))[0], output)
