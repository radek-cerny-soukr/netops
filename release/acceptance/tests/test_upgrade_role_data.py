import copy
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import generate_api_changes as generator
import verify_state as verify
from test_verify_state_api_changes import mcp


class UpgradeRoleData(unittest.TestCase):
    def test_elapsed_audit_age_is_dynamic_but_identity_and_findings_are_not(self):
        before, after = mcp(), mcp()
        row = after['calls']['audit_status']['reply']['result']['structuredContent']['devices'][0]
        row['age_hours'] = 1000.0
        result = verify.compare_mcp(before, after, '1.0.6', '1.0.7', [], [])
        self.assertTrue(result[2], result[3])
        for key in ('run_id', 'findings_total'):
            damaged = copy.deepcopy(after)
            damaged['calls']['audit_status']['reply']['result']['structuredContent']['devices'][0][key] = 999
            self.assertFalse(verify.compare_mcp(before, damaged, '1.0.6', '1.0.7', [], [])[2])

    def test_coverage_requires_an_exact_intentional_declaration(self):
        before, after = mcp(), mcp()
        after['calls']['audit_status']['reply']['result']['structuredContent']['devices'][0]['coverage'] = {'complete': True}
        self.assertFalse(verify.compare_mcp(before, after, '1.0.6', '1.0.7', [], [])[2])
        with self.assertRaisesRegex(ValueError, 'no reviewed reason for: audit_status response'):
            generator.generate(before, after, '1.0.6', '1.0.7')
        declaration = generator.generate(before, after, '1.0.6', '1.0.7', {'audit_status response': 'Coverage added.'})
        self.assertEqual([(c['tool'], c['kind'], c['reason']) for c in declaration['changes']],
                         [('audit_status', 'response', 'Coverage added.')])
        self.assertTrue(verify.compare_mcp(before, after, '1.0.6', '1.0.7', declaration['changes'], [])[2])
        after['calls']['audit_status']['reply']['result']['structuredContent']['devices'][0]['coverage']['complete'] = False
        self.assertFalse(verify.compare_mcp(before, after, '1.0.6', '1.0.7', declaration['changes'], [])[2])

    def test_admin_request_identity_and_completion_are_compared(self):
        for field, value in (('change_id', 'b' * 32), ('request_id', 'another-request'), ('status', 'running')):
            before, after = mcp(), mcp()
            after['calls']['admin_status']['reply']['result']['structuredContent'][field] = value
            result = verify.compare_mcp(before, after, '1.0.6', '1.0.7', [], [])
            self.assertFalse(result[2], field)

    def test_missing_roles_cannot_pass_as_identical_empty_replies(self):
        for name in ('audit_status', 'admin_status'):
            missing = mcp()
            del missing['calls'][name]
            result = verify.compare_mcp(missing, missing, '1.0.6', '1.0.7', [], [])
            self.assertFalse(result[2])
            with self.assertRaisesRegex(ValueError, 'missing response'):
                generator.generate(missing, missing, '1.0.6', '1.0.7')

    def test_reasons_come_from_a_reviewed_file_and_a_draft_placeholder_is_refused(self):
        import json
        import tempfile
        before, after = mcp(), mcp()
        after['calls']['audit_status']['reply']['result']['structuredContent']['devices'][0]['coverage'] = {'complete': True}
        draft = generator.generate(before, after, '1.0.6', '1.0.7', draft=True)
        self.assertTrue(draft['changes'][0]['reason'].startswith('TODO(api-review)'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'api-changes-1.0.6-1.0.7.json'
            path.write_text(json.dumps(draft))
            items, problems, _ = verify.load_api_changes(str(path), {'FROM_VERSION': '1.0.6', 'TO_VERSION': '1.0.7'})
            self.assertEqual(items, [])
            self.assertIn('unreviewed placeholder', problems[0])
            reviewed = dict(draft, changes=[dict(draft['changes'][0], reason='Coverage added.')])
            path.write_text(json.dumps(reviewed))
            again = generator.generate(before, after, '1.0.6', '1.0.7', generator.load_reasons(str(path)))
            self.assertEqual(again, reviewed)
        source = (HERE / 'generate_api_changes.py').read_text()
        self.assertNotIn('1.0.7', source)

    def test_prompts_and_capabilities_are_compared_like_tools(self):
        before, after = mcp(), mcp()
        after['calls']['prompts/list'] = {'http': 200, 'reply': {'result': {'prompts': [
            {'name': 'wifi_client_connectivity', 'description': 'Wi-Fi', 'arguments': [{'name': 'target', 'required': True}]}]}}}
        after['calls']['initialize'] = {'http': 200, 'reply': {'result': {'capabilities': {'prompts': {'listChanged': False}}}}}
        before['calls']['initialize'] = {'http': 200, 'reply': {'result': {'capabilities': {}}}}
        result = verify.compare_mcp(before, after, '1.0.6', '1.0.7', [], [])
        self.assertFalse(result[0])
        self.assertIn('prompt:wifi_client_connectivity added', result[1])
        self.assertIn('mcp:capabilities definition added_keys /prompts', result[1])
        declaration = generator.generate(before, after, '1.0.6', '1.0.7', {
            'prompt:wifi_client_connectivity added': 'New prompt.', 'mcp:capabilities definition': 'Prompts capability.'})
        self.assertTrue(verify.compare_mcp(before, after, '1.0.6', '1.0.7', declaration['changes'], [])[0])
        changed = copy.deepcopy(after)
        changed['calls']['prompts/list']['reply']['result']['prompts'][0]['description'] = 'other'
        self.assertFalse(verify.compare_mcp(after, changed, '1.0.7', '1.0.7', [], [])[0])


if __name__ == '__main__':
    unittest.main()
