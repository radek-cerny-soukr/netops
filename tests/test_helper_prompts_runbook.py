import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from netops import prompts  # noqa: E402


class FakeGateway:
    def __init__(self):
        self.prompts = {}

    def prompt(self, name, description):
        def decorate(function):
            self.prompts[name] = function
            return function
        return decorate


class RunbookTest(unittest.TestCase):
    def test_packaged_copy_matches_canonical_document(self):
        canonical = ROOT / 'docs/troubleshooting-by-symptom.md'
        packaged = ROOT / 'src/netops/troubleshooting-by-symptom.md'
        self.assertEqual(packaged.read_bytes(), canonical.read_bytes())
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/sync_troubleshooting_prompts.py'), '--check'])
        self.assertEqual(result.returncode, 0)

    def test_canonical_document_has_expected_headings(self):
        guide = (ROOT / 'docs/troubleshooting-by-symptom.md').read_text(encoding='utf-8')
        common, sections = prompts.load_sections(guide)
        self.assertEqual(len(sections), 5)
        self.assertTrue(common)

    def test_renamed_heading_gives_readable_error(self):
        guide = (ROOT / 'docs/troubleshooting-by-symptom.md').read_text(encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'heading not found'):
            prompts.load_sections(guide.replace('## 3. ', '## Three. '))
        with self.assertRaisesRegex(ValueError, 'heading not found'):
            prompts.load_sections(guide.replace('## Before you start', '## Start'))

    def test_register_registers_five_prompts_from_canonical_document(self):
        gateway = FakeGateway()
        self.assertTrue(prompts.register(gateway))
        self.assertEqual(len(gateway.prompts), 5)

    def test_middleware_names_are_the_registered_names(self):
        gateway = FakeGateway()
        prompts.register(gateway)
        self.assertEqual(prompts.PROMPT_NAMES, frozenset(gateway.prompts))
        self.assertEqual(len(prompts.PROMPT_NAMES), len(prompts.TITLES))
        for number, (name, function) in enumerate(gateway.prompts.items(), 1):
            self.assertEqual(function.__name__, name)
            self.assertIn(f'## {number}. {prompts.TITLES[number - 1]}', function('fw1'))

    def test_wifi_prompt_matches_the_wifi_triage_contract(self):
        gateway = FakeGateway()
        prompts.register(gateway)
        text = gateway.prompts['wifi_client_connectivity']('fw1')
        self.assertNotIn('enrolled IPv4', text)
        self.assertIn('need not be enrolled', text)
        self.assertIn('locate_endpoint', text)
        guide = (ROOT / 'docs/troubleshooting-by-symptom.md').read_text(encoding='utf-8')
        for stale in ('REST token path pending', 'not in this build', "separate triage budget",
                      "manual queries keep their own"):
            self.assertNotIn(stale, guide)

    def test_rendered_text_has_no_relative_links_and_no_empty_address(self):
        gateway = FakeGateway()
        prompts.register(gateway)
        for function in gateway.prompts.values():
            text = function('fw1')
            self.assertNotIn('](', text)
            self.assertNotIn('\nAddress:', text)
            self.assertIn('\nAddress: 198.51.100.1', function('fw1', '198.51.100.1'))

    def test_register_logs_instead_of_raising_on_bad_document(self):
        original = prompts.TITLES
        prompts.TITLES = ('No such heading',) * 5
        try:
            gateway = FakeGateway()
            with self.assertLogs(prompts.LOG, 'ERROR'):
                self.assertFalse(prompts.register(gateway))
            self.assertEqual(gateway.prompts, {})
        finally:
            prompts.TITLES = original


if __name__ == '__main__':
    unittest.main()
