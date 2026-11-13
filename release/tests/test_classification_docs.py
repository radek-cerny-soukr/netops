"""Keep the historical classification contract and current fixture count separate."""
from pathlib import Path
import json
import unittest
import tomllib

ROOT = Path(__file__).resolve().parents[2]


class ClassificationDocumentation(unittest.TestCase):
    def test_fixed_boundaries_are_documented(self):
        for document in ('components/netops-helper/docs/tools.md',
                         'components/netops-helper/docs/normalization.md',
                         'CHANGELOG.md', 'release/notes-1.0.7.md'):
            text = (ROOT / document).read_text()
            with self.subTest(document=document):
                for term in ('ReDoS', 'permission_denied', 'unsupported', 'not_applicable',
                             'FortiGate-80F', 'FortiADC', 'Ruckus', 'log_messages',
                             'log_interactive_commands', '`truncated` → `ok`',
                             'schema snapshots', 'sequential reads', '1fad86c',
                             'historical', '1023',
                             'coverage.warnings', 'refusal_like_line_in_data',
                             'command', '72', 'transport_error', 'unparsed', 'coverage.complete',
                             '200', '198', 'final data line', '1012', 'endpoint_not_seen_on_neighbor_target'):
                    self.assertIn(term, text)
                self.assertRegex(text, r'historical (?:classifier )?matrix covers 1023 texts')
                for obsolete in ('first response line', 'first-line', 'standalone terminal',
                                 'stricter control-output rule', '768 captures'):
                    self.assertNotIn(obsolete, text)

    def test_current_release_notes_document_current_fixture_count_when_present(self):
        # Phase F supplies the current notes. Earlier phases need not create them,
        # and growing the baseline must never rewrite the 1.0.7 history above.
        version = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
        document = ROOT / 'release' / f'notes-{version}.md'
        if not document.exists():
            return
        captures = json.loads((ROOT / 'components/netops-helper/tests/fixtures/output_status_baseline.json').read_text())
        self.assertRegex(document.read_text(), rf'\b{len(captures)}\b')

    def test_record_paging_has_a_distinct_continuation_name(self):
        for document in ('components/netops-helper/docs/tools.md',
                         'CHANGELOG.md', 'release/notes-1.0.7.md'):
            text = (ROOT / document).read_text()
            with self.subTest(document=document):
                for term in ('has_more', 'next', 'status: "truncated"', '1.0.6'):
                    self.assertIn(term, text)
                self.assertNotIn('`truncated` and `next`', text)


if __name__ == "__main__":
    unittest.main()
