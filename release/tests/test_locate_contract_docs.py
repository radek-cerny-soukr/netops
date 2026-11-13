"""Candidate #9: published limits and verdicts agree with the endpoint contract."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'components/netops-helper'


class LocateContractDocumentation(unittest.TestCase):
    def test_published_locate_limits_and_partial_coverage(self):
        readme = (ROOT / 'README.md').read_text()
        guide = (HELPER / 'docs/tools.md').read_text().split('## Endpoint location (locate_endpoint)', 1)[1].split('\n## ', 1)[0]
        for phrase in ('1–64', '40 reads', '8 reads per alias', '59.5-second deadline'):
            self.assertIn(phrase, readme)
        for phrase in ('at most eight', '59.5 seconds from the parent call, including worker startup',
                       '60-second boundary', '40 physical CLI reads', 'eight reads per alias',
                       'limits.target_reads', '`incomplete`', 'coverage.complete',
                       'unfinished_targets', 'edge_beyond_enrolled_targets'):
            self.assertIn(phrase, guide)
        tree = ast.parse((HELPER / 'src/netops_helper/locate.py').read_text())
        constants = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                     if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                     and node.targets[0].id in ('MAX_TARGETS', 'MAX_READS', 'MAX_SECONDS', 'MAX_PARALLEL')}
        self.assertEqual(constants, {'MAX_TARGETS': 64, 'MAX_READS': 40, 'MAX_SECONDS': 59.5, 'MAX_PARALLEL': 8})
        tree = ast.parse((HELPER / 'src/netops_helper/server.py').read_text())
        descriptor = next(ast.get_docstring(node) for node in tree.body
                          if isinstance(node, ast.FunctionDef) and node.name == 'locate_endpoint')
        for phrase in ('1-64', 'eight concurrent', 'below 60 seconds', 'unfinished targets'):
            self.assertIn(phrase, descriptor)


if __name__ == '__main__':
    unittest.main()
