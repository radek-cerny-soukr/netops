import ast
import unittest
from pathlib import Path
import re


class DistributionReadmeTest(unittest.TestCase):
    def test_distribution_is_github_only(self):
        readme = (Path(__file__).resolve().parents[1] / 'README.md').read_text()
        self.assertIn('NetOps is distributed exclusively through GitHub: the source repository, GitHub Releases, and container images in GitHub Container Registry (GHCR). It is not distributed through PyPI.', readme)
        self.assertNotIn('not published to PyPI by default', readme)

    def test_install_and_upgrade_instructions_follow_product_version(self):
        root = Path(__file__).resolve().parents[1]
        import re
        version = re.search(r'__version__ = "([^"]+)"', (root / 'src/netops/__init__.py').read_text())[1]
        readme = (root / 'README.md').read_text()
        guide = (root / 'docs/quickstart-1.0.md').read_text()
        for document in (readme, guide):
            downloads = re.findall(r'netops/releases/download/v([^/]+)/', document)
            self.assertTrue(downloads)
            self.assertEqual(set(downloads), {version})
            self.assertIn(f'netops-{version}-SHA256SUMS.sigstore.json', document)
            self.assertIn(f'netops-{version}-SHA256SUMS', document)
        self.assertIn('a 1.0.7 instance', readme)
        self.assertIn('"upgrade":{"from":"1.0.7","to":"1.0.8"}', guide)
        self.assertIn('No inventory or credential changes are required', guide)
        self.assertIn('lookup_prefixes', guide)
        self.assertIn('keyboard-interactive', guide)
        self.assertIn('five-second', guide)
        self.assertIn('netops-108', guide)

    def test_current_release_documents_page_boundary_security_fix(self):
        root = Path(__file__).resolve().parents[1]
        notes = (root / 'release/notes-1.0.7.md').read_text()
        security = notes.split('## Security\n', 1)[1].split('\n## ', 1)[0]
        for phrase in ('1.0.6', 'ssh_read', 'schema_read', 'session', 'transport',
                       'page boundary', 'two pages', 'before hashing and pagination', 'Upgrade to 1.0.7'):
            self.assertIn(phrase, security)
        changelog = (root / 'CHANGELOG.md').read_text()
        heading = re.search(r'(?m)^## 1\.0\.7 - (?:TODO\(release-date\)|\d{4}-\d{2}-\d{2})$', changelog)
        current = changelog[heading.end():].split('\n## ', 1)[0]
        self.assertIn('### Security', current)
        self.assertIn('page boundary', current)

    def test_documented_tool_counts_follow_the_source(self):
        root = Path(__file__).resolve().parents[1]

        def assigned(path, name):
            for node in ast.parse((root / path).read_text()).body:
                if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
                    value = node.value
                    return [key.value for key in value.keys] if isinstance(value, ast.Dict) else [item.value for item in value.elts]
            raise AssertionError(name)

        helper = len(assigned('components/netops-helper/src/netops_helper/proxy.py', 'TOOL_ARGUMENT_SCHEMAS'))
        auditor = len(assigned('components/netops-auditor/src/netops_auditor/mcp_server.py', 'TOOL_NAMES'))
        admin = len(assigned('components/netops-admin/src/netops_admin/mcp_server.py', 'TOOL_NAMES'))
        total, without_admin = helper + auditor + admin, helper + auditor
        guide = (root / 'docs/quickstart-1.0.md').read_text()
        self.assertIn(f'It prints `{total}`: {helper} Helper, {auditor} Auditor and {admin} Admin tools. '
                      f'On an instance initialized with `init --disable-admin` it prints `{without_admin}`', guide)
        self.assertIn(f'the tool count of step 9 is then `{without_admin}` instead of `{total}`', guide)
        tools = (root / 'components/netops-helper/docs/tools.md').read_text()
        self.assertIn(f'It exposes {helper} Helper tool names', tools)
        self.assertEqual((helper, auditor, admin), (26, 7, 6))

    def test_normalized_coverage_matrix_and_legend_stay_consistent(self):
        root = Path(__file__).resolve().parents[1]
        documents = [(root / name).read_text() for name in ('README.md', 'docs/verified-support.md')]
        blocks = [text.split('**✓**', 1)[1].split('Catalogue, triage', 1)[0] for text in documents]
        self.assertEqual(*blocks)
        header = next(line for line in blocks[0].splitlines() if line.startswith('| OS '))
        lag_column = [cell.strip() for cell in header.split('|')[1:-1]].index('LAG')
        for line in blocks[0].splitlines():
            if not line.startswith('| ') or line.startswith('| OS '):
                continue
            cells = [cell.strip() for cell in line.split('|')[1:-1]]
            if any(profile in cells[0] for profile in ('extreme_exos', 'cisco_', 'arista_eos', 'juniper_junos')):
                self.assertIn('⁶', cells[lag_column], cells[0])
            for label in ('replay', 'transit', 'ARP'):
                if label in cells[-1]:
                    self.assertIn(f'**{label}** means', documents[0])
        self.assertNotIn('shared router reads', blocks[0])

    def test_canonical_value_release_links_resolve_to_the_contract(self):
        root = Path(__file__).resolve().parents[1]
        for name in ('CHANGELOG.md', 'release/notes-1.0.7.md'):
            text = (root / name).read_text()
            matches = re.findall(r'\[[^\]]+\]\(([^)]+#operational-value-names)\)', text)
            self.assertEqual(len(matches), 1, name)
            path, anchor = matches[0].split('#')
            target = (root / name).parent / path
            self.assertIn('## Operational value names', target.read_text())
