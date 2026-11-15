import importlib.util
import json
from pathlib import Path
import re
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleaseVersion(unittest.TestCase):
    def test_product_build_and_candidate_use_one_version(self):
        version = re.search(r'__version__ = "([^"]+)"', (ROOT / 'src/netops/__init__.py').read_text())[1]
        self.assertEqual(tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version'], version)
        dockerfile = (ROOT / 'Dockerfile').read_text()
        self.assertIn(f'org.opencontainers.image.version="{version}"', dockerfile)
        self.assertIn(f'/dist/netops-{version}-py3-none-any.whl', dockerfile)
        workflow = (ROOT / '.github/workflows/candidate.yml').read_text()
        self.assertRegex(workflow, rf'(?m)^  VERSION: {re.escape(version)}$')
        self.assertTrue((ROOT / f'release/notes-{version}.md').is_file())

    def test_signing_gate_requires_the_current_predecessor(self):
        tool = (ROOT / 'release/sign/netops-release-sign.ps1').read_text()
        self.assertIn('$MinimumVersion = [version]"1.0.9"', tool)
        self.assertIn('$UpgradeFromVersion = "1.0.8"', tool)
        image = re.search(r'(?m)^FROM_IMAGE=(.+)$', (ROOT / 'release/acceptance/release.env').read_text())[1]
        self.assertIn(f'$UpgradeFromImage = "{image}"', tool)

    def test_upgrade_declaration_is_valid_for_configured_release(self):
        here = ROOT / 'release/acceptance'
        spec = importlib.util.spec_from_file_location('release_verify_version', here / 'verify_state.py')
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        path = here / 'api-changes-1.0.8-1.0.9.json'
        items, problems, info = verify.load_api_changes(path, {'FROM_VERSION': '1.0.8', 'TO_VERSION': '1.0.9'})
        self.assertEqual(problems, [])
        # 1.0.9 adds admin_undo_preview and findings_summary, the arguments expected_plan_sha256 (admin_apply) and
        # source_port (triage_flow), suppressions_configured in audit_status and two catalogue queries.
        self.assertEqual(sorted((item['tool'], item['kind']) for item in items),
                         [('admin_apply', 'definition'), ('admin_preview', 'definition'), ('admin_undo_preview', 'added'),
                          ('audit_status', 'response'), ('findings_summary', 'added'), ('read_query_catalog', 'response'),
                          ('triage_flow', 'definition')])
        self.assertEqual(info['file'], path.name)
        env = (here / 'release.env').read_text()
        self.assertIn('TO_IMAGE=netops-candidate:1.0.9', env)
        self.assertIn('FROM_IMAGE=ghcr.io/radek-cerny-soukr/netops@sha256:ad9416496b39aceb5313edd0e48d2939172513f034353e188726b4c2a262649f', env)


if __name__ == '__main__':
    unittest.main()
