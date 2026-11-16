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
        self.assertIn('$MinimumVersion = [version]"1.0.10"', tool)
        self.assertIn('$UpgradeFromVersion = "1.0.9"', tool)
        image = re.search(r'(?m)^FROM_IMAGE=(.+)$', (ROOT / 'release/acceptance/release.env').read_text())[1]
        self.assertIn(f'$UpgradeFromImage = "{image}"', tool)

    def test_upgrade_declaration_is_valid_for_configured_release(self):
        here = ROOT / 'release/acceptance'
        spec = importlib.util.spec_from_file_location('release_verify_version', here / 'verify_state.py')
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        path = here / 'api-changes-1.0.9-1.0.10.json'
        self.assertTrue(path.is_file(), f'{path.name} is missing: declare the MCP API changes of 1.0.9 -> 1.0.10')
        items, problems, info = verify.load_api_changes(path, {'FROM_VERSION': '1.0.9', 'TO_VERSION': '1.0.10'})
        self.assertEqual(problems, [])
        # 1.0.10 changes only the description of admin_apply (the FortiADC pool member table of Admin).
        self.assertEqual(sorted((item['tool'], item['kind']) for item in items), [('admin_apply', 'definition')])
        self.assertEqual(sorted(info['changes'][0]['changed_keys']), ['/description'])
        self.assertEqual(info['file'], path.name)
        env = (here / 'release.env').read_text()
        self.assertIn('TO_IMAGE=netops-candidate:1.0.10', env)
        self.assertIn('FROM_IMAGE=ghcr.io/radek-cerny-soukr/netops@sha256:94cec4ff7ec7d83710e0acf3e39ba5209212a01ec7d17ba3fbc610d89af7ce51', env)


if __name__ == '__main__':
    unittest.main()
