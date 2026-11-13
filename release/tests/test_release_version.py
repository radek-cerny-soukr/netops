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
        self.assertIn('$MinimumVersion = [version]"1.0.8"', tool)
        self.assertIn('$UpgradeFromVersion = "1.0.7"', tool)
        image = re.search(r'(?m)^FROM_IMAGE=(.+)$', (ROOT / 'release/acceptance/release.env').read_text())[1]
        self.assertIn(f'$UpgradeFromImage = "{image}"', tool)

    def test_upgrade_declaration_is_valid_for_configured_release(self):
        here = ROOT / 'release/acceptance'
        spec = importlib.util.spec_from_file_location('release_verify_version', here / 'verify_state.py')
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        path = here / 'api-changes-1.0.7-1.0.8.json'
        items, problems, info = verify.load_api_changes(path, {'FROM_VERSION': '1.0.7', 'TO_VERSION': '1.0.8'})
        self.assertEqual(problems, [])
        # The runtime change declares no API change; the Helper adds the cdp_neighbor table value to the switch_read
        # argument. Existing Linux catalogue commands and descriptions stay unchanged.
        self.assertEqual(sorted((item['tool'], item['kind']) for item in items),
                         [('switch_read', 'definition')])
        self.assertEqual(info['file'], path.name)
        env = (here / 'release.env').read_text()
        self.assertIn('TO_IMAGE=netops-candidate:1.0.8', env)
        self.assertIn('FROM_IMAGE=ghcr.io/radek-cerny-soukr/netops@sha256:e04b19091819897e1bb4dec11416253b1dd598c18d5567325583b7e7e5fb8dfc', env)


if __name__ == '__main__':
    unittest.main()
