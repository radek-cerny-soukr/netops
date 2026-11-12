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
        self.assertIn('$MinimumVersion = [version]"1.0.7"', tool)
        self.assertIn('$UpgradeFromVersion = "1.0.6"', tool)
        image = re.search(r'(?m)^FROM_IMAGE=(.+)$', (ROOT / 'release/acceptance/release.env').read_text())[1]
        self.assertIn(f'$UpgradeFromImage = "{image}"', tool)

    def test_upgrade_declaration_is_valid_for_configured_release(self):
        here = ROOT / 'release/acceptance'
        spec = importlib.util.spec_from_file_location('release_verify_version', here / 'verify_state.py')
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        path = here / 'api-changes-1.0.6-1.0.7.json'
        items, problems, info = verify.load_api_changes(path, {'FROM_VERSION': '1.0.6', 'TO_VERSION': '1.0.7'})
        self.assertEqual(problems, [])
        self.assertEqual({i['tool'] for i in items if i['kind'] == 'added'},
                         {'switch_read', 'locate_endpoint', 'triage_flow', 'wifi_clients', 'wifi_aps_live', 'wifi_rogue', 'wifi_triage'}
                         | {'prompt:' + name for name in ('internet_or_vpn', 'everything_slow', 'fortiadc_backend_down',
                                                          'tls_certificate_error', 'wifi_client_connectivity')})
        self.assertTrue(any(i['tool'] == 'audit_status' and i['kind'] == 'response' for i in items))
        env = (here / 'release.env').read_text()
        self.assertIn('TO_IMAGE=netops-candidate:1.0.7', env)
        self.assertIn('FROM_IMAGE=ghcr.io/radek-cerny-soukr/netops@sha256:20085d06a43ea4f0a57053f2dd35ce69709b43bfefd9d2a3cd8b1783c1e435fe', env)


if __name__ == '__main__':
    unittest.main()
