import importlib.util
from pathlib import Path
import re
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
        self.assertIn('$MinimumVersion = [version]"1.0.13"', tool)
        self.assertIn('$UpgradeFromVersion = "1.0.12"', tool)
        image = re.search(r'(?m)^FROM_IMAGE=(.+)$', (ROOT / 'release/acceptance/release.env').read_text())[1]
        self.assertIn(f'$UpgradeFromImage = "{image}"', tool)

    def test_historical_upgrade_declaration_retains_the_captured_changes(self):
        here = ROOT / 'release/acceptance'
        spec = importlib.util.spec_from_file_location('release_verify_version', here / 'verify_state.py')
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        path = here / 'api-changes-1.0.11-1.0.12.json'
        self.assertTrue(path.is_file(), f'{path.name} is missing: declare the MCP API changes of 1.0.11 -> 1.0.12')
        items, problems, info = verify.load_api_changes(path, {'FROM_VERSION': '1.0.11', 'TO_VERSION': '1.0.12'})
        self.assertEqual(problems, [])
        # The lab MCP capture of released 1.0.11 and the 1.0.12 build (tasks 722 and 724) pins
        # every declared (tool, kind) item and its changed_keys.
        self.assertEqual(sorted((item['tool'], item['kind']) for item in items), [
            ('admin_apply', 'definition'),
            ('admin_doctor', 'definition'),
            ('admin_preview', 'definition'),
            ('admin_schema_apply', 'definition'),
            ('admin_status', 'definition'),
            ('admin_status', 'response'),
            ('admin_unblock', 'added'),
            ('admin_unblock_preview', 'added'),
            ('admin_undo', 'added'),
            ('admin_undo_preview', 'definition'),
            ('config_diff', 'definition'),
            ('config_read', 'definition'),
            ('firewall_policy_hits', 'added'),
            ('fortios_diagnostics', 'definition'),
            ('fortiswitch_overview', 'added'),
            ('locate_endpoint', 'definition'),
            ('read_query_catalog', 'response'),
            ('ssh_read', 'definition'),
            ('switch_read', 'definition'),
            ('triage_flow', 'definition'),
            ('triage_health', 'definition'),
            ('triage_nxos_path', 'added'),
            ('triage_port', 'added'),
            ('triage_routing', 'definition'),
            ('vpc_compare', 'added'),
            ('wifi_triage', 'definition'),
        ])
        self.assertEqual({
            (item['tool'], item['kind']): sorted(item['changed_keys'])
            for item in items if item.get('changed_keys')
        }, {
            ('admin_apply', 'definition'): ['/description'],
            ('admin_doctor', 'definition'): ['/description'],
            ('admin_preview', 'definition'): ['/description'],
            ('admin_schema_apply', 'definition'): ['/description'],
            ('admin_status', 'definition'): ['/description'],
            ('admin_undo_preview', 'definition'): ['/description'],
            ('config_diff', 'definition'): ['/description'],
            ('config_read', 'definition'): ['/description'],
            ('fortios_diagnostics', 'definition'): [
                '/description',
                '/inputSchema/properties/count/description',
                '/inputSchema/properties/max_bytes/description',
                '/inputSchema/properties/timeout/description',
            ],
            ('locate_endpoint', 'definition'): ['/description'],
            ('read_query_catalog', 'response'): [
                '/catalog_sha256',
                '/query_metadata/cisco_ios/arp_table/description',
                '/query_metadata/cisco_ios/cdp_neighbors/description',
                '/query_metadata/cisco_ios/ipv6_neighbors/description',
                '/query_metadata/cisco_ios/lldp_neighbors/description',
                '/query_metadata/cisco_ios/mac_table/description',
                '/query_metadata/cisco_ios/ntp_associations/description',
                '/query_metadata/cisco_nxos/interface_transceiver/parameters/interface/kind',
                '/query_metadata/cisco_nxos/log_messages/description',
                '/query_metadata/cisco_nxos/ntp_associations/description',
                '/query_metadata/cisco_xe/arp_table/description',
                '/query_metadata/cisco_xe/cdp_neighbors/description',
                '/query_metadata/cisco_xe/hsrp_summary/description',
                '/query_metadata/cisco_xe/ipv6_neighbors/description',
                '/query_metadata/cisco_xe/lacp_neighbors/description',
                '/query_metadata/cisco_xe/lldp_neighbors/description',
                '/query_metadata/cisco_xe/mac_table/description',
                '/query_metadata/cisco_xe/ntp_associations/description',
                '/query_metadata/cisco_xe/stp_root/description',
                '/query_metadata/extreme_exos/access_list_counters/description',
                '/query_metadata/extreme_exos/arp_table/description',
                '/query_metadata/extreme_exos/ipv6_neighbors/description',
                '/query_metadata/extreme_exos/lldp_neighbors/description',
                '/query_metadata/extreme_exos/lldp_neighbors_detail/description',
                '/query_metadata/extreme_exos/mac_table/description',
                '/query_metadata/ruckus_unleashed/access_points/description',
                '/total',
            ],
            ('ssh_read', 'definition'): ['/description'],
            ('switch_read', 'definition'): [
                '/description',
                '/inputSchema/properties/table/enum',
            ],
            ('triage_flow', 'definition'): ['/description'],
            ('triage_health', 'definition'): ['/description'],
            ('triage_routing', 'definition'): ['/description'],
            ('wifi_triage', 'definition'): ['/description'],
        })
        self.assertEqual(info['file'], path.name)

    def test_upgrade_declaration_is_valid_for_configured_release(self):
        here = ROOT / 'release/acceptance'
        spec = importlib.util.spec_from_file_location('release_verify_version', here / 'verify_state.py')
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        path = here / 'api-changes-1.0.12-1.0.13.json'
        self.assertTrue(path.is_file(), path.name)
        items, problems, info = verify.load_api_changes(path, {'FROM_VERSION': '1.0.12', 'TO_VERSION': '1.0.13'})
        self.assertEqual(problems, [])
        self.assertIn(('network_overview', 'added'), {(item['tool'], item['kind']) for item in items})
        self.assertEqual(info['file'], path.name)
        env = (here / 'release.env').read_text()
        self.assertIn('TO_IMAGE=netops-candidate:1.0.13', env)
        self.assertIn('FROM_IMAGE=ghcr.io/radek-cerny-soukr/netops@sha256:0b7dc202bbb6a895fb3e382dda1873edf1f4a60fa43790fe57551d6e83e3d579', env)


if __name__ == '__main__':
    unittest.main()
