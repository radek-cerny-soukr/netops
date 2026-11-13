"""Every scenario in the unified live-capture input is automatically replayed."""
from pathlib import Path
import json

import pytest

from support.add_capture import import_scenario
from support.replay_capture import load, replay

ROOT = Path(__file__).parent / 'fixtures/real/scenarios'
SCENARIOS = sorted(ROOT.glob('*.json'))
assert SCENARIOS, 'the unified replay collection must not be empty'


@pytest.mark.parametrize('path', SCENARIOS, ids=lambda path: path.stem)
def test_all_live_capture_scenarios(path):
    for capture in load(path)['captures']:
        replay(capture)


def test_import_uses_one_map_for_all_commands_and_manual_expectations(tmp_path):
    source = load(SCENARIOS[0])
    first = source['captures'][0]
    first['stdout'] = '101 0000.5e00.53aa DYNAMIC Gi1/0/5\n'
    first.update(platform='cisco_ios', table='mac_entry', query='mac_table', command='show mac address-table')
    first['expected'] = {'status': 'ok', 'record_count': 1, 'unparsed_count': 0,
                         'records': [{'mac': '00:00:5e:00:53:aa', 'port': 'GigabitEthernet1/0/5', 'vlan_id': 101}]}
    second = dict(first, stdout='101 0000.5e00.53aa DYNAMIC Gi1/0/5\n')
    source['captures'] = [first, second]
    for number, capture in enumerate(source['captures']):
        capture['file'] = f'raw-{number}.txt'
        (tmp_path / capture['file']).write_text(capture.pop('stdout'))
    manifest = tmp_path / 'manifest.json'
    manifest.write_text(json.dumps(source))
    result = import_scenario(manifest, tmp_path / 'out/scenario.json')
    assert result['captures'][0]['stdout'] == result['captures'][1]['stdout']
    assert '0000.5e00.53aa' not in json.dumps(result)
    assert '00:00:5e:00:53:aa' not in json.dumps(result)
    for capture in result['captures']:
        replay(capture)


def test_import_requires_independent_expectations_and_never_overwrites(tmp_path):
    manifest = tmp_path / 'manifest.json'
    source = load(SCENARIOS[0])
    capture = source['captures'][0]
    (tmp_path / 'capture.txt').write_text(capture.pop('stdout'))
    capture['file'] = 'capture.txt'
    source['expected_source'] = ''
    manifest.write_text(json.dumps(source))
    output = tmp_path / 'scenario.json'
    with pytest.raises(ValueError, match='independent'):
        import_scenario(manifest, output)
    assert not output.exists()
    source['expected_source'] = 'manual CLI row inspection'
    manifest.write_text(json.dumps(source))
    import_scenario(manifest, output)
    with pytest.raises(FileExistsError):
        import_scenario(manifest, output)


@pytest.mark.parametrize('credential', [
    'set password synthetic-canary', 'authentication-key synthetic-canary',
    'key-string synthetic-canary', 'pre-shared-key synthetic-canary',
    'wpa-psk synthetic-canary', 'snmp-server user example group v3 auth sha synthetic-canary',
    'snmp-server user example group v3 priv aes synthetic-canary',
    'set auth-password synthetic-canary', 'set priv-password synthetic-canary',
])
def test_import_refuses_credentials_before_writing(tmp_path, credential):
    source = load(SCENARIOS[0])
    source['captures'][0].pop('stdout')
    source['captures'][0]['file'] = 'private.txt'
    (tmp_path / 'private.txt').write_text(credential + '\n')
    manifest = tmp_path / 'manifest.json'
    manifest.write_text(json.dumps(source))
    with pytest.raises(ValueError, match='credentials'):
        import_scenario(manifest, tmp_path / 'out.json')
    assert not (tmp_path / 'out.json').exists()
