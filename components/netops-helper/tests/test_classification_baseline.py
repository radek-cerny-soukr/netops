"""Compare every fixture/profile/rc against the independent 1fad86c oracle."""
import json
from pathlib import Path

from netops_helper import engine, normalization as n
from netops_helper.query_catalog import READ_QUERIES
from support.classification_fixtures import PROFILES, PAGER_CORRECTIONS, real_captures

ROOT = Path(__file__).parent / 'fixtures'


def test_all_captures_against_historical_classifier():
    assert set(PROFILES) == set(READ_QUERIES) | {None}
    baseline = json.loads((ROOT / 'output_status_baseline.json').read_text())
    captures = real_captures(ROOT)
    assert set(captures) == set(baseline)
    assert 'v1/ruckus_show_wlan_all.golden.txt' in baseline
    assert {name for name in baseline if name.startswith('ospf_live20.json#')} == {
        'ospf_live20.json#' + name for name in ('iosv', 'nxos', 'vjunos', 'iolxe', 'ceos')}
    fortigate = 'real/fortinet/fortigate80f_8.0.2_build0251/local_20261110/'
    assert {name for name in baseline if name.startswith(fortigate)} == {
        fortigate + name + '.txt' for name in ('physical', 'vlans', 'lldp', 'bridge_empty')}
    assert all(case['profile'] in PROFILES for case in baseline.values())
    differences = []
    for name, case in baseline.items():
        _, output, command, _ = captures[name]
        seen = set()
        for group in case['matrix']:
            for profile in group['profiles']:
                seen.add(profile)
                for sent in (None, command, 'unrelated command'):
                    assert bool(profile and engine._cli_refused(profile, output, command=sent)) == group['cli_refused'], (name, profile)
                    assert bool(profile and n.permission_refused(profile, output, command=sent)) == group['permission_refused'], (name, profile)
                    assert bool(profile and n.template_refused(profile, output, command=sent)) == group['template_refused'], (name, profile)
                    assert n.refusal_hint(profile, output, command=sent) == group['refusal_hint'], (name, profile)
                    for index, rc in enumerate((0, 1, 250)):
                        old = group['status'][index]
                        current = n.output_status(output, rc=rc, profile=profile, command=sent)
                        if current != old:
                            differences.append((name, profile, rc, old, current))
                            # N2 is explicitly retained by TASK: these two historical
                            # false pager truncations cannot also equal 1fad86c.
                            assert name in PAGER_CORRECTIONS and old == 'truncated'
                            expected = 'ok' if rc == 0 or profile == 'extreme_exos' and rc == 250 else 'transport_error'
                            assert current == expected
                assert bool(profile and engine._control_refused(profile, output)) == group['cli_refused']
        assert seen == set(PROFILES)
    assert len(differences) == 2 * len(PROFILES) * 3 * 3
    print('classifier_matrix captures=%d profiles=%d rc=0,1,250 command_variants=3 raw_differences=%d refusal_differences=0' %
          (len(captures), len(PROFILES), len(differences) // 3))

