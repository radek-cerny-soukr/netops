"""The lab measurement tables of the IOS and EOS vendor notes are generated from tests/fixtures/real."""
from pathlib import Path
import json
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_measurement_tables_are_current():
    result = subprocess.run([sys.executable, '-I', str(ROOT / 'tests/support/render_lab_measurements.py'), '--check'],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_junos_account_guidance_keeps_the_builtin_read_only_boundary():
    guide = (ROOT / 'docs/read-only-accounts.md').read_text().split('### Junos OS\n', 1)[1].split('\n### ', 1)[0]
    assert 'Use the built-in `read-only` login class' in guide
    assert 'not a deployable read-only recipe' in guide
    assert 'show system rollback 0' in guide
    assert 'known limitation' in guide and '`permission_denied`' in guide and 'syslog collector' in guide
    assert 'does not recommend granting those broader permissions' in guide
    assert 'permissions [' not in guide and 'deny-commands "' not in guide
    notes = (ROOT / 'docs/vendor-cli-references/juniper-junos.md').read_text()
    assert 'forward logs through syslog' in notes
    assert 'NetOps does not recommend the broader permissions' in notes


def test_measured_nxos_vpc_refusal_is_not_a_success():
    renderer = runpy.run_path(str(ROOT / 'tests/support/render_lab_measurements.py'))
    directory = ROOT / 'tests/fixtures/real/cisco_nxos/nexus9300v_9.3.12'
    index = json.loads((directory / 'index.json').read_text())
    assert renderer['cell'](directory, 'vpc_orphan_ports', index) == 'command failed, exit status 244'
    assert renderer['cell'](directory, 'vpc_consistency', index) == 'empty'
    assert renderer['cell'](directory, 'version', index).startswith('ok, ')
    rendered = renderer['render']('cisco_nxos', (('nexus9300v_9.3.12', 'Nexus'),))
    row = next(line for line in rendered.splitlines() if line.startswith('| `vpc_orphan_ports`'))
    assert '| command failed, exit status 244 | live |' in row
