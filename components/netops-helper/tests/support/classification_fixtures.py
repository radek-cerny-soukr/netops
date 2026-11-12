"""Discover captures independently and reproduce the 1fad86c classifier matrix.

CLI regenerates the historical oracle using only code read from git, never HEAD.
"""
import ast
import json
from pathlib import Path
import re
import subprocess
import types


PROFILES = ('arista_eos', 'cisco_ios', 'cisco_nxos', 'cisco_xe', 'extreme_exos',
            'fortiadc', 'fortinet', 'juniper_junos', 'juniper_junos_els', 'linux',
            'ruckus_unleashed', None)
PAGER_CORRECTIONS = {
    'real/juniper_junos_els/vjunosswitch_26.2R1.7/log_messages.admin.txt',
    'real/juniper_junos_els/vjunosswitch_26.2R1.7/log_interactive_commands.admin.txt',
}


def real_captures(root: Path) -> dict:
    captures = {}
    aliases = {'exos': 'extreme_exos', 'ceos': 'arista_eos', 'iosv': 'cisco_ios',
               'iosvl2': 'cisco_ios', 'iolxe': 'cisco_xe', 'nxos': 'cisco_nxos', 'vjunos': 'juniper_junos_els'}
    for path in sorted(root.rglob('*.txt')):
        name = path.relative_to(root).as_posix()
        parts = path.relative_to(root).parts
        candidate = parts[1] if parts[0] in {'real', 'docs', 'tables'} else path.stem
        if candidate.startswith('lab_endpoints'):
            candidate = parts[2]
        candidate = candidate.removeprefix('full_').removeprefix('synthetic_')
        profile = aliases.get(candidate, candidate)
        if profile not in PROFILES:
            profile = next((p for p in PROFILES if p and candidate.startswith(p)), None)
        if path.name.startswith('fortios_'):
            profile = 'fortinet'
        index = path.parent / 'index.json'
        metadata = json.loads(index.read_text()).get(path.stem, {}) if index.exists() else {}
        captures[name] = (profile, path.read_text(), metadata.get('command'), metadata.get('rc', 0))
    for path in sorted(root.glob('fortios_*.json')):
        captures[path.name] = ('fortinet', path.read_text(), None, 0)
        for member, body in json.loads(path.read_text()).get('members', {}).items():
            for command, output in body.get('responses', {}).items():
                lines = output.replace('\r', '').splitlines()
                if lines and lines[0] == command:
                    lines = lines[1:]
                if lines and lines[-1].rstrip().endswith(('#', '$')):
                    lines = lines[:-1]
                captures[path.name + '#' + member + ':' + command] = ('fortinet', '\n'.join(lines), command, 0)
    # The live OSPF captures are stored as structured records rather than .txt.
    ospf = root / 'ospf_live20.json'
    for target, capture in json.loads(ospf.read_text()).items():
        captures[ospf.name + '#' + target] = (aliases[target], capture['stdout'], capture['command'], 0)
    for path in sorted((root / 'tables').glob('*.json')):
        for table, output in json.loads(path.read_text()).items():
            assert isinstance(output, str)
            captures['tables/' + path.name + '#' + table] = (path.stem, output, None, 0)
    v1 = root.parents[3] / 'tests/v1/fixtures'
    for pattern, profile in (('fortiadc*.conf', 'fortiadc'), ('fortiadc*.txt', 'fortiadc'),
                             ('ruckus*.txt', 'ruckus_unleashed')):
        for path in sorted(v1.glob(pattern)):
            captures['v1/' + path.name] = (profile, path.read_text(), None, 0)
    return captures


def historical_classifier(repository, revision='1fad86c'):
    prefix = 'components/netops-helper/src/netops_helper/'
    def source(name):
        return subprocess.check_output(['git', '-C', str(repository), 'show',
                                        revision + ':' + prefix + name + '.py'], text=True)
    normalization = types.ModuleType('historical_normalization')
    exec(compile(source('normalization'), '<historical_normalization>', 'exec'), normalization.__dict__)
    tree = ast.parse(source('engine'))
    names = {'_CISCO_AUTOCOMMAND_REFUSAL', '_JUNOS_REFUSAL', '_CLI_REFUSALS'}
    nodes = [node for node in tree.body
             if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets)
             or isinstance(node, ast.FunctionDef) and node.name == '_cli_refused']
    assert len(nodes) == 4
    namespace = {'re': re, 'normalization': normalization}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<historical_refusals>', 'exec'), namespace)
    return normalization, namespace['_cli_refused']


def historical_matrix(repository):
    root = repository / 'components/netops-helper/tests/fixtures'
    norm, refused = historical_classifier(repository)
    baseline = {}
    for name, (native, output, command, rc) in real_captures(root).items():
        groups = {}
        for profile in PROFILES:
            signature = (tuple(norm.output_status(output, rc=code, profile=profile) for code in (0, 1, 250)),
                         bool(profile and refused(profile, output)),
                         bool(profile and norm.permission_refused(profile, output)),
                         bool(profile and norm.template_refused(profile, output)),
                         norm.refusal_hint(profile, output))
            groups.setdefault(signature, []).append(profile)
        baseline[name] = {'profile': native, 'rc': rc,
                          'matrix': [dict(profiles=profiles, status=list(signature[0]),
                                          cli_refused=signature[1], permission_refused=signature[2],
                                          template_refused=signature[3], refusal_hint=signature[4])
                                     for signature, profiles in groups.items()]}
    return baseline


if __name__ == '__main__':
    repository = Path(__file__).resolve().parents[4]
    baseline = historical_matrix(repository)
    target = repository / 'components/netops-helper/tests/fixtures/output_status_baseline.json'
    entries = []
    for name, case in baseline.items():
        groups = ',\n'.join('      ' + json.dumps(group) for group in case['matrix'])
        entries.append('  ' + json.dumps(name) + ': {\n    \"profile\": ' + json.dumps(case['profile']) +
                       ',\n    \"rc\": ' + str(case['rc']) + ',\n    \"matrix\": [\n' + groups + '\n    ]\n  }')
    target.write_text('{\n' + ',\n'.join(entries) + '\n}\n')
    print('historical_revision=1fad86c captures=%d profiles=%d rc=0,1,250' % (len(baseline), len(PROFILES)))
