"""Bound malformed device input before a regex can monopolize the Helper.

The alarm interrupts even CPython re holding the GIL. The matrix discovers regex
literals and composed constants in all text parser modules, including patterns
passed through matches()/lines(), rather than maintaining a regex allowlist.
"""
import ast
from contextlib import contextmanager
from pathlib import Path
import re
import signal
import time

from netops_helper import tables, wifi_parse


@contextmanager
def deadline(label, seconds=0.5):
    def expired(*_):
        raise AssertionError(f'parser exceeded {seconds}s: {label}')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def test_review_reproductions_are_bounded_and_report_unparsed():
    with deadline('Wi-Fi missing colon'):
        result = wifi_parse.summarize('wifi_ap_status', 'WTP: X 0-192.0.2.4:5246\n' + ' ' * 19999 + 'x\n')
        assert result['unparsed_count'] == 1
    with deadline('Junos LACP missing mux'):
        result = tables.parse('juniper_junos_els', 'lag', 'lacp_interfaces',
                              'Aggregated interface: ae0\n'
                              '    LACP protocol:        Receive State  Transmit State          Mux State\n'
                              '      ge-0/0/0 Current' + ' ' * 19900 + 'x\n')
        assert result['status'] == 'unparsed' and len(result['unparsed']) == 1
    with deadline('Junos route invalid age'):
        result = tables.parse('juniper_junos_els', 'route', 'route_table',
                              '192.0.2.0/24 *[Direct/0] ' + '1' * 19900 + 'x\n')
        assert result['status'] == 'unparsed' and len(result['unparsed']) == 1


def parser_patterns():
    directory = Path(tables.__file__).parent
    paths = sorted({directory / name for name in ('tables.py', 'normalization.py', 'wifi_parse.py',
                                                  'page_metadata.py', 'wifi_rest.py', 'ip_interfaces.py')} |
                   set(directory.glob('triage_*.py')) | set(directory.glob('switch_*.py')))
    for path in paths:
        tree = ast.parse(path.read_text())
        constants = {}

        def value(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if isinstance(node, ast.Name) and node.id in constants:
                return constants[node.id]
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                return value(node.left) + value(node.right)
            raise ValueError

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                try:
                    literal = value(node.value)
                except ValueError:
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        constants[target.id] = literal
        found = set()
        # Every string literal covers tuple/dict-based heading and field patterns;
        # composed strings cover e.g. MAC patterns and the pager expression.
        for node in ast.walk(tree):
            try:
                literal = value(node)
            except ValueError:
                continue
            if not literal or '\n' in literal or len(literal) > 1500:
                continue
            try:
                pattern = re.compile(literal)
            except re.error:
                continue  # fragments are exercised as part of composed patterns
            if literal not in found:
                found.add(literal)
                yield path.name, node.lineno, pattern


def pathological_inputs():
    for size in (128, 1000, 5000, 20000):
        for pump in (' ', '\t', '1', 'a', ':', '1:', 'a ', '1 ', 'a.', 'a,', '()', '"'):
            repeated = (pump * (size // len(pump) + 1))[:size - 1]
            yield repeated + '!'
        for prefix in ('ge-0/0/0 Current ', 'ge-0/0/0 (FUP) Current ', 'Cisco IOS Software, ',
                       '    key ', 'error: ', '192.0.2.0/24 *[Direct/0] '):
            for pump in (' ', '1', 'a '):
                yield prefix + (pump * size)[:size - len(prefix) - 1] + '!'


def test_all_parser_regexes_on_pathological_inputs():
    samples = list(pathological_inputs())
    count = 0
    started = time.perf_counter()
    for filename, line, pattern in parser_patterns():
        count += 1
        with deadline(f'{filename}:{line} {pattern.pattern!r}'):
            for sample in samples:
                pattern.fullmatch(sample)
        # Exercise the actual search operation for anchored patterns too; using
        # unanchored search on a fullmatch-only grammar would invent a new path.
        if pattern.pattern.startswith(('^', '(?m', '(?i')):
            with deadline(f'search {filename}:{line} {pattern.pattern!r}'):
                for sample in samples:
                    pattern.search(sample)
    assert count >= 294, count
    print(f'parser_regexes={count} inputs_per_regex={len(samples)} seconds={time.perf_counter() - started:.3f}')


def test_repeated_pager_prefixes_before_later_data_are_bounded():
    import subprocess
    import sys
    from netops_helper import normalization
    # An outer process timeout also works if a regex holds the interpreter.
    program = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location('pager_probe', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for boundary in ('\\n', '\\r'):
    text = 'Press <SPACE> to continue ' * 20000 + boundary + 'later data'
    assert module.output_status(text) == 'ok'
assert module.output_status('last line Press <SPACE> to continue or <Q> to quit:') == 'truncated'
"""
    subprocess.run([sys.executable, '-B', '-c', program, normalization.__file__],
                   check=True, timeout=5, capture_output=True)


def test_refusal_classification_of_400kb_blank_lines_is_linear():
    from netops_helper import normalization
    text = (' ' * 200 + '\n') * 2000
    assert len(text) >= 400_000
    for suffix, expected in (('', 'empty'), ('% Permission denied', 'permission_denied'),
                             ('% Invalid command', 'unsupported'), ('BGP is not running', 'not_applicable')):
        started = time.perf_counter()
        with deadline('400 kB whitespace refusal classification', seconds=1):
            assert normalization.output_status(text + suffix) == expected
        elapsed = time.perf_counter() - started
        assert elapsed < 1
        print(f'blank_lines_bytes={len(text)} status={expected} seconds={elapsed:.4f}')


def test_line_prefix_regexes_preserve_fixture_and_whitespace_results():
    from netops_helper import normalization
    from support.classification_fixtures import real_captures
    root = Path(__file__).parent / 'fixtures'
    # Freeze the previous spelling independently of the production constants.
    patterns = [
        (normalization._PERMISSION, re.compile(
            r'(?mi)^\s*(?:%\s*(?:Authorization failed|Authorization denied|Permission denied|Access denied)'
            r'|This user does not have permissions for this command|error:\s*permission denied'
            r'|Line has invalid autocommand|Error:\s*(?:Permission denied|You do not have))')),
        (normalization._IOS_INVALID_INPUT, re.compile(r'(?mi)^\s*%\s*Invalid input')),
        (normalization._UNSUPPORTED, re.compile(
            r'(?mi)^\s*(?:Method is not implemented on this platform\.'
            r'|%{1,2}\s*(?:Unrecognized command|Incomplete command|Ambiguous command|Invalid command|Invalid input)'
            r'|error:\s*(?:unknown command|syntax error|the [a-z0-9-]+ subsystem is not running)'
            r'|Syntax error while parsing)')),
        (normalization._NOT_CONFIGURED, re.compile(
            r'(?mi)^\s*(?:%\s*BGP (?:not active|inactive)\b|!\s*IPv6 routing not enabled\b|BGP is not running\b'
            r'|Spanning-tree is not enabled at global level\b'
            r'|warning: [a-z0-9-]+ subsystem not running - not needed by configuration\b)')),
    ]
    health = Path(normalization.__file__).with_name('triage_health.py')
    literals = [node.value for node in ast.walk(ast.parse(health.read_text()))
                if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    current = next(value for value in literals if value.startswith(r'(?m)^[^\S\n]*'))
    patterns.append((re.compile(current), re.compile(
        r'(?m)^\s*ipv[46] server\(([^)\s]*)\)\s+([0-9A-Fa-f:.]+)\s+--\s+([a-z]+)')))
    captures = {name: item[1] for name, item in real_captures(root).items()}
    # Include every fixture file, not only discovered device-capture formats.
    repository = root.parents[3]
    for directory in (root, repository / 'tests/v1/fixtures'):
        for path in directory.rglob('*'):
            if path.is_file():
                captures[str(path.relative_to(repository))] = path.read_text(errors='replace')
    for whitespace in ('', ' ', '\n', '\r\n', '\t\f\v\r\n \u001c\u00a0'):
        for message in ('% Permission denied', '% Invalid input', 'BGP is not running',
                        'error: unknown command: x', 'ipv4 server(ntp) 192.0.2.1 -- up', 'data'):
            captures[repr((whitespace, message))] = whitespace + message
    for name, text in captures.items():
        for current, previous in patterns:
            assert bool(current.search(text)) == bool(previous.search(text)), (name, current.pattern)
            if current.groups:
                assert current.findall(text) == previous.findall(text), name
    print(f'line_prefix_differential captures={len(captures)} patterns={len(patterns)} differences=0')
