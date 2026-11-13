"""Versioned input shared by the capture importer and parametrized replay test."""
import json

SCHEMA = 'netops-replay/1'


def validate(scenario):
    if scenario.get('schema') != SCHEMA:
        raise ValueError('unsupported replay schema')
    for field in ('scenario', 'expected_source'):
        if not isinstance(scenario.get(field), str) or not scenario[field].strip():
            raise ValueError('scenario and independent expectation source are required')
    captures = scenario.get('captures')
    if not isinstance(captures, list) or not captures:
        raise ValueError('at least one capture is required')
    for capture in captures:
        for field in ('platform', 'firmware', 'query', 'table', 'command'):
            if not isinstance(capture.get(field), str) or not capture[field].strip():
                raise ValueError('capture metadata is incomplete')
        if type(capture.get('rc')) is not int:
            raise ValueError('capture rc must be an integer')
        if not isinstance(capture.get('stdout'), str):
            raise ValueError('capture stdout is required')
        expected = capture.get('expected', {})
        if (not isinstance(expected.get('status'), str)
                or type(expected.get('record_count')) is not int
                or type(expected.get('unparsed_count')) is not int
                or not isinstance(expected.get('records'), list)):
            raise ValueError('explicit status, counts and manual records are required')
        if expected['record_count'] != len(expected['records']):
            raise ValueError('supply an expectation for every record')
        if any(not isinstance(row, dict) or not row for row in expected['records']):
            raise ValueError('each expected record needs independently chosen fields')
    return scenario


def load(path):
    return validate(json.loads(path.read_text()))


def replay(capture):
    from netops_helper import tables
    actual = tables.parse(capture['platform'], capture['table'], capture['query'],
                          capture['stdout'], rc=capture['rc'], command=capture['command'])
    expected = capture['expected']
    assert actual['status'] == expected['status'], actual
    assert len(actual['records']) == expected['record_count'], actual
    assert len(actual['unparsed']) == expected['unparsed_count'], actual
    for row, fields in zip(actual['records'], expected['records'], strict=True):
        assert {key: row[key] for key in fields} == fields, row
    return actual
