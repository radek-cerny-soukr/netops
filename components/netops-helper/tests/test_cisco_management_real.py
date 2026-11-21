"""Management diagnostics via the real engine with only SSH replaced by lab captures."""
from dataclasses import replace
import json
import re
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import engine
from netops_helper.auth import PolicyScopeError
from netops_helper.query_catalog import READ_QUERIES
from netops_helper.sanitize import redact, redact_response

FIXTURES = Path(__file__).parent / 'fixtures/real/management'
CASES = []
for path in sorted(FIXTURES.glob('*.json')):
    device = json.loads(path.read_text())
    for row in device['captures']:
        if row['command'] == 'show version':
            continue
        row['parameters'] = ({'address': '192.0.2.123'}
                             if device['profile'] == 'cisco_nxos' and row['command'].endswith(' 192.0.2.123') else {})
        matches = [n for n,q in READ_QUERIES[device['profile']].items()
                   if set(q.slots) == set(row['parameters']) and q.command.format_map(row['parameters']) == row['command']]
        if matches:
            row['query'] = matches[0]
            CASES.append((device, row))
        else:
            # Preserve original, disproven NX plan commands as evidence, never as runtime templates.
            assert device['profile'] == 'cisco_nxos' and row['command'] in (
                'show radius-server statistics', 'show tacacs-server statistics', 'show ssh server session')


def setup(monkeypatch, device, row, body=None, rc=None):
    profile = device['profile']
    query = row['query']
    identity = next(r['stdout'] for r in device['captures'] if r['command'] == 'show version' and r['role'] == row['role'])
    calls = []
    def transport(auth, actual_profile, command):
        assert actual_profile == profile
        calls.append(command)
        if command == 'show version':
            return 0, identity
        assert command == row['command']
        return (row['rc'] if rc is None else rc), (row['stdout'] if body is None else body)
    monkeypatch.setattr(engine, 'read_from_device', transport)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    auth = replace(_target(profile, query), read_inventory={'addresses': ('192.0.2.123',)})
    return auth, query, calls


def read(auth, query):
    params = {'address': '192.0.2.123'} if READ_QUERIES[auth.ssh_platform][query].slots else {}
    return engine.ssh_read(auth, auth.ssh_platform, query, params, 0, 16000)


@pytest.mark.parametrize('device,row', CASES, ids=[d['device']+'-'+r['role']+'-'+r['command'] for d,r in CASES])
def test_recorded_management_output(monkeypatch, device, row):
    auth, query, calls = setup(monkeypatch, device, row)
    result = read(auth, query)
    assert calls == ['show version', row['command']]
    refused = row['rc'] != 0 or 'invalid autocommand' in row['stdout']
    assert result['ok'] is (not refused), result
    if not refused:
        if device['profile'] == 'cisco_nxos':
            assert result['status'] == 'ok'
            assert result['complete']
            assert result['untrusted_device_output'].strip()
        else:
            assert result['untrusted_device_output'].strip() == redact_response(row['stdout'], auth.redaction_secrets).strip()
        assert result['next_offset'] is None
    else:
        assert result['status'] in ('permission_denied', 'unsupported', 'unparsed', 'transport_error', 'not_applicable')


@pytest.mark.parametrize('device,row', CASES)
def test_refused_and_incomplete_capture(monkeypatch, device, row):
    # An actual refusal captured on IOS; the only fake is the transport response.
    refusal = next((r for r in device['captures'] if 'Permission denied' in r['stdout'] or 'invalid autocommand' in r['stdout']),
                   json.loads((FIXTURES/'iosv.json').read_text())['captures'][5])
    auth, query, _ = setup(monkeypatch, device, row, body=refusal['stdout'], rc=refusal['rc'])
    result = read(auth, query)
    assert not result['ok']
    auth, query, _ = setup(monkeypatch, device, row, body=row['stdout']+'\n--More--\n')
    result = read(auth, query)
    assert result['status'] == 'truncated'
    assert not result['normalized']['coverage']['complete']


@pytest.mark.parametrize('device,row', CASES)
def test_unenrolled_management_query_never_connects(monkeypatch, device, row):
    auth, query, calls = setup(monkeypatch, device, row)
    with pytest.raises(PolicyScopeError):
        read(replace(auth, enabled_queries=('clock',)), query)
    assert calls == []


@pytest.mark.parametrize('label', ['Community name:', 'SNMP community string =', 'Shared secret:', 'Encryption key:'])
def test_diagnostic_credential_values_hidden_before_paging(label):
    # Synthetic credential canaries are security tests, not device-output fixtures.
    text = label+' "canary credential with spaces"\n17 SNMP packets input\n'
    for sanitizer in (redact, redact_response):
        result = sanitizer(text)
        assert 'canary' not in result and 'with spaces' not in result
        assert '17 SNMP packets input' in result


@pytest.mark.parametrize('device,row', CASES)
def test_empty_output_requires_a_catalogue_rule(monkeypatch, device, row):
    auth, query, _ = setup(monkeypatch, device, row, body='')
    result = read(auth, query)
    expected = 'transport_error' if device['profile'] == 'cisco_nxos' and row['rc'] else 'empty'
    assert result['status'] == expected
    assert result['ok'] is READ_QUERIES[device['profile']][query].empty_allowed
    complete_empty = result['ok'] and device['profile'] in {'cisco_ios', 'cisco_xe'}
    assert result['normalized']['coverage']['complete'] is complete_empty


@pytest.mark.parametrize('query', ['radius_statistics', 'tacacs_statistics'])
def test_nxos_statistics_require_an_enrolled_server(query):
    from netops_helper.read_policy import render_read_query
    inventory = {'addresses': ('192.0.2.123',)}
    assert render_read_query('cisco_nxos', query, {'address':'192.0.2.123'}, inventory)[1].endswith(' 192.0.2.123')
    for parameters in ({}, {'address':'192.0.2.124'}, {'address':'192.0.2.123;reload'}, {'address':'192.0.2.123\nreload'}):
        with pytest.raises(ValueError):
            render_read_query('cisco_nxos', query, parameters, inventory)


def test_nxos_missing_radius_server_has_specific_diagnostic(monkeypatch):
    device, row = next((d, r) for d, r in CASES if d['profile'] == 'cisco_nxos'
                       and r['query'] == 'radius_statistics' and r['role'] == 'ADMIN')
    auth, query, calls = setup(monkeypatch, device, row)
    result = read(auth, query)
    assert result['status'] == 'not_applicable' and not result['ok']
    assert result['error'] == 'The requested RADIUS server is not configured on the device'
    assert calls == ['show version', row['command']]


def test_nxos_session_summary_is_an_exact_exception():
    from netops_helper.read_policy import _validate_query_command
    _validate_query_command('cisco_nxos', 'show configuration session summary')
    for command in ('show configuration', 'show configuration session', 'show configuration session details',
                    'show configuration session summary all', 'show running-config', 'show conf session summary'):
        with pytest.raises(RuntimeError):
            _validate_query_command('cisco_nxos', command)
    with pytest.raises(RuntimeError):
        _validate_query_command('cisco_ios', 'show configuration session summary')


def test_nxos_snmp_community_table_hidden_in_every_page_and_json(monkeypatch):
    device,row = next((d,r) for d,r in CASES if d['device']=='nxos' and r['role']=='ADMIN' and r['command']=='show snmp')
    raw = re.sub(r'(?m)^<REDACTED>$', '"nx-canary with spaces" network-operator default', row['stdout'])
    assert 'nx-canary' in raw
    for sanitizer in (redact, redact_response):
        original_header = re.sub(r'(Community[ \t]+)<REDACTED>([ \t]*/[ \t]*Access)', r'\1Group\2', raw)
        for value in (raw, original_header, json.dumps({'output': raw}), json.dumps({'output': original_header})):
            cleaned = sanitizer(value)
            assert 'nx-canary' not in cleaned and 'with spaces' not in cleaned
    auth,query,calls = setup(monkeypatch,device,row,body=raw)
    offset=0
    sha=None
    while True:
        result=engine.ssh_read(auth,auth.ssh_platform,query,{},offset,1024,sha)
        assert result['ok'] and 'nx-canary' not in json.dumps(result)
        assert 'with spaces' not in json.dumps(result)
        if result['next_offset'] is None:
            break
        sha=result['content_sha256']
        offset=result['next_offset']
    assert calls == ['show version','show snmp']


@pytest.mark.parametrize("command,query,counter", [
    ("show snmp", "snmp_statistics", "SNMP packets input"),
    ("show aaa authentication", "aaa_authentication", "default: local"),
    ("show configuration session summary", "configuration_sessions", "Session Manager Database:"),
    ("show users", "users", "PID COMMENT"),
])
def test_nxos_g95_unknown_sensitive_lines_never_leave_engine(monkeypatch, command, query, counter):
    device, row = next((d, r) for d, r in CASES if d["device"] == "nxos" and r["role"] == "ADMIN"
                       and r["command"] == command)
    extra = "pwd qZ secret-phrase-tail\n"
    body = extra + row["stdout"] + extra
    auth, _, calls = setup(monkeypatch, device, row, body=body)
    result = read(auth, query)
    serialized = json.dumps(result)
    assert "qZ" not in serialized and "secret-phrase-tail" not in serialized
    assert "[redacted]" in result["untrusted_device_output"]
    assert counter in result["untrusted_device_output"]
    assert result["status"] == "unparsed" and not result["complete"]
    assert calls == ["show version", command]


def test_nxos_g95_snmp_keys_outside_community_section(monkeypatch):
    device, row = next((d, r) for d, r in CASES if d["device"] == "nxos" and r["role"] == "ADMIN"
                       and r["command"] == "show snmp")
    body = row["stdout"].replace("SNMP USERS", "SNMP USERS\nuser-v3  auth qZ priv secret-phrase-tail")
    assert "secret-phrase-tail" in body
    auth, query, _ = setup(monkeypatch, device, row, body=body)
    result = read(auth, query)
    assert result["status"] == "ok"
    serialized = json.dumps(result)
    assert "qZ" not in serialized and "secret-phrase-tail" not in serialized
    assert "[redacted]" in result["untrusted_device_output"]


def test_nxos_g95_untested_firmware_warns_without_blocking(monkeypatch):
    device, row = next((d, r) for d, r in CASES if d["device"] == "nxos" and r["role"] == "ADMIN"
                       and r["command"] == "show hosts")
    device = {**device, "captures": [
        {**r, "stdout": r["stdout"].replace("9.3(12)", "9.3(99)")} if r["command"] == "show version" else r
        for r in device["captures"]
    ]}
    auth, query, calls = setup(monkeypatch, device, row)
    result = read(auth, query)
    assert result["ok"] and result["firmware_support"]["status"] == "untested"
    assert calls == ["show version", "show hosts"]


@pytest.mark.parametrize("expected_count", [1, 2])
def test_nxos_g95_active_configuration_session_count(monkeypatch, expected_count):
    device, row = next((d, r) for d, r in CASES if d["device"] == "nxos" and r["role"] == "ADMIN"
                       and r["command"] == "show configuration session summary")
    fixture = FIXTURES.parent / "cisco_nxos/g95_9.3.12/configuration-session-one.out"
    capture = fixture.read_text()
    body = capture.replace("sessions = 1", f"sessions = {expected_count}")
    auth, query, _ = setup(monkeypatch, device, row, body=body)
    result = read(auth, query)
    assert "host01" in result["untrusted_device_output"]
    assert "user01" in result["untrusted_device_output"]
    assert result["status"] == ("ok" if expected_count == 1 else "unparsed")
    assert result["complete"] is (expected_count == 1)


def test_nxos_g95_redaction_precedes_snapshot_paging(monkeypatch):
    device, row = next((d, r) for d, r in CASES if d["device"] == "nxos" and r["role"] == "ADMIN"
                       and r["command"] == "show snmp")
    # Derive a long capture from a real counter line and insert a short credential plus a pager.
    lines = "\n".join(f"{value} Trap PDU" for value in range(120))
    body, replacements = re.subn(r"(?m)^\s*[0-9]+ Trap PDU[ \t]*$", lines, row["stdout"])
    assert replacements == 1
    body += "\nqZ very-private-tail--More--"
    auth, query, calls = setup(monkeypatch, device, row, body=body)
    first = engine.ssh_read(auth, auth.ssh_platform, query, {}, 0, 1024)
    assert first["next_offset"] is not None
    last = engine.ssh_read(auth, auth.ssh_platform, query, {}, first["next_offset"], 16000,
                           first["content_sha256"])
    for result in (first, last):
        assert result["status"] == "truncated" and not result["complete"]
        assert "qZ" not in json.dumps(result) and "very-private-tail" not in json.dumps(result)
    assert last["next_offset"] is None
    assert last["untrusted_device_output"].rstrip().endswith("[redacted]--More--")
    assert calls == ["show version", "show snmp"]


@pytest.mark.parametrize("node", ["d-nxos", "b04-nx-a", "b04-nx-b"])
def test_nxos_g95_active_ssh_user_from_live_capture(monkeypatch, node):
    device, row = next((d, r) for d, r in CASES if d["device"] == "nxos" and r["role"] == "RO"
                       and r["command"] == "show users")
    capture = (FIXTURES.parent / f"cisco_nxos/g95_9.3.12/users-{node}.out").read_text()
    auth, query, _ = setup(monkeypatch, device, row, body=capture)
    result = read(auth, query)
    assert result["status"] == "ok" and result["complete"]
    assert re.search(r"user01\s+pts/[0-9]+\s+Nov 20 .+\(192\.0\.2\.[0-9]+\)", result["untrusted_device_output"])


@pytest.mark.parametrize("scope", ["default", "management"])
def test_nxos_g95_configured_dns_from_real_capture(monkeypatch, scope):
    device, row = next((d, r) for d, r in CASES if d["device"] == "nxos" and r["role"] == "ADMIN"
                       and r["command"] == "show hosts")
    capture = (FIXTURES.parent / f"cisco_nxos/g95_9.3.12/dns-{scope}-vrf.out").read_text()
    auth, query, _ = setup(monkeypatch, device, row, body=capture)
    result = read(auth, query)
    assert result["status"] == "ok" and result["complete"]
    text = result["untrusted_device_output"]
    assert "Default domain is host01" in text
    assert "192.0.2.30" in text
    if scope == "management":
        assert re.search(r"default\s+management\s+name-server\(s\)\s+192\.0\.2\.30", text)
