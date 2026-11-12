"""Terminal controls are removed on the engine and proxy response paths."""
import hashlib
import json

import pytest

from conftest import _target
from netops_core.audit import Recorder
from netops_helper import audit, engine, proxy
from test_proxy_contracts import _configure, _request, _load_proxy
from test_fortios_diagnostics import (
    adc_engine, AdcAuth, AdcSession, ADC_PROMPT, ADC_CURL_OPTIONS, ADC_VIEW, ADC_URL,
)

# Representative HTTP response, not the unavailable original N5 live capture.
HTTP_LINES = ['HTTP/1.1 200 OK', 'Server: nginx', 'Content-Type: text/plain',
              'Content-Length: 3', 'X-Backend: backend-b', 'Connection: close']
PLAIN = '\n'.join(HTTP_LINES) + '\n\nok\n'
CURL = '\n'.join('\x1b[1m' + line + '\x1b[0m' for line in HTTP_LINES) + '\n\nok\n'


class CurlSession(AdcSession):
    def send(self, command):
        if command == 'get system status':
            return super().send(command)
        self.sent.append(command)
        if command == ADC_VIEW:
            text = ADC_CURL_OPTIONS.format('auto', 'auto')
        else:
            assert command == 'execute curl ' + ADC_URL
            text = CURL
        self.queue.append((command + '\r\n' + text + '\r\n').encode() + ADC_PROMPT)


def test_execute_curl_through_engine_sanitizes_before_hashing(adc_engine):
    use, _ = adc_engine
    session = CurlSession()
    result = use(session).fortios_diagnostics(AdcAuth(), 'http_probe', ADC_URL, '', 3, 1, 16000)
    assert CURL.count('\x1b') == 12
    assert result['ok'] and result['complete']
    text = result['untrusted_device_output']
    # The CLI shell trims the final newline, independently of sanitization.
    assert text.rstrip('\n') == PLAIN.rstrip('\n')
    assert result['content_sha256'] == hashlib.sha256(text.encode()).hexdigest()
    assert result['total_bytes'] == result['returned_bytes'] == len(text.encode())
    assert session.sent == ['get system status', ADC_VIEW, 'execute curl ' + ADC_URL]


@pytest.mark.parametrize('body,expected', [
    (CURL, PLAIN),
    ('a' + ''.join(chr(i) for i in range(32) if i not in (9, 10)) + '\tř\n', 'a\tř\n'),
    ('a\x1b[2Jb\x1b[?25lc\x1b[0md', 'abcd'),
    ('a\x1b]0;window title\x07b\x1b]8;;https://example.test\x1b\\link\x1b]8;;\x1b\\c', 'ablinkc'),
    ('a\x1bPdiscard\x1b\\b\x1b7c\x1b8d', 'abcd'),
    ('a\x1b]unfinished', 'aunfinished'),
    ('normal text: [1m, backslash \\u001b and Unicode ž\n\t', 'normal text: [1m, backslash \\u001b and Unicode ž\n\t'),
])
def test_engine_ssh_read_hash_and_page_use_clean_text(monkeypatch, tmp_path, body, expected):
    monkeypatch.setattr(audit, '_RECORDER', Recorder(tmp_path / 'audit.jsonl', 'helper'))
    from pathlib import Path
    identity = (Path(__file__).parent / 'fixtures/identity/cisco_ios.txt').read_text()
    monkeypatch.setattr(engine, 'read_from_device',
                        lambda auth, platform, command: (0, identity if command == 'show version' else body))
    result = engine.ssh_read(_target('cisco_ios', 'clock'), 'cisco_ios', 'clock', {}, 0, 16000)
    assert result['ok']
    assert result['untrusted_device_output'] == expected
    assert result['content_sha256'] == hashlib.sha256(expected.encode()).hexdigest()
    assert result['returned_bytes'] == result['total_bytes'] == len(expected.encode())


@pytest.mark.parametrize('encoded', [False, True])
def test_proxy_preserves_engine_cleaned_text_and_similar_output_fields(tmp_path, monkeypatch, encoded):
    # Real inventory/vault and real client request; fake server transport supplies its reply.
    module = _load_proxy()
    _configure(module, tmp_path)
    client = module.Proxy()
    request = client.request(_request(1, 'ssh_read', dict(target='device-a', platform='fortios', query='system_status')))
    assert request is not None
    auth = _target('cisco_ios', 'clock')
    cleaned = engine._redact_output(CURL, auth)
    payload = dict(ok=True, untrusted_device_output=cleaned,
                   stderr=engine._redact_output('x\x07y', auth), nested=[dict(output=cleaned)])
    result = dict(content=[dict(type='text', text=json.dumps(payload) if encoded else cleaned)], structuredContent=payload)
    forwarded = json.loads(client.response(json.dumps(dict(jsonrpc='2.0', id=1, result=result)).encode()))['result']
    assert forwarded['structuredContent']['untrusted_device_output'] == PLAIN
    assert forwarded['structuredContent']['stderr'] == 'xy'
    assert forwarded['structuredContent']['nested'][0]['output'] == PLAIN
    if encoded:
        assert json.loads(forwarded['content'][0]['text'])['untrusted_device_output'] == PLAIN
    else:
        assert forwarded['content'][0]['text'].endswith(PLAIN)

@pytest.mark.parametrize('text', [
    'set password\vTERMINALCANARY7Q\n', 'set password\fTERMINALCANARY7Q\n',
    'set\rpassword\rTERMINALCANARY7Q\n', 'password\x1b[1m: TERMINALCANARY7Q\x1b[0m\n',
])
def test_control_removal_keeps_the_existing_response_secrecy_floor(monkeypatch, tmp_path, text):
    cleaned = engine._redact_output(text, _target('cisco_ios', 'clock'))
    assert 'TERMINALCANARY7Q' not in cleaned
    assert not any(ord(c) < 32 and c not in '\n\t' for c in cleaned)


@pytest.mark.parametrize('introducer', [']', 'P', 'X', '^', '_'])
@pytest.mark.parametrize('ending', ['', '\r', '\n', '\r\n'])
def test_ansi_strings_are_bounded_and_unfinished_payload_is_preserved(introducer, ending):
    from netops_helper.sanitize import ANSI_STRING_LIMIT, strip_terminal_controls
    start = '\x1b' + introducer
    assert strip_terminal_controls('before' + start + 'payload' + ending + 'after') == (
        'beforepayload' + ending.replace('\r', '') + 'after')
    # A terminator on a later line never makes this a multiline control.
    assert strip_terminal_controls(start + 'first\r\nsecond\x1b\\\nthird') == 'first\nsecond\nthird'
    assert strip_terminal_controls(start + 'x' * ANSI_STRING_LIMIT + '\x1b\\tail') == 'tail'
    assert strip_terminal_controls(start + 'x' * (ANSI_STRING_LIMIT + 1) + '\x1b\\tail') == (
        'x' * (ANSI_STRING_LIMIT + 1) + 'tail')
    if introducer == ']':
        assert strip_terminal_controls(start + 'title\x07tail') == 'tail'
