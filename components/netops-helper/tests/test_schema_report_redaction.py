"""Compare disclosure against frozen 1.0.6 response redactors, not a new rule copy."""
import importlib.util
import json
from pathlib import Path
from dataclasses import replace

from netops_helper import engine, schema_read
from netops_helper.proxy import Proxy
from netops_helper.page_metadata import page_metadata
from netops_helper.proxy_sanitize import sanitize_object
from netops import worker
from netops.redaction import redact
from netops_core.schema import Library
from test_schema_read import auth, document, SECRET_DENSE


def baseline(name):
    path = Path(__file__).resolve().parents[3] / 'tests/v1/fixtures' / (name + '_1_0_6.py')
    spec = importlib.util.spec_from_file_location('baseline_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from strings(child)
    elif isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from strings(child)


def reports():
    library = Library(document())
    large = 'config firewall address\n' + ''.join(
        ' edit "obj%d"\n set comment "%s"\n set fortitoken "FTK%d"\n next\n'
        % (i, 'x' * 150, i) for i in range(300)) + 'end\n'
    for body in (SECRET_DENSE, large):
        for view in ('get', 'show'):
            yield schema_read.snapshot(library, body, 'firewall address', view, None, [],
                                       auth().secrets, current_vdom='root')
    yield {'nested': [[{'password': ['array-secret', {'token': 'nested-token'}]},
                       {'fortitoken': ['nested-ftk'], 'private-key': {'k': 'private-child'}},
                       ['token=bare-value', 'set passwd cli-value', 'ENC opaque-value',
                        'session-fixture-value', 'transport-fixture-value',
                        'unicode-秘密', 'quoted-"secret\\value', 987654321]]],
           'credentials': {'innocent': 'credential-child'},
           'password: key-fixture-value': 'key-child',
           '1000': 'numeric-key-child', 'known-number': 987654321,
           'stable': 'visible diagnostic', 'tuple': ('tuple-secret', {'value': 'nested-tuple-secret'}),
           'boolean': True, 'empty': None}


def pages_survive(candidate, target, sizes=(1000, 1777, 48000)):
    known = target.redaction_secrets
    for max_bytes in sizes:
        offset, joined = 0, ''
        while True:
            page = engine._schema_page(candidate, offset, max_bytes, target)
            fragment = page['untrusted_device_output']
            assert redact(sanitize_object(fragment, known), known)[0] == fragment, (max_bytes, offset)
            joined += fragment
            if page['complete']:
                break
            offset = page['next_offset']
        assert joined == candidate
    return True


def test_schema_report_discloses_no_string_hidden_by_1_0_6():
    old_proxy, old_worker = baseline('proxy_sanitize'), baseline('redaction')
    target = replace(auth(), output_secrets=('session-fixture-value', 'transport-fixture-value',
                                            'unicode-秘密', 'quoted-"secret\\value', '987654321', '8.0.0',
                                            'tuple-secret', 'nested-tuple-secret', 'true', 'null'))
    known = target.redaction_secrets
    comparisons = 0
    for report in reports():
        candidate = engine._redact_schema_report(report, target)
        decoded = json.loads(candidate)
        if 'boolean' in report:
            assert decoded['boolean'] == '[REDACTED]'
            assert decoded['empty'] == '[REDACTED]'
            assert decoded['known-number'] == '[REDACTED]'
            assert decoded['tuple'] == ['[REDACTED]', {'value': '[REDACTED]'}]
        # Every page survives the actual later rules, which judge a page as text and a whole
        # report as JSON; a whole report that they would change goes in more than one page.
        assert pages_survive(candidate, target)
        original = json.dumps(report, ensure_ascii=False, separators=(',', ':'))
        for max_bytes in (1000, 1001, 1777, 4096, 16000, 48000):
            old_pages, offset = [], 0
            while True:
                page = engine._page_text(original, offset, max_bytes)
                old_pages.append(page['untrusted_device_output'])
                if page['complete']:
                    break
                offset = page['next_offset']
            old = ''.join(old_worker.redact(old_proxy.sanitize_object(page, known), known)[0]
                          for page in old_pages)
            # Compare decoded strings too: a JSON escape is not considered hiding a secret.
            visible = '\n'.join(strings(json.loads(candidate)))
            canaries = {
                'array-secret', 'nested-token', 'nested-ftk', 'private-child', 'bare-value',
                'cli-value', 'opaque-value', 'session-fixture-value', 'transport-fixture-value',
                'unicode-秘密', 'quoted-"secret\\value', 'credential-child', 'key-fixture-value',
                '987654321', '8.0.0', 'tuple-secret', 'nested-tuple-secret', 'true', 'null',
                *(f'FTK{i}' for i in range(300)),
                *(f'synthetic-{kind}-{i}' for kind in ('token', 'enc', 'psk') for i in range(12)),
            }
            for value in canaries:
                # Only canaries actually present in the original report count as disclosure probes.
                original_values = '\n'.join(strings(report))
                if value not in original_values:
                    continue
                if value not in old and json.dumps(value, ensure_ascii=False)[1:-1] not in old:
                    assert value not in visible, (max_bytes, 'a baseline-hidden secret became visible')
                    comparisons += 1
    assert comparisons > 1500


def test_1_0_6_fixed_cuts_also_disclose_a_split_session_secret():
    old_proxy, old_worker = baseline('proxy_sanitize'), baseline('redaction')
    secret = 'SYNTHETICVALUE123'
    for size in (1000, 1777, 48000):
        original = 'x' * (size - 5) + secret + 'z' * 1100
        pages = [original[i:i + size] for i in range(0, len(original), size)]
        final = ''.join(old_worker.redact(old_proxy.sanitize_object(page, (secret,)), (secret,))[0]
                        for page in pages)
        assert secret in final  # Frozen 1.0.6 rules see neither complete occurrence.


def test_marker_preservation_never_preserves_a_marker_with_secret_suffix():
    from netops_helper.proxy_sanitize import sanitize_text
    for marker in ('[REDACTED]', '<REDACTED>', '<PRIVATE-KEY-REDACTED>'):
        for key in ('password', 'fortitoken', 'api_token'):
            text = json.dumps({key: marker + 'synthetic-marker-tail'}, separators=(',', ':'))
            assert 'synthetic-marker-tail' not in sanitize_object(text[:-1] + ',')
            assert 'synthetic-marker-tail' not in sanitize_text(text[:-1] + ',')


def test_a_known_secret_spanning_json_punctuation_is_withheld_before_paging():
    import pytest
    secret = 'a","b'
    target = replace(auth(), output_secrets=(secret,))
    report = {'values': ['x' * 990 + 'a', 'b' + 'z' * 1100]}
    assert secret in json.dumps(report, separators=(',', ':'))
    with pytest.raises(ValueError, match='schema redaction could not be verified; report withheld') as caught:
        engine._redact_schema_report(report, target)
    # A typed refusal: the worker reports its code and does not offer a pointless restart.
    assert isinstance(caught.value, engine.PaginationRefused)
    assert (caught.value.code, caught.value.restartable) == ('schema_redaction_unverified', False)
    assert engine._pagination_refused(str(caught.value)).restartable is False
    assert engine._pagination_refused(engine._SCHEMA_SNAPSHOT_EXPIRED).restartable is True


def _large_report(objects):
    return {'path': 'firewall address', 'view': 'get', 'objects': [
        {'vdom': 'root', 'owners': [['firewall address', 'obj%d' % i]], 'attributes': {
            'name': ['obj%d' % i], 'comment': ['comment text %d for object' % (i * 7919 % 100003)],
            'subnet': ['10.%d.%d.0 255.255.255.0' % (i % 256, i * 31 % 256)],
            'color': [str(i % 30)], 'associated-interface': ['port%d' % (i % 20)]}}
        for i in range(objects)]}


def test_schema_report_redaction_cost_does_not_grow_with_known_secrets():
    """A 1000-object report of about 200 kB with 60 long secrets: budget in CPU seconds.

    The old per-leaf normalization of every secret took 30-50 s on a small ARM board; the
    prepared secrets and per-string verdicts stay near the secret-free time (0.3 s here).
    """
    import time
    report = _large_report(1000)
    plain_text = json.dumps(report, ensure_ascii=False, separators=(',', ':'))
    assert 100_000 < len(plain_text) < 300_000
    secrets = tuple(('s%02d' % i) + 'Qz9' * 200 for i in range(60))
    timings = {}
    for count in (0, 60):
        target = replace(auth(), output_secrets=secrets[:count])
        started = time.process_time()
        candidate = engine._redact_schema_report(report, target)
        timings[count] = time.process_time() - started
        assert candidate == plain_text  # nothing in this report is secret
    assert timings[60] < 2.0, timings
    assert timings[60] < 2 * timings[0] + 0.5, timings
    leaking = _large_report(1000)
    leaking['objects'][500]['attributes']['comment'] = ['before ' + secrets[59] + ' after']
    hidden = json.loads(engine._redact_schema_report(leaking, replace(auth(), output_secrets=secrets)))
    assert hidden['objects'][500]['attributes']['comment'] == ['[REDACTED]']
    assert hidden['objects'][499] == leaking['objects'][499]


def test_page_changed_at_its_start_is_returned_at_once_instead_of_shortened_repeatedly():
    import time
    text = '{"a":"password 5 abc","b":[' + ','.join('"v%d"' % i for i in range(9000)) + ']}'
    offset = text.index('password 5')
    target = auth()
    original = engine._page_text(text, offset, 48000)
    started = time.process_time()
    page = engine._schema_page(text, offset, 48000, target)
    elapsed = time.process_time() - started
    assert page == original  # nothing a shorter end can repair; the worker will withhold it
    assert elapsed < 1.0, elapsed  # the unbounded loop took seconds for one such page


def test_page_cut_inside_a_marker_label_is_shortened_within_the_window():
    # A cut right after a secret key's name would leave its label without the value marker.
    body = ','.join('"k%d":"%s"' % (i, 'x' * 40) for i in range(40))
    text = '{' + body + ',"password":"synthetic-window-value","tail":"' + 'z' * 3000 + '"}'
    target = auth()
    cut = text.index('"password"') + len('"password":"syn')
    page = engine._schema_page(text, 0, 1000, target)
    assert page['untrusted_device_output'] == text[:page['returned_bytes']]
    for size in range(len(text[:cut]) - 40, len(text[:cut]) + 40):
        if size < 1000:
            continue
        shortened = engine._schema_page(text, 0, size, target)
        fragment = shortened['untrusted_device_output']
        assert 'synthetic-window-value' not in fragment
        assert text.startswith(fragment) and shortened['returned_bytes'] == len(fragment.encode())


def test_show_copy_is_rebuilt_from_redacted_attributes_not_hidden_as_a_whole():
    library = Library(document())
    body = ('config firewall address\n edit "a"\n  set comment "hello"\n  set password abc-synthetic\n'
            '  set fortitoken "FTK-synthetic"\n next\n edit "b"\n  set comment "plain"\nnext\nend\n')
    report = schema_read.snapshot(library, body, 'firewall address', 'show', None, [],
                                  auth().secrets, current_vdom='root')
    # The reader hides the password but not the suffix label; 1.0.6 kept the other lines of `show`.
    assert report['objects'][0]['show'] == ('set comment "hello"\nset fortitoken "FTK-synthetic"\n'
                                           'set password "<REDACTED>"')
    candidate = engine._redact_schema_report(report, auth())
    first, second = json.loads(candidate)['objects']
    # Under a key that the proxy judges by its suffix, the value is the proxy's own marker: 1.0.6
    # rewrites `"fortitoken":"[REDACTED]"` in a page, so the report carries what the client receives.
    assert first['attributes'] == {'comment': ['hello'], 'fortitoken': '<REDACTED>', 'password': '[REDACTED]'}
    assert first['show'] == 'set comment "hello"\nset fortitoken "[REDACTED]"\n[REDACTED]'
    assert second['show'] == 'set comment "plain"'  # an object without a sensitive attribute is untouched
    for canary in ('abc-synthetic', 'FTK-synthetic'):
        assert canary not in candidate
    assert pages_survive(candidate, auth())
    # A secret in an ordinary attribute value still hides the copy rather than the report.
    leaking = replace(auth(), output_secrets=('hello',))
    again = json.loads(engine._redact_schema_report(report, leaking))['objects'][0]
    assert again['attributes']['comment'] == ['[REDACTED]']
    assert 'hello' not in again['show'] and again['show'].startswith('set comment "[REDACTED]"')


def test_random_reports_page_into_valid_json_without_known_secrets():
    """300 seeded reports x 3 sizes: only pages verified by the worker join to JSON."""
    import hashlib
    import random
    rnd = random.Random(20261108)
    words = ['password', 'token', 'fortitoken', 'ENC abc', 'plain text', '[REDACTED]', '<REDACTED>', 'ž秘密',
             '-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----', 'psksecret', 'set passwd y',
             'snmp-server community x', '{"a":"b"}', 'x' * 200]
    session = ['session-secret-%d' % i for i in range(5)]

    def make(secrets, depth=0):
        choice = rnd.random()
        if choice < 0.5:
            return ' '.join(rnd.choice(words + list(secrets)) for _ in range(rnd.randrange(1, 4)))
        if choice < 0.6:
            return rnd.choice([1, 1000, 987654321, 2.5, True, None])
        if depth > 2 or choice < 0.75:
            return [make(secrets, depth + 1) for _ in range(rnd.randrange(0, 4))]
        return {rnd.choice(['comment', 'password', 'name', 'fortitoken', 'token', 'ciphertext', 'k%d' % rnd.randrange(9)])
                + ('' if rnd.random() < .7 else str(rnd.randrange(3))): make(secrets, depth + 1)
                for _ in range(rnd.randrange(1, 5))}

    documents, combinations, pages = 0, 0, 0
    for report_index in range(300):
        secrets = tuple(rnd.sample(session, rnd.randrange(0, 4)))
        target = replace(auth(), output_secrets=secrets)
        report = {'objects': [make(secrets) for _ in range(rnd.randrange(20, 120))], 'path': 'p'}
        # No whole-report refusal is expected for this fixed seed; an unexpected one fails.
        canonical = engine._redact_schema_report(report, target)
        documents += 1
        known = target.redaction_secrets
        assert not any(secret in canonical for secret in known)
        proxy = Proxy()
        proxy._remember_session_secrets(known)
        expected_bytes = canonical.encode("utf-8")
        expected_hash = hashlib.sha256(expected_bytes).hexdigest()
        for max_bytes in (1000, 1777, 16000):
            combinations += 1
            fragments, offset = [], 0
            while True:
                page = engine._schema_page(canonical, offset, max_bytes, target)
                payload = {"ok": True, **page}
                proxy.pending[1] = "tools/call"
                proxy.pending_tools[1] = "schema_read"
                proxy.response_secrets[1] = known
                response = {"jsonrpc": "2.0", "id": 1, "result": {
                    "content": [{"type": "text", "text": json.dumps(payload)}],
                    "structuredContent": payload, "isError": False}}
                transformed = json.loads(proxy.response(json.dumps(response).encode()))["result"]
                metadata = page_metadata(transformed["structuredContent"])
                assert metadata is not None
                final = worker._redacted_result(transformed, known, metadata)
                changed = worker._page_changes(final, page)
                assert changed == [], (report_index, max_bytes, offset, changed)
                assert final["isError"] is False
                views = (final["structuredContent"], json.loads(final["content"][0]["text"]))
                for view in views:
                    assert not any(secret in view["untrusted_device_output"] for secret in known)
                    assert view["offset"] == offset
                    assert view["content_sha256"] == expected_hash
                    assert view["total_bytes"] == len(expected_bytes)
                    assert view["returned_bytes"] == len(view["untrusted_device_output"].encode("utf-8"))
                    assert 0 < view["returned_bytes"] <= max_bytes
                assert views[0]["untrusted_device_output"] == views[1]["untrusted_device_output"]
                # Only the final, verified representation contributes bytes to the document.
                issued = views[0]
                fragments.append(issued["untrusted_device_output"])
                pages += 1
                if issued["complete"]:
                    assert issued["next_offset"] is None
                    assert offset + issued["returned_bytes"] == len(expected_bytes)
                    break
                assert issued["next_offset"] == offset + issued["returned_bytes"]
                offset = issued["next_offset"]
            joined = ''.join(fragments)
            assert joined == canonical
            assert len(joined.encode("utf-8")) == len(expected_bytes)
            assert hashlib.sha256(joined.encode("utf-8")).hexdigest() == expected_hash
            decoded = json.loads(joined)
            assert not any(secret in value for value in strings(decoded) for secret in known)
    assert (documents, combinations) == (300, 900)
