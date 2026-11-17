#!/usr/bin/env python3
"""Task 302-r6: a structural 1.0.8 floor on every path by which text leaves for the AI client.

Reviews 302-rv to 302-r5rv found, round after round, one more shape in which the new anchor logic
(which later rule takes the text after an anchor in a hidden value) guessed wrong and let a secret
pass that the released chains hid. r6 replaces the guess by a structural guarantee: on every path
every character that the frozen released chain hides is hidden too, found by original offsets.

- ``redact()`` (e.g. a FortiADC diagnostic -> ``untrusted_device_output`` -> proxy -> product):
  the complete released chain of that path (Helper 1.0.8, proxy 1.0.8, product) runs over the
  input with origin ranges; what it hides and the current chain would show is masked by
  ``redact()`` itself (``sanitize._redact_credentials``, ``_covering_floor``).
- The proxy (then the product in worker.py): what the 1.0.8 proxy and the product hide of a text
  stays hidden when the new rule changed it (``proxy_sanitize._sanitize_text``).
- ``redact_response``: the complete 1.0.8 chain floor as before (``_floor_response``).

Inputs of reviews 302-rv, r2rv, r3rv, r4rv and r5rv are regression inputs on every path
(``redact``, ``redact_response``, proxy + product, JSON, ``{"output": ...}``); a differential fuzz
compares the ``redact()`` path and the proxy path with the 1.0.8 and 1.0.6 chains. Every value
is synthetic.

NETOPS_R6_FUZZ_CASES sets the number of fuzz inputs (default 400), NETOPS_R6_FUZZ_SEED the seed.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import os
import pathlib
import random
import re

import pytest

from netops.redaction import redact as product_redact
from netops_helper import proxy_sanitize as P
from netops_helper import sanitize as S
from netops_helper.proxy import Proxy
from netops_helper.proxy_sanitize import sanitize_object, sanitize_text
from netops_helper.sanitize import redact, redact_response

HERE = pathlib.Path(__file__).parent
V1_FIXTURES = pathlib.Path(__file__).resolve().parents[3] / "tests/v1/fixtures"


def _load(path, alias):
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FLOOR = _load(HERE / "test_response_floor_1_0_8_and_main.py", "response_floor_reference_302r6")
WITHHELD = FLOOR.WITHHELD
OLD_PROXY = _load(V1_FIXTURES / "proxy_sanitize_1_0_6.py", "proxy_sanitize_1_0_6_302r6")
OLD_PRODUCT = _load(V1_FIXTURES / "redaction_1_0_6.py", "redaction_1_0_6_302r6")
OLD_HELPER = _load(V1_FIXTURES / "sanitize_1_0_6.py", "sanitize_1_0_6_302r6")

CASES = int(os.environ.get("NETOPS_R6_FUZZ_CASES", "400"))
SEED = int(os.environ.get("NETOPS_R6_FUZZ_SEED", "302006"))


def _shown(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _redact(text):
    try:
        return redact(text)
    except ValueError:
        return WITHHELD


def _response(text):
    try:
        return redact_response(text, ())
    except ValueError:
        return WITHHELD


def _proxy_worker(value):
    return _shown(product_redact(sanitize_object(value))[0])


def _proxy_final(text):
    """The proxy's final tools/call response for a Helper text result."""
    message = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": text}]}}
    message = sanitize_object(message, ())
    Proxy._sanitize_result_text(message, ())
    return json.dumps(message, ensure_ascii=False)


def _helper_chain(text):
    """redact() (e.g. a diagnostic output), then the proxy and the product (HelperBridge.call)."""
    helper = _redact(text)
    return WITHHELD if helper is WITHHELD else _proxy_worker(helper)


# --- The frozen released chains of the same paths -------------------------------------------------

def _old_helper_chain(text):
    """The redact() path in 1.0.8: Helper 1.0.8 credential rules, proxy 1.0.8, product."""
    helper = FLOOR.RULES_1_0_8._redact_credentials(text, ())
    return _shown(product_redact(FLOOR.PROXY_1_0_8._sanitize_object(str.__str__(helper), ()))[0])


def _old_helper_chain_1_0_6(text):
    """The redact() path in 1.0.6: Helper, proxy and product of 1.0.6."""
    return _shown(OLD_PRODUCT.redact(OLD_PROXY.sanitize_object(OLD_HELPER.redact(text)))[0])


def _old_proxy_worker(value):
    """The proxy path in 1.0.8: proxy 1.0.8, product."""
    return _shown(product_redact(FLOOR.PROXY_1_0_8._sanitize_object(value, ()))[0])


def _old_proxy_worker_1_0_6(value):
    return _shown(OLD_PRODUCT.redact(OLD_PROXY.sanitize_object(value))[0])


def _paths(text):
    """(name, output) of every path to the AI client: redact() -> proxy -> product (text,
    {"output": ...}, its JSON), the proxy and the product alone (the same three forms),
    redact_response and the final proxy response, also for {"output": text} as a JSON text."""
    helper = _redact(text)
    if helper is WITHHELD:
        yield "redact-proxy-worker", WITHHELD
    else:
        yield "redact-proxy-worker", _proxy_worker(helper)
        yield "redact-proxy-worker-object", _proxy_worker({"output": helper})
        yield "redact-proxy-worker-json", _proxy_worker(json.dumps({"output": helper}))
    yield "proxy-worker", _proxy_worker(text)
    yield "proxy-worker-object", _proxy_worker({"output": text})
    yield "proxy-worker-json", _proxy_worker(json.dumps({"output": text}))
    for name, value in (("response", text), ("response-json", json.dumps({"output": text}))):
        response = _response(value)
        yield name, response
        if response is not WITHHELD:
            yield name + "-final", _proxy_final(response)


def _visible(secret, output):
    return output is not WITHHELD and secret in output


# --- Inputs of the reviews 302-rv .. 302-r5rv -----------------------------------------------------

LF4097 = "\n" * 4097
# name: (text, secrets hidden on every path, secrets hidden on the paths through the Helper rules)
REVIEW = {
    # 302-rv finding 1: the algorithm was taken for the value and the hash stayed.
    "rv-algorithm": ("enable secret sha512 synthetic-canary", ("synthetic-canary",), ()),
    # 302-rv finding 2: redact() left an enable value in a JSON document.
    "rv-json-enable": ('{"config":"enable secret 5 synthetic-canary"}', ("synthetic-canary",), ()),
    # 302-r2rv: the new proxy rule removed `set` before `passwd` on the next line.
    "r2rv-algorithm": ("enable algorithm-type scrypt secret $9$synthetic-hash set\npasswd synthetic-canary",
                       ("synthetic-canary", "synthetic-hash"), ()),
    "r2rv-sha512": ("secret sha512 $6$s$synthetic-hash set\npasswd synthetic-canary",
                    ("synthetic-canary", "synthetic-hash"), ()),
    # 302-r3rv: a hash that ends like an anchor stayed whole.
    "r3rv-hash": ("secret sha512 $6$s$syntheticset", ("syntheticset",), ()),
    "r3rv-json": ('{"config":"secret sha512 $6$s$syntheticset"}', ("syntheticset",), ()),
    "r3rv-nested": ('{"output":"{\\"config\\":\\"secret sha512 $6$s$syntheticset\\"}"}', ("syntheticset",), ()),
    # 302-r4rv: the continuation lay beyond the 4096-character window.
    "r4rv-hash": ("secret sha512 $6$s$syntheticset" + LF4097 + "passwd synthetic-canary",
                  ("synthetic-canary", "syntheticset"), ()),
    "r4rv-set": ("secret sha512 set" + LF4097 + "passwd synthetic-canary", ("synthetic-canary",), ()),
    # 302-r5rv finding 1: a multiword anchor in an unclosed quoted value, the continuation far away.
    "r5rv-unclosed-quote": ('tacacs-server key "syntheticset passwd' + "\n" * 4097 + "synthetic-canary",
                            ("synthetic-canary",), ("syntheticset",)),
    # 302-r5rv finding 2: a whole private key header inside an account value.
    "r5rv-key-header": ('tacacs-server key "-----BEGIN RSAPRIVATE KEY-----"\nsynthetic-key-canary\n'
                        "-----END RSAPRIVATE KEY-----", ("synthetic-key-canary",), ()),
}
REVIEW["r5rv-single-quote"] = ("tacacs-server key 'syntheticset passwd" + "\n" * 4097 + "synthetic-canary",
                               ("synthetic-canary",), ())
REVIEW["r5rv-key-unquoted"] = ("tacacs-server key -----BEGIN RSAPRIVATE KEY-----\nsynthetic-key-canary\n"
                               "-----END RSAPRIVATE KEY-----", ("synthetic-key-canary",), ())
REVIEW["r5rv-key-far-end"] = ('tacacs-server key "-----BEGIN RSAPRIVATE KEY-----"\n'
                              + "\n".join("synthetic-key-canary%d" % index for index in range(12))
                              + "\n-----END RSAPRIVATE KEY-----", ("synthetic-key-canary",), ())
# Variants of r5rv with the other account rules and gaps: only the floors are compared (with `enable
# secret` and `username` the 1.0.8 Helper rules hid the first word of the quoted value themselves,
# and the product then did not take the canary in 1.0.8 either).
VARIANTS = {}
for prefix in ("username admin secret ", "configure account admin encrypted ", "enable secret ",
               "enable algorithm-type scrypt secret ", "radius-server key 7 "):
    for gap in ("\n", "\n" * 4097, " " * 5000, "\n\t" * 3000):
        VARIANTS["unclosed-%s-%d" % (prefix.split()[0], len(gap))] = (
            prefix + '"syntheticset passwd' + gap + "synthetic-canary", ("synthetic-canary",), ())
    VARIANTS["key-%s" % prefix.split()[0]] = (
        prefix + '"-----BEGIN RSAPRIVATE KEY-----"\nsynthetic-key-canary\n-----END RSAPRIVATE KEY-----',
        ("synthetic-key-canary",), ())


@pytest.mark.parametrize("name", REVIEW)
def test_review_inputs_on_every_path(name):
    text, always, helper = REVIEW[name]
    for path, output in _paths(text):
        for secret in always:
            assert not _visible(secret, output), (name, path, _shown(output)[-300:])
        if not path.startswith("proxy-worker"):
            for secret in helper:
                assert not _visible(secret, output), (name, path, _shown(output)[:300])


def _cjk_values(text):
    """The input with each `synthetic` replaced by unique CJK characters (anchors such as the
    `set` of `syntheticset` stay), for the floor comparison."""
    pool = iter(chr(code) for code in range(0x4E00, 0x4E00 + 3000))
    return re.sub("synthetic", lambda match: "".join(next(pool) for _ in range(3)), text)


@pytest.mark.parametrize("name", [*REVIEW, *VARIANTS])
def test_review_inputs_keep_the_released_floors(name):
    text, always, helper = REVIEW.get(name) or VARIANTS[name]
    text = _cjk_values(text)
    hidden = FLOOR._hidden
    for document in (text, {"output": text}):
        old, new = _old_proxy_worker(document), _proxy_worker(document)
        assert not hidden(text, old) - hidden(text, new), (name, document)
        assert not hidden(text, _old_proxy_worker_1_0_6(document)) - hidden(text, new), (name, document)
    new = _helper_chain(text)
    assert not hidden(text, _old_helper_chain(text)) - hidden(text, new), (name, new[-300:])
    assert not hidden(text, _old_helper_chain_1_0_6(text)) - hidden(text, new), (name, new[-300:])
    FLOOR._check(text)


def test_review_r5rv_exact_results():
    # Finding 1: the account value is hidden whole; the canary that the product hid through
    # `set` + `passwd` in the 1.0.8 chain is masked by redact() itself.
    text = REVIEW["r5rv-unclosed-quote"][0]
    assert redact(text) == "tacacs-server key <REDACTED>" + "\n" * 4097 + "<REDACTED>"
    # Finding 2: the key body and END line (the product's 1.0.8 range) are masked by redact().
    text = REVIEW["r5rv-key-header"][0]
    assert redact(text) == "tacacs-server key <REDACTED><REDACTED>"
    # A Helper output that already covers the floor does not change in the proxy and product.
    for name in ("r5rv-unclosed-quote", "r5rv-key-header"):
        once = redact(REVIEW[name][0])
        assert product_redact(sanitize_object(once))[0] == once


def test_review_r4rv_proxy_result():
    text = REVIEW["r4rv-hash"][0]
    # No Helper rule takes a bare `secret sha512` line (as in 1.0.8): the proxy's floor hides it.
    assert redact(text) == text
    assert sanitize_text(text) == "secret <REDACTED> <REDACTED>" + LF4097 + "passwd <REDACTED>"


# --- The guarantee is structural: it holds for a rule that removes anchors -------------------------

def test_redact_floor_holds_for_a_helper_rule_that_removes_an_anchor(monkeypatch):
    current = S._redact_current

    def weakening(value, normalized):
        # Hides every `set`: the product's `set` + `passwd` rule loses its anchor.
        return S.replace(current(value, normalized), "set", "<REDACTED>")

    monkeypatch.setattr(S, "_redact_current", weakening)
    for text in ("tacacs-server key k1\nset passwd 一丁丂", "tacacs-server key k1 set passwd 一丁丂",
                 "username a secret 5 x\n  set passwd\n\n一丁丂\n"):
        assert "一" not in _helper_chain(text), text
        assert not FLOOR._hidden(text, _old_helper_chain(text)) - FLOOR._hidden(text, _helper_chain(text))
        assert "一" not in redact(text)  # redact() masks it itself


def test_proxy_floor_holds_for_a_typed_rule_that_removes_an_anchor(monkeypatch):
    # A typed rule that also takes the `set` after the value: the product loses its anchor.
    monkeypatch.setattr(P, "CISCO_TYPED_SECRET", re.compile(r"(?im)^(secret[ \t]+sha512[ \t]+)\S+(?:[ \t]+set)?"))
    text = "secret sha512 $6$s$h set\npasswd 一丁丂"
    assert "一" not in _old_proxy_worker(text)
    assert "一" not in sanitize_text(text) and "一" not in _proxy_worker(text)
    assert "一" not in _proxy_worker({"output": text})


def test_covering_floor_steps():
    plain = "abcdefghij"
    released = [(2, 4), (6, 8)]
    output = S._origin(plain)

    # The later layers hide `cd`: only 6..8 is masked in the layer's output.
    def later(text):
        return S.replace(text, "cd", "<R>")
    assert str.__str__(S._covering_floor(plain, released, output, later)) == "abcdef<REDACTED>ij"
    # Nothing is missing: the output stays as it is.
    assert S._covering_floor(plain, released, output,
                             lambda text: S.replace(S.replace(text, "cd", "<R>"), "gh", "<R>")) is output

    # A later layer that shows again what the layer did not mask: every released character is
    # masked in the output itself.
    def revealing(text):
        return S._origin(plain)
    assert str.__str__(S._covering_floor(plain, released, output, revealing)) == "ab<REDACTED>ef<REDACTED>ij"


def test_mask_origin():
    marked = S.edits(S._origin("abcdefgh"), [(2, 4, "XYZ")])  # `cd` replaced: no origin
    assert str.__str__(S._mask_origin(marked, [(0, 1), (3, 6)])) == "<REDACTED>bXYZ<REDACTED>gh"
    assert str.__str__(S._mask_origin(marked, [(1, 2), (4, 5)])) == "a<REDACTED>XYZ<REDACTED>fgh"
    assert S._mask_origin(marked, []) is marked
    assert S._unclaimed("abcdefgh", S._mask_origin(marked, [(6, 8)])) == [(2, 4), (6, 8)]


def test_range_operations():
    assert S._subtract([(0, 10)], [(2, 3), (5, 7)]) == [(0, 2), (3, 5), (7, 10)]
    assert S._subtract([(0, 2), (4, 6)], [(1, 5)]) == [(0, 1), (5, 6)]
    assert S._subtract([(0, 2)], []) == [(0, 2)]
    assert S._subtract([], [(0, 2)]) == []
    assert S._subtract([(3, 4)], [(0, 10)]) == []
    assert S._union([(0, 2), (5, 6)], [(1, 3), (6, 8)]) == [(0, 3), (5, 8)]


def test_text_without_a_difference_takes_no_floor_pass(monkeypatch):
    # Without an account rule (or with the 1.0.8 text) redact() does not compute the chain floor.
    def fail(*args):
        raise AssertionError("floor computed")
    monkeypatch.setattr(S, "_later_layers", fail)
    assert redact("set password x\npassword: y\nENC abc") == "set password x\npassword: <REDACTED>\nENC <REDACTED>"
    assert redact("username a secret 5 x") == "username a secret 5 <REDACTED>"
    # And the proxy only when its new rule changed the text.
    monkeypatch.setattr(S, "_covering_floor", fail)
    assert sanitize_text("secret 5 x\nset passwd y") == "secret 5 <REDACTED>\nset passwd y"


# --- Differential fuzz over the redact() path and the proxy path ----------------------------------

_UNIQUE = itertools.cycle([chr(code) for code in range(0x4E00, 0x4E00 + 20000)])


def _cjk():
    return "".join(next(_UNIQUE) for _ in range(3))


PREFIXES = ("secret sha512 ", "password scrypt ", "secret ", "enable secret ", "enable secret sha512 ",
            "enable password level 3 ", "enable algorithm-type scrypt secret ", "enable secret 5 ",
            "R1#enable secret ", "username admin secret sha512 ", "username admin password ",
            "username admin privilege 15 secret 9 ", "tacacs-server key ", "radius-server key 7 ",
            "configure account admin encrypted ", "set password ", "ENABLE SECRET SHA512 ")
ANCHORS = ("set", "unset", "Set", "encrypted", "token", "password", "passwd", "password:", "token=", '"password":',
           '"passphrase":"', "community", "-----BEGIN", "ENC", "psk", "md5", "key", "secret", "SNMP", "bearer",
           "--password", "pre-shared-key", "set passwd", "set password", "")
VALUES = ("{c}", "{c}{a}", "$6$s${c}{a}", "{a}{c}", "{c}{a}{c2}", '"{c}{a}', '"{c}{a}"', "'{c} {a}", '"{c} {a}',
          "{c} {a}", "$9${c} {a}", '"-----BEGIN RSAPRIVATE KEY-----"', "-----BEGIN PRIVATE KEY-----{c}",
          '"{c}-----BEGIN RSAPRIVATE KEY-----"')
GAP_UNITS = (" ", "\n", "\n\t", "\n ", "\r\n")
GAP_SIZES = (1, 1, 1, 2, 5, 300, 4090, 4096, 4097, 4200, 5000)
CONTINUATIONS = ("passwd {v}", "password {v}", "= {v}", ": {v}", "{v}", "{v}\n-----END RSAPRIVATE KEY-----",
                 "{v}\n-----END PRIVATE KEY-----", " PRIVATE KEY-----\n{v}\n-----END PRIVATE KEY-----",
                 " RSAPRIVATE KEY-----\n{v}\n-----END RSAPRIVATE KEY-----", "string\nis\n:\n{v}", "7 {v}",
                 '"{v}"', "psk {v}", "set passwd {v}", "{v} rest of line", "")


def _fuzz_cases(count, seed):
    generator = random.Random(seed)
    pick = generator.choice
    for _ in range(count):
        lines = []
        for _ in range(generator.choice((1, 1, 2, 3))):
            value = pick(VALUES).format(a=pick(ANCHORS), c=_cjk(), c2=_cjk())
            unit, size = pick(GAP_UNITS), pick(GAP_SIZES)
            if unit == "\r\n" and generator.randrange(2):
                unit = "\n"  # most cases without CR: redact() runs the credential rules
            lines.append(pick(PREFIXES) + value + (unit * size)[:max(size, 1)] + pick(CONTINUATIONS).format(v=_cjk()))
        text = "\n".join(lines)
        if generator.randrange(3) == 0:
            text = "hostname r1\n" + text + "\nend\n"
        yield text


FUZZ = list(_fuzz_cases(CASES, SEED))


def test_fuzz_redact_path_keeps_the_1_0_8_and_1_0_6_floors():
    hidden = FLOOR._hidden
    for index, text in enumerate(FUZZ):
        new = _helper_chain(text)
        for name, old in (("1.0.8", _old_helper_chain(text)), ("1.0.6", _old_helper_chain_1_0_6(text))):
            missing = hidden(text, old) - hidden(text, new)
            assert not missing, (index, name, text[:200], sorted(missing), _shown(new)[:400])
        if index % 4 == 0:
            # The same output inside an object and as the JSON text the proxy decodes.
            helper = _redact(text)
            if helper is not WITHHELD:
                for document in ({"output": helper}, json.dumps({"output": helper})):
                    assert not hidden(text, _old_helper_chain(text)) - hidden(text, _proxy_worker(document))


def test_fuzz_redact_on_a_json_document_keeps_the_1_0_8_floor():
    hidden = FLOOR._hidden
    for text in FUZZ[:CASES // 4]:
        document = json.dumps({"config": text}, ensure_ascii=False)
        new = _helper_chain(document)
        missing = hidden(text, _old_helper_chain(document)) - hidden(text, new)
        assert not missing, (document[:200], sorted(missing), _shown(new)[:400])


def test_fuzz_proxy_path_keeps_the_1_0_8_and_1_0_6_floors():
    hidden = FLOOR._hidden
    for text in FUZZ:
        for document in (text, {"output": text}):
            new = _proxy_worker(document)
            for name, old in (("1.0.8", _old_proxy_worker(document)), ("1.0.6", _old_proxy_worker_1_0_6(document))):
                missing = hidden(text, old) - hidden(text, new)
                assert not missing, (name, text[:200], sorted(missing), new[:400])


def test_fuzz_response_keeps_the_floors_and_is_a_fixed_point():
    for text in FUZZ[:CASES // 8]:
        FLOOR._check(text)
        response = _response(text)
        if response is not WITHHELD:
            assert product_redact(sanitize_object(response))[0] == response, text[:200]


def test_fuzz_corpus_reaches_the_floor_passes(monkeypatch):
    # The corpus exercises both floors: redact() masks text the current chain would show, and so
    # does the proxy (not only cases that the current rules already cover).
    calls = {"redact": 0, "proxy": 0}
    original = S._covering_floor

    def counted(plain, released, output, later):
        covered = original(plain, released, output, later)
        if covered is not output:
            calls["proxy" if "_sanitize_text" in later.__qualname__ else "redact"] += 1
        return covered

    monkeypatch.setattr(S, "_covering_floor", counted)
    for text in FUZZ[:CASES // 4]:
        _redact(text)
        sanitize_text(text)
    assert calls["redact"] > 5 and calls["proxy"] > 5, calls
