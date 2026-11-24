#!/usr/bin/env python3
"""verification: a limit of the continuation window must not weaken the floor (inputs kept in r6).

Review finding 1: `"secret sha512 $6$s$syntheticset" + "\\n" * 4097 + "passwd
synthetic-canary"` (and the same with the whole token `set`) lost the anchor `set` in the typed
proxy rule, and the canary passed `redact()`, the proxy and the product, where 1.0.6 hid it.

verification replaced the anchor logic (continuation window, deferral, kept anchors) by a structural
floor: the proxy hides every character that the 1.0.8 proxy and the product hide of its text, and
``redact()`` every character that the complete 1.0.8 chain (Helper 1.0.8, proxy 1.0.8, product)
hides and the current chain would show. The inputs of r5 (gaps around the former 4096-character
window, the Helper account rules, communities over five lines, a product-only private key header)
stay as regression inputs on every path. Every value is synthetic.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import pathlib
import random
import re

import pytest

from netops.redaction import redact as product_redact
from netops_helper import sanitize as S
from netops_helper import proxy_sanitize as P
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


FLOOR = _load(HERE / "test_response_floor_1_0_8_and_main.py", "response_floor_reference_round5")
WITHHELD = FLOOR.WITHHELD
OLD_PROXY = _load(V1_FIXTURES / "proxy_sanitize_1_0_6.py", "proxy_sanitize_1_0_6_round5")
OLD_PRODUCT = _load(V1_FIXTURES / "redaction_1_0_6.py", "redaction_1_0_6_round5")

CANARY = "synthetic-canary"
HASH = "$6$s$syntheticset"
CORE = "syntheticq"
# The character limit of the r5 continuation window (removed in r6); the gaps around it stay as
# regression inputs.
LIMIT = 4096


def review_text(value=HASH, gap="\n" * 4097):
    return "secret sha512 " + value + gap + "passwd " + CANARY


def _shown(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _proxy_worker(value):
    return _shown(product_redact(sanitize_object(value))[0])


def _old_proxy_worker(value):
    return _shown(OLD_PRODUCT.redact(OLD_PROXY.sanitize_object(value))[0])


def _proxy_final(text):
    """The proxy's final tools/call response for a Helper text result."""
    message = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": text}]}}
    message = sanitize_object(message, ())
    Proxy._sanitize_result_text(message, ())
    return json.dumps(message, ensure_ascii=False)


def _response(text):
    try:
        return redact_response(text, ())
    except ValueError:
        return WITHHELD


def _redact(text):
    try:
        return redact(text)
    except ValueError:
        return ""  # output withheld: nothing is shown


def _helper_chain(value):
    """redact() (e.g. a diagnostic output), then the proxy and the product (HelperBridge.call)."""
    return _proxy_worker(_redact(value) if isinstance(value, str) else value)


def _old_helper_chain(text):
    """The same path with the released 1.0.8 Helper credential rules and proxy."""
    helper = FLOOR.RULES_1_0_8._redact_credentials(text, ())
    return _shown(product_redact(FLOOR.PROXY_1_0_8._sanitize_object(str.__str__(helper), ()))[0])


def _paths(text):
    """(name, output) of every path from the review: redact() -> proxy -> product, the proxy and
    the product alone (text, {"output": text}, its JSON), redact_response and the final proxy
    response, also for {"output": text} as a JSON text."""
    yield "redact-proxy-worker", _helper_chain(text)
    yield "redact-proxy-worker-object", _proxy_worker({"output": _redact(text)})
    yield "proxy-worker", _proxy_worker(text)
    yield "proxy-worker-object", _proxy_worker({"output": text})
    yield "proxy-worker-json", _proxy_worker(json.dumps({"output": text}))
    for name, value in (("response", text), ("response-json", json.dumps({"output": text}))):
        response = _response(value)
        if response is WITHHELD:
            continue
        yield name, response
        yield name + "-final", _proxy_final(response)


# Gaps between the anchor and its continuation, around the character limit: the window is
# complete up to LIMIT - 23 newlines (the whole text), the rule is found in it up to LIMIT - 8.
GAP_SIZES = (1, 3, LIMIT - 24, LIMIT - 23, LIMIT - 22, LIMIT - 9, LIMIT - 8, LIMIT - 7, LIMIT - 1, LIMIT,
             LIMIT + 1, LIMIT + 2, 5000, 9000)


def _gaps():
    for size in GAP_SIZES:
        yield "lf-%d" % size, "\n" * size
    for size in (LIMIT - 8, LIMIT + 1, 6000):
        yield "space-%d" % size, " " * size
        yield "crlf-%d" % size, "\r\n" * (size // 2)
        yield "mixed-%d" % size, ("\n \t" * size)[:size]


GAPS = dict(_gaps())


# --- Review finding 1 -------------------------------------------------------------------


@pytest.mark.parametrize("value", [HASH, "set"])
def test_review_input_exact_proxy_result(value):
    text = review_text(value)
    gap = "\n" * 4097
    # The proxy hides the token; the 1.0.8 proxy and product hid the canary through the anchor,
    # so the proxy's floor hides it too (verification).
    assert sanitize_text(text) == "secret <REDACTED> <REDACTED>" + gap + "passwd <REDACTED>"
    assert product_redact(sanitize_text(text))[0] == "secret <REDACTED> <REDACTED>" + gap + "passwd <REDACTED>"
    # No Helper rule takes a bare `secret sha512` line (as in 1.0.8).
    assert redact(text) == text
    assert _helper_chain(text) == "secret <REDACTED> <REDACTED>" + gap + "passwd <REDACTED>"
    # 1.0.6 hid the canary (the floor of the finding).
    assert CANARY not in _old_proxy_worker(text)


@pytest.mark.parametrize("value", [HASH, "set"])
@pytest.mark.parametrize("gap", GAPS)
def test_review_input_hides_value_and_canary_at_every_gap(value, gap):
    text = review_text(value, GAPS[gap])
    assert CANARY not in _old_proxy_worker(text)
    for name, output in _paths(text):
        assert CANARY not in output, (gap, name, output[-200:])
        assert "synthetic" not in output, (gap, name, output[-200:])
    if value == HASH:
        expected = "secret <REDACTED> <REDACTED>" + GAPS[gap] + "passwd <REDACTED>"
        assert sanitize_text(text) == expected, gap


@pytest.mark.parametrize("gap", ["lf-4097", "lf-9000", "crlf-6000"])
def test_review_input_inside_json_documents(gap):
    gap = GAPS.get(gap, "\n" * int(gap.split("-")[1]))
    line = review_text(HASH, gap)
    for document in (json.dumps({"config": line}), json.dumps({"config": line}, separators=(",", ":")),
                     json.dumps({"output": json.dumps({"config": line})}), json.dumps(["hostname r1", line, "end"])):
        for name, output in _paths(document):
            assert CANARY not in output and "synthetic" not in output, (name, output[-200:])


def test_review_input_floor_of_the_response():
    for gap in ("lf-4097", "lf-%d" % (LIMIT - 8), "space-4097", "crlf-6000"):
        FLOOR._check(review_text("$6$s$一丁丂set", GAPS[gap]))
        FLOOR._check(review_text("set", GAPS[gap]).replace(CANARY, "丄丅丆"))


# --- Helper account rules: the value is hidden, the continuation stays hidden ---------------------

HELPER_LINES = {
    "enable-algorithm-second": "enable algorithm-type scrypt secret $9$h $6$s$" + CORE + "set",
    "enable-sha512": "enable secret sha512 $6$s$" + CORE + "set",
    "enable-level": "enable password level 3 " + CORE + "set",
    "prompt-enable": "R1#enable secret $6$s$" + CORE + "set",
    "username-sha512": "username admin secret sha512 $6$s$" + CORE + "set",
    "username-scrypt": "username admin privilege 15 algorithm-type scrypt secret $9$" + CORE + "set",
    "aaa-key": "tacacs-server key " + CORE + "set",
    "exos": "configure account admin encrypted " + CORE + "set",
}


PROXY_TYPED = ("enable-sha512", "enable-level")


@pytest.mark.parametrize("gap", ["lf-1", "lf-3", "lf-4072", "lf-4097", "lf-9000", "space-4097", "mixed-6000"])
@pytest.mark.parametrize("name", HELPER_LINES)
def test_helper_value_and_continuation_are_hidden(name, gap):
    text = HELPER_LINES[name] + GAPS[gap] + "passwd " + CANARY
    helper = redact(text)
    assert CORE not in helper, (name, gap, helper[:200])
    # The 1.0.8 chain (Helper 1.0.8, proxy 1.0.8, product) hides the canary through the anchor.
    assert CANARY not in _old_helper_chain(text), (name, gap)
    for path, output in _paths(text):
        assert CANARY not in output, (name, gap, path, output[-200:])
        if not path.startswith("proxy-worker") or name in PROXY_TYPED:
            # The proxy alone has no account rules (as in 1.0.6): only its typed rule hides a value.
            assert CORE not in output, (name, gap, path, output[:200])
    cjk = text.replace(CORE, "一丁丂").replace(CANARY, "丄丅丆")
    assert not FLOOR._hidden(cjk, _old_helper_chain(cjk)) - FLOOR._hidden(cjk, _helper_chain(cjk)), (name, gap)


def test_helper_exact_results():
    # verification: the account rule hides the whole value; the canary that the 1.0.8 chain hid
    # through the product's `set` + `passwd` rule is masked by redact() itself (its floor).
    text = "enable algorithm-type scrypt secret $9$h $6$s$" + CORE + "set\npasswd " + CANARY
    assert redact(text) == "enable algorithm-type scrypt secret <REDACTED>\npasswd <REDACTED>"
    assert _helper_chain(text) == "enable algorithm-type scrypt secret <REDACTED>\npasswd <REDACTED>"
    assert redact("tacacs-server key $6$set\npasswd " + CANARY) == "tacacs-server key <REDACTED>\npasswd <REDACTED>"
    assert redact("tacacs-server key x-set\npasswd " + CANARY) == "tacacs-server key <REDACTED>\npasswd <REDACTED>"
    # The first of two tokens holds the anchor; the second is the label of the product rule.
    text = "enable algorithm-type scrypt secret $9$" + CORE + "set passwd\n" + CANARY
    assert redact(text) == "enable algorithm-type scrypt secret <REDACTED>\n<REDACTED>"
    assert CANARY not in _helper_chain(text)
    # Review fuzz: the proxy rule took the rest of the line in the 1.0.8 chain.
    text = "username admin secret sha512 一丁丂token=丄丅丆" + " " * 5000 + "丏丐丑"
    assert redact(text).startswith("username admin secret <REDACTED>")
    assert not FLOOR._hidden(text, _old_helper_chain(text)) - FLOOR._hidden(text, _helper_chain(text))
    assert "丏" not in _old_helper_chain(text) and "丏" not in _helper_chain(text)
    # FortiOS `ENC` + `psk VALUE` (full helper run of r5): the value stays hidden.
    text = "tacacs-server key ENC psk 一丁丂\nend"
    assert redact(text).startswith("tacacs-server key <REDACTED> ") and "一" not in redact(text)
    assert "ENC" not in redact(text)
    # The 1.0.8 rules hid the token themselves (`username NAME secret 9 set`): the 1.0.8 text.
    assert redact("username admin secret 9 set password " + CANARY + "\nend").startswith(
        "username admin secret 9 <REDACTED> password")
    # Without a continuation the whole value is hidden.
    assert redact("tacacs-server key " + CORE + "set") == "tacacs-server key <REDACTED>"
    assert redact("enable algorithm-type scrypt secret $9$h " + CORE + "set") == (
        "enable algorithm-type scrypt secret <REDACTED>")
    # A whole anchor token is hidden with the value; what the 1.0.8 chain hid after it stays hidden.
    long = "enable algorithm-type scrypt secret $9$h set" + "\n" * 5000 + "passwd " + CANARY
    assert redact(long) == "enable algorithm-type scrypt secret <REDACTED>" + "\n" * 5000 + "passwd <REDACTED>"
    assert redact("enable algorithm-type scrypt secret $9$h set" + "\n" * 5000 + "end") == (
        "enable algorithm-type scrypt secret <REDACTED>" + "\n" * 5000 + "end")
    assert redact("enable algorithm-type scrypt secret $9$h set\n" + "end") == (
        "enable algorithm-type scrypt secret <REDACTED>\nend")


def test_a_value_without_an_anchor_is_hidden_and_fixed_points_hold():
    for text in ("username admin secret sha512 $6$s$" + CORE + "\n" * 5000 + "passwd " + CANARY,
                 "enable secret 5 " + CORE + "\n" * 5000 + "end"):
        assert CORE not in redact(text)
    for text in ("enable algorithm-type scrypt secret $9$h $6$s$" + CORE + "set\npasswd " + CANARY,
                 "username admin secret sha512 $6$s$" + CORE + "set" + "\n" * 5000 + "passwd " + CANARY,
                 review_text(), review_text("set")):
        once = _helper_chain(text)
        assert _helper_chain(once) == once, text[:80]
        response = _response(text)
        if response is not WITHHELD:
            assert product_redact(sanitize_object(response))[0] == response


# --- Other limits of the new logic ----------------------------------------------------------------

def test_labeled_community_over_five_lines():
    # r4 counted two non-blank lines of its window: `community` was hidden and the value passed.
    for value in ("community", "$6$s$" + CORE + "-community"):
        text = "secret sha512 " + value + "\nstring\nis\n:\n" + CANARY
        assert CANARY not in _old_proxy_worker(text)
        for path, output in _paths(text):
            assert CANARY not in output, (value, path, output)
    text = "secret sha512 community\nstring\nis\n:\n" + CANARY
    # The typed rule hides `community`; the proxy's 1.0.8 floor hides what LABELED_COMMUNITY hid.
    assert CANARY not in sanitize_text(text) and CANARY in text


def test_product_private_key_with_a_far_end_line():
    # A header only the product takes (`RSAPRIVATE`): its END lies past the window lines.
    body = "\n".join("一丁丂%d" % index for index in range(12))
    for value in ("-----BEGIN", CORE + "-----BEGIN"):
        text = "secret sha512 " + value + " RSAPRIVATE KEY-----\n" + body + "\n-----END RSAPRIVATE KEY-----"
        assert "一丁丂" not in _old_proxy_worker(text)
        for path, output in _paths(text):
            assert "一丁丂" not in output, (value, path, output)
        FLOOR._check(text)


# --- Fuzz: long gaps between an anchor and its continuation ---------------------------------------

_UNIQUE = itertools.cycle([chr(code) for code in range(0x4E00, 0x4E00 + 20000)])


def _cjk():
    return "".join(next(_UNIQUE) for _ in range(3))


FUZZ_PREFIXES = ("secret sha512 ", "password scrypt ", "enable secret sha512 ", "enable password level 3 ",
                 "enable algorithm-type scrypt secret $9$h ", "secret level 15 5 ", "username admin secret sha512 ",
                 "R1#enable secret ", "tacacs-server key ", "ENABLE SECRET SHA512 ")
FUZZ_ANCHORS = ("set", "unset", "Set", "encrypted", "token", "password", "passwd", "password:", "token=",
                '"password":', "community", "-----BEGIN")
FUZZ_SHAPES = ("{a}", "{c}{a}", "$6$s${c}{a}", "{a}{c}", "{c}{a}{c2}")
FUZZ_GAPS = (4085, 4088, 4089, 4096, 4097, 4200, 6000)
FUZZ_GAP_TEXT = ("\n", " ", "\r\n", "\n\t")
FUZZ_CONTINUATIONS = ("password {0}", "passwd {0}", "= {0}", ": {0}", "{0}", " RSAPRIVATE KEY-----\n{0}\n"
                      "-----END RSAPRIVATE KEY-----")


HELPER_ONLY = ("enable algorithm-type", "username", "R1#", "tacacs")


def _fuzz_cases(count, seed):
    generator = random.Random(seed)
    pick = generator.choice
    for _ in range(count):
        core = _cjk()
        prefix = pick(FUZZ_PREFIXES)
        value = pick(FUZZ_SHAPES).format(a=pick(FUZZ_ANCHORS), c=core, c2=_cjk())
        unit = pick(FUZZ_GAP_TEXT)
        gap = (unit * pick(FUZZ_GAPS))[:pick(FUZZ_GAPS)]
        line = prefix + value + gap + pick(FUZZ_CONTINUATIONS).format(_cjk())
        text = line if generator.randrange(3) else "hostname r1\n" + line + "\nend\n"
        yield core, prefix.startswith(HELPER_ONLY), text


FUZZ = list(_fuzz_cases(160, 302005))


def test_fuzz_every_path_keeps_the_1_0_6_and_1_0_8_floors():
    for _, _, text in FUZZ:
        for document in (text, {"output": text}):
            old, new = _old_proxy_worker(document), _proxy_worker(document)
            assert not FLOOR._hidden(text, old) - FLOOR._hidden(text, new), (text[:120], new[-200:])
        old, new = _old_helper_chain(text), _helper_chain(text)
        assert not FLOOR._hidden(text, old) - FLOOR._hidden(text, new), (text[:120], new[-200:])


def test_fuzz_value_is_hidden():
    for core, helper_only, text in FUZZ:
        for path, output in _paths(text):
            if path.startswith("proxy-worker") and helper_only:
                continue  # Helper rules only (the proxy has no account rules, as in 1.0.6)
            assert not any(char in output for char in core), (text[:120], path, output[:300])


def test_fuzz_response_floor_and_fixed_point():
    for _, _, text in FUZZ[:80]:
        FLOOR._check(text)
        response = _response(text)
        if response is not WITHHELD:
            assert product_redact(sanitize_object(response))[0] == response, text[:120]
