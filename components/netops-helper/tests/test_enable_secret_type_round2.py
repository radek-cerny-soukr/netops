#!/usr/bin/env python3
"""`enable secret|password` values after a type word and inside JSON strings.

Review finding 1: `enable secret sha512 VALUE` hid the algorithm name instead of
the value (Helper CISCO_ENABLE_SECRET and proxy CISCO_SECRET take a numeric type only).
Finding 2: the standalone ``redact()`` kept `enable secret|password VALUE` inside a JSON
string (the opening quote before `enable` fails ``(?<!\\S)``, and the account rules that
decode JSON strings did not know `enable`).

The canary must be missing from ``redact``, ``redact_response`` and the final proxy
response (``sanitize_object`` of the message plus ``Proxy._sanitize_result_text``), in
plain text and inside JSON. Every character the frozen 1.0.6 proxy and product, the
complete 1.0.8 chain and the main chain hide stays hidden. Every value is synthetic.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import pathlib
import time

import pytest

from netops.redaction import redact as product_redact
from netops_helper import sanitize as S
from netops_helper import proxy_sanitize as P
from netops_helper.proxy import Proxy
from netops_helper.proxy_sanitize import sanitize_object, sanitize_text
from netops_helper.sanitize import redact, redact_response

HERE = pathlib.Path(__file__).parent
V1_FIXTURES = pathlib.Path(__file__).resolve().parents[3] / "tests/v1/fixtures"
CANARY = "synthetic-canary"


def _load(path, alias):
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Frozen 1.0.8 and main references and the property check of the earlier change.
FLOOR = _load(HERE / "test_response_floor_1_0_8_and_main.py", "response_floor_reference_round2")
WITHHELD = FLOOR.WITHHELD
# Frozen 1.0.6 proxy and product (worker) redaction.
OLD_PROXY = _load(V1_FIXTURES / "proxy_sanitize_1_0_6.py", "proxy_sanitize_1_0_6_round2")
OLD_PRODUCT = _load(V1_FIXTURES / "redaction_1_0_6.py", "redaction_1_0_6_round2")


def _proxy_final(text):
    """The proxy's final tools/call response for a Helper text result."""
    message = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": text}]}}
    message = sanitize_object(message, ())
    Proxy._sanitize_result_text(message, ())
    return json.dumps(message, ensure_ascii=False)


def _outputs(text, *, standalone=True):
    response = redact_response(text, ())
    outputs = {"redact_response": response, "proxy_final": _proxy_final(response)}
    if standalone:
        outputs["redact"] = redact(text)
    return outputs


# --- Review: exact inputs -----------------------------------------------------------------

REVIEW = {
    "enable-secret-sha512": "enable secret sha512 synthetic-canary",
    "enable-secret-sha512-lf": "enable secret sha512 synthetic-canary\n",
    "enable-password-sha512": "enable password sha512 synthetic-canary",
    "enable-password-sha512-lf": "enable password sha512 synthetic-canary\n",
    "json-enable-secret-sha512": '{"config":"enable secret sha512 synthetic-canary"}',
    "json-enable-password-sha512": '{"config":"enable password sha512 synthetic-canary"}',
    "json-enable-secret-5": '{"config":"enable secret 5 synthetic-canary"}',
    "json-enable-password": '{"config":"enable password synthetic-canary"}',
}


@pytest.mark.parametrize("name", REVIEW)
def test_review_inputs_hide_the_value_everywhere(name):
    text = REVIEW[name]
    for layer, output in _outputs(text).items():
        assert CANARY not in output, (layer, output)
        assert "canary" not in output, (layer, output)
    if text.startswith("{"):
        for layer in ("redact", "redact_response"):
            decoded = json.loads(_outputs(text)[layer])
            assert list(decoded) == ["config"]
            assert decoded["config"].startswith("enable ")
            assert decoded["config"].endswith("<REDACTED>")


def test_review_finding_2_standalone_redact_keeps_the_json_and_the_type():
    # Numeric type and no type: only the value is hidden; the document stays the same JSON.
    assert redact('{"config":"enable secret 5 synthetic-canary"}', ()) == (
        '{"config":"enable secret 5 <REDACTED>"}')
    assert redact('{"config":"enable password synthetic-canary"}', ()) == (
        '{"config":"enable password <REDACTED>"}')
    # A type word: the 1.0.8 rules did not hide it inside JSON, so it stays visible here.
    assert redact('{"config":"enable secret sha512 synthetic-canary"}', ()) == (
        '{"config":"enable secret sha512 <REDACTED>"}')
    assert redact(json.dumps({"config": "hostname r1\nenable secret 9 $9$synthetic-canary\nend"}), ()) == (
        json.dumps({"config": "hostname r1\nenable secret 9 <REDACTED>\nend"}))


def test_review_finding_1_plain_line_hides_the_value_and_the_released_floor():
    # The 1.0.8 rule hid `sha512`, so it stays hidden; the value is hidden by the new rule.
    for text in ("enable secret sha512 synthetic-canary", "enable password sha512 synthetic-canary\n"):
        expected = text.replace("sha512 synthetic-canary", "<REDACTED> <REDACTED>")
        assert redact(text) == expected
        assert redact_response(text, ()) == expected
        for layer, output in _outputs(text).items():
            assert "sha512" not in output, (layer, output)
            assert CANARY not in output, (layer, output)


# --- Platform forms (Cisco IOS/IOS XE, NX-OS, Arista EOS, ASA) -----------------------------------

LINES = {
    "eos-enable-password-sha512": "enable password sha512 $6$salt$synthetic-canary",
    "eos-enable-secret-sha512": "enable secret sha512 $6$salt$synthetic-canary",
    "ios-enable-secret-9": "enable secret 9 $9$synthetic-canary",
    "ios-enable-secret-8": "enable secret 8 $8$synthetic-canary",
    "ios-enable-secret-5": "enable secret 5 $1$salt$synthetic-canary",
    "ios-enable-secret-0": "enable secret 0 synthetic-canary",
    "ios-enable-password": "enable password synthetic-canary",
    "ios-enable-password-7": "enable password 7 synthetic-canary",
    "ios-enable-secret-level": "enable secret level 15 5 $1$salt$synthetic-canary",
    "ios-enable-password-level": "enable password level 3 synthetic-canary",
    "xe-enable-algorithm-scrypt": "enable algorithm-type scrypt secret synthetic-canary",
    "xe-enable-algorithm-sha256": "enable algorithm-type sha256 secret synthetic-canary",
    "xe-enable-algorithm-md5": "enable algorithm-type md5 secret synthetic-canary",
    "nxos-enable-secret-5": "enable secret 5 $5$salt$synthetic-canary",
    "enable-secret-scrypt": "enable secret scrypt $9$synthetic-canary",
    "enable-secret-pbkdf2": "enable secret pbkdf2 synthetic-canary",
    "enable-unknown-type-hash": "enable secret sha384 $6$salt$synthetic-canary",
    "enable-unknown-type-word": "enable secret type10 synthetic-canary",
    "asa-enable-password-encrypted": "enable password synthetic-canary encrypted",
    "asa-enable-password-pbkdf2": "enable password synthetic-canary pbkdf2",
    "upper-case": "ENABLE SECRET SHA512 $6$salt$synthetic-canary",
    "tab-separated": "enable\tsecret\tsha512\t$6$salt$synthetic-canary",
    "indented": "  enable secret sha512 $6$salt$synthetic-canary",
    "prompt": "R1(config)#enable secret sha512 $6$salt$synthetic-canary",
    "nxos-username-password-5": "username admin password 5 $5$salt$synthetic-canary  role network-admin",
    "eos-username-secret-sha512": "username admin privilege 15 role network-admin secret sha512 $6$salt$synthetic-canary",
    "eos-username-secret-0": "username admin secret 0 synthetic-canary",
    "xe-username-algorithm-scrypt": "username admin privilege 15 algorithm-type scrypt secret synthetic-canary",
    "xe-username-secret-9": "username admin privilege 15 secret 9 $9$synthetic-canary",
    "username-secret-scrypt": "username admin secret scrypt $9$synthetic-canary",
    "username-secret-pbkdf2": "username admin secret pbkdf2 synthetic-canary",
    "username-unknown-type-hash": "username admin secret sha384 $6$salt$synthetic-canary",
}
# Lines wrapped by a terminal: a bare `secret|password TYPE VALUE` line. The response chain
# hides them (proxy rule); the standalone redact() has no rule for bare lines, as before.
WRAPPED = {
    "eos-wrapped-secret-sha512": "username admin privilege 15 role network-admin\n secret sha512 $6$salt$synthetic-canary",
    "wrapped-password-sha512": "username admin\npassword sha512 $6$salt$synthetic-canary",
}


def _contexts(line):
    yield "line", line
    yield "line-lf", line + "\n"
    yield "line-crlf", line + "\r\n"
    yield "config", "hostname r1\n!\n" + line + "\n!\nend\n"
    yield "json", json.dumps({"config": line})
    yield "json-compact", json.dumps({"config": line}, separators=(",", ":"))
    yield "json-lines", json.dumps({"config": "hostname r1\n" + line + "\nend", "next": "visible"})
    yield "json-unicode", json.dumps({"config": "hostname r1 é\n" + line, "n": 1}, ensure_ascii=False)
    yield "json-list", json.dumps(["hostname r1", line, "end"])
    yield "json-nested", json.dumps({"output": json.dumps({"config": line})})


@pytest.mark.parametrize("name", LINES)
def test_platform_forms_hide_the_value_in_every_layer_and_context(name):
    for context, text in _contexts(LINES[name]):
        for layer, output in _outputs(text).items():
            assert CANARY not in output, (context, layer, output)
            assert "canary" not in output, (context, layer, output)
        if context.startswith("json") and name != "ios-enable-password-7":
            # The document keeps its structure and its other values (also a nested document,
            # the earlier change). Type 7 is excluded: the 1.0.8 rule CISCO_TYPE7_SECRET takes the
            # rest of the raw JSON token, as before this task (its value is hidden).
            result = json.loads(redact_response(text, ()))
            original = json.loads(text)
            assert type(result) is type(original)
            if isinstance(original, dict):
                assert list(result) == list(original)
                assert result.get("next") == original.get("next")


@pytest.mark.parametrize("name", WRAPPED)
def test_wrapped_bare_lines_are_hidden_by_the_response_chain(name):
    for context, text in _contexts(WRAPPED[name]):
        for layer, output in _outputs(text, standalone=False).items():
            assert CANARY not in output, (context, layer, output)


# The proxy alone (sanitize_text): lines that start with `enable|secret|password` and carry a
# numeric type, a known algorithm name, a level, an algorithm-type or a `$` hash after a word.
PROXY_LINES = [name for name in LINES if not name.startswith(("prompt", "nxos-username", "eos-username",
                                                              "xe-username", "username", "enable-unknown-type-word"))]


@pytest.mark.parametrize("name", PROXY_LINES + list(WRAPPED))
def test_proxy_alone_hides_the_value_after_the_type(name):
    text = {**LINES, **WRAPPED}[name]
    for context, value in _contexts(text):
        if not context.startswith("json"):
            # sanitize_text treats its argument as text; a JSON document goes through sanitize_object.
            cleaned = sanitize_text(value)
            assert CANARY not in cleaned, (context, cleaned)
        for document in (value, {"output": value}):
            cleaned = sanitize_object(document)
            assert CANARY not in json.dumps(cleaned), (context, cleaned)


def test_proxy_rule_keeps_numeric_types_to_cisco_secret():
    # A numeric type alone is CISCO_SECRET's case (1.0.6 rule, unchanged result).
    for text in ("enable secret 5 $1$abc priv-lvl 15", "password 7 0822455D0A16FF", "password 7\nvalue",
                 "Password expires in 5 days"):
        assert P.CISCO_TYPED_SECRET.search(text) is None, text
        assert sanitize_text(text) == OLD_PROXY.sanitize_text(text), text
    assert sanitize_text("enable password sha512 $6$s$h") == "enable password <REDACTED> <REDACTED>"
    assert sanitize_text("enable secret level 15 5 $1$s$h\n") == "enable secret <REDACTED> 15 5 <REDACTED>\n"
    assert sanitize_text("enable algorithm-type scrypt secret plain-x") == (
        "enable algorithm-type scrypt secret <REDACTED>")


def test_helper_rule_keeps_known_types_visible():
    rule = S.CISCO_ENABLE_ACCOUNT_SECRET
    sub = lambda text: rule.sub(S._replace_credential, text)  # noqa: E731
    assert sub("enable secret 9 $9$h") == "enable secret 9 <REDACTED>"
    assert sub("enable secret sha512 $6$s$h") == "enable secret sha512 <REDACTED>"
    assert sub("enable secret level 15 5 $1$s$h priv") == "enable secret level 15 5 <REDACTED> priv"
    assert sub("enable algorithm-type scrypt secret plain") == "enable algorithm-type scrypt secret <REDACTED>"
    assert sub("enable secret sha384 $6$s$h") == "enable secret sha384 <REDACTED>"
    # Without a known type both tokens are hidden (an unknown type word, or a value and a keyword).
    assert sub("enable secret type10 value") == "enable secret <REDACTED>"
    assert sub("enable password HASH encrypted") == "enable password <REDACTED>"
    assert sub("enable password plain") == "enable password <REDACTED>"
    assert sub("R1(config)#enable secret 5 $1$h") == "R1(config)#enable secret 5 <REDACTED>"
    # Not inside a word, not without a value.
    for text in ("xenable secret 5 v", "no enable secret\nnext", "enable secret \n", "disable secret 5 v"):
        assert sub(text) == text, text


# --- Floors: 1.0.6 proxy/product, complete 1.0.8 and main chains ---------------------------------

_UNIQUE = iter(chr(code) for code in range(0x4E00, 0x4E00 + 20000))


def _cjk():
    return "".join(next(_UNIQUE) for _ in range(3))


PREFIXES = ("enable secret ", "enable password ", "secret ", "password ", "enable secret level 15 ",
            "enable algorithm-type scrypt secret ", "ENABLE PASSWORD ", "R1#enable secret ")
TYPES = ("", "5 ", "7 ", "sha512 ", "scrypt ", "pbkdf2 ", "type10 ")
VALUES = ("{0}", "$6$s${0}")
# Later-rule anchors after the value: another rule hid what follows in the old chains.
TAILS = ("", " encrypted", " set password {0}", " token={0}", " community {0}", " ENC {0}",
         " psk {0}", " xset password {0}", "\nset password {0}", " password: {0}", ' "secret": "{0}"',
         " set\npassword {0}")


def _floor_cases():
    for prefix, kind, value, tail in itertools.product(PREFIXES, TYPES, VALUES, TAILS):
        line = prefix + kind + value.format(_cjk()) + tail.format(_cjk())
        yield line
        yield json.dumps({"config": line}, ensure_ascii=False)


FLOOR_CASES = list(_floor_cases())


def _hidden(text, output):
    return FLOOR._hidden(text, output)


def test_proxy_and_product_hide_everything_the_1_0_6_proxy_and_product_hid():
    for text in FLOOR_CASES:
        for value in (text, {"output": text}):
            old = OLD_PRODUCT.redact(OLD_PROXY.sanitize_object(value))[0]
            new = product_redact(sanitize_object(value))[0]
            old, new = (item if isinstance(item, str) else json.dumps(item, ensure_ascii=False) for item in (old, new))
            missing = _hidden(text, old) - _hidden(text, new)
            assert not missing, (text, sorted(missing), new)


def test_response_hides_everything_the_complete_1_0_8_and_main_chains_hid():
    for text in FLOOR_CASES:
        FLOOR._check(text)


def test_review_inputs_keep_the_floors():
    for text in list(REVIEW.values()) + [line for context in LINES.values() for _, line in _contexts(context)]:
        FLOOR._check(text.replace(CANARY, _cjk()))


def test_standalone_redact_hides_everything_the_1_0_8_rules_hid():
    release = FLOOR.RULES_1_0_8
    for text in FLOOR_CASES:
        old = release._redact_credentials(text, ())
        assert not _hidden(text, old) - _hidden(text, redact(text)), (text, redact(text))


def test_nested_document_floor_keeps_only_nested_string_contents():
    inner = {"config": "a b", "n": 1, "flag": True}
    text = json.dumps({"output": json.dumps(inner)})
    released = json.dumps({"output": json.dumps(inner, separators=(",", ":"))}, separators=(",", ":"))
    # The outer key keeps its contents; inside the nested document only its string contents.
    nested = [(text.index(word), text.index(word) + len(word)) for word in ("output", "config", "a b", "n\\", "flag")]
    nested[3] = (nested[3][0], nested[3][0] + 1)
    assert S._json_value_floor(text, [(0, len(text))], released) == nested
    # A floor on nested string contents only stays as it is.
    assert S._json_value_floor(text, [nested[2]], released) == [nested[2]]
    # The 1.0.8 result changed the nested number or broke the nested document: the outer
    # string keeps its floor on all of its contents, as before the earlier change.
    outer = [(match.start() + 1, match.end() - 1) for match in S._spans._JSON_STRING.finditer(text)]
    for other in ({"config": "a b", "n": 2, "flag": True}, {"config": "a b", "n": 1}, "{\"config\": "):
        broken = json.dumps({"output": other if isinstance(other, str) else json.dumps(other)})
        assert S._json_value_floor(text, [(0, len(text))], broken) == outer, other


def test_nested_key_document_stays_withheld():
    # the earlier change decision, unchanged by the nested reduction.
    inner = json.dumps({'username a secret "set password x"': 1, "auth_pwd": 0}, separators=(",", ":"))
    with pytest.raises(ValueError, match="output withheld"):
        redact_response(json.dumps({"output": inner}), ())


# --- Linear time ---------------------------------------------------------------------------------

def _seconds(function, text):
    start = time.perf_counter()
    function(text)
    return time.perf_counter() - start


@pytest.mark.parametrize("build", [
    lambda size: "enable secret " + " " * size + "x\n",
    lambda size: "enable secret sha512" + " " * size + "\n",
    lambda size: "enable enable " * size,
    lambda size: "enable secret 5 x\n" * size,
    lambda size: "secret sha512 " + "\t" * size + "$\n",
    lambda size: "username a " + "role x " * size + "\n",
], ids=["spaces", "type-spaces", "repeated-enable", "lines", "proxy-tabs", "username-options"])
def test_new_rules_scale_linearly(build):
    rules = (S.CISCO_ENABLE_ACCOUNT_SECRET, S.CISCO_USER_ACCOUNT_SECRET, P.CISCO_TYPED_SECRET)
    for rule in rules:
        run = lambda text, rule=rule: rule.sub("", text)  # noqa: E731
        small, large = build(5000), build(20000)
        run(small)
        timings = [min(_seconds(run, text) for _ in range(5)) for text in (small, large)]
        assert timings[1] < max(timings[0], 0.002) * 8, (rule.pattern[:40], timings)


def test_json_value_floor_iterates_without_copies():
    # the earlier change (non-blocking): N string tokens and N floor ranges stay roughly linear.
    def build(count):
        values = ["v%05d" % index for index in range(count)]
        text = json.dumps(values)
        tokens = [(match.start(), match.end()) for match in S._spans._JSON_STRING.finditer(text)]
        # Each range holds the separator before a token (outside every token), its opening
        # quote and the first character of its contents.
        floor = [(start - 1, start + 2) for start, _ in tokens]
        return text, floor, tokens

    def run(case):
        text, floor, tokens = case
        reduced = S._json_value_floor(text, floor, text)
        assert reduced == [(start + 2, end) for start, end in floor]
        assert sum(1 for start, end in floor for _ in S._outside(text, start, end, tokens)) == len(floor)

    small, large = build(4000), build(16000)
    run(small)
    timings = [min(_seconds(run, case) for _ in range(5)) for case in (small, large)]
    assert timings[1] < max(timings[0], 0.002) * 8, timings
