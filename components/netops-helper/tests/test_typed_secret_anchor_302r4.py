#!/usr/bin/env python3
"""Task 302-r4: the anchor exception must not let a secret through.

Review 302-r3rv, finding 1: `secret sha512 $6$s$syntheticset` kept the whole value, because
the exception for "the value token is itself an anchor of a later rule" searched the anchor
anywhere in the token (`...set` as a suffix) and did not check that a later rule really took
the text after it.

Now the exception holds only when the whole token is an anchor token (`set`, `token`,
`password:`, ...) and applying the later rules changes (or has already redacted) the text
after it (``sanitize._kept_anchor``, removed in r6). Any other value token is hidden; a token that merely
holds an anchor word whose rule takes the text after it is hidden by the proxy only after its
other rules and the product rules ran over it (``proxy_sanitize._hide_deferred``). Every value
is synthetic.

Task 302-r6 replaced the anchor exception and the deferral by structural floors (see
test_structural_floor_302r6.py): the token is hidden, and what the 1.0.8 proxy and the product
hid after it stays hidden. The inputs stay; exact results are those of r6.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import pathlib
import random

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


FLOOR = _load(HERE / "test_response_floor_1_0_8_and_main.py", "response_floor_reference_302r4")
WITHHELD = FLOOR.WITHHELD
OLD_PROXY = _load(V1_FIXTURES / "proxy_sanitize_1_0_6.py", "proxy_sanitize_1_0_6_302r4")
OLD_PRODUCT = _load(V1_FIXTURES / "redaction_1_0_6.py", "redaction_1_0_6_302r4")

REVIEW = "secret sha512 $6$s$syntheticset"
REVIEW_VALUE = "$6$s$syntheticset"
CORE = "syntheticq"
CANARY = "synthetic-canary"


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


def _shown(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _proxy_worker(value):
    return _shown(product_redact(sanitize_object(value))[0])


def _old_proxy_worker(value):
    return _shown(OLD_PRODUCT.redact(OLD_PROXY.sanitize_object(value))[0])


def _contexts(line):
    yield "line", line
    yield "line-lf", line + "\n"
    yield "line-crlf", line.replace("\n", "\r\n") + "\r\n"
    yield "config", "hostname r1\n!\n" + line + "\n!\nend\n"
    yield "json", json.dumps({"config": line})
    yield "json-compact", json.dumps({"config": line}, separators=(",", ":"))
    yield "json-lines", json.dumps({"config": "hostname r1\n" + line + "\nend", "next": "visible"})
    yield "json-list", json.dumps(["hostname r1", line, "end"])
    yield "json-nested", json.dumps({"output": json.dumps({"config": line})})


def _outputs(text):
    """(layer, output) of redact_response, the final proxy response and proxy + product."""
    response = _response(text)
    if response is not WITHHELD:
        yield "redact_response", response
        yield "proxy_final", _proxy_final(response)
    else:
        assert text.startswith(("{", "[")), text
    yield "proxy_worker", _proxy_worker(text)
    if not text.startswith(("{", "[")):
        yield "proxy_worker_object", _proxy_worker({"output": text})


# --- Review 302-r3rv, finding 1 -------------------------------------------------------------------

def test_review_input_exact_results():
    assert sanitize_text(REVIEW) == "secret <REDACTED> <REDACTED>"
    assert redact_response(REVIEW, ()) == "secret <REDACTED> <REDACTED>"
    assert product_redact(sanitize_text(REVIEW))[0] == "secret <REDACTED> <REDACTED>"
    for text in (REVIEW + "\n", REVIEW + "\r\n"):
        assert REVIEW_VALUE not in redact_response(text, ())


@pytest.mark.parametrize("context", [name for name, _ in _contexts(REVIEW)] + ["review-json", "review-nested"])
def test_review_input_hides_the_value_everywhere(context):
    texts = dict(_contexts(REVIEW))
    texts["review-json"] = '{"config":"secret sha512 $6$s$syntheticset"}'
    texts["review-nested"] = '{"output":"{\\"config\\":\\"secret sha512 $6$s$syntheticset\\"}"}'
    text = texts[context]
    for layer, output in _outputs(text):
        assert "syntheticset" not in output and "synthetic" not in output, (layer, output)
    FLOOR._check(text)


# --- Variants: an anchor word as a suffix, a prefix or inside the value ---------------------------

ANCHOR_WORDS = ("set", "token", "encrypted", "md5", "-----BEGIN", "password", "community", "unset", "Set",
                "passwd", "secret", "enc", "psk")
VALUE_FORMS = {
    "suffix": "$6$s$" + CORE + "{0}",
    "bare-suffix": CORE + "{0}",
    "prefix": "{0}" + CORE,
    "prefix-hash": "{0}$6$s$" + CORE,
    "inside": "$6$" + CORE + "{0}" + CORE,
    "colon": "$6$s${0}:" + CORE,
    "equals": "$6$s${0}=" + CORE,
    "colon-suffix": CORE + "{0}:",
    "equals-suffix": CORE + "{0}=",
}
INSIDE = ("$6$s$x:" + CORE, "$6$s$x=" + CORE, CORE + "x:", CORE + "x=", "x:" + CORE, "x=" + CORE,
          "$6$" + CORE + ":abc", CORE + '"password":')
TYPED = ("secret sha512 ", "password sha512 ", "enable secret sha512 ", "enable password pbkdf2 ",
         "enable algorithm-type scrypt secret ", "secret level 15 5 ", "enable password level 3 ", "secret scrypt ",
         "  secret md5 ", "ENABLE SECRET SHA512 ")


def _values():
    for word in ANCHOR_WORDS:
        for form in VALUE_FORMS.values():
            yield form.format(word)
    yield from INSIDE


VALUES = list(_values())


@pytest.mark.parametrize("prefix", TYPED)
def test_an_anchor_word_in_the_value_does_not_keep_it(prefix):
    for value in VALUES:
        line = prefix + value
        # The proxy alone hides the value token (also without a continuation).
        assert CORE not in sanitize_text(line), (line, sanitize_text(line))
        for context, text in _contexts(line):
            for layer, output in _outputs(text):
                assert CORE not in output, (context, layer, output)


def test_helper_enable_rule_hides_a_second_token_that_only_holds_an_anchor_word():
    def sub(text):
        return S.CISCO_ENABLE_ACCOUNT_SECRET.sub(S._replace_enable, text)

    for value in VALUES:
        for continuation in ("", "\npasswd " + CANARY, "\n= " + CANARY):
            text = "enable algorithm-type scrypt secret $9$h " + value + continuation
            assert CORE not in sub(text), (text, sub(text))
            assert CORE not in redact(text), (text, redact(text))
            for layer, output in _outputs(text):
                # The proxy alone takes only the first token after `algorithm-type ALG secret`
                # (as in 1.0.6); the Helper hides the second one.
                if not layer.startswith("proxy_worker"):
                    assert CORE not in output, (layer, output)
    # An anchor token without a continuation that a later rule takes: hidden as well.
    for anchor in ("set", "token", "encrypted", "password:", "community", "md5"):
        assert sub("enable secret $9$h " + anchor) == "enable secret <REDACTED>", anchor


# --- With a continuation of the later rule: the value and the continuation stay hidden ------------

CONTINUED = {
    "set": "\npasswd " + CANARY,
    "Set": "\r\npassword " + CANARY,
    "unset": "\npasswd " + CANARY,
    "encrypted": "\npassword " + CANARY,
    "token": "\n= " + CANARY,
    "password": ": " + CANARY,
    "passwd": "\n: " + CANARY,
    "community": " " + CANARY,
    "-----BEGIN": " PRIVATE KEY-----\n" + CANARY + "\n-----END PRIVATE KEY-----",
    "secret": "=" + CANARY,
    "md5": " 7 " + CANARY,
}
# No rule of the chain takes `md5 7 VALUE` or `community VALUE` after a word that ends with md5 or
# community (both rules need a word boundary), in 1.0.6/1.0.8 neither; only the value token is
# checked for them.
NO_RULE = ("md5", "community")


@pytest.mark.parametrize("word", CONTINUED)
def test_value_with_an_anchor_word_and_a_continuation(word):
    for prefix, form in itertools.product(("secret sha512 ", "enable algorithm-type scrypt secret ",
                                           "password level 3 "), ("suffix", "bare-suffix")):
        line = prefix + VALUE_FORMS[form].format(word) + CONTINUED[word]
        for context, text in _contexts(line):
            for layer, output in _outputs(text):
                assert CORE not in output, (context, layer, output)
                if word not in NO_RULE:
                    assert CANARY not in output, (context, layer, output)
            # Not weaker than the 1.0.6 proxy + product.
            assert CANARY in _old_proxy_worker(text) or CANARY not in _proxy_worker(text)
            FLOOR._check(text)


def test_proxy_hides_the_continuation_before_the_value():
    # v1 fuzz index 16926 (complete helper floor, proxy-worker): `SET Password` + next value keeps
    # its anchor for the product. Task 302-r6: the proxy alone no longer runs the product rules
    # (r4 deferral); the proxy + product path hides what the 1.0.8 proxy and the product hid.
    text = ("enable password level 3 $6$s$CNRY0227105QENCRYPTED PASSWORD\n=\t<REDACTED>\"}CNRY0227111Q"
            "\tSET Password\rprefixSH2CNRY0227112Q\n")
    output = _proxy_worker(text)
    assert "CNRY0227112Q" not in output and "CNRY0227105Q" not in output, output
    old = _shown(product_redact(S._proxy_1_0_8(text, ()))[0])
    assert "CNRY0227111Q" in old or "CNRY0227111Q" not in output, output
    assert sanitize_text("secret sha512 $6$s$syntheticset\npasswd x") == (
        "secret <REDACTED> <REDACTED>\npasswd <REDACTED>")
    # The product rule took `token\n= x` as a whole (also in 1.0.6): the proxy masks the rest.
    assert sanitize_text("secret sha512 $6$s$synthetictoken\n= x") == "secret <REDACTED> <REDACTED><REDACTED>"
    assert sanitize_text("secret sha512 $6$s$community x") == "secret <REDACTED> <REDACTED> <REDACTED>"
    assert sanitize_text("secret sha512 $6$s$syntheticcommunity x") == "secret <REDACTED> <REDACTED> x"
    # The edited text is a fixed point of the proxy and the product.
    for text in ("secret sha512 $6$s$syntheticset\npasswd x", "secret sha512 $6$s$synthetictoken\n= x",
                 "enable algorithm-type scrypt secret $9$syntheticset\npasswd x"):
        once = product_redact(sanitize_text(text))[0]
        assert product_redact(sanitize_text(once))[0] == once, (text, once)


# --- Whole anchor tokens (task 302-r3 inputs) still work -------------------------------------------

R3_ANCHORS = {
    "set": "secret sha512 set\npasswd synthetic-canary",
    "encrypted": "password level 3 encrypted\npassword synthetic-canary",
    "token": "secret sha512 token\n= synthetic-canary",
    "password-colon": "secret sha512 password:\nsynthetic-canary",
    "community": "secret sha512 community synthetic-canary",
    "json-key": 'secret sha512 "password": "synthetic-canary"',
    "algorithm-set": "enable algorithm-type scrypt secret set\npasswd synthetic-canary",
    "unset": "secret sha512 unset\npasswd synthetic-canary",
}


@pytest.mark.parametrize("name", R3_ANCHORS)
def test_whole_anchor_token_with_a_continuation_keeps_the_1_0_8_floor(name):
    text = R3_ANCHORS[name]
    # Task 302-r6: the token is hidden; the continuation stays hidden through the proxy's floor.
    assert CANARY not in product_redact(S._proxy_1_0_8(text, ()))[0]
    assert CANARY not in product_redact(sanitize_text(text))[0], sanitize_text(text)
    for context, value in _contexts(text):
        assert CANARY not in _proxy_worker(value) or context == "line-crlf", (context, _proxy_worker(value))
        response = _response(value)
        assert response is WITHHELD or CANARY not in response, (context, response)


@pytest.mark.parametrize("anchor", ["set", "token", "encrypted", "password:", "community", "-----BEGIN", "md5",
                                    '"password":', "password"])
def test_whole_anchor_token_without_a_continuation_is_hidden(anchor):
    text = "secret sha512 " + anchor
    assert sanitize_text(text) == "secret <REDACTED> <REDACTED>", sanitize_text(text)
    assert CORE not in redact_response("secret sha512 " + CORE + anchor, ())
    if anchor in ("set", "token", "encrypted", "-----BEGIN", "md5", "password"):
        # Text after the anchor that no later rule takes (a label with `:` or `community`
        # takes the next token, also on the next line).
        assert sanitize_text(text + " visible") == "secret <REDACTED> <REDACTED> visible"
        assert sanitize_text(text + "\nhostname r1") == "secret <REDACTED> <REDACTED>\nhostname r1"


# --- Fuzz: secret values with a random suffix / prefix from the anchor set ------------------------

_UNIQUE = itertools.cycle([chr(code) for code in range(0x4E00, 0x4E00 + 20000)])


def _cjk():
    return "".join(next(_UNIQUE) for _ in range(3))


FUZZ_PREFIXES = ("secret ", "password ", "enable secret ", "enable password ", "enable algorithm-type scrypt secret ",
                 "secret level 15 ", "password level 3 ", "  secret ", "ENABLE SECRET ", "\tpassword ",
                 "R1#enable secret ", "username admin secret ")
FUZZ_TYPES = ("sha512 ", "scrypt ", "pbkdf2 ", "md5 ", "5 ", "7 ", "")
FUZZ_ANCHORS = ("set", "unset", "Set", "encrypted", "token", "password", "passwd", "secret", "community", "md5",
                "-----BEGIN", "enc", "ENC", "psk", "key", "bearer", "api_token", "password:", "token=", '"password"',
                '"password":', "x:", "x=", ":", "=")
FUZZ_SHAPES = ("{a}{c}", "{c}{a}", "$6$s${c}{a}", "{a}$6${c}", "{c}{a}{c2}", "$6${a}{c}", "{c}{a}:{c2}",
               "{c}{a}={c2}")
FUZZ_CONTINUATIONS = ("", "", "\npassword {0}", "\npasswd {0}", "\r\n passwd {0}", "\n= {0}", "\n: {0}", " {0}",
                      ' : "{0}"', "\n{0}", " PRIVATE KEY-----\n{0}\n-----END PRIVATE KEY-----", " password {0} next",
                      " 7 {0}", "\n\n\npasswd {0}")


def _fuzz_cases(count, seed):
    generator = random.Random(seed)
    pick = generator.choice
    for _ in range(count):
        core = _cjk()
        value = pick(FUZZ_SHAPES).format(a=pick(FUZZ_ANCHORS), c=core, c2=_cjk())
        line = pick(FUZZ_PREFIXES) + pick(FUZZ_TYPES) + value + pick(FUZZ_CONTINUATIONS).format(_cjk())
        shape = generator.randrange(4)
        if shape == 0:
            text = line
        elif shape == 1:
            text = "hostname r1\n" + line + "\nend\n"
        elif shape == 2:
            text = json.dumps({"config": line}, ensure_ascii=False)
        else:
            text = json.dumps({"config": "hostname r1\n" + line + "\nend", "next": "visible"}, ensure_ascii=False)
        yield core, value, line, text


FUZZ = list(_fuzz_cases(1500, 302004))


def test_fuzz_value_is_hidden_in_every_layer():
    for core, _, line, text in FUZZ:
        for layer, output in _outputs(text):
            if layer.startswith("proxy_worker") and line.startswith(("R1#", "username")):
                continue  # Helper rules only (the proxy has no `username` / prompt rule)
            assert not any(char in output for char in core), (text, layer, output)


def test_fuzz_response_keeps_the_1_0_8_and_main_floors():
    for _, _, _, text in FUZZ:
        FLOOR._check(text)


def test_fuzz_response_is_a_fixed_point_of_the_proxy_and_the_product():
    for _, _, _, text in FUZZ:
        response = _response(text)
        if response is not WITHHELD:
            assert product_redact(sanitize_object(response))[0] == response, (text, response)


def test_fuzz_proxy_and_product_keep_the_1_0_6_floor():
    for _, _, _, text in FUZZ:
        for value in (text, {"output": text}):
            old, new = _old_proxy_worker(value), _proxy_worker(value)
            missing = FLOOR._hidden(text, old) - FLOOR._hidden(text, new)
            assert not missing, (text, sorted(missing), new)


def test_fuzz_standalone_redact_keeps_the_1_0_8_floor():
    for _, _, _, text in FUZZ:
        old = FLOOR.RULES_1_0_8._redact_credentials(text, ())
        assert not FLOOR._hidden(text, old) - FLOOR._hidden(text, redact(text)), (text, redact(text))
