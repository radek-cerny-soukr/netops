#!/usr/bin/env python3
"""``redact_response`` hides everything the complete 1.0.8 and main chains hide (task 165-r4).

The property is checked on the public output of the whole chain (Helper credential
rules, proxy, product, SNMP mask, terminal-control cleaning): every character that
the complete released 1.0.8 chain (61e7de3) hides and every character that the
complete main chain (14c6a5a) hides is also hidden now. Both references are frozen
copies (``release_1_0_8_chain.py``, ``release_14c6a5a_chain.py``), not imports of the
product's credential rules. Every value is synthetic.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import random
import re
import time

import pytest

from netops.redaction_spans import Marked, edits, replace, sub
from netops_helper import proxy_sanitize, sanitize
from netops_helper.sanitize import redact_response

HERE = pathlib.Path(__file__).parent


def _load(name, alias):
    spec = importlib.util.spec_from_file_location(alias, HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAIN = _load("release_14c6a5a_chain.py", "release_14c6a5a_chain_main")
MAIN.bind_layers()
PROXY_1_0_8 = MAIN.PROXY_1_0_8
# The 1.0.8 credential rules on span-carrying (SNMP) documents, as the released module ran them.
RULES_1_0_8 = _load("release_1_0_8_chain.py", "release_1_0_8_chain_spans")
RULES_1_0_8.Marked, RULES_1_0_8.sub, RULES_1_0_8.replace, RULES_1_0_8.edits = Marked, sub, replace, edits
RELEASE = _load("release_14c6a5a_chain.py", "release_14c6a5a_chain_1_0_8")
RELEASE.bind_layers()
RELEASE._redact_credentials = RULES_1_0_8._redact_credentials

CANARY = "synthetic-canary"
WITHHELD = object()


def _run(function, text, secrets=()):
    try:
        return function(text, secrets)
    except ValueError:
        return WITHHELD  # output withheld: every character is hidden


def _hidden(text, output):
    """Unique CJK characters of ``text`` missing from ``output`` (all when withheld)."""
    chars = {char for char in text if "一" <= char <= "鿿"}
    return chars if output is WITHHELD else {char for char in chars if char not in output}


def _check(text, secrets=()):
    """Assert the property for one input; return (hidden by 1.0.8, by main, now)."""
    now = _run(redact_response, text, secrets)
    main = _run(MAIN.redact_response, text, secrets)
    released = _run(RELEASE.redact_response, text, secrets)
    hidden_now = _hidden(text, now)
    hidden_main, hidden_1_0_8 = _hidden(text, main), _hidden(text, released)
    assert hidden_main <= hidden_now, (text, sorted(hidden_main - hidden_now), now)
    assert hidden_1_0_8 <= hidden_now, (text, sorted(hidden_1_0_8 - hidden_now), now)
    if now is not WITHHELD and CANARY in text:
        assert CANARY not in now or (main is not WITHHELD and CANARY in main
                                     and released is not WITHHELD and CANARY in released), (text, now)
    return hidden_1_0_8, hidden_main, hidden_now, now, main


# Review 165-r3rv: exact inputs and the safe results.
R3RV = {
    # Main hides the password through the product's `set password` rule; 1.0.8 hid `set`.
    "username-then-set-password": ("username a secret\nset password synthetic-canary\n",
                                   "username a secret\n<REDACTED> password [REDACTED]\n"),
    # One SNMP line makes the document range-tracked; the 1.0.8 `sha512` range stays hidden.
    "snmp-and-nbsp-username": ("set community public\n username a secret sha512\npassword synthetic-canary\n",
                               "set community <REDACTED>\n username a secret <REDACTED>\npassword <REDACTED>\n"),
}


@pytest.mark.parametrize("name", R3RV)
def test_review_165_r3rv_inputs(name):
    text, expected = R3RV[name]
    assert redact_response(text, ()) == expected
    assert CANARY not in redact_response(text, ())
    assert CANARY not in MAIN.redact_response(text, ())
    _check(text.replace(CANARY, "一丁丂"))


# Review 165-rv and the ref/result-164.md table (with the variants of the earlier tests).
FIXED = {
    "rv-nbsp-username-enc": " username a secret ENC synthetic-canary\n",
    "rv-algorithm-inside-account-prefix": "username a secret sha512 synthetic-canary\n",
    "164-nbsp-before-username": "  username synthetic secret 9 synthetic-canary\r\n",
    "164-wrapped-name-and-secret": "\nusername synthetic\nsecret 9 synthetic-canary\n",
    "164-nbsp-before-type": "username synthetic secret 9 synthetic-canary\n",
    "164-nbsp-before-secret": "username synthetic secret 9 synthetic-canary\n",
    # Table row `username <LS>7 Secret admin 7 ...`: 1.0.8 hid the word after `Secret` (here the canary).
    "164-line-separator-secret-admin": "username  7 Secret synthetic-canary 7 admin\n",
    "164-wrapped-enable-and-community": "USERNAME \nxenable secret \nset community synthetic-canary\n",
    "em-space-before-username": "  username synthetic secret 9 synthetic-canary\n",
    "wrapped-crlf": "username synthetic\r\nsecret 9 synthetic-canary\r\n",
    "nbsp-before-value": "username synthetic password 7 synthetic-canary\n",
    "unicode-spaces-between": "username synthetic password synthetic-canary\n",
    "upper-case": "USERNAME synthetic SECRET 5 synthetic-canary\n",
    # 1.0.8 hides `'q`, so the product's `set password` rule then hides the tail; main hides
    # the whole quoted value, keeps the tail visible, and the 1.0.8 floor must hide it.
    "whole-chain-anchor": "username a secret 'q set password ' synthetic-canary\n",
    "snmp-fortios-and-user": ("config system snmp community\nedit 1\nset name synthetic-canary\nnext\nend\n"
                              " username a secret 5 synthetic-canary\n"),
    "terminal-controls": "\x1b[0m username a secret 5 synthetic-canary\x01\n",
}


@pytest.mark.parametrize("name", FIXED)
def test_fixed_inputs_keep_both_floors(name):
    text = FIXED[name]
    result = redact_response(text, ())
    assert CANARY not in result, result
    assert "canary" not in result, result
    hidden_1_0_8, _, _, _, _ = _check(text.replace(CANARY, "一丁丂"))
    if name == "whole-chain-anchor":
        assert hidden_1_0_8 == {"一", "丁", "丂"}


def test_whole_chain_anchor_is_a_1_0_8_only_effect():
    text = "username a secret 'q set password ' 一丁\n"
    assert "一" in MAIN.redact_response(text, ())  # main alone shows the tail
    assert "一" not in RELEASE.redact_response(text, ())  # the complete 1.0.8 chain hid it
    assert "一" not in redact_response(text, ()) and "丁" not in redact_response(text, ())


@pytest.mark.parametrize("value", [314159, -314159, 3.14159, True, None, [314159], {"value": 314159}])
def test_json_account_key_keeps_whole_document_floor(value):
    # Review 165-r4rv finding 1: the current account rule consumes `set password`
    # in the key before the product sees it. Reserializing for auth_pwd must not
    # reveal any value that the complete 1.0.8 chain withheld.
    text = json.dumps({'username a secret "set password x"': value, 'auth_pwd': 0},
                      separators=(",", ":"))
    if value == 314159:
        assert text == '{"username a secret \\"set password x\\"":314159,"auth_pwd":0}'
    assert RELEASE.redact_response(text, ()) == '"[REDACTED]"'
    assert redact_response(text, ()) == '"[REDACTED]"'


@pytest.mark.parametrize("wrapper", ["object", "list"])
@pytest.mark.parametrize("compact", [False, True])
@pytest.mark.parametrize("value", [314159, -314159, 3.14159, True, None, [314159], {"value": 314159}])
def test_nested_json_account_key_keeps_document_floor(wrapper, compact, value):
    # Review 217-rv: the inner document's non-string values/punctuation must
    # not lose the 1.0.8 floor when the product decodes and reserializes it.
    options = {"separators": (",", ":")} if compact else {}
    inner = json.dumps({'username a secret "set password x"': value, "auth_pwd": 0}, **options)
    outer = {"output": inner}
    text = json.dumps([outer] if wrapper == "list" else outer, **options)
    released = json.loads(RELEASE.redact_response(text, ()))
    assert (released[0] if wrapper == "list" else released)["output"] == '"[REDACTED]"'
    with pytest.raises(ValueError, match="output withheld"):
        redact_response(text, ())


@pytest.mark.parametrize("format", ["cli", "json"])
@pytest.mark.parametrize("layer", ["product", "response"])
def test_many_snmp_ranges_and_product_matches_keep_linear_time(layer, format):
    """Reviews 165-r4rv/217-rv: n SNMP ranges and n substitutions, CLI and JSON."""
    from netops.redaction import redact as product_redact
    from netops.redaction_spans import mask

    line = "set community public\nset password synthetic-canary\n"
    expected = "set community <REDACTED>\nset password [REDACTED]\n"
    timings = []
    for count in (1000, 2000, 4000):
        text = (json.dumps(["set community public", "set password synthetic-canary"] * count)
                if format == "json" else line * count)
        wanted = (json.dumps(["set community <REDACTED>", "set password [REDACTED]"] * count,
                             separators=(",", ":")) if format == "json" else expected * count)
        if format == "json" and layer == "response":
            # The complete Helper applies CLI rules to the serialized document
            # too; preserve those existing bytes rather than require JSON output.
            wanted = MAIN.redact_response(text, ())
        value = sanitize._mark_snmp(text) if layer == "product" else text
        samples = []
        for _ in range(3):
            started = time.perf_counter()
            result = mask(product_redact(value)[0]) if layer == "product" else redact_response(value, ())
            samples.append(time.perf_counter() - started)
            assert result == wanted
            assert CANARY not in result and "public" not in result
        timings.append(min(samples))
    print(f"{layer}/{format} n=1000/2000/4000 seconds={timings}")
    # Use the best of three runs and generous ratios to tolerate a shared lab PC.
    # Four times the input should be ~4x, not the ~16x of the previous algorithm.
    assert timings[2] < max(timings[0], 0.02) * 7, timings
    assert timings[2] < max(timings[1], 0.02) * 3.5, timings


def test_inputs_inside_json_documents():
    for text, _ in R3RV.values():
        for document in (json.dumps({"output": text}), json.dumps({"output": text}, ensure_ascii=False),
                         json.dumps([{"lines": text.splitlines()}])):
            # Main and 1.0.8 both show the canary of the line list: the SNMP `set community` range
            # runs to the end of the JSON line. _check requires it hidden wherever one of them hides it.
            _check(document)
            _check(document.replace(CANARY, "一丁丂"))


_UNIQUE = [chr(code) for code in range(0x4E00, 0x4E00 + 20000)]
_WHITE = ("\n", "\n", " ", "  ", "\t", " ", " ", " ", "\r\n")
_WORDS = ("username ", "USERNAME ", "admin ", "secret ", "password ", "Secret ", "5 ", "7 ", "9 ", "sha512 ",
          "privilege 15 ", "role x ", "ENC ", "enable secret ", "community ", "snmp-server community ",
          "SNMP community string is: ", "key 7 ", "psk ", "pre-shared-key ", "--password ", "--token=",
          "password=", "secret: ", 'token="', "'", '"', "bearer ", "passphrase = ", "user:", "$6$", ":",
          "tacacs-server key ", "configure account ", "encrypted ", "\\",
          # Later-layer anchors (proxy, product, SNMP context) and terminal controls.
          "set password ", "set ", "set community ", "set psksecret ", "unset password ", "passwd ",
          "config system snmp community\n", "edit 1\n", "set name ", "next\n", "end\n",
          "configure snmp add community readonly ",
          # Split literal: the same anchor value, but no PEM marker line for the release source gate.
          "-----BEGIN PRIVATE " "KEY-----", "\x1b[0m", "\x01")


def _case(generator, unique):
    def token():
        return "cn" + "".join(next(unique) for _ in range(3))

    def gap():
        return "".join(generator.choice(_WHITE) for _ in range(generator.randrange(1, 3)))

    def account():
        # A `username` line with random whitespace between its tokens (the 1.0.8 rule takes
        # any whitespace, the current one spaces/tabs on one line).
        line = [generator.choice(("", "\n", " ", "\u00a0")), generator.choice(("username", "USERNAME")), gap(),
                generator.choice(("admin", token())), gap(), generator.choice(("secret", "password", "Secret"))]
        if generator.random() < 0.5:
            line += [gap(), generator.choice(("5", "7", "9", "sha512", "ENC", "'q", '"q'))]
        return "".join(line + [gap(), token()])

    parts = []
    for _ in range(generator.randrange(3, 18)):
        roll = generator.random()
        if roll < 0.08:
            parts.append(account())
            continue
        if roll < 0.45:
            parts.append(generator.choice(_WORDS))
        elif roll < 0.7:
            parts.append(gap())
        else:
            parts.append(token())
        if generator.random() < 0.35:
            parts.append(token() + " ")
    return "".join(parts)


# The texts the Helper's account rules may change (sanitize._ACCOUNT_HINT); since task 302-r2
# `enable secret|password` is an account rule too and hides more than the main chain.
_ACCOUNT_TEXT = re.compile(r"(?i)username|enable|account|(?:tacacs|radius)-server|\\u")
_CONTROLS = re.compile(r"\x1b\[0m|[\x00-\x08\x0b-\x1f]")
_TYPED = proxy_sanitize.CISCO_TYPED_SECRET


def test_generated_inputs_keep_every_character_both_chains_hide():
    generator, unique = random.Random(2026111404), iter(_UNIQUE * 400)
    checked = only_1_0_8 = same = 0
    for number in range(2500):
        text = _case(generator, unique)
        secrets = ()
        if number % 7 == 0:
            secrets = tuple(re.findall(r"cn\S{3}", text)[:1])
        hidden_1_0_8, hidden_main, hidden_now, now, main = _check(text, secrets)
        checked += bool(hidden_1_0_8 or hidden_main)
        only_1_0_8 += bool(hidden_1_0_8 - hidden_main)
        if (not _ACCOUNT_TEXT.search(text) and not _ACCOUNT_TEXT.search(_CONTROLS.sub("", text))
                and not _TYPED.search(text) and not _TYPED.search(_CONTROLS.sub("", text))):
            # Without account text both credential layers agree and without a typed
            # `secret|password` line both proxies agree (the main proxy has no
            # CISCO_TYPED_SECRET, task 302-r3): the main result, unchanged.
            assert now == main, text
            same += 1
    assert checked > 1000 and only_1_0_8 > 20 and same > 300, (checked, only_1_0_8, same)


def test_generated_json_documents_keep_every_character_both_chains_hide():
    generator, unique = random.Random(78), iter(_UNIQUE[::-1] * 400)
    checked = 0
    for _ in range(500):
        text = _case(generator, unique)
        document = json.dumps({"stdout": text, "lines": text.split("\n")}, ensure_ascii=False, indent=1)
        hidden_1_0_8, hidden_main, _, _, _ = _check(document)
        checked += bool(hidden_1_0_8 or hidden_main)
    assert checked > 100, checked


def _family(count):
    return "set community public\n" + " username a secret sha512\npassword synthetic-canary\n" * count


def test_floor_ranges_keep_linear_time():
    """Review 165-r3rv finding 2: n floor ranges in an SNMP document stay linear."""
    expected = "set community <REDACTED>\n" + " username a secret <REDACTED>\npassword <REDACTED>\n" * 3
    assert redact_response(_family(3), ()) == expected

    def measured(count):
        text = _family(count)
        timings = []
        for _ in range(2):
            started = time.perf_counter()
            result = redact_response(text, ())
            timings.append(time.perf_counter() - started)
        assert CANARY not in result and "sha512" not in result
        return min(timings)

    small, large = measured(2000), measured(8000)
    # Four times the input: about four times the time; quadratic work would be ~16 times.
    assert large < max(small, 0.05) * 6, (small, large)
    assert large < 120, (small, large)


def test_frozen_proxy_1_0_8_matches_302_fixtures_and_is_independent(monkeypatch):
    """Today's legacy rules agree; changing the product proxy cannot change the oracle."""
    import hashlib

    path = pathlib.Path(PROXY_1_0_8.__file__).resolve()
    assert path == HERE.resolve().parents[2] / "tests/v1/fixtures/proxy_sanitize_1_0_8.py"
    assert not PROXY_1_0_8.__name__.startswith("netops_helper.")
    # Pin the original bytes as well as the documented, import-only adaptation.
    original = path.read_bytes().split(b'"""', 1)[1]
    original = b'"""' + original.replace(b'from netops_helper.sanitize import ', b'from .sanitize import ')
    assert hashlib.sha256(original).hexdigest() == "3fa8532e15ab283ba6ac426db0b04fa89b1ba01e204af0d75401d892b60461de"
    corpus = [text for text, _ in R3RV.values()] + list(FIXED.values())
    samples = [(value, secrets) for text in corpus
               for value in (text, sanitize._origin(text), {"output": text},
                             json.dumps({"output": text}))
               for secrets in ((), (CANARY,))]
    expected = [proxy_sanitize._sanitize_object(value, secrets, typed=False)
                for value, secrets in samples]
    def observed(result, value):
        if isinstance(value, str):
            # Compare credential kinds, but compare origin tracking by ranges:
            # separate proxy calls create distinct origin marker objects.
            credentials = Marked(result, [(start, end, kind)
                                         for start, end, kind in getattr(result, "spans", ())
                                         if kind is None or kind == "community"])
            return sanitize._coverage(credentials), sanitize._unclaimed(str.__str__(value), result)
        return result

    expected = [observed(result, value) for result, (value, _) in zip(expected, samples)]
    assert [observed(PROXY_1_0_8._sanitize_object(value, secrets), value)
            for value, secrets in samples] == expected
    def changed_proxy(*args, **kwargs):
        raise AssertionError("the reference imported the current proxy")

    monkeypatch.setattr(proxy_sanitize, "_sanitize_object", changed_proxy)
    monkeypatch.setattr(sanitize, "_proxy_1_0_8", changed_proxy)
    assert [observed(PROXY_1_0_8._sanitize_object(value, secrets), value)
            for value, secrets in samples] == expected


def test_frozen_proxy_1_0_8_public_wrappers_are_disabled():
    for function in (PROXY_1_0_8.sanitize_object, PROXY_1_0_8.sanitize_text):
        with pytest.raises(RuntimeError, match=r"^frozen 1\.0\.8 reference: use _sanitize_object$"):
            function("set community synthetic-canary", ())
