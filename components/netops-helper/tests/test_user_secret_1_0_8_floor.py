#!/usr/bin/env python3
"""`username ... secret|password` redaction stays a superset of 1.0.8 (verification).

Commit f0f5f46 narrowed CISCO_USER_SECRET to space/tab separators on one line, so a
value after NBSP/Unicode whitespace or a wrapped `username X\\nsecret 9 VALUE` leaked
(a private review table). Every value below is synthetic. The tests call the real public
``sanitize.redact`` and ``sanitize.redact_response`` without mocking any layer.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import random
import re

import pytest

from netops_helper import sanitize
from netops_helper.sanitize import redact, redact_response

CANARY = "synthetic-canary"
FUNCTIONS = {"redact": redact, "redact_response": lambda text: redact_response(text, ())}
# The released 1.0.8 expression (61e7de3), copied independently of the product module.
RULE_1_0_8 = re.compile(r"(?im)^([^\S\n]*username\s+\S+\s+(?:password|secret)(?:\s+\d+)?\s+)\S+")

_SPEC = importlib.util.spec_from_file_location(
    "release_1_0_8_chain", pathlib.Path(__file__).with_name("release_1_0_8_chain.py"))
RELEASE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(RELEASE)

# Inputs from the private review table and its variants.
LEAK_INPUTS = {
    "nbsp-before-username": "\u00a0 username synthetic secret 9 synthetic-canary\r\n",
    "nbsp-before-username-lf": "\u00a0 username synthetic secret 9 synthetic-canary\n",
    "em-space-before-username": "\u00a0\u2003username synthetic secret 9 synthetic-canary\n",
    "wrapped-name-and-secret": "\nusername synthetic\nsecret 9 synthetic-canary\n",
    "wrapped-crlf": "username synthetic\r\nsecret 9 synthetic-canary\r\n",
    "nbsp-before-type": "username synthetic secret\u00a09 synthetic-canary\n",
    "nbsp-before-secret": "username synthetic\u00a0secret 9 synthetic-canary\n",
    "nbsp-before-value": "username synthetic password 7\u00a0synthetic-canary\n",
    "unicode-spaces-between": "username\u2003synthetic\u2002password\u2009synthetic-canary\n",
    "line-separator-between": "username synthetic\u2028secret 5 synthetic-canary\n",
    "upper-case": "USERNAME synthetic SECRET 5 synthetic-canary\n",
}


@pytest.mark.parametrize("function", FUNCTIONS)
@pytest.mark.parametrize("name", LEAK_INPUTS)
def test_value_is_redacted_with_any_whitespace(function, name):
    result = FUNCTIONS[function](LEAK_INPUTS[name])
    assert CANARY not in result
    assert "canary" not in result
    assert "<REDACTED>" in result
    assert "synthetic" in result  # the user name stays visible


@pytest.mark.parametrize("function", FUNCTIONS)
def test_result_examples_from_the_finding(function):
    run = FUNCTIONS[function]
    assert run("\nusername synthetic\nsecret 9 synthetic-canary\n") == "\nusername synthetic\nsecret 9 <REDACTED>\n"
    assert run("\u00a0 username synthetic secret 9 synthetic-canary\n") == (
        "\u00a0 username synthetic secret 9 <REDACTED>\n")


@pytest.mark.parametrize("function", FUNCTIONS)
def test_extensions_of_f0f5f46_are_kept(function):
    run = FUNCTIONS[function]
    assert run("username admin privilege 15 secret sha512 $6$FAKESALT$FAKEHASHNOTREAL\n") == (
        "username admin privilege 15 secret sha512 <REDACTED>\n")
    assert run("username admin role network-admin password 5 $5$FAKESALT$FAKEHASHNOTREAL\n") == (
        "username admin role network-admin password 5 <REDACTED>\n")
    quoted = run('username admin secret 0 "fake quoted value NOTREAL"\n')
    assert "quoted value" not in quoted and "NOTREAL" not in quoted


def test_released_rule_is_unchanged():
    assert sanitize.CISCO_USER_SECRET.pattern == RULE_1_0_8.pattern
    assert sanitize.CISCO_USER_SECRET.flags == RULE_1_0_8.flags


def test_every_value_redacted_by_1_0_8_is_redacted_now():
    """Generated inputs: no value the 1.0.8 rule would hide survives the current chain."""
    white = ("\n", "\n", " ", "  ", "\t", "\u00a0", "\u2003", "\u2028")
    fragments = white + ("username ", "USERNAME ", "admin ", "secret ", "password ", "Secret ", "5 ", "9 ",
                         "privilege 15 ", "x", "!", "cnry")
    generator = random.Random(20261114)

    def junk(count):
        return "".join(generator.choice(fragments) for _ in range(generator.randrange(0, count)))

    def gap():
        return "".join(generator.choice(white) for _ in range(generator.randrange(1, 3)))

    def structured():
        # A `username` line with random whitespace between every token, among random fragments.
        parts = [junk(6), generator.choice(("", "\n")), generator.choice(("", gap())),
                 generator.choice(("username", "USERNAME")), gap(), generator.choice(("admin", "cnryname")), gap(),
                 generator.choice(("secret", "password", "Secret"))]
        if generator.random() < 0.6:
            parts += [gap(), generator.choice(("5", "7", "9"))]
        parts += [gap(), "cnry" + generator.choice(("", "x", "!", "$9$")), junk(6)]
        return "".join(parts)

    checked = 0
    for number in range(3000):
        text = structured() if number % 2 else junk(24)
        hidden = sum(match.group(0)[len(match.group(1)):].count("cnry") for match in RULE_1_0_8.finditer(text))
        if not hidden:
            continue
        checked += 1
        for name, function in FUNCTIONS.items():
            result = function(text)
            assert result.count("cnry") <= text.count("cnry") - hidden, (name, text)
    assert checked > 500


# Review: one rule's early redaction must not remove another rule's anchor, and a
# 1.0.8 range inside the prefix of a newer rule must stay hidden.
REVIEW_INPUTS = {
    "nbsp-username-enc": ("\u00a0username a secret ENC synthetic-canary\n",
                          "\u00a0username a secret <REDACTED> <REDACTED>\n"),
    "algorithm-inside-account-prefix": ("username a secret sha512 synthetic-canary\n",
                                        "username a secret <REDACTED> <REDACTED>\n"),
}


@pytest.mark.parametrize("function", FUNCTIONS)
@pytest.mark.parametrize("name", REVIEW_INPUTS)
def test_review_inputs_keep_every_1_0_8_range(function, name):
    text, expected = REVIEW_INPUTS[name]
    result = FUNCTIONS[function](text)
    assert result == expected
    assert "canary" not in result
    # 1.0.8 hid `ENC` / `sha512` (and in the first input the value); both stay hidden.
    released = RELEASE.redact_1_0_8(text)
    assert "sha512" not in released and "ENC" not in released.replace("ENC <REDACTED>", "")
    assert "sha512" not in result and "ENC" not in result


def test_review_inputs_inside_json_documents():
    for text, _ in REVIEW_INPUTS.values():
        for document in (json.dumps({"output": text}), json.dumps({"output": text}, ensure_ascii=False),
                         json.dumps([{"lines": text.splitlines()}])):
            for function in FUNCTIONS.values():
                assert "canary" not in function(document), document


# Unique non-ASCII characters (word characters, not digits or whitespace) make a
# per-character check possible: every redaction inserts ASCII text only, so a unique
# character is hidden exactly when it is missing from the output.
_UNIQUE = [chr(code) for code in range(0x4E00, 0x4E00 + 20000)]
_WHITE = ("\n", "\n", " ", "  ", "\t", "\u00a0", "\u2003", "\u2028", "\r\n")
_WORDS = ("username ", "USERNAME ", "admin ", "secret ", "password ", "Secret ", "5 ", "7 ", "9 ", "sha512 ",
          "privilege 15 ", "role x ", "ENC ", "enable secret ", "community ", "snmp-server community ",
          "SNMP community string is: ", "key 7 ", "psk ", "pre-shared-key ", "--password ", "--token=",
          "password=", "secret: ", 'token="', "'", '"', "bearer ", "passphrase = ", "user:", "$6$", ":",
          "tacacs-server key ", "configure account ", "encrypted ", "\\")


def _floor_case(generator, unique):
    def token():
        return "cn" + "".join(next(unique) for _ in range(3))

    def gap():
        return "".join(generator.choice(_WHITE) for _ in range(generator.randrange(1, 3)))

    parts = []
    for _ in range(generator.randrange(3, 18)):
        roll = generator.random()
        if roll < 0.45:
            parts.append(generator.choice(_WORDS))
        elif roll < 0.7:
            parts.append(gap())
        else:
            parts.append(token())
        if generator.random() < 0.35:
            parts.append(token() + " ")
    return "".join(parts)


def _hidden(text, output):
    return {char for char in text if char >= "\u4e00" and char not in output}


def test_every_character_hidden_by_the_1_0_8_chain_stays_hidden():
    """Generated floor test: 1.0.8 copy versus the current public functions, per character."""
    generator, unique = random.Random(202611143), iter(_UNIQUE * 400)
    checked = withheld = 0
    for number in range(2500):
        text = _floor_case(generator, unique)
        secrets = ()
        if number % 7 == 0:
            found = re.findall(r"cn\S{3}", text)
            secrets = tuple(found[:1])
        floor = _hidden(text, RELEASE.redact_1_0_8(text, secrets))
        if not floor:
            continue
        checked += 1
        for name, function in (("redact", lambda value: redact(value, secrets)),
                               ("redact_response", lambda value: redact_response(value, secrets))):
            try:
                result = function(text)
            except ValueError:
                withheld += 1  # output withheld: nothing is disclosed
                continue
            assert floor <= _hidden(text, result), (name, text, sorted(floor - _hidden(text, result)))
        # The product's own floor ranges reproduce the 1.0.8 copy character by character.
        ranges = sanitize._floor_1_0_8_ranges(text, tuple(sorted(set(secrets), key=len, reverse=True)))
        covered = {char for start, end in ranges for char in text[start:end] if char >= "\u4e00"}
        assert covered == floor, text
    assert checked > 1000


def test_floor_inside_json_string_documents():
    generator, unique = random.Random(77), iter(_UNIQUE[::-1] * 400)
    checked = 0
    for _ in range(600):
        text = _floor_case(generator, unique)
        document = json.dumps({"stdout": text, "lines": text.split("\n")}, ensure_ascii=False, indent=1)
        floor = _hidden(document, RELEASE.redact_1_0_8(document))
        if not floor:
            continue
        checked += 1
        assert floor <= _hidden(document, redact(document)), document
    assert checked > 100
