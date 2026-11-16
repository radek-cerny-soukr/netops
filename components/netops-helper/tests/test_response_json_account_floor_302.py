#!/usr/bin/env python3
"""Task 302: JSON documents with CLI account lines and the complete chains of ``redact_response``.

(9) A JSON document whose string values hold CLI account lines keeps its structure;
only the credential values (and every character the complete 1.0.8 chain hid in a
key or string value) are hidden. A document is still withheld where a legacy rule
consumed JSON punctuation, a sibling value, a number or a literal.

(10) After the rules differ, the plain current chain stops as soon as the floor is
known to be partial: its remaining work could only repeat the text of the
floor-tracking chain. The result is the same as before (``_previous``) except for
documents that were withheld only because of structure (9).

Every value is synthetic.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import random

import pytest

from netops.redaction_spans import Marked
from netops_helper import proxy_sanitize as P
from netops_helper import sanitize as S
from netops_helper.sanitize import redact, redact_response

HERE = pathlib.Path(__file__).parent


def _load(name, alias):
    spec = importlib.util.spec_from_file_location(alias, HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Frozen 1.0.8 and main references and the property check of task 165-r4.
FLOOR = _load("test_response_floor_1_0_8_and_main.py", "response_floor_reference_302")
CANARY = "synthetic-canary"
WITHHELD = FLOOR.WITHHELD


def _previous(text, secrets=()):
    """``redact_response`` before task 302 (f902b32): three complete chains when the floor is partial.

    With the floor rules of task 302-r3: a proxy step that differs from the released
    proxy starts the floor as a Helper step does, and the 1.0.8 chain runs the released
    proxy (``S._proxy_1_0_8``). The differential below compares only the chain stop (10)
    and the JSON reduction (9).
    """
    secrets = tuple(secrets)
    differs = []  # the 302-r3 settle of the masked result is applied below as in redact_response

    def watched(value, normalized):
        result = S._redact_current(value, normalized)
        if not differs and S._coverage(S._redact_1_0_8(value, normalized)) != S._coverage(result):
            differs.append(True)
        return result

    def watched_proxy(value, proxy_secrets):
        changes = []
        result = P._sanitize_object(value, proxy_secrets, typed_changes=changes)
        if changes and not differs and not S._same_coverage(S._proxy_1_0_8(value, proxy_secrets), result):
            differs.append(True)
        return result

    result = S._response_chain(text, secrets, watched, watched_proxy)
    if not differs:
        return result
    floor = S._hidden_ranges(text, lambda marked: S._response_chain(marked, secrets, S._redact_1_0_8, S._proxy_1_0_8))
    if not floor:
        return result
    if floor == [(0, len(text))]:
        return S.dumps('[REDACTED]')
    plain = str.__str__(text)
    try:
        tracked = S._response_chain(Marked(plain, [(start, end, S._FLOOR) for start, end in floor]),
                                    secrets, S._redact_current)
    except S._UnrepresentableFloor:
        raise ValueError('redaction could not be verified; output withheld') from None
    if str.__str__(tracked) != str.__str__(result):
        raise ValueError('redaction could not be verified; output withheld')
    # Task 302-r3: the masked result runs through the current chain to its fixed point.
    return S._settle_floor_result(S._mask_floor(tracked), secrets)


def _run(function, text, secrets=()):
    try:
        return function(text, secrets)
    except ValueError:
        return WITHHELD


def _shape(value):
    if isinstance(value, dict):
        return {"dict": [_shape(child) for child in value.values()]}
    if isinstance(value, list):
        return [_shape(child) for child in value]
    return type(value).__name__ if isinstance(value, str) else value


# --- (9) -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("separators", [None, (",", ":")])
@pytest.mark.parametrize("layer", ["response", "redact"])
def test_a_username_secret_hash_hidden_hostname_kept(layer, separators):
    text = json.dumps({"config": "username admin secret 9 $9$abc\nhostname r1"}, separators=separators)
    result = (redact_response if layer == "response" else redact)(text, ())
    assert "$9$abc" not in result
    assert json.loads(result) == {"config": "username admin secret 9 <REDACTED>\nhostname r1"}


@pytest.mark.parametrize("line", ["enable secret 5 $1$xyz", "enable password synthetic-canary"])
@pytest.mark.parametrize("separators", [None, (",", ":")])
def test_b_enable_secret_hash_hidden_hostname_kept(line, separators):
    text = json.dumps({"config": line + "\nhostname r1", "next": "visible"}, separators=separators)
    result = redact_response(text, ())
    value = line.split()[-1]
    assert value not in result
    assert json.loads(result) == {"config": line[:-len(value)] + "<REDACTED>\nhostname r1", "next": "visible"}


# Withheld before task 302: the complete 1.0.8 chain re-serialized the document (its
# product rule hid `set password ...`), so the document punctuation counted as hidden.
NARROWED = {
    "set-password": "username admin secret 9 set password synthetic-canary\nhostname r1",
    "set-password-last": "username admin secret 9 set password synthetic-canary",
    "privilege-set-password": "username u privilege 15 secret 5 set password synthetic-canary\nhostname r1",
    "password-set-password": "username admin password 0 set password synthetic-canary\nhostname r1",
    "token-assignment": "username admin secret 9 token=synthetic-canary\nhostname r1",
    "password-assignment": "username admin secret 9 password=synthetic-canary\nhostname r1",
    "secret-colon": "username admin secret 9 secret: synthetic-canary\nhostname r1",
}


# Task 302-r5: the 1.0.8 rules do not hide this account value (`privilege` stands before `secret`), so the
# account rule keeps the anchor `set` of the product rule, which hides the value as in 1.0.8; the reference
# (_previous runs the current Helper rules) then needs no withholding either.
KEPT_ANCHOR = ("privilege-set-password",)


@pytest.mark.parametrize("separators", [None, (",", ":")])
@pytest.mark.parametrize("name", NARROWED)
def test_json_account_value_with_legacy_anchor_is_redacted_not_withheld(name, separators):
    document = {"config": NARROWED[name], "next": "visible", "count": 3, "flag": True, "none": None}
    text = json.dumps(document, separators=separators)
    if name not in KEPT_ANCHOR:
        assert _run(_previous, text) is WITHHELD
    result = redact_response(text, ())
    assert CANARY not in result
    decoded = json.loads(result)
    assert _shape(decoded) == _shape(document)
    assert {key: decoded[key] for key in ("next", "count", "flag", "none")} == {
        "next": "visible", "count": 3, "flag": True, "none": None}
    assert decoded["config"].startswith("username ")
    if "hostname r1" in NARROWED[name] and "=" not in NARROWED[name] and ":" not in NARROWED[name]:
        assert decoded["config"].endswith("\nhostname r1")
    # Every character the complete 1.0.8 and main chains hide stays hidden.
    FLOOR._check(text.replace(CANARY, "一丁丂"))
    FLOOR._check(json.dumps(document, separators=separators, ensure_ascii=False).replace(CANARY, "一丁丂"))


def test_narrowed_document_keeps_value_level_result():
    text = json.dumps({"config": NARROWED["set-password"], "next": "visible"})
    assert redact_response(text, ()) == (
        '{"config": "username admin secret 9 <REDACTED> password <REDACTED>\\nhostname r1", "next": "visible"}')


# (c) A legacy rule that crosses a JSON token still withholds the complete document.
STILL_WITHHELD = {
    # FortiOS `ENC` takes `abc","next":"visible"}`: a sibling key and value.
    "enc-crosses-siblings": '{"config":"username admin secret 9 ENC abc","next":"visible"}',
    # It takes `abc",` here: the 1.0.8 result is no JSON document any more.
    "enc-takes-separator": '{"config": "username admin secret 9 ENC abc", "next": "visible"}',
    "enc-in-list": '["username admin secret 9 ENC abc","visible"]',
}


@pytest.mark.parametrize("name", STILL_WITHHELD)
def test_legacy_rule_across_json_tokens_still_withholds(name):
    text = STILL_WITHHELD[name]
    assert _run(_previous, text) is WITHHELD
    with pytest.raises(ValueError, match="output withheld"):
        redact_response(text, ())


@pytest.mark.parametrize("value", [314159, True, None, [314159], {"value": 314159}])
def test_account_key_documents_stay_withheld(value):
    # Task 165-r4/217: unchanged decisions for the whole and the nested document floor.
    text = json.dumps({'username a secret "set password x"': value, 'auth_pwd': 0}, separators=(",", ":"))
    assert redact_response(text, ()) == '"[REDACTED]"'
    with pytest.raises(ValueError, match="output withheld"):
        redact_response(json.dumps({"output": text}), ())


def test_floor_reduction_keeps_every_string_character():
    text = json.dumps({"a": "x", "b": ["y", 5]})
    tokens = [(start, start + len(token)) for token, start in (('"a"', 1), ('"x"', 6), ('"b"', 11), ('"y"', 17))]
    assert [text[start:end] for start, end in tokens] == ['"a"', '"x"', '"b"', '"y"']
    contents = [(2, 3), (7, 8), (12, 13), (18, 19)]
    released = json.dumps({"[REDACTED]": "z", "b": ["w", 5]}, separators=(",", ":"))
    for floor in ([(0, len(text) - 4)], [(0, len(text))], [(0, 3), (4, 8), (9, 25)]):
        assert S._json_value_floor(text, floor, released) == contents
    floor = [(0, len(text) - 4)]
    assert S._json_value_floor(text, [(4, 6), (22, 23)], released) == []
    # A different shape, a changed number or literal, or a released text that is no JSON: unchanged.
    for other in (json.dumps({"a": "x", "b": ["y"]}), json.dumps({"a": "x", "b": ["y", 6]}),
                  json.dumps({"a": "x", "b": ["y", "5"]}), json.dumps({"a": "x", "b": ["y", 5.0]}),
                  json.dumps({"a": "x", "b": "y"}), '{"a": "x", "b": ["y", 5]', '"[REDACTED]"'):
        assert S._json_value_floor(text, floor, other) == floor, other
    # Without a floor between string tokens nothing changes (a quote is part of its token).
    assert S._json_value_floor(text, [(7, 9)], released) == [(7, 9)]
    # Not a JSON document, or no released result: unchanged.
    assert S._json_value_floor("x: " + text, floor, released) == floor
    assert S._json_value_floor(text, floor, None) == floor


# --- (10) and the differential with the previous algorithm --------------------------------------

def _corpus():
    texts = [text for text, _ in FLOOR.R3RV.values()] + list(FLOOR.FIXED.values())
    texts += [json.dumps({"config": line}) for line in NARROWED.values()] + list(STILL_WITHHELD.values())
    generator, unique = random.Random(302), iter(FLOOR._UNIQUE * 400)
    for number in range(900):
        text = FLOOR._case(generator, unique)
        texts.append(text)
        if number % 3 == 0:
            texts.append(json.dumps({"stdout": text, "lines": text.split("\n"), "n": number},
                                    ensure_ascii=bool(number % 2), separators=(",", ":") if number % 4 else None))
    return texts


def test_same_result_as_previous_algorithm_except_structure_only_withholding():
    narrowed = same = 0
    for text in _corpus():
        before, now = _run(_previous, text), _run(redact_response, text)
        if before is WITHHELD and now is not WITHHELD:
            # (9): the only change; the result is a JSON document of the same shape
            # that keeps every character both reference chains hide.
            assert _shape(json.loads(now)) == _shape(json.loads(text)), text
            FLOOR._check(text)
            narrowed += 1
        else:
            assert now == before, text
            same += 1
    print(f"differential: {same} same results, {narrowed} formerly withheld documents now redacted by value")
    assert narrowed >= len(NARROWED) and same > 1000, (narrowed, same)


class _Counter:
    def __init__(self, monkeypatch):
        self.started = self.completed = self.current = 0
        chain, current = S._response_chain, S._redact_current

        def counted_chain(*args):
            self.started += 1
            result = chain(*args)
            self.completed += 1
            return result

        def counted_current(*args):
            self.current += 1
            return current(*args)

        monkeypatch.setattr(S, "_response_chain", counted_chain)
        monkeypatch.setattr(S, "_redact_current", counted_current)


PASSES = {
    # rules agree: one chain
    "no-difference": ("username admin secret 9 synthetic-canary\nhostname r1\n", 1, 1, 1, 1),
    # the 1.0.8 chain hides nothing more: the current chain is the result
    "difference-empty-floor": (json.dumps({"config": "username admin secret 9 $9$abc\nhostname r1"}), 2, 2, 2, 2),
    # partial floor: before, the current chain ran to its end only to be compared with the tracked one
    # (task 302-r3: one more chain in both, the masked result runs to its fixed point)
    "difference-partial-floor": ("username a secret sha512 synthetic-canary\nhostname r1\n", 4, 4, 4, 3),
    # withheld before: the tracked chain could not follow the floor on the punctuation
    "json-structure-floor": (json.dumps({"config": NARROWED["set-password"], "next": "visible"}), 3, 2, 4, 3),
    # whole floor: the current chain still runs to its end (same errors as before)
    "difference-whole-floor": (json.dumps({'username a secret "set password x"': 1, 'auth_pwd': 0},
                                          separators=(",", ":")), 2, 2, 2, 2),
}


@pytest.mark.parametrize("name", PASSES)
def test_complete_chain_count(name, monkeypatch):
    text, started_before, completed_before, started_now, completed_now = PASSES[name]
    counter = _Counter(monkeypatch)
    before = _run(_previous, text)
    assert (counter.started, counter.completed) == (started_before, completed_before)
    current_before = counter.current
    counter.started = counter.completed = counter.current = 0
    now = _run(redact_response, text)
    assert (counter.started, counter.completed) == (started_now, completed_now)
    print(f"{name}: complete chains {completed_before} -> {completed_now}, "
          f"current credential passes {current_before} -> {counter.current}")
    if name == "difference-partial-floor":
        assert now == before == "username a secret <REDACTED> <REDACTED>\nhostname r1\n"
        # The stopped chain made only its first credential pass.
        assert counter.current == current_before - 1
    elif name == "json-structure-floor":
        assert before is WITHHELD and CANARY not in now
    else:
        assert now == before
