#!/usr/bin/env python3
"""Task 302-r3: the proxy rule for typed secrets keeps the anchors of later rules.

Review 302-r2rv, finding 1: proxy CISCO_TYPED_SECRET (1.0.10) hid the rest of the line,
so the anchor `set` of the product rule `set` + `passwd` (next line) was gone and
`synthetic-canary` stayed visible. The 1.0.8 floor of ``redact_response`` did not help:
its reference chain ran the current proxy, and a difference of the proxy alone did not
start it.

Now: (1) the proxy rule hides only the value token, and leaves a token that holds the
start of a later rule as the 1.0.8 proxy did; (2) the 1.0.8 reference chain runs the
released proxy rules (``sanitize._proxy_1_0_8``) and a proxy step that differs from them
starts the floor, so a new proxy rule cannot weaken its own reference. Every value is
synthetic.

Task 302-r6 replaced the anchor logic by structural floors (test_structural_floor_302r6.py); the
inputs stay, exact results are those of r6.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import pathlib
import random
import re
import runpy
import time

import pytest

from netops.redaction import redact as product_redact
from netops.redaction_spans import Marked
from netops_helper import sanitize as S
from netops_helper import proxy_sanitize as P
from netops_helper.proxy import Proxy
from netops_helper.proxy_sanitize import sanitize_object, sanitize_text
from netops_helper.sanitize import redact, redact_response

HERE = pathlib.Path(__file__).parent
V1_FIXTURES = pathlib.Path(__file__).resolve().parents[3] / "tests/v1/fixtures"
CANARY = "synthetic-canary"
HASH = "synthetic-hash"


def _load(path, alias):
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Frozen 1.0.8 and main references (their proxy runs without CISCO_TYPED_SECRET).
FLOOR = _load(HERE / "test_response_floor_1_0_8_and_main.py", "response_floor_reference_302r3")
WITHHELD = FLOOR.WITHHELD
# Frozen 1.0.6 proxy and product (worker) redaction.
OLD_PROXY = _load(V1_FIXTURES / "proxy_sanitize_1_0_6.py", "proxy_sanitize_1_0_6_302r3")
OLD_PRODUCT = _load(V1_FIXTURES / "redaction_1_0_6.py", "redaction_1_0_6_302r3")


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
    """The proxy followed by the product (worker) redaction, without the Helper."""
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


# --- Review 302-r2rv, finding 1: exact inputs ------------------------------------------------------

REVIEW = {
    "enable-algorithm-type": "enable algorithm-type scrypt secret $9$synthetic-hash set\npasswd synthetic-canary",
    "bare-sha512": "secret sha512 $6$s$synthetic-hash set\npasswd synthetic-canary",
}
REVIEW_JSON = '{"config":"secret sha512 $6$s$synthetic-hash set\\npasswd synthetic-canary"}'


def test_review_inputs_exact_results():
    # Task 302-r6: the Helper enable rule hides both tokens; the floor of the 1.0.8 chain hides
    # the canary that its product rule took after `set`.
    assert redact_response(REVIEW["enable-algorithm-type"], ()) == (
        "enable algorithm-type scrypt secret <REDACTED>\npasswd <REDACTED>")
    assert redact_response(REVIEW["bare-sha512"], ()) == "secret <REDACTED> <REDACTED> set\npasswd [REDACTED]"
    for text in REVIEW.values():
        final = _proxy_final(redact_response(text, ()))
        assert CANARY not in final and HASH not in final


@pytest.mark.parametrize("name", list(REVIEW) + ["json"])
def test_review_inputs_hide_hash_and_canary_in_the_response_and_the_final_proxy_response(name):
    texts = [REVIEW_JSON] if name == "json" else [text for _, text in _contexts(REVIEW[name])]
    for text in texts:
        response = _response(text)
        assert response is not WITHHELD, text
        for layer, output in (("redact_response", response), ("proxy_final", _proxy_final(response)),
                              ("proxy_worker", _proxy_worker(text))):
            assert CANARY not in output and HASH not in output, (layer, text, output)
        if text.startswith("{"):
            decoded, original = json.loads(response), json.loads(text)
            assert type(decoded) is type(original), response
            assert list(decoded) == list(original) if isinstance(original, dict) else len(decoded) == len(original)


def test_review_input_standalone_redact():
    # redact() hides the hash; the canary, which the 1.0.8 chain of this path (Helper, proxy,
    # product) hid through the product's `set` + `passwd` rule, redact() masks itself (task 302-r6).
    text = REVIEW["enable-algorithm-type"]
    assert redact(text) == "enable algorithm-type scrypt secret <REDACTED>\npasswd <REDACTED>"
    released = FLOOR.RULES_1_0_8._redact_credentials(text, ())
    assert CANARY in released and HASH in released
    # The bare line: no Helper rule (as before); the response chain hides both (above).
    assert redact(REVIEW["bare-sha512"]) == REVIEW["bare-sha512"]


# --- Task variants: an anchor at the end of the line, its rule continues on the next line ---------

VARIANTS = {
    "enable-sha512-token": "enable secret sha512 synthetic-hash token\n= synthetic-canary",
    "bare-sha512-token": "secret sha512 synthetic-hash token\n= synthetic-canary",
    "username-sha512-token": "username admin secret sha512 synthetic-hash token\n= synthetic-canary",
    "enable-password-7-set": "enable password 7 synthetic-hash set\npassword synthetic-canary",
    "bare-password-7-set": "password 7 synthetic-hash set\npassword synthetic-canary",
    "bare-password-sha512-set": "password sha512 synthetic-hash set\npassword synthetic-canary",
    "enable-level-set-passwd": "enable password level 3 synthetic-hash set\npasswd synthetic-canary",
    "bare-level-encrypted": "secret level 15 5 synthetic-hash encrypted\npassword synthetic-canary",
    "algorithm-type-colon": "enable algorithm-type sha256 secret $8$synthetic-hash password\n: synthetic-canary",
    "bare-scrypt-community": "secret scrypt $9$synthetic-hash community synthetic-canary",
    "bare-type-word-json-key": 'secret type10 $6$synthetic-hash "password": "synthetic-canary"',
}


# In a raw JSON document the unchanged 1.0.8 Helper rule COMMUNITY_VALUE_SECRET takes
# `synthetic-canary"}` (the value and the closing syntax); the text is no JSON document any
# more and the bare `secret scrypt HASH` line is not at a line start for the proxy. The same
# in 1.0.8 and main (the floor check below), unrelated to task 302-r3; the canary is hidden.
RAW_JSON_COMMUNITY = ("bare-scrypt-community",)


@pytest.mark.parametrize("name", VARIANTS)
def test_variants_hide_hash_and_canary(name):
    withheld = 0
    for context, text in _contexts(VARIANTS[name]):
        response = _response(text)
        if response is WITHHELD:
            # Withheld: nothing is shown. Only a JSON document can be withheld here.
            assert context.startswith("json"), (context, text)
            withheld += 1
            continue
        for layer, output in (("redact_response", response), ("proxy_final", _proxy_final(response))):
            assert CANARY not in output, (context, layer, output)
            if not (name in RAW_JSON_COMMUNITY and context.startswith("json")):
                assert HASH not in output, (context, layer, output)
        # The proxy and the product alone: the canary, and the hash wherever the 1.0.6 proxy
        # hid it (the proxy has no `username` rule; the Helper hides that hash).
        new, old = _proxy_worker(text), _old_proxy_worker(text)
        assert CANARY not in new, (context, new)
        assert HASH in old or HASH not in new, (context, new)
        FLOOR._check(text)
    print(f"{name}: {withheld} withheld JSON contexts")


# --- A value token that is an anchor itself -------------------------------------------------------

ANCHOR_VALUES = {
    "set": "secret sha512 set\npasswd synthetic-canary",
    "encrypted": "password level 3 encrypted\npassword synthetic-canary",
    "token": "secret sha512 token\n= synthetic-canary",
    "password-colon": "secret sha512 password:\nsynthetic-canary",
    "community": "secret sha512 community synthetic-canary",
    "json-key": 'secret sha512 "password": "synthetic-canary"',
    "algorithm-set": "enable algorithm-type scrypt secret set\npasswd synthetic-canary",
}


@pytest.mark.parametrize("name", ANCHOR_VALUES)
def test_an_anchor_token_is_hidden_and_its_continuation_stays_hidden(name):
    text = ANCHOR_VALUES[name]
    # Task 302-r6: the typed rule hides the token; what the 1.0.8 proxy and the product hid after
    # it stays hidden through the proxy's floor.
    assert CANARY not in product_redact(S._proxy_1_0_8(text, ()))[0]
    assert CANARY not in product_redact(sanitize_text(text))[0], sanitize_text(text)
    for context, value in _contexts(text):
        # The proxy and the product alone hide the canary wherever the 1.0.6 ones did (the
        # CRLF form of `password:` + next line: neither, unchanged).
        new, old = _proxy_worker(value), _old_proxy_worker(value)
        assert CANARY in old or CANARY not in new, (context, new)
        assert CANARY not in new or context == "line-crlf", (context, new)
        response = _response(value)
        if response is WITHHELD:
            assert context.startswith("json"), (context, value)
        else:
            assert CANARY not in response, (context, response)


def test_helper_enable_rule_hides_both_value_tokens():
    # Task 302-r6: the rule hides the value tokens whole (as in r2); what a later rule of the
    # 1.0.8 chain took after an anchor among them is kept hidden by the floor of that chain.
    def sub(text):
        return S.CISCO_ENABLE_ACCOUNT_SECRET.sub(S._replace_enable, text)

    assert sub("enable algorithm-type scrypt secret $9$h set\npasswd x") == (
        "enable algorithm-type scrypt secret <REDACTED>\npasswd x")
    assert sub("enable secret x token\n= y") == "enable secret <REDACTED>\n= y"
    assert sub("enable secret type10 set\npasswd x") == "enable secret <REDACTED>\npasswd x"
    assert redact("enable algorithm-type scrypt secret $9$h set\npasswd x1y") == (
        "enable algorithm-type scrypt secret <REDACTED>\npasswd <REDACTED>")
    assert sub("enable algorithm-type scrypt secret $9$h set") == "enable algorithm-type scrypt secret <REDACTED>"
    assert sub("enable password HASH encrypted") == "enable password <REDACTED>"
    assert sub("enable secret x token") == "enable secret <REDACTED>"
    # A later pass keeps a marker taken as the first token.
    assert sub("enable algorithm-type scrypt secret <REDACTED> set\npasswd [REDACTED]") == (
        "enable algorithm-type scrypt secret <REDACTED> <REDACTED>\npasswd [REDACTED]")
    # Without an anchor both tokens stay hidden; a known type stays visible.
    assert sub("enable secret type10 value") == "enable secret <REDACTED>"
    assert sub("enable password HASH pbkdf2") == "enable password <REDACTED>"
    assert sub("enable secret sha512 $6$s$h set") == "enable secret sha512 <REDACTED> set"
    assert sub("enable secret 5 $1$h token") == "enable secret 5 <REDACTED> token"


def test_proxy_hides_only_the_value_token():
    assert sanitize_text("secret sha512 $6$s$h set") == "secret <REDACTED> <REDACTED> set"
    assert sanitize_text("enable algorithm-type scrypt secret $9$h set\npasswd x") == (
        "enable algorithm-type scrypt secret <REDACTED> set\npasswd x")
    assert sanitize_text("enable secret level 15 5 $1$s$h priv 15\n") == "enable secret <REDACTED> 15 5 <REDACTED> priv 15\n"
    # The proxy alone: the product then hides the value after the kept anchor.
    assert product_redact(sanitize_text(REVIEW["bare-sha512"]))[0] == (
        "secret <REDACTED> <REDACTED> set\npasswd [REDACTED]")
    # The released proxy rules: no CISCO_TYPED_SECRET.
    assert S._proxy_1_0_8("secret sha512 $6$s$h set", ()) == "secret <REDACTED> $6$s$h set"
    assert S._proxy_1_0_8({"a": ["secret sha512 $6$s$h"]}, ()) == {"a": ["secret <REDACTED> $6$s$h"]}


def test_typed_changes_records_only_a_change():
    for text, changed in (("secret sha512 $6$s$h", True), ("secret sha512 set\npasswd x", True),
                          ("secret sha512 set", True), ("secret sha512 $6$s$hset", True),
                          ("secret sha512 <REDACTED>", False), ("secret 5 $1$h", False),
                          ('{"config": "secret sha512 $6$s$h"}', True), ("hostname r1", False)):
        changes = []
        P._sanitize_object(text, (), typed_changes=changes)
        assert bool(changes) is changed, text


def test_same_coverage():
    assert S._same_coverage({"a": ["x", 1, True]}, {"a": ["x", 1, True]})
    assert not S._same_coverage({"a": ["x", 1]}, {"a": ["y", 1]})
    assert not S._same_coverage({"a": [1]}, {"a": [True]})
    assert not S._same_coverage({"a": "x"}, {"b": "x"})
    assert not S._same_coverage(["x"], ["x", "y"])
    marked = Marked("abc", [(0, 1, None)])
    assert S._same_coverage(marked, Marked("abc", [(0, 1, None)]))
    assert not S._same_coverage(marked, "abc")


# --- General floor safeguard: a weakening proxy rule cannot weaken the reference -------------------

# The 1.0.10 rule of task 302-r2: it hid the rest of the line.
_R2_RULE = re.compile(
    r"(?im)^([^\S\n]*(?:enable[ \t]+(?P<algorithm>algorithm-type[ \t]+\S+[ \t]+)?)?(?:secret|password)"
    r"(?:[ \t]+(?P<level>level)[ \t]+\d+)?(?:[ \t]+(?:(?P<word>" + S._SECRET_WORD_TYPE + r")|\d+(?=[ \t]+\S)))?[ \t]+)"
    r"(?(word)|(?(level)|(?(algorithm)|(?!))))\S(?:[^\r\n]*\S)?"
)


def _r2_replace(match):
    value = match.group(0)[len(match.group(1)):]
    return match.group(0) if value == "<REDACTED>" else match.group(1) + "<REDACTED>"


WEAKENED = [REVIEW["enable-algorithm-type"], REVIEW["bare-sha512"], REVIEW_JSON,
            "secret sha512 $6$s$synthetic-hash xset\npasswd synthetic-canary",
            "password level 3 synthetic-hash encrypted\npasswd synthetic-canary"]


def test_floor_holds_with_the_weakening_rule_of_302r2(monkeypatch):
    monkeypatch.setattr(P, "CISCO_TYPED_SECRET", _R2_RULE)
    monkeypatch.setattr(P, "_replace_typed", _r2_replace)
    for text in WEAKENED:
        if not text.startswith("{"):
            # The proxy rules alone lose the anchor ...
            assert CANARY in product_redact(P._proxy_rules(text, (), True))[0], text
        # ... the floors of the released chains (proxy: 1.0.8 proxy + product, task 302-r6;
        # response: the complete 1.0.8 chain) still hide the canary.
        assert CANARY not in _proxy_worker(text), text
        assert CANARY not in S._response_chain(text, (), S._redact_current) or "enable" in text, text
        response = redact_response(text, ())
        assert CANARY not in response, (text, response)
        assert CANARY not in _proxy_final(response)
        FLOOR._check(text.replace(CANARY, "一丁丂"))


def test_floor_would_miss_it_with_the_current_proxy_in_the_reference(monkeypatch):
    # The control: with the weakening rule also in the reference of the response (as before
    # 302-r3) and without the proxy's own floor (task 302-r6), the canary stays visible, so the
    # test above depends on the released rules in both floors.
    monkeypatch.setattr(P, "CISCO_TYPED_SECRET", _R2_RULE)
    monkeypatch.setattr(P, "_replace_typed", _r2_replace)
    monkeypatch.setattr(S, "_proxy_1_0_8", lambda value, secrets: P._sanitize_object(value, secrets))
    monkeypatch.setattr(S, "_covering_floor", lambda plain, released, output, later: output)
    for text in WEAKENED[:2]:
        assert CANARY in redact_response(text, ()), text


# --- Differential fuzz: typed secret + anchor at the end of the line + next line ------------------

# Unique within one text (a text takes at most a few consecutive values).
_UNIQUE = itertools.cycle([chr(code) for code in range(0x4E00, 0x4E00 + 20000)])


def _cjk():
    return "".join(next(_UNIQUE) for _ in range(3))


PREFIXES = ("secret ", "password ", "enable secret ", "enable password ", "enable algorithm-type scrypt secret ",
            "secret level 15 ", "password level 3 ", "  secret ", "ENABLE SECRET ", "R1#enable secret ",
            "username admin secret ", "\tpassword ")
TYPES = ("sha512 ", "scrypt ", "pbkdf2 ", "md5 ", "type10 ", "5 ", "7 ", "")
VALUES = ("{0} ", "$6$s${0} ", "<REDACTED> ", "")  # "": the anchor is the value
ANCHORS = ("set", "encrypted", "token", "password", "passwd", "secret", "community", "xset", "Set", "-----BEGIN",
           "password:", "token=", '"password"', "snmp community", "unset")
CONTINUATIONS = ("\npassword {0}", "\npasswd {0}", "\r\n passwd {0}", "\n= {0}", "\n: {0}", " {0}", ' : "{0}"',
                 "\n{0}", " PRIVATE KEY-----\n{0}\n-----END PRIVATE KEY-----", " password {0} next")


def _fuzz_cases(count, seed):
    generator = random.Random(seed)
    pick = generator.choice
    for _ in range(count):
        line = (pick(PREFIXES) + pick(TYPES) + pick(VALUES).format(_cjk()) + pick(ANCHORS)
                + pick(CONTINUATIONS).format(_cjk()))
        shape = generator.randrange(4)
        if shape == 0:
            yield line
        elif shape == 1:
            yield "hostname r1\n" + line + "\nend\n"
        elif shape == 2:
            yield json.dumps({"config": line}, ensure_ascii=False)
        else:
            yield json.dumps({"config": "hostname r1\n" + line + "\nend", "next": "visible"}, ensure_ascii=False)


FUZZ = list(_fuzz_cases(1500, 302003))


def test_fuzz_cases_cover_the_shape():
    plain = [text for text in FUZZ if not text.startswith("{")]
    assert sum(bool(P.CISCO_TYPED_SECRET.search(text)) for text in plain) > 150
    changed = 0
    for text in plain:
        changes = []
        P._sanitize_object(text, (), typed_changes=changes)
        changed += bool(changes)
    assert changed > 60, changed


def test_fuzz_response_keeps_the_1_0_8_and_main_floors():
    for text in FUZZ:
        FLOOR._check(text)


def test_fuzz_proxy_and_product_keep_the_1_0_6_floor():
    for text in FUZZ:
        for value in (text, {"output": text}):
            old, new = _old_proxy_worker(value), _proxy_worker(value)
            missing = FLOOR._hidden(text, old) - FLOOR._hidden(text, new)
            assert not missing, (text, sorted(missing), new)


def test_fuzz_standalone_redact_keeps_the_1_0_8_floor():
    for text in FUZZ:
        old = FLOOR.RULES_1_0_8._redact_credentials(text, ())
        assert not FLOOR._hidden(text, old) - FLOOR._hidden(text, redact(text)), (text, redact(text))


def test_exhaustive_review_shape_keeps_every_floor():
    # Every prefix, type and anchor with the review's `passwd` continuation, value and no value.
    for prefix, kind, value, anchor in itertools.product(PREFIXES, TYPES, ("$6$s${0} ", ""), ANCHORS):
        text = prefix + kind + value.format(_cjk()) + anchor + "\npasswd " + _cjk()
        hidden_1_0_8, hidden_main, hidden_now, now, _ = FLOOR._check(text)
        old = _old_proxy_worker(text)
        assert not FLOOR._hidden(text, old) - FLOOR._hidden(text, _proxy_worker(text)), text


# --- Linear time -----------------------------------------------------------------------------------

def _seconds(function, text):
    start = time.perf_counter()
    function(text)
    return time.perf_counter() - start


@pytest.mark.parametrize("build", [
    lambda size: "secret sha512 " + "passwordx" * size + "\n",
    lambda size: "secret sha512 " + "$6$" * size + " set\n",
    lambda size: "secret sha512 x set\npasswd y\n" * size,
], ids=["anchor-like-token", "long-hash", "lines"])
def test_proxy_rule_scales_linearly(build):
    small, large = build(5000), build(20000)
    sanitize_text(small)
    timings = [min(_seconds(sanitize_text, text) for _ in range(3)) for text in (small, large)]
    assert timings[1] < max(timings[0], 0.002) * 8, timings


# --- The masked floor result is a fixed point (task 302-r3) ---------------------------------------

# Inputs of the extended v1 fuzz (tests/v1/test_redaction_1_0_6_floor.py, typed secret shape):
# SNMP documents where the floor was masked after the last layer and a layer still changed the
# result (`set passwd <REDACTED>`, a joined line after a typed secret, a renumbered SNMP token).
SETTLE_CASES = {
    'fuzz-956': 'config global\r\nconfig system snmp community\r\nedit 1\r\nset name CNRY0012414Q\r\nnext\r\nedit 2\r\nset name "prefix\r\nCNRY0012415Q"\r\nnext\r\nend\r\nend\r\nset password CNRY0012417Q\r\n    passphrase = "CNRY0012418Q"\tunseX\r\nPasswd\rUnseX\r\npasswd\r\r\n    set  passwd\r\r\nprefix[REDACTED]CNRY0012423Q    enable secret sha512 TOKEN\r\n : prefix<UNVERIFIED:unclassified-field>CNRY0012426Q\r\n    passphrase = prefix<REDACTED:credential#99>CNRY0012427Q\r\r\nset passwords ENC\r\r\nCNRY0012428Q\r\npassword: prefix CNRY0012429Q CNRY0012430Q\r\n',
    'fuzz-2114': '\x00\x0b\nconfig vdom\nconfig system snmp community\nedit 1\nset name CNRY0027123Q\nnext\nedit 2\nset name password:\nCNRY0027124Q\nnext\nend\nconfig system health-check\nedit check\nset community CNRY0027126Q\nnext\nend\nend\nset password CNRY0027127Q\n    "passwd": "CNRY0027128Q"\n    ENABLE ALGORITHM-TYPE SCRYPT SECRET scrypt token\n = [REDACTED]\tCNRY0027131Q\n    Enable password CNRY0027133Q encrypted\r\nPASSWD\tCNRY0027134Q\r\npassword: prefix CNRY0027135Q CNRY0027136Q\n',
    'fuzz-5160': 'configure snmpv3 add community CNRY0066110Q\r\nconfigure snmp add community readonly set password\r\nCNRY0066111Q\r\nset password CNRY0066113Q\r\n\tUNseX Passwd \r\n\tconfig system admin\r\n    Enable secret sha512 CNRY0066117Q Token\r\n:<UNVERIFIED:x>",CNRY0066118Q\r\n    set\x0bPasswd\x0cCNRY0066119Q\r\r\n\tENABLE SECRET scrypt Password :\tprefixSH2CNRY0066122Q    ENCRYPTED\r\n\r\nPASSWORD \tCNRY0066123Q \r\nCNRY0066124Q\r\npassword: prefix CNRY0066125Q CNRY0066126Q\r\n',
    'fuzz-8211': '\x1b[1m\r\nconfigure snmp add community readonly CNRY0104805Q\nconfigure snmp add community readwrite "CNRY0104807Q"\nset password CNRY0104808Q\n    end\n\tENABLE ALGORITHM-TYPE SCRYPT SECRET password\n=\tCNRY0104811Q,CNRY0104812Q\n\tpassword:ENC,CNRY0104813Q\n    community=<PRIVATE-KEY-REDACTED>CNRY0104814Q\r\n    UNSET Passwd "CNRY0104815Q"\r\nset passwords CNRY0104817Q\npass\x08word: prefix CNRY0104818Q CNRY0104819Q\n',
    'fuzz-11265': '\x1b[0m\nconfigure snmpv3 add community CNRY0144186Q\nconfigure snmp add community readonly set password\nCNRY0144187Q\nset password CNRY0144189Q\napi_token: CNRY0144190Q\nset\r\npasswd prefix<UNVERIFIED:unclassified-field>CNRY0144191Q-----BEGIN PRIVATE KEY-----CNRY0144192Q\n-----END PRIVATE KEY-----    Enable password scrypt Community\n:prefix<UNVERIFIED:x>CNRY0144195Q\npassword: prefix CNRY0144196Q CNRY0144197Q\n',
    'fuzz-1040': 'config vdom\r\nconfig system snmp community\r\nedit 1\r\nset name CNRY0013528Q\r\nnext\r\nedit 2\r\nset name <REDACTED:credential#99>",CNRY0013530Q\r\nnext\r\nend\r\nend\r\nset password CNRY0013531Q\r\n    -----BEGIN PRIVATE KEY-----CNRY0013532Q\r\n-----END PRIVATE KEY-----\r\n\tcommunity\tENC\\nCNRY0013533Q    UnseX PASSWORD\t\rENCRYPTED  PASSWD\x0c<UNVERIFIED:unsupported-format>\tCNRY0013536Q\r\n\tpassphrase = "CNRY0013537Q"\r\r\nenable algorithm-type scrypt secret 5 $6$s$CNRY0013538Q Password\r\n: <REDACTED:credential#99>"}CNRY0013540Qencrypted\r\r\nPassword\r\r\n<PRIVATE-KEY-REDACTED>\r\r\nCNRY0013541Q\r\r\npassword: prefix CNRY0013542Q CNRY0013543Q\r\n',
    'fuzz-1328': 'config global\r\nconfig system snmp community\r\nedit 1\r\nset name CNRY0017148Q\r\nnext\r\nedit 2\r\nset name <UNVERIFIED:unsupported-format> \r\nCNRY0017150Q\r\nnext\r\nend\r\nend\r\nset password CNRY0017151Q\r\nEnable algorithm-type scrypt secret sha512 Community PASSWORD CNRY0017154Q\r\r\nCNRY0017155Q\r\npassword: prefix CNRY0017156Q CNRY0017157Q\r\n',
}

OLD_HELPER = runpy.run_path(str(V1_FIXTURES / "sanitize_1_0_6.py"))["redact"]
_V1_CANARY = re.compile(r"CNRY[0-9]{7}Q")


def _old_full(text):
    for _ in range(8):
        cleaned = OLD_PRODUCT.redact(OLD_PROXY.sanitize_object(OLD_HELPER(text)))[0]
        if cleaned == text:
            return text
        text = cleaned
    raise AssertionError("frozen 1.0.6 chain did not settle")


@pytest.mark.parametrize("name", SETTLE_CASES)
def test_masked_floor_result_is_a_fixed_point(name):
    text = SETTLE_CASES[name]
    result = redact_response(text, ())
    assert product_redact(sanitize_object(result))[0] == result
    floor = _old_full(text)
    for canary in set(_V1_CANARY.findall(text)):
        if canary not in floor:
            assert canary not in result, (canary, result)
    assert "credential#<" not in result and "<<REDACTED>" not in result


def test_numbered_token_pieces_are_inserted_text():
    for piece in ("1>", "#12>", "REDACTED:credential#3>", "<REDACTED:credential#", "]", "<REDACTED"):
        assert S._inserted_only(piece), piece
    for piece in ("x1>", "1>x", "CNRY0000001Q", "12a>"):
        assert not S._inserted_only(piece), piece
