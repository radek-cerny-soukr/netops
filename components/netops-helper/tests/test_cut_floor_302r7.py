#!/usr/bin/env python3
"""Task 302-r7: a cut of the redacted output must not break the 1.0.8 floor.

Review 302-r6rv: ``redact()`` checked its floor over the whole output, but the diagnostics then
send only the first ``max_bytes`` UTF-8 bytes (``engine._fortiadc_diagnostics``). The new
redaction lengthened the text (`x` -> `<REDACTED>`), the cut took the END line of a private key,
and the product no longer hid its body, which the 1.0.8 chain with the same limit hid.

Every place that cuts a ``redact()`` output before it leaves for the AI client passes
``cut_bytes=max_bytes`` (``engine._fortiadc_logs``, the FortiOS ``logs`` recipe, the other
FortiOS recipes, ``engine._fortiadc_diagnostics``); the output then hides the floor itself, so
every prefix does (``sanitize._redact_credentials``). The tests run the exact review input through
the real engine paths (fake transport), then the proxy and the product, and compare with the
1.0.8 chain with the same limit; a differential fuzz cuts the ``redact()`` output at random
sizes as the engine does. Every value is synthetic.

NETOPS_R7_FUZZ_CASES sets the number of fuzz inputs (default 400), NETOPS_R7_FUZZ_SEED the seed.
"""

from __future__ import annotations

from contextlib import nullcontext
import importlib.util
import json
import os
import pathlib
import random
from types import SimpleNamespace

import pytest

from netops_helper import sanitize as S
from netops_helper.sanitize import redact

HERE = pathlib.Path(__file__).parent


def _load(path, alias):
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


R6 = _load(HERE / "test_structural_floor_302r6.py", "structural_floor_302r6_for_302r7")
FLOOR = R6.FLOOR
WITHHELD = R6.WITHHELD

CASES = int(os.environ.get("NETOPS_R7_FUZZ_CASES", "400"))
SEED = int(os.environ.get("NETOPS_R7_FUZZ_SEED", "302007"))
IP = "192.0.2.183"
CANARY = "synthetic-key-canary"


def _cut(text, size):
    """The engine's cut: the first ``size`` UTF-8 bytes, whole characters."""
    return text.encode("utf-8")[:size].decode("utf-8", "ignore")


def _review_raw(prefix=899):
    """The exact input of review 302-r6rv (1000 ASCII bytes with prefix 899; 16000 with 15899)."""
    return ("A" * prefix + "\n"
            "tacacs-server key x\n"
            "-----BEGIN RSAPRIVATE KEY-----\n"
            "synthetic-key-canary\n"
            "-----END RSAPRIVATE KEY-----")


def _released_1_0_8(raw, max_bytes):
    """The redact() path of 1.0.8 with the same limit: Helper 1.0.8 rules, the cut, proxy 1.0.8, product."""
    helper = str.__str__(FLOOR.RULES_1_0_8._redact_credentials(raw, ()))
    return R6._old_proxy_worker(_cut(helper, max_bytes))


def _client(value):
    """What the AI client gets: the proxy and the product (HelperBridge.call), as JSON text."""
    return R6._shown(R6._proxy_worker(value))


# --- The exact review input --------------------------------------------------------------------

@pytest.mark.parametrize("prefix,max_bytes", [(899, 1000), (15899, 16000)])
def test_review_input_redact_then_cut(prefix, max_bytes):
    raw = _review_raw(prefix)
    assert len(raw.encode()) == max_bytes
    # The 1.0.8 chain with the same limit: the cut keeps END, the product hides the key.
    assert _released_1_0_8(raw, max_bytes) == "A" * prefix + "\n" + "tacacs-server key x\n[REDACTED]"
    # Without a cut the output is unchanged from r6: the later layers hide the key.
    assert redact(raw) == "A" * prefix + "\ntacacs-server key <REDACTED>\n" + raw.split("\n", 2)[2]
    cleaned = redact(raw, cut_bytes=max_bytes)
    assert cleaned == "A" * prefix + "\ntacacs-server key <REDACTED>\n<REDACTED>"
    returned = _cut(cleaned, max_bytes)
    assert returned == cleaned and len(returned.encode()) <= max_bytes
    for value in (returned, {"untrusted_device_output": returned}, json.dumps({"untrusted_device_output": returned})):
        assert CANARY not in _client(value)
    # Every cut of that output keeps the key hidden.
    for size in range(1, len(cleaned.encode()) + 1):
        assert CANARY not in _client(_cut(cleaned, size))


# --- The real engine paths (fake transport) ------------------------------------------------------

def _transport(monkeypatch):
    import netops_core.target_lock
    from netops_helper import engine
    monkeypatch.setattr(netops_core.target_lock, "target_lock", lambda fingerprint: nullcontext())
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda auth: ["192.0.2.10"])
    monkeypatch.setattr(engine, "host_key_line", lambda *a: "pinned")
    monkeypatch.setattr(engine, "_paced_connection", lambda *a: nullcontext())
    monkeypatch.setattr(engine, "DeviceCredential", lambda auth: None)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda *a, **k: None)
    monkeypatch.setattr(engine.core_session, "Session",
                        lambda *a, **k: nullcontext(SimpleNamespace(close=lambda: None)))
    return engine


def _auth(platform):
    return SimpleNamespace(alias="lab", secrets=(), host_key_fingerprint="pin", port=22, login="ro",
                           legacy_ssh=False, ssh_platform=platform)


def _fortiadc_diagnostics(monkeypatch, raw, max_bytes):
    from netops_helper import fortios_diagnostics as d
    engine = _transport(monkeypatch)
    monkeypatch.setattr(d, "adc_validate", lambda *a, **k: None)
    monkeypatch.setattr(d, "adc_authorize", lambda *a, **k: None)
    monkeypatch.setattr(d, "adc_run", lambda *a, **k: (raw, False, ("FortiADC-KVM", "7.6.7", "0676")))
    return engine.fortios_diagnostics.__wrapped__(_auth("fortiadc"), "ping", IP, "", 3, 1, max_bytes)


def _fortios_ping(monkeypatch, raw, max_bytes):
    from netops_helper import fortios_diagnostics as d
    engine = _transport(monkeypatch)
    monkeypatch.setattr(d, "validate", lambda *a, **k: None)
    monkeypatch.setattr(d, "authorize", lambda *a, **k: None)
    monkeypatch.setattr(d, "run", lambda *a, **k: (raw, False, ("FortiGate-60F", "7.6.8", "3744"), "root"))
    return engine.fortios_diagnostics.__wrapped__(_auth("fortinet"), "ping", IP, "port2", 3, 1, max_bytes)


def _fortios_logs(monkeypatch, raw, max_bytes):
    from netops_helper import fortios_diagnostics as d
    engine = _transport(monkeypatch)
    monkeypatch.setattr(d, "validate", lambda *a, **k: None)
    monkeypatch.setattr(d, "authorize", lambda *a, **k: None)
    log = {"output": raw, "state": "ok", "filter": {"category": "traffic"}, "found": 1, "loaded": 1,
           "matched": 1, "returned": 1, "time_range": None, "truncated": False}
    monkeypatch.setattr(d, "run", lambda *a, **k: (log, False, ("FortiGate-60F", "7.6.8", "3744"), "root"))
    return engine.fortios_diagnostics.__wrapped__(_auth("fortinet"), "logs", IP, "", 3, 1, max_bytes)


def _fortiadc_logs(monkeypatch, raw, max_bytes):
    from netops_helper import fortiadc_diagnostics as adc
    engine = _transport(monkeypatch)
    monkeypatch.setattr(adc, "validate", lambda *a, **k: None)
    monkeypatch.setattr(adc, "authorize", lambda *a, **k: None)
    result = {"raw_output": raw, "output": raw, "state": "data", "cleanup": "verified", "timed_out": False,
              "identity": ("FortiADC-KVM", "7.6.7", "0676"), "loaded_records": 1, "returned_records": 1,
              "count_truncated": False, "unrecognized_body": False}
    monkeypatch.setattr(adc, "run", lambda *a, **k: result)
    return engine.fortios_diagnostics.__wrapped__(_auth("fortiadc"), "system_event_logs", "", "", 3, 1, max_bytes)


PATHS = {"fortiadc-diagnostics": _fortiadc_diagnostics, "fortios-recipe": _fortios_ping,
         "fortios-logs": _fortios_logs, "fortiadc-logs": _fortiadc_logs}


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("prefix,max_bytes", [(899, 1000), (15899, 16000)])
def test_review_input_on_every_engine_cut(monkeypatch, path, prefix, max_bytes):
    raw = _review_raw(prefix)
    result = PATHS[path](monkeypatch, raw, max_bytes)
    returned = result["untrusted_device_output"]
    assert returned == "A" * prefix + "\ntacacs-server key <REDACTED>\n<REDACTED>", path
    assert result["returned_bytes"] == len(returned.encode()) <= max_bytes
    assert result["truncated"] is False
    # The proxy and the product on the tool result (object and JSON text), as on the way to the client.
    for value in (result, json.dumps(result), returned):
        assert CANARY not in _client(value), path
    # Never weaker than the 1.0.8 chain with the same limit.
    old = _released_1_0_8(raw, max_bytes)
    assert not FLOOR._hidden(R6._cjk_values(raw), old) - FLOOR._hidden(R6._cjk_values(raw), returned)


@pytest.mark.parametrize("path", PATHS)
def test_engine_cut_keeps_the_floor_when_the_cut_falls_inside_the_key(monkeypatch, path):
    # A longer prefix: the output is really cut (truncated), inside the key block; the body stays hidden.
    raw = _review_raw(899) + "\n" + "B" * 200
    for max_bytes in (1000, 1005, 1020, 1100):
        result = PATHS[path](monkeypatch, raw, max_bytes)
        returned = result["untrusted_device_output"]
        assert result["returned_bytes"] == len(returned.encode()) <= max_bytes
        assert CANARY not in _client(result) and CANARY not in returned, (path, max_bytes)


# --- Differential fuzz: the redact() path with a cut where the engine cuts -------------------------

def _cjk_set(text):
    return {char for char in text if "一" <= char <= "鿿"}


def _sizes(generator, *lengths):
    """Cut sizes: one anywhere, and one in the last 48 bytes of each length (an END line)."""
    sizes = {generator.randrange(1, max(lengths) + 2)}
    for length in lengths:
        sizes.add(max(1, length - generator.randrange(0, 48)))
    return sorted(sizes)


def _fuzz_inputs():
    """r6 fuzz inputs, with a long first line in some of them so that a cut falls late in the text."""
    generator = random.Random(SEED)
    for index, text in enumerate(R6.FUZZ[:CASES]):
        if index % 3 == 0:
            text = "x" * generator.randrange(1, 900) + "\n" + text
        yield index, text


def _fuzz_leaks(count, first=False):
    """(index, size, leaked characters) of fuzz inputs whose cut redact() output, after the proxy and
    the product, shows a character that 1.0.8 with the same limit or the released chains hide;
    and the number of cut outputs that differ from the output without a cut."""
    generator = random.Random(SEED + 1)
    hidden = FLOOR._hidden
    leaks, changed = [], 0
    for index, text in _fuzz_inputs():
        if index >= count:
            break
        chars = _cjk_set(text)
        floor = hidden(text, R6._old_helper_chain(text)) | hidden(text, R6._old_helper_chain_1_0_6(text))
        helper = str.__str__(FLOOR.RULES_1_0_8._redact_credentials(text, ()))
        try:
            whole = redact(text)
        except ValueError:
            continue
        for size in _sizes(generator, len(whole.encode()), len(helper.encode())):
            try:
                cleaned = redact(text, cut_bytes=size)
            except ValueError:
                continue
            changed += cleaned != whole
            returned = _cut(cleaned, size)
            assert len(returned.encode("utf-8")) <= size
            old = _released_1_0_8(text, size)
            shown_old = chars & set(old)
            # What 1.0.8 with this limit hid of its own prefix.
            hidden_cut = (chars & set(_cut(helper, size))) - shown_old
            forbidden = (floor | hidden_cut) - shown_old
            for value in (returned, {"untrusted_device_output": returned}):
                leak = chars & set(_client(value)) & forbidden
                if leak:
                    leaks.append((index, size, text[:200], sorted(leak), returned[-300:]))
                    if first:
                        return leaks, changed
    return leaks, changed


def test_fuzz_cut_redact_output_keeps_the_released_floors():
    leaks, changed = _fuzz_leaks(CASES)
    assert not leaks, leaks[:3]
    assert changed > 5, changed


def test_fuzz_finds_the_leak_without_the_cut_floor(monkeypatch):
    # The r6 behaviour (the floor checked over the whole output only): the fuzz finds a leak.
    monkeypatch.setattr(S, "_cut", lambda value, size: value)
    leaks, _ = _fuzz_leaks(CASES, first=True)
    assert leaks


def test_review_input_leaks_without_the_cut_floor(monkeypatch):
    # The finding of review 302-r6rv, reproduced with the cut step switched off.
    monkeypatch.setattr(S, "_cut", lambda value, size: value)
    raw = _review_raw(899)
    returned = _cut(redact(raw, cut_bytes=1000), 1000)
    assert returned == "A" * 899 + "\ntacacs-server key <REDACTED>\n-----BEGIN RSAPRIVATE KEY-----\n" \
                       "synthetic-key-canary\n-----END RSAPRIVATE"
    assert CANARY in _client(returned)


def test_fuzz_cut_of_a_json_document_keeps_the_released_floor():
    generator = random.Random(SEED + 2)
    hidden = FLOOR._hidden
    for index, text in _fuzz_inputs():
        if index % 4:
            continue
        document = json.dumps({"config": text}, ensure_ascii=False)
        chars = _cjk_set(text)
        floor = hidden(text, R6._old_helper_chain(document))
        helper = str.__str__(FLOOR.RULES_1_0_8._redact_credentials(document, ()))
        try:
            whole = redact(document)
        except ValueError:
            continue
        for size in _sizes(generator, len(whole.encode()), len(helper.encode())):
            try:
                returned = _cut(redact(document, cut_bytes=size), size)
            except ValueError:
                continue
            old = _released_1_0_8(document, size)
            shown_old = chars & set(old)
            forbidden = (floor | ((chars & set(_cut(helper, size))) - shown_old)) - shown_old
            leak = chars & set(_client(returned)) & forbidden
            assert not leak, (index, size, document[:200], sorted(leak), returned[-300:])


# --- The mechanism -----------------------------------------------------------------------------

def test_output_within_the_limit_is_the_r6_output():
    # No cut: the output keeps the r6 form (the product hides the key on the way).
    raw = _review_raw(899)
    assert redact(raw, cut_bytes=1009) == redact(raw)
    assert redact(raw, cut_bytes=1008) != redact(raw)


def test_fast_path_gives_the_1_0_8_text_with_a_cut():
    # Without an account rule the text is the 1.0.8 Helper text: the same cut gives the 1.0.8 prefix.
    raw = "A" * 899 + "\n-----BEGIN RSAPRIVATE KEY-----\nsynthetic-key-canary\n-----END RSAPRIVATE KEY-----"
    assert redact(raw, cut_bytes=1000) == redact(raw) == str.__str__(FLOOR.RULES_1_0_8._redact_credentials(raw, ()))


def test_cut_of_a_marked_text():
    marked = S._origin("abécd")
    assert S._cut(marked, 100) is marked
    cut = S._cut(marked, 3)  # `é` takes two bytes: only `ab` fits
    assert str.__str__(cut) == "ab" and S._unclaimed("abécd", cut) == [(2, 5)]
    assert S._cut("abécd", 4) == "abé"
