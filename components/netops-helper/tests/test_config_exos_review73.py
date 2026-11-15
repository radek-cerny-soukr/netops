#!/usr/bin/env python3
"""Review 73 regressions for the unregistered EXOS consumer ``config_exos`` (task 109-06, part 76).

73-N1 (P1): inside a quoted value a backslash escapes the very next real character, also an ordinary
one such as ``b``/``t``/``c``; it must not swallow a later quote.  Otherwise an unknown multi-line
quoted payload falls apart into an apparently separate verified sentence that is released verbatim.

73-N2 (P2): ``memory_bytes`` must cover the consumer's own live working memory of one ``feed``
(decoded text, line pieces), not only the builder and pending buffers.  One large ``feed`` must be
processed in small bounded internal slices.

All payloads are SYNTHETIC.  They are given as hex so that backslash-b / backslash-t cannot be
mistaken for a backspace or tab escape in Python source.  Nothing is mocked: the tests drive the
real ``config_exos.StreamRedactor`` with the real ``ContentBuilder``/``Content``/``HiddenRecords``.
"""

from __future__ import annotations

import hashlib
import json
import tracemalloc

import pytest

from netops_helper import configuration
from netops_helper.config_buffers import HiddenRecords
from netops_helper.config_limits import ConfigurationLimits
from netops_helper import config_exos

LEAK_CASE = bytes.fromhex(
    "656e61626c6520706f72747320310a636f6e66696775726520756e6b6e6f776e2022615c62222022686561640a"
    "63726561746520766c616e204c45414b45445f56414c5545207461672032300a7461696c22205c632022656e6422"
    "0a")
CONTACT_CASE = bytes.fromhex(
    "656e61626c6520706f72747320310a636f6e66696775726520736e6d7020737973436f6e7461637420226f70735c"
    "7465616d220a")
MARKER = config_exos.MARKER


def test_hex_payloads_hold_literal_backslash_followed_by_ordinary_character():
    # Guard against a wrongly written payload: these are single literal backslashes.
    assert LEAK_CASE.count(b"\\") == 2 and b"\\b" in LEAK_CASE and b"\\c" in LEAK_CASE
    assert b"\x08" not in LEAK_CASE and b"\t" not in CONTACT_CASE
    assert CONTACT_CASE.count(b"\\") == 1 and b'"ops\\team"' in CONTACT_CASE
    assert LEAK_CASE.decode("ascii").split("\n")[2] == "create vlan LEAKED_VALUE tag 20"


def at(data, *cuts):
    edges = [0, *sorted(set(cuts)), len(data)]
    return [data[a:b] for a, b in zip(edges, edges[1:]) if b > a]


def positions(data, byte):
    return [index for index, value in enumerate(data) if value == byte]


def splittings(data):
    """One single feed plus exact cuts before/after each backslash, quote and LF, and every byte."""
    backslashes = positions(data, ord("\\"))
    quotes = positions(data, ord('"'))
    feeds = positions(data, ord("\n"))
    return {
        "single": [data],
        "before-backslash": at(data, *backslashes),
        "backslash|ordinary": at(data, *(index + 1 for index in backslashes)),
        "before-quote": at(data, *quotes),
        "after-quote": at(data, *(index + 1 for index in quotes)),
        "lf": at(data, *(index + 1 for index in feeds)),
        "before-lf": at(data, *feeds),
        "every-byte": [data[index:index + 1] for index in range(len(data))],
    }


def run(chunks, limits=None):
    redactor = config_exos.StreamRedactor((), "all", limits=limits)
    try:
        for chunk in chunks:
            redactor.feed(chunk)
        content, hidden, count = redactor.finish()
        return content, hidden, count, redactor.summary(), repr(redactor)
    finally:
        redactor.close()


def text_of(content):
    return content.page(0, content.total)[0]


def fragments(value, minimum=4):
    return {value[start:end] for start in range(len(value)) for end in range(start + minimum, len(value) + 1)}


# ---------------------------------------------------------------------------------------------
# 73-N1 escaped ordinary character inside a quoted value
# ---------------------------------------------------------------------------------------------

def test_n1_escaped_ordinary_character_keeps_multiline_quoted_record_opaque():
    expected = "enable ports 1\n" + (MARKER + "\n") * 3
    results = {}
    for name, chunks in splittings(LEAK_CASE).items():
        assert b"".join(chunks) == LEAK_CASE
        content, hidden, count, summary, rendered = run(chunks)
        page = text_of(content)
        assert page == expected, name
        assert content.sha256 == hashlib.sha256(page.encode("ascii")).hexdigest()
        assert count == summary["unverified_count"] == 3
        assert summary["credential_redactions"] == 0
        assert summary["unsupported_format_count"] == 3
        assert summary["unverified_fields"] == ["exos / multiline-record"]
        assert isinstance(hidden, HiddenRecords) and len(hidden) == 0
        joined = "\n".join((page, json.dumps(summary), rendered, repr(content), repr(hidden)))
        for fragment in fragments("LEAKED_VALUE") | {"LEAK", "ALUE", "vlan", "head", "tail", "unknown"}:
            assert fragment not in joined, (name, fragment)
        results[name] = (content.sha256, count, page, summary)
    assert len(set(map(repr, results.values()))) == 1


def test_n1_closed_quoted_value_with_escaped_ordinary_character_finishes():
    expected = "enable ports 1\n" + MARKER + "\n"
    results = set()
    for name, chunks in splittings(CONTACT_CASE).items():
        content, hidden, count, summary, rendered = run(chunks)
        page = text_of(content)
        assert page == expected, name
        assert count == summary["unverified_count"] == 1
        assert summary["unverified_fields"] == ["exos / unsupported-statement"]
        assert summary["unsupported_format_count"] == 0
        assert len(hidden) == 0
        assert "team" not in page + json.dumps(summary) + rendered
        results.add((content.sha256, count, page))
    assert len(results) == 1


@pytest.mark.parametrize("data", [
    b'enable ports 1\nconfigure snmp sysContact "FAKEopen\\"NOTREAL\n',
    b'enable ports 1\nconfigure snmp sysContact "FAKEopen\\\\\\"NOTREAL\nenable ports 2\n',
    b'enable ports 1\nconfigure snmp sysContact "FAKEopenNOTREAL\\\nenable ports 2\n',
])
def test_n1_unclosed_quote_including_escaped_quote_stays_withheld(data):
    for name, chunks in splittings(data).items():
        redactor = config_exos.StreamRedactor((), "all")
        try:
            with pytest.raises(configuration.ConfigurationRedactionError) as caught:
                for chunk in chunks:
                    redactor.feed(chunk)
                redactor.finish()
        finally:
            redactor.close()
        assert caught.value.reason == "stream-incomplete", name
        assert "FAKE" not in str(caught.value) + repr(caught.value.args)


# ---------------------------------------------------------------------------------------------
# 73-N2 live internal working memory of one large feed
# ---------------------------------------------------------------------------------------------

def small(**values):
    # Same helper values as tests/test_config_exos.py::small.
    base = dict(section_bytes=4096, all_bytes=1 << 20, physical_line_bytes=128,
                logical_record_bytes=512, memory_bytes=8 << 20)
    base.update(values)
    return ConfigurationLimits(**base)


REVIEW73_LIMITS = dict(physical_line_bytes=65536, logical_record_bytes=65536, memory_bytes=200_000)


@pytest.mark.parametrize("data,total", [
    (b"enable ports 1\n" * 3000, 45000),                    # exact review 73 repro
    (b"enable ports 1\n" + b"\n" * 60000, 15 + 60000),      # many tiny lines in one feed
], ids=["review73-3000-lines", "60000-empty-lines"])
def test_n2_single_large_feed_peak_internal_memory_stays_within_budget(data, total):
    """Measures, with tracemalloc in this CPython, the peak of NEW Python allocations made while the
    consumer processes one ``feed`` call.  The caller-owned input ``data`` and the redactor are
    created before the tracer starts and are not counted; a small warm-up run primes regex/codec
    caches.  This is not an RSS measurement."""
    limits = small(**REVIEW73_LIMITS)
    warm = config_exos.StreamRedactor((), "all", limits=limits)
    warm.feed(b"enable ports 1\r\n\r\nconfigure x \"a\"\n")  # no escape: N2 only
    warm.finish()
    redactor = config_exos.StreamRedactor((), "all", limits=limits)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        redactor.feed(data)
        unused, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    try:
        content, hidden, count = redactor.finish()
    finally:
        redactor.close()
    assert peak <= limits.memory_bytes, peak
    assert content.total == total and count == 0 and len(hidden) == 0
    assert text_of(content) == data.decode("ascii")


def test_n2_budget_too_small_for_work_slice_is_refused_before_processing():
    limits = small(memory_bytes=600)
    redactor = config_exos.StreamRedactor((), "all", limits=limits)
    try:
        with pytest.raises(configuration.ConfigurationBudgetError) as caught:
            redactor.feed(b"enable ports 1\n" * 100)
        rendered = repr(redactor)
    finally:
        redactor.close()
    assert "output withheld" in str(caught.value)
    assert "lines=0 " in rendered  # refused by the work reservation, not after processing lines
