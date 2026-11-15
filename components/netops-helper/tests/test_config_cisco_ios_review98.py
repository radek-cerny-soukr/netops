#!/usr/bin/env python3
"""Review 98 regressions for the standalone Cisco IOS consumer ``config_cisco_ios`` (task 102).

98-N1: an indented ``banner``/``macro name`` header must not be hidden as an ordinary sub-line so
that an exact ``!`` inside its body lets the following body lines be released as allowed syntax.
Refusing such a header is the accepted safe outcome; it does not rely on ``forbidden`` values.

98-N2: a crypto/key stanza is opaque up to its own real ``!``.  An ``end`` (and a prompt-looking
line) before that separator is part of the stanza, not the global end.

98-N3: the header of a crypto/key stanza and its indented body (lines and line endings) are one
logical record and share one ``logical_record_bytes`` budget.

All inputs are SYNTHETIC; ``FAKE`` marks invented secret-like text that must never be released.
Nothing is mocked: the real ``StreamRedactor`` with the real shared buffers and limits is driven.
"""

from __future__ import annotations

import random
import traceback

import pytest

from netops_helper import configuration
from netops_helper.config_limits import ConfigurationLimits


def ios():
    from netops_helper import config_cisco_ios
    return config_cisco_ios


def at(data, *cuts):
    edges = [0, *sorted(set(cut for cut in cuts if 0 < cut < len(data))), len(data)]
    return [data[a:b] for a, b in zip(edges, edges[1:]) if b > a]


def splittings(data, seed=98):
    rng = random.Random(seed)
    special = [i for i, value in enumerate(data) if value in b"\r\n\t^#@\"!"]
    return {
        "single": [data],
        "every-byte": [data[i:i + 1] for i in range(len(data))],
        "before-special": at(data, *special),
        "after-special": at(data, *(i + 1 for i in special)),
        "random": at(data, *rng.sample(range(1, len(data)), min(len(data) - 1, 17))),
    }


def run(chunks, limits=None):
    redactor = ios().StreamRedactor((), "all", limits=limits)
    try:
        for chunk in chunks:
            redactor.feed(chunk)
        content, hidden, count = redactor.finish()
        return content.page(0, content.total)[0], hidden, count
    finally:
        redactor.close()


def fail(chunks, limits=None):
    redactor = ios().StreamRedactor((), "all", limits=limits)
    try:
        for chunk in chunks:
            redactor.feed(chunk)
        redactor.finish()
    except ValueError as exc:
        rendered = repr(redactor)
        with pytest.raises(configuration.ConfigurationRedactionError) as again:
            redactor.finish()
        assert again.value.reason == "stream-incomplete"
        return exc, rendered
    finally:
        redactor.close()
    pytest.fail("stream was accepted")


def assert_refused(exc, rendered, expected, *raw):
    assert isinstance(exc, configuration.ConfigurationRedactionError), type(exc)
    assert exc.reason == expected
    assert exc.__context__ is None and exc.__cause__ is None
    text = " ".join((str(exc), repr(exc), repr(exc.args), "".join(traceback.format_exception(exc)),
                     rendered))
    assert "output withheld" in str(exc)
    assert "closed" in rendered
    for value in ("FAKE", *raw):
        assert value not in text, value


def small(**values):
    base = dict(section_bytes=4096, all_bytes=1 << 20, physical_line_bytes=128,
                logical_record_bytes=512, memory_bytes=8 << 20)
    base.update(values)
    return ConfigurationLimits(**base)


def marker(n, eol="\n"):
    return (ios().MARKER + eol) * n


# ---------------------------------------------------------------------------------------------
# 98-N1  indented banner / macro header
# ---------------------------------------------------------------------------------------------

N1_BANNER = (b"hostname R1\n!\nunknown-mode\n banner motd ^C\n!\nhostname FAKE_BANNER_BODY\n^C\n"
             b"!\nend\n")
N1_MACRO = b"hostname R1\n!\nunknown-mode\n macro name X\n!\nhostname FAKE_MACRO_BODY\n@\n!\nend\n"


@pytest.mark.parametrize("data", [
    N1_BANNER,
    N1_MACRO,
    N1_BANNER.replace(b" banner", b"\tbanner"),
    b"hostname R1\n!\ninterface Gi0/1\n banner motd #\n!\ninterface FAKE_IF\n#\n!\nend\n",
    b"hostname R1\n!\ncrypto isakmp client configuration group G\n banner ^C\n!\n"
    b"hostname FAKE_GROUP_BANNER\n^C\n!\nend\n",
], ids=["banner-unknown-stanza", "macro-unknown-stanza", "banner-tab", "banner-interface",
        "banner-crypto"])
def test_n1_indented_banner_or_macro_header_is_refused_without_fake_content(data):
    for name, chunks in splittings(data).items():
        assert b"".join(chunks) == data
        exc, rendered = fail(chunks)
        assert_refused(exc, rendered, "redaction-unverifiable", "hostname", "banner", "macro")


def test_n1_real_global_banner_and_macro_still_end_at_their_real_delimiter():
    data = (b"hostname R1\n!\nbanner motd ^C\n!\nhostname FAKE_IN_BANNER\nend\n^C\n!\n"
            b"interface Gi0/1\n description After banner\n macro description desk\n!\n"
            b"macro name M\n!\nhostname FAKE_IN_MACRO\n@\n!\nvlan 10\n name After_macro\n!\nend\n")
    page, hidden, count = run([data])
    assert page == ("hostname R1\n!\n" + marker(5) + "!\ninterface Gi0/1\n description After banner\n"
                    + marker(1) + "!\n" + marker(4) + "!\nvlan 10\n name After_macro\n!\nend\n")
    assert count == len(hidden) == 3
    assert "FAKE" not in page


# ---------------------------------------------------------------------------------------------
# 98-N2  end / prompt inside a crypto or key stanza
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("header", [b"crypto pki certificate chain TP", b"key chain KC"],
                         ids=["crypto", "key"])
def test_n2_end_inside_crypto_or_key_is_not_the_global_end(header):
    data = header + b"\nend\nFAKE_SECRET#\n"
    for name, chunks in splittings(data).items():
        exc, rendered = fail(chunks)
        assert_refused(exc, rendered, "stream-incomplete", "FAKE_SECRET", "end")


@pytest.mark.parametrize("header", [b"crypto pki certificate chain TP", b"key chain KC"],
                         ids=["crypto", "key"])
def test_n2_real_separator_and_real_end_after_fake_end_keep_legitimate_data(header):
    data = header + b"\nend\nFAKE_SECRET#\n!\nhostname R1\n!\nend\n\nR1#"
    for name, chunks in splittings(data).items():
        page, hidden, count = run(chunks)
        assert page == marker(3) + "!\nhostname R1\n!\nend\n\nR1#", name
        assert count == len(hidden) == 3


def test_n2_real_crypto_body_and_real_separator_stay_usable():
    data = (b"crypto pki certificate chain TP\n certificate ca 01\n  30820122 FAKE\n  \tquit\n!\n"
            b"hostname R1\n!\ninterface Gi0/2\n switchport\n!\nend\n\nR1#")
    page, hidden, count = run([data])
    assert page == marker(4) + "!\nhostname R1\n!\ninterface Gi0/2\n switchport\n!\nend\n\nR1#"
    assert count == len(hidden) == 1


# ---------------------------------------------------------------------------------------------
# 98-N3  crypto/key header + body share one logical record budget
# ---------------------------------------------------------------------------------------------

LIMITS = dict(physical_line_bytes=64, logical_record_bytes=128)
BODY = b" " + b"A" * 60 + b"\n"            # 62 bytes, fits the physical limit


@pytest.mark.parametrize("header", [b"crypto pki certificate chain TP\n", b"key chain KC\n"],
                         ids=["crypto", "key"])
def test_n3_header_and_body_over_logical_limit_are_refused(header):
    data = header + BODY + BODY + b"!\nend\n"
    assert all(len(line) <= 64 for line in data.split(b"\n"))
    assert len(header + BODY + BODY) > 128
    for name, chunks in splittings(data).items():
        exc, rendered = fail(chunks, limits=small(**LIMITS))
        assert_refused(exc, rendered, "capture-limit-exceeded", "AAAA")


HEADERS = pytest.mark.parametrize("header", [b"crypto pki certificate chain TP\n", b"key chain KC\n"],
                                  ids=["crypto", "key"])


def boundary_records(header):
    """Records of exactly 128 bytes: header + body lines, header + body + empty lines, and header +
    an indented quoted value spanning two lines."""
    last = b" " + b"B" * (128 - len(header) - len(BODY) - 2) + b"\n"
    blank = b"\n" * (128 - len(header) - len(BODY))
    opened = b' q "' + b"C" * 56 + b"\n"
    closing = b"C" * (128 - len(header) - len(opened) - 2) + b'"\n'
    records = {"body": header + BODY + last, "blank": header + BODY + blank,
               "quote": header + opened + closing}
    over = {"body": header + BODY + b" B" + last[1:], "blank": header + BODY + blank + b"\n",
            "quote": header + opened + b"C" + closing}
    for name, record in records.items():
        assert len(record) == 128 and len(over[name]) == 129, name
        assert all(len(line) <= 64 for line in over[name].split(b"\n")), name
    return records, over


@HEADERS
def test_n3_exact_logical_boundary_records_stay_valid(header):
    limits = small(**LIMITS)
    records, unused = boundary_records(header)
    page, hidden, count = run([records["body"] + b"!\nend\n"], limits=limits)
    assert page == marker(3) + "!\nend\n" and count == len(hidden) == 1
    page, hidden, count = run([records["blank"] + b"!\nend\n"], limits=limits)
    assert page == marker(2) + "\n" * (128 - len(header) - len(BODY)) + "!\nend\n"
    assert count == len(hidden) == 1
    # The quoted value is its own hidden record but stays inside the crypto/key record budget.
    page, hidden, count = run([records["quote"] + b"!\nend\n"], limits=limits)
    assert page == marker(3) + "!\nend\n" and count == len(hidden) == 2


@HEADERS
@pytest.mark.parametrize("kind", ["body", "blank", "quote"])
def test_n3_one_byte_over_the_logical_boundary_is_refused(header, kind):
    unused, over = boundary_records(header)
    for name, chunks in splittings(over[kind] + b"!\nend\n").items():
        exc, rendered = fail(chunks, limits=small(**LIMITS))
        assert_refused(exc, rendered, "capture-limit-exceeded", "BBBB", "CCCC")


@HEADERS
def test_n3_separate_stanzas_and_statements_have_their_own_budget(header):
    limits = small(**LIMITS)
    # Separated by a real '!': two records, each below the limit, together above it.
    page, hidden, count = run([header + BODY + b"!\n" + header + BODY + b"!\nhostname R1\n!\nend\n"],
                              limits=limits)
    assert page == marker(2) + "!\n" + marker(2) + "!\nhostname R1\n!\nend\n"
    assert count == len(hidden) == 2
    # A new unindented statement inside the stanza starts its own record.
    page, hidden, count = run([header + BODY + header + BODY + b"!\nend\n"], limits=limits)
    assert page == marker(4) + "!\nend\n" and count == len(hidden) == 2
