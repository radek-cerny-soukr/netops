#!/usr/bin/env python3
"""verification regressions for the standalone Cisco IOS consumer ``config_cisco_ios``.

A recognised ``menu`` header (``menu`` as a separate token, unindented or indented) outside an
already open banner/macro/quoted text body is an unsupported multi-line format (Cisco ``menu
<name> title|prompt <d> ... <d>``, syntax only; see ref/menu-source.json).  It must refuse the
whole capture fail-closed: no Content, no partial text, the consumer and its builder closed, an
existing constant safe reason and no raw text in the error.  Simply refusing every menu stanza is
the accepted outcome; there is no menu parser.

The literal word ``menu`` inside an opaque banner/macro/quoted body stays masked text, and a real
interface after the closing delimiter survives.  An ordinary configuration without ``menu`` keeps
working.

All inputs are DERIVED/SYNTHETIC (derived from the documented command syntax only, not a device
capture).  The ``PRIVATE_*_SENTINEL`` values are intentionally NOT passed in ``forbidden``
(``forbidden`` is ``tuple()``), so a pass cannot come from forbidden-value masking.  ``FAKE`` marks
other invented text that must never be released.  Nothing is mocked.
"""

from __future__ import annotations

import random
import traceback

import pytest

from netops_helper import configuration


def ios():
    from netops_helper import config_cisco_ios
    return config_cisco_ios


def at(data, *cuts):
    edges = [0, *sorted(set(cut for cut in cuts if 0 < cut < len(data))), len(data)]
    return [data[a:b] for a, b in zip(edges, edges[1:]) if b > a]


def splittings(data, seed=108):
    rng = random.Random(seed)
    special = [i for i, value in enumerate(data) if value in b"\r\n\t ^#@%/\"!"]
    return {
        "single": [data],
        "every-byte": [data[i:i + 1] for i in range(len(data))],
        "before-special": at(data, *special),
        "after-special": at(data, *(i + 1 for i in special)),
        "random": at(data, *rng.sample(range(1, len(data)), min(len(data) - 1, 17))),
    }


def marker(n, eol="\n"):
    return (ios().MARKER + eol) * n


def run(chunks):
    redactor = ios().StreamRedactor(tuple(), "all")
    try:
        for chunk in chunks:
            redactor.feed(chunk)
        content, hidden, count = redactor.finish()
        return content.page(0, content.total)[0], hidden, count, redactor.summary()
    finally:
        redactor.close()


def refuse(chunks):
    """Drive the consumer; the capture must be refused as a whole (never a short/empty success)."""
    redactor = ios().StreamRedactor(tuple(), "all")
    try:
        for chunk in chunks:
            redactor.feed(chunk)
        redactor.finish()
    except ValueError as exc:
        rendered = repr(redactor)
        # Consumer and builder are closed: nothing partial is retained or obtainable.
        assert redactor._state == "closed"
        assert redactor._hidden is None
        builder = redactor._builder
        assert not builder.buffer and not builder.chunks and builder.stored_bytes == 0
        with pytest.raises(configuration.ConfigurationRedactionError) as again:
            redactor.finish()
        assert again.value.reason == "stream-incomplete"
        return exc, rendered
    finally:
        redactor.close()
    pytest.fail("stream was accepted")


def assert_safe_refusal(exc, rendered, *raw):
    # Only the existing constant safe categories; no raw input in the error or the repr.
    assert type(exc) in (configuration.ConfigurationRedactionError,
                         configuration.ConfigurationRefusedError), type(exc)
    if type(exc) is configuration.ConfigurationRedactionError:
        assert exc.reason == "redaction-unverifiable"
        assert exc.context == ()
    assert exc.__context__ is None and exc.__cause__ is None
    text = " ".join((str(exc), repr(exc), repr(exc.args), rendered))
    # The traceback names this test file (which contains the word "menu"), so it is checked only
    # for values that can come solely from the input.
    trace = "".join(traceback.format_exception(exc))
    assert "output withheld" in str(exc)
    assert "closed" in rendered
    for value in ("FAKE", "SENTINEL", "PRIVATE", "Access1", "menu", "hostname", "title", *raw):
        assert value not in text, value
    for value in ("FAKE", "SENTINEL", "PRIVATE", "Access1"):
        assert value not in trace, value


# ---------------------------------------------------------------------------------------------
# DERIVED/SYNTHETIC reproductions: a menu header must refuse the whole capture
# ---------------------------------------------------------------------------------------------

MENU_TITLE = b"hostname R1\n!\nmenu Access1 title %\n!\nhostname PRIVATE_TITLE_SENTINEL\n%\n!\nend\n"
MENU_PROMPT = b"hostname R1\n!\nmenu Access1 prompt /\n!\nhostname PRIVATE_PROMPT_SENTINEL\n/\n!\nend\n"
MENU_INDENTED = (b"hostname R1\n!\nunknown-mode\n menu Access1 title /\n!\n"
                 b"hostname PRIVATE_INDENT_SENTINEL\n/\n!\nend\n")


@pytest.mark.parametrize("data", [
    MENU_TITLE,
    MENU_PROMPT,
    MENU_INDENTED,
    MENU_INDENTED.replace(b" menu", b"\tmenu"),
], ids=["1-title-percent", "2-prompt-slash", "3-indented-unknown-mode", "3-indented-tab"])
def test_menu_header_refuses_the_whole_capture(data):
    for name, chunks in splittings(data).items():
        assert b"".join(chunks) == data
        exc, rendered = refuse(chunks)
        assert_safe_refusal(exc, rendered)


def test_menu_sentinels_are_not_forbidden_values():
    # The refusal above must not depend on forbidden-value masking.
    redactor = ios().StreamRedactor(tuple(), "all")
    try:
        assert redactor._secrets == ()
    finally:
        redactor.close()


# ---------------------------------------------------------------------------------------------
# Positive: no menu, and literal "menu" inside opaque banner/macro/quoted bodies
# ---------------------------------------------------------------------------------------------

def test_plain_hostname_and_interface_without_menu_continue():
    data = (b"hostname R1\n!\ninterface Gi0/1\n description Menu board port\n switchport\n"
            b" switchport mode access\n!\nlogging host 192.0.2.7\n!\nend\n")
    for name, chunks in splittings(data).items():
        page, hidden, count, unused = run(chunks)
        assert page == ("hostname R1\n!\ninterface Gi0/1\n description Menu board port\n switchport\n"
                        " switchport mode access\n!\n" + marker(1) + "!\nend\n"), name
        assert count == len(hidden) == 1


def test_menu_inside_global_banner_stays_masked_and_later_interface_survives():
    data = (b"hostname R1\n!\nbanner motd ^C\nmenu Access1 title %\n!\nhostname FAKE_BANNER_MENU\n"
            b"%\nmenu Access1 prompt /\n^C\n!\ninterface Gi0/1\n description After banner\n!\nend\n")
    for name, chunks in splittings(data).items():
        page, hidden, count, summary = run(chunks)
        assert page == ("hostname R1\n!\n" + marker(7) +
                        "!\ninterface Gi0/1\n description After banner\n!\nend\n"), name
        assert count == len(hidden) == 1 and summary["unsupported_format_count"] == 1
        assert "FAKE" not in page and "menu" not in page


def test_menu_inside_inline_banner_and_macro_stays_masked():
    data = (b"hostname R1\n!\nbanner login #menu Access1 title % FAKE#\n!\n"
            b"macro name M\nmenu Access1 title /\n!\nhostname FAKE_MACRO_MENU\n/\n@\n!\n"
            b"interface Gi0/2\n switchport\n!\nend\n")
    for name, chunks in splittings(data).items():
        page, hidden, count, unused = run(chunks)
        assert page == ("hostname R1\n!\n" + marker(1) + "!\n" + marker(6) +
                        "!\ninterface Gi0/2\n switchport\n!\nend\n"), name
        assert count == len(hidden) == 2
        assert "FAKE" not in page and "menu" not in page


def test_menu_inside_banner_in_unknown_stanza_stays_masked():
    data = (b"hostname R1\n!\nlogging host 192.0.2.7\nbanner motd ^C\nmenu Access1 title %\n!\n"
            b"interface GigabitEthernet9/3\n description FAKE\n%\n^C\n!\ninterface Vlan1\n"
            b" description After\n!\nend\n")
    for name, chunks in splittings(data).items():
        page, hidden, count, unused = run(chunks)
        assert page == ("hostname R1\n!\n" + marker(8) +
                        "!\ninterface Vlan1\n description After\n!\nend\n"), name
        assert count == len(hidden) == 2


def test_menu_inside_open_quoted_value_stays_masked():
    data = (b'hostname R1\n!\nalias exec FAKE "show run\nmenu Access1 title /\n!\n'
            b'hostname FAKE_QUOTED_MENU\nend"\n!\ninterface Gi0/3\n no shutdown\n!\nend\n')
    for name, chunks in splittings(data).items():
        page, hidden, count, unused = run(chunks)
        assert page == ("hostname R1\n!\n" + marker(5) + "!\ninterface Gi0/3\n no shutdown\n!\nend\n"), name
        assert count == len(hidden) == 1


def test_real_crypto_body_still_masked_and_later_data_usable():
    data = (b"crypto pki certificate chain TP\n certificate ca 01\n  30820122 FAKE\n  \tquit\n!\n"
            b"hostname R1\n!\ninterface Gi0/2\n switchport\n!\nend\n\nR1#")
    page, hidden, count, unused = run([data])
    assert page == marker(4) + "!\nhostname R1\n!\ninterface Gi0/2\n switchport\n!\nend\n\nR1#"
    assert count == len(hidden) == 1
