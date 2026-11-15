#!/usr/bin/env python3
"""Standalone conservative Cisco IOS running-config stream consumer (task 96, bod 06).

The module under test, ``netops_helper.config_cisco_ios``, is a building block only: it is not a
public ``config_read``, has no SSH command, no admitted firmware and no gate.  These tests drive the
real ``config_cisco_ios.StreamRedactor`` with the real shared ``ContentBuilder``/``Content``/
``HiddenRecords``/``ConfigurationLimits`` and the shared error classes.  Nothing is mocked.

All inputs are SYNTHETIC and invented for this test.  Values containing ``FAKE`` or ``NOTREAL`` are
secret sentinels; they must never appear in Content, HiddenRecords, summary, repr or errors.  None of
the data is a vendor capture, a "real" fixture or a configuration of any device.
"""

from __future__ import annotations

import hashlib
import json
import random
import traceback
import tracemalloc
from pathlib import Path

import pytest

from netops_helper import configuration
from netops_helper.config_buffers import Content, HiddenRecords
from netops_helper.config_limits import ConfigurationLimits

SOURCE = Path(__file__).resolve().parents[1] / "src" / "netops_helper"
SENTINELS = ("FAKE", "NOTREAL")


def ios():
    from netops_helper import config_cisco_ios
    return config_cisco_ios


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------

def K(text):
    return ("k", text)


def H(text):
    return ("h", text)


def doc(rows, eol="\r\n"):
    """Raw bytes and the exact expected Content text for rows of kept (K) / hidden (H) lines."""
    marker = ios().MARKER
    raw = "".join(text + eol for unused, text in rows).encode("utf-8")
    expected = "".join((text if kind == "k" else marker) + eol for kind, text in rows)
    return raw, expected


def at(data, *cuts):
    edges = [0, *sorted(set(cut for cut in cuts if 0 < cut < len(data))), len(data)]
    return [data[a:b] for a, b in zip(edges, edges[1:]) if b > a]


def splittings(data, seed=96):
    """Single feed, every byte, cuts around each CR/LF/delimiter/quote and seeded random cuts."""
    rng = random.Random(seed)
    special = [i for i, value in enumerate(data) if value in b"\r\n\x03^#@\"\\!"]
    utf8 = [i for i, value in enumerate(data) if value >= 0x80]
    return {
        "single": [data],
        "every-byte": [data[i:i + 1] for i in range(len(data))],
        "before-special": at(data, *special),
        "after-special": at(data, *(i + 1 for i in special)),
        "inside-utf8": at(data, *utf8),
        "random-a": at(data, *rng.sample(range(1, max(2, len(data))), min(len(data) - 1, 40))),
        "random-b": at(data, *rng.sample(range(1, max(2, len(data))), min(len(data) - 1, 7))),
        "two-halves": at(data, len(data) // 2),
    }


def run(chunks, forbidden=(), limits=None):
    redactor = ios().StreamRedactor(forbidden, "all", limits=limits)
    try:
        for chunk in chunks:
            redactor.feed(chunk)
        content, hidden, count = redactor.finish()
        return content, hidden, count, redactor.summary(), repr(redactor)
    finally:
        redactor.close()


def fail(chunks, forbidden=(), limits=None):
    redactor = ios().StreamRedactor(forbidden, "all", limits=limits)
    try:
        for chunk in chunks:
            redactor.feed(chunk)
        redactor.finish()
    except ValueError as exc:
        rendered = repr(redactor)
        # After a refusal nothing partial can be obtained from the same consumer.
        with pytest.raises(configuration.ConfigurationRedactionError) as again:
            redactor.finish()
        assert again.value.reason == "stream-incomplete"
        assert redactor.summary()["unverified_truncated"] is False
        return exc, rendered
    finally:
        redactor.close()
    pytest.fail("stream was accepted")


def text_of(content):
    return content.page(0, content.total)[0]


def hidden_bytes(hidden):
    return b"".join(key + value for key, value in hidden.records())


def fragments(value, minimum=4):
    return {value[start:end] for start in range(len(value))
            for end in range(start + minimum, len(value) + 1)}


def assert_no_leak(values, *texts, hidden=None):
    joined = "\n".join(texts)
    for value in values:
        for fragment in fragments(value):
            assert fragment not in joined, fragment
            if hidden is not None:
                assert fragment.encode() not in hidden_bytes(hidden), fragment


def assert_safe_error(exc, *raw):
    assert isinstance(exc, ValueError)
    assert exc.__context__ is None and exc.__cause__ is None
    rendered = " ".join((str(exc), repr(exc), repr(exc.args), "".join(traceback.format_exception(exc))))
    assert "output withheld" in str(exc)
    for value in raw:
        assert value not in rendered, value
    for sentinel in SENTINELS:
        assert sentinel not in rendered


def reason(exc):
    assert isinstance(exc, configuration.ConfigurationRedactionError), type(exc)
    return exc.reason


def small(**values):
    base = dict(section_bytes=4096, all_bytes=1 << 20, physical_line_bytes=128,
                logical_record_bytes=512, memory_bytes=8 << 20)
    base.update(values)
    return ConfigurationLimits(**base)


# ---------------------------------------------------------------------------------------------
# Synthetic documents
# ---------------------------------------------------------------------------------------------

BASIC_ROWS = [
    K("Building configuration..."),
    K(""),
    K("Current configuration : 2048 bytes"),
    K("!"),
    K("version 15.2"),
    H("service timestamps debug datetime msec"),
    H("no service password-encryption"),
    K("!"),
    K("hostname LAB-SW1"),
    K("!"),
    H("enable secret 9 $9$FAKEenableNOTREAL"),
    K("!"),
    H("username FAKEadmin privilege 15 secret 5 $1$FAKEhashNOTREAL"),
    H("aaa new-model"),
    K("!"),
    K("vlan 20"),
    K(" name LAB_USERS"),
    H(" state FAKEstateNOTREAL"),
    K("!"),
    K("interface GigabitEthernet0/1"),
    K(" description Uplink to core"),
    K(" switchport trunk allowed vlan 10,20,30-40"),
    K(" switchport mode trunk"),
    H(" ip ospf authentication-key 7 FAKEospfNOTREAL"),
    K(" no shutdown"),
    K("!"),
    K("interface Vlan20"),
    K(" ip address 192.0.2.1 255.255.255.0"),
    K(" ipv6 address 2001:DB8:20::1/64"),
    K(" shutdown"),
    K("!"),
    K("interface GigabitEthernet0/2"),
    K(" switchport"),
    K(" switchport mode access"),
    K(" switchport access vlan 20"),
    H(" switchport port-security mac-address FAKEmacNOTREAL"),
    K(" description Access port"),
    K("!"),
    H("snmp-server community FAKEcommunityNOTREAL RO"),
    H("tacacs-server host 192.0.2.50 key 7 FAKEtacacsNOTREAL"),
    H(" interface GigabitEthernet0/9"),
    H("interface GigabitEthernet0/8"),
    H(" description FAKEinsideUnknownNOTREAL"),
    H("radius-server key FAKEradiusNOTREAL"),
    H("ntp authentication-key 1 md5 FAKEntpNOTREAL"),
    H("ppp chap password FAKEpppNOTREAL"),
    K("!"),
    K("interface GigabitEthernet0/3"),
    K(" description Later real port"),
    K("!"),
    H("line vty 0 4"),
    H(" password 7 FAKElineNOTREAL"),
    K("!"),
    K("end"),
]
BASIC_HIDDEN = sum(kind == "h" for kind, unused in BASIC_ROWS)


def test_module_is_standalone_and_shares_existing_building_blocks():
    module = ios()
    from netops_helper import config_exos
    assert module.StreamRedactor is not config_exos.StreamRedactor
    assert not issubclass(module.StreamRedactor, config_exos.StreamRedactor)
    assert module.ContentBuilder is config_exos.ContentBuilder
    assert module.ConfigurationLimits is ConfigurationLimits
    assert module.ConfigurationRedactionError is configuration.ConfigurationRedactionError
    assert module.ConfigurationBudgetError is configuration.ConfigurationBudgetError
    # Wired only through the reviewed adapter and the public config_read path.
    wired = {
        path.name
        for path in SOURCE.glob("*.py")
        if path.name != "config_cisco_ios.py" and "config_cisco_ios" in path.read_text()
    }
    assert wired == {
        "config_cisco_ios_adapter.py",
        "config_cisco_xe_adapter.py",
        "configuration.py",
        "engine.py",
        "proxy.py",
    }
    with pytest.raises(ValueError):
        module.StreamRedactor((), "system")
    with pytest.raises(ValueError):
        module.StreamRedactor((), "all", limits={"memory_bytes": 1})
    with pytest.raises(ValueError):
        module.StreamRedactor((b"bytes-not-str",), "all")


def test_basic_safe_lines_stay_readable_and_everything_else_is_hidden():
    raw, expected = doc(BASIC_ROWS)
    content, hidden, count, summary, rendered = run([raw])
    page = text_of(content)
    assert page == expected
    assert isinstance(content, Content) and isinstance(hidden, HiddenRecords)
    assert content.sha256 == hashlib.sha256(page.encode("ascii")).hexdigest()
    assert count == BASIC_HIDDEN == len(hidden) == summary["unverified_count"]
    assert summary == {"credential_redactions": 0, "unverified_count": BASIC_HIDDEN,
                       "unsupported_format_count": 0,
                       "unverified_fields": summary["unverified_fields"],
                       "unverified_truncated": False}
    assert summary["unverified_fields"] and all(
        label.startswith("cisco-ios / ") for label in summary["unverified_fields"])
    assert "schema_fields_verified" not in summary and "formats_verified" not in summary
    # The later, properly separated interface survives the unknown stanza.
    assert "interface GigabitEthernet0/3\r\n description Later real port\r\n" in page
    # Indented and unseparated interface lines inside the unknown stanza were never interpreted.
    assert "GigabitEthernet0/9" not in page and "GigabitEthernet0/8" not in page
    assert_no_leak(SENTINELS + ("FAKEcommunityNOTREAL", "tacacs", "radius"),
                   page, json.dumps(summary), rendered, repr(content), repr(hidden), hidden=hidden)


def test_line_endings_are_preserved_lf_cr_and_missing_final_newline():
    rows = [K("hostname R1"), K("!"), K("interface Vlan1"), H(" ip helper-address 192.0.2.9"), K("!"),
            K("end")]
    for eol in ("\n", "\r\n", "\r"):
        raw, expected = doc(rows, eol)
        content, hidden, count, unused, unused2 = run([raw])
        assert text_of(content) == expected and count == len(hidden) == 1
        content, hidden, count, unused, unused2 = run([raw[:-len(eol)]])
        assert text_of(content) == expected[:-len(eol)]
    mixed = b"hostname R1\r\n!\n!\rend\r\n\r\nR1#"
    content, unused, count, unused2, unused3 = run([mixed])
    assert text_of(content) == mixed.decode("ascii") and count == 0


def test_echo_prompt_and_preamble_are_exact_frames_only():
    raw = (b"LAB-SW1#show running-config\r\nBuilding configuration...\r\n\r\n"
           b"Current configuration : 99 bytes\r\n!\r\nhostname LAB-SW1\r\n!\r\nend\r\n\r\nLAB-SW1#")
    content, hidden, count, unused, unused2 = run([raw])
    assert text_of(content) == raw.decode("ascii") and count == 0 and len(hidden) == 0
    # The same frame text inside the body is not a frame; it is hidden.
    body = b"hostname R1\r\n!\r\nBuilding configuration...\r\n!\r\nend\r\n"
    content, unused, count, unused2, unused3 = run([body])
    assert "Building" not in text_of(content) and count == 1
    # Anything other than blank lines or an exact prompt after the global end is refused.
    for trailer in (b"hostname FAKEafterNOTREAL\n", b"R1#show FAKE NOTREAL\n", b" !\n"):
        exc, rendered = fail([b"hostname R1\n!\nend\n" + trailer])
        assert reason(exc) == "redaction-unverifiable"
        assert_safe_error(exc, "after")


# ---------------------------------------------------------------------------------------------
# Forbidden values in otherwise safe lines
# ---------------------------------------------------------------------------------------------

def test_forbidden_collision_masks_the_whole_safe_line_without_leaks():
    secret, other = "FAKEcollideNOTREAL", "FAKExyzzyNOTREAL"
    rows = [
        K("hostname LAB-SW1"),
        K("!"),
        K("vlan 30"),
        H(" name " + secret),
        K("!"),
        K("vlan 31"),
        K(" name Printers"),
        K("!"),
        K("interface GigabitEthernet0/4"),
        H(" description link " + other + " here"),
        K(" switchport access vlan 30"),
        K(" description Plain text"),
        K("!"),
        K("end"),
    ]
    raw, expected = doc(rows, "\n")
    content, hidden, count, summary, rendered = run([raw], forbidden=(secret, other, ""))
    page = text_of(content)
    assert page == expected
    assert count == len(hidden) == 2
    assert summary["credential_redactions"] == 2 and summary["unverified_count"] == 0
    assert_no_leak((secret, other), page, json.dumps(summary), rendered, repr(content), repr(hidden),
                   hidden=hidden)
    # A collision in a stanza header hides the header and its whole stanza (not interpreted).
    raw = b"hostname R1\n!\ninterface Gi0/" + secret.encode() + b"\n description Body\n!\nend\n"
    content, hidden, count, summary, unused = run([raw], forbidden=(secret,))
    assert "Body" not in text_of(content) and count == len(hidden) == 2
    assert summary["credential_redactions"] == 1
    # A forbidden value in the hostname is hidden, the rest stays.
    content, hidden, count, summary, unused = run([b"hostname " + secret.encode() + b"\n!\nend\n"],
                                                  forbidden=(secret,))
    assert text_of(content) == ios().MARKER + "\n!\nend\n" and count == 1


def test_identical_structure_with_other_secret_values_yields_identical_hidden_records():
    raw, unused = doc(BASIC_ROWS)
    other = raw.replace(b"FAKE", b"FAKX").replace(b"NOTREAL", b"NOTREAX")
    first = run([raw])
    second = run([other])
    assert first[0] == second[0] and first[2] == second[2] and first[3] == second[3]
    assert list(first[1].records()) == list(second[1].records())
    assert all(len(key) == 16 and len(value) == 16 for key, value in first[1].records())
    assert len({value for unused, value in first[1].records()}) <= len(first[3]["unverified_fields"]) + 1


# ---------------------------------------------------------------------------------------------
# Opaque blocks with fake valid-looking content
# ---------------------------------------------------------------------------------------------

BLOCK_ROWS = [
    K("hostname LAB-SW1"),
    K("!"),
    H("banner motd ^C"),
    H("FAKEmotdNOTREAL secret banner text"),
    H("!"),
    H("hostname FAKEbannerHOST"),
    H("interface GigabitEthernet9/9"),
    H(" ip address 192.0.2.9 255.255.255.0"),
    H("end"),
    H("Přístup jen pro oprávněné ✓ NOTREAL"),
    H("^C"),
    H("banner login #FAKEinline NOTREAL end hostname X#"),
    H("banner exec \x03"),
    H("!"),
    H("interface GigabitEthernet9/5"),
    H("FAKErawNOTREAL\x03 trailing"),
    H("banner incoming XFAKE incoming NOTREAL"),
    H("!"),
    H("end"),
    H("closing X"),
    K("!"),
    H("macro name FAKEmacroNOTREAL"),
    H("!"),
    H("hostname FAKEmacroHOST"),
    H("interface GigabitEthernet9/8"),
    H(" description FAKEinMacroNOTREAL"),
    H("end"),
    H("@"),
    K("!"),
    H("crypto pki certificate chain TP-FAKE-NOTREAL"),
    H(" certificate self-signed 01"),
    H("  3082FAKE 30820194 NOTREAL"),
    H("interface GigabitEthernet9/7"),
    H(" ip address 192.0.2.7 255.255.255.0"),
    H("  \tquit"),
    K("!"),
    H("key chain FAKEchainNOTREAL"),
    H(" key 1"),
    H("  key-string 7 FAKEkeystringNOTREAL"),
    K("!"),
    H('alias exec FAKEalias "show run'),
    H("hostname FAKEquotedHOST"),
    H("!"),
    H("interface GigabitEthernet9/6"),
    H("end"),
    H('still quoted NOTREAL"'),
    K("!"),
    K("interface GigabitEthernet0/5"),
    K(" description After blocks"),
    H(' service-policy input "FAKE'),
    H("!"),
    H("interface GigabitEthernet9/4"),
    H('end NOTREAL"'),
    K(" no shutdown"),
    H(" storm-control action FAKE\\"),
    H("!"),
    K(" switchport access vlan 40"),
    K("!"),
    K("vlan 40"),
    K(" name After_Blocks"),
    K("!"),
    K("end"),
]
# banner(4) + macro(1) + crypto(header + unindented line inside) + key chain(1) + quoted(1)
# + quoted sub-line in interface(1) + escape continuation(1)
BLOCK_HIDDEN = 4 + 1 + 2 + 1 + 1 + 1 + 1
BLOCK_FORMATS = 4 + 1 + 2 + 1 + 1 + 1 + 1


def check_blocks(content, hidden, count, summary, rendered, expected):
    page = text_of(content)
    assert page == expected
    assert count == len(hidden) == BLOCK_HIDDEN == summary["unverified_count"]
    assert summary["unsupported_format_count"] == BLOCK_FORMATS
    assert summary["credential_redactions"] == 0
    for fake in ("GigabitEthernet9", "10.9.9", "FAKEbannerHOST", "FAKEmacroHOST", "Přístup"):
        assert fake not in page
    assert page.count("\nend") == 1 and page.endswith("\nend\r\n")
    assert "interface GigabitEthernet0/5\r\n description After blocks\r\n" in page
    assert " name After_Blocks\r\n" in page
    assert_no_leak(SENTINELS + ("FAKEmotd", "keystring"),
                   page, json.dumps(summary), rendered, repr(content), repr(hidden), hidden=hidden)


def test_opaque_blocks_hide_fake_config_and_keep_later_real_data():
    raw, expected = doc(BLOCK_ROWS)
    check_blocks(*run([raw]), expected)


def test_opaque_blocks_are_split_independent():
    raw, expected = doc(BLOCK_ROWS)
    results = set()
    for name, chunks in splittings(raw).items():
        assert b"".join(chunks) == raw
        content, hidden, count, summary, rendered = run(chunks)
        check_blocks(content, hidden, count, summary, rendered, expected)
        results.add((content.sha256, count, tuple(hidden.records()), json.dumps(summary)))
    assert len(results) == 1


def test_crlf_utf8_and_control_delimiter_exactly_on_chunk_boundaries():
    raw = ("hostname R1\r\n!\r\nbanner motd \x03\r\nŽluťoučký kůň ✓\r\nend\r\n\x03\r\n!\r\n"
           "interface Vlan1\r\n description After\r\n!\r\nend\r\n").encode("utf-8")
    expected_kept = "hostname R1\r\n!\r\n" + (ios().MARKER + "\r\n") * 4 + \
        "!\r\ninterface Vlan1\r\n description After\r\n!\r\nend\r\n"
    for index in range(1, len(raw)):
        content, hidden, count, unused, unused2 = run([raw[:index], raw[index:]])
        assert text_of(content) == expected_kept, index
        assert count == len(hidden) == 1
    cr = raw.index(b"\r\n")
    content, unused, unused2, unused3, unused4 = run([raw[:cr + 1], b"", raw[cr + 1:cr + 2], raw[cr + 2:]])
    assert text_of(content) == expected_kept


@pytest.mark.parametrize("data", [
    b"hostname R1\n!\nbanner motd ^C\nFAKE NOTREAL\nend\n",
    b"hostname R1\n!\nbanner motd ^C\nFAKE NOTREAL\n!\nend\n^",
    b"hostname R1\n!\nbanner login #\nFAKE NOTREAL\nend\n",
    b"hostname R1\n!\nbanner exec \x03FAKE NOTREAL\nend\n",
    b"hostname R1\n!\nmacro name FAKEmacro\n hostname NOTREAL\nend\n",
    b"hostname R1\n!\nmacro name FAKEmacro\n hostname NOTREAL\n @\nend\n",
    b'hostname R1\n!\nalias exec FAKE "NOTREAL\n!\nend\n',
    b'hostname R1\n!\nalias exec FAKE "NOTREAL\\"\n!\nend\n',
    b"hostname R1\n!\nalias exec FAKE NOTREAL\\\nend\n",
    b"hostname R1\n!\ninterface Vlan1\n description FAKE NOTREAL\n!\n",
    b"hostname R1\n!\ncrypto pki certificate chain FAKE\n NOTREAL\n",
    b"",
], ids=["banner-caret", "banner-caret-half", "banner-hash", "banner-raw", "macro", "macro-indented-at",
        "quote", "quote-escaped", "escape-eol", "no-end", "crypto-no-end", "empty"])
def test_unclosed_block_or_missing_end_is_refused_without_partial_result(data):
    for name, chunks in splittings(data).items() if data else [("empty", [])]:
        exc, rendered = fail(chunks)
        assert reason(exc) == "stream-incomplete", name
        assert_safe_error(exc, "hostname")
        assert "FAKE" not in rendered


@pytest.mark.parametrize("header", [
    b"banner motd", b"banner motd ", b"banner", b"banner  ", b"banner motd \tX",
    "banner motd é FAKE NOTREAL é".encode(), b"banner MOTD #x#", b"banner motd \x00x\x00",
    b"banner motd \x03FAKE\x07NOTREAL\x03",
])
def test_unknown_or_malformed_banner_delimiter_is_refused(header):
    data = b"hostname R1\n!\n" + header + b"\n!\nend\n"
    exc, rendered = fail([data])
    assert reason(exc) == "redaction-unverifiable"
    assert_safe_error(exc, "banner", "motd")


def test_banner_inside_unknown_stanza_is_still_opaque():
    rows = [K("hostname R1"), K("!"), H("logging host 192.0.2.7"),
            H("banner motd ^C"), H("!"), H("interface GigabitEthernet9/3"), H(" description FAKE NOTREAL"),
            H("^C"), K("!"), K("end")]
    raw, expected = doc(rows, "\n")
    content, hidden, count, summary, unused = run([raw])
    assert text_of(content) == expected and count == len(hidden) == 2
    assert summary["unsupported_format_count"] == 1


# ---------------------------------------------------------------------------------------------
# Invalid input, refusals and lifecycle
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("data,expected", [
    (b"hostname R1\n!\nusername FAKE secret \xff\xfeNOTREAL\n!\nend\n", "redaction-unverifiable"),
    (b"hostname R1\n!\nhostname FAKE\x07NOTREAL\n!\nend\n", "redaction-unverifiable"),
    (b"hostname R1\n!\n description FAKE\xc2\x85NOTREAL\n!\nend\n", "redaction-unverifiable"),
    (b"hostname R1\n!\n --More-- FAKE NOTREAL\n!\nend\n", "redaction-unverifiable"),
    (b"hostname R1\n!\nend\n\xc3", "stream-incomplete"),
])
def test_invalid_utf8_controls_and_pager_are_refused_safely(data, expected):
    for name, chunks in splittings(data).items():
        exc, rendered = fail(chunks)
        assert reason(exc) == expected, name
        assert_safe_error(exc, "hostname", "username")


def test_device_error_line_is_a_refusal_without_input():
    exc, unused = fail([b"% Invalid input detected FAKE NOTREAL\nhostname R1\n!\nend\n"])
    assert isinstance(exc, configuration.ConfigurationRefusedError)
    assert_safe_error(exc, "Invalid")


def test_lifecycle_close_feed_finish():
    module = ios()
    redactor = module.StreamRedactor(("FAKEsecretNOTREAL",), "all")
    redactor.feed(b"hostname R1\n!\nend\n")
    content, hidden, count = redactor.finish()
    assert text_of(content) == "hostname R1\n!\nend\n" and count == 0
    assert "FAKE" not in repr(redactor) and "finished" in repr(redactor)
    late = b"hostname LATE" + b"VALUE\n"  # not a literal on the raising source line
    with pytest.raises(configuration.ConfigurationRedactionError) as caught:
        redactor.feed(late)
    assert_safe_error(caught.value, "LATEVALUE")
    with pytest.raises(configuration.ConfigurationRedactionError):
        redactor.finish()
    redactor.close()
    redactor.close()

    closed = module.StreamRedactor((), "all")
    closed.feed(b"hostname R1\n")
    closed.close()
    for action in (lambda: closed.feed(b"!\nend\n"), closed.finish):
        with pytest.raises(configuration.ConfigurationRedactionError) as caught:
            action()
        assert_safe_error(caught.value, "R1")

    typed = module.StreamRedactor((), "all")
    with pytest.raises(configuration.ConfigurationRedactionError):
        typed.feed(bytearray(b"hostname R1\n"))
    assert "closed" in repr(typed)
    typed.close()

    never = module.StreamRedactor((), "all")
    with pytest.raises(configuration.ConfigurationRedactionError) as caught:
        never.finish()
    assert caught.value.reason == "stream-incomplete"

    interrupted = module.StreamRedactor((), "all")
    interrupted.feed(b"hostname R1\n!\nbanner motd ^C\nFAKE NOTREAL")
    interrupted.close()
    with pytest.raises(configuration.ConfigurationRedactionError) as caught:
        interrupted.finish()
    assert caught.value.reason == "stream-incomplete"
    assert_safe_error(caught.value, "R1")


# ---------------------------------------------------------------------------------------------
# Budget boundaries
# ---------------------------------------------------------------------------------------------

def test_physical_line_boundary():
    limits = small(physical_line_bytes=64)
    exact = b"hostname " + b"A" * 55          # 64 bytes without the terminator
    content, unused, count, unused2, unused3 = run([exact + b"\r\n!\r\nend\r\n"], limits=limits)
    assert text_of(content).startswith(exact.decode()) and count == 0
    over = b"username FAKE" + b"N" * 52      # 65 bytes
    for name, chunks in splittings(over + b"\n!\nend\n").items():
        exc, unused = fail(chunks, limits=limits)
        assert reason(exc) == "capture-limit-exceeded", name
        assert_safe_error(exc, "username")


def test_logical_record_boundary_for_banner_macro_and_quote():
    limits = small(physical_line_bytes=64, logical_record_bytes=128)
    bodies = {
        "banner": (b"banner motd ^C\n", b"^C\n"),
        "macro": (b"macro name FAKE\n", b"@\n"),
        "quote": (b'alias exec FAKE "x\n', b'"\n'),
    }
    for name, (head, tail) in bodies.items():
        fill = 128 - len(head) - len(tail)
        lines = b"".join(b"N" * 39 + b"\n" for unused in range(fill // 40)) + b"N" * (fill % 40 - 1) + b"\n"
        data = head + lines + tail
        assert len(data) == 128
        content, unused, count, unused2, unused3 = run([b"hostname R1\n!\n" + data + b"!\nend\n"],
                                                       limits=limits)
        assert count == 1, name
        exc, unused = fail([b"hostname R1\n!\n" + head + b"N" + lines + tail + b"!\nend\n"], limits=limits)
        assert reason(exc) == "capture-limit-exceeded", name
        assert_safe_error(exc, "alias", "macro")


def test_capture_limit_on_raw_input_and_on_redacted_output():
    limits = small(all_bytes=4096, section_bytes=4096, logical_record_bytes=512)
    exc, unused = fail([b"hostname R1\n!\n" + b"!\n" * 2100 + b"end\n"], limits=limits)
    assert reason(exc) == "capture-limit-exceeded"
    # Raw input fits, but the markers of many short hidden lines do not.
    exc, unused = fail([b"x\n" * 1000 + b"!\nend\n"], limits=limits)
    assert reason(exc) == "capture-limit-exceeded"
    assert_safe_error(exc)


def test_hidden_record_limit_boundary(monkeypatch):
    module = ios()
    monkeypatch.setattr(module, "MAX_HIDDEN_RECORDS", 3)
    content, hidden, count, unused, unused2 = run([b"a\nb\nc\n!\nend\n"])
    assert count == len(hidden) == 3
    exc, unused = fail([b"a\nb\nc\nusername FAKE NOTREAL\n!\nend\n"])
    assert reason(exc) == "capture-limit-exceeded"
    assert_safe_error(exc, "username")


def test_work_reservation_refuses_before_processing():
    limits = small(memory_bytes=600)
    redactor = ios().StreamRedactor((), "all", limits=limits)
    try:
        with pytest.raises(configuration.ConfigurationBudgetError) as caught:
            redactor.feed(b"hostname R1\n" * 100)
        rendered = repr(redactor)
    finally:
        redactor.close()
    assert "output withheld" in str(caught.value) and caught.value.__context__ is None
    assert "lines=0 " in rendered


def test_memory_budget_boundary_on_retained_output():
    data = b"hostname R1\n" + b"!\n" * 3000 + b"end\n"
    content, hidden, count, unused, unused2 = run([data], limits=small(memory_bytes=1 << 20))
    assert content.total == len(data)
    exc, unused = fail([data], limits=small(memory_bytes=4096 + 1024))
    assert isinstance(exc, configuration.ConfigurationBudgetError)
    assert_safe_error(exc)


def warmed(limits):
    warm = ios().StreamRedactor((), "all", limits=limits)
    warm.feed(b"hostname R1\r\n\r\n x\r\nbanner motd ^C\r\n^C\r\n!\rend\n")
    warm.finish()
    warm.close()
    return ios().StreamRedactor((), "all", limits=limits)


@pytest.mark.parametrize("data", [
    b"!\r\n" * 20000 + b"end\r\n",
    b"\n" * 60000 + b"hostname R1\n!\nend\n",
], ids=["20000-short-lines", "60000-newlines"])
def test_single_large_feed_peak_stays_within_memory_budget(data):
    """Peak of NEW Python allocations (tracemalloc, this CPython) while one ``feed`` runs.  The input
    is created before the tracer starts.  Not an RSS or whole-process measurement."""
    limits = small(physical_line_bytes=65536, logical_record_bytes=65536, memory_bytes=200_000)
    redactor = warmed(limits)
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
    assert text_of(content) == data.decode("ascii") and count == 0 and len(hidden) == 0


def test_large_feed_has_no_whole_input_decode_or_split_copy():
    data = b"!\n" * 400_000 + b"end\n"
    limits = small(all_bytes=4 << 20, section_bytes=4096, physical_line_bytes=65536,
                   logical_record_bytes=65536, memory_bytes=16 << 20)
    redactor = warmed(limits)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        redactor.feed(data)
        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    try:
        content, unused, count = redactor.finish()
    finally:
        redactor.close()
    # Transient working memory above what is retained stays far below one copy of the input.
    assert peak - current < 384 * 1024 < len(data), (peak, current)
    assert content.total == len(data) and count == 0


def test_newline_only_chunks_and_split_crlf_stream():
    redactor = ios().StreamRedactor((), "all", limits=small())
    try:
        for unused in range(2000):
            redactor.feed(b"\n")
        for unused in range(500):
            redactor.feed(b"\r")
            redactor.feed(b"\n")
        redactor.feed(b"hostname R1\r")
        redactor.feed(b"\n!\r")
        redactor.feed(b"\nend\r")
        content, hidden, count = redactor.finish()
    finally:
        redactor.close()
    assert text_of(content) == "\n" * 2000 + "\r\n" * 500 + "hostname R1\r\n!\r\nend\r"
    assert count == 0 and len(hidden) == 0
