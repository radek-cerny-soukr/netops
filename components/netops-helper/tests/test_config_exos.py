#!/usr/bin/env python3
"""ExtremeXOS ``show configuration`` stream consumer (task 109-06, part 70).

Real input: the two existing PRE-REDACTED golden captures of EXOS 33.7.1.6-patch1-11 under
components/netops-admin/tests/golden/exos (account/sshd2 lines were already removed there, so they
prove neither credential redaction nor a new live capture).  DERIVED input: every value containing
``FAKE`` / ``NOTREAL`` below is synthetic and invented for this test; it is not a vendor capture.

The tests drive the real ``config_exos.StreamRedactor`` with the real ``ContentBuilder``/``Content``
/``HiddenRecords`` and page the result with the existing ``Content.page``.  Nothing is mocked.
"""

from __future__ import annotations

import hashlib
import json
import random
import traceback
from pathlib import Path

import pytest

from netops_helper import configuration
from netops_helper.config_buffers import CHUNK, Content, HiddenRecords
from netops_helper.config_limits import ConfigurationLimits

GOLDEN = (Path(__file__).resolve().parents[2] / "netops-admin" / "tests" / "golden" / "exos" /
          "33.7.1.6-patch1-11")
GOLDEN_FILES = {
    "X435-8P-4S": GOLDEN / "X435-8P-4S" / "show-configuration" / "X435-8P-4S__normal-redacted-secrets.conf",
    "X440G2-12p-10G4": GOLDEN / "X440G2-12p-10G4" / "show-configuration" /
                       "X440-G2-12p-10G4__normal-redacted-secrets.conf",
}
# The only non-empty golden lines the conservative policy may keep, in their original order.
GOLDEN_KEPT = {
    "X435-8P-4S": [
        "configure vlan default delete ports all",
        "configure vlan Default add ports 1-12 untagged  ",
        "enable ssh2",
        "disable telnet",
    ],
    "X440G2-12p-10G4": [
        "configure vlan default delete ports all",
        "configure ports 13 auto off speed 10000 duplex full ",
        "configure ports 14 auto off speed 10000 duplex full ",
        "configure ports 15 auto off speed 10000 duplex full ",
        "configure ports 16 auto off speed 10000 duplex full ",
        "configure vlan Default add ports 1-16 untagged  ",
        "enable ssh2",
        "disable telnet",
    ],
}


def exos():
    from netops_helper import config_exos
    return config_exos


def run(data, *, forbidden=(), splits=None, limits=None):
    redactor = exos().StreamRedactor(forbidden, "all", limits=limits)
    try:
        for chunk in (splits(data) if splits else [data]):
            redactor.feed(chunk)
        content, hidden, count = redactor.finish()
        return content, hidden, count, redactor.summary(), repr(redactor)
    finally:
        redactor.close()


def text_of(content):
    return content.page(0, content.total)[0]


def fail(data, *, forbidden=(), limits=None, splits=None):
    redactor = exos().StreamRedactor(forbidden, "all", limits=limits)
    try:
        for chunk in (splits(data) if splits else [data]):
            redactor.feed(chunk)
        redactor.finish()
    except ValueError as exc:
        return exc, redactor
    finally:
        redactor.close()
    pytest.fail("stream was accepted")


def assert_safe_error(exc, *raw):
    assert exc.__context__ is None and exc.__cause__ is None
    rendered = " ".join((str(exc), repr(exc), repr(exc.args), "".join(traceback.format_exception(exc))))
    assert "output withheld" in str(exc)
    for value in raw:
        assert value not in rendered


# ---------------------------------------------------------------------------------------------
# RED -> GREEN: the current Forti-only grammar refuses a verified-safe EXOS line.
# ---------------------------------------------------------------------------------------------

def test_red_baseline_exos_safe_line_survives_finish():
    """RED on the old engine: without config_exos the baseline is the Forti-only
    configuration.StreamRedactor (the parser the fullconfig flow uses today), which withholds this
    line.  GREEN: only the new config_exos.StreamRedactor is used."""
    try:
        from netops_helper import config_exos
    except ImportError:  # RED baseline only (old engine image without the new module)
        redactor = configuration.StreamRedactor((), "all")
    else:
        redactor = config_exos.StreamRedactor((), "all")
    try:
        redactor.feed(b"create vlan Lab tag 20\r\nconfigure vlan Lab add ports 1-4 untagged\r\n")
        content, hidden, count = redactor.finish()
    finally:
        redactor.close()
    assert type(redactor).__module__ == "netops_helper.config_exos"
    assert text_of(content) == "create vlan Lab tag 20\nconfigure vlan Lab add ports 1-4 untagged\n"
    assert count == 0 and len(hidden) == 0


# ---------------------------------------------------------------------------------------------
# Real pre-redacted golden captures
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("model", sorted(GOLDEN_FILES))
def test_golden_exos_keeps_only_verified_lines_in_order(model):
    raw = GOLDEN_FILES[model].read_bytes()
    marker = exos().MARKER
    content, hidden, count, summary, unused = run(raw, splits=lambda d: [d[i:i + 257] for i in range(0, len(d), 257)])
    source = raw.decode("ascii").split("\n")
    if source[-1] == "":
        source.pop()
    output = text_of(content).split("\n")
    assert output.pop() == ""
    assert len(output) == len(source)
    kept = []
    for before, after in zip(source, output):
        if before.strip(" \t") == "":
            assert after == before
        elif after != marker:
            assert after == before
            kept.append(after)
    assert kept == GOLDEN_KEPT[model]
    masked = sum(1 for line in output if line == marker)
    assert count == masked == summary["unverified_count"] > 0
    assert summary["credential_redactions"] == 0
    assert isinstance(hidden, HiddenRecords) and len(hidden) == 0
    page = text_of(content)
    for absent in ("Info: Command executed", "sysName", "Example Site", "ntp.example.net", "engine-id",
                   "VR-Default", "access-list", "Module", "X435-8P-4S", "X440-G2-12p-10G4"):
        assert absent not in page
    assert content.sha256 == hashlib.sha256(page.encode("ascii")).hexdigest()


# ---------------------------------------------------------------------------------------------
# DERIVED synthetic configuration: credentials, unknown values, quoting, Unicode, PEM, UPM
# ---------------------------------------------------------------------------------------------

LONG_RANDOM = "".join(random.Random(1090670).choice("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
                      for _ in range(96))
DERIVED_SECRETS = {
    "account-hash": "$5$FAKESALTxNOTREAL$FAKEaccountHASHpayloadNOTREAL0123456789",
    "account-sha512": "$6$FAKESALT6NOTREAL$FAKEsha512PAYLOADnotreal9876543210",
    "snmp-community": "FAKEsnmpCOMMUNITYnotreal42",
    "snmp-auth": "FAKEsnmpAUTHkeyNOTREAL77",
    "radius": "FAKEradiusSHAREDnotreal31",
    "tacacs": "FAKEtacacsSECRETnotreal55",
    "sshd2-key": "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEsshd2KEYmaterialNOTREAL0000000000",
    "pem-body": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCFAKEpemBODYnotREAL0123456789abcdef",
    "pem-body2": "FAKEsecondPEMlineNOTREALzyxwvutsrqponmlkjihgfedcba9876543210ZZ",
    "long-random": LONG_RANDOM,
    "quoted": 'FAKEquoted\\"escNOTREAL',
    "multiline": "FAKEmultiLINEnotreal",
    "unicode": "FAKEkancelářNOTREAL",
    "upm-body": "FAKEupmBODYnotreal",
    "desc": "FAKEdescriptionNOTREAL",
    "display": "FAKEdisplayNOTREAL",
}
S = DERIVED_SECRETS
DERIVED_LINES = [
    ("# DERIVED synthetic EXOS configuration for config_exos tests", False),
    ("create vlan Lab-20 tag 20", True),
    (f'configure account admin encrypted "{S["account-hash"]}"', False),
    ('configure vlan "Lab-20" add ports 1:1-1:4,2:7 tagged', True),
    (f'create account admin ops encrypted "{S["account-sha512"]}"', False),
    ("", True),
    (f'configure snmpv3 add community "{S["snmp-community"]}" name FAKEname encrypted "{S["snmp-community"]}"', False),
    ("configure vlan Lab-20 ipaddress 192.0.2.1 255.255.255.0", True),
    (f"configure snmpv3 add user FAKEuser authentication sha {S['snmp-auth']}", False),
    (f'configure radius mgmt-access primary shared-secret encrypted "{S["radius"]}"', False),
    ("enable ipforwarding vlan Lab-20", True),
    (f'configure tacacs primary shared-secret encrypted "{S["tacacs"]}"', False),
    (f"create sshd2 user-key k1 {S['sshd2-key']}", False),
    ("configure vlan Mgmt ipaddress 198.51.100.5/24", True),
    ("configure ssl privkey pregenerated", False),
    ("-----BEGIN PRIVATE KEY-----", False),
    (S["pem-body"], False),
    ("enable ports 1", False),  # inside the PEM block: masked although it looks safe
    (S["pem-body2"], False),
    ("-----END PRIVATE KEY-----", False),
    ("disable ports 9-12", True),
    (f"configure fakefeature value {S['long-random']}", False),
    (f'configure snmp sysContact "ops {S["quoted"]} team"', False),
    (f'configure snmp sysLocation "first {S["multiline"]}', False),
    ('second line of the same quoted record"', False),
    ("configure ports 5 auto off speed 1000 duplex full", True),
    (f'create vlan "{S["unicode"]}"', False),
    ("create upm profile p1", False),
    (f"enable ports 2 {S['upm-body']}", False),
    ("enable ports 3", False),  # inside the UPM block: masked although it looks safe
    (".", False),
    (f'create vlan Lab-30 tag 30 description "{S["desc"]}"', False),
    (f"configure ports 6 display-string {S['display']}", False),
    ("configure ports 6 max-frame-size 9216", True),
    ("\t", True),
    ("enable ipforwarding", True),
]
DERIVED = ("\n".join(line for line, unused in DERIVED_LINES) + "\n").encode("utf-8")


def suffixes(value):
    return {value, value[-12:], value[len(value) // 2:], value[:12]}


def assert_no_secret(*texts):
    joined = "\n".join(texts)
    for name, value in DERIVED_SECRETS.items():
        for fragment in suffixes(value.replace('\\"', '"')) | suffixes(value):
            assert fragment not in joined, name
    for word in ("FAKE", "NOTREAL", "notreal", "-----BEGIN", "$5$", "$6$", "kancel"):
        assert word not in joined


def test_derived_exos_masks_every_unverified_line_and_keeps_safe_text():
    marker = exos().MARKER
    content, hidden, count, summary, rendered = run(DERIVED)
    output = text_of(content).split("\n")
    assert output.pop() == ""
    assert len(output) == len(DERIVED_LINES)
    for (line, keep), after in zip(DERIVED_LINES, output):
        assert after == (line if keep else marker)
    masked = sum(1 for keep in DERIVED_LINES if not keep[1])
    assert count == masked == summary["unverified_count"]
    assert summary["credential_redactions"] == 0
    assert summary["unsupported_format_count"] == 2 + 5 + 4  # multiline record + PEM block + UPM block
    assert summary["unverified_fields"] == ["exos / comment", "exos / unsupported-statement",
                                            "exos / opaque-block", "exos / multiline-record"]
    assert summary["unverified_truncated"] is False
    assert len(hidden) == 0
    assert_no_secret(text_of(content), json.dumps(summary), rendered, repr(content), repr(hidden))


def test_summary_has_same_keys_and_types_as_existing_stream_redactor():
    baseline = configuration.StreamRedactor((), "all")
    try:
        expected = {key: type(value) for key, value in baseline.summary().items()}
    finally:
        baseline.close()
    unused, unused, unused, summary, unused = run(DERIVED)
    assert {key: type(value) for key, value in summary.items()} == expected
    assert all(type(item) is str for item in summary["unverified_fields"])


NEAR_MISSES = [
    'create vlan Lab tag 20 description "FAKEnearNOTREAL"',
    "configure vlan Lab add ports 1-4 untagged; FAKEnearNOTREAL",
    "configure vlan Lab tag 4096",
    "create vlan Lab tag 020",
    "create vlan 9Lab",
    "create vlan Lab$FAKEnearNOTREAL",
    'create vlan "Lab"x',
    "configure vlan Lab ipaddress 192.0.2.256 255.255.255.0",
    # Preserve the non-contiguous mask rejection case without an address-shaped literal.
    "configure vlan Lab ipaddress 192.0.2.1 255.0." + "255.0",
    "configure vlan Lab ipaddress 192.0.2.1/33",
    "configure vlan Lab ipaddress 192.0.2.01/24",
    "configure vlan Lab add ports 1-4 untagged FAKEnearNOTREAL",
    "configure vlan Lab add ports 1-4|FAKEnearNOTREAL",
    "configure ports 5 speed 1000 speed 100",
    "configure ports 5 speed 1234",
    "configure ports 5 max-frame-size 99999",
    "configure ports 5 auto",
    "configure ports 5 display-string FAKEnearNOTREAL",
    "enable ports 1-4 $(FAKEnearNOTREAL)",
    "enable ipforwarding vlan Lab FAKEnearNOTREAL",
    " enable ports 1",
    "Enable ports 1",
    "configure vlan Lab add ports 0",
]


@pytest.mark.parametrize("line", NEAR_MISSES)
def test_near_miss_sentence_is_not_prefix_passed(line):
    content, unused, count, summary, unused = run((line + "\nenable ipforwarding\n").encode())
    assert text_of(content) == exos().MARKER + "\nenable ipforwarding\n"
    assert count == summary["unverified_count"] == 1
    assert "FAKE" not in text_of(content) + json.dumps(summary)


# ---------------------------------------------------------------------------------------------
# Chunk splits, CRLF/CR, identical Content and SHA
# ---------------------------------------------------------------------------------------------

def every(size):
    return lambda data: [data[i:i + size] for i in range(0, len(data), size)]


def at(*cuts):
    def split(data):
        edges = [0, *cuts, len(data)]
        return [data[a:b] for a, b in zip(edges, edges[1:])]
    return split


def random_splits(seed):
    def split(data):
        rng, out, start = random.Random(seed), [], 0
        while start < len(data):
            step = rng.randint(1, 23)
            out.append(data[start:start + step])
            start += step
        return out
    return split


def test_split_positions_and_line_endings_give_identical_content():
    crlf = DERIVED.replace(b"\n", b"\r\n")
    cr = DERIVED.replace(b"\n", b"\r")
    utf8 = DERIVED.index("á".encode()) + 1
    secret = DERIVED.index(S["radius"].encode()) + 7
    pem = DERIVED.index(b"-----BEGIN") + 5
    reference, unused, ref_count, ref_summary, unused = run(DERIVED)
    cases = [(DERIVED, every(1)), (DERIVED, every(2)), (DERIVED, every(7)), (DERIVED, every(64)),
             (DERIVED, at(utf8)), (DERIVED, at(secret)), (DERIVED, at(pem)), (DERIVED, random_splits(7)),
             (crlf, every(1)), (crlf, at(crlf.index(b"\r\n") + 1)), (crlf, random_splits(11)),
             (cr, every(1)), (cr, every(3))]
    for data, splits in cases:
        content, unused, count, summary, unused = run(data, splits=splits)
        assert content == reference
        assert content.sha256 == reference.sha256 == hashlib.sha256(text_of(content).encode()).hexdigest()
        assert text_of(content) == text_of(reference)
        assert (count, summary) == (ref_count, ref_summary)


# ---------------------------------------------------------------------------------------------
# Content.page across several pages and 64 KiB chunks
# ---------------------------------------------------------------------------------------------

def test_content_page_walks_multiple_pages_and_chunks():
    lines = []
    for index in range(1, 3000):
        lines.append(f"create vlan V{index} tag {index}")
        lines.append(f"configure snmp sysName FAKEpageNOTREAL{index}")
    raw = ("\n".join(lines) + "\n").encode()
    content, unused, count, unused, unused = run(raw, splits=every(4093))
    expected = "".join((line if not line.startswith("configure snmp") else exos().MARKER) + "\n" for line in lines)
    assert content.total == len(expected) > 2 * CHUNK and count == 2999
    for limit in (48000, 1000, 333):
        pieces, offset = [], 0
        while offset < content.total:
            page, offset = content.page(offset, limit)
            pieces.append(page)
        assert len(pieces) > 2 and "".join(pieces) == expected
    paged = configuration.payload(content, 0, 48000)
    assert paged["content_sha256"] == content.sha256 and paged["next_offset"] is not None
    assert "FAKE" not in expected


# ---------------------------------------------------------------------------------------------
# Forbidden values, serialized markers and the builder guard
# ---------------------------------------------------------------------------------------------

def test_verified_sentence_colliding_with_registered_secret_is_masked():
    secret = "Lab-FAKEvlanSECRET-NOTREAL"
    raw = f"create vlan {secret} tag 30\nenable ports 1\n".encode()
    content, unused, count, summary, unused = run(raw, forbidden=(secret,), splits=every(5))
    assert text_of(content) == exos().MARKER + "\nenable ports 1\n"
    assert count == summary["credential_redactions"] == 1 and summary["unverified_count"] == 0
    assert_no_secret(text_of(content), json.dumps(summary))
    assert secret[-10:] not in text_of(content)


def test_serialized_marker_in_verified_sentence_is_masked_not_released():
    content, unused, count, summary, unused = run(b"create vlan ENC tag 5\nenable ports 1\n")
    assert text_of(content) == exos().MARKER + "\nenable ports 1\n"
    assert summary["unverified_fields"] == ["exos / reserved-marker-collision"]
    assert summary["credential_redactions"] == 0


def test_secret_colliding_with_marker_text_withholds_whole_output():
    exc, unused = fail(b"enable ports 1\nconfigure fake thing\n", forbidden=("opaque-line",))
    assert type(exc) is configuration.ConfigurationRedactionError
    assert exc.reason == "redaction-unverifiable"
    assert_safe_error(exc, "opaque-line")


# ---------------------------------------------------------------------------------------------
# Decoder, control characters, truncation
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("data", [
    b"enable ports 1\nconfigure FAKErawNOTREAL \xff\xfe\n",
    b"enable ports 1\nconfigure FAKErawNOTREAL \xc3\x28\n",
    b"enable ports 1\nconfigure FAKErawNOTREAL \x1b[0m\n",
    b"enable ports 1\nconfigure FAKErawNOTREAL \x00\n",
    "enable ports 1\nconfigure FAKErawNOTREAL \x85\n".encode(),
    "enable ports 1\nconfigure FAKErawNOTREAL �\n".encode(),
    "enable ports 1\nconfigure FAKErawNOTREAL  \n".encode(),
])
def test_invalid_unicode_and_control_characters_are_refused_without_echo(data):
    for splits in (None, every(1)):
        exc, redactor = fail(data, splits=splits)
        assert type(exc) is configuration.ConfigurationRedactionError
        assert exc.reason == "redaction-unverifiable"
        assert_safe_error(exc, "FAKErawNOTREAL", repr(data[-6:]))
        assert "FAKE" not in repr(redactor) + json.dumps(redactor.summary())


@pytest.mark.parametrize("data", [
    b"enable ports 1\n" + "create vlan á".encode()[:-1],
    b'enable ports 1\nconfigure snmp sysContact "FAKEopenNOTREAL\n',
    b"enable ports 1\n-----BEGIN PRIVATE KEY-----\nFAKEpemNOTREAL\n",
    b"enable ports 1\ncreate upm profile p1\nenable ports 2\n",
])
def test_truncated_stream_is_incomplete(data):
    for splits in (None, every(1)):
        exc, unused = fail(data, splits=splits)
        assert type(exc) is configuration.ConfigurationRedactionError
        assert exc.reason == "stream-incomplete"
        assert_safe_error(exc, "FAKEopenNOTREAL", "FAKEpemNOTREAL")


# ---------------------------------------------------------------------------------------------
# CLI refusal, pager, empty and unintelligible output
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("data", [
    b"%% Invalid input detected at '^' marker.\n",
    b"%% Unrecognized command: FAKEcliNOTREAL\n",
    b"enable ports 1\nError: FAKEcliNOTREAL is not permitted\n",
    b"Permission denied FAKEcliNOTREAL\n",
])
def test_cli_refusal_is_device_refused(data):
    for splits in (None, every(3)):
        exc, unused = fail(data, splits=splits)
        assert type(exc) is configuration.ConfigurationRefusedError
        assert "output withheld" in str(exc) and "FAKE" not in str(exc) + repr(exc.args)


@pytest.mark.parametrize("data", [
    b"enable ports 1\nPress <SPACE> to continue or <Q> to quit:",
    b"enable ports 1\n--More--\nenable ports 2\n",
])
def test_pager_prompt_is_withheld(data):
    exc, unused = fail(data)
    assert type(exc) is configuration.ConfigurationRedactionError
    assert exc.reason == "redaction-unverifiable"
    assert_safe_error(exc)


@pytest.mark.parametrize("data,reason", [
    (b"", "stream-incomplete"),
    (b"\n\n\n", "redaction-unverifiable"),
    (b"#\n# Module vlan configuration.\n#\n", "redaction-unverifiable"),
    (b"configure snmp sysName FAKEonlyNOTREAL\nenable snmp access\n", "redaction-unverifiable"),
])
def test_empty_or_unverified_output_is_not_a_configuration(data, reason):
    exc, redactor = fail(data)
    assert type(exc) is configuration.ConfigurationRedactionError and exc.reason == reason
    assert_safe_error(exc, "FAKEonlyNOTREAL")


# ---------------------------------------------------------------------------------------------
# Limits, memory budget, lifecycle
# ---------------------------------------------------------------------------------------------

def small(**values):
    base = dict(section_bytes=4096, all_bytes=1 << 20, physical_line_bytes=128,
                logical_record_bytes=512, memory_bytes=8 << 20)
    base.update(values)
    return ConfigurationLimits(**base)


def test_physical_line_limit_counts_unterminated_pending_line():
    redactor = exos().StreamRedactor((), "all", limits=small())
    redactor.feed(b"enable ports 1\n" + b"x" * 128)
    with pytest.raises(configuration.ConfigurationRedactionError) as caught:
        redactor.feed(b"y")
    assert caught.value.reason == "capture-limit-exceeded"
    with pytest.raises(configuration.ConfigurationRedactionError):
        redactor.feed(b"\n")


def test_logical_record_limit_for_quoted_multiline_record():
    data = b'enable ports 1\nconfigure snmp sysContact "FAKElogicalNOTREAL\n' + b"z" * 100 + b"\n"
    exc, unused = fail(data + (b"z" * 100 + b"\n") * 5, limits=small())
    assert exc.reason == "capture-limit-exceeded"
    assert_safe_error(exc, "FAKElogicalNOTREAL")


def test_all_bytes_limit_on_raw_stream():
    limits = small(section_bytes=1024, all_bytes=2048, logical_record_bytes=1024)
    exc, unused = fail(b"enable ports 1\n" * 200, limits=limits, splits=every(100))
    assert exc.reason == "capture-limit-exceeded"


def test_output_cap_counts_marker_expansion():
    limits = small(section_bytes=1024, all_bytes=4096, logical_record_bytes=1024)
    exc, unused = fail(b"enable ports 1\n" + b"#\n" * 1000, limits=limits)
    assert type(exc) is configuration.ConfigurationRedactionError and exc.reason == "capture-limit-exceeded"


def test_memory_budget_counts_builder_and_pending_line():
    limits = small(physical_line_bytes=65536, logical_record_bytes=65536, memory_bytes=200_000)
    content, unused, unused, unused, unused = run(b"enable ports 1\n" * 3000, limits=limits)
    assert content.total == 45000
    exc, unused = fail(b"enable ports 1\n" * 20000, limits=limits, splits=every(4096))
    assert type(exc) is configuration.ConfigurationBudgetError and "output withheld" in str(exc)
    tight = small(physical_line_bytes=65536, logical_record_bytes=65536, memory_bytes=20_000)
    exc, unused = fail(b"enable ports 1\n" + b"q" * 60000, limits=tight, splits=every(512))
    assert type(exc) is configuration.ConfigurationBudgetError


def test_only_section_all_and_valid_limits():
    for section in ("system interface", "vlan", "", None):
        with pytest.raises(ValueError):
            exos().StreamRedactor((), section)
    with pytest.raises(ValueError):
        exos().StreamRedactor((), "all", limits={"all_bytes": 1})


def test_close_is_idempotent_and_stream_rejects_feed_after_finish_or_close():
    redactor = exos().StreamRedactor((), "all")
    redactor.feed(b"enable ports 1\n")
    redactor.close()
    redactor.close()
    with pytest.raises(configuration.ConfigurationRedactionError):
        redactor.feed(b"enable ports 2\n")
    with pytest.raises(configuration.ConfigurationRedactionError) as caught:
        redactor.finish()
    assert caught.value.reason == "stream-incomplete"

    finished = exos().StreamRedactor((), "all")
    finished.feed(b"enable ports 1\n")
    content, unused, unused = finished.finish()
    assert isinstance(content, Content) and text_of(content) == "enable ports 1\n"
    with pytest.raises(configuration.ConfigurationRedactionError):
        finished.feed(b"enable ports 2\n")
    with pytest.raises(configuration.ConfigurationRedactionError):
        finished.finish()
    finished.close()
    finished.close()
    assert text_of(content) == "enable ports 1\n"
    with pytest.raises(configuration.ConfigurationRedactionError):
        finished.feed("enable ports 1\n")


def test_cancel_before_finish_releases_buffers_and_yields_no_content():
    redactor = exos().StreamRedactor(("FAKEcancelNOTREAL",), "all")
    redactor.feed(b"enable ports 1\nconfigure snmp sysName FAKEpartialNOTREAL")
    redactor.close()
    assert not redactor._physical and not redactor._pending and redactor._builder.memory_bytes < 4096
    assert "FAKE" not in repr(redactor) + json.dumps(redactor.summary())
    with pytest.raises(configuration.ConfigurationRedactionError):
        redactor.finish()
