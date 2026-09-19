from __future__ import annotations

import pytest

from netops_core.hostkey import DIGEST_LENGTH, PREFIX, HostKeyError, checked_pin

PIN = "SHA256:" + "A" * 43
MIXED = "SHA256:0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

BAD_PINS = (
    None,
    PIN[len(PREFIX):],
    PIN[:-1],
    PIN + "A",
    "sha256:" + "A" * 43,
    "SHA256:" + "!" * 43,
    "SHA256:" + "=" * 43,
    "SHA256:" + "A" * 42 + " ",
    "MD5:" + "A" * 43,
    "SHA256:",
    "",
    "   ",
    " " + PIN,
    PIN + " ",
    0,
    1,
    True,
    1.5,
    [PIN],
    {"sha256": PIN},
    PIN.encode("ascii"),
)


def test_prefix_and_length_follow_ssh_keygen():
    assert PREFIX == "SHA256:"
    assert DIGEST_LENGTH == 43


def test_well_formed_pin_passes_through():
    assert checked_pin(PIN) == PIN


def test_base64_alphabet_is_accepted_in_full():
    assert checked_pin(MIXED) == MIXED
    assert checked_pin("SHA256:" + "+/" * 21 + "A") == "SHA256:" + "+/" * 21 + "A"


def test_case_of_the_digest_is_kept():
    assert checked_pin(MIXED) != MIXED.lower()
    assert checked_pin(MIXED).startswith(PREFIX)


@pytest.mark.parametrize("value", BAD_PINS)
def test_anything_else_is_refused(value):
    with pytest.raises(HostKeyError) as caught:
        checked_pin(value)
    message = str(caught.value)
    assert repr(value) in message
    assert PREFIX in message
    assert str(DIGEST_LENGTH) in message


def test_refusal_rules_out_first_contact_trust():
    with pytest.raises(HostKeyError) as caught:
        checked_pin(None)
    assert "no first contact trust" in str(caught.value)
