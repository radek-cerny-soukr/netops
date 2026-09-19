from __future__ import annotations

import pytest

from netops_core.legacy_ssh import (
    OPENSSH_OPTIONS,
    PROFILES,
    LegacySshError,
    checked,
    openssh_options,
)

FREE_TEXT = (
    "ssh-rsa",
    "HostKeyAlgorithms=+ssh-rsa",
    "rsa-sha1,diffie-hellman-group14-sha1",
    "RSA-SHA1",
    "rsa_sha1",
    " rsa-sha1",
    "rsa-sha1 ",
    "-oProxyCommand=touch /somewhere/pwned",
    "",
    "   ",
    1,
    True,
    1.5,
    [],
    {},
    ["rsa-sha1"],
    b"rsa-sha1",
)


@pytest.mark.parametrize("profile", PROFILES)
def test_named_profile_passes_through(profile):
    assert checked(profile) == profile


def test_none_stays_none():
    assert checked(None) is None


@pytest.mark.parametrize("value", FREE_TEXT)
def test_free_text_is_refused(value):
    with pytest.raises(LegacySshError) as caught:
        checked(value)
    message = str(caught.value)
    assert repr(value) in message
    assert "rsa-sha1" in message


def test_refusal_says_the_profile_is_a_per_device_exception():
    with pytest.raises(LegacySshError) as caught:
        checked("ssh-rsa")
    message = str(caught.value)
    assert "that one device" in message
    assert "no global switch" in message


def test_no_profile_means_no_options():
    assert openssh_options(None) == ()


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_expands_to_written_down_options(profile):
    options = openssh_options(profile)
    assert options == OPENSSH_OPTIONS[profile]
    assert isinstance(options, tuple)
    assert options


def test_rsa_sha1_expands_to_both_openssh_options():
    assert openssh_options("rsa-sha1") == (
        "HostKeyAlgorithms=+ssh-rsa",
        "PubkeyAcceptedAlgorithms=+ssh-rsa",
    )


@pytest.mark.parametrize("value", FREE_TEXT)
def test_options_are_never_built_from_free_text(value):
    with pytest.raises(LegacySshError):
        openssh_options(value)


def test_every_profile_has_options_and_the_other_way_round():
    assert PROFILES == tuple(sorted(OPENSSH_OPTIONS))
