import pytest

from netops_core.legacy_ssh import (
    OPENSSH_OPTIONS,
    PROFILES,
    LegacySshError,
    checked,
    openssh_options,
)

PROFILE = "rsa-sha1"
OPTIONS = ("HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa")
BAD_PROFILES = (
    "ssh-rsa",
    "HostKeyAlgorithms=+ssh-rsa",
    "rsa-sha1,diffie-hellman-group14-sha1",
    "RSA-SHA1",
    " rsa-sha1",
    "-oProxyCommand=touch /tmp/pwned",
    "",
    "   ",
    1,
    True,
    [],
    {},
    ["rsa-sha1"],
    ("rsa-sha1",),
)


def test_the_profiles_and_their_options_are_written_down_in_this_module():
    assert PROFILES == (PROFILE,)
    assert tuple(OPENSSH_OPTIONS) == PROFILES
    assert OPENSSH_OPTIONS[PROFILE] == OPTIONS


def test_no_profile_means_no_algorithm_option_at_all():
    assert checked(None) is None
    assert openssh_options(None) == ()


def test_a_named_profile_expands_to_its_two_options():
    assert checked(PROFILE) == PROFILE
    assert openssh_options(PROFILE) == OPTIONS
    assert isinstance(openssh_options(PROFILE), tuple)


@pytest.mark.parametrize("profile", BAD_PROFILES)
def test_anything_else_is_refused_and_the_message_says_why(profile):
    for call in (checked, openssh_options):
        with pytest.raises(LegacySshError) as caught:
            call(profile)
        said = str(caught.value)
        assert "per device" in said
        assert "no global switch" in said
        assert PROFILE in said
        assert repr(profile) in said
