from __future__ import annotations

import pytest

from netops_core.platforms import ALIASES, PLATFORMS, PlatformError, normalize

NOT_TEXT = (None, 1, True, 1.5, [], {}, (), b"fortios", "", "   ")


@pytest.mark.parametrize("name", PLATFORMS)
def test_canonical_name_is_returned_unchanged(name):
    assert normalize(name) == name


@pytest.mark.parametrize("alias", sorted(ALIASES))
def test_alias_is_mapped_to_the_canonical_name(alias):
    assert normalize(alias) == ALIASES[alias]


def test_fortinet_is_the_alias_of_fortios():
    assert normalize("fortinet") == "fortios"


def test_every_alias_points_at_a_canonical_name():
    for alias, canonical in ALIASES.items():
        assert canonical in PLATFORMS
        assert alias not in PLATFORMS


def test_the_access_point_platform_is_canonical_and_has_no_alias():
    assert "ruckus_unleashed" in PLATFORMS
    assert normalize("ruckus_unleashed") == "ruckus_unleashed"
    assert normalize(" Ruckus_Unleashed ") == "ruckus_unleashed"
    assert "ruckus_unleashed" not in ALIASES


def test_names_are_unique():
    assert len(set(PLATFORMS)) == len(PLATFORMS)


@pytest.mark.parametrize(
    "value",
    ("FortiOS", "  fortios  ", "\tFORTIOS\n", "Fortinet", "EXOS", " Extreme_Switch_Engine "),
)
def test_case_and_surrounding_whitespace_do_not_matter(value):
    assert normalize(value) in PLATFORMS


@pytest.mark.parametrize(
    "value",
    ("fortiswitch", "ios", "nxos", "junos", "eos", "extreme", "forti os", "cisco-ios", "linux2"),
)
def test_unknown_name_is_refused(value):
    with pytest.raises(PlatformError) as caught:
        normalize(value)
    message = str(caught.value)
    assert repr(value) in message
    assert "fortios" in message
    assert "juniper_junos_els" in message
    assert "ruckus_unleashed" in message


@pytest.mark.parametrize("value", NOT_TEXT)
def test_value_that_is_not_text_is_refused(value):
    with pytest.raises(PlatformError) as caught:
        normalize(value)
    assert repr(value) in str(caught.value)


def test_refusal_lists_the_aliases():
    with pytest.raises(PlatformError) as caught:
        normalize("fortigate")
    message = str(caught.value)
    for alias in ALIASES:
        assert alias in message
