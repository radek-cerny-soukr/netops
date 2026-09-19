import pytest

from netops_core import prompt

BODY = "#config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=0\nconfig system global\nend\n"
NAME = "device-a"


def prompted(marker, platform="fortios", body=BODY):
    return prompt.cleaned(
        "%s %s %s%s %s" % (NAME, marker, body, NAME, marker), platform,
    )


@pytest.mark.parametrize("marker", ("#", "$"))
@pytest.mark.parametrize("platform", ("fortios", "exos", "fortinet", "extreme_exos"))
def test_both_measured_markers_are_cleaned_on_both_platform_spellings(marker, platform):
    assert prompt.cleaned(
        "%s %s Version: 1\n%s %s " % (NAME, marker, NAME, marker), platform,
    ) == "Version: 1\n"


@pytest.mark.parametrize("marker", ("#", "$"))
def test_the_prompt_goes_from_the_first_line_and_from_the_end(marker):
    assert prompted(marker) == BODY


@pytest.mark.parametrize("platform", ("linux", "cisco_ios", "ruckus_unleashed", "", None, 7))
def test_a_platform_without_a_table_entry_is_a_no_op(platform):
    text = "device-a # Version: 1\ndevice-a # "
    assert prompt.cleaned(text, platform) == text


def test_a_first_line_that_starts_with_the_marker_is_never_touched():
    assert prompt.cleaned(BODY, "fortios") == BODY
    assert prompt.cleaned("$ not a prompt\n", "fortios") == "$ not a prompt\n"


def test_the_middle_and_a_different_trailing_prompt_survive():
    text = 'device-a # config firewall address\n    edit "net # 42"\nend\ndevice-b # '
    assert prompt.cleaned(text, "fortios") == (
        'config firewall address\n    edit "net # 42"\nend\ndevice-b # '
    )


def test_an_empty_answer_stays_empty():
    assert prompt.cleaned("", "fortios") == ""
    assert prompt.cleaned("device-a # ", "fortios") == ""


def test_the_trailing_newline_of_the_answer_is_kept():
    assert prompt.cleaned("device-a $ one\ntwo\n", "fortios") == "one\ntwo\n"
    assert prompt.cleaned("device-a $ one\ntwo", "fortios") == "one\ntwo"


def test_the_table_names_the_two_measured_platforms_and_their_aliases():
    assert prompt.PLATFORMS == ("fortios", "exos")
    assert prompt.prefix("fortinet") is prompt.prefix("fortios")
    assert prompt.prefix("extreme_exos") is prompt.prefix("exos")
    assert prompt.prefix("junos") is None
