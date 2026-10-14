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


MIDDLE_SEPARATORS = ("\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " ")


@pytest.mark.parametrize("separator", MIDDLE_SEPARATORS)
def test_a_line_separator_other_than_newline_inside_a_value_survives(separator):
    body = 'config system global\n    set post-login-banner "a%sb"\nend\n' % separator
    assert prompt.cleaned("%s # %s%s #\n" % (NAME, body, NAME), "fortios") == body


@pytest.mark.parametrize("ending", ("\r\n", "\n", ""))
def test_a_crlf_answer_keeps_every_crlf_and_hashes_like_the_same_answer_without_a_prompt(ending):
    body = 'config firewall address\r\n    edit "net # 42"\r\n    set comment "x\r\ny"\r\nend\r\n'
    unprompted = prompt.cleaned(body, "fortios")
    prompted_answer = prompt.cleaned("%s # %s%s #%s" % (NAME, body, NAME, ending), "fortios")
    assert unprompted == body
    assert prompted_answer == body
    assert prompt.cleaned("%s # %s" % (NAME, body), "fortios") == body


def test_cleaning_answers_in_sequence_keeps_each_middle_and_the_plain_one_unchanged():
    plain = "%s # one\n  edit \"net # 42\"\n%s #\n" % (NAME, NAME)
    crlf = "%s # one\r\n  set comment \"a\x0cb\"\r\n%s #\r\n" % (NAME, NAME)
    assert prompt.cleaned(plain, "fortios") == 'one\n  edit "net # 42"\n'
    assert prompt.cleaned(crlf, "fortios") == 'one\r\n  set comment "a\x0cb"\r\n'
    assert prompt.cleaned(plain, "fortios") == 'one\n  edit "net # 42"\n'
