import pytest

from netops_admin import fortios

CHANGE = "ab12cd" + "0" * 26
FIRE = "2026-10-13 12:00:00"
INVERSE = ["config firewall address", 'edit "fixture"', 'set comment "previous"', "next", "end"]
NAMES = fortios.safeguard_names(CHANGE)
SECTIONS = {"action": "system automation-action", "trigger": "system automation-trigger",
            "stitch": "system automation-stitch"}


def answers():
    text = "\n".join(fortios.render_safeguard(CHANGE, INVERSE, FIRE)) + "\n"
    return {kind: text for kind in ("action", "trigger", "stitch")}


def changed(kind, original, replacement):
    texts = answers()
    assert original in texts[kind]
    texts[kind] = texts[kind].replace(original, replacement)
    return texts


def empty_section(kind, entry=None):
    lines = ["config " + SECTIONS[kind]]
    if entry is not None:
        lines += ['edit "%s"' % entry, "next"]
    return "\n".join(lines + ["end"]) + "\n"


def test_the_safeguard_removal_closes_every_section_it_opens():
    assert fortios.render_safeguard_removal(CHANGE) == [
        "config system automation-stitch", 'delete "%s"' % NAMES["stitch"], "end",
        "config system automation-trigger", 'delete "%s"' % NAMES["trigger"], "end",
        "config system automation-action", 'delete "%s"' % NAMES["action"], "end",
    ]


def test_an_action_that_is_not_a_cli_script_is_named_alone():
    texts = changed("action", "set action-type cli-script", "set action-type email")
    assert fortios.safeguard_state(CHANGE, texts, INVERSE, FIRE) == ["safeguard action is missing or not a cli-script"]


def test_a_script_that_differs_from_the_inverse_is_named_alone():
    texts = changed("action", 'set comment \\"previous\\"', 'set comment \\"other\\"')
    assert fortios.safeguard_state(CHANGE, texts, INVERSE, FIRE) == ["safeguard script differs from the planned inverse"]


def test_a_trigger_at_another_time_is_named_alone():
    texts = changed("trigger", FIRE, "2026-10-14 12:00:00")
    assert fortios.safeguard_state(CHANGE, texts, INVERSE, FIRE) == [
        "safeguard trigger is missing or not set to fire once at the planned time"]


def test_a_disabled_stitch_is_named_alone():
    texts = changed("stitch", "set status enable", "set status disable")
    assert fortios.safeguard_state(CHANGE, texts, INVERSE, FIRE) == [
        "safeguard stitch is missing, disabled or bound to another trigger"]


def test_a_stitch_without_the_planned_action_is_named_alone():
    texts = changed("stitch", 'set action "%s"' % NAMES["action"], 'set action "%s"' % (NAMES["action"] + "x"))
    assert fortios.safeguard_state(CHANGE, texts, INVERSE, FIRE) == ["safeguard stitch does not run the planned action"]


def test_every_safeguard_part_missing_is_reported_once_each():
    empty = {kind: empty_section(kind) for kind in SECTIONS}
    assert fortios.safeguard_state(CHANGE, empty, INVERSE, FIRE) == [
        "safeguard action is missing or not a cli-script",
        "safeguard trigger is missing or not set to fire once at the planned time",
        "safeguard stitch is missing, disabled or bound to another trigger",
    ]


def test_sections_that_no_longer_hold_the_safeguard_mean_it_is_absent():
    texts = {kind: empty_section(kind) for kind in SECTIONS}
    assert fortios.safeguard_absent(CHANGE, texts) is True
    others = {kind: empty_section(kind, "unrelated-" + kind) for kind in SECTIONS}
    assert fortios.safeguard_absent(CHANGE, others) is True


@pytest.mark.parametrize("kind", sorted(SECTIONS))
def test_one_remaining_safeguard_part_means_it_is_not_absent(kind):
    texts = {name: empty_section(name) for name in SECTIONS}
    texts[kind] = empty_section(kind, NAMES[kind])
    assert fortios.safeguard_absent(CHANGE, texts) is False


@pytest.mark.parametrize("kind", sorted(SECTIONS))
def test_an_answer_about_another_section_never_means_absent(kind):
    texts = {name: empty_section(name) for name in SECTIONS}
    other = {"action": "trigger", "trigger": "stitch", "stitch": "action"}[kind]
    texts[kind] = empty_section(other)
    assert fortios.safeguard_absent(CHANGE, texts) is False


def test_a_not_found_answer_for_every_part_means_absent():
    texts = {kind: "show x\n%s\n" % fortios.NOT_FOUND for kind in SECTIONS}
    assert fortios.safeguard_absent(CHANGE, texts) is True
