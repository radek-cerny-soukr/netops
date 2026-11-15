"""Finding 86-N1: a FortiOS IPv6 lookup holding only the CLI prompt is not a recognized no-route.

Direct normalization (tables.parse with the default state that Tables derives from the raw text, or an
explicit "ok") must report an IPv6 lookup whose body is empty once the known prompt framing is removed as
unparsed / ok False / incomplete coverage, like the already handled blank text. Only the explicit
"% Network not in table" is a recognized 0-row answer.

Every prompt-only, CRLF, whitespace or header text below is DERIVED (hand-written parser/contract input),
not a new live measurement or hardware qualification. The controls use the unchanged real FortiGate-60F
7.6.8 build 3744 captures 03 (connected loopback) and 04 (explicit no-route, marker right after the prompt)
of tests/fixtures/real/fortios/fg60f_7.6.8_ipv6_20261114; their CRLF variants are DERIVED.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from netops_helper import tables

FIXTURES = Path(__file__).parent / "fixtures" / "real" / "fortios" / "fg60f_7.6.8_ipv6_20261114"
CONNECTED = {"prefix": "::1/128", "next_hop": None, "interface": "root", "protocol": "connected", "vrf": "default"}
LOOKUP_03 = (FIXTURES / "03-lookup-loopback.txt").read_text(encoding="utf-8")
LOOKUP_04 = (FIXTURES / "04-lookup-documentation-address.txt").read_text(encoding="utf-8")

# DERIVED: prompt framing only, no answer at all.
DERIVED_PROMPT_ONLY = {
    "prompt_lf": "FortiGate-60F # \n",
    "prompt_no_newline": "FortiGate-60F # ",
    "prompt_crlf": "FortiGate-60F # \r\n",
    "prompt_trailing_spaces": "FortiGate-60F #    \n",
    "prompt_tab_after_marker": "FortiGate-60F # \t\n",
    "two_prompts": "FortiGate-60F # \nFortiGate-60F # \n",
    "two_prompts_crlf": "FortiGate-60F # \r\nFortiGate-60F # \r\n",
    "three_prompts": "FortiGate-60F # \nFortiGate-60F # \nFortiGate-60F # ",
    "prompt_blank_lines_prompt": "FortiGate-60F # \n\n\nFortiGate-60F # ",
    "prompt_whitespace_lines_prompt_crlf": "FortiGate-60F # \r\n \t\r\n\r\nFortiGate-60F # \r\n",
    "prompt_whitespace_lines": "FortiGate-60F # \n   \n\t\n",
    "vdom_prompt": "FW-01 (root) # \n",
    "vdom_prompt_crlf_twice": "FW-01 (root) # \r\n\r\nFW-01 (root) # ",
    "dollar_prompt": "FortiGate-60F $ \n",
}


def parse(text: str, **options) -> dict:
    return tables.parse("fortinet", "route", "ipv6_route_lookup", text, **options)


def assert_not_an_answer(result: dict, name: str) -> None:
    assert result["status"] == "unparsed", name
    assert result["ok"] is False, name
    assert result["records"] == [], name
    assert result["coverage"]["complete"] is False, name
    assert result["coverage"]["parsed_records"] == 0, name


@pytest.mark.parametrize("name", sorted(DERIVED_PROMPT_ONLY))
def test_derived_prompt_only_is_unparsed_with_the_default_state(name):
    assert_not_an_answer(parse(DERIVED_PROMPT_ONLY[name]), name)


@pytest.mark.parametrize("name", sorted(DERIVED_PROMPT_ONLY))
def test_derived_prompt_only_is_unparsed_with_an_explicit_ok_state(name):
    assert_not_an_answer(parse(DERIVED_PROMPT_ONLY[name], status="ok", rc=0), name)


def test_derived_prompt_only_is_reported_like_the_blank_text():
    blank = parse("")
    prompt = parse(DERIVED_PROMPT_ONLY["prompt_lf"])
    assert "blank_output_not_a_route_answer" in blank["warnings"]
    assert "blank_output_not_a_route_answer" in prompt["warnings"]
    for result in (blank, prompt):
        assert_not_an_answer(result, "blank-or-prompt")
        assert result["unparsed"] == []
        assert result["sources"][0]["status"] == "unparsed"


def test_derived_prompt_only_keeps_the_failure_refusal_and_pager_states():
    prompt = DERIVED_PROMPT_ONLY["prompt_lf"]
    failed = parse(prompt, rc=1)
    assert failed["status"] == "transport_error" and failed["ok"] is False and failed["records"] == []
    refused = parse(prompt + "Command fail. Return code -61\n", status="permission_denied", refused=True)
    assert refused["status"] == "permission_denied" and refused["ok"] is False and refused["records"] == []
    paged = parse(prompt + "--More--")
    assert paged["status"] == "truncated" and paged["ok"] is False and paged["records"] == []


# ---- controls on the real captures 03/04 ------------------------------------------------------------------------
@pytest.mark.parametrize("variant", ["real", "derived_crlf"])
def test_real_connected_record_is_fully_kept(variant):
    text = LOOKUP_03 if variant == "real" else LOOKUP_03.replace("\n", "\r\n")
    result = parse(text)
    assert result["status"] == "ok" and result["ok"] is True
    assert result["records"] == [CONNECTED] and result["unparsed"] == []
    assert result["coverage"]["complete"] is True and result["coverage"]["parsed_records"] == 1
    assert "blank_output_not_a_route_answer" not in result["warnings"]


@pytest.mark.parametrize("variant", ["real", "derived_crlf"])
def test_real_no_route_marker_is_the_only_valid_empty_answer(variant):
    text = LOOKUP_04 if variant == "real" else LOOKUP_04.replace("\n", "\r\n")
    result = parse(text)
    assert result["status"] == "empty" and result["ok"] is True
    assert result["records"] == [] and result["unparsed"] == []
    assert result["coverage"]["complete"] is True
    assert "blank_output_not_a_route_answer" not in result["warnings"]


@pytest.mark.parametrize("text", [
    "FortiGate-60F # Routing table for VRF=0\n\nFortiGate-60F # ",
    "FortiGate-60F # \nRouting table for VRF=0\n",
    "FortiGate-60F # % Network not in\n\nFortiGate-60F # ",
    "FortiGate-60F # % Network not in table\nRouting table for VRF=0\nFortiGate-60F # ",
    "FortiGate-60F # Command fail. Return code -61\n\nFortiGate-60F # ",
], ids=["derived_header_only", "derived_header_after_prompt", "derived_truncated_marker",
        "derived_marker_and_header", "derived_refusal_text"])
def test_derived_unknown_header_refusal_or_partial_marker_is_not_no_route(text):
    result = parse(text)
    assert result["status"] != "empty" and result["ok"] is False and result["records"] == []
    assert result["coverage"]["complete"] is False
