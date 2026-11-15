"""Arista EOS `show mlag interfaces` member parser (private building block, no public query wiring).

Real parser `netops_helper.switch_mlag_eos_interfaces.summarize()`, no mocks.

Data labels:
* DOC     - the only CLI block of ref/arista-mlag-interfaces-doc.json (source not mutated): official Arista ATD lab
            guide 2026.2, VXLAN chapter, fetched by HTTPS GET (200):
            https://labguides.testdrive.arista.com/2026.2/data_center/vxlan/
            Baseline: lab guide 2026.2 documentation example only; not a measurement, not an EOS release and not a
            hardware qualification.  Kept verbatim.
* DERIVED - rows built with `_row()` in exactly the DOC row layout (proven by reproducing the DOC row byte for byte),
            with other values, blanked cells or damaged lines, made only to exercise the parser.  They are neither
            documentation nor a measurement and no new CLI format.
The members are reported device data, never a health, forwarding, consistency or neighbor verdict.
"""
import hashlib
from pathlib import Path

import pytest

HERE = Path(__file__).parent
DOC_SOURCE = HERE / "fixtures" / "docs" / "arista_eos" / "mlag_interfaces.txt"

# DOC: ref/arista-mlag-interfaces-doc.json blocks[0], verbatim.
DOC_BLOCK = (
    "s1-leaf4(config)#show mlag interfaces\n"
    "                                                             local/remote\n"
    "mlag       desc             state       local       remote          status\n"
    "---------- ---------- ----------------- ----------- ------------ ------------\n"
    "    5       MLAG - HOST2        active-full         Po5          Po5           up/up\n"
)
DOC_BLOCK_SHA256 = "623c277ee63463d4b3e50d623761b0125108f30322a3d6d28c17e51326ac2178"
DOC_ROW = "    5       MLAG - HOST2        active-full         Po5          Po5           up/up"
DOC_TABLE = DOC_BLOCK[:DOC_BLOCK.index(DOC_ROW)]  # echo, pre-header, header and separator without the row
DOC_HEADER = "mlag       desc             state       local       remote          status"
DOC_SEP = "---------- ---------- ----------------- ----------- ------------ ------------"
DOC_MEMBER = {"id": 5, "description": "MLAG - HOST2", "state": "active-full", "local_port": "Po5",
              "remote_port": "Po5", "local_status": "up", "remote_status": "up", "missing_fields": []}
MEMBER_KEYS = {"id", "description", "state", "local_port", "remote_port", "local_status", "remote_status",
               "missing_fields"}
LONG = "x" * 1025  # DERIVED: one non-blank line longer than 1024 characters


def _summarize(text, capture_state="ok"):
    from netops_helper import switch_mlag_eos_interfaces
    return switch_mlag_eos_interfaces.summarize(text, capture_state)


def _row(mlag, desc, state, local, remote, status):
    """DERIVED: one row with the DOC cell positions (id ends at 5, desc 12, state 32, local 52, remote 65, status 79)."""
    assert len(desc) <= 18 and len(state) <= 18 and len(local) <= 11 and len(remote) <= 12
    line = f"{mlag:>5}".ljust(12) + desc.ljust(20) + state.ljust(20) + local.ljust(13) + remote.ljust(14) + status
    return line.rstrip()


def _table(*rows):
    return DOC_TABLE + "".join(row + "\n" for row in rows)


def _member(**changes):
    member = dict(DOC_MEMBER)
    member.update(changes)
    return member


def test_doc_source_is_unchanged_and_derived_layout_reproduces_doc_row():
    fixture = DOC_SOURCE.read_bytes().decode("utf-8")
    assert DOC_BLOCK == "s1-leaf4(config)#show mlag interfaces\n" + fixture
    assert hashlib.sha256(DOC_BLOCK.encode()).hexdigest() == DOC_BLOCK_SHA256
    assert _row("5", "MLAG - HOST2", "active-full", "Po5", "Po5", "up/up") == DOC_ROW
    assert _table(DOC_ROW) == DOC_BLOCK


def test_doc_row_gives_all_seven_fields_and_measured():
    summary = _summarize(DOC_BLOCK)
    assert summary == {"state": "measured", "members": [DOC_MEMBER], "missing_fields": []}
    assert set(summary["members"][0]) == MEMBER_KEYS and "healthy" not in summary


@pytest.mark.parametrize("capture_state", ["partial", "timeout", None])
def test_doc_row_with_incomplete_capture_is_partial_and_keeps_the_member(capture_state):
    assert _summarize(DOC_BLOCK, capture_state) == {"state": "partial", "members": [DOC_MEMBER],
                                                    "missing_fields": ["capture"]}


def test_derived_two_rows_with_description_spaces_are_measured():
    second = _row("6", "HOST3 active-full", "active-partial", "Po6", "Po6", "up/down")
    summary = _summarize(_table(DOC_ROW, second))
    assert summary == {"state": "measured", "missing_fields": [], "members": [
        DOC_MEMBER,
        {"id": 6, "description": "HOST3 active-full", "state": "active-partial", "local_port": "Po6",
         "remote_port": "Po6", "local_status": "up", "remote_status": "down", "missing_fields": []},
    ]}


def test_derived_blank_description_is_optional():
    second = _row("7", "", "inactive", "Po7", "Po7", "down/down")
    summary = _summarize(_table(DOC_ROW, second))
    assert summary == {"state": "measured", "missing_fields": [], "members": [
        DOC_MEMBER,
        {"id": 7, "description": None, "state": "inactive", "local_port": "Po7", "remote_port": "Po7",
         "local_status": "down", "remote_status": "down", "missing_fields": []},
    ]}


def test_derived_disabled_row_with_unset_remote_is_partial_not_up():
    second = _row("8", "HOST4", "disabled", "Po8", "-", "up/-")
    summary = _summarize(_table(DOC_ROW, second))
    assert summary == {"state": "partial", "missing_fields": ["members[1].remote_port", "members[1].remote_status"],
                       "members": [
                           DOC_MEMBER,
                           {"id": 8, "description": "HOST4", "state": "disabled", "local_port": "Po8",
                            "remote_port": None, "local_status": "up", "remote_status": None,
                            "missing_fields": ["remote_port", "remote_status"]},
                       ]}


@pytest.mark.parametrize("row, description", [
    (_row("5", "HOST2 active-full", "", "Po5", "Po5", "up/up"), "HOST2 active-full"),
    (_row("5", "HOST2  active-full", "", "Po5", "Po5", "up/up"), "HOST2  active-full"),
    (DOC_ROW.replace("active-full", " " * len("active-full")), "MLAG - HOST2"),
])
def test_derived_blanked_state_cell_never_takes_a_description_word(row, description):
    assert len(row) == len(DOC_ROW) and row.endswith("Po5          Po5           up/up")
    summary = _summarize(_table(row))
    assert summary == {"state": "partial", "missing_fields": ["members[0].state"],
                       "members": [_member(description=description, state=None, missing_fields=["state"])]}


@pytest.mark.parametrize("damaged", [
    _row("6", "HOST3", "active-full", "", "Po6", "up/up"),      # blank local cell
    _row("6", "HOST3", "active-full", "Po6", "", "up/up"),      # blank remote cell
    _row("6", "HOST3", "active-full", "Po6", "Po6", ""),        # blank status cell
    _row("6", "HOST3", "active-full", "Po6", "Po6", "up/up") + "   extra",  # extra cell
    LONG,                                                       # overlong line
    DOC_SEP,                                                    # a separator is no member
])
def test_derived_damaged_row_is_never_a_member_and_keeps_other_rows(damaged):
    for rows in ((damaged, DOC_ROW), (DOC_ROW, damaged)):
        summary = _summarize(_table(*rows))
        assert summary == {"state": "partial", "members": [DOC_MEMBER], "missing_fields": ["members"]}


def test_derived_na_and_malformed_tokens_are_none_and_keep_other_rows():
    na = _row("9", "HOST5", "active-full", "Po9", "N/A", "N/A")
    malformed = _row("1x", "HOST6", "activefull", "Port6", "Po6", "upup")
    summary = _summarize(_table(DOC_ROW, na, malformed))
    assert summary["state"] == "partial"
    assert summary["members"] == [
        DOC_MEMBER,
        {"id": 9, "description": "HOST5", "state": "active-full", "local_port": "Po9", "remote_port": None,
         "local_status": None, "remote_status": None,
         "missing_fields": ["remote_port", "local_status", "remote_status"]},
        {"id": None, "description": "HOST6", "state": None, "local_port": None, "remote_port": "Po6",
         "local_status": None, "remote_status": None,
         "missing_fields": ["id", "state", "local_port", "local_status", "remote_status"]},
    ]
    assert summary["missing_fields"] == [
        "members[1].remote_port", "members[1].local_status", "members[1].remote_status",
        "members[2].id", "members[2].state", "members[2].local_port", "members[2].local_status",
        "members[2].remote_status",
    ]


def test_derived_duplicate_id_is_ambiguous_and_keeps_both_rows():
    second = _row("5", "HOST3", "active-full", "Po6", "Po6", "up/up")
    summary = _summarize(_table(DOC_ROW, second))
    assert summary == {"state": "partial", "missing_fields": ["members", "members[0].id", "members[1].id"],
                       "members": [
                           _member(id=None, missing_fields=["id"]),
                           _member(id=None, description="HOST3", local_port="Po6", remote_port="Po6",
                                   missing_fields=["id"]),
                       ]}


@pytest.mark.parametrize("text", [
    "",
    "\r\n\r\n",
    None,
    "s1-leaf4(config)#",
    "s1-leaf4(config)#show mlag interfaces\n",
    "s1-leaf4(config)#show mlag interfaces\n% Invalid input detected at '^' marker.\ns1-leaf4(config)#",
    DOC_ROW + "\n",  # a row without its header cannot be placed
])
def test_blank_prompt_refusal_or_unknown_text_is_unparsed(text):
    assert _summarize(text) == {"state": "unparsed", "members": [], "missing_fields": ["table", "members"]}
    assert _summarize(text, "timeout") == {"state": "unparsed", "members": [],
                                           "missing_fields": ["table", "members", "capture"]}


def test_header_and_separator_without_rows_is_not_a_proven_empty_list():
    assert _summarize(DOC_TABLE) == {"state": "partial", "members": [], "missing_fields": ["members"]}
    assert _summarize(DOC_TABLE + "s1-leaf4(config)#") == {"state": "partial", "members": [],
                                                           "missing_fields": ["members"]}


@pytest.mark.parametrize("text", [
    DOC_HEADER + "\n" + DOC_ROW + "\n",                                    # separator missing
    DOC_HEADER + "\n" + DOC_SEP.rsplit(" ", 1)[0] + "\n" + DOC_ROW + "\n",  # five dash columns
])
def test_header_without_usable_separator_is_partial_without_guessed_members(text):
    assert _summarize(text) == {"state": "partial", "members": [], "missing_fields": ["table", "members"]}


def test_crlf_ansi_abbreviated_echo_and_trailing_prompt_are_framing_only():
    text = (DOC_BLOCK.replace("show mlag interfaces", "show mlag int")
            .replace("active-full", "\x1b[1mactive-full\x1b[0m").replace("\n", "\r\n")
            + "\x1b[Ks1-leaf4(config)#")
    assert _summarize(text) == {"state": "measured", "members": [DOC_MEMBER], "missing_fields": []}


def test_next_command_echo_ends_the_table():
    text = DOC_BLOCK + "s1-leaf4(config)#show version\nArista vEOS-lab\n"
    assert _summarize(text) == {"state": "measured", "members": [DOC_MEMBER], "missing_fields": []}


# 122-N1, DERIVED: an id cell, cell separators and a description starting with "#" are a table row, never an echo.
HASH_ROW = _row("6", "#HOST3", "active-full", "Po6", "Po6", "up/up")
HASH_MEMBER = {"id": 6, "description": "#HOST3", "state": "active-full", "local_port": "Po6", "remote_port": "Po6",
               "local_status": "up", "remote_status": "up", "missing_fields": []}
NEXT_ROW = _row("7", "HOST4", "active-full", "Po7", "Po7", "up/up")
NEXT_MEMBER = _member(id=7, description="HOST4", local_port="Po7", remote_port="Po7")
FOLLOWING = [
    pytest.param((), (), id="last-row"),
    pytest.param((NEXT_ROW,), (NEXT_MEMBER,), id="followed-by-member-7"),
]


@pytest.mark.parametrize("rows, members", FOLLOWING)
def test_derived_hash_description_row_is_a_member_not_a_next_command_echo(rows, members):
    summary = _summarize(_table(DOC_ROW, HASH_ROW, *rows))
    assert summary == {"state": "measured", "missing_fields": [], "members": [DOC_MEMBER, HASH_MEMBER, *members]}


@pytest.mark.parametrize("rows, members", FOLLOWING)
def test_derived_hash_description_row_with_cut_status_cell_is_damaged_not_an_echo(rows, members):
    damaged = _row("6", "#HOST3", "active-full", "Po6", "Po6", "")
    summary = _summarize(_table(DOC_ROW, damaged, *rows))
    assert summary == {"state": "partial", "members": [DOC_MEMBER, *members], "missing_fields": ["members"]}
