"""ExtremeXOS `show mlag peer` / `show mlag ports` structured summaries (ssh_read extreme_exos, key `mlag`).

Data labels:
* REAL    - tests/fixtures/real/exos/exosvm_33.6.1.14/{mlag_peer.txt,mlag_ports.txt}, unmodified RO captures of an
            EXOS-VM 33.6.1.14 without MLAG: the peer view prints only its 37-byte header, the ports view (1142 bytes)
            an empty table with the explicit footer count 0.  The x440g2-12p-10g4_33.7.1.6{,_2,_3} copies are the same
            empty output (inactive, not active cases).  x435-8p-4s_33.7.1.6 refuses both commands (rc 254): an
            unchanged known-unsupported capture, never zero peers.  No REAL capture is a live active MLAG and none is
            a hardware or family qualification.
* DOC     - the first CLI block of the official ExtremeXOS 33.4.1 User Guide MLAG example, fetched by HTTPS GET (200):
            https://documentation.extremenetworks.com/ExtremeXOS%20v33.4.1%20User%20Guide/content/documents/
            Switch_Operating_Systems/ExtremeXOS/User_Guide/example_of_mlag_configuration.shtml
            Baseline: ExtremeXOS 33.4.1 documentation example output of a BD8800 only; not a measurement and not a
            qualification of 33.6/33.7 or of any model family.  The block holds both views; it is split only at the
            explicit `show mlag peer` / `show mlag ports` command lines, labels kept as published; addresses sanitized to RFC 5737.  The
            peer names of the two views differ as published (leftBD8k / rightBD8K); they are separate views and are
            neither corrected nor correlated.  The second published block (damaged `FailId` header) is not used.
* DERIVED - explicit edits of REAL or DOC text (values, rows, counts, framing, damaged lines) made only to exercise
            the parser.  Neither documentation nor a measurement, and no new CLI format.
A summary is parsed data of one query; it is never a health, consistency, traffic or pairing verdict.
"""
import hashlib
import json
import re
from pathlib import Path

import pytest

HERE = Path(__file__).parent
REAL_DIR = HERE / "fixtures/real/exos/exosvm_33.6.1.14"
X435_DIR = HERE / "fixtures/real/exos/x435-8p-4s_33.7.1.6"
X440_DIRS = [HERE / f"fixtures/real/exos/x440g2-12p-10g4_33.7.1.6{suffix}" for suffix in ("", "_2", "_3")]
REAL_PEER = (REAL_DIR / "mlag_peer.txt").read_text()
REAL_PORTS = (REAL_DIR / "mlag_ports.txt").read_text()
REAL_PEER_SHA256 = "c8250ea74d07eac6e6ba100c1ac380e294cb26d40aee586d6496dff4582810da"
REAL_PORTS_SHA256 = "af858ac0f9b8c3f885de6d9530fed0e16d48b3de264289e625d4b06056e97f64"
X435_PEER = (X435_DIR / "mlag_peer.txt").read_text()
X435_PORTS = (X435_DIR / "mlag_ports.txt").read_text()

# DOC: first published CLI block, sanitized to RFC 5737 addresses (CRLF as published, no trailing newline).
DOC_BLOCK = (
    "BD-8810.5 # show mlag peer\r\n"
    "Multi-switch Link Aggregation Peers:\r\n"
    "MLAG Peer         : leftBD8k\r\n"
    "VLAN              : isc             Virtual Router    : VR-Default\r\n"
    "Local IP Address  : 192.0.2.2       Peer IP Address   : 192.0.2.1\r\n"
    "MLAG ports        : 2               Tx-Interval       : 1000 ms\r\n"
    "Checkpoint Status : Up              Peer Tx-Interval  : 1000 ms\r\n"
    "Rx-Hellos         : 184             Tx-Hellos         : 184\r\n"
    "Rx-Checkpoint Msgs: 12              Tx-Checkpoint Msgs: 12\r\n"
    "Rx-Hello Errors   : 0               Tx-Hello Errors   : 0\r\n"
    "Hello Timeouts    : 1               Checkpoint Errors : 0\r\n"
    "Up Time           : 0d:0h:0m:10s    Peer Conn.Failures: 1\r\n"
    "\r\n"
    "BD-8810.3 # show mlag ports\r\n"
    "Local  \r\n"
    "                                                            Local  Remote\r\n"
    "MLAG        Local   Link     Remote                 Peer    Fail   Fail\r\n"
    "Id          Port    State    Link    Peer           Status  Count  Count\r\n"
    "=========================================================================\r\n"
    "1       1:1   A        Up          rightBD8K        Up          0      0\r\n"
    "2       1:2   A        Up          rightBD8K        Up          0      0\r\n"
    "=========================================================================\r\n"
    "Local Link State: A - Active, D - Disabled, R - Ready, NP - Port not present\r\n"
    "Remote Link     : Up - One or more links are active on the remote switch,\r\n"
    "Down - No links are active on the remote switch,\r\n"
    "N/A - The peer has not communicated link state for this MLAG port\r\n"
    "Number of Multi-switch Link Aggregation Groups  : 2\r\n"
    "Convergence control                             : Fast"
)
DOC_BLOCK_SHA256 = "070525244f1483e0beb90a633f8efb6d13397ed907d69214ac36542eaaa0ad8d"
_PORTS_COMMAND = re.search(r"(?m)^[^\r\n]*# show mlag ports\r?$", DOC_BLOCK)
DOC_PEER, DOC_PORTS = DOC_BLOCK[:_PORTS_COMMAND.start()], DOC_BLOCK[_PORTS_COMMAND.start():]
DOC_PEER_LF = DOC_PEER.replace("\r\n", "\n")

DOC_PEER_ENTRY = {"name": "leftBD8k", "vlan": "isc", "virtual_router": "VR-Default", "local_address": "192.0.2.2",
                  "peer_address": "192.0.2.1", "configured_groups": 2, "checkpoint_status": "Up", "missing_fields": []}
DOC_MEMBERS = [
    {"id": 1, "local_port": "1:1", "local_link_state": "A", "remote_link": "Up", "peer_name": "rightBD8K",
     "peer_status": "Up", "local_fail_count": 0, "remote_fail_count": 0, "missing_fields": []},
    {"id": 2, "local_port": "1:2", "local_link_state": "A", "remote_link": "Up", "peer_name": "rightBD8K",
     "peer_status": "Up", "local_fail_count": 0, "remote_fail_count": 0, "missing_fields": []},
]
PEER_KEYS = {"name", "vlan", "virtual_router", "local_address", "peer_address", "configured_groups",
             "checkpoint_status", "missing_fields"}
MEMBER_KEYS = {"id", "local_port", "local_link_state", "remote_link", "peer_name", "peer_status",
               "local_fail_count", "remote_fail_count", "missing_fields"}
REAL_PEER_SUMMARY = {"state": "partial", "peers": [], "missing_fields": ["peer_details"]}
REAL_PORTS_SUMMARY = {"state": "measured", "configured_groups": 0, "members": [], "missing_fields": []}
UNPARSED_PORTS = {"state": "unparsed", "configured_groups": None, "members": [],
                  "missing_fields": ["table", "configured_groups", "members"]}


def _peer(text, capture_state="ok"):
    from netops_helper import switch_mlag_exos
    return switch_mlag_exos.summarize_peer(text, capture_state)


def _ports(text, capture_state="ok"):
    from netops_helper import switch_mlag_exos
    return switch_mlag_exos.summarize_ports(text, capture_state)


def _set_pair(text, label, value):
    """DERIVED: replace the value of one existing peer label (exact, once); the other pair of the line is kept."""
    pattern = re.compile(rf"(?m)(?<![\w-])({re.escape(label)}[ \t]*: )(\S+)")
    assert len(pattern.findall(text)) == 1, label
    return pattern.sub(lambda m: m.group(1) + value, text)


def _peer_block(text):
    """DERIVED: the lines of the one DOC peer block, from `MLAG Peer` to `Up Time`."""
    return text[text.index("MLAG Peer "):text.index("\n", text.index("Up Time")) + 1]


SEP = "=" * 80 + " "


def _row(*cells):
    """DERIVED: one member row in the column layout of the REAL header."""
    widths = (8, 8, 9, 8, 25, 8, 8)
    return "".join(f"{cell!s:<{width}}" for cell, width in zip(cells, widths)) + "".join(str(c) for c in cells[7:])


def _real_ports(rows, count="0"):
    """DERIVED: rows inserted between the two REAL separators and the REAL footer count replaced (or dropped)."""
    pair = f"{SEP}\n{SEP}\n"
    footer = "Number of Multi-switch Link Aggregation Groups  : 0\n"
    assert REAL_PORTS.count(pair) == 1 and REAL_PORTS.count(footer) == 1
    text = REAL_PORTS.replace(pair, f"{SEP}\n" + "".join(row + "\n" for row in rows) + f"{SEP}\n")
    return text.replace(footer, "" if count is None else f"Number of Multi-switch Link Aggregation Groups  : {count}\n")


R1 = _row(1, "1:1", "A", "Up", "peer-b", "Up", 0, 0)
R2 = _row(2, "1:2", "D", "N/A", "peer-b", "Down", 3, 0)
M1 = {"id": 1, "local_port": "1:1", "local_link_state": "A", "remote_link": "Up", "peer_name": "peer-b",
      "peer_status": "Up", "local_fail_count": 0, "remote_fail_count": 0, "missing_fields": []}
M2 = {"id": 2, "local_port": "1:2", "local_link_state": "D", "remote_link": "N/A", "peer_name": "peer-b",
      "peer_status": "Down", "local_fail_count": 3, "remote_fail_count": 0, "missing_fields": []}


# --- REAL captures ---
def test_real_captures_are_unchanged_and_indexed():
    assert hashlib.sha256((REAL_DIR / "mlag_peer.txt").read_bytes()).hexdigest() == REAL_PEER_SHA256
    assert hashlib.sha256((REAL_DIR / "mlag_ports.txt").read_bytes()).hexdigest() == REAL_PORTS_SHA256
    assert len(REAL_PEER.encode()) == 37 and len(REAL_PORTS.encode()) == 1142
    index = json.loads((REAL_DIR / "index.json").read_text())
    assert index["mlag_peer"] == {"command": "show mlag peer", "rc": 0, "lines": 1, "account": "netops-ro"}
    assert index["mlag_ports"] == {"command": "show mlag ports", "rc": 0, "lines": 18, "account": "netops-ro"}
    assert "ExtremeXOS version 33.6.1.14" in (REAL_DIR / "version.txt").read_text()
    for directory in X440_DIRS:  # the same empty output, not an active case
        assert (directory / "mlag_peer.txt").read_bytes() == REAL_PEER.encode()
        assert (directory / "mlag_ports.txt").read_bytes() == REAL_PORTS.encode()


def test_real_peer_header_alone_is_partial_not_zero_peers():
    summary = _peer(REAL_PEER)
    assert summary == REAL_PEER_SUMMARY
    assert summary["state"] != "measured" and not {"healthy", "health", "count", "peer_count"} & set(summary)


def test_real_ports_footer_zero_with_empty_table_is_measured_empty():
    summary = _ports(REAL_PORTS)
    assert summary == REAL_PORTS_SUMMARY
    assert summary["configured_groups"] == 0 and summary["configured_groups"] is not None
    assert not {"healthy", "health", "consistent", "isc_port"} & set(summary)


def test_real_x435_refusal_is_unparsed_never_zero():
    index = json.loads((X435_DIR / "index.json").read_text())
    assert index["mlag_peer"]["rc"] == 254 and index["mlag_ports"]["rc"] == 254
    assert "Unrecognized command" in X435_PEER and "Unrecognized command" in X435_PORTS
    assert _peer(X435_PEER) == {"state": "unparsed", "peers": [], "missing_fields": ["peer_details"]}
    assert _ports(X435_PORTS) == UNPARSED_PORTS
    assert _ports(X435_PORTS)["configured_groups"] is None


# --- DOC (official example output, not REAL) ---
def test_doc_block_is_the_sanitized_text_split_at_the_command_lines():
    assert hashlib.sha256(DOC_BLOCK.encode()).hexdigest() == DOC_BLOCK_SHA256 and len(DOC_BLOCK.encode()) == 1596
    assert DOC_PEER.startswith("BD-8810.5 # show mlag peer\r\n") and "show mlag ports" not in DOC_PEER
    assert DOC_PORTS.startswith("BD-8810.3 # show mlag ports\r\n") and "MLAG Peer " not in DOC_PORTS


def test_doc_peer_fields_are_read_exactly_from_two_pairs_per_line():
    summary = _peer(DOC_PEER)
    assert summary == {"state": "measured", "peers": [DOC_PEER_ENTRY], "missing_fields": []}
    assert set(summary["peers"][0]) == PEER_KEYS  # no ISC port, consistency or health is invented
    assert summary["peers"][0]["vlan"] == "isc" and summary["peers"][0]["checkpoint_status"] == "Up"


def test_doc_ports_two_rows_eight_columns():
    summary = _ports(DOC_PORTS)
    assert summary == {"state": "measured", "configured_groups": 2, "members": DOC_MEMBERS, "missing_fields": []}
    assert all(set(member) == MEMBER_KEYS for member in summary["members"])


# --- DERIVED peer ---
def test_derived_peer_second_pair_is_never_taken_into_the_first():
    text = _set_pair(DOC_PEER_LF, "Virtual Router", "")
    summary = _peer(text.replace("Virtual Router    : \n", "Virtual Router    :\n"))
    assert summary["peers"][0]["vlan"] == "isc" and summary["peers"][0]["virtual_router"] is None
    assert summary["missing_fields"] == ["peers[0].virtual_router"] and summary["state"] == "partial"
    narrow = DOC_PEER_LF.replace("VLAN              : isc             Virtual Router    : VR-Default",
                                 "VLAN : isc  Virtual Router : VR-Default")
    assert _peer(narrow) == _peer(DOC_PEER)


def test_derived_peer_missing_required_line_keeps_the_rest():
    text = DOC_PEER_LF.replace("Local IP Address  : 192.0.2.2       Peer IP Address   : 192.0.2.1\n", "")
    summary = _peer(text)
    assert summary["state"] == "partial"
    assert summary["peers"] == [{**DOC_PEER_ENTRY, "local_address": None, "peer_address": None,
                                 "missing_fields": ["local_address", "peer_address"]}]
    assert summary["missing_fields"] == ["peers[0].local_address", "peers[0].peer_address"]


def test_derived_peer_duplicate_required_label_is_ambiguous_not_first_or_last():
    text = DOC_PEER_LF.replace("Virtual Router    : VR-Default\n", "Virtual Router    : VR-Default\nVLAN              : isc2\n")
    summary = _peer(text)
    assert summary["peers"] == [{**DOC_PEER_ENTRY, "vlan": None, "missing_fields": ["vlan"]}]
    assert summary["missing_fields"] == ["peers[0].vlan"] and summary["state"] == "partial"


def test_derived_peer_blocks_are_separate_and_a_damaged_one_keeps_its_valid_fields():
    second = _peer_block(DOC_PEER_LF)
    for label, value in (("MLAG Peer", "peer-c"), ("VLAN", "isc-c"), ("Local IP Address", "198.51.100.2"),
                         ("Peer IP Address", "198.51.100.1"), ("MLAG ports", "3")):
        second = _set_pair(second, label, value)
    entry_c = {**DOC_PEER_ENTRY, "name": "peer-c", "vlan": "isc-c", "local_address": "198.51.100.2",
               "peer_address": "198.51.100.1", "configured_groups": 3}
    summary = _peer(DOC_PEER_LF + second)
    assert summary == {"state": "measured", "peers": [DOC_PEER_ENTRY, entry_c], "missing_fields": []}
    damaged = second.replace("Checkpoint Status : Up", "Checkpoint Status : Up\nCheckpoint Status : Down")
    summary = _peer(DOC_PEER_LF + damaged)
    assert summary["peers"] == [DOC_PEER_ENTRY, {**entry_c, "checkpoint_status": None,
                                                 "missing_fields": ["checkpoint_status"]}]
    assert summary["missing_fields"] == ["peers[1].checkpoint_status"] and summary["state"] == "partial"


def test_derived_peer_malformed_unknown_placeholder_and_redacted_values_are_missing():
    text = DOC_PEER_LF
    for label, value in (("MLAG ports", "-2"), ("Checkpoint Status", "N/A"), ("Peer IP Address", "0.0.0.0"),
                         ("MLAG Peer", "<REDACTED>"), ("VLAN", "unknown")):
        text = _set_pair(text, label, value)
    peer = _peer(text)["peers"][0]
    assert peer == {**DOC_PEER_ENTRY, "name": None, "vlan": None, "peer_address": None, "configured_groups": None,
                    "checkpoint_status": None,
                    "missing_fields": ["name", "vlan", "peer_address", "configured_groups", "checkpoint_status"]}
    assert _peer(_set_pair(DOC_PEER_LF, "MLAG ports", "0"))["peers"][0]["configured_groups"] == 0  # explicit 0


def test_derived_peer_management_fields_are_ignored():
    text = DOC_PEER_LF.replace("Rx-Hellos         : 184             Tx-Hellos         : 184\n",
                               "Authentication    : None            Brand New Field   : 7\n")
    assert _peer(text) == _peer(DOC_PEER)
    assert _peer(DOC_PEER_LF.replace("Up Time           : 0d:0h:0m:10s    Peer Conn.Failures: 1\n", "")) == _peer(DOC_PEER)


def test_derived_peer_field_outside_a_block_is_not_attributed():
    assert _peer("VLAN              : isc\n") == {"state": "partial", "peers": [], "missing_fields": ["peer_details"]}


@pytest.mark.parametrize("text", [
    "", "\n \n", "BD-8810.5 # ", "* X440G2.3 # show mlag peer\r\n* X440G2.3 # ", "% unknown\nnothing here: at all\n",
    None,
], ids=["empty", "blank", "prompt", "echo-prompt", "unknown", "non-string"])
def test_derived_peer_blank_prompt_or_unknown_is_unparsed(text):
    assert _peer(text) == {"state": "unparsed", "peers": [], "missing_fields": ["peer_details"]}


def test_derived_peer_crlf_echo_and_ansi_framing_give_the_same_summary():
    plain = DOC_PEER_LF.split("\n", 1)[1]  # without the command echo line
    ansi = plain.replace("MLAG Peer ", "\x1b[1mMLAG Peer\x1b[0m ").replace("Checkpoint", "\x1b[7mCheckpoint", 1)
    assert _peer(plain) == _peer(ansi) == _peer(DOC_PEER) == _peer(DOC_PEER + "BD-8810.5 # ")


@pytest.mark.parametrize("capture_state", ["partial", "truncated", "error", None])
def test_derived_peer_capture_state_is_never_measured_and_keeps_data(capture_state):
    assert _peer(DOC_PEER, capture_state) == {"state": "partial", "peers": [DOC_PEER_ENTRY], "missing_fields": ["capture"]}
    assert _peer(REAL_PEER, capture_state) == {"state": "partial", "peers": [],
                                               "missing_fields": ["peer_details", "capture"]}
    assert _peer("", capture_state)["state"] == "unparsed"


# --- DERIVED ports ---
def test_derived_ports_rows_are_reported_values_not_health():
    summary = _ports(_real_ports([R1, R2], "2"))
    assert summary == {"state": "measured", "configured_groups": 2, "members": [M1, M2], "missing_fields": []}
    assert summary["members"][1]["remote_link"] == "N/A"  # not verified, never Up
    assert summary["members"][0]["local_fail_count"] == 0 and summary["members"][0]["local_fail_count"] is not None
    assert all(set(member) == MEMBER_KEYS for member in summary["members"])


def test_derived_ports_other_reported_states_are_kept():
    row = _row(7, "2:1", "NP", "Virtual", "peer-b", "Up", 0, 12)
    member = _ports(_real_ports([row], "1"))["members"][0]
    assert (member["local_link_state"], member["remote_link"], member["remote_fail_count"]) == ("NP", "Virtual", 12)
    assert _ports(_real_ports([_row(8, "2:2", "R", "Down", "peer-b", "Down", 0, 0)], "1"))["state"] == "measured"


def test_derived_ports_unknown_and_malformed_cells_are_missing_and_keep_the_row():
    bad = _row("x", "1:3", "Q", "Bogus", "<REDACTED>", "n/a", "-1", "1e3")
    summary = _ports(_real_ports([R1, bad], "2"))
    assert summary["members"][0] == M1
    assert summary["members"][1] == {
        "id": None, "local_port": "1:3", "local_link_state": None, "remote_link": None, "peer_name": None,
        "peer_status": None, "local_fail_count": None, "remote_fail_count": None,
        "missing_fields": ["id", "local_link_state", "remote_link", "peer_name", "peer_status", "local_fail_count",
                           "remote_fail_count"]}
    assert summary["state"] == "partial" and summary["configured_groups"] == 2
    assert summary["missing_fields"] == [f"members[1].{key}" for key in summary["members"][1]["missing_fields"]]


@pytest.mark.parametrize("row", [
    _row(3, "1:3", "A", "Up", "peer-b", "Up", 0),
    _row(3, "1:3", "A", "Up", '"peer b"', "Up", 0, 0),
    "3       1:3     A        Up       peer-b                   Up      0       0       extra",
], ids=["short", "quoted-name", "long"])
def test_derived_ports_ragged_row_is_partial_and_valid_rows_are_kept(row):
    summary = _ports(_real_ports([R1, row, R2], "3"))
    assert summary == {"state": "partial", "configured_groups": 3, "members": [M1, M2], "missing_fields": ["members"]}


@pytest.mark.parametrize("count, expected", [("3", 3), ("0", 0), ("1", 1)])
def test_derived_ports_count_mismatch_is_partial_and_keeps_both(count, expected):
    summary = _ports(_real_ports([R1, R2], count))
    assert summary == {"state": "partial", "configured_groups": expected, "members": [M1, M2],
                       "missing_fields": ["members"]}


@pytest.mark.parametrize("count", [None, "x", "-1", "<REDACTED>", "", "two"])
def test_derived_ports_missing_or_malformed_count_is_not_derived_from_rows(count):
    summary = _ports(_real_ports([R1, R2], count))
    assert summary == {"state": "partial", "configured_groups": None, "members": [M1, M2],
                       "missing_fields": ["configured_groups", "members"]}


def test_derived_ports_duplicate_count_is_ambiguous():
    text = _real_ports([R1, R2], "2").replace("Convergence control",
                                               "Number of Multi-switch Link Aggregation Groups  : 2\nConvergence control")
    assert _ports(text)["configured_groups"] is None and _ports(text)["state"] == "partial"


def test_derived_ports_duplicate_member_id_is_partial_and_keeps_rows():
    twin = _row(1, "1:3", "A", "Up", "peer-b", "Up", 0, 0)
    summary = _ports(_real_ports([R1, twin], "2"))
    assert summary["members"] == [{**M1, "id": None, "missing_fields": ["id"]},
                                  {**M1, "id": None, "local_port": "1:3", "missing_fields": ["id"]}]
    assert summary["missing_fields"] == ["members", "members[0].id", "members[1].id"]
    assert summary["state"] == "partial" and summary["configured_groups"] == 2


def test_derived_ports_header_only_is_partial():
    header = REAL_PORTS[:REAL_PORTS.index(SEP)]
    assert _ports(header) == {"state": "partial", "configured_groups": None, "members": [],
                              "missing_fields": ["table", "configured_groups", "members"]}


def test_derived_ports_cut_table_keeps_rows_and_never_reads_legend_or_footer_as_members():
    head = REAL_PORTS[:REAL_PORTS.index(SEP)] + f"{SEP}\n{R1}\n{R2}\n"
    assert _ports(head, "truncated") == {"state": "partial", "configured_groups": None, "members": [M1, M2],
                                         "missing_fields": ["table", "configured_groups", "members", "capture"]}
    unclosed = _real_ports([R1, R2], "2").replace(f"{R2}\n{SEP}\n", f"{R2}\n", 1)
    assert _ports(unclosed) == {"state": "partial", "configured_groups": 2, "members": [M1, M2],
                                "missing_fields": ["table", "members"]}


def test_derived_ports_management_footer_does_not_change_the_summary():
    text = REAL_PORTS.replace("Conserve Access Lists", "Fast").replace("30 seconds", "0 seconds")
    text = re.sub(r"(?m)^Reload .*\n", "", text)
    assert text != REAL_PORTS and _ports(text) == REAL_PORTS_SUMMARY


def test_derived_ports_crlf_echo_and_ansi_framing_give_the_same_summary():
    framed = "* X440G2.3 # show mlag ports\r\n" + REAL_PORTS.replace("\n", "\r\n").replace(
        "Number of", "\x1b[1mNumber of", 1) + "* X440G2.3 # "
    assert _ports(framed) == REAL_PORTS_SUMMARY
    rows = _real_ports([R1, R2], "2")
    assert _ports("X440G2.3 # show mlag ports\n" + rows.replace(R1, f"\x1b[0m{R1}\x1b[0m")) == _ports(rows)
    assert _ports(DOC_PORTS.replace("\r\n", "\n").split("\n", 1)[1]) == _ports(DOC_PORTS)


@pytest.mark.parametrize("text", [
    "", "\n \n", "X440G2.3 # ", "* X440G2.3 # show mlag ports\n* X440G2.3 # ",
    "% unknown\nnothing here: at all\n", REAL_PORTS[REAL_PORTS.index("Local Link State"):].replace(
        "Number of Multi-switch Link Aggregation Groups  : 0\n", ""), None,
], ids=["empty", "blank", "prompt", "echo-prompt", "unknown", "legend-only", "non-string"])
def test_derived_ports_blank_prompt_or_unknown_is_unparsed(text):
    assert _ports(text) == UNPARSED_PORTS


@pytest.mark.parametrize("capture_state", ["partial", "truncated", "error", None])
def test_derived_ports_capture_state_is_never_measured_and_keeps_data(capture_state):
    assert _ports(REAL_PORTS, capture_state) == {"state": "partial", "configured_groups": 0, "members": [],
                                                 "missing_fields": ["capture"]}
    assert _ports(DOC_PORTS, capture_state)["members"] == DOC_MEMBERS
    assert _ports("", capture_state)["state"] == "unparsed"


def test_payload_only_for_exos_mlag_peer_and_ports():
    from netops_helper import switch_mlag_exos
    assert switch_mlag_exos.payload("extreme_exos", "mlag_peer", DOC_PEER, "ok") == {"mlag": _peer(DOC_PEER)}
    assert switch_mlag_exos.payload("extreme_exos", "mlag_ports", REAL_PORTS, "ok") == {"mlag": REAL_PORTS_SUMMARY}
    for platform, query in (("extreme_exos", "lacp"), ("extreme_exos", "version"), ("arista_eos", "mlag_detail"),
                            ("arista_eos", "mlag_peer"), ("cisco_nxos", "mlag_ports"), ("fortinet", "mlag_ports")):
        assert switch_mlag_exos.payload(platform, query, REAL_PORTS, "ok") == {}


# --- public path: Proxy.request -> TargetAuth.decode -> engine.ssh_read; fake physical SSH/audit only ---
EXOS_QUERIES = ("version", "mlag_peer", "mlag_ports", "temperature")


def _gateway(tmp_path, monkeypatch, outputs, platform="exos", queries=EXOS_QUERIES, rc=0,
             identity=REAL_DIR / "version.txt"):
    import test_proxy_contracts as contracts
    from netops_helper import engine
    module = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(module, tmp_path)
    section = contracts._section()
    section.update(ssh_platform=platform, device_types=["switch"], enabled_queries=list(queries), read_inventory={})
    section["egress"]["tcp_ports"].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, platform)))
    gateway = module.Proxy()
    calls = []

    def transport(auth, platform_name, command, **kwargs):
        calls.append(command)
        if command == "show version":
            return 0, identity.read_text()
        return rc, outputs[command]
    monkeypatch.setattr(engine, "_exec_read", transport)
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)
    engine._SSH_PAGE_CACHE.clear()
    return contracts, gateway, calls


def _ssh_read(contracts, gateway, index, platform="extreme_exos", **arguments):
    from netops_helper import engine
    from netops_helper.auth import TargetAuth
    forwarded = gateway.request(contracts._request(index, "ssh_read", {"target": "device-a", "platform": platform, **arguments}))
    assert forwarded is not None
    args = json.loads(forwarded)["params"]["arguments"]
    auth = TargetAuth.decode(args["target"], args["auth_context"])
    return engine.ssh_read(auth, args["platform"], args["query"], args.get("parameters"), args.get("offset", 0),
                           args.get("max_bytes", 48_000), args.get("content_sha256"))


def test_public_real_ports_fresh_and_cached_pages_share_the_whole_summary(tmp_path, monkeypatch):
    from netops_helper import engine
    raw = REAL_PORTS.encode()
    contracts, gateway, calls = _gateway(tmp_path, monkeypatch, {"show mlag ports": REAL_PORTS})
    first = _ssh_read(contracts, gateway, 1, query="mlag_ports", offset=0, max_bytes=1000)
    assert first["ok"] is True and not first["complete"] and first["pagination_source"] == "fresh", first
    assert first["mlag"] == REAL_PORTS_SUMMARY
    ssh_calls = len(calls)
    assert calls.count("show mlag ports") == 1
    second = _ssh_read(contracts, gateway, 2, query="mlag_ports", offset=first["next_offset"], max_bytes=1000,
                       content_sha256=first["content_sha256"])
    assert second["ok"] is True and second["complete"] and second["pagination_source"] == "cached", second
    assert second["next_offset"] is None and len(calls) == ssh_calls  # no new SSH for the cached page
    assert SEP not in second["untrusted_device_output"] and "Number of" not in second["untrusted_device_output"]
    assert second["mlag"] == first["mlag"] == REAL_PORTS_SUMMARY  # from the whole stored text, not the page
    assert first["untrusted_device_output"] + second["untrusted_device_output"] == REAL_PORTS
    assert (first["offset"], first["returned_bytes"], second["offset"], second["returned_bytes"]) == (0, 974, 974, 168)
    for page in (first, second):
        assert page["content_sha256"] == hashlib.sha256(raw).hexdigest() == REAL_PORTS_SHA256
        assert page["total_bytes"] == len(raw) == 1142 and page["rc"] == 0
        assert page["untrusted_device_output"] == raw[page["offset"]:page["offset"] + page["returned_bytes"]].decode()
        assert page["transport"] == engine._SSH_TRANSPORTS["extreme_exos"]


def test_public_real_peer_header_is_partial_on_one_fresh_page(tmp_path, monkeypatch):
    contracts, gateway, calls = _gateway(tmp_path, monkeypatch, {"show mlag peer": REAL_PEER})
    answer = _ssh_read(contracts, gateway, 1, query="mlag_peer", offset=0)
    assert answer["ok"] is True and answer["complete"] and answer["next_offset"] is None
    assert answer["pagination_source"] == "fresh" and answer["untrusted_device_output"] == REAL_PEER
    assert answer["content_sha256"] == REAL_PEER_SHA256 and answer["total_bytes"] == 37
    assert answer["mlag"] == REAL_PEER_SUMMARY and calls.count("show mlag peer") == 1


def test_public_nonzero_rc_downgrades_and_keeps_data(tmp_path, monkeypatch):
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show mlag ports": REAL_PORTS}, rc=1)
    answer = _ssh_read(contracts, gateway, 1, query="mlag_ports", offset=0)
    assert answer["ok"] is True and answer["mlag"] == {"state": "partial", "configured_groups": 0, "members": [],
                                                       "missing_fields": ["capture"]}


def test_public_forbidden_sentinel_goes_through_the_real_redaction(tmp_path, monkeypatch):
    sentinel = "ssh-password"  # the device secret of the test inventory; DERIVED lines, not a measurement
    ports = _real_ports([_row(1, "1:1", "A", "Up", sentinel, "Up", 0, 0), R2], "2")
    peer = _set_pair(DOC_PEER_LF, "MLAG Peer", sentinel)
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show mlag ports": ports, "show mlag peer": peer})
    answer = _ssh_read(contracts, gateway, 1, query="mlag_ports", offset=0)
    assert answer["ok"] is True
    assert sentinel not in json.dumps(answer) and "redacted" in answer["untrusted_device_output"].lower()
    assert answer["mlag"]["members"] == [{**M1, "peer_name": None, "missing_fields": ["peer_name"]}, M2]
    assert answer["mlag"]["state"] == "partial" and answer["mlag"]["missing_fields"] == ["members[0].peer_name"]
    answer = _ssh_read(contracts, gateway, 2, query="mlag_peer", offset=0)
    assert answer["ok"] is True and sentinel not in json.dumps(answer)
    assert answer["mlag"]["peers"] == [{**DOC_PEER_ENTRY, "name": None, "missing_fields": ["name"]}]


def test_public_x435_refusal_keeps_the_original_gate_and_has_no_mlag(tmp_path, monkeypatch):
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show mlag peer": X435_PEER, "show mlag ports": X435_PORTS},
                                     rc=254, identity=X435_DIR / "version.txt")
    for index, query in enumerate(("mlag_peer", "mlag_ports"), 1):
        answer = _ssh_read(contracts, gateway, index, query=query, offset=0)
        assert answer["ok"] is False and answer["error_code"] == "device_cli_error", answer
        assert "mlag" not in answer


def test_public_other_query_and_other_platform_get_no_exos_mlag(tmp_path, monkeypatch):
    from netops_helper import switch_mlag_eos
    temperature = (REAL_DIR / "temperature.txt").read_text()
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show temperature": temperature})
    answer = _ssh_read(contracts, gateway, 1, query="temperature", offset=0)
    assert answer["ok"] and "mlag" not in answer
    eos = (HERE / "fixtures/real/arista_eos/ceos_4.36.1F/mlag_detail.txt").read_text()
    (tmp_path / "eos").mkdir()
    contracts, gateway, _ = _gateway(tmp_path / "eos", monkeypatch, {"show mlag detail": eos}, platform="arista_eos",
                                     queries=("version", "mlag_detail"),
                                     identity=HERE / "fixtures/identity/arista_eos.txt")
    answer = _ssh_read(contracts, gateway, 2, platform="arista_eos", query="mlag_detail", offset=0)
    assert answer["ok"] and answer["mlag"] == switch_mlag_eos.summarize(eos)
    assert not {"peers", "configured_groups"} & set(answer["mlag"])


# --- task 136-r2: _PAIR and _PAIR_SPLIT without overlapping backtracking ---
# The 93bc99c spellings, frozen independently of the production constants: same results, quadratic backtracking
# (_PAIR in match/fullmatch/search; _PAIR_SPLIT in split/search over long blank runs, measured on PC-Radek).
_PAIR_93BC99C = re.compile(r"^[ \t]*([A-Za-z][A-Za-z0-9 .()/_-]*?)[ \t]*:[ \t]*(.*?)[ \t]*$")
_PAIR_SPLIT_93BC99C = re.compile(
    r"[ \t]{2,}(?=[A-Za-z](?:[A-Za-z0-9.()/_-]|[ \t](?![ \t]))*?[ \t]*:(?:[ \t]|$))")
EXOS_REAL_TEXTS = sorted(path for directory in ("exos", "extreme_exos")
                         for path in (HERE / "fixtures/real" / directory).rglob("*.txt"))


def _same_pair(text):
    from netops_helper import switch_mlag_exos
    for operation in ("match", "fullmatch", "search"):
        new = getattr(switch_mlag_exos._PAIR, operation)(text)
        old = getattr(_PAIR_93BC99C, operation)(text)
        assert (new is None) == (old is None), (operation, text)
        if new is not None:
            assert (new.span(), new.groups(), new.span(1), new.span(2)) == (
                old.span(), old.groups(), old.span(1), old.span(2)), (operation, text)


def _same_split(text):
    from netops_helper import switch_mlag_exos
    current, previous = switch_mlag_exos._PAIR_SPLIT, _PAIR_SPLIT_93BC99C
    assert current.split(text) == previous.split(text), text
    assert [m.span() for m in current.finditer(text)] == [m.span() for m in previous.finditer(text)], text
    for operation in ("match", "fullmatch", "search"):
        new, old = getattr(current, operation)(text), getattr(previous, operation)(text)
        assert (None if new is None else new.span()) == (None if old is None else old.span()), (operation, text)


def _pairs_93bc99c(line):
    found = []
    for segment in _PAIR_SPLIT_93BC99C.split(line):
        pair = _PAIR_93BC99C.match(segment)
        if pair is not None:
            found.append((" ".join(pair.group(1).lower().split()), pair.group(2)))
    return found


def test_pair_regexes_are_equivalent_on_every_real_exos_line_and_derived_text():
    from netops_helper import switch_mlag_exos
    real = EXOS_REAL_TEXTS
    assert REAL_DIR / "mlag_peer.txt" in real and REAL_DIR / "mlag_ports.txt" in real
    assert sum(path.name.startswith("mlag_") for path in real) == 10
    texts = [path.read_text(errors="replace") for path in real] + [DOC_BLOCK, DOC_PEER, DOC_PEER_LF, DOC_PORTS]
    lines = segments = pairs = 0
    for text in texts:
        # every line as summarize_peer() sees it, and the LF/CRLF/whole-text forms as well
        for line in switch_mlag_exos._lines(text, "peer") + text.split("\n") + text.splitlines(keepends=True):
            _same_split(line)
            for segment in _PAIR_SPLIT_93BC99C.split(line):
                _same_pair(segment)
                segments += 1
            found = switch_mlag_exos._pairs(line)
            assert found == _pairs_93bc99c(line), line
            lines += 1
            pairs += len(found)
    # the published two-pairs-per-line peer block is still split into exactly the published pairs
    # (a CR is value text for both spellings; summarize_peer() strips the CRLF framing before _pairs())
    assert switch_mlag_exos._pairs("Rx-Checkpoint Msgs: 12              Tx-Checkpoint Msgs: 12\r") == [
        ("rx-checkpoint msgs", "12"), ("tx-checkpoint msgs", "12\r")]
    assert switch_mlag_exos._pairs("Up Time           : 0d:0h:0m:10s    Peer Conn.Failures: 1") == [
        ("up time", "0d:0h:0m:10s"), ("peer conn.failures", "1")]
    print(f"pair_equivalence exos_files={len(real)} lines={lines} segments={segments} pairs={pairs} differences=0")


def test_pair_regexes_are_equivalent_on_all_short_strings():
    from itertools import product
    alphabet = ("a", "1", " ", "\t", ":", ".", "-", "!", "\n", "\r")
    count = 0
    for length in range(6):
        for letters in product(alphabet, repeat=length):
            tail = "".join(letters)
            for text in (tail, "a" + tail, "VLAN  : isc" + tail, "a :  b" + tail):
                _same_pair(text)
                _same_split(text)
                count += 1
    print(f"pair_exhaustive strings={count} differences=0")


@pytest.mark.parametrize("name, text", [
    ("_PAIR", "    key " + " " * 19991 + "!"), ("_PAIR", "ge-0/0/0 Current " + " " * 19982 + "!"),
    ("_PAIR", "k:a" + " " * 19996 + "!"), ("_PAIR", "Peer IP Address :" + " \t" * 10000 + "x"),
    ("_PAIR_SPLIT", " " * 19999 + "!"), ("_PAIR_SPLIT", "a" + "\t" * 19998 + "!"),
    ("_PAIR_SPLIT", "VLAN  : x" + " " * 9995 + "Peer" + " " * 9995),
], ids=["pair-label-spaces", "pair-label-after-words", "pair-value-spaces", "pair-value-mixed-blanks",
        "split-spaces", "split-tabs-after-word", "split-label-without-colon"])
def test_pair_regexes_are_linear_on_long_blank_runs(name, text):
    import signal
    import time
    from netops_helper import switch_mlag_exos
    pattern = getattr(switch_mlag_exos, name)

    def expired(*_):
        raise AssertionError(f"switch_mlag_exos.{name} exceeded 0.5s")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 0.5)
    try:
        started = time.perf_counter()
        for operation in ("match", "fullmatch", "search", "split"):
            getattr(pattern, operation)(text)
        if name == "_PAIR_SPLIT":
            switch_mlag_exos._pairs(text)  # production path: split, then _PAIR.match on each segment
        elapsed = time.perf_counter() - started
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    # 93bc99c, 20000 characters (PC-Radek): _PAIR 0.4-1.4 s per match, _PAIR_SPLIT 1.6-2.8 s per split
    assert elapsed < 0.05, elapsed
