"""Review 115-N1: a long non-blank line of an ExtremeXOS `show mlag ports` capture is never silently dropped.

Exactly four directly affected cases of `summarize_ports()` (real parser, no mocks):
1. REAL empty table + one DERIVED 1025-character data line -> partial, `members` missing (count 0 is not complete);
2. first official DOC ports view + one DERIVED long ragged row -> partial, both valid DOC rows kept;
3. unchanged REAL empty table -> measured empty;
4. unchanged first DOC ports view -> measured with its two rows.

Data labels:
* REAL    - tests/fixtures/real/exos/exosvm_33.6.1.14/mlag_ports.txt, unmodified RO capture of an EXOS-VM 33.6.1.14
            without MLAG (empty table, explicit footer count 0).  Not a live active MLAG, no hardware claim.
* DOC     - the first CLI block of ref/exos-mlag-official-doc.json (source not mutated): official ExtremeXOS 33.4.1
            User Guide MLAG example, fetched by HTTPS GET (200):
            https://documentation.extremenetworks.com/ExtremeXOS%20v33.4.1%20User%20Guide/content/documents/
            Switch_Operating_Systems/ExtremeXOS/User_Guide/example_of_mlag_configuration.shtml
            Baseline: ExtremeXOS 33.4.1 documentation example of a BD8800 only; not a measurement and not a
            qualification of any other release or model.  Sanitized to RFC 5737 addresses; only the `show mlag ports` view is used.
* DERIVED - one inserted line of 1025 `x` characters, made only to exercise the parser; neither documentation nor a
            measurement and no new CLI format.
"""
import hashlib
import re
from pathlib import Path

HERE = Path(__file__).parent
REAL_PORTS_PATH = HERE / "fixtures/real/exos/exosvm_33.6.1.14/mlag_ports.txt"
REAL_PORTS_SHA256 = "af858ac0f9b8c3f885de6d9530fed0e16d48b3de264289e625d4b06056e97f64"
REAL_PORTS = REAL_PORTS_PATH.read_text()

# DOC: ref/exos-mlag-official-doc.json selected_blocks[0], sanitized to RFC 5737 addresses (CRLF as published, no trailing newline).
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
DOC_PORTS = DOC_BLOCK[re.search(r"(?m)^[^\r\n]*# show mlag ports\r?$", DOC_BLOCK).start():]
DOC_MEMBERS = [
    {"id": 1, "local_port": "1:1", "local_link_state": "A", "remote_link": "Up", "peer_name": "rightBD8K",
     "peer_status": "Up", "local_fail_count": 0, "remote_fail_count": 0, "missing_fields": []},
    {"id": 2, "local_port": "1:2", "local_link_state": "A", "remote_link": "Up", "peer_name": "rightBD8K",
     "peer_status": "Up", "local_fail_count": 0, "remote_fail_count": 0, "missing_fields": []},
]

LONG = "x" * 1025  # DERIVED: one non-blank line longer than 1024 characters
SEP = "=" * 80 + " "
DOC_SEP = "=" * 73


def _ports(text, capture_state="ok"):
    from netops_helper import switch_mlag_exos
    return switch_mlag_exos.summarize_ports(text, capture_state)


def _sources_unchanged():
    assert hashlib.sha256(REAL_PORTS_PATH.read_bytes()).hexdigest() == REAL_PORTS_SHA256
    assert hashlib.sha256(DOC_BLOCK.encode()).hexdigest() == DOC_BLOCK_SHA256


def test_real_empty_table_with_1025_character_line_is_partial_not_complete():
    _sources_unchanged()
    pair = f"{SEP}\n{SEP}\n"
    assert REAL_PORTS.count(pair) == 1
    text = REAL_PORTS.replace(pair, f"{SEP}\n{LONG}\n{SEP}\n")
    assert len(LONG) == 1025 and "Number of Multi-switch Link Aggregation Groups  : 0\n" in text
    summary = _ports(text)
    assert summary == {"state": "partial", "configured_groups": 0, "members": [], "missing_fields": ["members"]}


def test_doc_ports_with_long_ragged_row_is_partial_and_keeps_both_valid_rows():
    _sources_unchanged()
    rows = DOC_PORTS[DOC_PORTS.index(DOC_SEP):]
    second = rows.index("2       1:2")
    text = DOC_PORTS.replace(rows, rows[:second] + LONG + "\r\n" + rows[second:])
    assert text.count(LONG) == 1 and text.count(DOC_SEP + "\r\n") == 2
    summary = _ports(text)
    assert summary == {"state": "partial", "configured_groups": 2, "members": DOC_MEMBERS,
                       "missing_fields": ["members"]}


def test_unchanged_real_empty_table_is_measured_empty():
    _sources_unchanged()
    assert _ports(REAL_PORTS) == {"state": "measured", "configured_groups": 0, "members": [], "missing_fields": []}


def test_unchanged_first_doc_ports_view_is_measured_with_its_two_rows():
    _sources_unchanged()
    assert _ports(DOC_PORTS) == {"state": "measured", "configured_groups": 2, "members": DOC_MEMBERS,
                                 "missing_fields": []}
