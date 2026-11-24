"""NX-OS `show vpc brief` structured summary (ssh_read cisco_nxos/vpc_status, key `vpc`).

Data labels:
* REAL  - tests/fixtures/real/cisco_nxos/nexus9300v_9.3.12/vpc_status.txt, an unmodified RO capture
          (N9K-C9300v, NX-OS 9.3(12)): domain 29, peer link not configured, consistency failed, 0 vPCs.
* DOC   - the `show vpc bri` example of Cisco TechNote 218333 "Understand and Configure Nexus 9000 vPC with
          Best Practices" (Leaf-3, secondary). A documented example, not a live measurement; it says nothing
          about other firmware or hardware.
* DERIVED - explicit edits of REAL or DOC text made only to exercise framing, malformed rows and scope.
The summary is device data read for display; it is never a global health verdict and no device text is executed.
"""
import hashlib
import json
import re
from pathlib import Path

import pytest

HERE = Path(__file__).parent
REAL_DIR = HERE / "fixtures/real/cisco_nxos/nexus9300v_9.3.12"
REAL = (REAL_DIR / "vpc_status.txt").read_text()

# DOC: exact block from Cisco TechNote 218333 (HTTP 200, cisco.com); last line has no newline.
DOC_LINES = [
    "Leaf-3(config-if)# show vpc bri",
    "Legend:",
    "(*) - local vPC is down, forwarding via vPC peer-link",
    "vPC domain id : 1",
    "Peer status : peer adjacency formed ok",
    "vPC keep-alive status : peer is alive",
    "Configuration consistency status : success",
    "Per-vlan consistency status : success",
    "Type-2 consistency status : success",
    "vPC role : secondary",
    "Number of vPCs configured : 1",
    "Peer Gateway : Enabled",
    "Dual-active excluded VLANs :",
    "Graceful Consistency Check : Enabled",
    "Auto-recovery status : Disabled",
    "Delay-restore status : Timer is off.(timeout = 30s)",
    "Delay-restore SVI status : Timer is off.(timeout = 10s)",
    "Delay-restore Orphan-port status : Timer is off.(timeout = 0s)",
    "Operational Layer3 Peer-router : Disabled",
    "Virtual-peerlink mode : Disabled",
    "vPC Peer-link status",
    "—" * 33,
    "id Port Status Active vlans",
    "-- ---- ------ -------------------------------------------------",
    "1 Po10 up 1-2,10",
    "\u00a0",  # no-break space, as published
    "vPC status",
    "-" * 76,
    "Id Port Status Consistency Reason Active vlans",
    "-" * 15,
    "20 Po20 up success success 1-2,10",
    "\u00a0",  # no-break space, as published
    'Please check "show vpc consistency-parameters vpc <vpc-num>" for the consistency reason of down vpc '
    "and for type-2 consistency reasons for any vpc.",
]
DOC = "\n".join(DOC_LINES)
DOC_SHA256 = "cecd60499ae38b41a99ccb86c2440824121311d4c12b51b9e120fca3f429c45a"  # ref/vpc-documented-secondary.txt

FIELDS = {"state", "domain_id", "peer_status", "keepalive_status", "role", "consistency_status",
          "consistency_reason", "configured_vpcs", "peer_links", "members", "missing_fields"}
DOC_PEER_LINK = {"id": 1, "port": "Po10", "status": "up", "active_vlans": "1-2,10"}
DOC_MEMBER = {"id": 20, "port": "Po20", "status": "up", "consistency": "success", "reason": "success",
              "active_vlans": "1-2,10"}


def _summarize(text, capture_state="ok"):
    from netops_helper import switch_vpc
    return switch_vpc.summarize(text, capture_state)


def _replace(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


# --- REAL and DOC captures ---
def test_real_capture_is_unchanged_and_indexed():
    index = json.loads((REAL_DIR / "index.json").read_text())["vpc_status"]
    assert index == {"command": "show vpc brief", "rc": 0, "lines": 21, "account": "netops-ro"}
    version = (REAL_DIR / "version.txt").read_text()
    assert "NXOS: version 9.3(12)" in version and "C9300v" in version
    assert hashlib.sha256(DOC.encode("utf-8")).hexdigest() == DOC_SHA256


def test_real_inactive_domain_is_a_recognized_negative_state():
    summary = _summarize(REAL)
    assert set(summary) == FIELDS
    assert summary == {
        "state": "measured", "domain_id": 29, "peer_status": "peer link not configured",
        "keepalive_status": "Suspended (Destination IP not reachable)", "role": "none established",
        "consistency_status": "failed", "consistency_reason": "vPC peer-link does not exist",
        "configured_vpcs": 0, "peer_links": [], "members": [], "missing_fields": [],
    }
    # Documented zero is 0 (not None); no health, traffic or topology field is invented.
    assert summary["configured_vpcs"] == 0 and summary["configured_vpcs"] is not None
    assert not {"healthy", "health", "forwarding", "traffic"} & set(summary)


def test_doc_active_secondary_example():
    summary = _summarize(DOC)
    assert summary == {
        "state": "measured", "domain_id": 1, "peer_status": "peer adjacency formed ok",
        "keepalive_status": "peer is alive", "role": "secondary", "consistency_status": "success",
        "consistency_reason": None, "configured_vpcs": 1,
        "peer_links": [DOC_PEER_LINK], "members": [DOC_MEMBER], "missing_fields": [],
    }


# --- DERIVED framing ---
@pytest.mark.parametrize("framed", [
    DOC.replace("\n", "\r\n"),
    "\x1b[?2004h" + DOC.replace("\n", "\r\n") + "\r\nLeaf-3(config-if)# ",
    "show vpc brief\n" + DOC.split("\n", 1)[1] + "\nLeaf-3# \n",
    "Leaf-3# show vpc brief\r\n" + "\x1b[0m" + DOC.split("\n", 1)[1] + "\r\nLeaf-3#",
], ids=["crlf", "ansi-crlf-prompt", "bare-echo", "prompt-echo"])
def test_derived_framing_gives_the_doc_summary(framed):
    assert _summarize(framed) == _summarize(DOC)


@pytest.mark.parametrize("framed", [REAL.replace("\n", "\r\n"), "n9k# show vpc brief\r\n" + REAL + "n9k# "])
def test_derived_framing_of_real_capture(framed):
    assert _summarize(framed) == _summarize(REAL)


def test_derived_padded_column_layout():
    text = DOC
    text = _replace(text, "id Port Status Active vlans", "id    Port   Status Active vlans")
    text = _replace(text, "1 Po10 up 1-2,10", "1     Po10   up     1-2,10")
    text = _replace(text, "Id Port Status Consistency Reason Active vlans",
                    "Id    Port          Status Consistency Reason                Active vlans")
    text = _replace(text, "20 Po20 up success success 1-2,10",
                    "20    Po20          up     success     success               1-2,10")
    text = _replace(text, "vPC domain id : 1", "vPC domain id                     : 1  ")
    assert _summarize(text) == _summarize(DOC)


# --- DERIVED missing fields, malformed rows, scope ---
def test_derived_multiword_reason_and_dash_vlans_are_kept_verbatim():
    text = _replace(DOC, "20 Po20 up success success 1-2,10",
                    "20 Po20 down* success Consistency Check Not Performed -")
    summary = _summarize(text)
    assert summary["state"] == "measured"
    assert summary["members"] == [{"id": 20, "port": "Po20", "status": "down*", "consistency": "success",
                                   "reason": "Consistency Check Not Performed", "active_vlans": "-"}]


@pytest.mark.parametrize("line, field", [
    ("vPC domain id : 1", "domain_id"),
    ("Peer status : peer adjacency formed ok", "peer_status"),
    ("vPC keep-alive status : peer is alive", "keepalive_status"),
    ("vPC role : secondary", "role"),
    ("Configuration consistency status : success", "consistency_status"),
])
def test_derived_omitted_field_is_none_and_missing(line, field):
    summary = _summarize(_replace(DOC, line + "\n", ""))
    assert summary["state"] == "partial" and summary[field] is None
    assert field in summary["missing_fields"]
    assert summary["peer_links"] == [DOC_PEER_LINK] and summary["members"] == [DOC_MEMBER]


def test_derived_omitted_count_is_none_not_zero():
    summary = _summarize(_replace(DOC, "Number of vPCs configured : 1\n", ""))
    assert summary["state"] == "partial" and summary["configured_vpcs"] is None
    assert "configured_vpcs" in summary["missing_fields"] and summary["members"] == [DOC_MEMBER]


def test_derived_non_integer_domain_is_not_guessed():
    summary = _summarize(_replace(DOC, "vPC domain id : 1", "vPC domain id : one"))
    assert summary["domain_id"] is None and "domain_id" in summary["missing_fields"]
    assert summary["state"] == "partial" and summary["role"] == "secondary"


def test_derived_failed_consistency_without_reason_is_missing():
    summary = _summarize(_replace(DOC, "Configuration consistency status : success",
                                  "Configuration consistency status : failed"))
    assert summary["consistency_status"] == "failed" and summary["consistency_reason"] is None
    assert summary["state"] == "partial" and "consistency_reason" in summary["missing_fields"]


def test_derived_status_labels_are_scoped_not_substrings():
    text = _replace(DOC, "Configuration consistency status : success",
                    "Status : down\nConfiguration consistency status : success\nvPC status : bogus")
    text = _replace(text, "Per-vlan consistency status : success", "Per-vlan consistency status : failed")
    text = _replace(text, "Type-2 consistency status : success", "Type-2 consistency status : failed\n"
                    "Type-2 inconsistency reason : SVI type-2 configuration incompatible")
    summary = _summarize(text)
    assert summary["consistency_status"] == "success" and summary["consistency_reason"] is None
    assert summary["peer_status"] == "peer adjacency formed ok" and summary["keepalive_status"] == "peer is alive"
    assert summary["state"] == "measured", summary


def test_derived_duplicate_label_is_ambiguous_not_overwritten():
    text = _replace(DOC, "Peer status : peer adjacency formed ok",
                    "Peer status : peer adjacency formed ok\nPeer status : peer link is down")
    summary = _summarize(text)
    assert summary["peer_status"] is None and "peer_status" in summary["missing_fields"]
    assert summary["state"] == "partial" and summary["members"] == [DOC_MEMBER]


def test_derived_malformed_member_row_keeps_other_fields():
    summary = _summarize(_replace(DOC, "20 Po20 up success success 1-2,10", "20 Po20"))
    assert summary["state"] == "partial" and summary["members"] == []
    assert summary["missing_fields"] == ["members"]
    assert summary["peer_links"] == [DOC_PEER_LINK] and summary["domain_id"] == 1 and summary["role"] == "secondary"


def test_derived_malformed_peer_link_row_does_not_guess_a_port():
    summary = _summarize(_replace(DOC, "1 Po10 up 1-2,10", "1 up"))
    assert summary["peer_links"] == [] and summary["missing_fields"] == ["peer_links"]
    assert summary["members"] == [DOC_MEMBER] and summary["state"] == "partial"


def test_derived_unknown_row_under_table_is_partial():
    text = _replace(DOC, "20 Po20 up success success 1-2,10",
                    "20 Po20 up success success 1-2,10\nsomething unexpected here")
    summary = _summarize(text)
    assert summary["state"] == "partial" and summary["members"] == [DOC_MEMBER]
    assert "members" in summary["missing_fields"]


def test_derived_member_count_mismatch_is_partial():
    summary = _summarize(_replace(DOC, "Number of vPCs configured : 1", "Number of vPCs configured : 2"))
    assert summary["configured_vpcs"] == 2 and summary["members"] == [DOC_MEMBER]
    assert summary["state"] == "partial" and "members" in summary["missing_fields"]


def test_derived_omitted_tables_without_explicit_absence_are_partial():
    head = DOC.split("\nvPC Peer-link status", 1)[0]
    summary = _summarize(head)
    assert summary["state"] == "partial"
    assert summary["peer_links"] is None and summary["members"] is None
    assert summary["missing_fields"] == ["peer_links", "members"]
    assert summary["domain_id"] == 1 and summary["configured_vpcs"] == 1


def test_derived_real_without_explicit_absence_is_partial():
    text = _replace(REAL, "peer link not configured", "peer adjacency formed ok")
    text = _replace(text, "Number of vPCs configured         : 0", "Number of vPCs configured         : 3")
    summary = _summarize(text)
    assert summary["state"] == "partial" and summary["peer_links"] is None and summary["members"] is None


def test_derived_unknown_line_in_metadata_is_partial():
    summary = _summarize(_replace(DOC, "Peer Gateway : Enabled", "Peer Gateway : Enabled\n!!! unexpected"))
    assert summary["state"] == "partial" and summary["missing_fields"] == ["unrecognized_lines"]
    assert summary["members"] == [DOC_MEMBER]


@pytest.mark.parametrize("text", [
    "", "   \n\r\n", "Leaf-3# ", "Leaf-3(config-if)# show vpc bri\nLeaf-3(config-if)# ",
    "Legend:\n(*) - local vPC is down, forwarding via vPC peer-link\n",
    "vPC Peer-link status\n----\nid Port Status Active vlans\n-- ---- ------ ------\n\nvPC status\n----\n"
    "Id Port Status Consistency Reason Active vlans\n----\n",
    "garbage line\nanother: line\n", "\x00\x01 binary \x1b[31m",
], ids=["empty", "blank", "prompt-only", "echo-prompt", "legend-only", "headers-only", "unknown", "binary"])
def test_derived_nothing_recognized_is_unparsed_not_healthy_empty(text):
    summary = _summarize(text)
    assert summary["state"] == "unparsed"
    assert summary["peer_links"] is None and summary["members"] is None
    assert summary["configured_vpcs"] is None and "configured_vpcs" in summary["missing_fields"]


@pytest.mark.parametrize("capture_state", ["truncated", "transport_error", "permission_denied", None])
def test_derived_capture_state_downgrades_but_keeps_data(capture_state):
    summary = _summarize(DOC, capture_state)
    assert summary["state"] == "partial" and summary["missing_fields"] == ["capture"]
    assert summary["members"] == [DOC_MEMBER] and summary["domain_id"] == 1
    real = _summarize(REAL, capture_state)
    assert real["state"] == "partial" and real["configured_vpcs"] == 0 and real["peer_links"] == []
    empty = _summarize("", capture_state)
    assert empty["state"] == "unparsed" and empty["missing_fields"][-1] == "capture"


# --- public path: Proxy.request -> TargetAuth.decode -> engine.ssh_read; fake physical SSH/audit only ---
IDENTITY = {"cisco_nxos": REAL_DIR / "version.txt", "arista_eos": HERE / "fixtures/identity/arista_eos.txt"}


def _gateway(tmp_path, monkeypatch, outputs, platform="cisco_nxos", queries=("version", "vpc_status", "vpc_role"), rc=0):
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
            return 0, IDENTITY[platform_name].read_text()
        return rc, outputs[command]
    monkeypatch.setattr(engine, "_exec_read", transport)
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)
    engine._SSH_PAGE_CACHE.clear()
    return contracts, gateway, calls


def _ssh_read(contracts, gateway, index, platform="cisco_nxos", **arguments):
    from netops_helper import engine
    from netops_helper.auth import TargetAuth
    forwarded = gateway.request(contracts._request(index, "ssh_read", {"target": "device-a", "platform": platform, **arguments}))
    assert forwarded is not None
    args = json.loads(forwarded)["params"]["arguments"]
    auth = TargetAuth.decode(args["target"], args["auth_context"])
    return engine.ssh_read(auth, args["platform"], args["query"], args.get("parameters"), args.get("offset", 0),
                           args.get("max_bytes", 48_000), args.get("content_sha256"))


def _assert_body_untouched(answer, text):
    from netops_helper import engine
    raw = text.encode("utf-8")
    assert answer["transport"] == engine._SSH_TRANSPORTS["cisco_nxos"]
    assert answer["content_sha256"] == hashlib.sha256(raw).hexdigest() and answer["total_bytes"] == len(raw)
    page = raw[answer["offset"]:answer["offset"] + answer["returned_bytes"]].decode("utf-8")
    assert answer["untrusted_device_output"] == page


@pytest.mark.parametrize("text, expected", [(REAL, lambda: _summarize(REAL)), (DOC, lambda: _summarize(DOC))],
                         ids=["real", "doc"])
def test_public_ssh_read_adds_vpc_and_keeps_body(tmp_path, monkeypatch, text, expected):
    contracts, gateway, calls = _gateway(tmp_path, monkeypatch, {"show vpc brief": text})
    answer = _ssh_read(contracts, gateway, 1, query="vpc_status", offset=0)
    assert answer["ok"] is True, answer
    assert answer["vpc"] == expected() and answer["vpc"]["state"] == "measured"
    assert answer["complete"] is True and answer["untrusted_device_output"] == text
    _assert_body_untouched(answer, text)
    assert answer["pagination_source"] == "fresh" and calls.count("show vpc brief") == 1


def test_public_ssh_read_fresh_and_cached_pages_share_the_whole_summary(tmp_path, monkeypatch):
    assert len(DOC.encode("utf-8")) > 1000  # DOC alone spans two 1000-byte pages; no repetition needed
    contracts, gateway, calls = _gateway(tmp_path, monkeypatch, {"show vpc brief": DOC})
    first = _ssh_read(contracts, gateway, 1, query="vpc_status", offset=0, max_bytes=1000)
    assert first["ok"] and not first["complete"] and first["pagination_source"] == "fresh"
    assert "20 Po20" not in first["untrusted_device_output"]  # members are on the second page only
    assert first["vpc"] == _summarize(DOC) and first["vpc"]["members"] == [DOC_MEMBER]
    ssh_calls = len(calls)
    second = _ssh_read(contracts, gateway, 2, query="vpc_status", offset=first["next_offset"], max_bytes=1000,
                       content_sha256=first["content_sha256"])
    assert second["ok"] and second["complete"] and second["pagination_source"] == "cached"
    assert len(calls) == ssh_calls and calls.count("show vpc brief") == 1  # no further SSH
    assert second["vpc"] == first["vpc"]
    assert second["content_sha256"] == first["content_sha256"]
    _assert_body_untouched(first, DOC)
    _assert_body_untouched(second, DOC)
    assert first["untrusted_device_output"] + second["untrusted_device_output"] == DOC


def test_public_ssh_read_nonzero_rc_downgrades_and_keeps_data(tmp_path, monkeypatch):
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show vpc brief": DOC}, rc=1)
    answer = _ssh_read(contracts, gateway, 1, query="vpc_status", offset=0)
    assert answer["ok"] is True and answer["status"] != "ok"
    assert answer["vpc"]["state"] == "partial" and answer["vpc"]["missing_fields"] == ["capture"]
    assert answer["vpc"]["members"] == [DOC_MEMBER] and answer["untrusted_device_output"] == DOC


def test_public_ssh_read_pager_tail_is_not_measured(tmp_path, monkeypatch):
    text = DOC.split("\nvPC status", 1)[0] + "\n --More-- "
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show vpc brief": text})
    answer = _ssh_read(contracts, gateway, 1, query="vpc_status", offset=0)
    assert answer["ok"] and answer["vpc"]["state"] == "partial"
    assert answer["vpc"]["peer_links"] == [DOC_PEER_LINK] and answer["vpc"]["members"] is None
    assert "capture" in answer["vpc"]["missing_fields"]


def test_public_other_queries_and_platforms_have_no_vpc(tmp_path, monkeypatch):
    role = "vPC Role status\n----------------------------------------------------\nvPC role : secondary\n"
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show vpc role": role})
    answer = _ssh_read(contracts, gateway, 1, query="vpc_role", offset=0)
    assert answer["ok"] and "vpc" not in answer
    version = _ssh_read(contracts, gateway, 2, query="version", offset=0)
    assert version["ok"] and "vpc" not in version


def test_public_eos_mlag_has_no_vpc(tmp_path, monkeypatch):
    mlag = "MLAG Configuration:\ndomain-id                          :                   \n"
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show mlag detail": mlag}, platform="arista_eos",
                                     queries=("version", "mlag_detail"))
    answer = _ssh_read(contracts, gateway, 1, platform="arista_eos", query="mlag_detail", offset=0)
    assert answer["ok"] and "vpc" not in answer


def test_public_cli_refusal_has_no_vpc(tmp_path, monkeypatch):
    refused = "                  ^\n% Invalid command at '^' marker.\n"
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show vpc brief": refused}, rc=16)
    answer = _ssh_read(contracts, gateway, 1, query="vpc_status", offset=0)
    assert answer["ok"] is False and "vpc" not in answer


# --- _KEY_VALUE without lazy quantifiers over overlapping classes ---
# The 3f867a8 spelling, frozen independently of the production constant: same groups, quadratic backtracking.
_KEY_VALUE_3F867A8 = re.compile(r"^[ \t]*([A-Za-z][A-Za-z0-9 ()/._-]*?)[ \t]*:[ \t]*(.*?)[ \t]*$")


def _same(current, previous, text):
    for operation in ("match", "fullmatch", "search"):
        new, old = getattr(current, operation)(text), getattr(previous, operation)(text)
        assert (new is None) == (old is None), (operation, text)
        if new is not None:
            assert (new.span(), new.groups(), new.span(1), new.span(2)) == (
                old.span(), old.groups(), old.span(1), old.span(2)), (operation, text)


def test_key_value_regex_is_equivalent_on_every_real_nxos_line_and_derived_text():
    from netops_helper import switch_vpc
    current = switch_vpc._KEY_VALUE
    real = sorted((HERE / "fixtures/real/cisco_nxos").rglob("*.txt"))
    assert REAL_DIR / "vpc_status.txt" in real and REAL_DIR / "vpc_role.txt" in real
    texts = [path.read_text(errors="replace") for path in real] + [DOC]
    lines = matched = 0
    for text in texts:
        # every raw line as summarize() sees it, and the CRLF/whole-text forms as well
        for line in switch_vpc._lines(text) + text.split("\n") + text.splitlines(keepends=True):
            _same(current, _KEY_VALUE_3F867A8, line)
            lines += 1
            matched += current.match(line) is not None
    # every "label : value" metadata line of the DOC block is matched with the published label and value
    for line in DOC_LINES:
        if " : " in line or line.endswith(" :"):
            pair = current.match(line)
            assert pair is not None and pair.groups() == tuple(part.strip() for part in line.split(":", 1)), line
    print(f"key_value_equivalence nxos_files={len(real)} lines={lines} matched={matched} differences=0")


def test_key_value_regex_is_equivalent_on_all_short_strings():
    from itertools import product
    from netops_helper import switch_vpc
    alphabet = ("a", "1", " ", "\t", ":", "(", "-", "!", "\n", "\r")
    count = 0
    for length in range(6):
        for letters in product(alphabet, repeat=length):
            tail = "".join(letters)
            for text in (tail, "a" + tail, "vPC role" + tail, "a :" + tail):
                _same(switch_vpc._KEY_VALUE, _KEY_VALUE_3F867A8, text)
                count += 1
    print(f"key_value_exhaustive strings={count} differences=0")


@pytest.mark.parametrize("text", [
    "    key " + " " * 99991 + "!", "ge-0/0/0 Current " + " " * 99982 + "!",  # label side (test_parser_complexity)
    "k:a" + " " * 99996 + "!", "vPC role :" + " \t" * 50000 + "x",  # value side
], ids=["label-spaces", "label-after-words", "value-spaces", "value-mixed-blanks"])
def test_key_value_regex_is_linear_on_long_blank_runs(text):
    import signal
    import time
    from netops_helper import switch_vpc

    def expired(*_):
        raise AssertionError("switch_vpc._KEY_VALUE exceeded the 10 s hard stop")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 10)  # hard stop only; the verdict below is the work done, not the speed
    try:
        started = time.perf_counter()
        for operation in ("match", "fullmatch", "search"):
            getattr(switch_vpc._KEY_VALUE, operation)(text)
        elapsed = time.perf_counter() - started
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    # Speed-independent: 100000 characters make a quadratic pattern take tens of seconds on any machine
    # (at 20000 characters the old code took 0.4-2.8 s), so the 10 s hard stop trips it; a linear one needs milliseconds.
    # This bound has a reserve of three orders of magnitude for a slow or fully loaded runner.
    assert elapsed < 5, elapsed
