"""Arista EOS `show mlag detail` structured summary (ssh_read arista_eos/mlag_detail, key `mlag`).

Data labels:
* REAL    - tests/fixtures/real/arista_eos/ceos_4.36.1F/mlag_detail.txt, an unmodified RO capture of a cEOSLab
            4.36.1F engineering build with MLAG not configured.  It is an inactive case: not a live active MLAG
            and not a hardware qualification.
* DERIVED - explicit edits of REAL text (non-empty scalar values, non-zero counts, framing, damaged lines) made only
            to exercise the parser.  They are neither documentation nor a measurement of an active MLAG, and no
            new CLI format.
The summary is device data read for display; it is never a health verdict and this query lists no member ports.
"""
import hashlib
import json
import re
from pathlib import Path

import pytest

HERE = Path(__file__).parent
REAL_DIR = HERE / "fixtures/real/arista_eos/ceos_4.36.1F"
REAL = (REAL_DIR / "mlag_detail.txt").read_text()
REAL_SHA256 = "5c21346949dc6f181b4e1065722434864b32d01a62de5a989ab014a5ebf24d3f"

FIELDS = {"state", "domain_id", "operational_state", "detailed_state", "peer_state", "peer_address", "peer_link",
          "local_interface", "peer_link_status", "local_interface_status", "negotiation_status", "peer_config",
          "ports", "members", "missing_fields"}
SCALARS = ("domain_id", "peer_address", "peer_link", "local_interface", "peer_link_status",
           "local_interface_status", "negotiation_status", "peer_config", "peer_state")
ZERO_PORTS = {"disabled": 0, "configured": 0, "inactive": 0, "active_partial": 0, "active_full": 0}
REAL_MISSING = ["domain_id", "peer_state", "peer_address", "peer_link", "local_interface", "peer_link_status",
                "local_interface_status", "negotiation_status", "peer_config"]
ACTIVE_VALUES = {  # DERIVED: non-empty reported scalars for the existing labels
    "domain-id": "mlag-lab", "local-interface": "Vlan4094", "peer-address": "198.51.100.2",
    "peer-link": "Port-Channel10", "peer-config": "consistent", "negotiation status": "Connected",
    "peer-link status": "Up", "local-int status": "Up", "state": "Active", "State": "primary",
    "Peer State": "secondary", "Configured": "3", "Active-full": "3",
}


def _summarize(text, capture_state="ok"):
    from netops_helper import switch_mlag_eos
    return switch_mlag_eos.summarize(text, capture_state)


def _set(text, label, value):
    """DERIVED: replace the value of one existing label (exact, case-sensitive, once)."""
    pattern = re.compile(rf"^{re.escape(label)} +:.*$", re.M)
    assert len(pattern.findall(text)) == 1, label
    return pattern.sub(lambda m: f"{label:<34} : {value:>19}", text)


def _drop(text, label):
    """DERIVED: remove the one line of an existing label."""
    pattern = re.compile(rf"^{re.escape(label)} +:.*\n", re.M)
    assert len(pattern.findall(text)) == 1, label
    return pattern.sub("", text)


def _add_after(text, label, line):
    """DERIVED: add one extra line right after the one line of an existing label."""
    pattern = re.compile(rf"^{re.escape(label)} +:.*\n", re.M)
    assert len(pattern.findall(text)) == 1, label
    return pattern.sub(lambda m: m.group(0) + line + "\n", text)


def _derived(values):
    text = REAL
    for label, value in values.items():
        text = _set(text, label, value)
    return text


ACTIVE = _derived(ACTIVE_VALUES)
ALL_ZERO_KNOWN = _derived({key: value for key, value in ACTIVE_VALUES.items()
                           if key not in ("Configured", "Active-full")})


# --- REAL capture ---
def test_real_capture_is_unchanged_and_indexed():
    assert hashlib.sha256((REAL_DIR / "mlag_detail.txt").read_bytes()).hexdigest() == REAL_SHA256
    assert len(REAL.encode()) == 2769 and len(REAL.splitlines()) == 54
    index = json.loads((REAL_DIR / "index.json").read_text())["mlag_detail"]
    assert index == {"command": "show mlag detail", "rc": 0, "lines": 54, "account": "netops-ro"}
    version = (REAL_DIR / "version.txt").read_text()
    assert "cEOSLab" in version and "4.36.1F-48405728.4361F" in version


def test_real_inactive_case_separates_the_two_states_and_five_zero_counts():
    summary = _summarize(REAL)
    assert set(summary) == FIELDS
    assert summary == {
        "state": "partial", "domain_id": None, "operational_state": "Disabled", "detailed_state": "disabled",
        "peer_state": None, "peer_address": None, "peer_link": None, "local_interface": None,
        "peer_link_status": None, "local_interface_status": None, "negotiation_status": None, "peer_config": None,
        "ports": ZERO_PORTS, "members": [], "missing_fields": REAL_MISSING,
    }
    assert all(summary["ports"][key] == 0 and summary["ports"][key] is not None for key in ZERO_PORTS)
    assert summary["operational_state"] != summary["detailed_state"]  # separate sections, no key overwrite
    assert not {"healthy", "health", "role", "neighbor", "traffic"} & set(summary)


# --- DERIVED: non-empty scalars and non-zero counts ---
def test_derived_active_values_are_read_exactly_but_stay_partial_without_member_names():
    summary = _summarize(ACTIVE)
    assert summary == {
        "state": "partial", "domain_id": "mlag-lab", "operational_state": "Active", "detailed_state": "primary",
        "peer_state": "secondary", "peer_address": "198.51.100.2", "peer_link": "Port-Channel10",
        "local_interface": "Vlan4094", "peer_link_status": "Up", "local_interface_status": "Up",
        "negotiation_status": "Connected", "peer_config": "consistent",
        "ports": {"disabled": 0, "configured": 3, "inactive": 0, "active_partial": 0, "active_full": 3},
        "members": None, "missing_fields": ["members"],
    }  # members are never invented, correlated or taken from counts


def test_derived_state_words_do_not_decide_health():
    text = _derived({**ACTIVE_VALUES, "state": "Inactive", "State": "disabled", "Peer State": "primary"})
    summary = _summarize(text)
    assert (summary["operational_state"], summary["detailed_state"], summary["peer_state"]) == (
        "Inactive", "disabled", "primary")
    assert summary["state"] == "partial" and summary["members"] is None
    assert not {"healthy", "health"} & set(summary)


def test_derived_zero_counts_with_all_scalars_known_is_measured_parsed_data_only():
    summary = _summarize(ALL_ZERO_KNOWN)
    assert summary["state"] == "measured" and summary["missing_fields"] == [] and summary["members"] == []
    assert summary["ports"] == ZERO_PORTS and summary["peer_address"] == "198.51.100.2"
    assert _summarize(ALL_ZERO_KNOWN, "partial")["state"] == "partial"


def test_derived_nonzero_other_count_contradicts_empty_members():
    summary = _summarize(_derived({"Active-full": "2"}))
    assert summary["members"] is None and "members" in summary["missing_fields"]
    assert summary["ports"]["configured"] == 0 and summary["ports"]["active_full"] == 2


def test_derived_active_full_count_is_not_a_peer_or_config_claim():
    summary = _summarize(_derived({"Configured": "3", "Active-full": "3"}))
    assert summary["ports"]["active_full"] == 3
    assert summary["peer_state"] is None and summary["peer_config"] is None and summary["state"] == "partial"


def test_derived_placeholder_peer_address_unknown_and_redaction_markers_are_not_values():
    text = _derived({"peer-address": "0.0.0.0", "domain-id": "unknown", "peer-link": "<REDACTED>",
                     "peer-config": "[REDACTED]", "local-interface": "<REDACTED:credential#1>",
                     "negotiation status": "n/a"})
    summary = _summarize(text)
    for key in ("peer_address", "domain_id", "peer_link", "peer_config", "local_interface", "negotiation_status"):
        assert summary[key] is None and key in summary["missing_fields"]
    assert summary["state"] == "partial"


# --- DERIVED: damaged, duplicated, scoped, missing, unknown ---
def test_derived_state_label_is_scoped_to_its_section():
    summary = _summarize(_derived({"state": "Active", "State": "disabled"}))
    assert summary["operational_state"] == "Active" and summary["detailed_state"] == "disabled"
    only_detailed = _summarize(_drop(REAL, "state"))
    assert only_detailed["operational_state"] is None and "operational_state" in only_detailed["missing_fields"]
    assert only_detailed["detailed_state"] == "disabled"  # the other section's State is not borrowed


def test_derived_duplicate_label_in_one_section_is_ambiguous_not_first_or_last():
    text = _set(REAL, "domain-id", "55")
    text = _add_after(text, "peer-config", "domain-id                          :                 77")
    summary = _summarize(text)
    assert summary["domain_id"] is None and "domain_id" in summary["missing_fields"]
    assert summary["operational_state"] == "Disabled" and summary["ports"] == ZERO_PORTS


def test_derived_same_label_in_another_section_is_not_a_duplicate():
    text = _add_after(REAL, "Configured", "Disabled                           :                   9")
    assert _summarize(text)["ports"]["disabled"] is None  # duplicate inside MLAG Ports
    assert _summarize(REAL)["operational_state"] == "Disabled"  # 'Disabled' value/label elsewhere is harmless


def test_derived_damaged_counter_is_missing_and_keeps_the_others():
    summary = _summarize(_derived({"Inactive": "x1", "Active-partial": "-3", "Disabled": ""}))
    assert summary["ports"] == {"disabled": None, "configured": 0, "inactive": None, "active_partial": None,
                                "active_full": 0}
    assert {"ports.disabled", "ports.inactive", "ports.active_partial"} <= set(summary["missing_fields"])
    assert summary["operational_state"] == "Disabled" and summary["state"] == "partial"
    assert summary["members"] == []  # explicit Configured=0, no read count contradicts it


def test_derived_missing_ports_section_keeps_other_data_and_does_not_invent_members():
    head = REAL.split("MLAG Ports:", 1)[0]
    tail = "MLAG Detailed Status:" + REAL.split("MLAG Detailed Status:", 1)[1]
    summary = _summarize(head + tail)
    assert summary["ports"] == dict.fromkeys(ZERO_PORTS)
    assert summary["members"] is None and "members" in summary["missing_fields"]
    assert summary["operational_state"] == "Disabled" and summary["detailed_state"] == "disabled"
    assert summary["state"] == "partial"


def test_derived_unknown_management_fields_are_ignored_not_a_defect():
    text = REAL + "Brand new management field        :              whatever\nReload delay                    : 5\n"
    assert _summarize(text) == _summarize(REAL)
    assert _summarize(_drop(text, "Hardware ready")) == _summarize(REAL)


@pytest.mark.parametrize("text", [
    "", "\n\n  \n", "switch#", "switch>\r\n", "switch#show mlag detail\nswitch#", "MLAG Configuration:\nMLAG Status:\n",
    "% some totally unknown text\nnothing here: at all\n", "domain-id : 5\nstate : Active\n",
], ids=["empty", "blank", "prompt", "prompt-crlf", "echo-prompt", "headers-only", "unknown", "no-sections"])
def test_derived_blank_prompt_header_or_unknown_is_unparsed_not_healthy_empty(text):
    summary = _summarize(text)
    assert summary["state"] == "unparsed" and set(summary) == FIELDS
    assert all(summary[key] is None for key in SCALARS) and summary["operational_state"] is None
    assert summary["ports"] == dict.fromkeys(ZERO_PORTS) and summary["members"] is None
    assert "members" in summary["missing_fields"]


def test_derived_non_string_input_is_unparsed():
    assert _summarize(None)["state"] == "unparsed"


# --- DERIVED: framing and capture state ---
def test_derived_crlf_echo_prompt_and_ansi_framing_give_the_same_summary():
    body = "\r\n".join(REAL.split("\n"))
    framed = "switch#show mlag detail\r\n" + body.replace("MLAG Status:", "\x1b[1mMLAG Status:\x1b[0m") + "switch#"
    assert _summarize(framed) == _summarize(REAL)
    assert _summarize("switch(config)#show mlag detail\n" + ACTIVE + "\nswitch(config)# ") == _summarize(ACTIVE)


@pytest.mark.parametrize("capture_state", ["partial", "truncated", "error", None])
def test_derived_capture_state_downgrades_but_keeps_valid_data(capture_state):
    real = _summarize(REAL, capture_state)
    assert real["state"] == "partial" and real["missing_fields"] == REAL_MISSING + ["capture"]
    assert real["operational_state"] == "Disabled" and real["ports"] == ZERO_PORTS
    active = _summarize(ACTIVE, capture_state)
    assert active["peer_address"] == "198.51.100.2" and active["missing_fields"] == ["members", "capture"]
    cut = _summarize(REAL.split("MLAG Ports:")[0], capture_state)
    assert cut["state"] == "partial" and cut["operational_state"] == "Disabled" and "capture" in cut["missing_fields"]
    unparsed = _summarize("switch#", capture_state)
    assert unparsed["state"] == "unparsed" and "capture" in unparsed["missing_fields"]


def test_payload_only_for_eos_mlag_detail():
    from netops_helper import switch_mlag_eos
    assert switch_mlag_eos.payload("arista_eos", "mlag_detail", REAL, "ok") == {"mlag": _summarize(REAL)}
    for platform, query in (("arista_eos", "mlag_config_sanity"), ("arista_eos", "version"),
                            ("cisco_nxos", "vpc_status"), ("cisco_nxos", "mlag_detail"), ("fortinet", "mlag_detail")):
        assert switch_mlag_eos.payload(platform, query, REAL, "ok") == {}


# --- public path: Proxy.request -> TargetAuth.decode -> engine.ssh_read; fake physical SSH/audit only ---
NXOS_DIR = HERE / "fixtures/real/cisco_nxos/nexus9300v_9.3.12"
IDENTITY = {"cisco_nxos": NXOS_DIR / "version.txt", "arista_eos": HERE / "fixtures/identity/arista_eos.txt"}
EOS_QUERIES = ("version", "mlag_detail", "mlag_config_sanity")


def _gateway(tmp_path, monkeypatch, outputs, platform="arista_eos", queries=EOS_QUERIES, rc=0):
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


def _ssh_read(contracts, gateway, index, platform="arista_eos", **arguments):
    from netops_helper import engine
    from netops_helper.auth import TargetAuth
    forwarded = gateway.request(contracts._request(index, "ssh_read", {"target": "device-a", "platform": platform, **arguments}))
    assert forwarded is not None
    args = json.loads(forwarded)["params"]["arguments"]
    auth = TargetAuth.decode(args["target"], args["auth_context"])
    return engine.ssh_read(auth, args["platform"], args["query"], args.get("parameters"), args.get("offset", 0),
                           args.get("max_bytes", 48_000), args.get("content_sha256"))


def _page(answer, raw):
    return raw[answer["offset"]:answer["offset"] + answer["returned_bytes"]].decode("utf-8")


def test_public_fresh_and_cached_pages_share_the_whole_summary_and_leave_body_untouched(tmp_path, monkeypatch):
    from netops_helper import engine
    raw = REAL.encode()
    contracts, gateway, calls = _gateway(tmp_path, monkeypatch, {"show mlag detail": REAL})
    first = _ssh_read(contracts, gateway, 1, query="mlag_detail", offset=0, max_bytes=1000)
    assert first["ok"] is True and not first["complete"] and first["pagination_source"] == "fresh", first
    assert "Disabled" in first["untrusted_device_output"] and "MLAG Detailed Status" not in first["untrusted_device_output"]
    assert first["mlag"] == _summarize(REAL) and first["mlag"]["detailed_state"] == "disabled"  # from the whole text
    ssh_calls = len(calls)
    assert calls.count("show mlag detail") == 1
    pages, answer, index = [first], first, 2
    while not answer["complete"]:
        answer = _ssh_read(contracts, gateway, index, query="mlag_detail", offset=answer["next_offset"],
                           max_bytes=1000, content_sha256=first["content_sha256"])
        assert answer["ok"] and answer["pagination_source"] == "cached"
        assert answer["mlag"] == first["mlag"]
        pages.append(answer)
        index += 1
    assert len(pages) >= 3 and len(calls) == ssh_calls  # no further SSH for any cached page
    assert "".join(page["untrusted_device_output"] for page in pages) == REAL
    for page in pages:
        assert page["content_sha256"] == hashlib.sha256(raw).hexdigest() == REAL_SHA256
        assert page["total_bytes"] == len(raw) == 2769
        assert page["untrusted_device_output"] == _page(page, raw)
        assert page["transport"] == engine._SSH_TRANSPORTS["arista_eos"]
    assert [page["offset"] for page in pages][0] == 0


def test_public_derived_active_text_is_partial_without_member_names(tmp_path, monkeypatch):
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show mlag detail": ACTIVE})
    answer = _ssh_read(contracts, gateway, 1, query="mlag_detail", offset=0)
    assert answer["ok"] is True and answer["untrusted_device_output"] == ACTIVE
    assert answer["mlag"] == _summarize(ACTIVE)
    assert answer["mlag"]["state"] == "partial" and answer["mlag"]["members"] is None
    assert answer["mlag"]["missing_fields"] == ["members"] and answer["mlag"]["peer_address"] == "198.51.100.2"


def test_public_nonzero_rc_downgrades_and_keeps_data(tmp_path, monkeypatch):
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show mlag detail": ALL_ZERO_KNOWN}, rc=1)
    answer = _ssh_read(contracts, gateway, 1, query="mlag_detail", offset=0)
    assert answer["ok"] is True and answer["mlag"]["state"] == "partial"
    assert answer["mlag"]["missing_fields"] == ["capture"] and answer["mlag"]["peer_address"] == "198.51.100.2"


def test_public_forbidden_sentinel_goes_through_the_real_redaction(tmp_path, monkeypatch):
    sentinel = "ssh-password"  # the device secret of the test inventory; DERIVED line, not a measurement
    text = _derived({**ACTIVE_VALUES, "peer-link": sentinel})
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show mlag detail": text})
    answer = _ssh_read(contracts, gateway, 1, query="mlag_detail", offset=0)
    assert answer["ok"] is True
    assert sentinel not in json.dumps(answer) and sentinel not in answer["untrusted_device_output"]
    assert "redacted" in answer["untrusted_device_output"].lower()
    assert answer["mlag"]["peer_link"] is None and "peer_link" in answer["mlag"]["missing_fields"]
    assert answer["mlag"]["peer_address"] == "198.51.100.2" and answer["mlag"]["state"] == "partial"


def test_public_other_query_and_other_profile_get_no_mlag_key(tmp_path, monkeypatch):
    sanity = (REAL_DIR / "mlag_config_sanity.txt").read_text()
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show mlag config-sanity": sanity})
    answer = _ssh_read(contracts, gateway, 1, query="mlag_config_sanity", offset=0)
    assert "mlag" not in answer
    version = _ssh_read(contracts, gateway, 2, query="version", offset=0)
    assert version["ok"] and "mlag" not in version
    nxos = (NXOS_DIR / "vpc_status.txt").read_text()
    (tmp_path / "nxos").mkdir()
    contracts, gateway, _ = _gateway(tmp_path / "nxos", monkeypatch, {"show vpc brief": nxos}, platform="cisco_nxos",
                                     queries=("version", "vpc_status"))
    answer = _ssh_read(contracts, gateway, 3, platform="cisco_nxos", query="vpc_status", offset=0)
    assert answer["ok"] and "vpc" in answer and "mlag" not in answer


# --- task 136: _KEY_VALUE without lazy quantifiers over overlapping classes ---
# The ed1b508 spelling, frozen independently of the production constant: same groups, quadratic backtracking.
_KEY_VALUE_ED1B508 = re.compile(r"^[ \t]*([A-Za-z][A-Za-z0-9 ()/._-]*?)[ \t]*:[ \t]*(.*?)[ \t]*$")


def _same(current, previous, text):
    for operation in ("match", "fullmatch", "search"):
        new, old = getattr(current, operation)(text), getattr(previous, operation)(text)
        assert (new is None) == (old is None), (operation, text)
        if new is not None:
            assert (new.span(), new.groups(), new.span(1), new.span(2)) == (
                old.span(), old.groups(), old.span(1), old.span(2)), (operation, text)


def test_key_value_regex_is_equivalent_on_every_real_eos_line_and_derived_text():
    from netops_helper import switch_mlag_eos
    current = switch_mlag_eos._KEY_VALUE
    real = sorted(path for path in (HERE / "fixtures/real/arista_eos").rglob("*.txt"))
    assert REAL_DIR / "mlag_detail.txt" in real and REAL_DIR / "mlag_config_sanity.txt" in real
    texts = [path.read_text(errors="replace") for path in real] + [ACTIVE, ALL_ZERO_KNOWN]
    lines = matched = 0
    for text in texts:
        # every raw line as summarize() sees it, and the CRLF/whole-text forms as well
        for line in switch_mlag_eos._lines(text) + text.split("\n") + text.splitlines(keepends=True):
            _same(current, _KEY_VALUE_ED1B508, line)
            lines += 1
            matched += current.match(line) is not None
    # every line of the real capture that has a colon (headings and labels) is matched
    assert sum(current.match(line) is not None for line in switch_mlag_eos._lines(REAL)) == sum(
        ":" in line for line in REAL.splitlines()) == 50
    print(f"key_value_equivalence eos_files={len(real)} lines={lines} matched={matched} differences=0")


def test_key_value_regex_is_equivalent_on_all_short_strings():
    from itertools import product
    from netops_helper import switch_mlag_eos
    alphabet = ("a", "1", " ", "\t", ":", "(", "-", "!", "\n", "\r")
    count = 0
    for length in range(6):
        for letters in product(alphabet, repeat=length):
            tail = "".join(letters)
            for text in (tail, "a" + tail, "Peer state" + tail, "a :" + tail):
                _same(switch_mlag_eos._KEY_VALUE, _KEY_VALUE_ED1B508, text)
                count += 1
    print(f"key_value_exhaustive strings={count} differences=0")


@pytest.mark.parametrize("text", [
    "    key " + " " * 19991 + "!", "ge-0/0/0 Current " + " " * 19982 + "!",  # label side (test_parser_complexity)
    "k:a" + " " * 19996 + "!", "Peer State :" + " \t" * 10000 + "x",  # value side
], ids=["label-spaces", "label-after-words", "value-spaces", "value-mixed-blanks"])
def test_key_value_regex_is_linear_on_long_blank_runs(text):
    import signal
    import time
    from netops_helper import switch_mlag_eos

    def expired(*_):
        raise AssertionError("switch_mlag_eos._KEY_VALUE exceeded 0.5s")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 0.5)
    try:
        started = time.perf_counter()
        for operation in ("match", "fullmatch", "search"):
            getattr(switch_mlag_eos._KEY_VALUE, operation)(text)
        elapsed = time.perf_counter() - started
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    assert elapsed < 0.05, elapsed  # ed1b508: about 0.4-1.4 s per fullmatch at 20000 characters (PC-Radek)
