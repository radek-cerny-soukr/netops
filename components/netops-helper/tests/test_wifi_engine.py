"""Wi-Fi reads through the engine: one SSH session for the log sequence, verified wtp ids, filters after redaction."""

import dataclasses
from pathlib import Path

import pytest

from conftest import EXEC_CLIENT, FORTIOS_STATUS, _target, _write_client
import netops_helper.engine as engine
from netops_helper.auth import PolicyScopeError

FIXTURES = Path(__file__).parent / "fixtures"
PROMPT = b"FGT80F0000001111(Primary) $ "
SERIAL_1, SERIAL_2 = "FAPEXAMPLE0000001", "FAPEXAMPLE0000002"
CLIENT = "00:00:5e:00:53:37"
STATUS_80F = "Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)\nVirtual domain configuration: disable\n"
QUERIES = ("system_status", "arp_table", "wifi_events", "wifi_ap_status", "wifi_vap_status", "wifi_rf_analysis",
           "wifi_neighbors", "wifi_controller_status")


def fixture(name):
    return (FIXTURES / ("fortios_80f_802_wifi_" + name + ".txt")).read_text(encoding="utf-8")


def auth(*queries, inventory=None, alias="wire-test"):
    target = _target("fortinet", queries[0] if queries else "system_status")
    return dataclasses.replace(target, alias=alias, enabled_queries=tuple(queries) or ("system_status",),
                               read_inventory=inventory or {})


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    engine._WTP_SEEN.clear()
    engine._SSH_PAGE_CACHE.clear()
    yield
    engine._WTP_SEEN.clear()


def fake_terminal(monkeypatch, outputs, sent):
    """A FortiOS read-only CLI: each command is answered with the next scripted output."""
    script = iter(outputs)

    class Terminal:
        def __init__(self, *args, **options):
            self.buffer = [b"banner\r\n" + PROMPT]

        def expect(self, patterns, timeout):
            return 0, self.buffer.pop(0)

        def discard(self, seen):
            pass

        def send(self, text):
            sent.append(text)
            body = next(script).replace("\n", "\r\n").encode()
            self.buffer.append(text.encode() + b"\r\n" + body + (b"\r\n" if body else b"") + PROMPT)

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(engine.core_session, "Session", Terminal)


def identity_on_the_wire(wire, status=STATUS_80F):
    _write_client(wire["binaries"], "ssh", EXEC_CLIENT.format(log=str(wire["log"]), output=status, code=0))


def read(target, query, parameters=None):
    return engine.ssh_read(target, "fortinet", query, parameters or {}, 0, 48_000)


def test_events_run_as_one_session_with_exactly_the_four_commands(wire, monkeypatch):
    identity_on_the_wire(wire)
    sent = []
    fake_terminal(monkeypatch, ["", "", "", fixture("log_display_wireless")], sent)
    answer = read(auth("wifi_events"), "wifi_events", {"lines": "20"})
    assert sent == [
        "execute log filter category event",
        "execute log filter field subtype wireless",
        "execute log filter view-lines 20",
        "execute log display",
    ]
    assert answer["ok"] is True and answer["transport"] == "pty"
    wifi = answer["wifi"]
    assert (wifi["found"], wifi["returned"], len(wifi["records"]), wifi["unparsed"]) == (211, 20, 20, [])
    assert "mac_filter" not in wifi


def test_mac_literal_filters_the_redacted_text_and_never_reaches_the_device(wire, monkeypatch):
    identity_on_the_wire(wire)
    sent = []
    fake_terminal(monkeypatch, ["", "", "", fixture("log_display_wireless")], sent)
    answer = read(auth("wifi_events"), "wifi_events", {"lines": "200", "mac_literal": CLIENT})
    assert CLIENT not in "".join(sent) and sent[2] == "execute log filter view-lines 200"
    assert [item["index"] for item in answer["wifi"]["records"]] == [12, 13, 14, 19]
    assert answer["wifi"]["mac_filter"] == {"mac_literal": CLIENT, "scanned_lines": 20, "matched": 4}
    assert answer["untrusted_device_output"].count("stamac=") == 4
    assert "Rogue AP" not in answer["untrusted_device_output"]


def test_a_filter_command_that_prints_is_a_device_refusal_and_stops_the_sequence(wire, monkeypatch):
    identity_on_the_wire(wire)
    sent = []
    fake_terminal(monkeypatch, ["", "command parse error before 'wireless'\nCommand fail. Return code -61", "", ""], sent)
    answer = read(auth("wifi_events"), "wifi_events", {"lines": "5"})
    assert answer["ok"] is False and answer["error_code"] == "device_cli_error"
    assert len(sent) == 2


@pytest.mark.parametrize('step', [0, 1, 2, 3])
@pytest.mark.parametrize('path', ['ssh', 'triage'])
def test_sequence_keeps_refusal_detection_after_output(wire, monkeypatch, step, path):
    identity_on_the_wire(wire)
    sent = []
    body = 'diagnostic preamble\ncommand parse error before \'wireless\'\nCommand fail. Return code -61\nSession ending'
    fake_terminal(monkeypatch, [''] * step + [body], sent)
    target = auth('wifi_events')
    result = (read(target, 'wifi_events', {'lines': '5'}) if path == 'ssh'
              else engine._triage_read(target, 'fortinet', 'wifi_events', {'lines': '5'}))
    assert not result['ok']
    assert result.get('error_code', result.get('reason')) == 'device_cli_error'
    assert len(sent) == step + 1
    assert not engine._SSH_PAGE_CACHE


def test_the_engine_refuses_to_send_anything_but_the_reviewed_sequence(wire, monkeypatch):
    opened = []
    monkeypatch.setattr(engine.core_session, "Session", lambda *a, **k: opened.append(1))
    target = auth("wifi_events")
    for commands in (("execute reboot",), ("execute log display",),
                     ("execute log filter category event", "execute log filter field subtype wireless",
                      "execute log filter view-lines 201", "execute log display"),
                     ("execute log filter category event", "execute log filter field subtype wireless",
                      "execute log filter view-lines 5", "execute log display", "execute reboot")):
        with pytest.raises(ValueError, match="outside the reviewed shapes"):
            engine._sequence_read(target, "fortinet", commands)
    with pytest.raises(ValueError, match="only for FortiOS"):
        engine._sequence_read(target, "linux", (
            "execute log filter category event", "execute log filter field subtype wireless",
            "execute log filter view-lines 5", "execute log display"))
    assert opened == []


def test_events_on_another_product_are_refused_before_any_command(wire, monkeypatch):
    identity_on_the_wire(wire, "Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n")
    sent = []
    fake_terminal(monkeypatch, ["", "", "", "x"], sent)
    answer = read(auth("wifi_events"), "wifi_events", {"lines": "5"})
    assert answer["ok"] is False and answer["error_code"] == "product_identity" and sent == []


def test_events_need_their_own_target_grant(wire):
    with pytest.raises(PolicyScopeError):
        read(auth("system_status"), "wifi_events", {"lines": "5"})


def fake_exec(monkeypatch, outputs):
    commands = []

    def fake(target, platform, command, prompt=False):
        commands.append(command)
        return 0, outputs[command]

    monkeypatch.setattr(engine, "_verified_read", fake)
    return commands


def test_wtp_id_is_refused_until_the_target_listed_it(monkeypatch):
    commands = fake_exec(monkeypatch, {"get wireless-controller wtp-status": fixture("wtp_status"),
                                       "get wireless-controller wtp-status " + SERIAL_1: fixture("wtp_status")})
    target = auth("wifi_ap_status")
    with pytest.raises(ValueError, match="not enrolled"):
        read(target, "wifi_ap_status", {"wtp_id": SERIAL_1})
    assert commands == []
    listing = read(target, "wifi_ap_status")
    assert [item["serial"] for item in listing["wifi"]["records"]] == [SERIAL_1, SERIAL_2]
    one = read(target, "wifi_ap_status", {"wtp_id": SERIAL_1})
    assert one["ok"] is True and commands[-1] == "get wireless-controller wtp-status " + SERIAL_1
    with pytest.raises(ValueError, match="not enrolled"):
        read(target, "wifi_ap_status", {"wtp_id": "FAPEXAMPLE0000009"})
    # another target never inherits the ids this one listed
    with pytest.raises(ValueError, match="not enrolled"):
        read(auth("wifi_ap_status", alias="other"), "wifi_ap_status", {"wtp_id": SERIAL_1})


def test_an_enrolled_wtp_id_needs_no_earlier_listing(monkeypatch):
    commands = fake_exec(monkeypatch, {"get wireless-controller rf-analysis " + SERIAL_1: fixture("rf_analysis_one")})
    answer = read(auth("wifi_rf_analysis", inventory={"wtp_ids": (SERIAL_1,)}), "wifi_rf_analysis", {"wtp_id": SERIAL_1})
    assert commands == ["get wireless-controller rf-analysis " + SERIAL_1]
    assert answer["wifi"]["records"][0]["wtp"] == SERIAL_1 and answer["wifi"]["unparsed"] == []


def test_listing_then_details_keep_individual_expiry(monkeypatch):
    listing = fixture("wtp_status")
    first, second = listing.split("WTP: " + SERIAL_2, 1)
    clock = [100.0]
    monkeypatch.setattr(engine.time, "monotonic", lambda: clock[0])
    fake_exec(monkeypatch, {"get wireless-controller wtp-status": listing,
                            "get wireless-controller wtp-status " + SERIAL_1: first,
                            "get wireless-controller wtp-status " + SERIAL_2: "WTP: " + SERIAL_2 + second})
    target = auth("wifi_ap_status")
    read(target, "wifi_ap_status")
    clock[0] += 100
    assert read(target, "wifi_ap_status", {"wtp_id": SERIAL_1})["ok"]
    clock[0] = 100 + engine._WTP_SEEN_TTL_SECONDS + 1
    assert engine._observed_wtp_ids(target) == frozenset({SERIAL_1})
    with pytest.raises(ValueError, match="not enrolled"):
        read(target, "wifi_ap_status", {"wtp_id": SERIAL_2})
    read(target, "wifi_ap_status")
    read(target, "wifi_ap_status", {"wtp_id": SERIAL_1})
    assert read(target, "wifi_ap_status", {"wtp_id": SERIAL_2})["ok"]


def test_only_a_wtp_status_listing_teaches_wtp_ids(monkeypatch):
    fake_exec(monkeypatch, {"get wireless-controller rf-analysis": fixture("rf_analysis_one"),
                            "get wireless-controller vap-status": fixture("vap_status")})
    target = auth("wifi_rf_analysis", "wifi_vap_status")
    read(target, "wifi_rf_analysis")
    read(target, "wifi_vap_status")
    assert engine._observed_wtp_ids(target) == frozenset()
    engine._remember_wtp_ids(target, ["A;reboot", "x y", "", "-a", SERIAL_2])
    assert engine._observed_wtp_ids(target) == frozenset({SERIAL_2})


def test_observed_ids_expire_and_are_bounded(monkeypatch):
    target = auth("wifi_ap_status")
    engine._remember_wtp_ids(target, [SERIAL_1])
    clock = [0.0]
    monkeypatch.setattr(engine.time, "monotonic", lambda: clock[0] + 10_000_000)
    assert engine._observed_wtp_ids(target) == frozenset()
    monkeypatch.undo()
    for number in range(engine._WTP_SEEN_MAX_TARGETS + 5):
        engine._remember_wtp_ids(auth("wifi_ap_status", alias="t%d" % number), [SERIAL_1])
    assert len(engine._WTP_SEEN) == engine._WTP_SEEN_MAX_TARGETS


def test_wifi_triage_reads_the_client_chain_and_verifies_the_rf_id_from_its_own_listing(wire, monkeypatch):
    target = auth(*QUERIES)
    commands = []
    texts = {
        "get system status": STATUS_80F,
        "get system arp": fixture("system_arp").replace("00:00:5e:00:53:32", CLIENT),
        "get wireless-controller wtp-status": fixture("wtp_status"),
        "get wireless-controller vap-status": fixture("vap_status"),
        "get wireless-controller rf-analysis " + SERIAL_2: fixture("rf_analysis_one").replace(SERIAL_1, SERIAL_2),
        "get wireless-controller scan": fixture("scan"),
    }

    def fake_read(auth_, platform, command, **options):
        commands.append(command)
        return 0, texts[command]

    sequences = []

    def fake_sequence(auth_, platform, sequence):
        sequences.append(sequence)
        return None, fixture("log_display_wireless")

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    monkeypatch.setattr(engine, "_sequence_read", fake_sequence)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    result = engine.triage_wifi(target, None, "192.0.2.19")
    assert commands == ["get system status", "get system arp", "get wireless-controller wtp-status",
                        "get wireless-controller vap-status", "get wireless-controller rf-analysis " + SERIAL_2,
                        "get wireless-controller scan"]
    assert len(sequences) == 1 and sequences[0][2] == "execute log filter view-lines 200"
    assert result["client"]["mac"] == CLIENT and result["verdict"] == "incomplete"
    assert result["chain"]["rf"]["channel"] == 116
    wired = next(item for item in result["missing"] if item["step"] == "locate_endpoint")
    assert wired["reason"] == "not_correlated" and "switch port" in wired["detail"]
    assert wired["lldp_uplink"] == result["chain"]["access_point"]["lldp"]
    assert any(item["step"] == "rf_data" for item in result["missing"])


def test_wifi_triage_reports_a_query_the_target_did_not_enable_as_permission_denied(monkeypatch):
    target = auth("system_status", "wifi_events")

    def fake_read(auth_, platform, command, **options):
        return 0, STATUS_80F

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    monkeypatch.setattr(engine, "_sequence_read", lambda *args: (None, fixture("log_display_wireless")))
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    result = engine.triage_wifi(target, CLIENT, None)
    assert {"step": "wifi_ap_status", "reason": "permission_denied"} in result["missing"]
    assert result["verdict"] == "incomplete" and result["chain"]["access_point"] is None
    assert result.get("ok", True) is True and "error_code" not in result and "failed_step" not in result


@pytest.mark.parametrize("mac,ip", [(None, None), (CLIENT, "192.0.2.1"), ("AA:BB:CC:DD:EE:FF", None), (None, "999.1.1.1")])
def test_wifi_triage_rejects_bad_selectors_before_any_device_contact(monkeypatch, mac, ip):
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    monkeypatch.setattr(engine, "read_from_device", lambda *a, **k: pytest.fail("device contacted"))
    with pytest.raises(ValueError, match="invalid_argument"):
        engine.triage_wifi(auth(*QUERIES), mac, ip)


def test_a_session_failure_of_the_sequence_forgets_the_host_key_and_is_raised(wire, monkeypatch):
    identity_on_the_wire(wire)
    forgotten = []
    def fail(*args, **options):
        raise engine.core_session.SessionError('connection lost')
    monkeypatch.setattr(engine.core_session, "Session", fail)
    monkeypatch.setattr(engine, "_forget_host_key_line", lambda address, port: forgotten.append((address, port)))
    with pytest.raises(engine.core_session.SessionError):
        engine._sequence_read(auth("wifi_events"), "fortinet", (
            "execute log filter category event", "execute log filter field subtype wireless",
            "execute log filter view-lines 5", "execute log display"))
    assert len(forgotten) == 1
