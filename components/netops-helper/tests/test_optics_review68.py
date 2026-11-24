"""Review regressions: capture state limits `measured` (N1); unreadable/absent metric headers (N2).

D = real RO capture sample_a-port13.txt, T = real RO capture sample_a-temperature.txt (home64, EXOS 33.7.1.6).
Every input below is a DERIVED mutation of D/T (or D/T with a fake SSH rc/pager tail), not a new measurement.
The public cases go through Proxy.request -> TargetAuth.decode -> engine.ssh_read -> real catalog/parser;
only the SSH transport is fake (reused test_optics._gateway/_ssh_read).
"""
import json

import test_optics as base

D_COMMAND = "show ports 13 transceiver information detail"
T_COMMAND = "show temperature"
OTHER = ("temperature", "tx_power", "rx_power", "tx_bias_current")


def _d():
    return base._read("sample_a-port13.txt")


def _t():
    return base._read("sample_a-temperature.txt")


def _dom(tmp_path, monkeypatch, output, rc, **extra):
    contracts, gateway, calls = base._gateway(tmp_path, monkeypatch, {D_COMMAND: output}, rc=rc)
    answer = base._ssh_read(contracts, gateway, 1, query="interface_transceiver", parameters={"interface": "13"},
                            offset=0, **extra)
    return contracts, gateway, calls, answer


def _assert_d_values_kept(optics, keys=base.KEYS):
    for key in keys:
        assert optics["readings"][key]["value"] == base.EXPECTED["a"][key]
        assert tuple(optics["readings"][key]["thresholds"].values()) == base.THRESHOLDS[key]


# --- N1: the real capture state (normalization.output_status) gates `measured` ---
def test_n1_healthy_literal_is_existing_output_status_ok():
    from netops_helper import normalization
    assert normalization.output_status(_d(), rc=0, profile="extreme_exos", command=D_COMMAND) == "ok"
    assert normalization.output_status(_d() + "--More--", rc=0, profile="extreme_exos", command=D_COMMAND) == "truncated"
    assert normalization.output_status(_d(), rc=1, profile="extreme_exos", command=D_COMMAND) == "transport_error"


def test_n1_pager_tail_is_truncated_and_optics_partial(tmp_path, monkeypatch):
    _, _, calls, answer = _dom(tmp_path, monkeypatch, _d() + "--More--", 0)
    assert answer["status"] == "truncated", answer
    optics = answer["optics"]
    assert optics["state"] == "partial" and "capture" in optics["missing_fields"]
    _assert_d_values_kept(optics)
    assert calls.count(D_COMMAND) == 1


def test_n1_rc1_dom_is_transport_error_and_optics_partial(tmp_path, monkeypatch):
    _, _, _, answer = _dom(tmp_path, monkeypatch, _d(), 1)
    assert answer["status"] == "transport_error", answer
    assert answer["optics"]["state"] == "partial" and "capture" in answer["optics"]["missing_fields"]
    _assert_d_values_kept(answer["optics"])


def test_n1_rc1_temperature_is_transport_error_and_environment_partial(tmp_path, monkeypatch):
    contracts, gateway, _ = base._gateway(tmp_path, monkeypatch, {T_COMMAND: _t()}, rc=1)
    answer = base._ssh_read(contracts, gateway, 1, query="temperature", offset=0)
    assert answer["status"] == "transport_error", answer
    environment = answer["environment"]
    assert environment["state"] == "partial" and "capture" in environment["missing_fields"]
    assert environment["temperatures"][0]["value"] == 79.0


def test_n1_cached_continuation_keeps_capture_gate_without_io(tmp_path, monkeypatch):
    contracts, gateway, calls, first = _dom(tmp_path, monkeypatch, _d() + "--More--", 0, max_bytes=1000)
    assert not first["complete"] and first["status"] == "truncated"
    assert first["optics"]["state"] == "partial" and "capture" in first["optics"]["missing_fields"]
    second = base._ssh_read(contracts, gateway, 2, query="interface_transceiver", parameters={"interface": "13"},
                            offset=first["next_offset"], max_bytes=1000, content_sha256=first["content_sha256"])
    assert second["pagination_source"] == "cached" and second["status"] == "truncated"
    assert second["optics"] == first["optics"]
    assert calls.count(D_COMMAND) == 1


def test_n1_healthy_capture_stays_measured(tmp_path, monkeypatch):
    _, _, _, answer = _dom(tmp_path, monkeypatch, _d(), 0)
    assert answer["optics"]["state"] == "measured" and answer["optics"]["missing_fields"] == []
    _assert_d_values_kept(answer["optics"])


# --- N2: a metric header starts its block even when its value is unreadable or absent ---
def _without_voltage_line(text, drop_blank_before=False):
    lines = text.splitlines(True)
    index = next(i for i, line in enumerate(lines) if "Voltage AUX-1/Vcc" in line)
    start = index - 1 if drop_blank_before else index
    if drop_blank_before:
        assert not lines[start].strip()
    return "".join(lines[:start] + lines[index + 1:])


def test_n2_repro_a_removed_voltage_header_keeps_other_metrics():
    text = _without_voltage_line(_d())
    assert "3.10" in text and "3.70" in text  # both voltage threshold lines are kept
    result = base._optics().transceiver(text, "13")
    assert result["state"] == "partial" and "voltage" in result["missing_fields"]
    assert result["readings"]["voltage"]["availability"] == "missing"
    assert result["readings"]["voltage"]["value"] is None
    assert set(result["readings"]["voltage"]["thresholds"].values()) == {None}  # orphan thresholds not guessed to voltage
    _assert_d_values_kept(result, OTHER)  # temperature thresholds are not overwritten
    json.dumps(result, allow_nan=False)


def test_n2_repro_a_without_blank_boundary_withholds_contested_thresholds():
    text = _without_voltage_line(_d(), drop_blank_before=True)
    result = base._optics().transceiver(text, "13")
    assert result["state"] == "partial" and "voltage" in result["missing_fields"]
    temperature = result["readings"]["temperature"]
    assert temperature["value"] == 53.58
    for name, value in temperature["thresholds"].items():
        assert value is None and f"temperature.{name}" in result["missing_fields"]
    assert set(result["readings"]["voltage"]["thresholds"].values()) == {None}
    _assert_d_values_kept(result, ("tx_power", "rx_power", "tx_bias_current"))


def test_n2_empty_voltage_value_keeps_block_and_thresholds():
    text = _d()
    old = "Voltage AUX-1/Vcc (Volts) :  3.34 "
    assert old in text
    result = base._optics().transceiver(text.replace(old, "Voltage AUX-1/Vcc (Volts) :       "), "13")
    assert result["state"] == "partial" and "voltage.value" in result["missing_fields"]
    voltage = result["readings"]["voltage"]
    assert voltage["value"] is None and voltage["availability"] == "missing"
    assert tuple(voltage["thresholds"].values()) == base.THRESHOLDS["voltage"]
    _assert_d_values_kept(result, OTHER)


def test_n2_repro_b_unreadable_duplicate_header_is_unparsed():
    result = base._optics().transceiver(_d() + "\n    Rx Power (dBm) :\n", "13")
    assert result["state"] == "unparsed" and result["readings"] == {}


def test_n2_orphan_thresholds_after_boundary_are_not_measured():
    orphan = "\n          Low Warn Threshold  :  1.00       High Warn Threshold  :  2.00    \n"
    result = base._optics().transceiver(_d() + orphan, "13")
    assert result["state"] == "partial" and result["missing_fields"]
    _assert_d_values_kept(result)


def test_n2_public_repro_a_is_partial(tmp_path, monkeypatch):
    _, _, _, answer = _dom(tmp_path, monkeypatch, _without_voltage_line(_d()), 0)
    optics = answer["optics"]
    assert optics["state"] == "partial" and "voltage" in optics["missing_fields"]
    assert "capture" not in optics["missing_fields"]
    _assert_d_values_kept(optics, OTHER)
