"""EXOS DOM/temperature summaries: real RO captures (home64), explicitly derived mutations, public proxy path."""
import json
import math
from dataclasses import replace
from pathlib import Path

import pytest

HERE = Path(__file__).parent
DOM = HERE / "fixtures/real/exos/dom_33.7.1.6_20261114"
KEYS = ["temperature", "voltage", "tx_power", "rx_power", "tx_bias_current"]
UNITS = dict(zip(KEYS, ["C", "V", "dBm", "dBm", "mA"]))
EXPECTED = {  # measured values copied from the real captures sample_a / sample_b
    "a": {"temperature": 53.58, "voltage": 3.34, "tx_power": -5.29, "rx_power": -5.20, "tx_bias_current": 22.75},
    "b": {"temperature": 56.37, "voltage": 3.34, "tx_power": -4.04, "rx_power": -5.86, "tx_bias_current": 23.86},
}
THRESHOLDS = {
    "temperature": (0.0, 70.0, -5.0, 75.0), "voltage": (3.1, 3.6, 3.0, 3.7),
    "tx_power": (-9.5, -1.0, -13.5, 1.0), "rx_power": (-19.0, -3.0, -23.01, 1.0),
    "tx_bias_current": (4.0, 70.0, 3.0, 75.0),
}


def _optics():
    from netops_helper import optics
    return optics


def _read(name):
    return (DOM / name).read_text()


@pytest.mark.parametrize("sample", ["a", "b"])
def test_real_port13_has_five_metrics_and_thresholds(sample):
    result = _optics().transceiver(_read(f"sample_{sample}-port13.txt"), "13")
    assert result["state"] == "measured" and result["interface"] == "13" and result["missing_fields"] == []
    assert list(result["readings"]) == KEYS
    for key in KEYS:
        item = result["readings"][key]
        assert item["value"] == EXPECTED[sample][key] and item["unit"] == UNITS[key]
        assert item["status"] == "Normal" and item["availability"] == "available"
        assert tuple(item["thresholds"].values()) == THRESHOLDS[key]
        assert list(item["thresholds"]) == ["low_warn", "high_warn", "low_alarm", "high_alarm"]


def test_real_negative_values_are_kept_and_other_port_is_refused():
    result = _optics().transceiver(_read("sample_a-port13.txt"), "13")
    assert result["readings"]["tx_power"]["value"] < 0
    assert _optics().transceiver(_read("sample_a-port13.txt"), "14")["state"] == "unparsed"


def test_real_absence_and_existing_ddmi_unsupported():
    for sample in "ab":
        assert _optics().transceiver(_read(f"sample_{sample}-port14.txt"), "14") == {
            "state": "not_present", "interface": "14", "readings": {}, "missing_fields": []}
    result = _optics().transceiver(_read("existing_port1_ddmi_unsupported.txt"), "1")
    assert result["state"] == "unsupported" and result["readings"] == {}


@pytest.mark.parametrize("sample,chassis", [("a", 79.0), ("b", 75.0)])
def test_real_temperature_is_chassis_not_dom(sample, chassis):
    result = _optics().environment(_read(f"sample_{sample}-temperature.txt"))
    assert result["state"] == "measured" and len(result["temperatures"]) == 1
    row = result["temperatures"][0]
    assert row["unit"] == "C" and row["status"] == "Normal" and "X440G2" in row["component"]
    assert row["reported_limits"] == {"min": 0.0, "normal_min": 10.0, "normal_max": 100.0, "max": 110.0}
    assert row["value"] not in (53.58, 56.37)
    assert row["value"] == chassis


def test_existing_x435_temperature_86_37():
    text = (HERE / "fixtures/real/exos/x435-8p-4s_33.7.1.6/temperature.txt").read_text()
    assert _optics().environment(text)["temperatures"][0]["value"] == 86.37


# --- DERIVED (synthetic mutations of real captures, not new measurements) ---
def _derived(**changes):
    text = _read("sample_a-port13.txt")
    for old, new in changes.items():
        assert old in text
        text = text.replace(old, new)
    return text


def test_derived_na_inf_zero_and_negative():
    text = _read("sample_a-port13.txt")
    text = text.replace(":  53.58 ", ":  0.00  ").replace("-5.20 ", "N/A   ").replace("22.75 ", "-inf  ")
    result = _optics().transceiver(text, "13")
    assert result["state"] == "measured"
    assert result["readings"]["temperature"]["value"] == 0.0
    assert result["readings"]["temperature"]["availability"] == "available"
    assert result["readings"]["rx_power"] == {**result["readings"]["rx_power"], "value": None, "availability": "not_applicable"}
    assert result["readings"]["tx_bias_current"]["availability"] == "undefined"
    assert result["readings"]["tx_bias_current"]["value"] is None
    json.dumps(result, allow_nan=False)


def test_derived_missing_metric_threshold_and_garbage_are_partial():
    lines = _read("sample_a-port13.txt").splitlines(True)
    cut = "".join(line for line in lines if "Voltage" not in line and "3.10" not in line and "3.00" not in line)
    result = _optics().transceiver(cut, "13")
    assert result["state"] == "partial" and "voltage" in result["missing_fields"]
    assert result["readings"]["voltage"]["availability"] == "missing"
    assert result["readings"]["tx_power"]["value"] == -5.29
    broken = _optics().transceiver(_derived(**{"High Warn Threshold  :  70.00": "High Warn Threshold  :  xx"}), "13")
    assert broken["state"] == "partial" and "temperature.high_warn" in broken["missing_fields"]
    assert broken["readings"]["temperature"]["thresholds"]["high_warn"] is None
    unit = _optics().transceiver(_derived(**{":  53.58 ": ":  53.58C"}), "13")
    assert unit["state"] == "partial" and "temperature.value" in unit["missing_fields"] and unit["readings"]["temperature"]["value"] is None
    for bad in ("nan", "inf"):
        assert math.isfinite(_optics().transceiver(_derived(**{":  53.58 ": f":  {bad} "}), "13")["readings"]["temperature"]["value"] or 0)


def test_derived_duplicate_header_metric_and_unknown_are_not_guessed():
    text = _read("sample_a-port13.txt")
    assert _optics().transceiver(text + text, "13")["state"] == "unparsed"
    block = text.split("Tx Power")[1]
    dup = text + "\n    Tx Power" + block
    assert _optics().transceiver(dup, "13")["state"] == "unparsed"
    assert _optics().transceiver("", "13")["state"] == "empty"
    assert _optics().transceiver("something else\n", "13")["state"] == "unparsed"


def test_derived_temperature_variants():
    text = _read("sample_a-temperature.txt")
    zero = _optics().environment(text.replace("79.00", " 0.00"))
    assert zero["temperatures"][0]["value"] == 0.0 and zero["state"] == "measured"
    assert _optics().environment("")["state"] == "empty"
    assert _optics().environment("garbage\n")["state"] == "unparsed"
    header_only = "\n".join(text.splitlines()[:2]) + "\n"
    assert _optics().environment(header_only)["state"] == "unparsed"
    bad = _optics().environment(text + "Fan : weird row\n")
    assert bad["state"] == "partial" and bad["missing_fields"]
    assert bad["temperatures"][0]["value"] == 79.0


# --- public proxy path: Proxy.request -> TargetAuth.decode -> engine.ssh_read -> real catalog/parser; fake SSH transport only ---
def _gateway(tmp_path, monkeypatch, outputs, rc=0):
    import test_proxy_contracts as contracts
    from netops_helper import engine
    module = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(module, tmp_path)
    section = contracts._section()
    section.update(ssh_platform="exos", device_types=["switch"], enabled_queries=["interface_transceiver", "temperature"],
                   read_inventory={"interfaces": ["13", "14"], "services": [], "addresses": [], "switches": []})
    section["egress"]["tcp_ports"].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, "exos")))
    gateway = module.Proxy()
    calls = []

    def transport(auth, platform, command, **kwargs):
        calls.append(command)
        if command == "show version":
            return 0, (HERE / "fixtures/identity/extreme_exos.txt").read_text()
        return rc, outputs[command]
    monkeypatch.setattr(engine, "_exec_read", transport)
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)
    engine._SSH_PAGE_CACHE.clear()
    return contracts, gateway, calls


def _ssh_read(contracts, gateway, index, **arguments):
    from netops_helper import engine
    from netops_helper.auth import TargetAuth
    forwarded = gateway.request(contracts._request(index, "ssh_read", {"target": "device-a", "platform": "extreme_exos", **arguments}))
    assert forwarded is not None
    args = json.loads(forwarded)["params"]["arguments"]
    auth = TargetAuth.decode(args["target"], args["auth_context"])
    return engine.ssh_read(auth, args["platform"], args["query"], args.get("parameters"), args.get("offset", 0),
                           args.get("max_bytes", 48_000), args.get("content_sha256"))


@pytest.mark.parametrize("sample", ["a", "b"])
def test_public_ssh_read_positive_dom(tmp_path, monkeypatch, sample):
    text = _read(f"sample_{sample}-port13.txt")
    contracts, gateway, calls = _gateway(tmp_path, monkeypatch, {"show ports 13 transceiver information detail": text})
    answer = _ssh_read(contracts, gateway, 1, query="interface_transceiver", parameters={"interface": "13"}, offset=0)
    assert answer["ok"] is True, answer
    assert "optics" in answer and answer["optics"]["state"] == "measured"
    assert answer["optics"]["readings"]["temperature"]["value"] == EXPECTED[sample]["temperature"]
    assert answer["optics"]["readings"]["tx_power"]["value"] == EXPECTED[sample]["tx_power"]
    assert "Temp (Celsius)" in answer["untrusted_device_output"] and answer["complete"] is True
    assert calls.count("show ports 13 transceiver information detail") == 1


def test_public_ssh_read_no_module_and_temperature(tmp_path, monkeypatch):
    outputs = {"show ports 14 transceiver information detail": _read("sample_a-port14.txt"),
               "show temperature": _read("sample_a-temperature.txt")}
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, outputs)
    absent = _ssh_read(contracts, gateway, 1, query="interface_transceiver", parameters={"interface": "14"}, offset=0)
    assert absent["ok"] and absent["optics"] == {"state": "not_present", "interface": "14", "readings": {}, "missing_fields": []}
    temp = _ssh_read(contracts, gateway, 2, query="temperature", offset=0)
    assert temp["ok"] and temp["environment"]["state"] == "measured"
    assert temp["environment"]["temperatures"][0]["value"] == 79.0


def test_public_ssh_read_paged_snapshot_keeps_whole_capture_derivation(tmp_path, monkeypatch):
    text = _read("sample_a-port13.txt")
    contracts, gateway, calls = _gateway(tmp_path, monkeypatch, {"show ports 13 transceiver information detail": text})
    first = _ssh_read(contracts, gateway, 1, query="interface_transceiver", parameters={"interface": "13"}, offset=0, max_bytes=1000)
    assert first["ok"] and not first["complete"] and first["optics"]["state"] == "measured"
    second = _ssh_read(contracts, gateway, 2, query="interface_transceiver", parameters={"interface": "13"},
                       offset=first["next_offset"], max_bytes=1000, content_sha256=first["content_sha256"])
    assert second["pagination_source"] == "cached" and second["optics"] == first["optics"]
    assert second["content_sha256"] == first["content_sha256"]
    assert calls.count("show ports 13 transceiver information detail") == 1


def test_public_ssh_read_other_platform_and_cli_error_have_no_optics(tmp_path, monkeypatch):
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show temperature": "%% Invalid input detected at '^' marker.\n"}, rc=1)
    answer = _ssh_read(contracts, gateway, 1, query="temperature", offset=0)
    assert not answer["ok"] and "environment" not in answer
    from netops_helper import optics
    assert optics.payload("cisco_ios", "temperature", "x", {}) == {}
