"""FOS-13 modem query via proxy policy, authorization and the real Helper reader."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from netops_core import ssh
from netops_core.audit import Recorder
from netops_helper import audit, engine, proxy
from netops_helper.auth import TargetAuth
from test_fortios_ipv6_lookup import real as fortigate_capture
import test_proxy_contracts as c


FIXTURES = Path(__file__).parent / "fixtures/real/fortios/fortiextender_modem_g15"
QUERY = "extender_modem_status"
SERIAL = "FX211E0000000000"
COMMAND = f"get extender modem-status {SERIAL}"
LEGACY = (FIXTURES / "modem-fortios-54.out").read_text()
MODERN_EXCERPT = (FIXTURES / "modem-fortios-80-excerpt.out").read_text()


@pytest.fixture
def wire(tmp_path, monkeypatch):
    inventory, _, _, _ = c._configure(proxy, tmp_path)
    cfg = c._section()
    cfg.update(enabled_queries=[QUERY], device_types=["firewall"])
    c._write(inventory, c._inventory(c._device(cfg)))
    monkeypatch.setattr(audit, "_RECORDER", Recorder(tmp_path / "audit.jsonl", "helper"))
    monkeypatch.setattr(engine, "record", audit.record)
    monkeypatch.setattr(engine, "host_key_line", lambda *_args: "pinned-fixture-key")
    sent, emitted = [], []
    handle = proxy.Proxy()
    handle._emit = emitted.append

    def run(text, *, rc=0, serial=SERIAL):
        def response(auth, address, key, credential, command, platform, stdout_consumer=None):
            sent.append(command)
            assert address == "192.0.2.10" and key == "pinned-fixture-key"
            assert auth.enabled_queries == (QUERY,) and platform == "fortinet" and credential.use() == c.DEVICE_SECRET
            if command == "get system status":
                return ssh.Result(0, fortigate_capture("01-version.txt").encode(), "", "", "")
            assert command == COMMAND
            return ssh.Result(rc, text.encode(), "", "", "")

        monkeypatch.setattr(engine, "_exec_command", response)
        forwarded = handle.request(c._request(1, "ssh_read", {
            "target": "device-a", "platform": "fortinet", "query": QUERY, "parameters": {"serial": serial},
        }))
        if forwarded is None:
            return None
        args = json.loads(forwarded)["params"]["arguments"]
        context = args.pop("auth_context")
        auth = TargetAuth.decode(args.pop("target"), context)
        values = args.pop("redaction_context", None)
        if values is not None:
            auth = replace(auth, output_secrets=tuple(dict.fromkeys((context, *values))))
        return engine.ssh_read(auth, **{"platform": args["platform"], "query": args["query"],
                                      "parameters": args["parameters"], "offset": 0, "max_bytes": 16000})

    return run, sent, emitted


def test_modem_projection_keeps_signal_and_redacts_subscriber_identifiers(wire):
    run, sent, _ = wire
    # Derived from the published output, with synthetic values for redaction coverage.
    canaries = ("351111111111113", "222", "8911111111111111111", "+420 700 111 234")
    text = LEGACY.replace("imsi: <REDACTED>", "imsi: " + canaries[0]).replace(
        "esn_imei: <REDACTED>", f"esn_imei: {canaries[1]}\nICCID: {canaries[2]}\nPhone Number: {canaries[3]}")
    result = run(text)
    assert sent == ["get system status", COMMAND]
    assert result["ok"] and result["complete"] and result["status"] == "ok", result
    assert result["firmware_support"]["status"] == "untested"
    data = result["fortiextender_modem"]
    assert data["identifiers_redacted"]
    assert data["modems"][0]["connection_status"] == "connected"
    assert data["modems"][0]["rssi"] == {"value": -68, "unit": "dBm"}
    assert data["modems"][0]["signal_strength"]["value"] == 73
    assert not any(value in json.dumps(result) for value in canaries)


@pytest.mark.parametrize("text", [MODERN_EXCERPT, LEGACY.rsplit("usb_wan_mac", 1)[0],
                                  LEGACY + "--More--", LEGACY + "\nUnrecognized: 8911111111111111111",
                                  ""])
def test_truncated_and_unknown_output_is_incomplete(wire, text):
    run, _, _ = wire
    result = run(text)
    assert result["status"] == "incomplete" and not result["complete"]
    assert "8911111111111111111" not in json.dumps(result)


def test_fortios_refusal_does_not_relay_device_text(wire):
    run, _, _ = wire
    result = run("Unknown action 0\nPhone Number: +420 700 111 234\n", rc=1)
    assert not result["ok"] and not result["complete"] and result["status"] == "incomplete", result
    assert result["error_code"] == "device_cli_error"
    assert "+420" not in json.dumps(result)


def test_modem_serial_is_checked_before_transport(wire):
    run, sent, emitted = wire
    assert run(LEGACY, serial=SERIAL + " | extra") is None
    assert not sent and emitted
