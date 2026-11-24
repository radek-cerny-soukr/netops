"""Error branches of config_read, each entered by a failure of the device side.

The device is the substituted OpenSSH client of tests/conftest.py, answering
each remote command from a table, so the stream passes through the real
netops_core SSH runner, the real stream redactor and the real FortiADC pager
normalizer. Outcomes such as a transport that already names a failure, a malformed
terminal frame or an exhausted snapshot store are injected at their boundaries.
Each test checks the caller-facing error and whether a snapshot was kept.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from conftest import FORTIADC_STATUS, PORT, _fortinet_wire, _target
from netops_helper import configuration
from netops_helper.auth import EgressPolicy
from netops_helper.config_limits import ConfigurationLimits
import netops_helper.engine as engine

STATUS = ("Version: FortiGate-VM64-KVM v7.6.8,build3744,260101 (GA)\n"
          "Virtual domain configuration: disable\n")
CONFIG = ("config system interface\n edit port1\n set ip 192.0.2.1 255.255.255.0\n next\nend\n")
SMALL = ConfigurationLimits(section_bytes=4096, all_bytes=4096, physical_line_bytes=1024,
                            logical_record_bytes=4096)
OVERSIZED = ("config system interface\n"
             + "".join(f" edit port{i}\n set alias fixture-value\n next\n" for i in range(400))
             + "end\n")
TIGHT = ConfigurationLimits(memory_bytes=1024 * 1024)
WITHHELD = "; output withheld"

@pytest.fixture(autouse=True)
def _no_snapshots():
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    yield
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


def _device(wire, answers: dict) -> None:
    typed = {}
    for command, (code, output) in answers.items():
        if code == 255:
            typed[command] = {"partial": output} if output else None
        elif code == 1:
            typed[command] = output + "Command fail. Return code -61\n"
        else:
            typed[command] = output + ("\n" if output and not output.endswith("\n") else "")
    _fortinet_wire(wire, typed)


def _fortios(limits: ConfigurationLimits = ConfigurationLimits()):
    return replace(_target("fortinet", "system_status"), read_inventory={"config_access": ("read",)},
                   egress=EgressPolicy(addresses=("127.0.0.1",), tcp_ports=(PORT,)),
                   configuration_limits=limits)


def _fortiadc():
    return replace(_target("fortiadc", "system_status"), read_inventory={"config_access": ("read",)},
                   egress=EgressPolicy(addresses=("127.0.0.1",), tcp_ports=(PORT,)))


def _minimal(auth, **options):
    return engine.config_read(auth, "fortios", "all", True, **options)


def _full(auth, platform="fortios", **options):
    return engine.config_read(auth, platform, "all", True, redaction="full", **options)


def _refused(call, message, kind=ValueError):
    with pytest.raises(kind) as caught:
        call()
    assert type(caught.value) is kind
    assert str(caught.value) == message
    assert caught.value.__cause__ is None
    return caught.value


def _lost(platform):
    """A configuration read whose terminal disconnected before a prompt."""
    return {"ok": False, "target": "wire-test", "platform": platform, "section": "all",
            "error_code": "disconnected", "error": engine._TRANSPORT_ADVICE["disconnected"]}


def _sent(wire) -> list[str]:
    return wire["transcript"].read_text().splitlines()


# minimal redaction


def test_minimal_identity_read_that_the_transport_loses_withholds_everything(wire) -> None:
    _device(wire, {"get system status": [255, ""]})
    assert _minimal(_fortios()) == _lost("fortios")
    assert _sent(wire) == ["get system status"]
    assert configuration._SNAPSHOTS == {}


def test_minimal_capture_beyond_the_byte_limit_is_withheld(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [0, OVERSIZED]})
    _refused(lambda: _minimal(_fortios(SMALL)), "configuration capture-limit-exceeded" + WITHHELD)
    assert _sent(wire) == ["get system status", "show"]
    assert configuration._SNAPSHOTS == {}


def test_minimal_capture_with_a_control_character_is_unverifiable(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [0, "config system global\n set alias a\x01b\nend\n"]})
    _refused(lambda: _minimal(_fortios()), "configuration redaction-unverifiable" + WITHHELD)
    assert configuration._SNAPSHOTS == {}


def test_minimal_capture_beyond_the_target_memory_limit_names_the_budget(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [0, CONFIG]})
    _refused(lambda: _minimal(_fortios(TIGHT)),
             "configuration memory budget exhausted for target" + WITHHELD, configuration.ConfigurationBudgetError)
    assert configuration._SNAPSHOTS == {}


def test_minimal_last_record_without_a_newline_is_still_held_to_the_memory_limit(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [0, "config system global"]})
    _refused(lambda: _minimal(_fortios(TIGHT)),
             "configuration memory budget exhausted for target" + WITHHELD, configuration.ConfigurationBudgetError)
    assert configuration._SNAPSHOTS == {}


def test_minimal_stream_that_ends_inside_a_block_is_not_stored(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [0, "config system global\n set alias x\n"]})
    _refused(lambda: _minimal(_fortios()), "configuration redaction-unverifiable" + WITHHELD)
    assert configuration._SNAPSHOTS == {}


def test_minimal_capture_the_device_refuses_with_an_exit_code_is_not_stored(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [1, ""]})
    _refused(lambda: _minimal(_fortios()), "configuration read failed" + WITHHELD)
    assert configuration._SNAPSHOTS == {}


def test_minimal_page_with_a_stale_filter_keeps_the_existing_snapshot(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [0, CONFIG]})
    auth = _fortios()
    first = _minimal(auth)
    snapshot = first["snapshot_id"]
    _refused(lambda: _minimal(auth, snapshot_id=snapshot, contains="port1",
                              content_sha256="0" * 64, filter_sha256="0" * 64),
             "configuration filter changed; restart at offset 0")
    assert list(configuration._SNAPSHOTS) == [snapshot]
    again = _minimal(auth, snapshot_id=snapshot)
    assert again["untrusted_device_output"] == first["untrusted_device_output"]
    assert _sent(wire) == ["get system status", "show"]


# full redaction


def test_full_identity_read_that_the_transport_loses_names_the_stage(wire) -> None:
    _device(wire, {"get system status": [255, ""]})
    assert _full(_fortios()) == _lost("fortios")
    assert _sent(wire) == ["get system status"]


def test_full_read_of_untested_firmware_returns_data_with_a_warning(wire) -> None:
    # STARTUP (2026-11-17): an untested build is read with the nearest field policy and a warning, not refused.
    status = STATUS.replace("v7.6.8,build3744", "v7.4.1,build2463")
    _device(wire, {"get system status": [0, status], "show": [0, CONFIG]})
    result = _full(_fortios())
    assert result["ok"] is True and "edit port1" in result["untrusted_device_output"]
    assert _sent(wire) == ["get system status", "show"]
    assert result["firmware_support"]["status"] == "untested"
    assert result["firmware_support"]["device_version"] == "7.4.1 build2463"
    assert result["firmware_support"]["tested_versions"] == ["7.6.8 build3744", "8.0.2 build0251"]
    assert result["policy_firmware"] == "7.6.8"
    assert result["warnings"] == [{"code": "firmware_untested", "message": result["firmware_support"]["message"]}]


def test_full_read_of_another_product_is_unverifiable(wire) -> None:
    status = STATUS.replace("FortiGate-VM64-KVM", "FortiADC-KVM")
    _device(wire, {"get system status": [0, status]})
    _refused(lambda: _full(_fortios()), "configuration identity-unverifiable" + WITHHELD)
    assert _sent(wire) == ["get system status"]


def test_full_read_of_an_ambiguous_identity_is_unverifiable(wire) -> None:
    _device(wire, {"get system status": [0, STATUS + STATUS]})
    _refused(lambda: _full(_fortios()), "configuration identity-unverifiable" + WITHHELD)
    assert _sent(wire) == ["get system status"]


def test_full_capture_beyond_the_byte_limit_is_withheld(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [0, OVERSIZED]})
    _refused(lambda: _full(_fortios(SMALL)), "configuration capture-limit-exceeded" + WITHHELD)
    assert configuration._SNAPSHOTS == {}


def test_full_capture_with_an_unparseable_line_names_the_line(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [0, "unexpected device banner\n" + CONFIG]})
    _refused(lambda: _full(_fortios()), "configuration redaction-unverifiable at line 1" + WITHHELD)
    assert configuration._SNAPSHOTS == {}


def test_full_capture_that_the_transport_loses_names_the_stage(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [255, ""]})
    assert _full(_fortios()) == _lost("fortios")
    assert configuration._SNAPSHOTS == {}


def test_full_capture_the_device_refuses_with_an_exit_code_names_the_stage(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [1, ""]})
    _refused(lambda: _full(_fortios()), "configuration device-refused during capture" + WITHHELD)
    assert configuration._SNAPSHOTS == {}


def test_fortiadc_capture_that_ends_inside_a_pager_prompt_is_incomplete(wire) -> None:
    _device(wire, {"get system status": [0, FORTIADC_STATUS],
                   "show": [255, "config system global\n    set hostname ADC-LAB\nend\n--Mo"]})
    _refused(lambda: _full(_fortiadc(), "fortiadc"), "configuration stream-incomplete" + WITHHELD)
    assert configuration._SNAPSHOTS == {}


def test_full_page_with_a_stale_filter_keeps_the_existing_snapshot(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [0, CONFIG]})
    auth = _fortios()
    first = _full(auth)
    snapshot = first["snapshot_id"]
    _refused(lambda: _full(auth, snapshot_id=snapshot, contains="port1",
                           content_sha256="0" * 64, filter_sha256="0" * 64),
             "configuration filter changed; restart at offset 0")
    assert list(configuration._SNAPSHOTS) == [snapshot]
    again = _full(auth, snapshot_id=snapshot)
    assert again["untrusted_device_output"] == first["untrusted_device_output"]
    assert _sent(wire) == ["get system status", "show"]


# outcomes the wire cannot produce, injected at the engine seam


def _identity_then(failure):
    def read(auth, platform, command, **kwargs):
        if command == "get system status":
            return 0, STATUS
        raise failure
    return read


def test_full_capture_keeps_a_budget_refusal_raised_by_the_transport(wire, monkeypatch) -> None:
    refusal = configuration.ConfigurationBudgetError("configuration memory budget exhausted" + WITHHELD)
    monkeypatch.setattr(engine, "read_from_device", _identity_then(refusal))
    caught = _refused(lambda: _full(_fortios()), "configuration memory budget exhausted" + WITHHELD,
                      configuration.ConfigurationBudgetError)
    assert caught is refusal
    assert configuration._SNAPSHOTS == {}


def test_full_capture_from_a_runner_that_also_accumulated_stdout_is_unverifiable(wire, monkeypatch) -> None:
    monkeypatch.setattr(engine, "read_from_device", _identity_then(
        ValueError("streaming transport returned unexpected accumulated output")))
    _refused(lambda: _full(_fortios()), "configuration redaction-unverifiable" + WITHHELD)
    assert configuration._SNAPSHOTS == {}


def test_full_capture_that_runs_out_of_memory_while_storing_is_not_kept(wire, monkeypatch) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [0, CONFIG]})

    def store(*args, **kwargs):
        raise MemoryError()

    monkeypatch.setattr(configuration, "store", store)
    _refused(lambda: _full(_fortios()), "configuration capture-failed" + WITHHELD)
    assert configuration._SNAPSHOTS == {}


def test_minimal_capture_keeps_a_budget_refusal_raised_by_the_transport(wire, monkeypatch):
    refusal = configuration.ConfigurationBudgetError("configuration memory budget exhausted" + WITHHELD)
    monkeypatch.setattr(engine, "read_from_device", _identity_then(refusal))
    caught = _refused(lambda: _minimal(_fortios()), str(refusal), configuration.ConfigurationBudgetError)
    assert caught is refusal
    assert not configuration._SNAPSHOTS


def test_full_capture_unexpected_transport_error_withholds_exception_text(wire, monkeypatch):
    monkeypatch.setattr(engine, "read_from_device", _identity_then(RuntimeError("fixture private detail")))
    _refused(lambda: _full(_fortios()), "configuration transport-failed during capture" + WITHHELD)
    assert not configuration._SNAPSHOTS


def test_fortiadc_stream_that_ends_inside_pager_is_incomplete_after_successful_transport(wire, monkeypatch):
    def read(auth, platform, command, *, stdout_consumer=None):
        if command == "get system status":
            return 0, FORTIADC_STATUS
        stdout_consumer(CONFIG.encode() + b"--Mor")
        return 0, ""

    monkeypatch.setattr(engine, "read_from_device", read)
    with pytest.raises(ValueError, match=r"configuration stream-incomplete.*output withheld"):
        _full(_fortiadc(), "fortiadc")
    assert not configuration._SNAPSHOTS


@pytest.mark.parametrize("closing_prompt, expected", [
    (b"fixture-fortinet # ", "capture-limit-exceeded"),
    (b"fixture-fortinet # \r", "redaction-unverifiable"),
])
def test_adc_capture_checks_final_transport_frame(wire, monkeypatch, closing_prompt, expected):
    from contextlib import contextmanager
    from pathlib import Path

    sample = Path(__file__).parent / "fixtures/fortiadc_adc_health/profile.out"
    lines = sample.read_text().splitlines(keepends=True)
    data = lines[0].partition("# ")[2].encode() + "".join(lines[1:-1]).encode()
    opening_prompt = b"fixture-fortinet # "
    if expected == "capture-limit-exceeded":
        remaining = SMALL.all_bytes - len(opening_prompt) - len(data)
        data += b"\n" * remaining

    class Terminal:
        _last_prompt = opening_prompt

        def run(self, command, *, stdout_consumer, **kwargs):
            if command == "get system status":
                return engine.core_session.FortinetResult(0, FORTIADC_STATUS.encode(), "", "", "")
            assert command == "show full-configuration load-balance profile LB_PROF_TCP"
            stdout_consumer(data)
            self._last_prompt = closing_prompt
            return engine.core_session.FortinetResult(0, b"", "", "", "")

    closed = []

    @contextmanager
    def open_terminal(*args, **kwargs):
        try:
            yield Terminal()
        finally:
            closed.append(True)

    monkeypatch.setattr(engine.core_session, "fortinet_session", open_terminal)
    auth = replace(_fortiadc(), configuration_limits=SMALL)
    with pytest.raises(ValueError, match=expected + WITHHELD):
        engine.config_read(auth, "fortiadc", "load-balance profile LB_PROF_TCP",
                           redaction="full", include_defaults=True)
    assert closed == [True] and not configuration._SNAPSHOTS
