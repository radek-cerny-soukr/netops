"""Error branches of config_read, each entered by a failure of the device side.

The device is the substituted OpenSSH client of tests/conftest.py, answering
each remote command from a table, so the stream passes through the real
netops_core SSH runner, the real stream redactor and the real FortiADC pager
normalizer. Only the three outcomes that this wire cannot produce (a transport
that already names the failure category, a streaming runner that also
accumulates stdout, and running out of memory while storing the snapshot) are
injected at the engine seam. Each test checks the exact error the caller
receives and whether a snapshot was kept.
"""

from __future__ import annotations

from dataclasses import replace
import json

import pytest

from conftest import FORTIADC_STATUS, PORT, _calls, _target, _write_client
from netops_helper import configuration
from netops_helper.auth import EgressPolicy
from netops_helper.config_limits import ConfigurationLimits
import netops_helper.engine as engine

STATUS = ("Version: FortiGate-VM64-KVM v7.6.8,build3744,260101 (GA)\n"
          "Virtual domain configuration: disable\n")
CONFIG = ("config system interface\n edit port1\n set ip 192.0.2.1 255.255.255.0\n next\nend\n")
SMALL = ConfigurationLimits(section_bytes=4096, all_bytes=4096, physical_line_bytes=1024,
                            logical_record_bytes=4096)
OVERSIZED = "config system global\n" + " set alias fixture-value\n" * 400 + "end\n"
TIGHT = ConfigurationLimits(memory_bytes=1024 * 1024)
WITHHELD = "; output withheld"

ANSWER_CLIENT = '''#!/usr/bin/env python3
import json, sys

with open({log!r}, "a") as handle:
    handle.write(json.dumps({{"argv": sys.argv[1:]}}) + "\\n")
with open({answers!r}) as handle:
    answers = json.load(handle)
code, output = answers[sys.argv[-1]]
sys.stdout.buffer.write(output.encode("utf-8"))
sys.stdout.flush()
sys.exit(code)
'''


@pytest.fixture(autouse=True)
def _no_snapshots():
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    yield
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


def _device(wire, answers: dict) -> None:
    path = wire["log"].parent / "answers.json"
    path.write_text(json.dumps(answers), encoding="utf-8")
    _write_client(wire["binaries"], "ssh", ANSWER_CLIENT.format(log=str(wire["log"]), answers=str(path)))


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


def _sent(wire) -> list[str]:
    return [call["argv"][-1] for call in _calls(wire) if "env" not in call]


# minimal redaction


def test_minimal_identity_read_that_the_transport_loses_withholds_everything(wire) -> None:
    _device(wire, {"get system status": [255, ""]})
    _refused(lambda: _minimal(_fortios()), "configuration identity read failed" + WITHHELD)
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
    _refused(lambda: _minimal(_fortios()), "configuration read failed" + WITHHELD)
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
    _refused(lambda: _full(_fortios()), "configuration transport-failed during identity read" + WITHHELD)
    assert _sent(wire) == ["get system status"]


def test_full_read_of_unsupported_firmware_names_detected_and_supported_builds(wire) -> None:
    status = STATUS.replace("v7.6.8,build3744", "v7.4.1,build2463")
    _device(wire, {"get system status": [0, status]})
    _refused(lambda: _full(_fortios()),
             "configuration firmware-not-supported for fortios; detected 7.4.1 build 2463; "
             "supported 7.6.8 build 3744, 8.0.2 build 0251" + WITHHELD)
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
    _refused(lambda: _full(_fortios()), "configuration transport-failed during capture" + WITHHELD)
    assert configuration._SNAPSHOTS == {}


def test_full_capture_the_device_refuses_with_an_exit_code_names_the_stage(wire) -> None:
    _device(wire, {"get system status": [0, STATUS], "show": [1, ""]})
    _refused(lambda: _full(_fortios()), "configuration device-refused during capture" + WITHHELD)
    assert configuration._SNAPSHOTS == {}


def test_fortiadc_capture_that_ends_inside_a_pager_prompt_is_incomplete(wire) -> None:
    _device(wire, {"get system status": [0, FORTIADC_STATUS],
                   "show": [0, "config system global\n    set hostname ADC-LAB\nend\n--Mo"]})
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
