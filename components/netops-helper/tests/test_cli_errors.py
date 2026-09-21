import json

import pytest

from conftest import EXEC_CLIENT, PASSWORD, _plain_query, _target, _write_client
import netops_helper.engine as engine


@pytest.mark.parametrize("platform,output,code", [
    ("fortinet", "Command fail. Return code -7622\n", 0),
    ("fortinet", "command parse error before 'status'\n", 0),
    ("fortinet", "Unknown action 0\n", 0),
    ("extreme_exos", "This user does not have permissions for this command.\n", 254),
    ("extreme_exos", "%% Invalid input detected at '^' marker.\n", 254),
])
def test_cli_refusal_is_failed_without_caching_and_valid_next_read_works(wire, monkeypatch, platform, output, code):
    events = []
    monkeypatch.setattr(engine, "record", lambda event, **fields: events.append(fields))
    query, _ = _plain_query(platform)
    target = _target(platform, query)
    payload = "x" * 2000 + "\n" + output + PASSWORD
    _write_client(wire["binaries"], "ssh", EXEC_CLIENT.format(log=str(wire["log"]), output=payload, code=code))
    answer = engine.ssh_read(target, platform, query, {}, 0, 1000)
    assert answer["ok"] is False
    assert answer["rc"] == code
    assert answer["error_code"] == "device_cli_error"
    assert PASSWORD not in json.dumps(answer)
    assert events[-1]["status"] == "failed"
    assert not engine._SSH_PAGE_CACHE
    _write_client(wire["binaries"], "ssh", EXEC_CLIENT.format(log=str(wire["log"]), output="Version: valid\n", code=0))
    answer = engine.ssh_read(target, platform, query, {}, 0, 1000)
    assert answer["ok"] is True
    assert events[-1]["status"] == "ok"


@pytest.mark.parametrize("platform,output,code", [
    ("extreme_exos", "VLAN Interface with name Users created by user\n802.1Q Tag 10\n", 250),
    ("fortinet", "Errors: 0\nLast error: Command fail. Return code -61\n", 0),
    ("linux", "Command fail. Return code -61\n", 0),
])
def test_device_specific_classifier_preserves_valid_status_and_data(wire, platform, output, code):
    _write_client(wire["binaries"], "ssh", EXEC_CLIENT.format(log=str(wire["log"]), output=output, code=code))
    query, _ = _plain_query(platform)
    answer = engine.ssh_read(_target(platform, query), platform, query, {}, 0, 1000)
    assert answer["ok"] is True
    assert answer["rc"] == code
    assert answer["untrusted_device_output"] == output
