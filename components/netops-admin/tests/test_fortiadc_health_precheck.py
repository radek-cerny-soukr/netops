from __future__ import annotations

import json
from pathlib import Path

import pytest
from fake_fortiadc import CHECK_ACCOUNT_REFUSAL, FakeFortiADC

from types import SimpleNamespace

from netops_admin import access, cli, fortiadc
from netops_admin.errors import Rejected
from netops_core import ssh

REFUSED = CHECK_ACCOUNT_REFUSAL
MEASURED_VS_STAT = (Path(__file__).with_name("fortiadc_vs_stat_767_0676.txt")).read_text()


def only_member_one_is_healthy(device):
    device.health["vs-a"] = {1: "UP", 2: "UP", 3: "UP", 4: "DOWN"}
    device.pools["pool-a"][2]["status"] = "disable"
    device.pools["pool-a"][3]["status"] = "maintain"


def refused_untouched(device, caught):
    assert device.applied_blocks == []
    assert caught.value.reasons


def test_last_healthy_enabled_member_cannot_be_disabled():
    device = FakeFortiADC()
    only_member_one_is_healthy(device)
    with pytest.raises(Rejected) as caught:
        fortiadc.run(device, "pool-a", "1", "disable")
    refused_untouched(device, caught)
    assert "without a healthy enabled member" in caught.value.reasons[0]
    assert device.pools["pool-a"][1]["status"] == "enable"


def test_a_change_that_keeps_a_healthy_enabled_member_is_written_with_health_read_by_the_write_account():
    device = FakeFortiADC()
    result = fortiadc.run(device, "pool-a", "1", "disable")
    assert result["result"] == "confirmed"
    assert [command for command in device.queries if "vs_stat" in command] == [
        "diagnose server-load-balance vs_stat vdom root vs vs-a"]
    assert device.check_queries == []


def test_measured_vs_stat_of_767_0676_with_two_healthy_members_allows_disabling_one():
    device = FakeFortiADC()
    device.pools["pool-a"] = {1: {"real-server": "RS_A", "status": "enable", "pool_member_weight": "1"},
                              2: {"real-server": "RS_B", "status": "enable", "pool_member_weight": "1"}}
    device.vs_stat_text = MEASURED_VS_STAT
    assert fortiadc.run(device, "pool-a", "2", "disable")["result"] == "confirmed"
    assert device.pools["pool-a"][2]["status"] == "disable"


def test_measured_vs_stat_of_767_0676_refuses_disabling_the_last_enabled_member():
    device = FakeFortiADC()
    device.pools["pool-a"] = {1: {"real-server": "RS_A", "status": "disable", "pool_member_weight": "1"},
                              2: {"real-server": "RS_B", "status": "enable", "pool_member_weight": "1"}}
    device.vs_stat_text = MEASURED_VS_STAT
    with pytest.raises(Rejected) as caught:
        fortiadc.run(device, "pool-a", "2", "disable")
    refused_untouched(device, caught)
    assert "without a healthy enabled member" in caught.value.reasons[0]


def test_measured_vs_stat_of_767_0676_parses_both_members_up():
    assert fortiadc.parse_vs_stat(MEASURED_VS_STAT) == {1: "UP", 2: "UP"}


@pytest.mark.parametrize("text", [REFUSED, "", "\n\n", "availability: HEALTHY\n", "garbage line\n",
                                  "availability: HEALTHY\n id:1 hc_state:MAYBE\n",
                                  "availability: HEALTHY\n hc_state:UP\n",
                                  "availability: HEALTHY\n id:1 hc_state:UP\n id:1 hc_state:UP\n",
                                  "availability: HEALTHY\navailability: HEALTHY\n id:4 hc_state:UP\n",
                                  "availability: HEALTHY\n id:1 hc_state:UP\n id:4 hc_state:UP\nCommand fail. Return code is -284\n"])
def test_unreadable_or_refused_vs_stat_refuses_the_change(text):
    device = FakeFortiADC()
    device.vs_stat_text = text
    with pytest.raises(Rejected) as caught:
        fortiadc.run(device, "pool-a", "1", "disable")
    refused_untouched(device, caught)
    assert "health of the pool members cannot be read" in caught.value.reasons[0]


def test_failing_vs_stat_query_refuses_the_change():
    device = FakeFortiADC()
    device.vs_stat_error = True
    with pytest.raises(Rejected) as caught:
        fortiadc.run(device, "pool-a", "1", "disable")
    refused_untouched(device, caught)


def test_health_does_not_need_a_check_account():
    device = FakeFortiADC()
    bare = type("Bare", (), {"query": device.query, "diagnose_query": device.diagnose_query,
                             "apply": device.apply})()
    assert fortiadc.run(bare, "pool-a", "1", "disable")["result"] == "confirmed"


def test_down_members_do_not_count_as_healthy():
    device = FakeFortiADC()
    device.health["vs-a"][4] = "DOWN"
    device.pools["pool-a"][2]["status"] = "enable"
    device.health["vs-a"][2] = "DOWN"
    with pytest.raises(Rejected) as caught:
        fortiadc.run(device, "pool-a", "1", "disable")
    refused_untouched(device, caught)


def test_maintain_member_is_not_a_healthy_enabled_member():
    device = FakeFortiADC()
    only_member_one_is_healthy(device)
    with pytest.raises(Rejected):
        fortiadc.run(device, "pool-a", "1", "maintain")
    assert device.applied_blocks == []


def test_member_missing_from_vs_stat_is_not_healthy():
    device = FakeFortiADC()
    only_member_one_is_healthy(device)
    device.health["vs-a"] = {1: "UP", 2: "UP"}
    with pytest.raises(Rejected):
        fortiadc.run(device, "pool-a", "1", "disable")


def test_every_virtual_server_using_the_pool_is_evaluated():
    device = FakeFortiADC()
    device.virtual_servers["vs-c"] = {"load-balance-pool": "pool-a"}
    device.health["vs-c"] = {1: "UP", 2: "DOWN", 3: "DOWN", 4: "DOWN"}
    with pytest.raises(Rejected) as caught:
        fortiadc.run(device, "pool-a", "1", "disable")
    refused_untouched(device, caught)
    assert "vs-c" in caught.value.reasons[0]
    assert sorted(command for command in device.queries if "vs_stat" in command) == [
        fortiadc.vs_stat_command("vs-a"), fortiadc.vs_stat_command("vs-c")]


def test_virtual_servers_of_other_pools_are_not_read():
    device = FakeFortiADC()
    fortiadc.run(device, "pool-a", "1", "disable")
    assert fortiadc.vs_stat_command("vs-b") not in device.queries


@pytest.mark.parametrize("attributes", [{"content-routing": "enable", "load-balance-pool": "pool-a"},
                                        {"schedule-pool-list": "sp1"}])
def test_pool_selection_that_cannot_be_evaluated_refuses_the_change(attributes):
    device = FakeFortiADC()
    device.virtual_servers["vs-x"] = attributes
    device.health["vs-x"] = {1: "UP"}
    with pytest.raises(Rejected) as caught:
        fortiadc.run(device, "pool-a", "1", "disable")
    refused_untouched(device, caught)


def test_pool_used_by_no_virtual_server_refuses_the_change():
    device = FakeFortiADC()
    device.virtual_servers.pop("vs-a")
    with pytest.raises(Rejected) as caught:
        fortiadc.run(device, "pool-a", "1", "disable")
    refused_untouched(device, caught)


def test_unreadable_virtual_server_listing_refuses_the_change():
    device = FakeFortiADC()
    original = device.query

    def query(command):
        if command == fortiadc.VS_COMMAND:
            raise RuntimeError("down")
        return original(command)

    device.query = query
    with pytest.raises(Rejected):
        fortiadc.run(device, "pool-a", "1", "disable")
    assert device.applied_blocks == []


def test_enabling_a_member_is_checked_too():
    device = FakeFortiADC()
    device.vs_stat_text = REFUSED
    with pytest.raises(Rejected):
        fortiadc.run(device, "pool-a", "2", "enable")
    assert device.applied_blocks == []


def test_unchanged_state_needs_no_health_read():
    device = FakeFortiADC()
    device.vs_stat_text = REFUSED
    assert fortiadc.run(device, "pool-a", "1", "enable")["result"] == "unchanged"
    assert not any("vs_stat" in command for command in device.queries)


def test_health_source_is_one_replaceable_function(monkeypatch):
    device = FakeFortiADC()
    device.vs_stat_text = REFUSED
    monkeypatch.setattr(fortiadc, "read_health", lambda access, vs: {1: True, 4: True})
    assert fortiadc.run(device, "pool-a", "1", "disable")["result"] == "confirmed"
    assert not any("vs_stat" in command for command in device.queries)


def test_result_carries_no_vs_stat_output():
    device = FakeFortiADC()
    assert "hc_state" not in json.dumps(fortiadc.run(device, "pool-a", "1", "disable"))


def test_cli_reports_the_refusal_with_a_reason_and_writes_nothing(monkeypatch, capsys):
    from test_fortiadc_pool_member import cli_run
    device = FakeFortiADC()
    device.vs_stat_text = REFUSED
    code, document = cli_run(monkeypatch, capsys, device)
    assert (code, document["result"]) == (cli.EXIT_REJECTED, "rejected")
    assert "health of the pool members cannot be read" in json.dumps(document)
    assert device.applied_blocks == []


MEASURED_EXEC_STDOUT = b"FortiADC-KVM # \nFortiADC-KVM # "


def exec_access(monkeypatch, stdout=MEASURED_EXEC_STDOUT, stderr=MEASURED_VS_STAT.encode() + b"\n", rc=0):
    calls = []

    def run_command(address, port, login, credential, host_key_line, command, **options):
        calls.append((credential.login, command))
        return ssh.Result(rc=rc, stdout=stdout, said="", started_at="a", finished_at="b", stderr=stderr)

    monkeypatch.setattr(access.ssh, "run_command", run_command)
    handle = access.DeviceAccess.__new__(access.DeviceAccess)
    handle.device = SimpleNamespace(address="192.0.2.1", check_address=None, port=22,
                                    host_key_fingerprint="SHA256:x", legacy_ssh=None, platform="fortiadc")
    handle.credential = SimpleNamespace(login="admin")
    handle.check_credential = SimpleNamespace(login="netops-read")
    handle._host_key_lines = {"192.0.2.1": "192.0.2.1 ssh-ed25519 AAAA"}
    return handle, calls


def test_measured_exec_of_767_0676_answers_vs_stat_on_stderr_and_the_precheck_reads_it(monkeypatch):
    handle, calls = exec_access(monkeypatch)
    assert handle.query(fortiadc.vs_stat_command("VS_APP_HTTP")).strip() == ""
    assert fortiadc.read_health(handle, "VS_APP_HTTP") == {1: True, 2: True}
    assert calls[-1] == ("admin", "diagnose server-load-balance vs_stat vdom root vs VS_APP_HTTP")


def test_vs_stat_split_between_stdout_and_stderr_is_read_whole(monkeypatch):
    head, tail = MEASURED_VS_STAT.split("\treal-server-pool", 1)
    handle, _ = exec_access(monkeypatch, stdout=b"FortiADC-KVM # \n" + head.encode(),
                            stderr=b"\treal-server-pool" + tail.encode())
    assert fortiadc.read_health(handle, "VS_APP_HTTP") == {1: True, 2: True}


@pytest.mark.parametrize("stderr", [b"", REFUSED.encode(), b"garbage line\n",
                                    MEASURED_VS_STAT.encode() + REFUSED.encode()])
def test_vs_stat_on_stderr_that_is_empty_refused_or_unrecognised_refuses_the_health_read(monkeypatch, stderr):
    handle, _ = exec_access(monkeypatch, stderr=stderr)
    with pytest.raises(Rejected) as caught:
        fortiadc.read_health(handle, "VS_APP_HTTP")
    assert "health of the pool members cannot be read" in caught.value.reasons[0]


def test_vs_stat_on_stderr_cut_at_the_capture_limit_refuses_the_health_read(monkeypatch):
    padded = (MEASURED_VS_STAT.encode() + b"\n" + b"\t\t\tRequests: 0\n" * ssh.STDERR_MAX_BYTES)[:ssh.STDERR_MAX_BYTES]
    assert len(padded) == ssh.STDERR_MAX_BYTES
    assert fortiadc.parse_vs_stat(padded.decode()) == {1: "UP", 2: "UP"}
    handle, _ = exec_access(monkeypatch, stderr=padded)
    with pytest.raises(Rejected):
        fortiadc.read_health(handle, "VS_APP_HTTP")


def test_vs_stat_with_a_failing_exit_status_refuses_the_health_read(monkeypatch):
    handle, _ = exec_access(monkeypatch, rc=1)
    with pytest.raises(Rejected):
        fortiadc.read_health(handle, "VS_APP_HTTP")
