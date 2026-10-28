from __future__ import annotations

import itertools
import json

import pytest
from fake_fortiadc import FakeFortiADC

from netops_admin import cli, fortiadc
from netops_admin.errors import Rejected

STATUSES = ("enable", "disable", "maintain")
BLOCK = ["config load-balance pool", 'edit "pool-a"', "config pool_member", "edit 1", "set status %s",
         "next", "end", "next", "end"]


def status_of(device, pool="pool-a", member=1):
    return device.pools[pool][member]["status"]


def block(status):
    return [line % status if "%s" in line else line for line in BLOCK]


@pytest.mark.parametrize(("start", "wanted"), [(a, b) for a, b in itertools.permutations(STATUSES, 2)])
def test_state_change_is_written_in_one_block_and_confirmed(start, wanted):
    device = FakeFortiADC()
    device.pools["pool-a"][1]["status"] = start
    result = fortiadc.run(device, "pool-a", "1", wanted)
    assert result["result"] == "confirmed"
    assert (result["before"], result["after"], result["requested"]) == (start, wanted, wanted)
    assert device.applied_blocks == [block(wanted)]
    assert status_of(device) == wanted


@pytest.mark.parametrize("state", STATUSES)
def test_same_state_writes_nothing(state):
    device = FakeFortiADC()
    device.pools["pool-a"][1]["status"] = state
    result = fortiadc.run(device, "pool-a", "1", state)
    assert result["result"] == "unchanged"
    assert device.applied_blocks == []
    assert fortiadc.exit_code(result) == 0


def test_only_status_of_the_named_member_changes():
    device = FakeFortiADC()
    others = json.dumps({k: v for k, v in device.pools.items()}, sort_keys=True)
    fortiadc.run(device, "pool-a", "2", "maintain")
    expected = json.loads(others)
    expected["pool-a"]["2"]["status"] = "maintain"
    assert json.loads(json.dumps(device.pools, sort_keys=True)) == expected
    assert all(line.startswith(("config", "edit", "set status", "next", "end")) for line in device.applied_blocks[0])


def test_absent_status_in_show_means_enable():
    device = FakeFortiADC()
    assert "set status" not in device.query("show load-balance pool pool-a").split("edit 1")[1].split("next")[0]
    assert fortiadc.run(device, "pool-a", "1", "enable")["result"] == "unchanged"
    assert fortiadc.run(device, "pool-a", "1", "disable")["before"] == "enable"


def test_default_shown_explicitly_is_read_the_same():
    device = FakeFortiADC()
    device.show_default = True
    assert fortiadc.run(device, "pool-a", "1", "enable")["result"] == "unchanged"


def test_prompt_anchor_uses_the_hostname_of_the_device():
    device = FakeFortiADC(hostname="adc-two")
    fortiadc.run(device, "pool-a", "1", "disable")
    assert device.specs[0].anchor == b"\nadc-two"


def test_ignored_write_is_reported_and_state_stays_original():
    device = FakeFortiADC()
    device.ignore_writes = True
    result = fortiadc.run(device, "pool-a", "1", "disable")
    assert (result["result"], result["after"], fortiadc.exit_code(result)) == ("rolled_back", "enable", 4)
    assert status_of(device) == "enable"


@pytest.mark.parametrize("bad", ['set status "enable', 'set status enable"', 'set status ""enable""', 'set status "en"able'])
def test_ignored_write_with_malformed_readback_is_never_confirmed(bad):
    device = FakeFortiADC()
    device.ignore_writes = True
    device.garbage_after_apply = ('config load-balance pool\n edit "pool-a"\n  config pool_member\n   edit 2\n'
                                  '    %s\n   next\n  end\n next\nend\n' % bad)
    result = fortiadc.run(device, "pool-a", "2", "enable")
    assert (result["result"], fortiadc.exit_code(result)) == ("unknown", 7)
    assert status_of(device, member=2) == "disable"


def test_quoted_values_with_spaces_are_read():
    device = FakeFortiADC()
    device.garbage = ('config load-balance pool\n edit "pool-a"\n  set comments "two words \\" here"\n'
                      '  config pool_member\n   edit 1\n    set status "maintain"\n   next\n  end\n next\nend\n')
    result = fortiadc.run(device, "pool-a", "1", "maintain")
    assert (result["result"], result["before"]) == ("unchanged", "maintain")


def test_readback_mismatch_restores_original_state():
    device = FakeFortiADC()
    device.coerce = {"maintain": "disable"}
    result = fortiadc.run(device, "pool-a", "1", "maintain")
    assert (result["result"], fortiadc.exit_code(result)) == ("rolled_back", 4)
    assert (result["before"], result["after"]) == ("enable", "enable")
    assert device.applied_blocks == [block("maintain"), block("enable")]
    assert status_of(device) == "enable"


def test_refused_write_with_partial_effect_restores_original_state():
    device = FakeFortiADC()
    device.fail_after_write = {1}
    result = fortiadc.run(device, "pool-a", "1", "disable")
    assert (result["result"], status_of(device)) == ("rolled_back", "enable")
    assert device.applied_blocks == [block("disable"), block("enable")]


def test_refused_write_without_effect_needs_no_second_write():
    device = FakeFortiADC()
    device.refuse_apply = {1}
    result = fortiadc.run(device, "pool-a", "1", "disable")
    assert (result["result"], status_of(device)) == ("rolled_back", "enable")
    assert device.applied_blocks == [block("disable")]


def test_failed_restore_is_unknown():
    device = FakeFortiADC()
    device.coerce = {"maintain": "disable"}
    device.refuse_apply = {2}
    result = fortiadc.run(device, "pool-a", "1", "maintain")
    assert (result["result"], fortiadc.exit_code(result)) == ("unknown", 7)
    assert status_of(device) == "disable"


def test_unreadable_readback_restores_and_stays_unknown_when_still_unreadable():
    device = FakeFortiADC()
    device.unreadable_after_apply = True
    result = fortiadc.run(device, "pool-a", "1", "disable")
    assert (result["result"], fortiadc.exit_code(result)) == ("unknown", 7)
    assert device.applied_blocks == [block("disable"), block("enable")]


@pytest.mark.parametrize(("pool", "member"), [("pool-x", "1"), ("pool-a", "9"), ("pool-b", "2")])
def test_unknown_pool_or_member_is_rejected_without_write(pool, member):
    device = FakeFortiADC()
    with pytest.raises(Rejected):
        fortiadc.run(device, pool, member, "disable")
    assert device.applied_blocks == []


def test_unreadable_state_before_write_is_rejected_without_write():
    device = FakeFortiADC()
    device.unreadable = True
    with pytest.raises(Rejected) as caught:
        fortiadc.run(device, "pool-a", "1", "disable")
    assert device.applied_blocks == [] and "RuntimeError" not in " ".join(caught.value.reasons)


@pytest.mark.parametrize("text", [
    "", "config load-balance pool\n", "config load-balance pool\n    edit \"pool-a\"\n",
    "end\n", "entry is not found in table\n",
    'config load-balance pool\n edit "pool-a"\n  config pool_member\n   edit 1\n    set status sleeping\n   next\n  end\n next\nend\n',
    'config load-balance pool\n edit "pool-a"\n  config pool_member\n   edit 1\n   next\n   edit 1\n   next\n  end\n next\nend\n',
    'config load-balance pool\n edit "pool-a"\n  config pool_member\n   edit 1\n    set status "enable\n   next\n  end\n next\nend\n',
    'config load-balance pool\n edit "pool-a"\n  config pool_member\n   edit 1"\n   next\n  end\n next\nend\n',
    'config load-balance pool\n edit """pool-a"""\n  config pool_member\n   edit 1\n   next\n  end\n next\nend\n',
    'config load-balance pool\n edit "pool-a\n  config pool_member\n   edit 1\n   next\n  end\n next\nend\n',
    'config load-balance pool\n edit "pool-a" x\n  config pool_member\n   edit 1\n   next\n  end\n next\nend\n',
])
def test_malformed_show_is_rejected_without_write(text):
    device = FakeFortiADC()
    device.garbage = text
    with pytest.raises(Rejected):
        fortiadc.run(device, "pool-a", "1", "disable")
    assert device.applied_blocks == []


@pytest.mark.parametrize(("pool", "member", "status"), [
    ("pool-a", "1", "disabled"), ("pool-a", "1", "ENABLE"), ("pool-a", "1", ""), ("pool-a", "1", "enable\nend"),
    ("pool-a", "0", "enable"), ("pool-a", "01", "enable"), ("pool-a", "1;2", "enable"), ("pool-a", "1 2", "enable"),
    ("pool-a", "9999999999", "enable"), ("pool-a", "", "enable"),
    ('pool-a"', "1", "enable"), ("pool a", "1", "enable"), ("pool-a\nend", "1", "enable"), ("", "1", "enable"),
    ("-pool", "1", "enable"), ("p" * 64, "1", "enable"),
])
def test_invalid_input_is_rejected_before_any_device_contact(pool, member, status):
    device = FakeFortiADC()
    with pytest.raises(Rejected):
        fortiadc.run(device, pool, member, status)
    assert device.queries == [] and device.applied_blocks == []


def test_hostname_missing_is_rejected_without_write():
    device = FakeFortiADC(hostname="bad host")
    with pytest.raises(Rejected):
        fortiadc.run(device, "pool-a", "1", "disable")
    assert device.applied_blocks == []


@pytest.mark.parametrize(("text", "found"), [
    ("Command fail. Return code -1", True), ("command parse error before 'x'", True),
    ("Unknown action 0", True), ("Value parse error", True), ("adc-lab (pool_member) # ", False), ("", False),
])
def test_cli_error_recognises_refusals(text, found):
    assert (fortiadc.cli_error(text) is not None) is found


def test_result_carries_no_device_output():
    device = FakeFortiADC()
    text = json.dumps(fortiadc.run(device, "pool-a", "1", "disable"))
    assert "rs-1" not in text and "Serial" not in text


def cli_run(monkeypatch, capsys, fake, platform="fortiadc", **flags):
    from netops_admin import config as admin_config
    configured = type("Config", (), {"devices": {"adc": type("Device", (), {"platform": platform, "name": "adc"})()}})()
    monkeypatch.setattr(admin_config, "load_config", lambda _path: configured)
    monkeypatch.setattr(cli, "open_access", lambda _device: fake)
    arguments = {"--pool": "pool-a", "--member": "1", "--status": "disable", "--device": "adc"}
    arguments.update({"--" + key: value for key, value in flags.items()})
    argv = ["pool-member", "--config", "/nonexistent/admin.json"]
    for key, value in arguments.items():
        argv += [key, value]
    code = cli.main(argv)
    return code, json.loads(capsys.readouterr().out)


def test_cli_changes_status_and_exits_zero(monkeypatch, capsys):
    device = FakeFortiADC()
    code, document = cli_run(monkeypatch, capsys, device)
    assert (code, document["result"], status_of(device)) == (0, "confirmed", "disable")


def test_cli_repeat_is_idempotent(monkeypatch, capsys):
    device = FakeFortiADC()
    cli_run(monkeypatch, capsys, device)
    code, document = cli_run(monkeypatch, capsys, device)
    assert (code, document["result"], len(device.applied_blocks)) == (0, "unchanged", 1)


def test_cli_rolled_back_exit_code(monkeypatch, capsys):
    device = FakeFortiADC()
    device.ignore_writes = True
    code, document = cli_run(monkeypatch, capsys, device)
    assert (code, document["result"]) == (cli.EXIT_NOT_CONFIRMED, "rolled_back")


def test_cli_unknown_exit_code(monkeypatch, capsys):
    device = FakeFortiADC()
    device.coerce = {"disable": "maintain"}
    device.refuse_apply = {2}
    code, document = cli_run(monkeypatch, capsys, device)
    assert (code, document["result"]) == (cli.EXIT_UNKNOWN, "unknown")


def test_cli_rejection_exit_code(monkeypatch, capsys):
    device = FakeFortiADC()
    code, document = cli_run(monkeypatch, capsys, device, status="bogus")
    assert (code, document["result"]) == (cli.EXIT_REJECTED, "rejected")


def test_cli_refuses_a_device_of_another_platform(monkeypatch, capsys):
    device = FakeFortiADC()
    code, document = cli_run(monkeypatch, capsys, device, platform="fortios")
    assert (code, document["result"], device.queries) == (cli.EXIT_REJECTED, "rejected", [])


def test_cli_refuses_an_unconfigured_device(monkeypatch, capsys):
    device = FakeFortiADC()
    code, document = cli_run(monkeypatch, capsys, device, device="other")
    assert (code, document["result"], device.queries) == (cli.EXIT_REJECTED, "rejected", [])


