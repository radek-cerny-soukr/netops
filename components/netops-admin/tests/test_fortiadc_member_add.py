from __future__ import annotations

import copy
import json

import pytest
from fake_fortiadc import FakeFortiADC

from netops_admin import cli, fortiadc_member as fm
from netops_admin.errors import Rejected

ADD = ["config load-balance pool", 'edit "pool-a"', "config pool_member", "edit 9",
       'set real-server "rs-new"', "set pool_member_service_port 8443", "set status disable",
       "next", "end", "next", "end"]
REMOVE = ["config load-balance pool", 'edit "pool-a"', "config pool_member", "delete 9", "end", "next", "end"]


def add(device, **over):
    args = dict(pool="pool-a", member="9", real_server="rs-new", port="8443")
    args.update(over)
    return fm.add(device, args["pool"], args["member"], args["real_server"], args["port"])


def test_add_creates_a_disabled_member_in_one_block_with_exact_grammar():
    device = FakeFortiADC()
    before = copy.deepcopy(device.pools)
    result = add(device)
    assert device.applied_blocks == [ADD]
    assert result["result"] == "confirmed" and result["after"] == "disable"
    assert device.pools["pool-a"][9] == {"status": "disable", "real-server": "rs-new",
                                          "pool_member_service_port": "8443"}
    assert {k: v for k, v in device.pools["pool-a"].items() if k != 9} == before["pool-a"]
    assert device.pools["pool-b"] == before["pool-b"]


def test_preview_lists_commands_bindings_and_inverse():
    result = add(FakeFortiADC())
    assert result["preview"] == {"commands": ADD, "existing_members": ["1", "2", "3", "4"],
                                 "virtual_servers": ["vs-a"], "inverse": REMOVE}
    assert result["operation"] == "pool-member-add"


@pytest.mark.parametrize("over", [{"member": "1"}, {"real_server": "rs-1", "port": "80"}])
def test_used_number_or_duplicate_binding_is_refused_without_write(over):
    device = FakeFortiADC()
    device.pools["pool-a"][1]["pool_member_service_port"] = "80"
    with pytest.raises(Rejected):
        add(device, **over)
    assert device.applied_blocks == []


def test_unknown_real_server_is_refused_without_write():
    device = FakeFortiADC()
    with pytest.raises(Rejected, match="real server is not configured"):
        add(device, real_server="rs-none")
    assert device.applied_blocks == []


@pytest.mark.parametrize("over", [{"pool": "a b"}, {"member": "0"}, {"member": "x"}, {"real_server": 'r"s'},
                                  {"port": "0"}, {"port": "65536"}, {"port": "80a"}, {"port": "-1"}])
def test_invalid_input_is_refused_without_any_device_contact(over):
    device = FakeFortiADC()
    with pytest.raises(Rejected):
        add(device, **over)
    assert device.queries == [] and device.applied_blocks == []


def test_unknown_pool_is_refused():
    with pytest.raises(Rejected):
        add(FakeFortiADC(), pool="pool-zz")


def test_prompt_anchor_uses_the_device_hostname():
    device = FakeFortiADC(hostname="adc-two")
    add(device)
    assert device.specs[0].anchor == b"\nadc-two"


def test_ignored_write_is_rolled_back_to_the_original_members():
    device = FakeFortiADC()
    device.ignore_writes = True
    result = add(device)
    assert result["result"] == "rolled_back" and 9 not in device.pools["pool-a"]


def test_coerced_status_is_not_confirmed_and_member_is_removed():
    device = FakeFortiADC()
    device.coerce = {"disable": "enable"}
    result = add(device)
    assert result["result"] == "rolled_back" and 9 not in device.pools["pool-a"]
    assert device.applied_blocks[-1] == REMOVE


def test_error_after_write_removes_the_new_member():
    device = FakeFortiADC()
    device.fail_after_write = {1}
    result = add(device)
    assert result["result"] == "rolled_back" and 9 not in device.pools["pool-a"]


def test_wrong_port_in_readback_is_not_confirmed():
    device = FakeFortiADC()
    device.coerce = {"8443": "9999"}
    assert add(device)["result"] == "rolled_back"


def test_other_member_changed_meanwhile_is_not_confirmed():
    device = FakeFortiADC()
    original = device.apply

    def apply(steps, spec):
        original(steps, spec)
        device.pools["pool-a"][1]["pool_member_weight"] = "7"
    device.apply = apply
    result = add(device)
    assert result["result"] == "unknown" and 9 not in device.pools["pool-a"]


def test_unreadable_after_failed_rollback_is_unknown():
    device = FakeFortiADC()
    device.unreadable_after_apply = True
    assert add(device)["result"] == "unknown"


def test_remove_deletes_only_a_disabled_member_and_reads_back():
    device = FakeFortiADC()
    result = fm.remove(device, "pool-a", "2")
    assert device.applied_blocks == [[line.replace("delete 9", "delete 2") for line in REMOVE]]
    assert result["result"] == "confirmed" and 2 not in device.pools["pool-a"]
    assert sorted(device.pools["pool-a"]) == [1, 3, 4]


@pytest.mark.parametrize("member", ["1", "4"])
def test_remove_refuses_enabled_member(member):
    device = FakeFortiADC()
    with pytest.raises(Rejected, match="only a disabled or maintained"):
        fm.remove(device, "pool-a", member)
    assert device.applied_blocks == []


def test_remove_refuses_missing_member_and_reports_ignored_delete():
    device = FakeFortiADC()
    with pytest.raises(Rejected):
        fm.remove(device, "pool-a", "8")
    device.ignore_writes = True
    assert fm.remove(device, "pool-a", "2")["result"] == "rolled_back"


def test_add_then_remove_restores_the_original_listing():
    device = FakeFortiADC()
    start = device.query("show load-balance pool pool-a")
    add(device)
    assert fm.remove(device, "pool-a", "9")["result"] == "confirmed"
    assert device.query("show load-balance pool pool-a") == start


def test_parse_members_rejects_duplicates_and_garbage():
    text = ('config load-balance pool\n edit "p"\n config pool_member\n  edit 1\n   set real-server "a"\n'
            '  next\n  edit 1\n  next\n end\n next\nend\n')
    with pytest.raises(Rejected):
        fm.parse_members(text, "p")
    with pytest.raises(Rejected):
        fm.parse_members("garbage\n", "p")


def cli_member(monkeypatch, capsys, fake, command, platform="fortiadc", **flags):
    from netops_admin import config as admin_config
    configured = type("Config", (), {"devices": {"adc": type("Device", (), {"platform": platform, "name": "adc"})()}})()
    monkeypatch.setattr(admin_config, "load_config", lambda _path: configured)
    monkeypatch.setattr(cli, "open_access", lambda _device: fake)
    argv = [command, "--config", "/nonexistent/admin.json"]
    for key, value in flags.items():
        argv += ["--" + key.replace("_", "-"), value]
    code = cli.main(argv)
    return code, json.loads(capsys.readouterr().out)


ADD_FLAGS = dict(device="adc", pool="pool-a", member="9", real_server="rs-new", service_port="8443")


def test_cli_add_and_remove_round_trip(monkeypatch, capsys):
    device = FakeFortiADC()
    code, document = cli_member(monkeypatch, capsys, device, "pool-member-add", **ADD_FLAGS)
    assert (code, document["result"], document["device"]) == (0, "confirmed", "adc")
    code, document = cli_member(monkeypatch, capsys, device, "pool-member-remove",
                                device="adc", pool="pool-a", member="9")
    assert (code, document["result"], 9 in device.pools["pool-a"]) == (0, "confirmed", False)


def test_cli_add_rolled_back_exit_code(monkeypatch, capsys):
    device = FakeFortiADC()
    device.ignore_writes = True
    code, document = cli_member(monkeypatch, capsys, device, "pool-member-add", **ADD_FLAGS)
    assert (code, document["result"]) == (cli.EXIT_NOT_CONFIRMED, "rolled_back")


def test_cli_add_rejection_and_foreign_platform(monkeypatch, capsys):
    device = FakeFortiADC()
    code, document = cli_member(monkeypatch, capsys, device, "pool-member-add", **dict(ADD_FLAGS, service_port="0"))
    assert (code, document["result"]) == (cli.EXIT_REJECTED, "rejected")
    code, document = cli_member(monkeypatch, capsys, device, "pool-member-add", platform="fortios", **ADD_FLAGS)
    assert (code, device.applied_blocks) == (cli.EXIT_REJECTED, [])


def test_remove_accepts_a_maintained_member_and_reads_back():
    device = FakeFortiADC()
    result = fm.remove(device, "pool-a", "3")
    assert result["result"] == "confirmed" and sorted(device.pools["pool-a"]) == [1, 2, 4]
    assert device.applied_blocks == [[line.replace("delete 9", "delete 3") for line in REMOVE]]


@pytest.mark.parametrize("status", ["disable", "maintain"])
def test_the_last_member_of_a_pool_is_never_removed(status):
    device = FakeFortiADC()
    device.pools["pool-b"][1]["status"] = status
    with pytest.raises(Rejected, match="last member"):
        fm.remove(device, "pool-b", "1")
    assert device.applied_blocks == [] and list(device.pools["pool-b"]) == [1]


def test_the_second_last_member_can_be_removed_leaving_one():
    device = FakeFortiADC()
    for number in (1, 3, 4):
        del device.pools["pool-a"][number]
    device.pools["pool-a"][5] = {"real-server": "rs-new", "status": "disable"}
    assert fm.remove(device, "pool-a", "5")["result"] == "confirmed"
    assert list(device.pools["pool-a"]) == [2]


def test_the_only_member_of_a_pool_stays_even_when_enabled():
    device = FakeFortiADC()
    with pytest.raises(Rejected):
        fm.remove(device, "pool-b", "1")
    assert device.applied_blocks == [] and list(device.pools["pool-b"]) == [1]


RESTORE_2 = ["config load-balance pool", 'edit "pool-a"', "config pool_member", "edit 2", 'set real-server "rs-2"',
             "set status disable", 'set pool_member_cookie "rs2"', "set pool_member_weight 5",
             "next", "end", "next", "end"]
REMOVE_2 = [line.replace("delete 9", "delete 2") for line in REMOVE]


def cookie_device():
    device = FakeFortiADC()
    device.pools["pool-a"][2]["pool_member_cookie"] = "rs2"
    return device


def test_remove_preview_holds_the_full_member_and_the_inverse_create():
    result = fm.remove(cookie_device(), "pool-a", "2")
    assert result["preview"] == {"commands": REMOVE_2, "existing_members": ["1", "2", "3", "4"],
                                 "virtual_servers": ["vs-a"],
                                 "member_before": {"real-server": "rs-2", "status": "disable", "pool_member_weight": "5",
                                                   "pool_member_cookie": "rs2"},
                                 "inverse": RESTORE_2}


def test_member_deleted_but_write_reported_failure_is_recreated_from_the_preview():
    device = cookie_device()
    before = copy.deepcopy(device.pools)
    device.fail_after_write = {1}
    result = fm.remove(device, "pool-a", "2")
    assert device.applied_blocks == [REMOVE_2, RESTORE_2]
    assert (result["result"], result["after"]) == ("rolled_back", "present")
    assert result["restore"] == {"attempted": True, "write": "ok"}
    assert device.pools == before


def test_other_change_after_delete_restores_the_member_but_stays_unknown():
    device = cookie_device()
    original = device.apply

    def apply(steps, spec):
        original(steps, spec)
        device.pools["pool-a"][1]["pool_member_weight"] = "7"
    device.apply = apply
    result = fm.remove(device, "pool-a", "2")
    assert device.applied_blocks == [REMOVE_2, RESTORE_2]
    assert (result["result"], result["after"], result["reason"]) == ("unknown", "unverified", "read-back differs")
    assert result["restore"] == {"attempted": True, "write": "ok"}
    assert device.pools["pool-a"][2] == {"real-server": "rs-2", "status": "disable", "pool_member_weight": "5",
                                         "pool_member_cookie": "rs2"}


def test_member_with_a_setting_that_cannot_be_restored_is_refused_before_delete():
    device = FakeFortiADC()
    device.pools["pool-a"][2]["backup"] = "enable"
    with pytest.raises(Rejected, match="cannot be restored: backup"):
        fm.remove(device, "pool-a", "2")
    assert device.applied_blocks == [] and 2 in device.pools["pool-a"]


def test_enabled_member_shown_with_explicit_status_is_refused():
    device = FakeFortiADC()
    device.show_default = True
    with pytest.raises(Rejected, match="only a disabled or maintained"):
        fm.remove(device, "pool-a", "1")
    assert device.applied_blocks == []


def test_remove_help_names_both_removable_states(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "remove one DISABLED or MAINTAIN pool member" in " ".join(capsys.readouterr().out.split())
