"""A read-only FortiOS account is warned about wifi queries it cannot run (Return code -61)."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from netops_helper import inventory

sys.path.insert(0, str(Path(__file__).parent))
import test_check_operator_config as base  # noqa: E402

WIFI = ("wifi_clients", "wifi_access_points", "wifi_ap_detail", "wifi_ssid_mapping", "wifi_client_detail")
ENTRY = SimpleNamespace(
    credential="fixture-account", name="gate", address="192.0.2.30", port=22,
    host_key_fingerprint="SHA256:" + "A" * 43, legacy_ssh=None,
)
EGRESS = {"addresses": ["192.0.2.30"], "tcp_ports": [22], "udp_ports": [], "tcp_port_ranges": [],
          "udp_port_ranges": [], "allow_icmp": False, "allow_dns": False, "tls_server_names": []}


def _section(role="read-only", platform="fortios", queries=("system_status", "wifi_clients")):
    helper = {"account_role": role, "ssh_platform": platform, "enabled_queries": list(queries),
              "read_inventory": {"wireless_clients": ["00:00:5e:00:53:01"]} if "wifi_client_detail" in queries else {},
              "egress": EGRESS}
    if role == "admin-bounded":
        helper["role_boundary"] = "catalogue"
    return inventory.section(SimpleNamespace(**{**vars(ENTRY), "helper": helper}))


def test_read_only_fortios_with_a_wifi_query_warns_with_the_query_name():
    warnings = inventory.section_warnings(ENTRY.name, _section(queries=("system_status", "wifi_clients")))
    assert warnings == [
        "device gate: query wifi_clients is enabled for a read-only FortiOS account, which the device refuses"
        " with 'Return code -61'; enroll an admin-bounded account (access profile 'wifi read-write'"
        " and 'cli-diagnose enable') or remove the query"
    ]


@pytest.mark.parametrize("name", WIFI)
def test_every_refused_wifi_query_is_named(name):
    warnings = inventory.section_warnings("gate", _section(queries=("system_status", name)))
    assert len(warnings) == 1 and "query %s " % name in warnings[0]


def test_each_enabled_wifi_query_has_its_own_warning():
    warnings = inventory.section_warnings("gate", _section(queries=("wifi_ssid_mapping", "wifi_ap_detail")))
    assert [w.split()[3] for w in warnings] == ["wifi_ssid_mapping", "wifi_ap_detail"]


def test_admin_bounded_account_does_not_warn():
    assert inventory.section_warnings("gate", _section(role="admin-bounded")) == []


def test_read_only_without_a_wifi_query_does_not_warn():
    assert inventory.section_warnings("gate", _section(queries=("system_status",))) == []


def test_another_vendor_does_not_warn():
    section = SimpleNamespace(account_role="read-only", ssh_platform="exos", enabled_queries=("wifi_clients",))
    assert inventory.section_warnings("sw", section) == []


def _inventory_with(queries):
    document = copy.deepcopy(base.GOOD_INVENTORY)
    helper = document["devices"][0]["helper"]
    helper["ssh_platform"] = "fortios"
    helper["enabled_queries"] = list(queries)
    helper["fortios_output_standard_verified"] = True
    return document


def _run(document):
    with tempfile.TemporaryDirectory() as directory:
        directory_path = Path(directory)
        paths = base._good_paths(directory_path)
        base._write(directory_path, "inventory.json", document, 0o644)
        argv = ["check_operator_config.py", "--inventory", str(paths["inventory.json"]),
                "--vault", str(paths["vault.json"]), "--egress-policy", str(paths["egress-policy.json"]),
                "--runner", str(paths["runner.json"])]
        with mock.patch.object(sys, "argv", argv), redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
            code = base.checker.main()
    return code, out.getvalue(), err.getvalue()


def test_operator_config_check_passes_and_prints_the_warning_on_stderr():
    code, out, err = _run(_inventory_with(("system_status", "wifi_clients")))
    assert code == 0
    assert "operator_config_check=passed devices=1 credentials=2" in out
    assert "operator_config_warning=device device-a: query wifi_clients " in err


def test_operator_config_check_without_a_wifi_query_prints_no_warning():
    code, out, err = _run(_inventory_with(("system_status",)))
    assert (code, err) == (0, "")
