from __future__ import annotations

import json

import pytest

from fortinet_ssh_fixture import BLOB, PUBLIC_KEY
from netops_admin import execute, readiness
from netops_core import hostkey
from netops_admin.config import load_config
from netops_admin.errors import Rejected


def write_config(tmp_path, platform):
    path = tmp_path / "admin.json"
    path.write_text(json.dumps({
        "version": 1, "state_dir": str(tmp_path / "state"), "audit_file": str(tmp_path / "audit.log"),
        "devices": {"adc": {
            "platform": platform, "address": "192.0.2.50",
            "host_key_fingerprint": "SHA256:" + "A" * 43, "vault": str(tmp_path / "vault"),
            "credential": "adc-rw", "check_credential": "adc-ro"}},
    }), encoding="utf-8")
    return path


def test_config_accepts_fortiadc_devices(tmp_path):
    assert load_config(write_config(tmp_path, "fortiadc")).devices["adc"].platform == "fortiadc"


def test_config_still_refuses_unknown_platforms(tmp_path):
    with pytest.raises(Rejected):
        load_config(write_config(tmp_path, "cisco"))


def test_plan_apply_adapters_serve_fortiadc():
    from netops_admin import engine, exec_fortiadc, fortiadc_plan
    assert execute._adapter("fortiadc") is exec_fortiadc and readiness.execute._adapter("fortiadc") is exec_fortiadc
    assert engine.adapter_for("fortiadc") is fortiadc_plan
    assert exec_fortiadc.COMPENSATING is True


def test_config_validates_public_host_key_against_fingerprint(tmp_path):
    path = write_config(tmp_path, "fortiadc")
    body = json.loads(path.read_text())
    device = body["devices"]["adc"]
    device["host_key"] = PUBLIC_KEY
    path.write_text(json.dumps(body))
    with pytest.raises(Rejected, match="does not match") as refused:
        load_config(path)
    assert refused.value.diagnostic == ("config.devices[].host_key", "ssh-public-key")
    device["host_key_fingerprint"] = hostkey.fingerprint_of(BLOB)
    path.write_text(json.dumps(body))
    assert load_config(path).devices["adc"].host_key == PUBLIC_KEY
