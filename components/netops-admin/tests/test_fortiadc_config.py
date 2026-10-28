from __future__ import annotations

import json

import pytest

from netops_admin import execute, readiness
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


def test_plan_apply_adapters_refuse_fortiadc():
    with pytest.raises(Rejected):
        execute._adapter("fortiadc")
    with pytest.raises(Rejected):
        readiness.execute._adapter("fortiadc")
