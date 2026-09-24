from __future__ import annotations

import json

import pytest

from netops_admin.config import load_config
from netops_admin.errors import Rejected


def write(tmp_path, **device):
    body = {"platform": "fortios", "address": "192.0.2.1", "host_key_fingerprint": "SHA256:" + "A" * 43,
            "vault": "/etc/netops-admin/vault.json", "credential": "rw", "check_credential": "ro"}
    body.update(device)
    body = {name: value for name, value in body.items() if value is not None}
    path = tmp_path / "admin.json"
    path.write_text(json.dumps({"version": 1, "state_dir": "/var/lib/a", "audit_file": "/var/lib/a/audit.jsonl",
                                "devices": {"fw-lab": body}}))
    return path


def test_a_device_with_a_separate_check_account_loads(tmp_path):
    assert load_config(write(tmp_path)).devices["fw-lab"].check_credential == "ro"


@pytest.mark.parametrize(("change", "fragment"), [
    ({"check_credential": None}, "needs check_credential"),
    ({"check_credential": "rw"}, "another account"),
    ({"check_address": "192.0.2.1"}, "another address"),
])
def test_the_check_account_is_required_and_separate(tmp_path, change, fragment):
    with pytest.raises(Rejected) as caught:
        load_config(write(tmp_path, **change))
    assert fragment in caught.value.reasons[0]
