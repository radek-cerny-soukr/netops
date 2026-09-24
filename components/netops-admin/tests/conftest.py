from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def request_bytes(**fields) -> bytes:
    body = {
        "table": "firewall address",
        "op": "create",
        "key": "new-host",
        "changes": {"subnet": "192.0.2.30/32"},
        "reason": "operator asked for a host object",
        "user_request": "create an address object for the new host",
        "request_id": "req-0001-example",
    }
    body.update(fields)
    return json.dumps(body).encode("utf-8")


@pytest.fixture
def fortios_snapshot() -> bytes:
    return (FIXTURES / "fortios_8_0_0.conf").read_bytes()


@pytest.fixture
def exos_snapshot() -> bytes:
    return (FIXTURES / "exos_33_7_1.conf").read_bytes()
