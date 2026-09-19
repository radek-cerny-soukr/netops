#!/usr/bin/env python3
"""Run portable phase-1 contracts without requiring pytest."""

from __future__ import annotations

from base64 import b64encode, urlsafe_b64encode
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable

_CORE_SOURCE = Path(__file__).resolve().parents[2] / "netops-core" / "src"
if importlib.util.find_spec("netops_core") is None and _CORE_SOURCE.is_dir():
    sys.path.insert(0, str(_CORE_SOURCE))

from netops_core.hostkey import fingerprint_of
from netops_helper.auth import TargetAuth
from netops_helper.read_policy import render_read_query
from netops_helper.sanitize import redact


ROOT = Path(__file__).resolve().parents[1]
HOST_KEY_PIN = fingerprint_of(b64encode(b"portable-contract-host-key").decode("ascii"))
SOURCE_PATH = os.pathsep.join(
    (str(ROOT / "src"), str(ROOT.parent / "netops-core" / "src"))
)
DEPENDENCY_FREE_TESTS = (
    "tests/test_engine_contracts.py",
    "tests/test_query_catalog_arista.py",
    "tests/test_query_catalog_cisco.py",
    "tests/test_query_catalog_extreme.py",
    "tests/test_query_catalog_fortinet.py",
    "tests/test_query_catalog_junos.py",
    "tests/test_query_catalog_ruckus.py",
    "tests/test_query_catalog_docs.py",
    "tests/test_vendor_references.py",
    "tests/test_proxy_contracts.py",
    "tests/test_sanitize.py",
    "tests/test_egress_scripts.py",
    "tests/test_apply_egress_rules.py",
    "tests/test_supply_chain.py",
    "tests/test_policy_parity.py",
)


def must_fail(function: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    try:
        function(*args, **kwargs)
    except Exception:
        return
    raise AssertionError(f"{function.__name__} unexpectedly succeeded")


def _auth_context() -> str:
    payload = {
        "alias": "device-a",
        "host": "192.0.2.10",
        "port": 22,
        "login": "operator",
        "credential_kind": "password",
        "secret": "ssh-secret-value",
        "host_key_fingerprint": HOST_KEY_PIN,
        "account_role": "read-only",
        "read_inventory": {"interfaces": ["port3"]},
        "ssh_platform": "fortios",
        "enabled_queries": ["interface_details"],
        "egress": {
            "addresses": ["192.0.2.10"],
            "tcp_ports": [],
            "udp_ports": [],
            "tcp_port_ranges": [],
            "udp_port_ranges": [],
            "allow_icmp": False,
            "allow_dns": False,
            "tls_server_names": [],
        },
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _run_core_contracts() -> None:
    context = _auth_context()
    auth = TargetAuth.decode("device-a", context)
    assert auth.secrets == ("ssh-secret-value",)
    must_fail(TargetAuth.decode, "device-b", context)

    cleaned = redact(
        "peer 192.0.2.10 aa:bb:cc:dd:ee:ff "
        "username=operator password=synthetic-secret ENC blob",
        secrets=("synthetic-secret",),
    )
    for visible in (
        "192.0.2.10",
        "aa:bb:cc:dd:ee:ff",
        "operator",
    ):
        assert visible in cleaned
    for hidden in ("synthetic-secret", "ENC blob"):
        assert hidden not in cleaned

    _, command = render_read_query(
        "fortios",
        "interface_details",
        {"interface": "port3"},
        {"interfaces": ("port3",)},
    )
    assert command == "diagnose netlink interface list port3"
    must_fail(
        render_read_query,
        "fortios",
        "interface_details",
        {"interface": "port4"},
        {"interfaces": ("port3",)},
    )
    must_fail(
        render_read_query,
        "fortios",
        "config system interface",
        {},
        {},
    )

    proxy_path = ROOT / "scripts/remote_mcp_proxy.py"
    sys.path.insert(0, str(proxy_path.parent))
    specification = importlib.util.spec_from_file_location(
        "remote_mcp_proxy_smoke",
        proxy_path,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)

    proxy = module.Proxy()
    proxy.pending[9] = "tools/call"
    proxy.pending_tools[9] = "tcp_probe"
    proxy.response_secrets[9] = ("response-secret",)
    response = {
        "jsonrpc": "2.0",
        "id": 9,
        "result": {
            "content": [{
                "type": "text",
                "text": (
                    "Sep 9 10:23:45 ip=192.0.2.10 "
                    "serial=DEVICE123 username=operator response-secret"
                ),
            }],
        },
    }
    transformed = json.loads(proxy.response(json.dumps(response).encode("utf-8")))
    output = transformed["result"]["content"][0]["text"]
    for visible in ("10:23:45", "192.0.2.10", "DEVICE123", "operator"):
        assert visible in output
    assert "response-secret" not in output
    assert output.startswith("UNTRUSTED DEVICE DATA")

    assert not (ROOT / "plugin").exists()
    source = "\n".join(
        path.read_text(encoding="utf-8").lower()
        for path in (ROOT / "src/netops_helper").rglob("*.py")
    )
    forbidden = (
        "prepare_",
        "apply_",
        "cancel_change",
        "sftp_upload",
        "send_command_timing",
        "posix_rename",
        "save_config",
        "config_mode",
    )
    for marker in forbidden:
        assert marker not in source


def _run_dependency_free_files() -> None:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = SOURCE_PATH
    for relative in DEPENDENCY_FREE_TESTS:
        path = ROOT / relative
        if not path.is_file():
            raise AssertionError(f"dependency-free contract is missing: {relative}")
        completed = subprocess.run(
            [sys.executable, "-B", str(path)],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        if completed.returncode:
            raise AssertionError(
                f"dependency-free contract failed: {relative} "
                f"(exit {completed.returncode})"
            )


def main() -> int:
    _run_core_contracts()
    _run_dependency_free_files()
    print("security_unit_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
