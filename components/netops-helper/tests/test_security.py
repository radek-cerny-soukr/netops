from __future__ import annotations

from base64 import b64encode, urlsafe_b64encode
import json

from netops_core.hostkey import fingerprint_of
import pytest

from netops_helper.auth import AuthenticationContextError, TargetAuth
from netops_helper.read_policy import render_read_query
from netops_helper.sanitize import redact


PIN = fingerprint_of(b64encode(b"security-test-host-key").decode("ascii"))


def envelope(alias: str = "device-a", role: str = "read-only") -> str:
    raw = json.dumps({
        "alias": alias,
        "host": "192.0.2.10",
        "port": 22,
        "login": "operator",
        "credential_kind": "password",
        "secret": "correct horse battery staple",
        "host_key_fingerprint": PIN,
        "account_role": role,
        "fortios_output_standard_verified": True,
        "ssh_platform": None,
        "enabled_queries": [],
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
        "read_inventory": {
            "interfaces": ["port3"],
            "services": ["example.service"],
            "addresses": ["192.0.2.20"],
        },
    }).encode()
    return urlsafe_b64encode(raw).decode().rstrip("=")


def test_auth_context_requires_alias_and_read_only_enrollment() -> None:
    decoded = TargetAuth.decode("device-a", envelope())
    assert decoded.port == 22 and decoded.account_role == "read-only"
    assert decoded.fortios_output_standard_verified is True
    assert not hasattr(decoded, "https_endpoints")
    assert not hasattr(decoded, "require_https_endpoint")
    with pytest.raises(AuthenticationContextError):
        TargetAuth.decode("device-b", envelope())
    with pytest.raises(AuthenticationContextError):
        TargetAuth.decode("device-a", envelope(role="administrator"))


def test_redaction_preserves_diagnostic_identifiers_and_removes_secrets() -> None:
    value = redact(
        "peer 192.0.2.10 mac aa:bb:cc:dd:ee:ff hostname=edge username=operator "
        "serial=FGABCDEF123456 password=hunter2 ENC blob "
        "enable secret 5 $1$abc community private-community\nroot:$6$salt$hash:1:2:3",
        secrets=("hunter2",),
    )
    for visible in ("192.0.2.10", "aa:bb:cc:dd:ee:ff", "edge", "operator", "FGABCDEF123456"):
        assert visible in value
    assert "hunter2" not in value
    for hidden in ("ENC blob", "$1$abc", "private-community", "$6$salt$hash"):
        assert hidden not in value


def test_typed_query_uses_enrolled_inventory() -> None:
    platform, command = render_read_query(
        "fortios", "interface_details", {"interface": "port3"}, {"interfaces": ("port3",)},
    )
    assert platform == "fortinet"
    assert command == "diagnose netlink interface list port3"


@pytest.mark.parametrize("value", ["port4", "port3 | show full-configuration", "port3\nend"])
def test_typed_query_rejects_unenrolled_or_unsafe_interface(value: str) -> None:
    with pytest.raises(ValueError):
        render_read_query(
            "fortios", "interface_details", {"interface": value}, {"interfaces": ("port3",)},
        )


def test_raw_or_mutating_query_names_do_not_exist() -> None:
    for query in ("config system interface", "show running-config", "execute reboot"):
        with pytest.raises(ValueError):
            render_read_query("fortios", query, {}, {})
