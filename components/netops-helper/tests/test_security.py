from __future__ import annotations

from base64 import b64encode, urlsafe_b64encode
import json

from netops_core.hostkey import fingerprint_of
import pytest

from netops_helper.auth import AuthenticationContextError, TargetAuth
from netops_helper.read_policy import render_read_query
from netops_helper.sanitize import redact


PIN = fingerprint_of(b64encode(b"security-test-host-key").decode("ascii"))


def envelope(
    alias: str = "device-a",
    role: str = "read-only",
    *,
    ssh_platform: str | None = None,
    enabled_queries: tuple[str, ...] | list[str] = (),
    read_inventory: dict | None = None,
) -> str:
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
        "ssh_platform": ssh_platform,
        "enabled_queries": list(enabled_queries),
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
        "read_inventory": read_inventory if read_inventory is not None else {
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


def test_firewall_address_inventory_survives_encoded_auth_context_decode() -> None:
    context = envelope(
        ssh_platform="fortios",
        enabled_queries=["fqdn_object_detail"],
        read_inventory={"firewall_addresses": ["api.example"]},
    )
    decoded = TargetAuth.decode("device-a", context)
    assert decoded.enabled_queries == ("fqdn_object_detail",)
    assert decoded.read_inventory["firewall_addresses"] == ("api.example",)
    platform, command = render_read_query(
        "fortios",
        "fqdn_object_detail",
        {"name": "api.example"},
        decoded.read_inventory,
    )
    assert platform == "fortinet"
    assert command == "diagnose firewall fqdn get-ip api.example"


@pytest.mark.parametrize(
    ("query", "source", "destination", "command"),
    (
        (
            "policy_lookup_ipv4", "192.0.2.10", "198.51.100.10",
            "diagnose firewall iprope lookup",
        ),
        (
            "policy_lookup_ipv6", "2001:db8::10", "2001:db8::20",
            "diagnose firewall iprope6 lookup",
        ),
    ),
)
def test_policy_lookup_inventory_survives_encoded_auth_context_decode(
    query: str, source: str, destination: str, command: str,
) -> None:
    inventory = {
        "addresses": [source, destination],
        "flow_ports": ["40000", "443"],
        "ip_protocols": ["6"],
        "interfaces": ["port2"],
        "policy_types": ["policy"],
    }
    context = envelope(
        ssh_platform="fortios",
        enabled_queries=[query],
        read_inventory=inventory,
    )
    decoded = TargetAuth.decode("device-a", context)
    assert decoded.enabled_queries == (query,)
    for category, values in inventory.items():
        assert decoded.read_inventory[category] == tuple(values)

    parameters = {
        "src_ip": source, "src_port": "40000",
        "dst_ip": destination, "dst_port": "443",
        "protocol": "6", "device": "port2", "pol_type": "policy",
    }
    platform, rendered = render_read_query(
        "fortios", query, parameters, decoded.read_inventory,
    )
    assert platform == "fortinet"
    assert rendered == (
        f"{command} {source} 40000 {destination} 443 6 port2 policy"
    )


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


def test_wireless_client_inventory_survives_encoded_auth_context_decode() -> None:
    mac = "00:00:5e:00:53:01"
    queries = ["wifi_clients", "wifi_client_detail"]
    context = envelope(ssh_platform="fortios", enabled_queries=queries, read_inventory={"wireless_clients": [mac]})
    decoded = TargetAuth.decode("device-a", context)
    assert decoded.enabled_queries == tuple(queries)
    assert decoded.read_inventory["wireless_clients"] == (mac,)
    platform, command = render_read_query("fortios", "wifi_clients", {}, decoded.read_inventory)
    assert platform == "fortinet"
    assert command == "diagnose wireless-controller wlac -c sta"
    platform, command = render_read_query("fortios", "wifi_client_detail", {"mac": mac}, decoded.read_inventory)
    assert platform == "fortinet"
    assert command == f"diagnose wireless-controller wlac -d sta {mac}"
