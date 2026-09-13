#!/usr/bin/env python3
"""Generate a secret-free, fail-closed egress manifest and iptables rule contract."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
from pathlib import Path, PurePosixPath
import stat
import tempfile
from typing import Any
import sys

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))
from netops_helper.auth import LEGACY_SSH_PROFILES
from netops_helper.read_policy import (
    PLATFORM_MAP,
    READ_QUERIES,
    normalize_platform,
    validate_inventory_item,
    validate_query_inventory,
)


BUNDLE_SCHEMA = 3
POLICY_SCHEMA = 1
GLOBAL_POLICY_KEY = "_egress"
BRIDGE_NAME = "nh-egress0"
NETWORK_NAME = "netops-helper"
NETWORK_IPV6_ENABLED = False
IPV6_BOUNDARY = "docker-network-disabled"
BACKEND = "iptables"
CHAIN_NAME = "NETOPS_HELPER_EGRESS"
MAX_TARGETS = 256
MAX_DESTINATIONS = 256
MAX_PORTS = 256
MAX_RANGES = 64
MAX_DNS_RESOLVERS = 16
MAX_LAN_CIDRS = 32
MAX_TLS_SERVER_NAMES = 256
RFC1918_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    (0x0A000000, 8), (0xAC100000, 12), (0xC0A80000, 16),
))
SUPPORTED_SSH_PLATFORMS = set(PLATFORM_MAP)
SAFE_QUERY_NAME = re.compile(r"[a-z][a-z0-9_]{0,127}")
SAFE_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
TARGET_POLICY_KEYS = {
    "account_role", "ssh_platform", "enabled_queries", "read_inventory",
    "sftp_roots", "fortios_output_standard_verified",
    "legacy_ssh", "rate_limit", "egress",
}
REQUIRED_TARGET_POLICY_KEYS = {
    "account_role", "ssh_platform", "enabled_queries", "egress",
}


class EgressContractError(ValueError):
    """Raised when egress inputs cannot produce a safe deterministic contract."""


def _load_object(path: Path, *, require_mode_600: bool = False) -> dict[str, Any]:
    try:
        if require_mode_600 and stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise EgressContractError("credential vault mode must be 600")
        value = json.loads(path.read_text(encoding="utf-8"))
    except EgressContractError:
        raise
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise EgressContractError("input JSON is unavailable or invalid") from exc
    if not isinstance(value, dict):
        raise EgressContractError("input JSON must be an object")
    return value


def _ipv4_address(value: Any) -> str:
    if not isinstance(value, str):
        raise EgressContractError("address must be an IPv4 literal")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise EgressContractError("address must be an IPv4 literal") from exc
    if address.version != 4:
        raise EgressContractError("IPv6 destinations are denied by this contract")
    if str(address) != value:
        raise EgressContractError("address must be canonical")
    return str(address)


def _ipv4_network(value: Any) -> str:
    if not isinstance(value, str):
        raise EgressContractError("LAN scope must be an IPv4 CIDR")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise EgressContractError("LAN scope must be a canonical IPv4 CIDR") from exc
    if network.version != 4:
        raise EgressContractError("IPv6 destinations are denied by this contract")
    if str(network) != value:
        raise EgressContractError("LAN scope must be canonical")
    if not any(network.subnet_of(private) for private in RFC1918_NETWORKS):
        raise EgressContractError("LAN scope must be contained in RFC1918 space")
    return str(network)


def _bounded_list(value: Any, maximum: int, label: str) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise EgressContractError(f"{label} must be a bounded list")
    return value


def _ports(value: Any) -> list[int]:
    items = _bounded_list(value, MAX_PORTS, "ports")
    if len(items) != len(set(item for item in items if isinstance(item, int))):
        raise EgressContractError("ports must be unique")
    result: list[int] = []
    for port in items:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise EgressContractError("port is outside 1-65535")
        result.append(port)
    return sorted(result)


def _port_ranges(value: Any) -> list[list[int]]:
    result: list[list[int]] = []
    for item in _bounded_list(value, MAX_RANGES, "port ranges"):
        if (
            not isinstance(item, list)
            or len(item) != 2
            or any(isinstance(part, bool) or not isinstance(part, int) for part in item)
        ):
            raise EgressContractError("port range must contain two integers")
        start, end = item
        if not 1 <= start <= end <= 65_535:
            raise EgressContractError("port range is outside 1-65535")
        result.append([start, end])
    result.sort()
    if any(current[0] <= previous[1] for previous, current in zip(result, result[1:])):
        raise EgressContractError("port ranges overlap")
    return result


def _normalize_global(policy: dict[str, Any]) -> dict[str, Any]:
    raw = policy.get(GLOBAL_POLICY_KEY)
    required = {
        "schema_version", "profile", "backend", "bridge_name", "network_name",
        "ipv6_mode", "dns_resolvers", "lan_cidrs",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise EgressContractError("global egress policy has an invalid structure")
    if raw["schema_version"] != POLICY_SCHEMA:
        raise EgressContractError("unsupported egress policy schema")
    if raw["profile"] not in {"strict-target", "lan-constrained"}:
        raise EgressContractError("unsupported egress profile")
    if raw["backend"] != BACKEND:
        raise EgressContractError("only the reviewed iptables backend is supported")
    if raw["bridge_name"] != BRIDGE_NAME or raw["network_name"] != NETWORK_NAME:
        raise EgressContractError("egress network anchor does not match the reviewed Compose contract")
    if raw["ipv6_mode"] != "deny":
        raise EgressContractError("IPv6 must fail closed")
    raw_dns = _bounded_list(raw["dns_resolvers"], MAX_DNS_RESOLVERS, "DNS resolvers")
    dns = [_ipv4_address(item) for item in raw_dns]
    if len(dns) != len(set(dns)):
        raise EgressContractError("DNS resolvers must be unique")
    dns.sort(key=lambda item: int(ipaddress.ip_address(item)))
    raw_lans = _bounded_list(raw["lan_cidrs"], MAX_LAN_CIDRS, "LAN scopes")
    lans = [_ipv4_network(item) for item in raw_lans]
    if len(lans) != len(set(lans)):
        raise EgressContractError("LAN scopes must be unique")
    lans.sort(key=lambda item: (
        int(ipaddress.ip_network(item).network_address),
        ipaddress.ip_network(item).prefixlen,
    ))
    if raw["profile"] == "strict-target" and lans:
        raise EgressContractError("strict-target profile must not declare LAN-wide scopes")
    if raw["profile"] == "lan-constrained" and not lans:
        raise EgressContractError("lan-constrained profile requires explicit LAN scopes")
    return {
        "schema_version": POLICY_SCHEMA,
        "profile": raw["profile"],
        "backend": BACKEND,
        "bridge_name": BRIDGE_NAME,
        "network_name": NETWORK_NAME,
        "ipv6_mode": "deny",
        "dns_resolvers": dns,
        "lan_cidrs": lans,
    }


def _safe_dns_name(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or value != value.lower()
        or value.endswith(".")
    ):
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return all(SAFE_DNS_LABEL.fullmatch(label) for label in value.split("."))


def _tls_server_names(value: Any) -> tuple[str, ...]:
    names = _bounded_list(value, MAX_TLS_SERVER_NAMES, "TLS server names")
    if len(names) != len(set(name for name in names if isinstance(name, str))):
        raise EgressContractError("TLS server names must be unique")
    if not all(_safe_dns_name(name) for name in names):
        raise EgressContractError("TLS server name is invalid")
    return tuple(sorted(names))


def _normalize_target(
    record: Any, entry: Any, dns_resolvers: list[str],
) -> tuple[dict[str, Any], bool]:
    required_record = {"host", "port", "login", "password"}
    allowed_record = required_record | {"snmp_community"}
    if (
        not isinstance(record, dict)
        or not required_record <= set(record) <= allowed_record
    ):
        raise EgressContractError("credential record has an invalid structure")
    host, record_port = record.get("host"), record.get("port")
    login, password = record.get("login"), record.get("password")
    try:
        password_bytes = password.encode("utf-8") if isinstance(password, str) else b""
    except UnicodeError as exc:
        raise EgressContractError("credential password is invalid") from exc
    if (
        not isinstance(host, str)
        or not 0 < len(host) <= 253
        or any(ord(character) < 33 or ord(character) == 127 for character in host)
        or isinstance(record_port, bool)
        or not isinstance(record_port, int)
        or not 1 <= record_port <= 65_535
        or not isinstance(login, str)
        or not 0 < len(login) <= 512
        or any(ord(character) < 32 or ord(character) == 127 for character in login)
        or not isinstance(password, str)
        or not 3 <= len(password_bytes) <= 4_096
        or "\x00" in password
        or "\x7f" in password
    ):
        raise EgressContractError("credential record has invalid authentication material")
    community = record.get("snmp_community")
    try:
        community_bytes = (
            community.encode("utf-8") if isinstance(community, str) else b""
        )
    except UnicodeError as exc:
        raise EgressContractError("credential SNMP material is invalid") from exc
    if community is not None and (
        not isinstance(community, str)
        or not 3 <= len(community_bytes) <= 255
        or any(ord(character) < 32 or ord(character) == 127 for character in community)
        or hmac.compare_digest(community_bytes, password_bytes)
    ):
        raise EgressContractError("credential record has invalid SNMP material")
    if (
        not isinstance(entry, dict)
        or set(entry) - TARGET_POLICY_KEYS
        or not REQUIRED_TARGET_POLICY_KEYS.issubset(entry)
    ):
        raise EgressContractError("target policy has an invalid structure")
    if entry["account_role"] != "read-only":
        raise EgressContractError("target is not enrolled read-only")
    inventory = entry.get("read_inventory", {})
    if not isinstance(inventory, dict) or any(
        key not in {"interfaces", "services", "addresses", "switches"}
        or not isinstance(items, list)
        or len(items) > 256
        or not all(isinstance(item, str) for item in items)
        for key, items in inventory.items()
    ):
        raise EgressContractError("read inventory is invalid")
    for key, items in inventory.items():
        if len(set(items)) != len(items):
            raise EgressContractError("read inventory values must be unique")
        for item in items:
            if (
                not item
                or len(item) > 128
                or any(ord(character) < 32 or ord(character) == 127 for character in item)
            ):
                raise EgressContractError("read inventory contains an unsafe value")
            try:
                validated = validate_inventory_item(key, item)
            except ValueError as exc:
                raise EgressContractError(
                    "read inventory contains an unsafe value"
                ) from exc
            if validated != item:
                raise EgressContractError(
                    "read inventory value must be canonical"
                )
    verified = entry.get("fortios_output_standard_verified", False)
    if not isinstance(verified, bool):
        raise EgressContractError("FortiOS output verification flag must be boolean")
    legacy_ssh = entry.get("legacy_ssh")
    if legacy_ssh is not None and (
        not isinstance(legacy_ssh, str) or legacy_ssh not in LEGACY_SSH_PROFILES
    ):
        raise EgressContractError("legacy SSH profile is invalid")
    rate = entry.get("rate_limit", {"requests": 30, "window_seconds": 60})
    if not isinstance(rate, dict) or set(rate) != {"requests", "window_seconds"}:
        raise EgressContractError("rate limit is invalid")
    requests, window = rate.get("requests"), rate.get("window_seconds")
    if (
        isinstance(requests, bool)
        or not isinstance(requests, int)
        or not 1 <= requests <= 60
        or isinstance(window, bool)
        or not isinstance(window, int)
        or not 1 <= window <= 3_600
    ):
        raise EgressContractError("rate limit is invalid")
    raw = entry["egress"]
    required = {
        "addresses", "tcp_ports", "udp_ports", "tcp_port_ranges",
        "udp_port_ranges", "allow_icmp", "allow_dns", "tls_server_names",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise EgressContractError("target egress policy has an invalid structure")
    raw_addresses = _bounded_list(raw["addresses"], MAX_DESTINATIONS, "target addresses")
    if len(raw_addresses) != len(set(
        item for item in raw_addresses if isinstance(item, str)
    )):
        raise EgressContractError("target addresses must be unique")
    addresses = sorted(
        (_ipv4_address(item) for item in raw_addresses),
        key=lambda item: int(ipaddress.ip_address(item)),
    )
    if not isinstance(host, str):
        raise EgressContractError("credential target host is invalid")
    try:
        parsed_host = ipaddress.ip_address(host)
    except ValueError:
        if not _safe_dns_name(host):
            raise EgressContractError("credential target hostname is invalid")
        host_address = None
    else:
        if parsed_host.version != 4 or str(parsed_host) != host:
            raise EgressContractError("credential target address is invalid")
        host_address = str(parsed_host)
    if not isinstance(raw["allow_dns"], bool):
        raise EgressContractError("allow_dns must be boolean")
    if host_address is None and (not addresses or not raw["allow_dns"] or not dns_resolvers):
        raise EgressContractError(
            "hostname targets require addresses, DNS enrollment, and DNS resolvers"
        )
    if host_address is not None and host_address not in addresses:
        raise EgressContractError("literal target host is outside egress addresses")
    if not addresses:
        raise EgressContractError("target egress address list is empty")
    if raw["allow_dns"] and not dns_resolvers:
        raise EgressContractError("DNS enrollment requires DNS resolvers")

    tcp_ports = _ports(raw["tcp_ports"])
    udp_ports = _ports(raw["udp_ports"])
    tcp_ranges = _port_ranges(raw["tcp_port_ranges"])
    udp_ranges = _port_ranges(raw["udp_port_ranges"])
    for ports, ranges in ((tcp_ports, tcp_ranges), (udp_ports, udp_ranges)):
        if any(start <= item <= end for item in ports for start, end in ranges):
            raise EgressContractError("explicit port overlaps a same-protocol range")
    if isinstance(record_port, bool) or not isinstance(record_port, int) or not 1 <= record_port <= 65_535:
        raise EgressContractError("credential target port is invalid")
    platform = entry.get("ssh_platform")
    queries = entry.get("enabled_queries")
    roots = entry.get("sftp_roots", [])
    try:
        normalized_platform = None if platform is None else normalize_platform(platform)
    except (TypeError, ValueError):
        raise EgressContractError("SSH platform is invalid") from None
    if (
        not isinstance(queries, list)
        or len(queries) > 256
        or not all(
            isinstance(query, str) and SAFE_QUERY_NAME.fullmatch(query)
            for query in queries
        )
        or len(queries) != len(set(queries))
        or normalized_platform is None and queries
        or normalized_platform is not None
        and any(query not in READ_QUERIES[normalized_platform] for query in queries)
    ):
        raise EgressContractError("enabled SSH queries are invalid")
    try:
        validate_query_inventory(
            normalized_platform,
            tuple(queries),
            {
                key: tuple(items)
                for key, items in inventory.items()
            },
        )
    except (KeyError, TypeError, ValueError):
        raise EgressContractError(
            "read inventory is invalid for enabled SSH queries"
        ) from None
    if not isinstance(roots, list) or len(roots) > 256:
        raise EgressContractError("SFTP roots are invalid")
    if len(roots) != len(set(root for root in roots if isinstance(root, str))):
        raise EgressContractError("SFTP roots must be unique")
    for root in roots:
        if not isinstance(root, str):
            raise EgressContractError("SFTP roots are invalid")
        requested = PurePosixPath(root)
        if (
            not requested.is_absolute()
            or not root.strip("/")
            or root.startswith("//")
            or "\x00" in root
            or ".." in requested.parts
            or len(root) > 2_000
        ):
            raise EgressContractError("SFTP roots are unsafe")
    if (platform is not None and queries) or roots:
        tcp_ports = sorted(set(tcp_ports) | {record_port})

    for ports, ranges in ((tcp_ports, tcp_ranges), (udp_ports, udp_ranges)):
        if any(start <= item <= end for item in ports for start, end in ranges):
            raise EgressContractError("effective port overlaps a same-protocol range")
    if not isinstance(raw["allow_icmp"], bool):
        raise EgressContractError("allow_icmp must be boolean")
    _tls_server_names(raw["tls_server_names"])
    return ({
        "destinations": addresses,
        "tcp_ports": tcp_ports,
        "udp_ports": udp_ports,
        "tcp_port_ranges": tcp_ranges,
        "udp_port_ranges": udp_ranges,
        "allow_icmp": raw["allow_icmp"],
    }, raw["allow_dns"])


def require_ftp_scope(
    scope: dict[str, Any], control_port: int, passive_port: int,
) -> None:
    """Require an FTP control port and a range-bound negotiated passive port."""
    if not isinstance(scope, dict):
        raise EgressContractError("FTP scope is invalid")
    tcp_ports = _ports(scope.get("tcp_ports"))
    tcp_ranges = _port_ranges(scope.get("tcp_port_ranges"))
    if (
        isinstance(control_port, bool)
        or not isinstance(control_port, int)
        or not 1 <= control_port <= 65_535
        or control_port not in tcp_ports
        and not any(start <= control_port <= end for start, end in tcp_ranges)
    ):
        raise EgressContractError("FTP control port is outside the egress scope")
    if not tcp_ranges:
        raise EgressContractError("FTP requires an explicit passive TCP range")
    if (
        isinstance(passive_port, bool)
        or not isinstance(passive_port, int)
        or not any(start <= passive_port <= end for start, end in tcp_ranges)
    ):
        raise EgressContractError("FTP passive port is outside the explicit range")


def build_manifest(vault: dict[str, Any], policy: dict[str, Any], master_alias: str) -> dict[str, Any]:
    global_scope = _normalize_global(policy)
    target_entries = [
        (alias, entry)
        for alias, entry in policy.items()
        if alias != GLOBAL_POLICY_KEY and alias != master_alias
    ]
    if not target_entries or len(target_entries) > MAX_TARGETS:
        raise EgressContractError("target policy must contain a bounded non-empty enrollment")
    normalized: list[dict[str, Any]] = []
    allow_dns = False
    for alias, entry in target_entries:
        if not isinstance(alias, str) or not alias:
            raise EgressContractError("target enrollment is invalid")
        scope, target_allows_dns = _normalize_target(
            vault.get(alias), entry, global_scope["dns_resolvers"],
        )
        normalized.append(scope)
        allow_dns = allow_dns or target_allows_dns
    unique = {
        json.dumps(item, sort_keys=True, separators=(",", ":")): item
        for item in normalized
    }
    targets = [unique[key] for key in sorted(unique)]
    if global_scope["profile"] == "lan-constrained":
        lans = [ipaddress.ip_network(item) for item in global_scope["lan_cidrs"]]
        for target in targets:
            for destination in target["destinations"]:
                if not any(ipaddress.ip_address(destination) in lan for lan in lans):
                    raise EgressContractError("target is outside the declared LAN scope")
    return {
        "schema_version": POLICY_SCHEMA,
        "profile": global_scope["profile"],
        "backend": BACKEND,
        "network_name": NETWORK_NAME,
        "bridge_name": BRIDGE_NAME,
        "network_ipv6_enabled": NETWORK_IPV6_ENABLED,
        "ipv6_boundary": IPV6_BOUNDARY,
        "default_action": "drop",
        "allow_dns": allow_dns,
        "dns_resolvers": global_scope["dns_resolvers"],
        "lan_cidrs": global_scope["lan_cidrs"],
        "targets": targets,
    }


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def _accept_rule(destination: str, protocol: str, port: int | list[int]) -> str:
    rendered_port = str(port) if isinstance(port, int) else f"{port[0]}:{port[1]}"
    return (
        f"-A {CHAIN_NAME} -d {destination} -p {protocol} -m {protocol} "
        f"--dport {rendered_port} -j ACCEPT"
    )


def _scope_rules(destination: str, scope: dict[str, Any]) -> list[str]:
    rules: list[str] = []
    for protocol in ("tcp", "udp"):
        for port in scope[f"{protocol}_ports"]:
            rules.append(_accept_rule(destination, protocol, port))
        for item in scope[f"{protocol}_port_ranges"]:
            rules.append(_accept_rule(destination, protocol, item))
    if scope["allow_icmp"]:
        rules.append(
            f"-A {CHAIN_NAME} -d {destination} -p icmp -m icmp --icmp-type 8 -j ACCEPT"
        )
    return rules


def build_ruleset(manifest: dict[str, Any], digest: str) -> dict[str, Any]:
    marker = f"netops-helper-egress:{digest}"
    jump = (
        f'-A DOCKER-USER -i {BRIDGE_NAME} -m comment --comment "{marker}" '
        f"-j {CHAIN_NAME}"
    )
    ipv4_rules: list[str] = []
    if manifest["allow_dns"]:
        for resolver in manifest["dns_resolvers"]:
            for protocol in ("tcp", "udp"):
                ipv4_rules.append(_accept_rule(f"{resolver}/32", protocol, 53))
    if manifest["profile"] == "strict-target":
        for scope in manifest["targets"]:
            for destination in scope["destinations"]:
                ipv4_rules.extend(_scope_rules(f"{destination}/32", scope))
    else:
        union = {
            "tcp_ports": sorted({port for scope in manifest["targets"] for port in scope["tcp_ports"]}),
            "udp_ports": sorted({port for scope in manifest["targets"] for port in scope["udp_ports"]}),
            "tcp_port_ranges": [list(item) for item in sorted({tuple(item) for scope in manifest["targets"] for item in scope["tcp_port_ranges"]})],
            "udp_port_ranges": [list(item) for item in sorted({tuple(item) for scope in manifest["targets"] for item in scope["udp_port_ranges"]})],
            "allow_icmp": any(scope["allow_icmp"] for scope in manifest["targets"]),
        }
        for lan in manifest["lan_cidrs"]:
            ipv4_rules.extend(_scope_rules(lan, union))
    ipv4_rules.append(f"-A {CHAIN_NAME} -j DROP")
    return {
        "backend": BACKEND,
        "chain": CHAIN_NAME,
        "ipv4": {"jump_rule": jump, "chain_rules": ipv4_rules},
    }


def build_bundle(vault: dict[str, Any], policy: dict[str, Any], master_alias: str) -> dict[str, Any]:
    manifest = build_manifest(vault, policy, master_alias)
    digest = manifest_digest(manifest)
    return {
        "bundle_schema": BUNDLE_SCHEMA,
        "manifest": manifest,
        "manifest_sha256": digest,
        "ruleset": build_ruleset(manifest, digest),
    }


def write_bundle(path: Path, bundle: dict[str, Any]) -> None:
    resolved_parent = path.parent.resolve(strict=True)
    destination = resolved_parent / path.name
    payload = canonical_json(bundle) + b"\n"
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=resolved_parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
        directory_fd = os.open(resolved_parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def generate(vault_path: Path, policy_path: Path, output_path: Path, master_alias: str) -> None:
    resolved_vault = vault_path.resolve(strict=True)
    resolved_policy = policy_path.resolve(strict=True)
    resolved_output = output_path.parent.resolve(strict=True) / output_path.name
    if resolved_output in {resolved_vault, resolved_policy}:
        raise EgressContractError("output must not replace an input")
    vault = _load_object(resolved_vault, require_mode_600=True)
    policy = _load_object(resolved_policy)
    bundle = build_bundle(vault, policy, master_alias)
    write_bundle(resolved_output, bundle)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a secret-free NetOps egress contract.")
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    master_alias = os.environ.get("NETOPS_MASTER_ALIAS", "netops-runner")
    try:
        generate(arguments.vault, arguments.policy, arguments.output, master_alias)
    except (EgressContractError, OSError):
        print("egress_generation=failed", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
