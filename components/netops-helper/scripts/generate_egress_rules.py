#!/usr/bin/env python3
"""Generate a secret-free, fail-closed egress manifest and iptables rule contract."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import tempfile
from typing import Any
import sys

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
for SOURCE_ROOT in (
    COMPONENT_ROOT / "src", COMPONENT_ROOT.parent / "netops-core" / "src",
):
    if str(SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(SOURCE_ROOT))
from netops_helper import inventory as helper_inventory
from netops_core.inputs import InputError, read_regular


BUNDLE_SCHEMA = 4
POLICY_SCHEMA = helper_inventory.POLICY_SCHEMA
BRIDGE_NAME = helper_inventory.BRIDGE_NAME
NETWORK_NAME = helper_inventory.NETWORK_NAME
NETWORK_IPV6_ENABLED = False
IPV6_BOUNDARY = "docker-network-disabled"
BACKEND = helper_inventory.BACKEND
CHAIN_NAME = "NETOPS_HELPER_EGRESS"
INPUT_CHAIN_NAME = "NETOPS_HELPER_INPUT"
ESTABLISHED_RULE = (
    f"-A {INPUT_CHAIN_NAME} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
)
DIGEST_LENGTH = 64
MAX_TARGETS = 256
MAX_PORTS = helper_inventory.MAX_PORTS
MAX_RANGES = helper_inventory.MAX_RANGES
RFC1918_NETWORKS = helper_inventory.RFC1918_NETWORKS


class EgressContractError(ValueError):
    """Raised when egress inputs cannot produce a safe deterministic contract."""


JSON_INPUT_MAX_BYTES = 4 * 1024 * 1024
JSON_INPUT_ERRORS = (OSError, InputError, ValueError, RecursionError)


def read_json(path: Path) -> Any:
    return json.loads(read_regular(path, JSON_INPUT_MAX_BYTES).decode("utf-8"),
                      object_pairs_hook=helper_inventory.unique_object)


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = read_json(path)
    except JSON_INPUT_ERRORS as exc:
        raise EgressContractError("input JSON is unavailable or invalid") from exc
    if not isinstance(value, dict):
        raise EgressContractError("input JSON must be an object")
    return value


def inventory_digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise EgressContractError("inventory file is unavailable") from exc


def _devices(path: Path) -> tuple:
    try:
        return helper_inventory.load(path)
    except helper_inventory.InventoryError as exc:
        raise EgressContractError("inventory is unavailable or invalid") from exc


PORT_OVERLAP_REASON = "effective port overlaps a same-protocol range"


def _section(entry: Any) -> Any:
    try:
        return helper_inventory.section(entry)
    except helper_inventory.EgressPortOverlapError as exc:
        raise EgressContractError(PORT_OVERLAP_REASON) from exc
    except helper_inventory.InventoryError as exc:
        raise EgressContractError("helper section of a device is invalid") from exc


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
    try:
        raw = helper_inventory.egress_policy(policy)
    except helper_inventory.InventoryError as exc:
        raise EgressContractError("global egress policy has an invalid structure") from exc
    dns = sorted(raw["dns_resolvers"], key=lambda item: int(ipaddress.ip_address(item)))
    lans = sorted(raw["lan_cidrs"], key=lambda item: (
        int(ipaddress.ip_network(item).network_address),
        ipaddress.ip_network(item).prefixlen,
    ))
    return {
        "schema_version": POLICY_SCHEMA,
        "profile": raw["profile"],
        "backend": BACKEND,
        "bridge_name": BRIDGE_NAME,
        "network_name": NETWORK_NAME,
        "ipv6_mode": raw["ipv6_mode"],
        "dns_resolvers": dns,
        "lan_cidrs": lans,
    }


def _normalize_target(
    entry: Any, section: Any, dns_resolvers: list[str],
) -> tuple[dict[str, Any], bool]:
    egress = section.egress
    addresses = list(egress["addresses"])
    if not addresses:
        raise EgressContractError("target egress address list is empty")
    if helper_inventory.ipv4_literal(entry.address) is None and not dns_resolvers:
        raise EgressContractError(
            "hostname targets require addresses, DNS enrollment, and DNS resolvers"
        )
    if egress["allow_dns"] and not dns_resolvers:
        raise EgressContractError("DNS enrollment requires DNS resolvers")
    tcp_ports = list(egress["tcp_ports"])
    udp_ports = list(egress["udp_ports"])
    tcp_ranges = [list(item) for item in egress["tcp_port_ranges"]]
    udp_ranges = [list(item) for item in egress["udp_port_ranges"]]
    if (section.ssh_platform is not None and section.enabled_queries) or section.sftp_roots:
        tcp_ports = sorted(set(tcp_ports) | {entry.port})
    for ports, ranges in ((tcp_ports, tcp_ranges), (udp_ports, udp_ranges)):
        if any(start <= item <= end for item in ports for start, end in ranges):
            raise EgressContractError(PORT_OVERLAP_REASON)
    return ({
        "destinations": addresses,
        "tcp_ports": tcp_ports,
        "udp_ports": udp_ports,
        "tcp_port_ranges": tcp_ranges,
        "udp_port_ranges": udp_ranges,
        "allow_icmp": egress["allow_icmp"],
    }, egress["allow_dns"])


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


def build_manifest(
    devices: tuple, policy: dict[str, Any], digest: str, allow_host_dns: bool = False,
) -> dict[str, Any]:
    global_scope = _normalize_global(policy)
    if not isinstance(digest, str) or len(digest) != DIGEST_LENGTH or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise EgressContractError("inventory digest must be a sha256 hexadecimal digest")
    entries = helper_inventory.devices(devices)
    if not entries or len(entries) > MAX_TARGETS:
        raise EgressContractError("inventory must hold a bounded non-empty enrollment")
    normalized: list[dict[str, Any]] = []
    allow_dns = False
    for entry in entries:
        scope, target_allows_dns = _normalize_target(
            entry, _section(entry), global_scope["dns_resolvers"],
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
    if not isinstance(allow_host_dns, bool):
        raise EgressContractError("host DNS input must be true or false")
    if allow_host_dns and not allow_dns:
        raise EgressContractError(
            "host DNS input requires DNS enrollment and DNS resolvers"
        )
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
        "inventory_sha256": digest,
        "targets": targets,
        "host_input": {
            "default_action": "drop",
            "established_related": "accept",
            "allow_dns": allow_host_dns,
        },
    }


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def _accept_rule(
    destination: str, protocol: str, port: int | list[int], chain: str = CHAIN_NAME,
) -> str:
    rendered_port = str(port) if isinstance(port, int) else f"{port[0]}:{port[1]}"
    return (
        f"-A {chain} -d {destination} -p {protocol} -m {protocol} "
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
    input_jump = (
        f'-A INPUT -i {BRIDGE_NAME} -m comment --comment "{marker}" '
        f"-j {INPUT_CHAIN_NAME}"
    )
    input_rules = [ESTABLISHED_RULE]
    if manifest["host_input"]["allow_dns"]:
        for resolver in manifest["dns_resolvers"]:
            for protocol in ("tcp", "udp"):
                input_rules.append(
                    _accept_rule(f"{resolver}/32", protocol, 53, INPUT_CHAIN_NAME)
                )
    input_rules.append(f"-A {INPUT_CHAIN_NAME} -j DROP")
    return {
        "backend": BACKEND,
        "chain": CHAIN_NAME,
        "input_chain": INPUT_CHAIN_NAME,
        "ipv4": {
            "jump_rule": jump,
            "chain_rules": ipv4_rules,
            "input_jump_rule": input_jump,
            "input_chain_rules": input_rules,
        },
    }


def build_bundle(
    devices: tuple, policy: dict[str, Any], digest: str, allow_host_dns: bool = False,
) -> dict[str, Any]:
    manifest = build_manifest(devices, policy, digest, allow_host_dns)
    manifest_sha256 = manifest_digest(manifest)
    return {
        "bundle_schema": BUNDLE_SCHEMA,
        "manifest": manifest,
        "manifest_sha256": manifest_sha256,
        "ruleset": build_ruleset(manifest, manifest_sha256),
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


def generate(
    inventory_path: Path, policy_path: Path, output_path: Path, allow_host_dns: bool = False,
) -> None:
    resolved_inventory = inventory_path.resolve(strict=True)
    resolved_policy = policy_path.resolve(strict=True)
    resolved_output = output_path.parent.resolve(strict=True) / output_path.name
    if resolved_output in {resolved_inventory, resolved_policy}:
        raise EgressContractError("output must not replace an input")
    devices = _devices(resolved_inventory)
    policy = _load_object(resolved_policy)
    bundle = build_bundle(
        devices, policy, inventory_digest(resolved_inventory), allow_host_dns,
    )
    write_bundle(resolved_output, bundle)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a secret-free NetOps egress contract.")
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--allow-host-dns",
        action="store_true",
        help="also accept DNS from the bridge to the policy resolvers on the runner's INPUT path",
    )
    arguments = parser.parse_args()
    try:
        generate(
            arguments.inventory, arguments.policy, arguments.output, arguments.allow_host_dns,
        )
    except EgressContractError as exc:
        print(f"egress_generation=failed reason={exc}", file=os.sys.stderr)
        return 2
    except OSError:
        print(
            "egress_generation=failed reason=an input or the output file is unavailable",
            file=os.sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
