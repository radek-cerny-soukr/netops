#!/usr/bin/env python3
"""Read-only verification for a generated NetOps Helper egress contract."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_egress_rules as generator


class EgressCheckError(ValueError):
    """Raised when expected or observed state cannot be checked safely."""


def _read_json(path: Path, *, require_mode_600: bool = False) -> dict[str, Any]:
    try:
        if require_mode_600 and stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise EgressCheckError("expected bundle mode must be 600")
        value = json.loads(path.read_text(encoding="utf-8"))
    except EgressCheckError:
        raise
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise EgressCheckError("JSON input is unavailable or invalid") from exc
    if not isinstance(value, dict):
        raise EgressCheckError("JSON input must be an object")
    return value


def validate_bundle(bundle: dict[str, Any]) -> None:
    if set(bundle) != {"bundle_schema", "manifest", "manifest_sha256", "ruleset"}:
        raise EgressCheckError("bundle structure is invalid")
    if bundle["bundle_schema"] != generator.BUNDLE_SCHEMA:
        raise EgressCheckError("bundle schema is unsupported")
    manifest = bundle["manifest"]
    if not isinstance(manifest, dict):
        raise EgressCheckError("manifest is invalid")
    expected_manifest_keys = {
        "schema_version", "profile", "backend", "network_name", "bridge_name",
        "network_ipv6_enabled", "ipv6_boundary", "default_action", "allow_dns",
        "dns_resolvers", "lan_cidrs", "inventory_sha256",
        "targets",
    }
    if set(manifest) != expected_manifest_keys:
        raise EgressCheckError("manifest structure is invalid")
    if (
        manifest.get("schema_version") != generator.POLICY_SCHEMA
        or manifest.get("profile") not in {"strict-target", "lan-constrained"}
        or manifest.get("backend") != generator.BACKEND
        or manifest.get("network_name") != generator.NETWORK_NAME
        or manifest.get("bridge_name") != generator.BRIDGE_NAME
        or manifest.get("network_ipv6_enabled") is not generator.NETWORK_IPV6_ENABLED
        or manifest.get("ipv6_boundary") != generator.IPV6_BOUNDARY
        or manifest.get("default_action") != "drop"
        or not isinstance(manifest.get("allow_dns"), bool)
        or not isinstance(manifest.get("dns_resolvers"), list)
        or not isinstance(manifest.get("lan_cidrs"), list)
        or not isinstance(manifest.get("inventory_sha256"), str)
        or len(manifest["inventory_sha256"]) != generator.DIGEST_LENGTH
        or any(
            character not in "0123456789abcdef"
            for character in manifest["inventory_sha256"]
        )
        or not isinstance(manifest.get("targets"), list)
    ):
        raise EgressCheckError("manifest safety boundary is invalid")
    target_keys = {
        "destinations", "tcp_ports", "udp_ports", "tcp_port_ranges",
        "udp_port_ranges", "allow_icmp",
    }
    try:
        if manifest["dns_resolvers"] != sorted(set(
            generator._ipv4_address(item) for item in manifest["dns_resolvers"]
        ), key=lambda item: int(generator.ipaddress.ip_address(item))):
            raise EgressCheckError("DNS resolver scope is not canonical")
        if manifest["allow_dns"] and not manifest["dns_resolvers"]:
            raise EgressCheckError("DNS is enabled without a resolver scope")
        canonical_lans = sorted(set(
            generator._ipv4_network(item) for item in manifest["lan_cidrs"]
        ), key=lambda item: (
            int(generator.ipaddress.ip_network(item).network_address),
            generator.ipaddress.ip_network(item).prefixlen,
        ))
        if manifest["lan_cidrs"] != canonical_lans:
            raise EgressCheckError("LAN scope is not canonical")
        if manifest["profile"] == "strict-target" and canonical_lans:
            raise EgressCheckError("strict target manifest contains LAN-wide scope")
        if manifest["profile"] == "lan-constrained" and not canonical_lans:
            raise EgressCheckError("LAN-constrained manifest has no LAN scope")
        canonical_lan_networks = tuple(
            generator.ipaddress.ip_network(item) for item in canonical_lans
        )
        if any(not isinstance(scope, dict) or set(scope) != target_keys for scope in manifest["targets"]):
            raise EgressCheckError("target scope structure is invalid")
        for scope in manifest["targets"]:
            canonical_destinations = sorted(set(
                generator._ipv4_address(item) for item in scope["destinations"]
            ), key=lambda item: tuple(int(part) for part in item.split(".")))
            if not canonical_destinations or scope["destinations"] != canonical_destinations:
                raise EgressCheckError("target destination scope is not canonical")
            if manifest["profile"] == "lan-constrained" and any(
                not any(
                    generator.ipaddress.ip_address(destination) in lan
                    for lan in canonical_lan_networks
                )
                for destination in canonical_destinations
            ):
                raise EgressCheckError("target is outside the declared LAN scope")
            for protocol in ("tcp", "udp"):
                if scope[f"{protocol}_ports"] != generator._ports(scope[f"{protocol}_ports"]):
                    raise EgressCheckError("target port scope is not canonical")
                if scope[f"{protocol}_port_ranges"] != generator._port_ranges(scope[f"{protocol}_port_ranges"]):
                    raise EgressCheckError("target port range is not canonical")
                if any(
                    start <= port <= end
                    for port in scope[f"{protocol}_ports"]
                    for start, end in scope[f"{protocol}_port_ranges"]
                ):
                    raise EgressCheckError("target port overlaps a same-protocol range")
            if not isinstance(scope["allow_icmp"], bool):
                raise EgressCheckError("target ICMP scope is invalid")
    except generator.EgressContractError as exc:
        raise EgressCheckError("manifest network scope is invalid") from exc
    digest = generator.manifest_digest(manifest)
    if bundle["manifest_sha256"] != digest:
        raise EgressCheckError("manifest digest does not match")
    try:
        expected_ruleset = generator.build_ruleset(manifest, digest)
    except (KeyError, TypeError, ValueError) as exc:
        raise EgressCheckError("manifest cannot be rendered safely") from exc
    if bundle["ruleset"] != expected_ruleset:
        raise EgressCheckError("ruleset does not match the manifest")


def _run(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EgressCheckError("host inspection command failed") from exc
    if completed.returncode != 0:
        raise EgressCheckError("host inspection command failed")
    return completed.stdout


def inspect_live_state(bundle: dict[str, Any]) -> dict[str, Any]:
    manifest = bundle["manifest"]
    network_name = manifest["network_name"]
    try:
        inspected = json.loads(_run(["docker", "network", "inspect", network_name]))
        network = inspected[0]
        options = network.get("Options") or {}
        network_driver = network.get("Driver")
        network_bridge = options.get("com.docker.network.bridge.name")
        network_ipv6_enabled = network["EnableIPv6"]
        if not isinstance(network_ipv6_enabled, bool):
            raise TypeError("Docker EnableIPv6 must be boolean")
    except (EgressCheckError, IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise EgressCheckError("Docker network inspection failed") from exc

    bridge_names = []
    try:
        bridge_names = sorted(path.name for path in Path("/sys/class/net").iterdir())
    except OSError as exc:
        raise EgressCheckError("host network interface inspection failed") from exc

    nft_tables = _run(["nft", "list", "tables"])
    native_nftables = "docker-bridges" in nft_tables
    backend = "nftables" if native_nftables else "iptables"
    if native_nftables:
        ipv4_save = ""
    else:
        ipv4_save = _run(["iptables-save"])
    return {
        "backend": backend,
        "network_name": network_name,
        "network_driver": network_driver,
        "network_bridge": network_bridge,
        "network_ipv6_enabled": network_ipv6_enabled,
        "bridge_names": bridge_names,
        "ipv4_save": ipv4_save,
    }


def _chain_rules(save: str, chain: str) -> list[str]:
    prefix = f"-A {chain} "
    return [line.strip() for line in save.splitlines() if line.strip().startswith(prefix)]


def _has_exact_jump(line: str, source_chain: str, target_chain: str) -> bool:
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        return False
    jumps = [index for index, token in enumerate(tokens) if token == "-j"]
    return (
        len(tokens) >= 4
        and tokens[:2] == ["-A", source_chain]
        and len(jumps) == 1
        and tokens[-2:] == ["-j", target_chain]
    )


def _has_forward_jump(save: str) -> bool:
    forward = _chain_rules(save, "FORWARD")
    return bool(forward) and _has_exact_jump(forward[0], "FORWARD", "DOCKER-USER")


def _check_family(observed_save: str, expected: dict[str, Any], family: str) -> list[str]:
    errors: list[str] = []
    docker_user = _chain_rules(observed_save, "DOCKER-USER")
    expected_jump = expected["jump_rule"]
    if not _has_forward_jump(observed_save):
        errors.append(f"{family}_docker_user_unreachable")
    if not docker_user or docker_user[0] != expected_jump:
        errors.append(f"{family}_jump_missing_or_not_first")
    actual_chain = _chain_rules(observed_save, generator.CHAIN_NAME)
    if actual_chain != expected["chain_rules"]:
        errors.append(f"{family}_rules_drift")
    if not actual_chain or actual_chain[-1] != f"-A {generator.CHAIN_NAME} -j DROP":
        errors.append(f"{family}_default_deny_missing")
    return errors


def check(bundle: dict[str, Any], observed: dict[str, Any]) -> list[str]:
    validate_bundle(bundle)
    required_state = {
        "backend", "network_name", "network_driver", "network_bridge",
        "network_ipv6_enabled", "bridge_names", "ipv4_save",
    }
    if set(observed) != required_state:
        raise EgressCheckError("observed state structure is invalid")
    manifest = bundle["manifest"]
    errors: list[str] = []
    if observed["backend"] != manifest["backend"]:
        errors.append("backend_mismatch")
    if observed["network_name"] != manifest["network_name"]:
        errors.append("network_name_mismatch")
    if observed["network_driver"] != "bridge":
        errors.append("network_driver_mismatch")
    if observed["network_bridge"] != manifest["bridge_name"]:
        errors.append("network_bridge_mismatch")
    if not isinstance(observed["network_ipv6_enabled"], bool):
        raise EgressCheckError("observed Docker IPv6 state is invalid")
    if observed["network_ipv6_enabled"] != manifest["network_ipv6_enabled"]:
        errors.append("network_ipv6_mismatch")
    if not isinstance(observed["bridge_names"], list) or manifest["bridge_name"] not in observed["bridge_names"]:
        errors.append("bridge_missing")
    if not isinstance(observed["ipv4_save"], str):
        raise EgressCheckError("observed firewall state is invalid")
    ruleset = bundle["ruleset"]
    errors.extend(_check_family(observed["ipv4_save"], ruleset["ipv4"], "ipv4"))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify NetOps Helper egress state without modifying it.")
    parser.add_argument("--expected", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        bundle = _read_json(arguments.expected.resolve(strict=True), require_mode_600=True)
        validate_bundle(bundle)
        observed = inspect_live_state(bundle)
        errors = check(bundle, observed)
    except (EgressCheckError, OSError):
        print("egress_check=failed code=inspection_error", file=sys.stderr)
        return 2
    if errors:
        print("egress_check=failed codes=" + ",".join(sorted(set(errors))), file=sys.stderr)
        return 1
    print("egress_check=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
