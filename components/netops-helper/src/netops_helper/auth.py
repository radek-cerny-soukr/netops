"""Ephemeral credentials and read-only target policy injected by the local MCP proxy."""

from __future__ import annotations

from base64 import urlsafe_b64decode
from dataclasses import dataclass, field
import hmac
import ipaddress
import json
from pathlib import PurePosixPath
import re
from typing import Any

from .read_policy import (
    READ_QUERIES,
    normalize_platform,
    validate_inventory_item,
    validate_query_inventory,
)


class AuthenticationContextError(ValueError):
    """Raised when the proxy-provided authentication envelope is invalid."""


class AuthenticationMaterialError(AuthenticationContextError):
    """Raised when a tool-specific credential is absent or unsafe."""

    error_code = "auth_material"


class PolicyScopeError(AuthenticationContextError):
    """Raised when a requested capability is outside target policy."""

    error_code = "policy_scope"


class LegacySshProfileRequired(PolicyScopeError):
    """Raised when a target needs an explicitly enrolled legacy SSH profile."""


class EgressScopeError(PolicyScopeError):
    """Raised when a requested destination or protocol is outside egress policy."""

    error_code = "egress_scope"


LEGACY_SSH_PROFILES = ("rsa-sha1",)
_ENVELOPE_KEYS = {
    "alias",
    "host",
    "port",
    "login",
    "password",
    "known_hosts",
    "sftp_roots",
    "read_inventory",
    "account_role",
    "fortios_output_standard_verified",
    "snmp_community",
    "ssh_platform",
    "enabled_queries",
    "legacy_ssh",
    "egress",
}
_EGRESS_KEYS = {
    "addresses",
    "tcp_ports",
    "udp_ports",
    "tcp_port_ranges",
    "udp_port_ranges",
    "allow_icmp",
    "allow_dns",
    "tls_server_names",
}
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def _canonical_ipv4(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version != 4:
        raise ValueError("only IPv4 target addresses are supported")
    return str(address)


def _normalize_dns_name(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("DNS name is invalid")
    try:
        normalized = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("DNS name is invalid") from exc
    if not normalized or len(normalized) > 253:
        raise ValueError("DNS name is invalid")
    if any(not _DNS_LABEL.fullmatch(label) for label in normalized.split(".")):
        raise ValueError("DNS name is invalid")
    return normalized


def _normalize_host(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("target host is invalid")
    address = _canonical_ipv4(value)
    return address if address is not None else _normalize_dns_name(value)


def _normalize_tls_name(value: str) -> str:
    address = _canonical_ipv4(value)
    return address if address is not None else _normalize_dns_name(value)


def _bounded_list(value: object, name: str, limit: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{name} must be a bounded list")
    return value


def _normalize_ports(value: object, name: str) -> tuple[int, ...]:
    items = _bounded_list(value, name, 256)
    if (
        any(
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535
            for port in items
        )
        or len(set(items)) != len(items)
    ):
        raise ValueError(f"{name} contains an invalid or duplicate port")
    return tuple(items)


def _normalize_port_ranges(value: object, name: str) -> tuple[tuple[int, int], ...]:
    items = _bounded_list(value, name, 64)
    normalized: list[tuple[int, int]] = []
    for item in items:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or any(isinstance(port, bool) or not isinstance(port, int) for port in item)
        ):
            raise ValueError(f"{name} contains an invalid range")
        start, end = item
        if not 1 <= start <= end <= 65_535:
            raise ValueError(f"{name} contains an invalid range")
        normalized.append((start, end))
    normalized.sort()
    if any(
        current[0] <= previous[1]
        for previous, current in zip(normalized, normalized[1:])
    ):
        raise ValueError(f"{name} contains overlapping ranges")
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    addresses: tuple[str, ...] = ()
    tcp_ports: tuple[int, ...] = ()
    udp_ports: tuple[int, ...] = ()
    tcp_port_ranges: tuple[tuple[int, int], ...] = ()
    udp_port_ranges: tuple[tuple[int, int], ...] = ()
    allow_icmp: bool = False
    allow_dns: bool = False
    tls_server_names: tuple[str, ...] = ()

    def allows_address(self, address: str) -> bool:
        try:
            canonical = _canonical_ipv4(address)
        except ValueError:
            return False
        return canonical is not None and canonical in self.addresses

    @staticmethod
    def _allows_port(
        port: int,
        explicit: tuple[int, ...],
        ranges: tuple[tuple[int, int], ...],
        *,
        ranges_only: bool = False,
    ) -> bool:
        return (
            not isinstance(port, bool)
            and isinstance(port, int)
            and 1 <= port <= 65_535
            and (
                (not ranges_only and port in explicit)
                or any(start <= port <= end for start, end in ranges)
            )
        )

    def allows_tcp(self, port: int, *, ranges_only: bool = False) -> bool:
        return self._allows_port(
            port, self.tcp_ports, self.tcp_port_ranges, ranges_only=ranges_only,
        )

    def allows_udp(self, port: int) -> bool:
        return self._allows_port(port, self.udp_ports, self.udp_port_ranges)


def _normalize_egress(value: object) -> EgressPolicy:
    if not isinstance(value, dict) or set(value) != _EGRESS_KEYS:
        raise ValueError("egress must contain exactly the supported fields")

    addresses = _bounded_list(value["addresses"], "egress addresses", 256)
    normalized_addresses: list[str] = []
    for address in addresses:
        if not isinstance(address, str):
            raise ValueError("egress addresses must be IPv4 strings")
        canonical = _canonical_ipv4(address)
        if canonical is None or canonical != address:
            raise ValueError("egress addresses must be canonical IPv4 strings")
        normalized_addresses.append(canonical)
    if len(set(normalized_addresses)) != len(normalized_addresses):
        raise ValueError("egress addresses must be unique")

    tls_names = _bounded_list(value["tls_server_names"], "TLS server names", 256)
    if not all(isinstance(name, str) for name in tls_names):
        raise ValueError("TLS server names must be strings")
    normalized_tls_names = [_normalize_dns_name(name) for name in tls_names]
    if normalized_tls_names != tls_names or len(set(tls_names)) != len(tls_names):
        raise ValueError("TLS server names must be unique canonical DNS names")

    allow_icmp = value["allow_icmp"]
    allow_dns = value["allow_dns"]
    if not isinstance(allow_icmp, bool) or not isinstance(allow_dns, bool):
        raise ValueError("egress protocol flags must be boolean")

    tcp_ports = _normalize_ports(value["tcp_ports"], "egress TCP ports")
    udp_ports = _normalize_ports(value["udp_ports"], "egress UDP ports")
    tcp_ranges = _normalize_port_ranges(
        value["tcp_port_ranges"], "egress TCP port ranges",
    )
    udp_ranges = _normalize_port_ranges(
        value["udp_port_ranges"], "egress UDP port ranges",
    )
    if any(start <= port <= end for port in tcp_ports for start, end in tcp_ranges):
        raise ValueError("egress TCP ports overlap an egress TCP port range")
    if any(start <= port <= end for port in udp_ports for start, end in udp_ranges):
        raise ValueError("egress UDP ports overlap an egress UDP port range")

    return EgressPolicy(
        addresses=tuple(normalized_addresses),
        tcp_ports=tcp_ports,
        udp_ports=udp_ports,
        tcp_port_ranges=tcp_ranges,
        udp_port_ranges=udp_ranges,
        allow_icmp=allow_icmp,
        allow_dns=allow_dns,
        tls_server_names=tuple(normalized_tls_names),
    )


def _normalize_inventory(value: object) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, dict) or any(
        key not in {"interfaces", "services", "addresses", "switches"}
        or not isinstance(values, list)
        or not all(isinstance(item, str) for item in values)
        for key, values in value.items()
    ):
        raise TypeError("read_inventory has an invalid structure")
    normalized: dict[str, tuple[str, ...]] = {}
    for key, values in value.items():
        if len(values) > 256 or len(set(values)) != len(values):
            raise ValueError("read_inventory category is too large or contains duplicates")
        clean: list[str] = []
        for item in values:
            if (
                not item or len(item) > 128
                or any(ord(char) < 32 or ord(char) == 127 for char in item)
            ):
                raise ValueError("read_inventory contains an unsafe value")
            try:
                validated = validate_inventory_item(key, item)
            except ValueError as exc:
                raise ValueError("read_inventory contains an unsafe value") from exc
            if validated != item:
                raise ValueError("read_inventory value is not canonical")
            clean.append(validated)
        normalized[key] = tuple(clean)
    return normalized


def _normalize_ssh_policy(
    platform: object,
    queries: object,
) -> tuple[str | None, tuple[str, ...]]:
    if platform is None:
        normalized_platform = None
    elif isinstance(platform, str):
        normalized_platform = normalize_platform(platform)
    else:
        raise TypeError("ssh_platform must be a supported string or null")

    query_items = _bounded_list(queries, "enabled_queries", 256)
    if not all(
        isinstance(query, str)
        and query
        and len(query) <= 128
        and not any(ord(char) < 32 or ord(char) == 127 for char in query)
        for query in query_items
    ):
        raise ValueError("enabled_queries contains an invalid query")
    if len(set(query_items)) != len(query_items):
        raise ValueError("enabled_queries contains a duplicate query")
    normalized_queries = tuple(query_items)
    if normalized_platform is None:
        if normalized_queries:
            raise ValueError("enabled_queries requires ssh_platform")
    else:
        available = READ_QUERIES[normalized_platform]
        if any(query not in available for query in normalized_queries):
            raise ValueError("enabled_queries contains an unknown platform query")
    return normalized_platform, normalized_queries


def _normalize_legacy_ssh(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in LEGACY_SSH_PROFILES:
        raise ValueError("legacy_ssh must be null or a supported profile name")
    return value


@dataclass(frozen=True, slots=True)
class TargetAuth:
    alias: str
    host: str
    port: int
    login: str
    password: str
    known_hosts: str
    sftp_roots: tuple[str, ...] = ()
    read_inventory: dict[str, tuple[str, ...]] = field(default_factory=dict)
    account_role: str = "read-only"
    fortios_output_standard_verified: bool = False
    snmp_community: str | None = None
    ssh_platform: str | None = None
    enabled_queries: tuple[str, ...] = ()
    egress: EgressPolicy = field(default_factory=EgressPolicy)
    legacy_ssh: str | None = None

    @classmethod
    def decode(cls, expected_alias: str, context: str) -> "TargetAuth":
        try:
            padding = "=" * (-len(context) % 4)
            raw = urlsafe_b64decode((context + padding).encode("ascii"))
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise TypeError("authentication context must be an object")
            if set(data) - _ENVELOPE_KEYS:
                raise ValueError("authentication context contains unsupported fields")
            if "ssh_platform" not in data or "enabled_queries" not in data or "egress" not in data:
                raise ValueError("authentication context is missing mandatory policy fields")
            if not {"alias", "host", "port", "login", "password"} <= set(data):
                raise ValueError("authentication context is missing required identity fields")

            alias = data["alias"]
            port = data["port"]
            login = data["login"]
            password = data["password"]
            known_hosts = data.get("known_hosts", "")
            account_role = data.get("account_role", "")
            verified = data.get("fortios_output_standard_verified", False)
            if (
                not isinstance(alias, str) or not 0 < len(alias) <= 128
                or any(ord(char) < 33 or ord(char) == 127 for char in alias)
                or isinstance(port, bool) or not isinstance(port, int)
                or not 1 <= port <= 65_535
                or not isinstance(login, str) or not login or len(login) > 512
                or any(ord(char) < 32 or ord(char) == 127 for char in login)
                or not isinstance(password, str)
                or not 3 <= len(password.encode("utf-8")) <= 4_096
                or "\x00" in password or "\x7f" in password
                or not isinstance(known_hosts, str) or len(known_hosts) > 65_536
                or "\x00" in known_hosts or "\x7f" in known_hosts
                or "known_hosts" in data and not known_hosts.strip()
                or not isinstance(account_role, str)
                or not isinstance(verified, bool)
            ):
                raise ValueError("authentication context contains invalid identity material")

            host = _normalize_host(data["host"])
            ssh_platform, enabled_queries = _normalize_ssh_policy(
                data["ssh_platform"], data["enabled_queries"],
            )
            legacy_ssh = _normalize_legacy_ssh(data.get("legacy_ssh"))
            egress = _normalize_egress(data["egress"])
            read_inventory = _normalize_inventory(
                data.get("read_inventory", {}),
            )
            validate_query_inventory(
                ssh_platform,
                enabled_queries,
                read_inventory,
            )

            snmp_community = data.get("snmp_community")
            if "snmp_community" in data and (
                not isinstance(snmp_community, str)
                or not 3 <= len(snmp_community.encode("utf-8")) <= 255
                or any(ord(char) < 32 or ord(char) == 127 for char in snmp_community)
            ):
                raise ValueError("snmp_community must contain 3-255 printable UTF-8 bytes")

            roots = data.get("sftp_roots", [])
            if (
                not isinstance(roots, list) or len(roots) > 256
                or not all(isinstance(root, str) for root in roots)
                or len(set(roots)) != len(roots)
            ):
                raise TypeError("sftp_roots must be a bounded unique list of strings")
            for root in roots:
                normalized = str(PurePosixPath(root))
                if (
                    not root.startswith("/") or root.startswith("//") or root == "/"
                    or root != normalized or len(root) > 2_000
                    or ".." in PurePosixPath(root).parts
                    or any(ord(char) < 32 or ord(char) == 127 for char in root)
                ):
                    raise ValueError("sftp_roots contains an unsafe root")
            normalized_roots = tuple(roots)

            result = cls(
                alias=alias,
                host=host,
                port=port,
                login=login,
                password=password,
                known_hosts=known_hosts,
                sftp_roots=normalized_roots,
                read_inventory=read_inventory,
                account_role=account_role,
                fortios_output_standard_verified=verified,
                snmp_community=snmp_community,
                ssh_platform=ssh_platform,
                enabled_queries=enabled_queries,
                egress=egress,
                legacy_ssh=legacy_ssh,
            )
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            raise AuthenticationContextError("invalid ephemeral authentication context") from exc

        if result.alias != expected_alias:
            raise AuthenticationContextError("target alias does not match authentication context")
        if not result.host or not result.login or not result.password:
            raise AuthenticationContextError("authentication context has empty required fields")
        if not 1 <= result.port <= 65_535:
            raise AuthenticationContextError("authentication context has invalid port")
        if result.account_role != "read-only":
            raise AuthenticationContextError("target is not explicitly enrolled as a read-only account")
        if (
            result.snmp_community is not None
            and hmac.compare_digest(
                result.snmp_community.encode("utf-8"), result.password.encode("utf-8")
            )
        ):
            raise AuthenticationMaterialError("SNMP community must differ from the account password")
        literal_host = _canonical_ipv4(result.host)
        if literal_host is not None:
            if not result.egress.allows_address(literal_host):
                raise EgressScopeError("target address is outside the egress allowlist")
        elif not result.egress.allow_dns or not result.egress.addresses:
            raise EgressScopeError(
                "hostname targets require DNS permission and explicit IPv4 addresses"
            )
        return result

    def require_known_hosts(self) -> None:
        if not self.known_hosts.strip():
            raise AuthenticationContextError("verified SSH host keys are unavailable")

    def require_snmp_community(self) -> str:
        community = self.snmp_community
        password = self.password
        if community is None:
            raise AuthenticationMaterialError("SNMP community is not enrolled for this target")
        if not isinstance(community, str) or not isinstance(password, str):
            raise AuthenticationMaterialError(
                "SNMP authentication material has an unsafe structure"
            )
        try:
            community_bytes = community.encode("utf-8")
            password_bytes = password.encode("utf-8")
        except UnicodeError as exc:
            raise AuthenticationMaterialError(
                "SNMP authentication material has an unsafe structure"
            ) from exc
        if (
            not 3 <= len(community_bytes) <= 255
            or any(ord(char) < 32 or ord(char) == 127 for char in community)
        ):
            raise AuthenticationMaterialError("SNMP community has an unsafe structure")
        if hmac.compare_digest(community_bytes, password_bytes):
            raise AuthenticationMaterialError(
                "SNMP community must differ from the account password"
            )
        return community

    def require_ssh_query(self, platform: str, query: str) -> str:
        normalized = normalize_platform(platform)
        if self.ssh_platform is None:
            raise PolicyScopeError("SSH queries are not enabled for this target")
        if normalized != self.ssh_platform:
            raise PolicyScopeError("SSH platform is outside target policy")
        if query not in self.enabled_queries:
            raise PolicyScopeError("SSH query is not enabled for this target")
        return normalized

    def require_tcp_port(self, port: int) -> int:
        if not self.egress.allows_tcp(port):
            raise EgressScopeError("TCP port is outside the target egress allowlist")
        return port

    def require_passive_tcp_range(self) -> None:
        if not self.egress.tcp_port_ranges:
            raise EgressScopeError("FTP requires a non-empty passive TCP port range")

    def require_passive_tcp_port(self, port: int) -> int:
        if not self.egress.allows_tcp(port, ranges_only=True):
            raise EgressScopeError("FTP passive port is outside the target egress allowlist")
        return port

    def require_udp_port(self, port: int) -> int:
        if not self.egress.allows_udp(port):
            raise EgressScopeError("UDP port is outside the target egress allowlist")
        return port

    def require_dns(self) -> None:
        if not self.egress.allow_dns:
            raise EgressScopeError("DNS is not enabled for this target")

    def require_icmp(self) -> None:
        if not self.egress.allow_icmp:
            raise EgressScopeError("ICMP is not enabled for this target")

    def require_tls_server_name(self, server_name: str | None) -> str:
        selected = server_name or self.host
        if selected == self.host:
            return selected
        normalized = _normalize_dns_name(selected)
        if normalized != selected or normalized not in self.egress.tls_server_names:
            raise EgressScopeError("TLS server name is outside the target egress allowlist")
        return selected


    @property
    def secrets(self) -> tuple[str, ...]:
        """Only credentials are secrets; diagnostic identifiers must remain observable."""
        return tuple(dict.fromkeys(
            value for value in (self.password, self.snmp_community) if value
        ))
