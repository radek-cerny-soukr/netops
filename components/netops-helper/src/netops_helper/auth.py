"""Ephemeral credentials and read-only target policy injected by the local MCP proxy."""

from __future__ import annotations

from base64 import urlsafe_b64decode
from dataclasses import dataclass, field
from .config_limits import ConfigurationLimits
import ipaddress
import json
from pathlib import PurePosixPath
import re
from typing import Any

from netops_core.hostkey import HostKeyError, checked_pin
from netops_core.legacy_ssh import LegacySshError, checked as checked_legacy_ssh
from netops_core.platforms import PlatformError, normalize as normalize_canonical_platform
from netops_core.vault import PRIVATE_KEY_HEADER
from netops_core.snmp import validate_snmp_usm

from .inventory import INVENTORY_CATEGORIES, InventoryError, unique_object
from .query_catalog.model import DEVICE_TYPES
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


LEGACY_SSH_PROFILES = ("rsa-sha1", "rsa-sha1-dh14")
ENVELOPE_VERSION = "0.3.0"
CREDENTIAL_KINDS = ("password", "ssh-key")
_CATALOG_PLATFORMS = {"fortios": "fortinet", "exos": "extreme_exos"}
ADMIN_BOUNDED_PLATFORMS = frozenset({"fortinet", "fortiadc", "ruckus_unleashed"})
_ENVELOPE_KEYS = {
    "alias",
    "host",
    "port",
    "login",
    "credential_kind",
    "secret",
    "host_key_fingerprint",
    "sftp_roots",
    "read_inventory",
    "configuration_limits",
    "account_role",
    "role_boundary",
    "fortios_output_standard_verified",
    "snmp_usm",
    "ssh_platform",
    "enabled_queries",
    "device_types",
    "legacy_ssh",
    "egress",
    "tls_ca_certificate",
    "fortios_rest_port",
    "fortios_rest_token",
    "fortios_rest_certificate_sha256",
    "fortios_rest_rate_limit",
    "wifi_thresholds",
    "locate_read_limit",
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
        key not in INVENTORY_CATEGORIES
        or not isinstance(values, list)
        or not all(isinstance(item, str) for item in values)
        for key, values in value.items()
    ):
        raise TypeError("read_inventory has an invalid structure")
    normalized: dict[str, tuple[str, ...]] = {}
    for key, values in value.items():
        if len(values) > (4096 if key == "schema_paths" else 256) or len(set(values)) != len(values):
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
    rights = normalized.get("config_access", ())
    if "compare" in rights and "read" not in rights:
        raise ValueError("config_access compare requires read")
    return normalized


def _normalize_ssh_policy(
    platform: object,
    queries: object,
) -> tuple[str | None, tuple[str, ...]]:
    if platform is None:
        normalized_platform = None
    elif isinstance(platform, str):
        canonical = normalize_canonical_platform(platform)
        normalized_platform = normalize_platform(
            _CATALOG_PLATFORMS.get(canonical, canonical)
        )
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


def _normalize_device_types(value: object) -> tuple[str, ...]:
    items = _bounded_list(value, "device_types", len(DEVICE_TYPES))
    if any(item not in DEVICE_TYPES for item in items) or len(set(items)) != len(items):
        raise ValueError("device_types must be a unique subset of " + ", ".join(DEVICE_TYPES))
    return tuple(items)


def _normalize_legacy_ssh(value: object) -> str | None:
    return checked_legacy_ssh(value)


def _normalize_credential(kind: object, secret: object) -> tuple[str, str]:
    if not isinstance(kind, str) or kind not in CREDENTIAL_KINDS:
        raise ValueError("credential_kind must be one of " + ", ".join(CREDENTIAL_KINDS))
    if not isinstance(secret, str) or "\x00" in secret or "\x7f" in secret:
        raise ValueError("secret must be printable text")
    if kind == "ssh-key":
        if PRIVATE_KEY_HEADER.match(secret) is None or not 64 <= len(
            secret.encode("utf-8")
        ) <= 65_536:
            raise ValueError("an ssh-key secret must hold a bounded private key document")
    elif not 3 <= len(secret.encode("utf-8")) <= 4_096:
        raise ValueError("a password secret must contain 3-4096 UTF-8 bytes")
    return kind, secret


@dataclass(frozen=True, slots=True)
class TargetAuth:
    alias: str
    host: str
    port: int
    login: str
    secret: str
    host_key_fingerprint: str
    credential_kind: str = "password"
    sftp_roots: tuple[str, ...] = ()
    read_inventory: dict[str, tuple[str, ...]] = field(default_factory=dict)
    account_role: str = "read-only"
    role_boundary: str | None = None
    fortios_output_standard_verified: bool = False
    snmp_usm: dict[str, str] | None = field(default=None, repr=False)
    ssh_platform: str | None = None
    enabled_queries: tuple[str, ...] = ()
    egress: EgressPolicy = field(default_factory=EgressPolicy)
    legacy_ssh: str | None = None
    configuration_limits: ConfigurationLimits = field(default_factory=ConfigurationLimits)
    tls_ca_certificate: str | None = None
    fortios_rest_port: int = 443
    fortios_rest_token: str | None = field(default=None, repr=False)
    fortios_rest_certificate_sha256: str | None = None
    locate_read_limit: int = 40
    wifi_thresholds: dict = field(default_factory=dict)
    fortios_rest_rate_limit: dict = field(default_factory=lambda: {"requests": 30, "window_seconds": 60})
    output_secrets: tuple[str, ...] = field(default=(), repr=False)
    device_types: tuple[str, ...] = ()

    @classmethod
    def decode(cls, expected_alias: str, context: str) -> "TargetAuth":
        try:
            padding = "=" * (-len(context) % 4)
            raw = urlsafe_b64decode((context + padding).encode("ascii"))
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
            if not isinstance(data, dict):
                raise TypeError("authentication context must be an object")
            if set(data) - _ENVELOPE_KEYS:
                raise ValueError("authentication context contains unsupported fields")
            if "ssh_platform" not in data or "enabled_queries" not in data or "egress" not in data:
                raise ValueError("authentication context is missing mandatory policy fields")
            if not {
                "alias", "host", "port", "login",
                "credential_kind", "secret", "host_key_fingerprint",
            } <= set(data):
                raise ValueError("authentication context is missing required identity fields")

            alias = data["alias"]
            port = data["port"]
            login = data["login"]
            account_role = data.get("account_role", "")
            verified = data.get("fortios_output_standard_verified", False)
            if (
                not isinstance(alias, str) or not 0 < len(alias) <= 128
                or any(ord(char) < 33 or ord(char) == 127 for char in alias)
                or isinstance(port, bool) or not isinstance(port, int)
                or not 1 <= port <= 65_535
                or not isinstance(login, str) or not login or len(login) > 512
                or any(ord(char) < 32 or ord(char) == 127 for char in login)
                or not isinstance(account_role, str)
                or not isinstance(verified, bool)
            ):
                raise ValueError("authentication context contains invalid identity material")

            credential_kind, secret = _normalize_credential(
                data["credential_kind"], data["secret"],
            )
            host_key_fingerprint = checked_pin(data["host_key_fingerprint"])

            host = _normalize_host(data["host"])
            ssh_platform, enabled_queries = _normalize_ssh_policy(
                data["ssh_platform"], data["enabled_queries"],
            )
            device_types = _normalize_device_types(data.get("device_types", []))
            if ssh_platform is not None and any(
                READ_QUERIES[ssh_platform][query].group not in (None, *device_types)
                for query in enabled_queries
            ):
                raise ValueError("enabled_queries need a device type the target does not declare")
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

            snmp_usm = (
                validate_snmp_usm(data["snmp_usm"]) if "snmp_usm" in data else None
            )

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

            tls_ca = data.get("tls_ca_certificate")
            if tls_ca is not None and (
                not isinstance(tls_ca, str) or not tls_ca.startswith("/")
                or tls_ca.startswith("//") or tls_ca != str(PurePosixPath(tls_ca))
                or len(tls_ca) > 2_000 or ".." in PurePosixPath(tls_ca).parts
                or any(ord(char) < 32 or ord(char) == 127 for char in tls_ca)
            ):
                raise ValueError("tls_ca_certificate must be a canonical absolute path")

            from .inventory import _checked_rate_limit, checked_rest_port
            rest_port = checked_rest_port(data.get("fortios_rest_port", 443))
            rest_token = data.get("fortios_rest_token")
            rest_pin = data.get("fortios_rest_certificate_sha256")
            if rest_token is not None or rest_pin is not None:
                from .wifi_rest import checked_token, checked_pin as checked_rest_pin
                rest_token = checked_token(rest_token)
                rest_pin = checked_rest_pin(rest_pin)
            rest_rate = _checked_rate_limit("FortiOS REST", data.get("fortios_rest_rate_limit", {
                "requests": 30, "window_seconds": 60}))
            if rest_token is not None and (ssh_platform != "fortinet" or (rest_pin is None and tls_ca is None)):
                raise ValueError("FortiOS REST requires a FortiOS target and certificate pin or CA")
            from .wifi_policy import thresholds
            wifi_thresholds = thresholds(data.get("wifi_thresholds"))
            locate_read_limit = data.get("locate_read_limit", 40)
            if type(locate_read_limit) is not int or not 1 <= locate_read_limit <= 40:
                raise ValueError("locate_read_limit must be a whole number from 1 to 40")
            result = cls(
                alias=alias,
                host=host,
                port=port,
                login=login,
                secret=secret,
                host_key_fingerprint=host_key_fingerprint,
                credential_kind=credential_kind,
                sftp_roots=normalized_roots,
                read_inventory=read_inventory,
                configuration_limits=ConfigurationLimits.from_mapping(data.get("configuration_limits", {})),
                account_role=account_role,
                role_boundary=data.get("role_boundary"),
                fortios_output_standard_verified=verified,
                snmp_usm=snmp_usm,
                ssh_platform=ssh_platform,
                enabled_queries=enabled_queries,
                egress=egress,
                legacy_ssh=legacy_ssh,
                tls_ca_certificate=tls_ca,
                fortios_rest_port=rest_port,
                fortios_rest_token=rest_token,
                fortios_rest_certificate_sha256=rest_pin,
                fortios_rest_rate_limit=rest_rate,
                wifi_thresholds=wifi_thresholds,
                locate_read_limit=locate_read_limit,
                device_types=device_types,
            )
        except (
            KeyError, TypeError, ValueError, UnicodeError, RecursionError,
            HostKeyError, LegacySshError, PlatformError, InventoryError,
        ) as exc:
            raise AuthenticationContextError("invalid ephemeral authentication context") from exc

        if result.alias != expected_alias:
            raise AuthenticationContextError("target alias does not match authentication context")
        if not result.host or not result.login or not result.secret:
            raise AuthenticationContextError("authentication context has empty required fields")
        if not 1 <= result.port <= 65_535:
            raise AuthenticationContextError("authentication context has invalid port")
        if (result.account_role, result.role_boundary) != ("read-only", None) and not (
            result.account_role == "admin-bounded" and result.role_boundary == "catalogue"
            and result.ssh_platform in ADMIN_BOUNDED_PLATFORMS
        ):
            raise AuthenticationContextError(
                "target is not explicitly enrolled as a read-only account or as an"
                " admin-bounded account on a supported platform"
            )
        literal_host = _canonical_ipv4(result.host)
        if literal_host is not None:
            if not result.egress.allows_address(literal_host):
                raise EgressScopeError("target address is outside the egress allowlist")
        elif not result.egress.allow_dns or not result.egress.addresses:
            raise EgressScopeError(
                "hostname targets require DNS permission and explicit IPv4 addresses"
            )
        return result

    def require_snmp_usm(self) -> dict[str, str]:
        try:
            return validate_snmp_usm(self.snmp_usm)
        except ValueError:
            raise AuthenticationMaterialError(
                "SNMPv3 authPriv material is absent or invalid"
            ) from None

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
    def redaction_secrets(self) -> tuple[str, ...]:
        """Every value redacted from a paged result: the credentials plus the private handoff."""
        return tuple(dict.fromkeys((*self.secrets, *self.output_secrets)))

    @property
    def secrets(self) -> tuple[str, ...]:
        """Only credentials are secrets; diagnostic identifiers must remain observable."""
        usm = self.snmp_usm if isinstance(self.snmp_usm, dict) else {}
        return tuple(dict.fromkeys(
            value for value in (self.secret, self.fortios_rest_token, usm.get("auth_key"), usm.get("priv_key"))
            if isinstance(value, str) and value
        ))
