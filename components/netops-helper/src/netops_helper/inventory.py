"""Validation of the helper section of the shared device inventory."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import PurePosixPath
import re
from typing import Any

from netops_core import inventory as core

from .read_policy import (
    PLATFORM_MAP,
    READ_QUERIES,
    normalize_platform,
    validate_inventory_item,
    validate_query_inventory,
)

CONSUMER = "helper"
FILE_VERSION = core.FILE_VERSION
SECTION_FIELDS = (
    "account_role",
    "ssh_platform",
    "enabled_queries",
    "read_inventory",
    "sftp_roots",
    "fortios_output_standard_verified",
    "rate_limit",
    "egress",
    "snmp_credential",
)
REQUIRED_SECTION_FIELDS = (
    "account_role", "ssh_platform", "enabled_queries", "egress",
)
EGRESS_FIELDS = (
    "addresses",
    "tcp_ports",
    "udp_ports",
    "tcp_port_ranges",
    "udp_port_ranges",
    "allow_icmp",
    "allow_dns",
    "tls_server_names",
)
EGRESS_POLICY_FIELDS = (
    "schema_version",
    "profile",
    "backend",
    "bridge_name",
    "network_name",
    "ipv6_mode",
    "dns_resolvers",
    "lan_cidrs",
)
ACCOUNT_ROLE = "read-only"
CATALOG_PLATFORMS = {"fortios": "fortinet", "exos": "extreme_exos"}
CREDENTIAL_KINDS = ("password", "ssh-key")
SNMP_CREDENTIAL_KIND = "snmp-community"
INVENTORY_CATEGORIES = ("interfaces", "services", "addresses", "switches", "vlans", "managed_switches", "certificates")
POLICY_SCHEMA = 1
BACKEND = "iptables"
BRIDGE_NAME = "nh-egress0"
NETWORK_NAME = "netops-helper"
PROFILES = ("strict-target", "lan-constrained")
IPV6_MODE = "deny"
DEFAULT_RATE_REQUESTS = 30
DEFAULT_RATE_WINDOW_SECONDS = 60
MAX_QUERIES = 256
MAX_ROOTS = 256
MAX_ROOT_LENGTH = 2_000
MAX_INVENTORY_ITEMS = 256
MAX_DESTINATIONS = 256
MAX_PORTS = 256
MAX_RANGES = 64
MAX_TLS_SERVER_NAMES = 256
MAX_DNS_RESOLVERS = 16
MAX_LAN_CIDRS = 32
RFC1918_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    (0x0A000000, 8), (0xAC100000, 12), (0xC0A80000, 16),
))
SAFE_QUERY_NAME = re.compile(r"[a-z][a-z0-9_]{0,127}")
SAFE_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

InventoryError = core.InventoryError
Device = core.Device


class RoleError(InventoryError):
    """Raised when a device is not explicitly enrolled as a read-only account."""


@dataclass(frozen=True)
class HelperSection:
    account_role: str
    ssh_platform: str | None
    enabled_queries: tuple
    read_inventory: dict
    sftp_roots: tuple
    fortios_output_standard_verified: bool
    rate_limit: dict
    egress: dict
    snmp_credential: str | None

    def catalog_platform(self) -> str | None:
        return catalog_platform(self.ssh_platform)


def catalog_platform(value: str | None) -> str | None:
    if value is None:
        return None
    return normalize_platform(CATALOG_PLATFORMS.get(value, value))


def ipv4_literal(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version != 4 or str(address) != value:
        return None
    return value


def safe_dns_name(value: Any) -> bool:
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


def _bounded_list(where: str, name: str, value: Any, maximum: int) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        raise InventoryError(
            "%s: %s must be a list of at most %d entries, got %r"
            % (where, name, maximum, value)
        )
    return value


def _checked_ports(where: str, name: str, value: Any) -> list:
    items = _bounded_list(where, name, value, MAX_PORTS)
    for port in items:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise InventoryError(
                "%s: %s must hold whole numbers between 1 and 65535, got %r"
                % (where, name, port)
            )
    if len(set(items)) != len(items):
        raise InventoryError("%s: %s must be unique" % (where, name))
    return sorted(items)


def _checked_port_ranges(where: str, name: str, value: Any) -> list:
    items = _bounded_list(where, name, value, MAX_RANGES)
    result: list = []
    for item in items:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or any(isinstance(part, bool) or not isinstance(part, int) for part in item)
        ):
            raise InventoryError(
                "%s: %s must hold [start, end] pairs of whole numbers, got %r"
                % (where, name, item)
            )
        start, end = item
        if not 1 <= start <= end <= 65_535:
            raise InventoryError(
                "%s: %s must hold ranges between 1 and 65535, got %r" % (where, name, item)
            )
        result.append([start, end])
    result.sort()
    if any(current[0] <= previous[1] for previous, current in zip(result, result[1:])):
        raise InventoryError("%s: %s must not overlap" % (where, name))
    return result


def _checked_egress(where: str, value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != set(EGRESS_FIELDS):
        raise InventoryError(
            "%s: egress must hold exactly the fields %s, got %r"
            % (where, ", ".join(EGRESS_FIELDS), value)
        )
    addresses = _bounded_list(where, "egress addresses", value["addresses"], MAX_DESTINATIONS)
    for item in addresses:
        if ipv4_literal(item) is None:
            raise InventoryError(
                "%s: egress addresses must hold canonical IPv4 literals, got %r"
                % (where, item)
            )
    if len(set(addresses)) != len(addresses):
        raise InventoryError("%s: egress addresses must be unique" % where)
    names = _bounded_list(
        where, "egress tls_server_names", value["tls_server_names"], MAX_TLS_SERVER_NAMES,
    )
    if not all(safe_dns_name(name) for name in names):
        raise InventoryError(
            "%s: egress tls_server_names must hold canonical lowercase DNS names, got %r"
            % (where, names)
        )
    if len(set(names)) != len(names):
        raise InventoryError("%s: egress tls_server_names must be unique" % where)
    for name in ("allow_icmp", "allow_dns"):
        if not isinstance(value[name], bool):
            raise InventoryError(
                "%s: egress %s must be true or false, got %r" % (where, name, value[name])
            )
    ports = {
        name: _checked_ports(where, "egress " + name, value[name])
        for name in ("tcp_ports", "udp_ports")
    }
    ranges = {
        name: _checked_port_ranges(where, "egress " + name, value[name])
        for name in ("tcp_port_ranges", "udp_port_ranges")
    }
    for protocol in ("tcp", "udp"):
        if any(
            start <= port <= end
            for port in ports["%s_ports" % protocol]
            for start, end in ranges["%s_port_ranges" % protocol]
        ):
            raise InventoryError(
                "%s: an explicit egress %s port must not repeat a port of a %s range"
                % (where, protocol, protocol)
            )
    return {
        "addresses": sorted(addresses, key=lambda item: int(ipaddress.IPv4Address(item))),
        "tcp_ports": ports["tcp_ports"],
        "udp_ports": ports["udp_ports"],
        "tcp_port_ranges": ranges["tcp_port_ranges"],
        "udp_port_ranges": ranges["udp_port_ranges"],
        "allow_icmp": value["allow_icmp"],
        "allow_dns": value["allow_dns"],
        "tls_server_names": sorted(names),
    }


def _checked_platform(where: str, value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in core.platforms.PLATFORMS:
        raise InventoryError(
            "%s: ssh_platform must be null or one of the canonical platform names %s,"
            " got %r" % (where, ", ".join(core.platforms.PLATFORMS), value)
        )
    if CATALOG_PLATFORMS.get(value, value) not in PLATFORM_MAP:
        raise InventoryError(
            "%s: ssh_platform %r has no read query catalogue in this component"
            % (where, value)
        )
    return value


def _checked_queries(where: str, platform: str | None, value: Any) -> tuple:
    items = _bounded_list(where, "enabled_queries", value, MAX_QUERIES)
    for query in items:
        if not isinstance(query, str) or SAFE_QUERY_NAME.fullmatch(query) is None:
            raise InventoryError(
                "%s: enabled_queries must hold catalogue query names, got %r" % (where, query)
            )
    if len(set(items)) != len(items):
        raise InventoryError("%s: enabled_queries must be unique" % where)
    if platform is None:
        if items:
            raise InventoryError(
                "%s: enabled_queries must be empty for a device without ssh_platform" % where
            )
        return ()
    available = READ_QUERIES[catalog_platform(platform)]
    unknown = [query for query in items if query not in available]
    if unknown:
        raise InventoryError(
            "%s: enabled_queries holds names outside the %s catalogue: %s"
            % (where, platform, ", ".join(unknown))
        )
    return tuple(items)


def _checked_read_inventory(where: str, value: Any) -> dict:
    if not isinstance(value, dict):
        raise InventoryError("%s: read_inventory must be an object, got %r" % (where, value))
    unknown = sorted(set(value) - set(INVENTORY_CATEGORIES))
    if unknown:
        raise InventoryError(
            "%s: read_inventory holds unknown categories: %s" % (where, ", ".join(unknown))
        )
    normalized: dict = {}
    for category in sorted(value):
        items = _bounded_list(
            where, "read_inventory " + category, value[category], MAX_INVENTORY_ITEMS,
        )
        if len(set(items)) != len(items):
            raise InventoryError(
                "%s: read_inventory %s must be unique" % (where, category)
            )
        clean: list = []
        for item in items:
            if (
                not isinstance(item, str)
                or not item
                or len(item) > 128
                or any(ord(character) < 32 or ord(character) == 127 for character in item)
            ):
                raise InventoryError(
                    "%s: read_inventory %s holds an unsafe value %r"
                    % (where, category, item)
                )
            try:
                validated = validate_inventory_item(category, item)
            except ValueError as error:
                raise InventoryError(
                    "%s: read_inventory %s holds an unsafe value %r (%s)"
                    % (where, category, item, error)
                ) from None
            if validated != item:
                raise InventoryError(
                    "%s: read_inventory %s must hold the canonical form %r, got %r"
                    % (where, category, validated, item)
                )
            clean.append(item)
        normalized[category] = tuple(clean)
    return normalized


def _checked_roots(where: str, value: Any) -> tuple:
    roots = _bounded_list(where, "sftp_roots", value, MAX_ROOTS)
    for root in roots:
        if not isinstance(root, str):
            raise InventoryError("%s: sftp_roots must hold strings, got %r" % (where, root))
        if (
            not root.startswith("/")
            or root.startswith("//")
            or root == "/"
            or root != str(PurePosixPath(root))
            or len(root) > MAX_ROOT_LENGTH
            or ".." in PurePosixPath(root).parts
            or any(ord(character) < 32 or ord(character) == 127 for character in root)
        ):
            raise InventoryError(
                "%s: sftp_roots must hold canonical absolute paths below the root"
                " directory, got %r" % (where, root)
            )
    if len(set(roots)) != len(roots):
        raise InventoryError("%s: sftp_roots must be unique" % where)
    return tuple(roots)


def _checked_rate_limit(where: str, value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != {"requests", "window_seconds"}:
        raise InventoryError(
            "%s: rate_limit must hold exactly requests and window_seconds, got %r"
            % (where, value)
        )
    requests, window = value["requests"], value["window_seconds"]
    if (
        isinstance(requests, bool) or not isinstance(requests, int)
        or not 1 <= requests <= 60
        or isinstance(window, bool) or not isinstance(window, int)
        or not 1 <= window <= 3_600
    ):
        raise InventoryError(
            "%s: rate_limit requests must be 1 to 60 and window_seconds 1 to 3600, got %r"
            % (where, value)
        )
    return {"requests": requests, "window_seconds": window}


def _checked_credential(where: str, entry: Device, kinds: dict | None) -> None:
    if entry.credential is None:
        raise InventoryError(
            "%s: credential must name a record in the credential store, a device is"
            " reached with an account" % where
        )
    if entry.host_key_fingerprint is None:
        raise InventoryError(
            "%s: host_key_fingerprint must pin the host key of the device, there is no"
            " first contact trust" % where
        )
    if kinds is None:
        return
    kind = kinds.get(entry.credential)
    if kind is None:
        raise InventoryError(
            "%s: credential %r is not a record of the credential store"
            % (where, entry.credential)
        )
    if kind not in CREDENTIAL_KINDS:
        raise InventoryError(
            "%s: credential %r has kind %s, a device is reached with one of: %s"
            % (where, entry.credential, kind, ", ".join(CREDENTIAL_KINDS))
        )


def _checked_snmp_credential(where: str, value: Any, kinds: dict | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise InventoryError(
            "%s: snmp_credential must be null or name a record in the credential store,"
            " got %r" % (where, value)
        )
    if kinds is not None:
        kind = kinds.get(value)
        if kind is None:
            raise InventoryError(
                "%s: snmp_credential %r is not a record of the credential store"
                % (where, value)
            )
        if kind != SNMP_CREDENTIAL_KIND:
            raise InventoryError(
                "%s: snmp_credential %r has kind %s, it must be %s"
                % (where, value, kind, SNMP_CREDENTIAL_KIND)
            )
    return value


def _checked_reach(where: str, entry: Device, egress: dict) -> None:
    if entry.address is None:
        raise InventoryError(
            "%s: address and port must name the device, the helper reaches it over the"
            " network" % where
        )
    literal = ipv4_literal(entry.address)
    if literal is not None:
        if literal not in egress["addresses"]:
            raise InventoryError(
                "%s: address %s must be listed in egress addresses" % (where, literal)
            )
        return
    if not egress["allow_dns"] or not egress["addresses"]:
        raise InventoryError(
            "%s: a device named by a host name requires egress allow_dns and the"
            " explicit IPv4 addresses it is allowed to resolve to" % where
        )


def section(entry: Device, kinds: dict | None = None) -> HelperSection:
    where = "device %s: helper section" % entry.name
    item = entry.helper
    if not isinstance(item, dict):
        raise InventoryError("%s: must be an object, got %r" % (where, item))
    missing = [name for name in REQUIRED_SECTION_FIELDS if name not in item]
    if missing:
        raise InventoryError("%s: missing fields: %s" % (where, ", ".join(missing)))
    unknown = sorted(set(item) - set(SECTION_FIELDS))
    if unknown:
        raise InventoryError("%s: unknown fields: %s" % (where, ", ".join(unknown)))
    if item["account_role"] != ACCOUNT_ROLE:
        raise RoleError(
            "%s: account_role must be %r, an account the operator has not declared"
            " read-only is refused, got %r" % (where, ACCOUNT_ROLE, item["account_role"])
        )
    platform = _checked_platform(where, item["ssh_platform"])
    queries = _checked_queries(where, platform, item["enabled_queries"])
    read_inventory = _checked_read_inventory(where, item.get("read_inventory", {}))
    try:
        validate_query_inventory(catalog_platform(platform), queries, read_inventory)
    except (KeyError, TypeError, ValueError) as error:
        raise InventoryError(
            "%s: read_inventory does not hold usable values for the enabled queries (%s)"
            % (where, error)
        ) from None
    verified = item.get("fortios_output_standard_verified", False)
    if not isinstance(verified, bool):
        raise InventoryError(
            "%s: fortios_output_standard_verified must be true or false, got %r"
            % (where, verified)
        )
    egress = _checked_egress(where, item["egress"])
    _checked_credential(where, entry, kinds)
    _checked_reach(where, entry, egress)
    return HelperSection(
        account_role=ACCOUNT_ROLE,
        ssh_platform=platform,
        enabled_queries=queries,
        read_inventory=read_inventory,
        sftp_roots=_checked_roots(where, item.get("sftp_roots", [])),
        fortios_output_standard_verified=verified,
        rate_limit=_checked_rate_limit(where, item.get("rate_limit", {
            "requests": DEFAULT_RATE_REQUESTS,
            "window_seconds": DEFAULT_RATE_WINDOW_SECONDS,
        })),
        egress=egress,
        snmp_credential=_checked_snmp_credential(
            where, item.get("snmp_credential"), kinds,
        ),
    )


def egress_policy(value: Any, where: str = "egress policy") -> dict:
    if not isinstance(value, dict) or set(value) != set(EGRESS_POLICY_FIELDS):
        raise InventoryError(
            "%s: must hold exactly the fields %s, got %r"
            % (where, ", ".join(EGRESS_POLICY_FIELDS), value)
        )
    if value["schema_version"] != POLICY_SCHEMA or isinstance(
        value["schema_version"], bool,
    ):
        raise InventoryError(
            "%s: unknown egress policy schema %r, expected %d"
            % (where, value["schema_version"], POLICY_SCHEMA)
        )
    if value["profile"] not in PROFILES:
        raise InventoryError(
            "%s: profile must be one of %s, got %r"
            % (where, ", ".join(PROFILES), value["profile"])
        )
    for name, expected in (
        ("backend", BACKEND),
        ("bridge_name", BRIDGE_NAME),
        ("network_name", NETWORK_NAME),
        ("ipv6_mode", IPV6_MODE),
    ):
        if value[name] != expected:
            raise InventoryError(
                "%s: %s must be %r, the reviewed Compose contract knows no other value,"
                " got %r" % (where, name, expected, value[name])
            )
    resolvers = _bounded_list(where, "dns_resolvers", value["dns_resolvers"], MAX_DNS_RESOLVERS)
    for item in resolvers:
        if ipv4_literal(item) is None:
            raise InventoryError(
                "%s: dns_resolvers must hold canonical IPv4 literals, got %r" % (where, item)
            )
    if len(set(resolvers)) != len(resolvers):
        raise InventoryError("%s: dns_resolvers must be unique" % where)
    lans = _bounded_list(where, "lan_cidrs", value["lan_cidrs"], MAX_LAN_CIDRS)
    for item in lans:
        if not isinstance(item, str):
            raise InventoryError(
                "%s: lan_cidrs must hold canonical IPv4 networks, got %r" % (where, item)
            )
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as error:
            raise InventoryError(
                "%s: lan_cidrs must hold canonical IPv4 networks, got %r (%s)"
                % (where, item, error)
            ) from None
        if network.version != 4 or str(network) != item:
            raise InventoryError(
                "%s: lan_cidrs must hold canonical IPv4 networks, got %r" % (where, item)
            )
        if not any(network.subnet_of(private) for private in RFC1918_NETWORKS):
            raise InventoryError(
                "%s: lan_cidrs must stay inside RFC1918 space, got %r" % (where, item)
            )
    if len(set(lans)) != len(lans):
        raise InventoryError("%s: lan_cidrs must be unique" % where)
    if value["profile"] == "strict-target" and lans:
        raise InventoryError(
            "%s: the strict-target profile reaches every device on its own addresses and"
            " must declare no LAN scope" % where
        )
    if value["profile"] == "lan-constrained" and not lans:
        raise InventoryError(
            "%s: the lan-constrained profile requires the LAN scopes it constrains" % where
        )
    return {name: value[name] for name in EGRESS_POLICY_FIELDS}


def load(path) -> tuple:
    return core.load(path)


def devices(entries) -> tuple:
    return core.for_consumer(entries, CONSUMER)


def device(entries, name) -> Device:
    return core.device(entries, name)
