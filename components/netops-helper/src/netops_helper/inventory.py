"""Validation of the helper section of the shared device inventory."""

from __future__ import annotations
from contextlib import contextmanager

from dataclasses import dataclass, field
import ipaddress
from pathlib import Path, PurePosixPath
import re
import ssl
from typing import Any

from netops_core import inventory as core

from .config_limits import ConfigurationLimits
from .query_catalog.model import DEVICE_TYPES

from .read_policy import (
    PLATFORM_MAP,
    READ_QUERIES,
    normalize_platform,
    validate_inventory_item,
    validate_query_inventory,
)

CONSUMER = "helper"
TLS_CERT_DIR = Path("/etc/netops-helper/certs")
MAX_TLS_CA_BYTES = 64 * 1024
TLS_CA_FIELD = "inventory.devices[].helper.tls_ca_certificate"
FILE_VERSION = core.FILE_VERSION
SECTION_FIELDS = (
    "account_role",
    "ssh_platform",
    "enabled_queries",
    "device_types",
    "read_inventory",
    "configuration_limits",
    "sftp_roots",
    "fortios_output_standard_verified",
    "rate_limit",
    "egress",
    "snmp_credential",
    "role_boundary",
    "tls_ca_certificate",
    "wifi_thresholds",
    "fortios_rest_port",
    "fortios_rest_credential",
    "fortios_rest_certificate_sha256",
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
ADMIN_BOUNDED_ROLE = "admin-bounded"
CATALOGUE_ROLE_BOUNDARY = "catalogue"
ADMIN_BOUNDED_PLATFORMS = frozenset({"fortios", "fortiadc", "ruckus_unleashed"})
CATALOG_PLATFORMS = {"fortios": "fortinet", "exos": "extreme_exos"}
CREDENTIAL_KINDS = ("password", "ssh-key")
SNMP_CREDENTIAL_KIND = "snmpv3-authpriv"
SNMP_LEGACY_KIND = "snmp-community"
INVENTORY_CATEGORIES = ("vrfs", "virtual_routers", "routing_instances", "interfaces", "services", "addresses", "lookup_prefixes", "switches", "vlans", "managed_switches", "managed_switch_ports", "managed_switch_trunks", "certificates", "firewall_addresses", "nat_pools", "wireless_clients", "wtp_ids", "flow_ports", "ip_protocols", "policy_types", "sdwan_members", "sdwan_rules", "sdwan_health_checks", "link_monitors", "schema_paths", "diagnostic_recipes", "diagnostic_vdoms", "diagnostic_virtual_servers", "diagnostic_names", "diagnostic_http_endpoints", "adc_health_checks", "config_access", "adc_vdoms", "adc_virtual_servers")
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


class EgressPortOverlapError(InventoryError):
    """Raised when an explicit or derived egress port repeats a port of a same-protocol range."""


class DuplicateKeyError(ValueError):
    """Raised when a key is repeated within one JSON object of an operator input."""


def unique_object(pairs) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("a key is repeated within one JSON object")
        result[key] = value
    return result


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
    role_boundary: str | None = None
    configuration_limits: ConfigurationLimits = field(default_factory=ConfigurationLimits)
    tls_ca_certificate: str | None = None
    wifi_thresholds: dict = field(default_factory=dict)
    fortios_rest_port: int = 443
    fortios_rest_credential: str | None = None
    fortios_rest_certificate_sha256: str | None = None
    device_types: tuple = ()

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


def _shape(value: Any) -> str:
    if isinstance(value, dict):
        return "the fields %s" % (", ".join(sorted(str(name) for name in value)) or "none")
    if isinstance(value, list):
        return "a list of %d entries" % len(value)
    return type(value).__name__


def _bounded_list(where: str, name: str, value: Any, maximum: int) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        raise InventoryError(
            "%s: %s must be a list of at most %d entries, got %s"
            % (where, name, maximum, _shape(value))
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
            "%s: egress must hold exactly the fields %s, got %s"
            % (where, ", ".join(EGRESS_FIELDS), _shape(value))
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
            raise EgressPortOverlapError(
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


def _checked_device_types(where: str, value: Any) -> tuple:
    items = _bounded_list(where, "device_types", value, len(DEVICE_TYPES))
    if any(item not in DEVICE_TYPES for item in items) or len(set(items)) != len(items):
        raise InventoryError(
            "%s: device_types must be a unique subset of %s" % (where, ", ".join(DEVICE_TYPES))
        )
    return tuple(items)


def _checked_queries(where: str, platform: str | None, value: Any, device_types: tuple = ()) -> tuple:
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
    blocked = [
        query for query in items
        if available[query].group is not None and available[query].group not in device_types
    ]
    if blocked:
        raise InventoryError(
            "%s: enabled_queries need a device type the target does not declare in device_types: %s"
            % (where, ", ".join(blocked))
        )
    return tuple(items)


def _checked_read_inventory(where: str, value: Any) -> dict:
    if not isinstance(value, dict):
        raise InventoryError(
            "%s: read_inventory must be an object, got %s" % (where, _shape(value))
        )
    unknown = sorted(set(value) - set(INVENTORY_CATEGORIES))
    if unknown:
        raise InventoryError(
            "%s: read_inventory holds unknown categories: %s" % (where, ", ".join(unknown))
        )
    normalized: dict = {}
    for category in sorted(value):
        items = _bounded_list(
            where, "read_inventory " + category, value[category], 4096 if category == "schema_paths" else MAX_INVENTORY_ITEMS,
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
        if len(set(clean)) != len(clean):
            raise InventoryError(
                "%s: read_inventory %s must be unique" % (where, category)
            )
        normalized[category] = tuple(clean)
    rights = normalized.get("config_access", ())
    if "compare" in rights and "read" not in rights:
        raise InventoryError("config_access compare requires read")
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
            "%s: rate_limit must hold exactly requests and window_seconds, got %s"
            % (where, _shape(value))
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
    with _field("credential"):
        _checked_credential_record(where, entry, kinds)
    with _field("host_key_fingerprint"):
        if entry.host_key_fingerprint is None:
            raise InventoryError(
                "%s: host_key_fingerprint must pin the host key of the device, there is no"
                " first contact trust" % where
            )


def _checked_credential_record(where: str, entry: Device, kinds: dict | None) -> None:
    if entry.credential is None:
        raise InventoryError(
            "%s: credential must name a record in the credential store, a device is"
            " reached with an account" % where
        )
    if kinds is None:
        return
    kind = kinds.get(entry.credential)
    if kind is None:
        raise InventoryError(
            "%s: credential names no record of the credential store; the value is not"
            " repeated, a value that names no record may be a misplaced secret" % where
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
        given = "a blank string" if isinstance(value, str) else type(value).__name__
        raise InventoryError(
            "%s: snmp_credential must be null or name a record in the credential store,"
            " got %s" % (where, given)
        )
    if kinds is not None:
        kind = kinds.get(value)
        if kind is None:
            raise InventoryError(
                "%s: snmp_credential names no record of the credential store; the value is not"
                " repeated, a value that names no record may be a misplaced secret" % where
            )
        if kind not in (SNMP_CREDENTIAL_KIND, SNMP_LEGACY_KIND):
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


def _checked_derived_port(
    where: str, entry: Device, platform: str | None, queries: tuple, roots: tuple, egress: dict,
) -> None:
    if not ((platform is not None and queries) or roots):
        return
    for start, end in egress["tcp_port_ranges"]:
        if start <= entry.port <= end:
            raise EgressPortOverlapError(
                "%s: port %d of the device lies inside egress tcp_port_ranges [%d, %d]; the"
                " egress rules add the port of a device with SSH queries or SFTP roots as an"
                " explicit TCP port, and an explicit port must not repeat a port of a range,"
                " so move the range off port %d" % (where, entry.port, start, end, entry.port)
            )


def _checked_role_boundary(
    where: str, role: str, platform: str | None, item: dict,
) -> str | None:
    if role == ACCOUNT_ROLE:
        if "role_boundary" in item:
            raise RoleError(
                "%s: role_boundary belongs only to account_role %r" % (where, ADMIN_BOUNDED_ROLE)
            )
        return None
    if item.get("role_boundary") != CATALOGUE_ROLE_BOUNDARY:
        raise RoleError(
            "%s: account_role %r requires role_boundary %r, got %r"
            % (where, ADMIN_BOUNDED_ROLE, CATALOGUE_ROLE_BOUNDARY, item.get("role_boundary"))
        )
    if platform not in ADMIN_BOUNDED_PLATFORMS:
        raise RoleError(
            "%s: account_role %r is accepted only for a supported ssh_platform"
            " account (%s); use %r, got ssh_platform %r"
            % (where, ADMIN_BOUNDED_ROLE, ", ".join(sorted(ADMIN_BOUNDED_PLATFORMS)),
               ACCOUNT_ROLE, platform)
        )
    return CATALOGUE_ROLE_BOUNDARY


def _tls_ca_error(message: str, code: str) -> InventoryError:
    return InventoryError(message, field=TLS_CA_FIELD, code=code)


def _checked_tls_ca(where: str, value: Any) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value.startswith("//")
        or value != str(PurePosixPath(value))
        or len(value) > MAX_ROOT_LENGTH
        or ".." in PurePosixPath(value).parts
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise _tls_ca_error(
            "%s: tls_ca_certificate must be a canonical absolute path to a PEM file"
            " below %s, got %s" % (where, TLS_CERT_DIR, _shape(value)), "tls-ca-path"
        )
    if TLS_CERT_DIR not in PurePosixPath(value).parents:
        raise _tls_ca_error(
            "%s: tls_ca_certificate must be below %s" % (where, TLS_CERT_DIR), "tls-ca-path"
        )
    root = TLS_CERT_DIR.resolve()
    path = Path(value).resolve()
    if root not in path.parents:
        raise _tls_ca_error(
            "%s: tls_ca_certificate symlink leaves %s" % (where, TLS_CERT_DIR), "tls-ca-symlink"
        )
    if not path.is_file():
        raise _tls_ca_error(
            "%s: tls_ca_certificate must name an existing regular file below %s"
            % (where, TLS_CERT_DIR), "tls-ca-missing"
        )
    try:
        with path.open("rb") as handle:
            content = handle.read(MAX_TLS_CA_BYTES + 1)
    except OSError:
        raise _tls_ca_error("%s: tls_ca_certificate is not readable" % where, "tls-ca-read") from None
    if len(content) > MAX_TLS_CA_BYTES:
        raise _tls_ca_error("%s: tls_ca_certificate is larger than 64 KiB" % where, "tls-ca-read")
    if b"PRIVATE KEY" in content:
        raise _tls_ca_error(
            "%s: tls_ca_certificate must not hold a private key" % where, "tls-ca-private-key"
        )
    blocks = content.count(b"-----BEGIN CERTIFICATE-----")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cadata=content.decode("ascii"))
    except (UnicodeDecodeError, ssl.SSLError, ValueError):
        blocks = 0
    if blocks == 0 or len(context.get_ca_certs()) != blocks:
        raise _tls_ca_error(
            "%s: tls_ca_certificate must hold only PEM certificates of certificate"
            " authorities (basicConstraints CA=true)" % where, "tls-ca-not-ca"
        )
    return value


@contextmanager
def _field(name: str, problem: str = "is invalid"):
    # Names the refused field for the operator message, which repeats the field name and never its value.
    try:
        yield
    except InventoryError as error:
        if getattr(error, "helper_field", None) is None:
            error.helper_field = (name, problem)
        raise


def section(entry: Device, kinds: dict | None = None) -> HelperSection:
    where = "device %s: helper section" % entry.name
    item = entry.helper
    with _field("helper", "must be an object"):
        if not isinstance(item, dict):
            raise InventoryError("%s: must be an object, got %s" % (where, _shape(item)))
    missing = [name for name in REQUIRED_SECTION_FIELDS if name not in item]
    with _field(", ".join("helper." + name for name in missing), "is missing" if len(missing) == 1 else "are missing"):
        if missing:
            raise InventoryError("%s: missing fields: %s" % (where, ", ".join(missing)))
    unknown = sorted(set(item) - set(SECTION_FIELDS))
    with _field("helper", "contains unknown fields; only documented fields are accepted"):
        if unknown:
            raise InventoryError("%s: unknown fields: %s" % (where, ", ".join(unknown)))
    role = item["account_role"]
    with _field("helper.account_role"):
        if role != ACCOUNT_ROLE and role != ADMIN_BOUNDED_ROLE:
            raise RoleError(
                "%s: account_role must be %r, an account the operator has not declared"
                " read-only is refused, got %r" % (where, ACCOUNT_ROLE, role)
            )
    with _field("helper.ssh_platform"):
        platform = _checked_platform(where, item["ssh_platform"])
    with _field("helper.role_boundary"):
        boundary = _checked_role_boundary(where, role, platform, item)
    with _field("helper.device_types"):
        device_types = _checked_device_types(where, item.get("device_types", []))
    with _field("helper.enabled_queries"):
        queries = _checked_queries(where, platform, item["enabled_queries"], device_types)
    with _field("helper.read_inventory"):
        read_inventory = _checked_read_inventory(where, item.get("read_inventory", {}))
        try:
            validate_query_inventory(catalog_platform(platform), queries, read_inventory)
        except (KeyError, TypeError, ValueError) as error:
            raise InventoryError(
                "%s: read_inventory does not hold usable values for the enabled queries (%s)"
                % (where, error)
            ) from None
    with _field("helper.configuration_limits"):
        try:
            configuration_limits = ConfigurationLimits.from_mapping(item.get('configuration_limits', {}))
        except (TypeError, ValueError) as error:
            raise InventoryError('%s: %s' % (where, str(error))) from None
    verified = item.get("fortios_output_standard_verified", False)
    with _field("helper.fortios_output_standard_verified"):
        if not isinstance(verified, bool):
            raise InventoryError(
                "%s: fortios_output_standard_verified must be true or false, got %r"
                % (where, verified)
            )
    with _field("helper.egress"):
        egress = _checked_egress(where, item["egress"])
    _checked_credential(where, entry, kinds)
    with _field("address"):
        _checked_reach(where, entry, egress)
    with _field("helper.sftp_roots"):
        roots = _checked_roots(where, item.get("sftp_roots", []))
    with _field("helper.egress.tcp_port_ranges"):
        _checked_derived_port(where, entry, platform, queries, roots, egress)
    from .wifi_policy import thresholds
    with _field("helper.wifi_thresholds"):
        try:
            wifi_thresholds = thresholds(item.get("wifi_thresholds"))
        except ValueError as error:
            raise InventoryError(str(error)) from None
    with _field("helper.fortios_rest_port"):
        rest_port = checked_rest_port(item.get("fortios_rest_port", 443))
    rest_credential = item.get("fortios_rest_credential")
    rest_pin = item.get("fortios_rest_certificate_sha256")
    with _field("helper.fortios_rest_certificate_sha256"):
        if rest_pin is not None and (not isinstance(rest_pin, str) or re.fullmatch(r"[0-9a-f]{64}", rest_pin) is None):
            raise InventoryError("fortios_rest_certificate_sha256 must be a lowercase SHA-256 hex digest")
    with _field("helper.fortios_rest_credential"):
        _checked_rest(rest_credential, rest_pin, platform, item, kinds)
    with _field("helper.fortios_rest_port"):
        if rest_credential is not None and not (rest_port in egress["tcp_ports"] or any(
                a <= rest_port <= b for a, b in egress["tcp_port_ranges"])):
            raise InventoryError("FortiOS REST requires fortios_rest_port in TCP egress")
    with _field("helper.rate_limit"):
        rate_limit = _checked_rate_limit(where, item.get("rate_limit", {
            "requests": DEFAULT_RATE_REQUESTS,
            "window_seconds": DEFAULT_RATE_WINDOW_SECONDS,
        }))
    with _field("helper.snmp_credential"):
        snmp_credential = _checked_snmp_credential(where, item.get("snmp_credential"), kinds)
    return HelperSection(
        account_role=role,
        role_boundary=boundary,
        ssh_platform=platform,
        enabled_queries=queries,
        device_types=device_types,
        read_inventory=read_inventory,
        configuration_limits=configuration_limits,
        sftp_roots=roots,
        fortios_output_standard_verified=verified,
        rate_limit=rate_limit,
        egress=egress,
        snmp_credential=snmp_credential,
        tls_ca_certificate=_checked_tls_ca(where, item.get("tls_ca_certificate")),
        wifi_thresholds=wifi_thresholds,
        fortios_rest_port=rest_port,
        fortios_rest_credential=rest_credential,
        fortios_rest_certificate_sha256=rest_pin,
    )


def checked_rest_port(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise InventoryError("fortios_rest_port must be a whole number from 1 to 65535")
    return value


def _checked_rest(rest_credential: Any, rest_pin: Any, platform: str | None, item: dict, kinds: dict | None) -> None:
    if rest_credential is not None:
        if not isinstance(rest_credential, str) or not rest_credential.strip():
            raise InventoryError("fortios_rest_credential must name an api-token credential")
        if kinds is not None and kinds.get(rest_credential) != "api-token":
            raise InventoryError("fortios_rest_credential must name an existing api-token credential; value withheld")
        if platform != "fortios":
            raise InventoryError("FortiOS REST requires the fortios platform")
        if rest_pin is None and item.get("tls_ca_certificate") is None:
            raise InventoryError("FortiOS REST requires a certificate SHA-256 pin or tls_ca_certificate")


FORTIOS_READ_ONLY_REFUSED_QUERIES = tuple(
    name for name, entry in READ_QUERIES["fortinet"].items() if entry.read_only_account == "refused"
)


_REST_ALTERNATIVE = {
    "wifi_clients": ("stations", "wifi_clients"), "wifi_client_detail": ("stations", "wifi_clients"),
    "wifi_access_points": ("access points", "wifi_aps_live"), "wifi_ap_detail": ("access points", "wifi_aps_live"),
    "wifi_ssid_mapping": ("access points and SSIDs", "wifi_aps_live"),
}


def section_warnings(name: str, section: Any) -> list:
    if section.account_role != ACCOUNT_ROLE or section.ssh_platform != "fortios":
        return []
    return [
        "device %s: query %s is enabled for a read-only FortiOS account, which the device refuses"
        " with 'Return code -61'; enroll an admin-bounded account (access profile 'wifi read-write'"
        " and 'cli-diagnose enable') or remove the SSH query. For live %s, use the REST tool"
        " %s with helper.fortios_rest_credential; see docs/fortios-wifi-rest.md"
        % ((name, query) + _REST_ALTERNATIVE.get(query, ("stations", "wifi_clients")))
        for query in section.enabled_queries
        if query in FORTIOS_READ_ONLY_REFUSED_QUERIES
    ]


def egress_policy(value: Any, where: str = "egress policy") -> dict:
    if not isinstance(value, dict) or set(value) != set(EGRESS_POLICY_FIELDS):
        raise InventoryError(
            "%s: must hold exactly the fields %s, got %s"
            % (where, ", ".join(EGRESS_POLICY_FIELDS), _shape(value))
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
