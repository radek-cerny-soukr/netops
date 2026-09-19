from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path

from . import hostkey, legacy_ssh, platforms

FILE_VERSION = 2
DOCUMENT_FIELDS = ("version", "devices")
DEVICE_FIELDS = (
    "name",
    "platform",
    "address",
    "port",
    "role",
    "credential",
    "host_key_fingerprint",
    "legacy_ssh",
    "auditor",
    "helper",
)
ROLES = ("perimetr", "interni", "lab")
CONSUMERS = ("auditor", "helper")
PORT_MIN = 1
PORT_MAX = 65535
DNS_NAME_MAX_LENGTH = 253
DNS_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z")
SECRET_MARKERS = (
    "password",
    "passwd",
    "passphrase",
    "token",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "psk",
)


class InventoryError(Exception):
    pass


@dataclass(frozen=True)
class Device:
    name: str
    platform: str
    address: str | None
    port: int | None
    role: str
    credential: str | None
    host_key_fingerprint: str | None
    legacy_ssh: str | None
    auditor: dict | None
    helper: dict | None

    def consumers(self) -> tuple:
        return tuple(name for name in CONSUMERS if getattr(self, name) is not None)


def _normalized(name) -> str:
    return str(name).lower().replace("-", "_").replace(" ", "_")


def _secret_free(where: str, names) -> None:
    found = sorted(
        name for name in names if any(marker in _normalized(name) for marker in SECRET_MARKERS)
    )
    if found:
        raise InventoryError(
            "%s: secrets do not belong in the inventory, remove fields: %s;"
            " credential may only name a record in the credential store"
            % (where, ", ".join(str(name) for name in found))
        )


def _checked_text(where: str, name: str, value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InventoryError("%s: %s must be a non-empty string, got %r" % (where, name, value))
    return value


def _checked_choice(where: str, name: str, value, allowed) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise InventoryError(
            "%s: %s must be one of %s, got %r" % (where, name, ", ".join(allowed), value)
        )
    return value


def _checked_platform(where: str, value) -> str:
    try:
        return platforms.normalize(value)
    except platforms.PlatformError as error:
        raise InventoryError("%s: %s" % (where, error)) from None


def _address_refused(where: str, value) -> InventoryError:
    return InventoryError(
        "%s: address must be null, a canonical IPv4 literal or a lowercase DNS name"
        " (labels of letters, digits and hyphens, no trailing dot, at most %d characters),"
        " got %r" % (where, DNS_NAME_MAX_LENGTH, value)
    )


def _checked_address(where: str, value):
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise _address_refused(where, value)
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        parsed = None
    if parsed is not None:
        if parsed.version != 4:
            raise InventoryError(
                "%s: IPv6 targets are not supported, address must be null, a canonical IPv4"
                " literal or a lowercase DNS name, got %r" % (where, value)
            )
        if str(parsed) != value:
            raise InventoryError(
                "%s: address must hold the canonical form of the IPv4 literal, got %r,"
                " expected %r" % (where, value, str(parsed))
            )
        return value
    if len(value) > DNS_NAME_MAX_LENGTH or value != value.lower() or value.endswith("."):
        raise _address_refused(where, value)
    labels = value.split(".")
    if labels[-1].isdigit() or any(DNS_LABEL.match(label) is None for label in labels):
        raise _address_refused(where, value)
    return value


def _checked_port(where: str, value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InventoryError(
            "%s: port must be null or an integer between %d and %d, got %r"
            % (where, PORT_MIN, PORT_MAX, value)
        )
    if not PORT_MIN <= value <= PORT_MAX:
        raise InventoryError(
            "%s: port must be null or an integer between %d and %d, got %r"
            % (where, PORT_MIN, PORT_MAX, value)
        )
    return value


def _checked_reach(where: str, address, port) -> None:
    if (address is None) != (port is None):
        raise InventoryError(
            "%s: address and port must be both null or both set, a device is reached by both or"
            " by neither, got address %r and port %r" % (where, address, port)
        )


def _checked_credential(where: str, value):
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise InventoryError(
            "%s: credential must be null or name a record in the credential store, got %r"
            % (where, value)
        )
    return value


def _checked_host_key(where: str, value, address):
    if value is None:
        return None
    try:
        pin = hostkey.checked_pin(value)
    except hostkey.HostKeyError as error:
        raise InventoryError("%s: %s" % (where, error)) from None
    if address is None:
        raise InventoryError(
            "%s: host_key_fingerprint pins the key of the host behind address, it must be null"
            " for a device without an address, got %r" % (where, value)
        )
    return pin


def _checked_legacy_ssh(where: str, value, host_key_fingerprint):
    try:
        profile = legacy_ssh.checked(value)
    except legacy_ssh.LegacySshError as error:
        raise InventoryError("%s: %s" % (where, error)) from None
    if profile is not None and host_key_fingerprint is None:
        raise InventoryError(
            "%s: legacy_ssh %r requires host_key_fingerprint, weakening the algorithms of a"
            " session whose host key is not pinned makes no sense" % (where, profile)
        )
    return profile


def _checked_section(where: str, name: str, value):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InventoryError(
            "%s: %s must be null or an object, its content belongs to that component, got %r"
            % (where, name, value)
        )
    return value


def _checked_sections(where: str, sections) -> None:
    if all(section is None for section in sections):
        raise InventoryError(
            "%s: at least one of %s must be an object, a device no component consumes is refused"
            % (where, ", ".join(CONSUMERS))
        )


def _device(index: int, item) -> Device:
    where = "device %d" % index
    if not isinstance(item, dict):
        raise InventoryError("%s: must be an object, got %r" % (where, item))
    _secret_free(where, item)
    missing = [name for name in DEVICE_FIELDS if name not in item]
    if missing:
        raise InventoryError("%s: missing fields: %s" % (where, ", ".join(missing)))
    unknown = sorted(set(item) - set(DEVICE_FIELDS))
    if unknown:
        raise InventoryError("%s: unknown fields: %s" % (where, ", ".join(unknown)))
    address = _checked_address(where, item["address"])
    port = _checked_port(where, item["port"])
    _checked_reach(where, address, port)
    host_key_fingerprint = _checked_host_key(where, item["host_key_fingerprint"], address)
    sections = tuple(_checked_section(where, name, item[name]) for name in CONSUMERS)
    _checked_sections(where, sections)
    return Device(
        name=_checked_text(where, "name", item["name"]),
        platform=_checked_platform(where, item["platform"]),
        address=address,
        port=port,
        role=_checked_choice(where, "role", item["role"], ROLES),
        credential=_checked_credential(where, item["credential"]),
        host_key_fingerprint=host_key_fingerprint,
        legacy_ssh=_checked_legacy_ssh(where, item["legacy_ssh"], host_key_fingerprint),
        auditor=sections[0],
        helper=sections[1],
    )


def _document(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise InventoryError("cannot read inventory file %s: %s" % (path, error)) from None
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise InventoryError("inventory file %s is not valid JSON: %s" % (path, error)) from None
    if not isinstance(document, dict):
        raise InventoryError("inventory file %s must hold an object, got %r" % (path, document))
    _secret_free("inventory file %s" % path, document)
    missing = [name for name in DOCUMENT_FIELDS if name not in document]
    if missing:
        raise InventoryError(
            "inventory file %s: missing document fields: %s" % (path, ", ".join(missing))
        )
    unknown = sorted(set(document) - set(DOCUMENT_FIELDS))
    if unknown:
        raise InventoryError(
            "inventory file %s: unknown document fields: %s" % (path, ", ".join(unknown))
        )
    version = document["version"]
    if isinstance(version, bool) or version != FILE_VERSION:
        raise InventoryError(
            "inventory file %s: unknown inventory file version %r, expected %d"
            % (path, version, FILE_VERSION)
        )
    if not isinstance(document["devices"], list):
        raise InventoryError(
            "inventory file %s: devices must be a list, got %r" % (path, document["devices"])
        )
    return document


def load(path) -> tuple:
    location = Path(path)
    document = _document(location)
    devices, seen = [], {}
    for index, item in enumerate(document["devices"]):
        entry = _device(index, item)
        if entry.name in seen:
            raise InventoryError(
                "device %d: duplicate name %r, already used by device %d"
                % (index, entry.name, seen[entry.name])
            )
        seen[entry.name] = index
        devices.append(entry)
    return tuple(devices)


def device(devices, name) -> Device:
    for entry in devices:
        if entry.name == name:
            return entry
    known = ", ".join(sorted(entry.name for entry in devices))
    raise InventoryError(
        "unknown device %r, inventory holds: %s" % (name, known if known else "no devices")
    )


def for_consumer(devices, consumer) -> tuple:
    if not isinstance(consumer, str) or consumer not in CONSUMERS:
        raise InventoryError(
            "consumer must be one of %s, got %r" % (", ".join(CONSUMERS), consumer)
        )
    return tuple(entry for entry in devices if getattr(entry, consumer) is not None)
