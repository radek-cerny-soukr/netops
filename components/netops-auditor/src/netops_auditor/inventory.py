from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

FILE_VERSION = 1
DOCUMENT_FIELDS = ("version", "devices")
DEVICE_FIELDS = (
    "name",
    "platform",
    "channel",
    "source",
    "role",
    "consumer",
    "credential",
    "required_sections",
    "tls_fingerprint",
    "host_key_fingerprint",
    "legacy_ssh",
)
PLATFORMS = ("fortios", "exos")
CHANNEL_FILE = "file"
CHANNEL_REST = "fortios-rest"
CHANNEL_SSH = "ssh"
CHANNELS = (CHANNEL_FILE, CHANNEL_REST, CHANNEL_SSH)
CREDENTIAL_CHANNELS = (CHANNEL_REST, CHANNEL_SSH)
ROLES = ("perimetr", "interni", "lab")
CONSUMERS = ("auditor", "helper")
TLS_FINGERPRINT_LENGTH = 64
TLS_FINGERPRINT_CHARS = frozenset("0123456789abcdef")
HOST_KEY_PREFIX = "SHA256:"
HOST_KEY_DIGEST_LENGTH = 43
HOST_KEY_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
LEGACY_SSH_PROFILES = ("rsa-sha1",)
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
    channel: str
    source: str
    role: str
    consumer: str
    credential: str | None
    required_sections: tuple
    tls_fingerprint: str | None
    host_key_fingerprint: str | None
    legacy_ssh: str | None


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


def _checked_sections(where: str, value) -> tuple:
    if not isinstance(value, list) or not value:
        raise InventoryError(
            "%s: required_sections must be a non-empty list, got %r" % (where, value)
        )
    for index, section in enumerate(value):
        if not isinstance(section, str) or not section.strip():
            raise InventoryError(
                "%s: required_sections[%d] must be a non-empty string, got %r"
                % (where, index, section)
            )
    return tuple(value)


def _checked_credential(where: str, channel: str, value):
    if channel == CHANNEL_FILE:
        if value is not None:
            raise InventoryError(
                "%s: credential must be null for channel %s, got %r" % (where, CHANNEL_FILE, value)
            )
        return None
    if not isinstance(value, str) or not value.strip():
        raise InventoryError(
            "%s: credential must name a record in the credential store for channel %s, got %r"
            % (where, channel, value)
        )
    return value


def _checked_tls_fingerprint(where: str, channel: str, value):
    if channel != CHANNEL_REST:
        if value is not None:
            raise InventoryError(
                "%s: tls_fingerprint must be null for channel %s, got %r" % (where, channel, value)
            )
        return None
    if (
        not isinstance(value, str)
        or len(value) != TLS_FINGERPRINT_LENGTH
        or not set(value.lower()) <= TLS_FINGERPRINT_CHARS
    ):
        raise InventoryError(
            "%s: tls_fingerprint must hold the sha256 certificate fingerprint of the device"
            " for channel %s, %d hexadecimal characters, no first contact trust, got %r"
            % (where, CHANNEL_REST, TLS_FINGERPRINT_LENGTH, value)
        )
    return value.lower()


def _checked_host_key(where: str, channel: str, value):
    if channel != CHANNEL_SSH:
        if value is not None:
            raise InventoryError(
                "%s: host_key_fingerprint must be null for channel %s, got %r"
                % (where, channel, value)
            )
        return None
    if (
        not isinstance(value, str)
        or not value.startswith(HOST_KEY_PREFIX)
        or len(value) != len(HOST_KEY_PREFIX) + HOST_KEY_DIGEST_LENGTH
        or not set(value[len(HOST_KEY_PREFIX):]) <= HOST_KEY_CHARS
    ):
        raise InventoryError(
            "%s: host_key_fingerprint must hold the sha256 host key fingerprint of the device"
            " for channel %s as ssh-keygen -lf prints it (%s and %d base64 characters),"
            " no first contact trust, got %r"
            % (where, CHANNEL_SSH, HOST_KEY_PREFIX, HOST_KEY_DIGEST_LENGTH, value)
        )
    return value


def _checked_legacy_ssh(where: str, channel: str, value):
    if channel != CHANNEL_SSH:
        if value is not None:
            raise InventoryError(
                "%s: legacy_ssh must be null for channel %s, got %r" % (where, channel, value)
            )
        return None
    if value is None:
        return None
    if not isinstance(value, str) or value not in LEGACY_SSH_PROFILES:
        raise InventoryError(
            "%s: legacy_ssh must be null for a device that speaks current algorithms or name one"
            " of the profiles %s for channel %s, a profile weakens the session for that device"
            " alone, got %r"
            % (where, ", ".join(LEGACY_SSH_PROFILES), CHANNEL_SSH, value)
        )
    return value


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
    channel = _checked_choice(where, "channel", item["channel"], CHANNELS)
    return Device(
        name=_checked_text(where, "name", item["name"]),
        platform=_checked_choice(where, "platform", item["platform"], PLATFORMS),
        channel=channel,
        source=_checked_text(where, "source", item["source"]),
        role=_checked_choice(where, "role", item["role"], ROLES),
        consumer=_checked_choice(where, "consumer", item["consumer"], CONSUMERS),
        credential=_checked_credential(where, channel, item["credential"]),
        required_sections=_checked_sections(where, item["required_sections"]),
        tls_fingerprint=_checked_tls_fingerprint(where, channel, item["tls_fingerprint"]),
        host_key_fingerprint=_checked_host_key(where, channel, item["host_key_fingerprint"]),
        legacy_ssh=_checked_legacy_ssh(where, channel, item["legacy_ssh"]),
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
    return tuple(entry for entry in devices if entry.consumer == consumer)
