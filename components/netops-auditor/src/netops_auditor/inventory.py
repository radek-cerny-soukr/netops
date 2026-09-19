from __future__ import annotations

from dataclasses import dataclass

from netops_core import inventory as core

CONSUMER = "auditor"
FILE_VERSION = core.FILE_VERSION
SECTION_FIELDS = ("channel", "source", "required_sections", "tls_fingerprint")
CHANNEL_FILE = "file"
CHANNEL_REST = "fortios-rest"
CHANNEL_SSH = "ssh"
CHANNELS = (CHANNEL_FILE, CHANNEL_REST, CHANNEL_SSH)
SOURCE_CHANNELS = (CHANNEL_FILE, CHANNEL_REST)
REST_SCHEME = "https://"
TLS_FINGERPRINT_LENGTH = 64
TLS_FINGERPRINT_CHARS = frozenset("0123456789abcdef")

InventoryError = core.InventoryError
Device = core.Device


@dataclass(frozen=True)
class AuditorSection:
    channel: str
    source: str | None
    required_sections: tuple
    tls_fingerprint: str | None


def _checked_choice(where: str, name: str, value, allowed) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise InventoryError(
            "%s: %s must be one of %s, got %r" % (where, name, ", ".join(allowed), value)
        )
    return value


def _checked_source(where: str, channel: str, value):
    if channel == CHANNEL_SSH:
        if value is not None:
            raise InventoryError(
                "%s: source must be null for channel %s, the session is opened against the"
                " address and port of the device, got %r" % (where, CHANNEL_SSH, value)
            )
        return None
    if not isinstance(value, str) or not value.strip():
        raise InventoryError(
            "%s: source must be a non-empty string for channel %s, got %r"
            % (where, channel, value)
        )
    if channel == CHANNEL_REST and not value.startswith(REST_SCHEME):
        raise InventoryError(
            "%s: source must name the device as %shost[:port] for channel %s, got %r"
            % (where, REST_SCHEME, CHANNEL_REST, value)
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


def _checked_common(where: str, channel: str, entry) -> None:
    if channel == CHANNEL_FILE:
        if entry.credential is not None:
            raise InventoryError(
                "%s: credential must be null for channel %s, a dump on disk is opened without"
                " logging in anywhere, got %r" % (where, CHANNEL_FILE, entry.credential)
            )
        return
    if entry.credential is None:
        raise InventoryError(
            "%s: credential must name a record in the credential store for channel %s"
            % (where, channel)
        )
    if channel == CHANNEL_REST:
        if entry.host_key_fingerprint is not None:
            raise InventoryError(
                "%s: host_key_fingerprint must be null for channel %s, that channel pins the"
                " certificate in tls_fingerprint, got %r"
                % (where, CHANNEL_REST, entry.host_key_fingerprint)
            )
        return
    if entry.address is None:
        raise InventoryError(
            "%s: address must name the device for channel %s" % (where, CHANNEL_SSH)
        )
    if entry.host_key_fingerprint is None:
        raise InventoryError(
            "%s: host_key_fingerprint must pin the host key for channel %s, there is no first"
            " contact trust" % (where, CHANNEL_SSH)
        )


def section(entry) -> AuditorSection:
    where = "device %s: auditor section" % entry.name
    item = entry.auditor
    if not isinstance(item, dict):
        raise InventoryError(
            "%s: must be an object, got %r" % (where, item)
        )
    missing = [name for name in SECTION_FIELDS if name not in item]
    if missing:
        raise InventoryError("%s: missing fields: %s" % (where, ", ".join(missing)))
    unknown = sorted(set(item) - set(SECTION_FIELDS))
    if unknown:
        raise InventoryError("%s: unknown fields: %s" % (where, ", ".join(unknown)))
    channel = _checked_choice(where, "channel", item["channel"], CHANNELS)
    _checked_common(where, channel, entry)
    return AuditorSection(
        channel=channel,
        source=_checked_source(where, channel, item["source"]),
        required_sections=_checked_sections(where, item["required_sections"]),
        tls_fingerprint=_checked_tls_fingerprint(where, channel, item["tls_fingerprint"]),
    )


def load(path) -> tuple:
    devices = core.load(path)
    for entry in core.for_consumer(devices, CONSUMER):
        section(entry)
    return devices


def device(devices, name) -> Device:
    return core.device(devices, name)
