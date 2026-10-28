from __future__ import annotations

import re

PLATFORMS = (
    "fortios",
    "exos",
    "linux",
    "cisco_ios",
    "cisco_xe",
    "cisco_nxos",
    "arista_eos",
    "juniper_junos",
    "juniper_junos_els",
    "ruckus_unleashed",
    "fortiadc",
)
ALIASES = {
    "fortinet": "fortios",
    "extreme_exos": "exos",
    "extreme_switch_engine": "exos",
}


VERSION_RECORD = re.compile(r"Version:\s+([A-Za-z0-9_.+-]+)\s+v(\d+\.\d+\.\d+),\s*build(\d{4,6})(?:,|\s|$)")
PRODUCT_HARDWARE = {
    "fortiadc": ("FortiADC-",),
    "fortios": ("FortiGate-", "FortiWiFi-"),
}


class PlatformError(Exception):
    pass


class VersionRecordError(Exception):
    pass


def normalize(value) -> str:
    if isinstance(value, str):
        name = value.strip().lower()
        if name in PLATFORMS:
            return name
        if name in ALIASES:
            return ALIASES[name]
    raise PlatformError(
        "platform must be one of %s or an alias of one (%s), got %r"
        % (
            ", ".join(PLATFORMS),
            ", ".join("%s -> %s" % (alias, ALIASES[alias]) for alias in sorted(ALIASES)),
            value,
        )
    )


def version_record(status_output):
    if isinstance(status_output, str):
        candidates = [line for line in status_output.split("\n") if line.startswith("Version:")]
        if len(candidates) == 1:
            found = VERSION_RECORD.match(candidates[0])
            if found:
                return found.groups()
    raise VersionRecordError("the status output does not contain exactly one well-formed Version record")


def require_identity(platform, status_output) -> str:
    selected = normalize(platform)
    if selected not in PRODUCT_HARDWARE:
        raise PlatformError(
            "product identity can be checked only for %s, got %r" % (", ".join(PRODUCT_HARDWARE), selected)
        )
    try:
        hardware = version_record(status_output)[0]
    except VersionRecordError:
        raise PlatformError("the device did not return one exact Version record") from None
    if not hardware.startswith(PRODUCT_HARDWARE[selected]):
        raise PlatformError("the live device is not a %s product" % selected)
    return selected
