from __future__ import annotations

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
)
ALIASES = {
    "fortinet": "fortios",
    "extreme_exos": "exos",
    "extreme_switch_engine": "exos",
}


class PlatformError(Exception):
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
