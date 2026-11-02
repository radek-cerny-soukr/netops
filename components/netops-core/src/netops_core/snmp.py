"""Shared validation for the enrolled SNMPv3 authPriv-only credential."""

from collections.abc import Mapping

AUTH_PROTOCOLS = ("sha256",)
PRIV_PROTOCOLS = ("aes128",)
_USM_KEYS = frozenset({"user", "auth_protocol", "auth_key", "priv_protocol", "priv_key"})
_ERROR = "invalid SNMPv3 authPriv material"


def validate_snmp_usm(mapping: object) -> dict[str, str]:
    """Return a detached, validated USM credential without echoing input."""
    if not isinstance(mapping, Mapping) or set(mapping) != _USM_KEYS:
        raise ValueError(_ERROR)
    if (
        mapping["auth_protocol"] not in AUTH_PROTOCOLS
        or mapping["priv_protocol"] not in PRIV_PROTOCOLS
    ):
        raise ValueError(_ERROR)
    for name, minimum, maximum in (
        ("user", 1, 32), ("auth_key", 8, 4096), ("priv_key", 8, 4096),
    ):
        value = mapping[name]
        if not isinstance(value, str) or not value.isprintable():
            raise ValueError(_ERROR)
        try:
            size = len(value.encode("utf-8"))
        except UnicodeError:
            raise ValueError(_ERROR) from None
        if not minimum <= size <= maximum:
            raise ValueError(_ERROR)
    return dict(mapping)
