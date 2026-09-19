from __future__ import annotations

PROFILES = ("rsa-sha1",)
OPENSSH_OPTIONS = {
    "rsa-sha1": ("HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa"),
}


class LegacySshError(Exception):
    pass


def checked(value):
    if value is None:
        return None
    if isinstance(value, str) and value in PROFILES:
        return value
    raise LegacySshError(
        "legacy_ssh must be null for a device that speaks current algorithms or name one of the"
        " profiles %s, the options of a profile are written down in this module and never taken"
        " from the inventory, a profile is an exception per device, for that one device only, and there is no global"
        " switch, got %r" % (", ".join(PROFILES), value)
    )


def openssh_options(profile) -> tuple:
    name = checked(profile)
    if name is None:
        return ()
    return OPENSSH_OPTIONS[name]
