"""Immutable model and typed inventory slots shared by query catalogues."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


# Device types are a per-target inventory attribute. A template with a group is
# usable only on targets declaring that type; no group means any device type.
DEVICE_TYPES = ("switch", "router", "firewall")


@dataclass(frozen=True, slots=True)
class Slot:
    inventory: str | None
    kind: str
    lookup_only: bool = False


LITERAL = "literal"


@dataclass(frozen=True, slots=True)
class Query:
    command: str
    slots: Mapping[str, Slot]
    description: str
    high_volume: bool = False
    pty: bool = False
    empty_allowed: bool = False
    # The engine compares requires_device_permission with the literal "wifi read-write"
    # to classify the refusal; a new requirement needs a matching engine rule.
    requires_device_permission: str | None = None
    read_only_account: str | None = None
    # Slots that may be left out; an omitted trailing command field is dropped with its space.
    optional_slots: frozenset[str] = frozenset()
    group: str | None = None
    # Filter parameters are applied by the Helper to the redacted output.
    filter_slots: frozenset[str] = field(default_factory=frozenset, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "slots", MappingProxyType(dict(self.slots)))
        object.__setattr__(self, "optional_slots", frozenset(self.optional_slots))
        object.__setattr__(self, "filter_slots", frozenset(self.filter_slots))


@dataclass(frozen=True, slots=True)
class SequenceQuery(Query):
    """Fixed command sequence; `command` is only its display form."""

    commands: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        Query.__post_init__(self)
        object.__setattr__(self, "commands", tuple(self.commands))


NO_SLOTS: Mapping[str, Slot] = MappingProxyType({})
INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "interface"),
})
FORTIOS_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "fortios_interface"),
})
FORTIOS_PHYSICAL_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "fortios_physical_interface"),
})
FORTIADC_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "fortiadc_interface"),
})
CISCO_IOS_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_ios_interface"),
})
CISCO_IOS_PHYSICAL_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_ios_physical_interface"),
})
CISCO_IOS_SWITCHPORT: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_ios_switchport"),
})
CISCO_XE_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_xe_interface"),
})
CISCO_XE_PHYSICAL_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_xe_physical_interface"),
})
CISCO_XE_SWITCHPORT: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_xe_switchport"),
})
CISCO_NXOS_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_nxos_interface"),
})
CISCO_NXOS_ERRORS_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_nxos_errors_interface"),
})
CISCO_NXOS_NON_SUBINTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_nxos_non_subinterface"),
})
SERVICE: Mapping[str, Slot] = MappingProxyType({
    "service": Slot("services", "service"),
})
ADDRESS: Mapping[str, Slot] = MappingProxyType({
    "address": Slot("addresses", "address"),
})
IPV4_ADDRESS: Mapping[str, Slot] = MappingProxyType({
    "address": Slot("addresses", "ipv4_address"),
})
IPV6_ADDRESS: Mapping[str, Slot] = MappingProxyType({
    "address": Slot("addresses", "ipv6_address"),
})
IPV4_LOOKUP: Mapping[str, Slot] = MappingProxyType({
    "address": Slot("addresses", "ipv4_lookup"),
})
SWITCH: Mapping[str, Slot] = MappingProxyType({
    "switch": Slot("switches", "switch"),
})
FORTIOS_WTP: Mapping[str, Slot] = MappingProxyType({
    "wtp_id": Slot("wtp_ids", "fortios_wtp_id"),
})
