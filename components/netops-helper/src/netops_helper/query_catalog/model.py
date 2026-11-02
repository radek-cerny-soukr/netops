"""Immutable model and typed inventory slots shared by query catalogues."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True, slots=True)
class Slot:
    inventory: str
    kind: str


@dataclass(frozen=True, slots=True)
class Query:
    command: str
    slots: Mapping[str, Slot]
    description: str
    high_volume: bool = False
    pty: bool = False
    empty_allowed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "slots", MappingProxyType(dict(self.slots)))


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
CISCO_XE_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_xe_interface"),
})
CISCO_XE_PHYSICAL_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_xe_physical_interface"),
})
CISCO_NXOS_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_nxos_interface"),
})
CISCO_NXOS_ERRORS_INTERFACE: Mapping[str, Slot] = MappingProxyType({
    "interface": Slot("interfaces", "cisco_nxos_errors_interface"),
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
SWITCH: Mapping[str, Slot] = MappingProxyType({
    "switch": Slot("switches", "switch"),
})
