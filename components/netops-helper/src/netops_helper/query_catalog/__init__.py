"""Canonical platform map for phase-1 read-query catalogues."""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from .arista import QUERIES as ARISTA_EOS_QUERIES
from .cisco import IOS_QUERIES, IOS_XE_QUERIES, NXOS_QUERIES
from .extreme import QUERIES as EXTREME_EXOS_QUERIES
from .fortinet import QUERIES as FORTINET_QUERIES
from .junos import COMMON_QUERIES as JUNIPER_JUNOS_QUERIES
from .junos import ELS_QUERIES as JUNIPER_JUNOS_ELS_QUERIES
from .linux import QUERIES as LINUX_QUERIES
from .model import Query
from .ruckus import QUERIES as RUCKUS_UNLEASHED_QUERIES


READ_QUERIES: Mapping[str, Mapping[str, Query]] = MappingProxyType({
    "linux": LINUX_QUERIES,
    "fortinet": FORTINET_QUERIES,
    "extreme_exos": EXTREME_EXOS_QUERIES,
    "cisco_ios": IOS_QUERIES,
    "cisco_xe": IOS_XE_QUERIES,
    "cisco_nxos": NXOS_QUERIES,
    "arista_eos": ARISTA_EOS_QUERIES,
    "juniper_junos": JUNIPER_JUNOS_QUERIES,
    "juniper_junos_els": JUNIPER_JUNOS_ELS_QUERIES,
    "ruckus_unleashed": RUCKUS_UNLEASHED_QUERIES,
})
