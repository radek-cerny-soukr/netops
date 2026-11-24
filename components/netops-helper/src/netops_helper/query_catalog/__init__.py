"""Canonical platform map for phase-1 read-query catalogues."""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from .arista import QUERIES as ARISTA_EOS_QUERIES
from .cisco import IOS_QUERIES, IOS_XE_QUERIES, NXOS_QUERIES
from .extreme import QUERIES as EXTREME_EXOS_QUERIES
from .fortiadc import QUERIES as FORTIADC_QUERIES
from .fortinet import QUERIES as FORTINET_QUERIES
from .junos import ELS_QUERIES as JUNIPER_JUNOS_ELS_QUERIES
from .junos import JUNOS_QUERIES as JUNIPER_JUNOS_QUERIES
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
    "fortiadc": FORTIADC_QUERIES,
})


# Declarations are independent of the overview adapters. The base catalogue stays
# public until the integration step explicitly activates reviewed fragments.
OVERVIEW_QUERY_MODULES = MappingProxyType({
    "cisco_ios": "overview_cisco", "cisco_xe": "overview_cisco", "cisco_nxos": "overview_cisco",
    "juniper_junos": "overview_junos", "juniper_junos_els": "overview_junos",
    "linux": "overview_linux",
})


def compose(fragments: Mapping[str, Mapping[str, Query]]) -> Mapping[str, Mapping[str, Query]]:
    """Compose already imported declarations with the base catalogue for verification."""
    from .linux import _LinuxQueries

    if unknown := fragments.keys() - OVERVIEW_QUERY_MODULES.keys():
        raise ValueError(f"unapproved overview query platform: {sorted(unknown)}")
    catalog = dict(READ_QUERIES)
    for platform, additions in fragments.items():
        base = catalog[platform]
        if overlap := (base.keys() | ({"version"} if platform == "linux" else set())) & additions.keys():
            raise ValueError(f"duplicate {platform} queries: {sorted(overlap)}")
        if any(not isinstance(query, Query) for query in additions.values()):
            raise ValueError(f"invalid query declaration for {platform}")
        merged = {**base, **additions}
        catalog[platform] = _LinuxQueries(merged) if platform == "linux" else MappingProxyType(merged)
    return MappingProxyType(catalog)
