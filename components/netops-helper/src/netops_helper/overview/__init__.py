"""Late loading of the approved network overview adapters."""

from importlib import import_module
from types import MappingProxyType

ADAPTERS = MappingProxyType({
    "fortinet": "fortinet", "extreme_exos": "exos",
    "cisco_ios": "cisco", "cisco_xe": "cisco", "cisco_nxos": "cisco",
    "arista_eos": "eos", "juniper_junos": "junos", "juniper_junos_els": "junos",
    "fortiadc": "fortiadc", "ruckus_unleashed": "ruckus", "linux": "linux",
})


def adapter(platform):
    module = ADAPTERS.get(platform)
    if module is None:
        return None
    name = f"{__name__}.{module}"
    try:
        return import_module(name)
    except ModuleNotFoundError as error:
        if error.name != name:
            raise
        return None
