"""CDP detail records from IOS, IOS XE and NX-OS RO captures.

CDP capabilities are preserved as advertised text: they are not IEEE LLDP
capability letters. Entry addresses are not assumed to be management addresses.
"""
from __future__ import annotations

import ipaddress
import re

FIELDS = ('local_port', 'neighbor', 'neighbor_port', 'management_ip', 'platform', 'capabilities')
PROFILES = ('cisco_ios', 'cisco_xe', 'cisco_nxos')


def parse(table, text):
    from . import tables
    from .normalization import normalize_port

    rows, unknown, current, section = [], [], None, None
    start = 1

    def close():
        if current is not None and any(current[field] is None for field in ('local_port', 'neighbor', 'neighbor_port')):
            unknown.append({'line': start, 'text': 'incomplete CDP neighbor block'})

    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        if re.fullmatch(r'-{5,}', value):
            section = None
            continue
        match = re.fullmatch(r'Device ID:\s*(.+)', value, re.I)
        if match:
            close()
            current = tables.record('cdp_neighbor', neighbor=match[1])
            rows.append(current)
            start, section = number, None
            continue
        if re.fullmatch(r'Total cdp entries displayed\s*:\s*\d+', value, re.I):
            section = None
            continue
        if value == 'show cdp neighbors detail' or re.fullmatch(r'[\w.-]+[#>]', value):
            continue
        if current is None:
            unknown.append({'line': number, 'text': raw})
            continue
        if re.fullmatch(r'Version\s*:', value, re.I):
            section = 'version'
            continue
        # The version TLV is vendor text, ended by the advertisement metadata.
        if re.fullmatch(r'advertisement version:\s*\d+', value, re.I):
            section = None
            continue
        if section == 'version':
            continue
        if re.fullmatch(r'(?:Entry|Interface) address\(es\):\s*\d*', value, re.I):
            section = 'entry'
            continue
        if re.fullmatch(r'(?:Management|Mgmt) address\(es\):\s*', value, re.I):
            section = 'management'
            continue
        match = re.fullmatch(r'(?:IP|IPv4|IPv6) [Aa]ddress:\s*(\S+)', value)
        if match and section in ('entry', 'management'):
            try:
                address = str(ipaddress.ip_address(match[1]))
            except ValueError:
                unknown.append({'line': number, 'text': raw})
                continue
            if section == 'management':
                if current['management_ip'] not in (None, address):
                    unknown.append({'line': number, 'text': raw})
                else:
                    current['management_ip'] = address
            continue
        section = None
        match = re.fullmatch(r'Platform:\s*(.*?),\s*Capabilities:\s*(.*)', value)
        if match:
            current.update(platform=match[1].strip() or None, capabilities=match[2].strip() or None)
            continue
        match = re.fullmatch(r'Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(.+)', value)
        if match:
            try:
                current['local_port'] = tables.port(match[1])
                current['neighbor_port'] = normalize_port(match[2])['name']
            except ValueError:
                unknown.append({'line': number, 'text': raw})
            continue
        if any(re.fullmatch(pattern, value, re.I) for pattern in (
                r'Holdtime\s*:\s*\d+ sec', r'Duplex:\s*(?:full|half)',
                r'(?:Peer Source|Local Interface|Remote Interface) MAC:\s*[0-9a-f:.]+',
                r'VTP Management Domain:.*', r'Native VLAN:\s*\d+')):
            continue
        unknown.append({'line': number, 'text': raw})
    close()
    return rows, unknown


def register(fields, optional, bindings, parsers):
    fields['cdp_neighbor'] = FIELDS
    optional['cdp_neighbor'] = {'management_ip', 'platform', 'capabilities'}
    for profile in PROFILES:
        bindings[profile]['cdp_neighbor'] = 'cdp_neighbors'
        parsers[(profile, 'cdp_neighbor', 'cdp_neighbors')] = parse
