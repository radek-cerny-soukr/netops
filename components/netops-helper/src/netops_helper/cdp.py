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
    start, displayed, separated = 1, None, False

    def close():
        if current is None:
            return
        # Cisco interface names are normalized only for a Cisco neighbor; a foreign device
        # (Linux eth0, an IP phone "Port 1") keeps the port text it advertised.
        port = current['neighbor_port']
        if port is not None and (current['platform'] or '').lower().startswith('cisco'):
            try:
                current['neighbor_port'] = normalize_port(port)['name']
            except ValueError:
                pass
        if any(current[field] is None for field in ('local_port', 'neighbor', 'neighbor_port')):
            unknown.append({'line': start, 'text': 'incomplete CDP neighbor block'})

    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        if re.fullmatch(r'-{5,}', value):
            section, separated = None, True
            continue
        after_separator, separated = separated, False
        if section == 'orphan':
            # Text after a "Device ID:" that did not follow a separator, up to the next separator.
            unknown.append({'line': number, 'text': raw})
            continue
        if section == 'version' and not re.fullmatch(r'advertisement version:\s*\d+', value, re.I):
            # The version TLV is vendor text, ended by the advertisement metadata or by the
            # dashed record separator. A "Device ID:" inside it is text, not a new neighbor.
            continue
        match = re.fullmatch(r'Device ID:\s*(.+)', value, re.I)
        if match and current is not None and not after_separator:
            # A new record starts only at the first block or right after the dashed separator; an
            # injected "advertisement version" line must not open a record boundary.
            unknown.append({'line': number, 'text': raw})
            section = 'orphan'
            continue
        if match:
            close()
            current = tables.record('cdp_neighbor', neighbor=match[1])
            rows.append(current)
            start, section = number, None
            continue
        match = re.fullmatch(r'Total cdp entries displayed\s*:\s*(\d+)', value, re.I)
        if match:
            displayed = (number, raw, int(match[1]))
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
        if re.fullmatch(r'advertisement version:\s*\d+', value, re.I):
            section = None
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
            except ValueError:
                unknown.append({'line': number, 'text': raw})
            current['neighbor_port'] = match[2].strip() or None
            continue
        if any(re.fullmatch(pattern, value, re.I) for pattern in (
                r'Holdtime\s*:\s*\d+ sec', r'Duplex:\s*(?:full|half)',
                r'(?:Peer Source|Local Interface|Remote Interface) MAC:\s*[0-9a-f:.]+',
                r'VTP Management Domain:.*', r'Native VLAN:\s*\d+',
                # IP phone power and second-port TLVs: recognized, not exposed by the schema.
                r'Power (?:drawn|request|Available TLV)\b.*', r'Second Port Status:.*')):
            continue
        unknown.append({'line': number, 'text': raw})
    close()
    if displayed is not None and displayed[2] != len(rows):
        # The device's own entry count disagrees with the parsed blocks: never a complete read.
        line, raw, count = displayed
        unknown.append({'line': line, 'text': f'{raw.strip()} (parsed {len(rows)} CDP neighbor blocks)'})
    return rows, unknown


def register(fields, optional, bindings, parsers):
    fields['cdp_neighbor'] = FIELDS
    optional['cdp_neighbor'] = {'management_ip', 'platform', 'capabilities'}
    for profile in PROFILES:
        bindings[profile]['cdp_neighbor'] = 'cdp_neighbors'
        parsers[(profile, 'cdp_neighbor', 'cdp_neighbors')] = parse
