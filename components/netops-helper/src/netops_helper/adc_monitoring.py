"""Fixed read-only disk/NTP recipes measured on FortiADC 7.6.7 build0676."""
from __future__ import annotations

import re
import shlex

RECIPES = frozenset({'disk_usage', 'ntp_status'})
NTP_TIMEOUT = 60
STATUS = 'get system status'
COMMANDS = {
    'disk_usage': ('diagnose hardware get sysinfo df', 'get log setting local'),
    'ntp_status': ('show full-configuration system time ntp', 'diagnose system ntp'),
}
REFUSED = re.compile(r'(?mi)^\s*(?:Command fail\.|Parsing error|permission denied|unknown action)')
SECRET_LINE = re.compile(r'(?im)^.*(?:\bENC\b|\b(?:set\s+)?(?:key|password|secret|passwd|psk|community)\s*(?::|\s)).*$')


def safe_text(text):
    # NTP authentication keys must never reach raw output, audit, hashes or parsers.
    return SECRET_LINE.sub('<REDACTED>', text.replace('\r\n', '\n').replace('\r', '\n'))


def disk_summary(df, rotation):
    lines = [line.strip() for line in df.splitlines() if line.strip()]
    header = 'Filesystem Size Used Available Use% Mounted on'
    records = []
    valid = bool(lines) and ' '.join(lines[0].split()) == header
    size = r'(?:\d+(?:\.\d+)?[KMGTPE]?B?)'
    pattern = re.compile(rf'(\S+)\s+({size})\s+({size})\s+({size})\s+(\d+)%\s+(/\S*)')
    for line in lines[1:]:
        match = pattern.fullmatch(line)
        if match is None or not 0 <= int(match[5]) <= 100:
            valid = False
            continue
        row = dict(zip(('filesystem', 'size', 'used', 'available', 'used_percent', 'mount'), match.groups()))
        row['used_percent'] = int(row['used_percent'])
        if row not in records:  # the appliance repeats /var/log and /home
            records.append(row)
    values = {}
    for line in rotation.splitlines():
        key, sep, value = line.partition(':')
        if sep and key.strip() in ('status', 'rotation-size', 'disk-full'):
            key = key.strip()
            if key in values:
                valid = False
            values[key] = value.strip()
    rotation_valid = (values.get('status') in ('enable', 'disable')
                      and values.get('rotation-size', '').isdigit()
                      and values.get('disk-full') in ('overwrite', 'nolog'))
    valid = valid and bool(records) and rotation_valid
    return {'status': 'complete' if valid else 'incomplete', 'filesystems': records,
            'log_storage': [row for row in records if row['mount'] == '/var/log'],
            'rotation_configuration': values,
            'capacity_units': 'device-reported human-readable; rounded',
            'rotation_scope': 'configuration only; no log rotation was performed'}


def ntp_summary(config, status, runtime):
    lines = [line.strip() for line in config.splitlines() if line.strip()]
    valid = bool(lines) and lines[0] == 'config system time ntp'
    depth = 0
    enabled = None
    interval = None
    servers = []
    current = None
    for line in lines:
        try:
            parts = shlex.split(line)
        except ValueError:
            valid = False
            continue
        if not parts:
            continue
        if parts[0] == 'config':
            depth += 1
        elif parts[0] == 'end':
            depth -= 1
            if depth < 0:
                valid = False
        elif parts[0] == 'edit' and len(parts) == 2:
            if current is not None:
                valid = False
            current = {'id': parts[1], 'servers': []}
        elif parts[0] == 'next':
            if current is None or not current['servers']:
                valid = False
            else:
                servers.append(current)
            current = None
        elif parts[:2] == ['set', 'ntpsync']:
            if len(parts) != 3 or parts[2] not in ('enable', 'disable') or enabled is not None:
                valid = False
            else:
                enabled = parts[2] == 'enable'
        elif parts[:2] == ['set', 'syncinterval']:
            if len(parts) == 3 and parts[2].isdigit() and 1 <= int(parts[2]) <= 1440:
                interval = int(parts[2])
            else:
                valid = False
        elif parts[:2] == ['set', 'server']:
            if current is None or len(parts) < 3:
                valid = False
            else:
                current['servers'] = parts[2:]
    clock = re.findall(r'(?m)^System Time:\s+([^\n]+)$', status)
    valid = (valid and depth == 0 and current is None and enabled is not None and len(clock) == 1
             and lines[-1:] == ['end'] and (not enabled or bool(servers)))
    runtime_match = re.fullmatch(
        r'System clock last updated:\s*([^\n]+)\nSystem clock synchronized: (yes|no)\n'
        r'Current server status:[ \t]*\n?(.*)', runtime.strip(), re.S)
    runtime_valid = (runtime_match is not None and '--More--' not in runtime and '\x00' not in runtime
                     and REFUSED.search(runtime) is None
                     and runtime.count('System clock synchronized:') == 1)
    valid = valid and runtime_valid
    return {'status': 'complete' if valid else 'incomplete',
            'ntpsync_configured': enabled, 'configured_servers': servers,
            'syncinterval_minutes': interval, 'system_time': clock[0].strip() if len(clock) == 1 else None,
            'sync_status': ('synchronized' if runtime_match[2] == 'yes' else 'unsynchronized')
                           if runtime_valid else 'unknown',
            'last_updated': runtime_match[1].strip() if runtime_valid else None,
            'server_status_lines': runtime_match[3].splitlines() if runtime_valid and runtime_match[3] else [],
            'runtime_status': 'measured' if runtime_valid else ('device_refused' if REFUSED.search(runtime) else 'unrecognized'),
            'offset_ms': None, 'offset_status': 'not_parsed',
            'server_visibility': 'reported_configuration' if enabled else 'hidden_when_disabled',
            'reason': 'Synchronization is read from diagnose system ntp; no offset grammar verified on this appliance'}



def run(shell, recipe, timeout):
    from .config_fortiadc import verify_identity

    if recipe not in RECIPES:
        raise ValueError('unknown FortiADC monitoring recipe')
    status = safe_text(shell.command(STATUS, timeout))
    identity = verify_identity(status)[0]
    outputs = [safe_text(shell.command(command, timeout)) for command in COMMANDS[recipe]]
    raw = '\n'.join([status, *outputs])
    if any(REFUSED.search(text) for text in (outputs if recipe == 'disk_usage' else outputs[:1])):
        return {'identity': identity, 'state': 'device_refused', 'raw': raw}
    summary = disk_summary(*outputs) if recipe == 'disk_usage' else ntp_summary(outputs[0], status, outputs[1])
    if '--More--' in raw or '\x00' in raw:
        summary['status'] = 'incomplete'
        if recipe == 'ntp_status':
            summary['sync_status'] = 'unknown'
    return {'identity': identity, 'state': 'data' if summary['status'] == 'complete' else 'incomplete',
            'raw': raw, 'disk' if recipe == 'disk_usage' else 'ntp': summary}
