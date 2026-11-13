#!/usr/bin/env python3
"""Import a whole scenario; expectations must already be supplied independently."""
import argparse
import json
from pathlib import Path
import re

try:
    from .anonymize_fixture import Anonymizer
    from .replay_capture import SCHEMA, validate
except ImportError:  # direct CLI invocation
    from anonymize_fixture import Anonymizer
    from replay_capture import SCHEMA, validate

# The anonymizer preserves syntax; it is not a credential scrubber. Refuse
# credential-bearing captures before writing any repository output.
SENSITIVE = re.compile(r'(?im)(?:-----BEGIN .*PRIVATE KEY|\bENC\s+\S+|'
                       r'\bsnmp[^\r\n]*?\b(?:auth|priv)\s+(?:\S+\s+)?\S+|'
                       r'\b(?:set\s+)?(?:password|passwd|psksecret|community|token|secret|authentication-key|key-string|pre-shared-key|wpa-psk|auth-password|priv-password|auth-passphrase|priv-passphrase)\s+\S+)')


def import_scenario(manifest, output, *, names=(), serials=(), ssids=(), users=()):
    source = json.loads(manifest.read_text())
    source['schema'] = SCHEMA
    for capture in source['captures']:
        capture['stdout'] = (manifest.parent / capture.pop('file')).read_text()
    validate(source)
    if SENSITIVE.search(json.dumps(source)) or any(SENSITIVE.search(capture['stdout']) for capture in source['captures']):
        raise ValueError('remove credentials from the private capture before import')
    anonymizer = Anonymizer(names=names, serials=serials, ssids=ssids, users=users)
    # Prime every capture and independent expectation before replacing the first
    # byte; cross-command identities/MAC spellings remain consistent.
    anonymizer.prime('\n'.join(capture['stdout'] for capture in source['captures']))

    def transform(value):
        if isinstance(value, str):
            return anonymizer.text(value)
        if isinstance(value, list):
            return [transform(item) for item in value]
        if isinstance(value, dict):
            return {key: transform(item) for key, item in value.items()}
        return value

    result = transform(source)
    validate(result)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as handle:
        handle.write(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    # Never persist/print the map: it contains original site identifiers.
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('output', type=Path)
    for name in ('name', 'serial', 'ssid', 'user'):
        parser.add_argument('--' + name, action='append', default=[])
    args = parser.parse_args()
    import_scenario(args.manifest, args.output, names=args.name, serials=args.serial,
                    ssids=args.ssid, users=args.user)


if __name__ == '__main__':
    main()
