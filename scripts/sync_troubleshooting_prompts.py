#!/usr/bin/env python3
"""Copy the canonical runbook into the installed gateway package."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
source = root / 'docs/troubleshooting-by-symptom.md'
destination = root / 'src/netops/troubleshooting-by-symptom.md'
data = source.read_bytes()
if sys.argv[1:] == ['--check']:
    if destination.exists() and destination.read_bytes() == data:
        sys.exit(0)
    print('src/netops/troubleshooting-by-symptom.md differs from docs/troubleshooting-by-symptom.md: '
          'run python3 -B scripts/sync_troubleshooting_prompts.py and commit the result', file=sys.stderr)
    sys.exit(1)
destination.write_bytes(data)
