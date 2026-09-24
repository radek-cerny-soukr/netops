#!/usr/bin/env python3
"""Record the queue of the syslog-ng destination that ships the netops-admin audit log; run as root by a timer."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

DESTINATION = re.compile(r"^[A-Za-z0-9_]{1,64}$")
QUEUED = re.compile(r"^dst\.syslog\.(?P<name>[A-Za-z0-9_]+)#\d+\.[^=]*\.queued=(?P<count>\d+)$")


def queued(destination: str, ctl: str, run=subprocess.run) -> int:
    answer = run([ctl, "query", "get", "dst.syslog.%s#*.queued" % destination],
                 capture_output=True, text=True, timeout=20, check=True)
    counts = [int(match.group("count")) for match in map(QUEUED.match, answer.stdout.splitlines())
              if match is not None and match.group("name") == destination]
    if not counts:
        raise RuntimeError("syslog-ng reports no queue for destination %s" % destination)
    return sum(counts)


def write_status(output: Path, pending: int, now: float) -> dict:
    since_file = output.with_name(output.name + ".pending-since")
    if pending:
        try:
            since = float(since_file.read_text())
        except (OSError, ValueError):
            since = now
            since_file.write_text("%.3f" % since)
        age = max(0.0, now - since)
    else:
        since_file.unlink(missing_ok=True)
        age = 0.0
    document = {"updated_at": now, "pending": pending, "oldest_pending_age_seconds": round(age, 1)}
    temporary = output.with_name("." + output.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(document, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, output)
    return document


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ctl", default="syslog-ng-ctl")
    args = parser.parse_args(argv)
    if not DESTINATION.match(args.destination):
        print("destination must be a syslog-ng identifier", file=sys.stderr)
        return 2
    try:
        pending = queued(args.destination, args.ctl)
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        print("export status not updated: %s" % exc, file=sys.stderr)
        return 1
    write_status(args.output, pending, time.time())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
