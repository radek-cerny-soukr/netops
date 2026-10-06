#!/usr/bin/env python3
"""Record the queue of the syslog-ng destination that ships the netops-admin audit log; run as root by a timer."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path

DESTINATION = re.compile(r"[A-Za-z0-9_]{1,64}")
QUEUED = re.compile(r"dst\.syslog\.(?P<name>[A-Za-z0-9_]+)#[0-9]+\.[^=]*\.queued=(?P<count>[0-9]{1,18})")
SINCE_MAX_BYTES = 64


def queued(destination: str, ctl: str, run=subprocess.run) -> int:
    answer = run([ctl, "query", "get", "dst.syslog.%s#*.queued" % destination],
                 capture_output=True, text=True, errors="replace", timeout=20, check=True)
    counts = [int(match.group("count")) for match in map(QUEUED.fullmatch, answer.stdout.splitlines())
              if match is not None and match.group("name") == destination]
    if not counts:
        raise RuntimeError("syslog-ng reports no queue for destination %s" % destination)
    return sum(counts)


def _replace(path: Path, text: str) -> None:
    temporary = path.with_name(".%s.%s.tmp" % (path.name, secrets.token_hex(8)))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _pending_since(path: Path, now: float):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None
        data = os.read(descriptor, SINCE_MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        since = float(data.decode("ascii"))
    except ValueError:
        return None
    return since if len(data) <= SINCE_MAX_BYTES and math.isfinite(since) and since <= now else None


def write_status(output: Path, pending: int, now: float, audit_file: str | None = None) -> dict:
    since_file = output.with_name(output.name + ".pending-since")
    if pending:
        since = _pending_since(since_file, now)
        if since is None:
            since = now
            _replace(since_file, "%.3f" % since)
        age = max(0.0, now - since)
    else:
        since_file.unlink(missing_ok=True)
        age = 0.0
    document = {"updated_at": now, "pending": pending, "oldest_pending_age_seconds": round(age, 1)}
    if audit_file is not None:
        document["audit_file"] = audit_file
    _replace(output, json.dumps(document))
    return document


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ctl", default="syslog-ng-ctl")
    parser.add_argument("--audit-file", help="absolute path of the audit log the destination reads")
    args = parser.parse_args(argv)
    if not DESTINATION.fullmatch(args.destination):
        print("destination must be a syslog-ng identifier", file=sys.stderr)
        return 2
    if args.audit_file is not None and not os.path.isabs(args.audit_file):
        print("audit file must be an absolute path", file=sys.stderr)
        return 2
    if not args.output.name:
        print("output must name a file", file=sys.stderr)
        return 2
    try:
        pending = queued(args.destination, args.ctl)
    except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as exc:
        print("export status not updated: %s" % exc, file=sys.stderr)
        return 1
    try:
        write_status(args.output, pending, time.time(), args.audit_file)
    except (OSError, ValueError) as exc:
        print("export status not written: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
