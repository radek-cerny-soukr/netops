from __future__ import annotations

import json
import os
import subprocess
import sys

from netops_admin import audit

CHILD = r"""
import json, os, resource, signal, sys
from netops_admin.audit import AuditLog

path, spare = sys.argv[1], int(sys.argv[2])
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
log = AuditLog(path)
log.event("step", change_id="c" * 32, device="lab", step="first", detail="one")
soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
if spare >= 0:
    resource.setrlimit(resource.RLIMIT_FSIZE, (os.path.getsize(path) + spare, hard))
outcome = []
try:
    log.event("step", change_id="c" * 32, device="lab", step="second", detail="x" * 150)
    outcome.append("ok")
except OSError:
    outcome.append("OSError")
resource.setrlimit(resource.RLIMIT_FSIZE, (hard, hard))
for name in ("third", "fourth"):
    log.event("step", change_id="c" * 32, device="lab", step=name, detail="must be readable")
    outcome.append("ok")
print(json.dumps(outcome))
"""


def run_child(path, spare):
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    finished = subprocess.run(
        [sys.executable, "-B", "-c", CHILD, str(path), str(spare)],
        capture_output=True, text=True, timeout=60, env=environment,
    )
    assert finished.returncode == 0, finished.stderr
    return json.loads(finished.stdout)


def steps(path):
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    return [json.loads(line)["step"] for line in raw.split(b"\n") if line]


def test_events_written_without_a_disk_error_are_one_line_each(tmp_path):
    path = tmp_path / "audit.jsonl"
    assert run_child(path, -1) == ["ok", "ok", "ok"]
    assert steps(path) == ["first", "second", "third", "fourth"]


def test_a_partial_write_leaves_no_fragment_in_front_of_the_next_event(tmp_path):
    path = tmp_path / "audit.jsonl"
    assert run_child(path, 60) == ["OSError", "ok", "ok"]
    assert steps(path) == ["first", "third", "fourth"]


def test_a_fragment_left_by_an_interrupted_writer_stays_off_the_next_event(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = audit.AuditLog(path)
    log.event("step", change_id="c" * 32, device="lab", step="first", detail="one")
    with open(path, "ab") as handle:
        handle.write(b'{"change_id":"cccc')
    log.event("step", change_id="c" * 32, device="lab", step="second", detail="must be readable")
    log.event("step", change_id="c" * 32, device="lab", step="third", detail="must be readable")
    lines = path.read_bytes().split(b"\n")
    assert lines[-1] == b""
    assert lines[1] == b'{"change_id":"cccc'
    assert [json.loads(line)["step"] for line in (lines[0], *lines[2:-1])] == ["first", "second", "third"]
