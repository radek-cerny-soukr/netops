import json
import os
import subprocess
import sys
from pathlib import Path

from netops_core.audit import Recorder

SOURCE = Path(__file__).resolve().parents[1] / "src"

CHILD = r"""
import json, os, resource, signal, sys
from netops_core.audit import AuditPersistenceError, Recorder

path, spare = sys.argv[1], int(sys.argv[2])
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
keeper = Recorder(path, "helper")
keeper.record("first", detail="one")
soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
if spare >= 0:
    resource.setrlimit(resource.RLIMIT_FSIZE, (os.path.getsize(path) + spare, hard))
outcome = []
try:
    keeper.record("second", detail="x" * 120)
    outcome.append("ok")
except AuditPersistenceError:
    outcome.append("AuditPersistenceError")
resource.setrlimit(resource.RLIMIT_FSIZE, (hard, hard))
for event in ("third", "fourth"):
    keeper.record(event, detail="must be readable")
    outcome.append("ok")
print(json.dumps(outcome))
"""


def run_child(path, spare):
    environment = dict(os.environ, PYTHONPATH=str(SOURCE))
    finished = subprocess.run(
        [sys.executable, "-B", "-c", CHILD, str(path), str(spare)],
        capture_output=True, text=True, timeout=60, env=environment,
    )
    assert finished.returncode == 0, finished.stderr
    return json.loads(finished.stdout)


def events(path):
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    return [json.loads(line)["event"] for line in raw.split(b"\n") if line]


def test_records_written_without_a_disk_error_are_one_line_each(tmp_path):
    path = tmp_path / "audit.jsonl"
    assert run_child(path, -1) == ["ok", "ok", "ok"]
    assert events(path) == ["first", "second", "third", "fourth"]


def test_a_partial_write_leaves_no_fragment_in_front_of_the_next_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    assert run_child(path, 40) == ["AuditPersistenceError", "ok", "ok"]
    assert events(path) == ["first", "third", "fourth"]


def test_a_fragment_left_by_an_interrupted_writer_stays_off_the_next_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    keeper = Recorder(path, "helper")
    keeper.record("first", detail="one")
    with open(path, "ab") as handle:
        handle.write(b'{"component":"helper","detail":"xxxx')
    keeper.record("second", detail="must be readable")
    keeper.record("third", detail="must be readable")
    lines = path.read_bytes().split(b"\n")
    assert lines[-1] == b""
    assert lines[1] == b'{"component":"helper","detail":"xxxx'
    assert [json.loads(line)["event"] for line in (lines[0], *lines[2:-1])] == [
        "first", "second", "third",
    ]
