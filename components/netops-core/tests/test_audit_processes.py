import json
import multiprocessing
import os
import stat

from netops_core.audit import LOCK_SUFFIX, AuditPersistenceError, Recorder

COMPONENT = "auditor"
DEVICE = "fw-a.example.invalid"
SEGMENT_BYTES = 700
RETAINED_SEGMENTS = 400
RECORDS = 300
WRITERS = ("a", "b")


def _identifier(tag, index) -> str:
    return "op_%s%031x" % (tag, index)


def _write(path, tag, count, failures) -> None:
    keeper = Recorder(path, COMPONENT, SEGMENT_BYTES, RETAINED_SEGMENTS)
    broken = 0
    for index in range(count):
        try:
            keeper.record("ssh_read", device=DEVICE, status="ok", operation_id=_identifier(tag, index))
        except AuditPersistenceError:
            broken += 1
    failures.put((tag, broken))


def _written(directory, name) -> list:
    found = []
    for path in sorted(directory.iterdir()):
        if not path.name.startswith(name) or path.name.endswith(LOCK_SUFFIX):
            continue
        for line in path.read_bytes().splitlines():
            found.append(json.loads(line))
    return found


def test_two_processes_keep_every_record_across_a_rotation(tmp_path):
    path = tmp_path / "audit.jsonl"
    failures = multiprocessing.Queue()
    workers = [
        multiprocessing.Process(target=_write, args=(path, tag, RECORDS, failures))
        for tag in WRITERS
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(120)
    broken = dict(failures.get() for _ in WRITERS)

    assert broken == {tag: 0 for tag in WRITERS}
    for worker in workers:
        assert worker.exitcode == 0

    records = _written(tmp_path, "audit.jsonl")
    expected = {_identifier(tag, index) for tag in WRITERS for index in range(RECORDS)}
    assert {record["operation_id"] for record in records} == expected
    assert len(records) == len(expected)


def test_the_lock_is_a_stable_hidden_file_beside_the_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    keeper = Recorder(path, COMPONENT)
    keeper.record("started")
    lock = keeper.lock_path()

    assert lock == tmp_path / ".audit.jsonl.lock"
    assert lock.exists()
    assert stat.S_IMODE(os.stat(lock).st_mode) == 0o600

    keeper.record("started")
    assert keeper.lock_path() == lock
    assert sorted(item.name for item in tmp_path.iterdir()) == [".audit.jsonl.lock", "audit.jsonl"]


def test_the_lock_file_is_not_one_of_the_retained_segments(tmp_path):
    path = tmp_path / "audit.jsonl"
    keeper = Recorder(path, COMPONENT, segment_bytes=260, retained_segments=3)
    for index in range(30):
        keeper.record("ssh_read", device=DEVICE, status="ok", detail="event-%02d" % index)

    segments = sorted(item.name for item in tmp_path.glob("audit.jsonl*"))
    assert segments == ["audit.jsonl", "audit.jsonl.1", "audit.jsonl.2"]
