from dataclasses import dataclass
from datetime import datetime, timezone

from netops_auditor import query
from netops_auditor.store import Store

TENANT = "tenant-a"
DEVICE = "fw-example"
DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
NOW = datetime(2026, 10, 13, 13, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Event:
    request: str
    started_at: str
    device: str = DEVICE
    channel: str = "ssh"
    response_sha256: str = DIGEST
    response_bytes: int = 0
    finished_at: str = ""
    outcome: str = "ok"

    def __post_init__(self):
        if not self.finished_at:
            object.__setattr__(self, "finished_at", self.started_at)


def written(store, *events):
    for item in events:
        store.record_channel_events(TENANT, DEVICE, (item,))
    return [row["request"] for row in store.channel_events(TENANT, DEVICE)]


def test_channel_events_written_in_clock_order_are_listed_newest_first():
    with Store(":memory:") as store:
        listed = written(store, Event("first", "2026-10-13T10:00:00Z"), Event("second", "2026-10-13T11:00:00Z"))
    assert listed == ["second", "first"]


def test_channel_events_are_listed_by_the_order_they_were_written_not_by_their_clock():
    with Store(":memory:") as store:
        listed = written(
            store,
            Event("ahead", "2027-10-13T10:00:00Z"),
            Event("before-step", "2026-10-13T11:00:00Z"),
            Event("after-step", "2026-10-13T09:00:00Z"),
        )
        latest = [row["request"] for row in store.channel_events(TENANT, DEVICE, limit=1)]
    assert listed == ["after-step", "before-step", "ahead"]
    assert latest == ["after-step"]


def test_since_filters_the_latest_committed_run_by_its_own_timestamp():
    with Store(":memory:") as store:
        store.record_run(TENANT, DEVICE, "a" * 64, "fixture", "v1", (), started_at="2026-10-13T12:00:00Z")
        latest = store.record_run(TENANT, DEVICE, "b" * 64, "fixture", "v1", (), started_at="2026-10-13T11:00:00Z")
        unfiltered = query.list_findings(store, TENANT, DEVICE, now=NOW)
        before = query.list_findings(store, TENANT, DEVICE, now=NOW, since="2026-10-13T10:00:00Z")
        after = query.list_findings(store, TENANT, DEVICE, now=NOW, since="2026-10-13T11:30:00Z")
    assert (unfiltered["run_id"], before["run_id"]) == (latest, latest)
    assert (after["run_state"], after["run_id"]) == (query.RUN_BEFORE_SINCE, None)
