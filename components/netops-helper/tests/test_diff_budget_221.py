"""Whole Myers trace/reconstruction budget (review finding 1)."""
from array import array
import sys
import tracemalloc

import pytest

from netops_helper import configuration


@pytest.fixture(autouse=True)
def empty_cache():
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    yield
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


def test_review_trace_exhausts_18100000_bytes(monkeypatch):
    monkeypatch.setattr(configuration, '_ACTIVE_BUDGET', 18_100_000)
    with pytest.raises(configuration.ConfigurationBudgetError):
        configuration._edit_script(array('i', [1]) * 1500, array('i', [2]) * 1500, [0])


def test_3000_edits_still_succeed_with_room_for_the_whole_trace(monkeypatch):
    monkeypatch.setattr(configuration, '_ACTIVE_BUDGET', 64 * 1024 * 1024)
    charged = [0]
    hunks = configuration._edit_script(array('i', [1]) * 1500, array('i', [2]) * 1500, charged)
    assert hunks == [(list(range(1500)), list(range(1500)))]
    actual = sys.getsizeof(hunks)
    for hunk in hunks:
        actual += sys.getsizeof(hunk)
        for indexes in hunk:
            actual += sys.getsizeof(indexes) + sum(sys.getsizeof(index) for index in indexes)
    assert charged[0] >= actual


def test_trace_and_fragmented_reconstruction_peak_is_reserved(monkeypatch):
    a = array('i', range(600))
    b = array('i', (value if value % 3 else -value - 1 for value in a))
    reservations = []
    budget = configuration._budget

    def recording(staged=0):
        reservations.append(staged)
        budget(staged)

    monkeypatch.setattr(configuration, '_budget', recording)
    tracemalloc.start()
    try:
        hunks = configuration._edit_script(a, b, [0])
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert len(hunks) == 200
    assert peak <= max(reservations), (peak, max(reservations))


def test_empty_side_result_is_charged_and_budgeted(monkeypatch):
    charged = [0]
    assert configuration._edit_script(array('i'), array('i', [1]), charged) == [(range(0), range(1))]
    assert charged[0] > 0
    monkeypatch.setattr(configuration, '_ACTIVE_BUDGET', 1)
    with pytest.raises(configuration.ConfigurationBudgetError):
        configuration._edit_script(array('i'), array('i', [1]), [0])
