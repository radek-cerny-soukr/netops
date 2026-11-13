"""Origin invariance and actual parent/worker/pacing clock sharing."""
import subprocess
import sys

import pytest

from netops_helper import engine, endpoint_worker, locate
from support.virtual_clock import Clock, install, worker_source


@pytest.mark.parametrize('origin', [0.0, 10_000_000.0])
def test_parent_worker_budget_and_pacing_share_advances(tmp_path, monkeypatch, origin):
    clock = Clock(origin, tmp_path / 'clock')
    install(monkeypatch, clock)
    budget = locate.Budget()
    code = worker_source(clock) + '''
budget = locate.Budget()
assert budget.now() == engine._now() == endpoint_worker.time.monotonic()
engine._sleep(5)
assert budget.remaining() == locate.MAX_SECONDS - 5
'''
    subprocess.run([sys.executable, '-B', '-c', code], check=True, timeout=10)
    assert engine._now() == endpoint_worker.time.monotonic() == origin + 5
    assert budget.remaining() == locate.MAX_SECONDS - 5
    engine._sleep(2)
    assert clock() == origin + 7


def test_existing_clock_is_not_reset(tmp_path):
    path = tmp_path / 'clock'
    first = Clock(7.0, path)
    first.advance(3.0)
    assert Clock(99.0, path).monotonic() == 10.0
    assert not list(tmp_path.glob('.clock-*'))
