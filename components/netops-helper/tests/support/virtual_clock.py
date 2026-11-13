"""One monotonic domain for test budgets, pacing and isolated workers.

Only application clocks are replaced. OS selectors wait in real time, but
their timeout is derived from the remaining virtual budget. Event.wait and
the parser watchdog retain real-time behavior.
"""
import fcntl
import os
import tempfile
from pathlib import Path
import struct
import threading
from types import SimpleNamespace


class Clock:
    def __init__(self, start=0.0, path=None):
        self.start = start
        self.path = Path(path) if path is not None else None
        self._value = start
        self._lock = threading.RLock()
        self.sleeps = []
        if self.path is not None:
            # Coordinate creators, then publish a complete value with rename.
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                fcntl.flock(directory, fcntl.LOCK_EX)
                if not self.path.exists():
                    fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix='.clock-')
                    try:
                        with os.fdopen(fd, 'wb') as handle:
                            handle.write(struct.pack('d', start))
                        os.rename(temporary, self.path)
                    finally:
                        if os.path.exists(temporary):
                            os.unlink(temporary)
            finally:
                os.close(directory)

    def _access(self, change=None):
        with self._lock:
            if self.path is None:
                if change is not None:
                    self._value = change(self._value)
                return self._value
            with self.path.open('r+b') as handle:
                fcntl.flock(handle, fcntl.LOCK_EX)
                value, = struct.unpack('d', handle.read(8))
                if change is not None:
                    value = change(value)
                    handle.seek(0)
                    handle.write(struct.pack('d', value))
                    handle.flush()
                return value

    def monotonic(self):
        return self._access()

    __call__ = monotonic

    @property
    def value(self):
        return self.monotonic()

    @value.setter
    def value(self, value):
        self._access(lambda _: value)

    now = value

    def advance(self, seconds):
        assert seconds >= 0
        return self._access(lambda value: value + seconds)

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.advance(seconds)


def install(monkeypatch, clock):
    from netops_helper import engine, endpoint_worker, locate
    monkeypatch.setattr(engine, '_now', clock.monotonic)
    monkeypatch.setattr(engine, '_sleep', clock.sleep)
    original = locate.Budget
    monkeypatch.setattr(locate, 'Budget', lambda: original(clock.monotonic))
    monkeypatch.setattr(endpoint_worker, 'time', SimpleNamespace(monotonic=clock.monotonic))


def worker_source(clock):
    """Bootstrap using the same helper and shared state as the parent process."""
    assert clock.path is not None
    return '''
import sys
sys.path.insert(0, %r)
from support.virtual_clock import Clock
from netops_helper import engine, endpoint_worker, locate
from types import SimpleNamespace
clock = Clock(path=%r)
engine._now = clock.monotonic
engine._sleep = clock.sleep
original_budget = locate.Budget
locate.Budget = lambda: original_budget(clock.monotonic)
endpoint_worker.time = SimpleNamespace(monotonic=clock.monotonic)
''' % (str(Path(__file__).resolve().parents[1]), str(clock.path))
