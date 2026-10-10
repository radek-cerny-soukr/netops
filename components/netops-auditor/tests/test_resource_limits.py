import importlib.util
import os
import resource
import signal
import subprocess
import sys
import time
import threading
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("guard_under_test", Path(__file__).with_name("_test_guard.py"))
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def test_normal_call_preserves_result_and_signal_state():
    result = object()
    previous = signal.getsignal(signal.SIGALRM)
    assert guard.bounded(lambda: result, 1, 32 * 1024 * 1024, TimeoutError) is result
    assert signal.getsignal(signal.SIGALRM) == previous
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_timeout_is_enforced_and_handler_restored():
    previous = signal.getsignal(signal.SIGALRM)
    with pytest.raises(TimeoutError):
        guard.bounded(lambda: time.sleep(2), 0.05, 32 * 1024 * 1024, TimeoutError)
    assert signal.getsignal(signal.SIGALRM) == previous
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_child_memory_ceiling_is_enforced():
    memory = 96 * 1024 * 1024
    def limit():
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    program = "import time\ntry:\n x=bytearray(128*1024*1024);time.sleep(.15)\nexcept MemoryError:raise SystemExit(77)"
    if sys.platform == "darwin":
        with pytest.raises(AssertionError, match="memory ceiling"):
            guard.run([sys.executable, "-B", "-c", program], memory_limit=memory,
                      preexec_fn=limit, capture_output=True, timeout=5)
    else:
        done = guard.run([sys.executable, "-B", "-c", program], memory_limit=memory,
                         preexec_fn=limit, capture_output=True, timeout=5)
        assert done.returncode == 77, done.stderr


def test_in_process_memory_ceiling_is_enforced_in_an_isolated_probe():
    prefix = "import importlib.util;s=importlib.util.spec_from_file_location('probe',"+repr(str(Path(guard.__file__)))+");g=importlib.util.module_from_spec(s);s.loader.exec_module(g);"
    program = prefix + "import time\ndef grow():\n x=bytearray(128*1024*1024);time.sleep(.15)\ntry:g.bounded(grow,2,24*1024*1024,TimeoutError)\nexcept MemoryError:raise SystemExit(77)"
    done = subprocess.run([sys.executable, "-B", "-c", program], capture_output=True, timeout=6)
    expected = -signal.SIGKILL if sys.platform == "darwin" else 77
    assert done.returncode == expected, done.stderr


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin resident-memory observer")
def test_observation_failure_on_a_live_child_is_refused(monkeypatch):
    def unavailable(pid):
        raise RuntimeError("resident memory observation failed")
    monkeypatch.setattr(guard, "resident", unavailable)
    with pytest.raises(RuntimeError, match="observation failed"):
        guard.run([sys.executable, "-c", "import time;time.sleep(2)"],
                  preexec_fn=lambda: None, memory_limit=64*1024*1024,
                  capture_output=True, timeout=3)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin resident-memory observer")
def test_child_exit_during_memory_observation_is_collected(monkeypatch):
    def exited(pid):
        timer = threading.Timer(0.01, os.kill, args=(pid, signal.SIGTERM))
        timer.daemon = True
        timer.start()
        raise RuntimeError("resident memory observation failed")
    monkeypatch.setattr(guard, "resident", exited)
    done = guard.run([sys.executable, "-c", "import time;time.sleep(2)"],
                     preexec_fn=lambda: None, memory_limit=64*1024*1024,
                     capture_output=True, timeout=3)
    assert done.returncode == -signal.SIGTERM
