import signal
import sys


_stopping = False
_stop_callback = None


class StartupStopped(Exception):
    pass


def stop_requested():
    return _stopping


def request_stop(signum, frame):
    global _stopping
    _stopping = True
    callback = _stop_callback
    if callback is not None:
        callback()


def handoff_stop(callback):
    global _stop_callback
    _stop_callback = callback
    if _stopping and callback is not None:
        callback()


def main():
    serving = sys.argv[1:2] == ["serve"]
    previous = signal.signal(signal.SIGTERM, request_stop) if serving else None
    if serving:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
    try:
        from .cli import main as run
        if serving and stop_requested():
            return 0
        return run()
    finally:
        if serving:
            handoff_stop(None)
            signal.signal(signal.SIGTERM, previous)
