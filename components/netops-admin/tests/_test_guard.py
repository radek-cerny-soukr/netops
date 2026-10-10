import ctypes
import os
import resource
import select
import signal
import subprocess
import sys
import time
from pathlib import Path


def resident(pid):
    if sys.platform != "darwin":
        return int(Path("/proc/%d/statm" % pid).read_text().split()[1]) * resource.getpagesize()
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    library.proc_pidinfo.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(96)
    count = library.proc_pidinfo(pid, 4, 0, buffer, len(buffer))
    if count != len(buffer):
        raise RuntimeError("resident memory observation failed")
    return int.from_bytes(buffer.raw[8:16], sys.byteorder)


def watch(pid, ceiling, stop, ready):
    try:
        resident(pid)
        os.write(ready, b"R")
        os.close(ready)
        while not select.select([stop], [], [], 0.01)[0]:
            if resident(pid) > ceiling:
                os.kill(pid, signal.SIGKILL)
                return 3
        return 0
    except BaseException:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return 4


def bounded(call, seconds, memory, timeout_error):
    previous = signal.getsignal(signal.SIGALRM)
    timer = signal.getitimer(signal.ITIMER_REAL)
    watcher = None
    stop_read = stop_write = ready_read = ready_write = None
    limits = None
    def expire(signum, frame):
        raise timeout_error()
    try:
        if sys.platform == "darwin":
            ceiling = resident(os.getpid()) + memory
            stop_read, stop_write = os.pipe()
            ready_read, ready_write = os.pipe()
            watcher = subprocess.Popen(
                [sys.executable, "-B", str(Path(__file__).resolve()), "--watch",
                 str(os.getpid()), str(ceiling), str(stop_read), str(ready_write)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                pass_fds=(stop_read, ready_write),
            )
            os.close(stop_read)
            stop_read = None
            os.close(ready_write)
            ready_write = None
            if not select.select([ready_read], [], [], 3)[0] or os.read(ready_read, 1) != b"R":
                raise RuntimeError("memory supervisor did not become ready")
        else:
            limits = resource.getrlimit(resource.RLIMIT_AS)
            used = int(Path("/proc/self/statm").read_text().split()[0]) * resource.getpagesize()
            ceiling = used + memory if limits[1] == resource.RLIM_INFINITY else min(limits[1], used + memory)
            resource.setrlimit(resource.RLIMIT_AS, (ceiling, limits[1]))
        signal.signal(signal.SIGALRM, expire)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        return call()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if limits is not None:
            resource.setrlimit(resource.RLIMIT_AS, limits)
        for fd in [stop_write, stop_read, ready_write, ready_read]:
            if fd is not None:
                os.close(fd)
        if watcher is not None:
            try:
                status = watcher.wait(timeout=3)
            except subprocess.TimeoutExpired:
                watcher.kill()
                watcher.wait()
                raise RuntimeError("memory supervisor cleanup failed")
            if status != 0:
                raise RuntimeError("memory supervisor failed")
        signal.signal(signal.SIGALRM, previous)
        signal.setitimer(signal.ITIMER_REAL, *timer)


def run(*args, memory_limit=768 * 1024 * 1024, input=None, capture_output=False, timeout=None, check=False, **kwargs):
    if sys.platform != "darwin" or kwargs.get("preexec_fn") is None:
        return subprocess.run(*args, input=input, capture_output=capture_output, timeout=timeout, check=check, **kwargs)
    kwargs.pop("preexec_fn")
    if input is not None:
        if kwargs.get("stdin") is not None:
            raise ValueError("stdin and input cannot both be used")
        kwargs["stdin"] = subprocess.PIPE
    if capture_output:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            raise ValueError("capture_output cannot be combined with stdout or stderr")
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    started = time.monotonic()
    with subprocess.Popen(*args, **kwargs) as child:
        try:
            first = True
            while True:
                try:
                    out, err = child.communicate(input=input if first else None, timeout=0.02)
                    break
                except subprocess.TimeoutExpired:
                    first = False
                if child.poll() is None:
                    try:
                        used = resident(child.pid)
                    except RuntimeError:
                        # Darwin can withdraw process info before waitpid observes exit.
                        # Give that transition a bounded grace period; a live unobserved
                        # child still fails closed and is killed by the outer cleanup.
                        try:
                            child.wait(timeout=0.05)
                        except subprocess.TimeoutExpired:
                            raise RuntimeError("resident memory observation failed") from None
                    else:
                        if used > memory_limit:
                            raise AssertionError("child exceeded the resident memory ceiling")
                if timeout is not None and time.monotonic() - started >= timeout:
                    raise subprocess.TimeoutExpired(child.args, timeout)
        except BaseException:
            child.kill()
            child.communicate()
            raise
        if check and child.returncode:
            raise subprocess.CalledProcessError(child.returncode, child.args, output=out, stderr=err)
        return subprocess.CompletedProcess(child.args, child.returncode, out, err)


if __name__ == "__main__":
    if len(sys.argv) != 6 or sys.argv[1] != "--watch":
        raise SystemExit(2)
    raise SystemExit(watch(*(int(value) for value in sys.argv[2:])))
