"""Real-time growth measurements in a disposable process (Linux lab/Actions).

Explicit fork preserves test closures and monkeypatches on Python 3.14, whose
multiprocessing default changed. A blocked regex cannot block the test runner.
"""
import gc
import multiprocessing
import time
import traceback


def measured_growth(build, run, small=2500, *, factor=4, timeout=15):
    context = multiprocessing.get_context('fork')
    reader, writer = context.Pipe(duplex=False)

    def measure():
        reader.close()
        try:
            samples = []
            result = None
            for size in (small, small * factor):
                value = build(size)
                timings = []
                for repeat in range(3):
                    gc.disable()
                    started = time.perf_counter()
                    current = run(value)
                    timings.append(time.perf_counter() - started)
                    if size == small and repeat == 0:
                        result = current
                samples.append(min(timings))
            writer.send(('ok', result, samples))
        except BaseException:
            writer.send(('error', traceback.format_exc()))
        finally:
            writer.close()

    child = context.Process(target=measure)
    child.start()
    writer.close()
    try:
        if not reader.poll(timeout):
            raise AssertionError(f'parser subprocess exceeded {timeout}s watchdog')
        try:
            message = reader.recv()
        except EOFError as exc:
            raise AssertionError('parser subprocess exited without a result') from exc
        child.join(1)
        assert message[0] == 'ok', message[1]
        assert child.exitcode == 0, child.exitcode
        _, result, (first, second) = message
        # Four times the input: tolerate linear growth and scheduler noise,
        # but reject quadratic/exponential growth once above timer noise.
        assert second < max(first, 0.002) * 8, (first, second)
        return result
    finally:
        if child.is_alive():
            child.kill()
        child.join()
        reader.close()
