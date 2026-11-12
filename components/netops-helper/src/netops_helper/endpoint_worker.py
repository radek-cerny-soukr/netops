"""Private subprocess boundary for the 60-second, multi-target read budget."""
from __future__ import annotations

import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

from .auth import TargetAuth
from .locate import MAX_READS, MAX_SECONDS, MAX_TARGETS
from .normalization import IDENTITY_PROFILES


VERDICTS = ('located', 'own_interface_of_target', 'ambiguous', 'incomplete', 'not_found_in_checked_data')
# The worker holds the credentials of the explicitly enrolled targets: it gets only these variables and NETOPS_* ones.
ENVIRONMENT = ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'TZ')


def decode(targets, auth_context):
    if (not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS
            or any(not isinstance(t, str) for t in targets) or len(set(targets)) != len(targets)):
        raise ValueError(f'locate_endpoint requires 1 to {MAX_TARGETS} distinct enrolled targets')
    try:
        contexts = json.loads(auth_context)
    except (TypeError, ValueError):
        raise ValueError('invalid multi-target authentication context') from None
    if not isinstance(contexts, dict) or set(contexts) != set(targets):
        raise ValueError('authentication context does not match targets')
    auths = [TargetAuth.decode(t, contexts[t]) for t in targets]
    if any(a.ssh_platform not in IDENTITY_PROFILES | {'fortinet'} for a in auths):
        raise ValueError('locate_endpoint supports enrolled network OS targets only')
    return auths


def _terminate(process):
    # SIGTERM raises inside the worker so existing SSH finally blocks close and
    # reap their own process groups and remove ephemeral authentication files.
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass                        # killed; nothing else can be done without blocking the Helper


def command():
    """`python -I`: no working directory or user site on sys.path and no PYTHON* variables, like the askpass
    program. The package directories of the running Helper are given explicitly instead."""
    import netops
    import netops_core
    import netops_helper
    roots = list(dict.fromkeys(str(Path(module.__file__).resolve().parents[1])
                               for module in (netops_helper, netops_core, netops)))
    bootstrap = 'import sys; sys.path[:0] = %r; from netops_helper.endpoint_worker import main; main()' % (roots,)
    return [sys.executable, '-I', '-B', '-c', bootstrap]


def environment():
    return {name: value for name, value in os.environ.items() if name in ENVIRONMENT or name.startswith('NETOPS_')}


def call(targets, endpoint, auth_context, *, seconds=60):
    started = time.monotonic()
    last = {'ok': False, 'endpoint': {}, 'findings': [], 'missing': [], 'vantage': [], 'reads': 0}
    request = json.dumps({'targets': targets, 'endpoint': endpoint, 'auth_context': auth_context,
                          'deadline': started + max(0, seconds - 0.5)}).encode() + b'\n'
    def failure(reason):
        partial = reason == 'timeout' and last.get('ok') is True
        verdict = 'incomplete'
        if partial and last.get('own_interfaces'):
            verdict = 'own_interface_of_target'
        if partial and (len({i['target'] for i in last.get('own_interfaces', [])}) > 1
                        or not last.get('own_interfaces') and sum(bool(i.get('edge')) for i in last.get('findings', [])) > 1):
            verdict = 'ambiguous'
        last.update(ok=partial, verdict=verdict, error_code=reason, failed_step='worker')
        coverage = last.setdefault('coverage', {'requested_targets': targets, 'completed_targets': [],
                                                 'unfinished_targets': targets})
        coverage['complete'] = False
        last['missing'].append({'vantage': None, 'table': 'worker', 'reason': reason})
        last['elapsed_seconds'] = round(time.monotonic() - started, 3)
        return last

    try:
        process = subprocess.Popen(command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   start_new_session=True, env=environment())
    except OSError:
        return failure('worker_failed')
    buffer = b''
    final = False
    malformed = False
    try:
        process.stdin.write(request)
        process.stdin.close()
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while time.monotonic() - started < seconds:
                ready = selector.select(max(0, seconds - (time.monotonic() - started)))
                if not ready:
                    break
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                buffer += chunk
                if len(buffer) > 4_000_000:
                    break
                while b'\n' in buffer and not malformed:
                    line, buffer = buffer.split(b'\n', 1)
                    try:
                        message = json.loads(line)
                        result, is_final = message['result'], message['final']
                        if (not isinstance(result, dict) or not isinstance(is_final, bool)
                                or type(result.get('ok')) is not bool
                                or not isinstance(result.get('missing'), list)
                                or is_final and result.get('verdict') not in VERDICTS):
                            raise TypeError
                    except (ValueError, KeyError, TypeError):
                        malformed = True        # a broken worker line is a failed worker, not a crash
                        break
                    last, final = result, is_final
                if malformed:
                    break
                if final:
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass            # the finally block stops a worker that stays after its final line
                    if process.returncode not in (None, 0):
                        break
                    return last
        reason = 'timeout' if time.monotonic() - started >= seconds and not malformed else 'worker_failed'
        return failure(reason)
    except OSError:
        return failure('worker_failed')
    finally:
        if process.poll() is None:
            _terminate(process)
        process.stdout.close()


def main():
    from .engine import _locate_endpoint_run
    request = json.loads(sys.stdin.buffer.readline(4_000_001))
    auths = decode(request['targets'], request['auth_context'])
    from .tables import literal
    kind, value = literal(request['endpoint'])
    checkpoint = {'ok': False, 'endpoint': {kind: value}, 'vantage': [], 'findings': [], 'missing': [], 'reads': 0,
                  'coverage': {'complete': False, 'requested_targets': request['targets'],
                               'completed_targets': [], 'unfinished_targets': request['targets']},
                  'limits': {'targets': MAX_TARGETS, 'reads': MAX_READS, 'seconds': MAX_SECONDS}}
    def emit(result, final=False):
        nonlocal checkpoint
        checkpoint = result
        print(json.dumps({'result': result, 'final': final}, separators=(',', ':')), flush=True)
    def expired(signum, frame):
        # BaseException bypasses broad per-read error handling; unwinds the
        # transport cleanup before the worker exits. No background reads remain.
        raise SystemExit(124)
    signal.signal(signal.SIGTERM, expired)
    from .audit import AuditPersistenceError, AuditPreflightError
    try:
        result = _locate_endpoint_run(auths, request['endpoint'], emit, deadline=request.get('deadline'))
    except AuditPersistenceError as exc:
        code = 'audit_preflight_failed' if isinstance(exc, AuditPreflightError) else 'audit_post_operation_failed'
        result = {**checkpoint, 'ok': False, 'error_code': code, 'failed_step': 'audit', 'verdict': 'incomplete',
                  'findings': [], 'missing': [{'vantage': None, 'table': 'audit', 'reason': code}]}
    emit(result, True)


if __name__ == '__main__':
    main()
