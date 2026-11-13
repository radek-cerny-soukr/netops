#!/usr/bin/env python3
"""Run the prescribed cumulative suites on a Docker lab host; retain full logs.

Build product, engine-regression and tooling-regression images first. Tooling
requires the local Docker socket for private fixture containers. Its temporary
files use an identical host/container path, so nested bind mounts are real.
Only the three release tooling suites use host networking for local fixtures.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--engine-image', required=True)
    parser.add_argument('--tooling-image', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--suite', action='append', choices=('selftest', 'unit', 'engine-core',
        'engine-helper', 'engine-auditor', 'engine-admin', 'root', 'release', 'acceptance', 'sign', 'replay'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o755)
    results = []
    started = time.perf_counter()
    common = ['docker', 'run', '--rm', '--network', 'none', '--read-only',
              '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges']
    product = common + ['--user', '51000:51000']
    engine = common + ['--memory', '2g', '--cpus', '2',
                       '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=512m,mode=1777',
                       '--tmpfs', '/pytmp:rw,nosuid,nodev,exec,size=512m,mode=1777']

    def run(name, command):
        if args.suite and name not in args.suite:
            return
        before = time.perf_counter()
        with (output / (name + '.log')).open('w') as handle:
            result = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT)
        row = {'suite': name, 'seconds': round(time.perf_counter() - before, 3),
               'rc': result.returncode, 'command': command}
        results.append(row)
        print(json.dumps(row), flush=True)
        (output / 'timings.json').write_text(json.dumps({
            'commit': args.commit, 'image': args.image, 'engine_image': args.engine_image,
            'tooling_image': args.tooling_image, 'suites': results,
            'total_seconds': round(time.perf_counter() - started, 3),
            'finished_utc': datetime.now(timezone.utc).isoformat()}, indent=2) + '\n')
        if result.returncode:
            print((output / (name + '.log')).read_text(), flush=True)

    # Exactly the candidate Actions flags: no tmpfs or writable root for selftest.
    run('selftest', product + [args.image, 'selftest'])
    run('unit', product + ['--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
                          '--entrypoint', 'python', args.image, '-B', '-m', 'unittest',
                          'discover', '-s', '/opt/netops/tests', '-v'])
    for role in ('core', 'helper', 'auditor', 'admin'):
        report = output / role
        report.mkdir(mode=0o777)
        report.chmod(0o777)
        run('engine-' + role, engine + ['--mount', f'type=bind,source={report},target=/reports',
            args.engine_image, '--role', role, '--candidate-commit', args.commit,
            '--candidate-image', args.image, '--output', '/reports/engine-report.json'])

    temporary = output / 'tooling-tmp'
    temporary.mkdir(mode=0o700)
    uid = f'{os.getuid()}:{os.getgid()}'
    tooling = ['docker', 'run', '--rm', '--read-only',
               '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=256m,mode=1777', '--user', uid,
               '--group-add', str(Path('/var/run/docker.sock').stat().st_gid),
               '--mount', f'type=bind,source={root},target={root},readonly',
               '--mount', f'type=bind,source={temporary},target={temporary}',
               '--workdir', str(root), '-e', f'TMPDIR={temporary}', '-e', 'HOME=/tmp',
               '-e', 'NETOPS_SIGN_TEST_WORKERS=2', '--entrypoint', '/testenv/bin/python']
    run('root', tooling + ['--network', 'none', args.tooling_image, '-B', '-m',
                          'unittest', 'discover', '-s', 'tests', '-v'])
    for name, directory in (('release', 'release/tests'), ('acceptance', 'release/acceptance/tests'),
                            ('sign', 'release/sign/tests')):
        # Execute each file as Actions does, avoiding module-name collisions.
        code = '''import pathlib, subprocess, sys
failed = False
for test in sorted(pathlib.Path(sys.argv[1]).glob('test_*.py')):
    print('TEST_FILE', test, flush=True)
    rc = subprocess.run([sys.executable, '-B', str(test)]).returncode
    failed |= rc != 0
sys.exit(int(failed))
'''
        run(name, tooling + ['--network', 'host', '--mount',
            'type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock',
            args.tooling_image, '-B', '-c', code, directory])
    # Existing and unified replays already run within helper. This separate
    # timing makes their contribution visible without excluding them there.
    run('replay', engine + ['--entrypoint', '/testenv/bin/python', args.engine_image,
        '-B', '-m', 'pytest', '-q', '--tb=long', '-p', 'no:cacheprovider',
        '/repo/components/netops-helper/tests/test_capture_replay.py',
        '/repo/components/netops-helper/tests/test_locate_review_replays.py',
        '/repo/components/netops-helper/tests/test_fortiswitch_review_replays.py',
        '/repo/components/netops-helper/tests/test_route_review_replays.py',
        '/repo/components/netops-helper/tests/test_locate_real_output.py',
        '/repo/components/netops-helper/tests/test_locate_acceptance_107.py',
        '/repo/components/netops-helper/tests/test_wifi_review24.py',
        '/repo/components/netops-helper/tests/test_wifi_vap_review24.py'])
    return int(any(row['rc'] != 0 for row in results))


if __name__ == '__main__':
    raise SystemExit(main())
