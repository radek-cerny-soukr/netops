#!/bin/bash
set -euo pipefail
umask 077
BUNDLE=$(cd "$1" && pwd)
IMAGE="$2"
BENCH_COMMIT=ba0b402ea56aafbb9a56f09cc13ee629160c58b6
OUT="$BUNDLE/reports"
mkdir -p "$OUT"
test -z "$(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit)"
STATUS="$OUT/cis-command-status.tsv"
: > "$STATUS"
instance="$HOME/netops"
bench="$HOME/docker-bench-security"
created=0
compat=""
compat_inode=""
run() {
  local key="$1" rc
  shift
  if "$@"; then rc=0; else rc=$?; fi
  printf '%s\t%s\n' "$key" "$rc" >> "$STATUS"
  return "$rc"
}
compose() { sudo docker compose --project-directory "$instance" -f "$instance/compose.yaml" "$@"; }
finish() {
  local rc=$? cleanup_rc
  trap - EXIT
  if [ "$created" -eq 1 ]; then
    if run down compose down > "$OUT/down.txt" 2>&1; then :; else
      cleanup_rc=$?; if [ "$rc" -eq 0 ]; then rc=$cleanup_rc; fi
    fi
  fi
  if [ -n "$compat" ]; then
    if run compatibility-cleanup python3 - "$compat" "$compat_inode" "$OUT" <<'PY_COMPAT_CLEANUP'
import os, pathlib, stat, sys
if not __debug__: raise RuntimeError("Enabled assertions required")
p=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[3])
s=p.lstat()
assert p.parent == out and p.name.startswith(".docker-compat.")
assert str(s.st_dev)+":"+str(s.st_ino) == sys.argv[2]
assert stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700
assert {x.name for x in p.iterdir()} == {"bin"}
b=p/"bin"; s=b.lstat()
assert stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700
assert {x.name for x in b.iterdir()} == {"docker"}
f=b/"docker"; s=f.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700
f.unlink(); b.rmdir(); p.rmdir()
assert not os.path.lexists(p)
PY_COMPAT_CLEANUP
    then :; else cleanup_rc=$?; if [ "$rc" -eq 0 ]; then rc=$cleanup_rc; fi; fi
  fi
  if run ownership sudo chown -R "$(id -u):$(id -g)" "$OUT"; then :; else
    cleanup_rc=$?; if [ "$rc" -eq 0 ]; then rc=$cleanup_rc; fi
  fi
  printf '%s\n' "$rc" > "$OUT/cis-actual-exit-code.txt"
  exit "$rc"
}
trap finish EXIT
run git-prerequisite command -v git > "$OUT/git-prerequisite.txt"
run fresh-instance test ! -e "$instance"
run fresh-benchmark test ! -e "$bench"
run smoke bash "$BUNDLE/platform_smoke.sh" "$IMAGE" > "$OUT/smoke.jsonl" 2> "$OUT/smoke.err"
run smoke-selftest grep -q '"check":"selftest","status":"PASS"' "$OUT/smoke.jsonl"
run image-id sudo docker image inspect --format '{{.Id}}' "$IMAGE" > "$OUT/cis-image-id.txt"
run image-id-lines test "$(wc -l < "$OUT/cis-image-id.txt")" -eq 1
run image-id-format grep -Ex 'sha256:[0-9a-f]{64}' "$OUT/cis-image-id.txt" > /dev/null
run mkdir-instance mkdir "$instance"
created=1
run copy-profile cp "$BUNDLE/compose.yaml" "$instance/compose.yaml"
run copy-env cp "$BUNDLE/env.example" "$instance/.env"
run configure-env sed -i "s|^NETOPS_IMAGE=.*|NETOPS_IMAGE=$IMAGE|; s|^NETOPS_BIND_IP=.*|NETOPS_BIND_IP=127.0.0.1|; s|^NETOPS_PORT=.*|NETOPS_PORT=8443|; s|^NETOPS_SERVER_NAME=.*|NETOPS_SERVER_NAME=localhost|" "$instance/.env"
run init compose run --rm -T netops init --audit local --accept-local-audit > "$OUT/init.txt" 2>&1
run up compose up -d --wait --wait-timeout 120 > "$OUT/up.txt" 2>&1
run container-id compose ps -q netops > "$OUT/cis-container-id.txt"
run container-id-lines test "$(wc -l < "$OUT/cis-container-id.txt")" -eq 1
run container-id-format grep -Ex '[0-9a-f]{64}' "$OUT/cis-container-id.txt" > /dev/null
cid=$(cat "$OUT/cis-container-id.txt")
run inspect-before sudo docker inspect "$cid" > "$OUT/cis-container-before.json"
run clone git clone -q https://github.com/docker/docker-bench-security "$bench" > "$OUT/git-clone.txt" 2>&1
run checkout git -C "$bench" checkout -q --detach "$BENCH_COMMIT" > "$OUT/git-checkout.txt" 2>&1
run benchmark-head git -C "$bench" rev-parse HEAD > "$OUT/benchmark-head.txt"
run benchmark-head-lines test "$(wc -l < "$OUT/benchmark-head.txt")" -eq 1
run benchmark-pin grep -Fx "$BENCH_COMMIT" "$OUT/benchmark-head.txt"
cd "$bench"
run compatibility-real-docker sudo sh -c 'command -v docker' > "$OUT/compat-real-docker.txt"
run compatibility-sudo-path sudo sh -c 'printf "%s\n" "$PATH"' > "$OUT/compat-sudo-path.txt"
real_docker=$(cat "$OUT/compat-real-docker.txt")
benchmark_path=$(cat "$OUT/compat-sudo-path.txt")
run compatibility-sudo-path-nonempty test -n "$benchmark_path"
compat=$(mktemp -d "$OUT/.docker-compat.XXXXXXXX")
compat_inode=$(stat -c '%d:%i' "$compat")
run compatibility-bin mkdir -m700 "$compat/bin"
run compatibility-wrapper python3 - "$compat/bin/docker" "$real_docker" <<'PY_COMPAT_WRAPPER'
import json, os, pathlib, sys
if not __debug__: raise RuntimeError("Enabled assertions required")
target=pathlib.Path(sys.argv[1]); real=sys.argv[2]
assert os.path.isabs(real) and os.path.isfile(real) and os.access(real, os.X_OK)
template = r'''#!/usr/bin/python3
import os
import sys

args = sys.argv[1:]
if args == ["images"]:
    args = ["image", "ls", "--format", r"table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}"]
os.execv("/usr/bin/docker", ["/usr/bin/docker", *args])
'''
body=template.replace('"/usr/bin/docker"', json.dumps(real, ensure_ascii=True))
with target.open("x") as f:
    f.write(body)
target.chmod(0o700)
PY_COMPAT_WRAPPER
run compatibility-pin sha256sum "$compat/bin/docker" > "$OUT/compat-wrapper.sha256"
run cis-all sudo env PATH="$compat/bin:$benchmark_path" sh docker-bench-security.sh -b -l "$OUT/cis-all" > "$OUT/cis-all.txt" 2>&1
run cis-netops sudo env PATH="$compat/bin:$benchmark_path" sh docker-bench-security.sh -b -c container_images,container_runtime -i netops -l "$OUT/cis-netops" > "$OUT/cis-netops.txt" 2>&1
run inspect-after sudo docker inspect "$cid" > "$OUT/cis-container-after.json"
run ownership-before-report sudo chown -R "$(id -u):$(id -g)" "$OUT"
run report-format python3 "$BUNDLE/cis_report_shape.py" "$OUT" > "$OUT/cis-findings-summary.json"
