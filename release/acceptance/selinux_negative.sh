#!/bin/bash
set -u
BUNDLE="$1"
IMAGE="$2"
COMMIT="$3"
DIGEST="$4"
OUTPUT="$5"
start=$(date '+%m/%d/%Y %H:%M:%S')
mode=$(getenforce 2>/dev/null || echo unknown)
data=$(mktemp -d /tmp/netops-selinux.XXXXXX)
project=$(mktemp -d /tmp/netops-selinux-project.XXXXXX)
echo selinux-negative-marker > "$data/f"
chmod 755 "$data"
chmod 644 "$data/f"
cp "$BUNDLE/compose.yaml" "$project/"
cp "$BUNDLE/env.example" "$project/.env"
sed -i "s|^NETOPS_IMAGE=.*|NETOPS_IMAGE=$IMAGE|; s|^NETOPS_BIND_IP=.*|NETOPS_BIND_IP=127.0.0.1|; s|^NETOPS_PORT=.*|NETOPS_PORT=18499|; s|^NETOPS_SERVER_NAME=.*|NETOPS_SERVER_NAME=localhost|" "$project/.env"
attempt() { out=$("$@" 2>&1); echo "rc=$? $(echo "$out" | tail -1 | tr -d '"\\' | cut -c1-120)"; }
sudo docker rm -f netops-selinux-owner > /dev/null 2>&1
sudo docker run -d --name netops-selinux-owner -v "$data:/d:Z" --entrypoint sleep "$IMAGE" 600 > /dev/null
owner_label=$(sudo docker inspect -f '{{.ProcessLabel}}' netops-selinux-owner)
private_label=$(ls -Z "$data/f" | awk '{print $1}')
owner_read=$(attempt sudo docker exec netops-selinux-owner cat /d/f)
other_read=$(attempt sudo docker run --rm -v "$data:/d" --entrypoint cat "$IMAGE" /d/f)
product_read=$(cd "$project" && attempt sudo docker compose -p netops-selinux run --rm --no-deps -T -v "$data:/d" --entrypoint cat netops /d/f)
sudo docker rm -f netops-selinux-owner > /dev/null 2>&1
shared_read=$(cd "$project" && attempt sudo docker compose -p netops-selinux run --rm --no-deps -T -v "$data:/d:z" --entrypoint cat netops /d/f)
shared_label=$(ls -Z "$data/f" | awk '{print $1}')
file_mode=$(stat -c %a "$data/f")
denials=$(sudo ausearch -m AVC -ts $start 2>/dev/null | grep -c 'denied.*comm="cat"')
(cd "$project" && sudo docker compose -p netops-selinux down -v > /dev/null 2>&1)
sudo rm -rf "$data" "$project"
status=FAIL
case "$mode|$owner_read|$other_read|$product_read|$shared_read|$file_mode" in
  "Enforcing|rc=0 selinux-negative-marker|rc=1 "*"Permission denied"*"|rc=1 "*"Permission denied"*"|rc=0 selinux-negative-marker|644")
    if printf '%s' "$private_label" | grep -Eq ':s0:c[0-9]+,c[0-9]+$' && printf '%s' "$shared_label" | grep -Eq ':s0$' \
       && [ "${owner_label##*:s0:}" = "${private_label##*:s0:}" ]; then status=PASS; fi ;;
esac
python3 - "$OUTPUT" "$COMMIT" "$DIGEST" "$status" "$mode" "$owner_label" "$private_label" "$owner_read" "$other_read" "$product_read" "$shared_read" "$shared_label" "$file_mode" "$denials" <<'PY'
import json, sys
output, commit, digest, status, mode, owner_label, private_label, owner_read, other_read, product_read, shared_read, shared_label, file_mode, denials = sys.argv[1:]
detail = ("%s; owner container %s with private file label %s reads (%s); another container without relabel: %s; "
          "product service profile without relabel: %s; product service profile with shared relabel: %s, file label %s; "
          "file mode %s unchanged; %s AVC denials logged (informational, container policy may not audit them)") % (mode, owner_label, private_label, owner_read, other_read, product_read, shared_read, shared_label, file_mode, denials)
json.dump({"schema": "netops-acceptance-selinux/1", "summary": {status: 1}, "candidate_commit": commit, "candidate_image": digest,
           "checks": [{"check": "selinux-label-negative", "spec": "F31", "status": status, "detail": detail}]}, open(output, "w"), indent=1)
print(status.ljust(8), "selinux-label-negative", "F31", detail)
sys.exit(0 if status == "PASS" else 1)
PY
