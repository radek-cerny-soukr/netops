#!/bin/bash
set -u
umask 077
BUNDLE="$1"
IMAGE="$2"
COMMIT="$3"
LABEL="$4"
DIGEST="${IMAGE#*@}"
OUT="$BUNDLE/reports"
mkdir -p "$OUT"
acceptance_rc=0
STATUS_FILE="$OUT/command-status.tsv"
: > "$STATUS_FILE" || exit 1
save_status() {
  local check_rc="$2"
  printf '%s\t%d\n' "$1" "$check_rc" >> "$STATUS_FILE" || acceptance_rc=1
  if [ "$check_rc" -ne 0 ]; then acceptance_rc=1; fi
}
bash "$BUNDLE/platform_smoke.sh" "$IMAGE" > "$OUT/smoke.jsonl" 2> "$OUT/smoke.err"
save_status smoke $?
cat "$OUT/smoke.jsonl"
if ! grep -q '"check":"selftest","status":"PASS"' "$OUT/smoke.jsonl"; then
  echo '{"check":"runtime","status":"NOT RUN","detail":"docker install, pull or selftest failed"}'
  exit 1
fi
case "$IMAGE" in
  *@*) ;;
  *)
    if ! DIGEST=$(sudo docker image inspect --format '{{.Id}}' "$IMAGE"); then
      echo '{"check":"image-binding","status":"FAIL","detail":"loaded local image identity could not be resolved"}'
      exit 1
    fi
    ;;
esac
if ! [[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo '{"check":"image-binding","status":"FAIL","detail":"expected one native sha256 image identity"}'
  exit 1
fi
printf '%s\n' "$DIGEST" > "$OUT/native-image-id.txt" || exit 1
. /etc/os-release
instance="$HOME/netops"
rm -rf "$instance" && mkdir -p "$instance"
cp "$BUNDLE/compose.yaml" "$BUNDLE/env.example" "$instance/"
cd "$instance"
cp env.example .env
sed -i "s|^NETOPS_IMAGE=.*|NETOPS_IMAGE=$IMAGE|; s|^NETOPS_BIND_IP=.*|NETOPS_BIND_IP=127.0.0.1|; s|^NETOPS_PORT=.*|NETOPS_PORT=8443|; s|^NETOPS_SERVER_NAME=.*|NETOPS_SERVER_NAME=localhost|" .env
startup_failure() {
  echo '{"check":"startup","status":"FAIL","detail":"initialization or captured-output preparation failed"}'
  sudo docker compose down > "$OUT/startup-cleanup.txt" 2>&1
  exit 1
}
if ! sudo docker compose run --rm -T netops init --audit local --accept-local-audit > "$OUT/init.txt" 2>&1; then startup_failure; fi
echo '{"check":"init","status":"PASS","detail":"initialization completed; captured output is checked separately"}'
if ! sudo docker compose up -d > "$OUT/up.txt" 2>&1; then startup_failure; fi
if ! sudo docker compose run --rm -T netops ca > netops-ca.pem 2>/dev/null; then startup_failure; fi
if ! sudo docker compose run --rm -T netops token show > token.txt 2>/dev/null; then startup_failure; fi
if ! sudo docker compose logs --no-color > "$OUT/container-after-up.txt" 2>&1; then startup_failure; fi
if ! python3 -B "$BUNDLE/token_output.py" --token-file "$instance/token.txt" --files "$OUT/init.txt" "$OUT/up.txt" "$OUT/container-after-up.txt" \
  --allow-empty-file "$OUT/container-after-up.txt" --commit "$COMMIT" --image-digest "$DIGEST" --output "$OUT/acceptance-$LABEL-token-output.json"; then startup_failure; fi
save_status token-output 0
cd "$BUNDLE"
sudo -E python3 -B blackbox.py --url https://localhost:8443/mcp --ca "$instance/netops-ca.pem" --token-file "$instance/token.txt" \
  --expect-name localhost --expect-tool helper_status --expect-tool read_query_catalog --expect-tool list_rules \
  --expect-tool audit_status --expect-tool admin_status --commit "$COMMIT" --image-digest "$DIGEST" --wait-seconds 120 \
  --output "$OUT/acceptance-$LABEL-blackbox.json" > "$OUT/blackbox.txt" 2>&1
save_status blackbox $?
tail -1 "$OUT/blackbox.txt"
sudo python3 -B redteam.py --compose-dir "$instance" --project netops --url https://localhost:8443/mcp --ca "$instance/netops-ca.pem" \
  --token-out "$instance/token.txt" --commit "$COMMIT" --image-digest "$DIGEST" --output "$OUT/acceptance-$LABEL-redteam.json" > "$OUT/redteam.txt" 2>&1
save_status redteam $?
tail -1 "$OUT/redteam.txt"
sudo python3 -B failclosed.py --compose-file "$BUNDLE/compose.yaml" --image "$IMAGE" --port 8444 --commit "$COMMIT" --image-digest "$DIGEST" \
  --output "$OUT/acceptance-$LABEL-failclosed.json" > "$OUT/failclosed.txt" 2>&1
save_status failclosed $?
tail -1 "$OUT/failclosed.txt"
sudo python3 -B syslog_delivery.py --compose-file "$BUNDLE/compose.yaml" --image "$IMAGE" --port 8446 --commit "$COMMIT" --image-digest "$DIGEST" \
  --output "$OUT/acceptance-$LABEL-syslog.json" > "$OUT/syslog.txt" 2>&1
save_status syslog $?
tail -2 "$OUT/syslog.txt"
sudo python3 -B device_read.py --compose-dir "$instance" --project netops --url https://localhost:8443/mcp --ca "$instance/netops-ca.pem" \
  --token-file "$instance/token.txt" --commit "$COMMIT" --image-digest "$DIGEST" --output "$OUT/acceptance-$LABEL-device.json" > "$OUT/device.txt" 2>&1
save_status device $?
tail -1 "$OUT/device.txt"
if [ "$ID" = fedora ]; then
  bash "$BUNDLE/selinux_negative.sh" "$BUNDLE" "$IMAGE" "$COMMIT" "$DIGEST" "$OUT/acceptance-$LABEL-selinux.json" > "$OUT/selinux.txt" 2>&1
save_status selinux $?
  tail -1 "$OUT/selinux.txt"
fi
cd "$instance" && sudo docker compose restart > /dev/null 2>&1
save_status restart $?
cd "$BUNDLE" && sudo -E python3 -B blackbox.py --url https://localhost:8443/mcp --ca "$instance/netops-ca.pem" --token-file "$instance/token.txt" \
  --expect-name localhost --expect-tool helper_status --commit "$COMMIT" --image-digest "$DIGEST" --wait-seconds 120 \
  --output "$OUT/acceptance-$LABEL-after-restart.json" > "$OUT/after-restart.txt" 2>&1
save_status after-restart $?
tail -1 "$OUT/after-restart.txt"
cd "$instance" && sudo docker compose down > /dev/null 2>&1
save_status down $?
bash "$BUNDLE/nonroot_operator.sh" "$BUNDLE" "$IMAGE" "$COMMIT" "$DIGEST" "$OUT/acceptance-$LABEL-nonroot.json" > "$OUT/nonroot.txt" 2>&1
save_status nonroot $?
tail -4 "$OUT/nonroot.txt"
sudo chown -R "$(id -u):$(id -g)" "$OUT"
save_status ownership $?
python3 -B "$BUNDLE/report_status.py" --directory "$OUT" --label "$LABEL" --os "$ID" --commit "$COMMIT" \
  --image-digest "$DIGEST" --command-status "$STATUS_FILE" --output "$OUT/platform-status.json"
status_rc=$?
[ "$acceptance_rc" = 0 ] && [ "$status_rc" = 0 ]
