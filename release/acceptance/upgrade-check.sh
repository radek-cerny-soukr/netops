#!/usr/bin/env bash
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ENV_FILE=$(realpath "${1:-$HERE/release.env}")
. "$ENV_FILE"
: "${FROM_IMAGE:?}" "${TO_IMAGE:?}" "${FROM_COMPOSE:?}" "${TO_COMPOSE:?}" "${FROM_QUICKSTART:?}" "${TO_QUICKSTART:?}"
: "${SERVER_NAME:?}" "${PORT:?}" "${WORKDIR:?}"
cd "$(dirname "$ENV_FILE")" || exit 2
FROM_COMPOSE=$(realpath "$FROM_COMPOSE") TO_COMPOSE=$(realpath "$TO_COMPOSE") || exit 2
FROM_QUICKSTART=$(realpath "$FROM_QUICKSTART") TO_QUICKSTART=$(realpath "$TO_QUICKSTART") || exit 2
WORKDIR=$(realpath -m "$WORKDIR")
BIND_IP=${BIND_IP:-127.0.0.1}
DOCKER=${DOCKER:-docker}
NONCE=${NONCE:-$(date -u +%Y%m%dt%H%M%S)-$$}
WORK=$WORKDIR/upg-$NONCE
OUT=${OUTDIR:-$WORKDIR/out-$NONCE}
P_FROM=netops-$NONCE-from
P_TO=netops-$NONCE-to
URL=https://$SERVER_NAME:$PORT/mcp
TARGET=linux-a.example.invalid

umask 077
mkdir -p "$WORK/from" "$WORK/to" "$WORK/secret" "$OUT" || exit 2
cp "$FROM_COMPOSE" "$WORK/from/compose.yaml" && cp "$TO_COMPOSE" "$WORK/to/compose.yaml" || exit 2
for side in from to; do
  image=$FROM_IMAGE; [ "$side" = to ] && image=$TO_IMAGE
  printf 'NETOPS_IMAGE=%s\nNETOPS_BIND_IP=%s\nNETOPS_PORT=%s\nNETOPS_SERVER_NAME=%s\n' \
    "$image" "$BIND_IP" "$PORT" "$SERVER_NAME" > "$WORK/$side/.env"
done

dc_from() { $DOCKER compose -f "$WORK/from/compose.yaml" -p "$P_FROM" "$@"; }
dc_to() { $DOCKER compose -f "$WORK/to/compose.yaml" -p "$P_TO" "$@"; }
image_version() { $DOCKER run --rm --network none --entrypoint netops "$1" version < /dev/null; }
quickstart_manifest() {
  awk -v q="'" 'f == 0 && index($0, "STATE_MANIFEST=" q) == 1 { f = 1; $0 = substr($0, 17) }
    f == 1 { if (substr($0, length($0)) == q) { print substr($0, 1, length($0) - 1); exit } print }' "$1"
}
step() {
  local name=$1 start=$SECONDS rc
  shift
  echo "== $name"
  "$@"
  rc=$?
  echo "rc=$rc $name $((SECONDS - start))s" >> "$WORK/steps.log"
  return $rc
}

FROM_VERSION=${FROM_VERSION:-$(image_version "$FROM_IMAGE")}
TO_VERSION=${TO_VERSION:-$(image_version "$TO_IMAGE")}
export FROM_IMAGE TO_IMAGE FROM_VERSION TO_VERSION SERVER_NAME PORT NONCE
python3 -c 'import json, os; print(json.dumps({k: os.environ[k] for k in
  ("FROM_IMAGE", "TO_IMAGE", "FROM_VERSION", "TO_VERSION", "SERVER_NAME", "PORT", "NONCE")}))' > "$WORK/params.json"

install_from() {
  dc_from run --rm -T netops init --audit local --accept-local-audit < /dev/null > "$WORK/from-init.txt" &&
  dc_from up -d --wait &&
  dc_from run --rm -T netops ca < /dev/null > "$WORK/from-ca.pem" &&
  dc_from run --rm -T netops token show < /dev/null > "$WORK/secret/token" &&
  dc_from run --rm -T netops connection < /dev/null > "$WORK/from-connection.txt"
}

populate_from() {
  python3 -c 'import secrets, sys; sys.stdout.write(secrets.token_urlsafe(24))' > "$WORK/secret/vault-secret" &&
  python3 - "$WORK/secret/vault-secret" "$TARGET" > "$WORK/secret/helper-private.json" <<'EOF' &&
import json, sys
secret, target = open(sys.argv[1]).read(), sys.argv[2]
egress = {"addresses": ["192.0.2.10"], "tcp_ports": [22], "udp_ports": [], "tcp_port_ranges": [],
          "udp_port_ranges": [], "allow_icmp": False, "allow_dns": False, "tls_server_names": []}
device = {"name": target, "platform": "linux", "address": "192.0.2.10", "port": 22, "role": "lab",
          "credential": "linux-a-ro", "host_key_fingerprint": "SHA256:" + "A" * 43, "legacy_ssh": None,
          "auditor": None, "helper": {"account_role": "read-only", "ssh_platform": "linux",
                                      "enabled_queries": ["kernel"], "egress": egress}}
print(json.dumps({"inventory": {"version": 2, "devices": [device]},
                  "vault": {"version": 2, "credentials": {"linux-a-ro": {"kind": "password", "login": "read-only", "value": secret}}}}))
EOF
  dc_from stop &&
  dc_from run -T --rm netops configure helper < "$WORK/secret/helper-private.json" &&
  dc_from up -d --wait &&
  python3 "$HERE/verify_state.py" mcp --url "$URL" --ca "$WORK/from-ca.pem" --token-file "$WORK/secret/token" \
    --target "$TARGET" --out "$WORK/from-mcp.json"
}

backup_from() {
  SOURCE_COMPOSE="$WORK/from/compose.yaml"
  SOURCE_PROJECT=$P_FROM
  BACKUP_FILE=$WORK/backup.tar
  STATE_MANIFEST=$(quickstart_manifest "$FROM_QUICKSTART")
  docker() { command $DOCKER "$@"; }
  docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" stop &&
  (
    umask 077
    set -C
    test ! -e "$BACKUP_FILE" &&
    test ! -e "$BACKUP_FILE.source-manifest.json" &&
    docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" run --rm -T --entrypoint python netops -B -c "$STATE_MANIFEST" < /dev/null > "$BACKUP_FILE.source-manifest.json" &&
    docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" run --rm -T --entrypoint tar netops -C /var/lib/netops -cpf - . < /dev/null > "$BACKUP_FILE"
  )
}

restore_to() {
  BACKUP_FILE=$WORK/backup.tar
  RESTORED_COMPOSE=$WORK/to/compose.yaml
  RESTORED_PROJECT=$P_TO
  STATE_MANIFEST=$(quickstart_manifest "$TO_QUICKSTART")
  docker() { command $DOCKER "$@"; }
  test -r "$BACKUP_FILE" &&
  test -r "$BACKUP_FILE.source-manifest.json" &&
  docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" run --rm -T --entrypoint python netops -B -c 'from pathlib import Path; assert not any(Path("/var/lib/netops").iterdir())' < /dev/null &&
  docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" run --rm -T --entrypoint tar netops -C /var/lib/netops -xpf - < "$BACKUP_FILE" &&
  (
    umask 077
    docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" run --rm -T --entrypoint python netops -B -c "$STATE_MANIFEST" < /dev/null > "$BACKUP_FILE.restored-manifest.json"
  ) &&
  cmp "$BACKUP_FILE.source-manifest.json" "$BACKUP_FILE.restored-manifest.json" &&
  docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" up -d --wait
}

verify_to() {
  dc_to ps &&
  dc_to exec -T netops netops health < /dev/null > "$WORK/to-health.txt" &&
  dc_to exec -T netops netops version < /dev/null > "$WORK/to-version.txt" &&
  dc_to run --rm -T netops audit stats < /dev/null &&
  $DOCKER inspect --format '{{.Image}}' "$(dc_to ps -q netops)" > "$WORK/to-image-id.txt" &&
  $DOCKER image inspect --format '{{.Id}}' "$TO_IMAGE" > "$WORK/to-expected-image-id.txt"
}

state_manifest() {
  local compose=$1 quickstart=$2 out=$3
  "$compose" run --rm -T --entrypoint python netops -B -c "$(quickstart_manifest "$quickstart")" < /dev/null > "$out"
}

second_start_to() {
  dc_to stop &&
  state_manifest dc_to "$TO_QUICKSTART" "$WORK/m1.json" &&
  dc_to up -d --wait &&
  python3 "$HERE/verify_state.py" mcp --url "$URL" --ca "$WORK/from-ca.pem" --token-file "$WORK/secret/token" \
    --target "$TARGET" --out "$WORK/to-mcp.json" &&
  dc_to run --rm -T netops ca < /dev/null > "$WORK/to-ca.pem" &&
  dc_to run --rm -T netops connection < /dev/null > "$WORK/to-connection.txt" &&
  dc_to logs --no-color > "$WORK/to-logs.txt" 2>&1 &&
  dc_to stop &&
  state_manifest dc_to "$TO_QUICKSTART" "$WORK/m2.json" &&
  dc_to run --rm -T --entrypoint tar netops -C /var/lib/netops -cf - gateway/config.json gateway/audit < /dev/null > "$WORK/after-gw.tar"
}

rollback_from() {
  dc_to stop &&
  state_manifest dc_from "$FROM_QUICKSTART" "$WORK/from-before-rollback-manifest.json" &&
  dc_from up -d --wait &&
  dc_from exec -T netops netops version < /dev/null > "$WORK/rollback-version.txt" &&
  dc_from exec -T netops netops health < /dev/null > "$WORK/rollback-health.txt" &&
  python3 "$HERE/verify_state.py" mcp --url "$URL" --ca "$WORK/from-ca.pem" --token-file "$WORK/secret/token" \
    --target "$TARGET" --out "$WORK/rollback-mcp.json" &&
  dc_from logs --no-color > "$WORK/from-logs.txt" 2>&1 &&
  dc_from stop
}

main() {
  step 1-install-from install_from &&
  step 2-populate-from populate_from &&
  step 3-backup-from backup_from &&
  step 4-restore-to restore_to &&
  step 5-verify-to verify_to &&
  step 5-second-start-to second_start_to &&
  step 6-rollback-from rollback_from
}

START=$SECONDS
main
step 7-report python3 "$HERE/verify_state.py" report --work "$WORK" --out "$OUT" \
  --secret "$WORK/secret/token" --secret "$WORK/secret/vault-secret"
RC=$?
echo "total $((SECONDS - START))s" >> "$WORK/steps.log"
cp "$WORK/steps.log" "$OUT/steps.log"
(cd "$OUT" && sha256sum report.json summary.txt steps.log > SHA256SUMS)
if [ "${KEEP:-0}" != 1 ]; then
  dc_from down -v --remove-orphans > /dev/null 2>&1
  dc_to down -v --remove-orphans > /dev/null 2>&1
  rm -rf "$WORK"
fi
echo "vystup: $OUT (rc $RC)"
exit $RC
