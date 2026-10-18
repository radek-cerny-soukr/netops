#!/bin/bash
set -u -o pipefail
BUNDLE="$1"
IMAGE="$2"
COMMIT="$3"
DIGEST="$4"
OUTPUT="$5"
SUFFIX=$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n') || SUFFIX=""
case "$SUFFIX" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) echo "no random account suffix" >&2; exit 1 ;; esac
OPERATOR="netops-op-$SUFFIX"
OTHER="netops-ot-$SUFFIX"
PROJECT="netops-nonroot-$SUFFIX"
PORT=18471
RESULTS=$(mktemp) || { echo "no temporary results file" >&2; exit 1; }
created_operator=0
created_other=0
write_failed=0
result() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS" || write_failed=1; }
account() { getent passwd "$1" > /dev/null 2>&1; case $? in 0) echo present ;; 2) echo absent ;; *) echo unknown ;; esac; }
remove_created() {
  problems=""
  if [ "$created_operator" = 1 ]; then
    sudo -iu "$OPERATOR" bash -c "cd ~/netops && docker compose -p $PROJECT down -v" > /dev/null 2>&1 || problems="$problems compose-down"
    if left=$(sudo docker ps -aq --filter "label=com.docker.compose.project=$PROJECT"); then [ -z "$left" ] || problems="$problems containers-left"; else problems="$problems container-inventory-failed"; fi
    if left=$(sudo docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT"); then [ -z "$left" ] || problems="$problems volumes-left"; else problems="$problems volume-inventory-failed"; fi
    if left=$(sudo docker network ls -q --filter "label=com.docker.compose.project=$PROJECT"); then [ -z "$left" ] || problems="$problems networks-left"; else problems="$problems network-inventory-failed"; fi
    sudo userdel -r "$OPERATOR" > /dev/null 2>&1 || problems="$problems userdel-$OPERATOR"
    [ "$(account "$OPERATOR")" = absent ] || problems="$problems $OPERATOR-not-confirmed-removed"
    created_operator=0
  fi
  if [ "$created_other" = 1 ]; then
    sudo userdel -r "$OTHER" > /dev/null 2>&1 || problems="$problems userdel-$OTHER"
    [ "$(account "$OTHER")" = absent ] || problems="$problems $OTHER-not-confirmed-removed"
    created_other=0
  fi
}
abort_cleanup() { remove_created; rm -f "$RESULTS"; }
trap abort_cleanup EXIT
report() {
  python3 - "$RESULTS" "$OUTPUT" "$COMMIT" "$DIGEST" "$1" "$write_failed" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as stream:
        rows = [line.rstrip("\n").split("\t", 2) for line in stream if line.strip()]
except OSError:
    rows = []
checks = [{"check": check, "spec": "F32", "status": status, "detail": detail} for check, status, detail in rows]
expected = sys.argv[5].split()
missing = [name for name in expected if name not in [check["check"] for check in checks]]
if missing or sys.argv[6] != "0" or len(checks) != len(expected):
    checks.append({"check": "nonroot-report-complete", "spec": "F32", "status": "FAIL",
                   "detail": "expected checks %s, missing %s, result write failed %s" % (" ".join(expected), " ".join(missing) or "none", sys.argv[6] != "0")})
summary = {}
for check in checks:
    summary[check["status"]] = summary.get(check["status"], 0) + 1
json.dump({"schema": "netops-acceptance-nonroot/1", "summary": summary, "candidate_commit": sys.argv[3], "candidate_image": sys.argv[4], "checks": checks}, open(sys.argv[2], "w"), indent=1)
for check in checks:
    print("%-8s %-30s %s" % (check["status"], check["check"], check["detail"]))
sys.exit(0 if checks and set(summary) == {"PASS"} else 1)
PY
}
SETUP=nonroot-setup
CHECKS="nonroot-operator-quickstart nonroot-operator-file-modes container-nonroot-refused other-user-denied nonroot-cleanup"
if [ "$(account "$OPERATOR")" != absent ] || [ "$(account "$OTHER")" != absent ]; then
  result nonroot-setup FAIL "account $OPERATOR or $OTHER exists or the account database is unreadable; refusing to use or remove an account this run did not create"
  report "$SETUP"; exit 1
fi
if ! existing=$(sudo docker ps -aq --filter "label=com.docker.compose.project=$PROJECT") || [ -n "$existing" ] \
   || ! existing=$(sudo docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT") || [ -n "$existing" ] \
   || ! existing=$(sudo docker network ls -q --filter "label=com.docker.compose.project=$PROJECT") || [ -n "$existing" ]; then
  result nonroot-setup FAIL "Docker project $PROJECT already has containers, volumes or networks, or the Docker inventory is unreadable; refusing to use or remove objects this run did not create"
  report "$SETUP"; exit 1
fi
sudo useradd -m -s /bin/bash -G docker "$OPERATOR" && created_operator=1
sudo useradd -m -s /bin/bash "$OTHER" && created_other=1
if [ "$created_operator" != 1 ] || [ "$created_other" != 1 ]; then
  result nonroot-setup FAIL "could not create the test accounts"
  report "$SETUP"; exit 1
fi
setup_failed() { result nonroot-setup FAIL "$1"; report "$SETUP"; exit 1; }
entry=$(getent passwd "$OPERATOR") && home=$(printf '%s' "$entry" | cut -d: -f6) && [ "${home#/}" != "$home" ] || setup_failed "home directory of $OPERATOR unreadable"
sudo install -d -o "$OPERATOR" -g "$OPERATOR" -m 0700 "$home/netops" \
  && sudo install -o "$OPERATOR" -g "$OPERATOR" -m 0600 "$BUNDLE/compose.yaml" "$BUNDLE/env.example" "$home/netops/" || setup_failed "could not install the bundle for $OPERATOR"
script=$(mktemp) || setup_failed "no temporary script file"
cat > "$script" <<'OP'
set -u -o pipefail
cd ~/netops || exit 1
umask 077
cp env.example .env && sed -i "s|^NETOPS_IMAGE=.*|NETOPS_IMAGE=$1|; s|^NETOPS_BIND_IP=.*|NETOPS_BIND_IP=127.0.0.1|; s|^NETOPS_PORT=.*|NETOPS_PORT=$2|; s|^NETOPS_SERVER_NAME=.*|NETOPS_SERVER_NAME=localhost|" .env || exit 1
C="docker compose -p $3"
step() { "$@" > step.log 2>&1; rc=$?; echo "$rc"; }
echo "init=$(step $C run --rm -T netops init --audit local --accept-local-audit)"
echo "up=$(step $C up -d --wait)"
$C run --rm -T netops ca > netops-ca.pem 2> /dev/null; echo "ca=$? $(head -1 netops-ca.pem | tr -d ' -')"
token=$($C run --rm -T netops token show 2> /dev/null) || token=""; echo "token_length=${#token}"
echo "connection=$(step $C run --rm -T netops connection)"
code=$(NETOPS_TOKEN="$token" python3 - "$2" <<'PY'
import json, os, ssl, sys, urllib.request
context = ssl.create_default_context(cafile="netops-ca.pem")
body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "nonroot", "version": "1"}}}).encode()
request = urllib.request.Request("https://localhost:%s/mcp" % sys.argv[1], data=body, headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": "Bearer " + os.environ["NETOPS_TOKEN"]})
try:
    with urllib.request.urlopen(request, context=context, timeout=30) as response:
        print(response.status)
except Exception as error:
    print(type(error).__name__)
PY
)
echo "mcp=$code"
echo "audit_tail=$(step $C run --rm -T netops audit tail)"
echo "restart=$(step $C restart)"
echo "stop=$(step $C stop)"
snapshot() {
  local value ca
  value=$($C run --rm -T netops token show 2> /dev/null) && [ ${#value} -eq 64 ] || return 1
  ca=$($C run --rm -T netops ca 2> /dev/null) && case "$ca" in "-----BEGIN CERTIFICATE-----"*) ;; *) return 1 ;; esac || return 1
  printf '%s\n%s' "$value" "$ca" | sha256sum | cut -c1-64
}
before=$(snapshot) || before=""
refused=0; total=0; leaked=""
for user in 1000:1000 51000:51000 51001:51001 51002:51002 51003:51003; do
  for command in "token show" "token rotate" "ca rotate" "audit recover" "configure helper" "configure admin" "configure auditor" "configure syslog" "admin doctor" "auditor import-snapshot"; do
    total=$((total + 1))
    echo '{}' | $C run -T --rm --no-deps --user "$user" netops $command > refusal.log 2>&1
    if [ $? -ne 0 ] && grep -q "default container user" refusal.log; then refused=$((refused + 1)); else leaked="$leaked $user:${command// /_}"; fi
  done
done
after=$(snapshot) || after=""
echo "container_nonroot_refused=$refused/$total"
echo "container_nonroot_not_refused=${leaked# }"
if [ -z "$before" ] || [ -z "$after" ]; then echo "state_unchanged=unreadable"; elif [ "$before" = "$after" ]; then echo "state_unchanged=yes"; else echo "state_unchanged=no"; fi
echo "modes=$(stat -c '%a' .env netops-ca.pem | tr '\n' ' ')"
echo "up_again=$(step $C up -d --wait)"
rm -f step.log refusal.log
echo "done=1"
OP
sudo install -o "$OPERATOR" -g "$OPERATOR" -m 0700 "$script" "$home/nonroot-operator.sh" || setup_failed "could not install the operator script"
rm -f "$script"
operator_output=$(sudo -iu "$OPERATOR" bash "$home/nonroot-operator.sh" "$IMAGE" "$PORT" "$PROJECT" 2>&1); operator_rc=$?
value() { [ "$operator_rc" = 0 ] || return 0; printf '%s\n' "$operator_output" | sed -n "s/^$1=//p" | tail -1; }
[ "$(value done)" = 1 ] && [ "$(value init)" = 0 ] && [ "$(value up)" = 0 ] && [ "$(value token_length)" = 64 ] && [ "$(value connection)" = 0 ] && [ "$(value mcp)" = 200 ] \
  && [ "$(value audit_tail)" = 0 ] && [ "$(value restart)" = 0 ] && [ "$(value stop)" = 0 ] && [ "$(value up_again)" = 0 ] \
  && case "$(value ca)" in "0 BEGINCERTIFICATE") true ;; *) false ;; esac \
  && result nonroot-operator-quickstart PASS "docker-group operator without sudo: init, up --wait, ca, token show (64), connection, MCP initialize HTTP 200 with the instance CA, audit tail, restart, stop, up" \
  || result nonroot-operator-quickstart FAIL "operator script rc $operator_rc: $(printf '%s' "$operator_output" | tr '\n' ' ' | cut -c1-300)"
[ "$(value done)" = 1 ] && [ "$(value modes)" = "600 600 " ] && result nonroot-operator-file-modes PASS ".env and exported CA created with umask 077 are 0600" || result nonroot-operator-file-modes FAIL "modes $(value modes)"
[ "$(value done)" = 1 ] && [ "$(value container_nonroot_refused)" = "50/50" ] && [ "$(value state_unchanged)" = yes ] \
  && result container-nonroot-refused PASS "token show/rotate, ca rotate, audit recover, configure helper/admin/auditor/syslog, admin doctor and auditor import-snapshot refused for UIDs 1000 and 51000-51003 with the default-user message; token and CA unchanged" \
  || result container-nonroot-refused FAIL "refused $(value container_nonroot_refused), not refused: $(value container_nonroot_not_refused), state unchanged: $(value state_unchanged)"
entry=$(getent passwd "$OTHER") && other_home=$(printf '%s' "$entry" | cut -d: -f6) && [ "${other_home#/}" != "$other_home" ] || setup_failed "home directory of $OTHER unreadable"
other_script=$(mktemp) || setup_failed "no temporary script file"
cat > "$other_script" <<'OT'
docker ps > /dev/null 2>&1 && echo docker=allowed || echo docker=denied
cat "$1" > /dev/null 2>&1 && echo env=readable || echo env=denied
python3 - "$2" <<'PY'
import ssl, sys, urllib.error, urllib.request
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
request = urllib.request.Request("https://localhost:%s/mcp" % sys.argv[1], data=b"{}", headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
try:
    urllib.request.urlopen(request, context=context, timeout=15)
    print("mcp=200")
except urllib.error.HTTPError as error:
    print("mcp=%d" % error.code)
except Exception as error:
    print("mcp=" + type(error).__name__)
PY
OT
sudo install -o "$OTHER" -g "$OTHER" -m 0700 "$other_script" "$other_home/nonroot-other.sh" || setup_failed "could not install the script for $OTHER"
rm -f "$other_script"
other=$(sudo -iu "$OTHER" bash "$other_home/nonroot-other.sh" "$home/netops/.env" "$PORT" 2>&1); other_rc=$?
[ "$other_rc" = 0 ] || other="script rc $other_rc: $other"
case "$other" in "docker=denied"*"env=denied"*"mcp=401"*) result other-user-denied PASS "local user without Docker access: docker denied, operator .env unreadable, MCP without token HTTP 401" ;;
  *) result other-user-denied FAIL "$(printf '%s' "$other" | tr '\n' ' ')" ;; esac
remove_created
[ -z "$problems" ] && result nonroot-cleanup PASS "compose project, its containers, volumes and networks and both test accounts created by this run removed" \
  || result nonroot-cleanup FAIL "cleanup incomplete:$problems"
report "$CHECKS"
