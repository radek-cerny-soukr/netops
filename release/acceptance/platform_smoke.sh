#!/bin/bash
set -u
REF="$1"
DOCKER_APT_FPR="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
DOCKER_RPM_FPR="060A61C51B558A7F742B77AAC52FEB6B621E9F35"
pgp_fpr() {
  python3 -c '
import base64, hashlib, sys
lines = [l.strip() for l in sys.stdin.read().splitlines()]
start = next(i for i, l in enumerate(lines) if l.startswith("-----BEGIN PGP PUBLIC KEY BLOCK"))
body, i = [], start + 1
while lines[i]:
    i += 1
for l in lines[i + 1:]:
    if l.startswith("=") or l.startswith("-----END"):
        break
    body.append(l)
data = base64.b64decode("".join(body))
tag = data[0]
if tag & 0x40:
    first = data[1]
    if first < 192:
        length, off = first, 2
    elif first < 224:
        length, off = ((first - 192) << 8) + data[2] + 192, 3
    else:
        length, off = int.from_bytes(data[2:6], "big"), 6
else:
    kind = tag & 3
    size = {0: 1, 1: 2, 2: 4}[kind]
    length, off = int.from_bytes(data[1:1 + size], "big"), 1 + size
packet = data[off:off + length]
if packet[0] != 4:
    sys.exit("unsupported key version")
print(hashlib.sha1(b"\x99" + len(packet).to_bytes(2, "big") + packet).hexdigest().upper())
'
}
report() { printf '{"check":"%s","status":"%s","detail":"%s"}\n' "$1" "$2" "$(printf '%s' "$3" | tr -d '"\\' | tr '\n' ' ' | cut -c1-400)"; }
. /etc/os-release
report os INFO "$PRETTY_NAME $(uname -m) kernel $(uname -r)"
install_apt() {
  base="https://download.docker.com/linux/$ID"
  sudo apt-get -o DPkg::Lock::Timeout=600 update -qq >/dev/null &&
  sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq ca-certificates curl >/dev/null &&
  sudo install -m 0755 -d /etc/apt/keyrings &&
  sudo curl -fsSL "$base/gpg" -o /etc/apt/keyrings/docker.asc &&
  sudo chmod a+r /etc/apt/keyrings/docker.asc || return 1
  fpr=$(pgp_fpr < /etc/apt/keyrings/docker.asc)
  if [ "$fpr" != "$DOCKER_APT_FPR" ]; then report docker-repo-key FAIL "fingerprint $fpr"; return 1; fi
  report docker-repo-key PASS "$fpr"
  if [ "$ID" = ubuntu ]; then suite=$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}"); else suite=$(. /etc/os-release && echo "$VERSION_CODENAME"); fi
  sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOT
Types: deb
URIs: $base
Suites: $suite
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOT
  sudo apt-get -o DPkg::Lock::Timeout=600 update -qq >/dev/null &&
  sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
}
install_rpm() {
  local repo=/etc/yum.repos.d/docker-ce.repo repo_tmp repo_match
  if sudo test -L "$repo"; then
    report docker-repo-config FAIL "refusing symlink Docker repository"; return 1
  fi
  if sudo test -e "$repo"; then
    sudo test -f "$repo" || return 1
    repo_tmp=$(mktemp) || return 1
    if curl -fsSL https://download.docker.com/linux/fedora/docker-ce.repo -o "$repo_tmp" && sudo cmp -s "$repo_tmp" "$repo"; then
      repo_match=0
    else
      repo_match=1
    fi
    rm -f "$repo_tmp" || return 1
    if [ "$repo_match" != 0 ]; then
      report docker-repo-config FAIL "existing Docker repository differs or cannot be verified"; return 1
    fi
  else
    sudo dnf -y -q config-manager addrepo --from-repofile https://download.docker.com/linux/fedora/docker-ce.repo || return 1
  fi
  sudo dnf -y -q install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null || return 1
  fprs=$(curl -fsSL https://download.docker.com/linux/fedora/gpg | pgp_fpr)
  imported=$(rpm -q gpg-pubkey --qf '%{version}\n' 2>/dev/null | tr 'a-f' 'A-F')
  case "$imported" in *"${DOCKER_RPM_FPR: -8}"*) ;; *) report docker-repo-key FAIL "key ${DOCKER_RPM_FPR: -8} not imported: $(echo $imported)"; return 1 ;; esac
  if ! printf '%s\n' "$fprs" | grep -qx "$DOCKER_RPM_FPR"; then report docker-repo-key FAIL "imported keys: $(echo $fprs)"; return 1; fi
  report docker-repo-key PASS "$DOCKER_RPM_FPR"
  sudo systemctl enable --now docker >/dev/null 2>&1
  if [ -f "$(dirname "$0")/fedora-daemon.json" ]; then
    if sudo cmp -s "$(dirname "$0")/fedora-daemon.json" /etc/docker/daemon.json; then
      report docker-selinux-config INFO "unchanged, no restart: $(cat "$(dirname "$0")/fedora-daemon.json")"
    else
      sudo install -m 0644 "$(dirname "$0")/fedora-daemon.json" /etc/docker/daemon.json && sudo systemctl restart docker || return 1
      report docker-selinux-config INFO "installed, docker restarted: $(cat "$(dirname "$0")/fedora-daemon.json")"
    fi
  fi
}
wait_pkg_idle() {
  if command -v cloud-init >/dev/null 2>&1; then sudo cloud-init status --wait >/dev/null 2>&1; fi
  local i
  for i in $(seq 1 120); do
    systemctl is-active --quiet apt-daily.service apt-daily-upgrade.service dnf-makecache.service || return 0
    sleep 5
  done
  report package-manager FAIL "package jobs still active after 600 s"; return 1
}
case "$ID" in
  ubuntu|debian) wait_pkg_idle && install_apt ;;
  fedora) wait_pkg_idle && install_rpm ;;
  *) report docker-install FAIL "unsupported $ID"; exit 1 ;;
esac
rc=$?
if [ $rc -ne 0 ] || ! sudo docker version >/dev/null 2>&1; then report docker-install FAIL "rc $rc"; exit 1; fi
report docker-install PASS "$(sudo docker version --format 'Engine {{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}') storage $(sudo docker info --format '{{.Driver}}')"
if ! sudo docker pull -q "$REF" >/dev/null 2>&1; then report pull FAIL "$REF"; exit 1; fi
got=$(sudo docker image inspect --format '{{json .RepoDigests}}' "$REF")
case "$got" in *"${REF#*@}"*) report pull PASS "$REF" ;; *) report pull FAIL "repo digests $got" ;; esac
out=$(sudo docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$REF" selftest 2>&1); src=$?
if [ $src -eq 0 ] && printf '%s' "$out" | grep -q '"helper"'; then report selftest PASS "$(printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["version"], {k: v["tools"] for k, v in d["roles"].items()})' 2>/dev/null)"; else report selftest FAIL "rc $src: $out"; fi
if [ "$ID" = fedora ]; then
  mode=$(getenforce)
  cid=$(sudo docker run -d --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint python "$REF" -c 'import time; time.sleep(30)')
  sleep 2
  label=$(sudo docker inspect --format '{{.ProcessLabel}}' "$cid")
  running=$(sudo docker inspect --format '{{.State.Running}}' "$cid")
  pid=$(sudo docker inspect --format '{{.State.Pid}}' "$cid")
  plabel=""; [ "$running" = true ] && [ "${pid:-0}" != 0 ] && plabel=$(ps -o label= -p "$pid")
  sudo docker rm -f "$cid" >/dev/null
  case "$mode/$label/$plabel" in Enforcing/*container_t*/*container_t*) report selinux PASS "$mode, running pid $pid label $plabel (config $label)" ;; *) report selinux FAIL "$mode, running $running pid $pid, process label '$plabel', config label $label" ;; esac
fi
exit 0
