# NetOps 1.0 quickstart

This guide installs NetOps 1.0.3 on one Linux host and checks it before any MCP client or device is involved. Follow the steps in order. Each step ends with a check; continue only when it succeeds.

| Step | What you do |
|---|---|
| [1](#1-install-docker-engine) | Install Docker Engine and the Compose plugin from Docker's repository |
| [2](#2-fedora-enable-selinux-support-in-docker) | Fedora only: enable SELinux support in Docker |
| [3](#3-give-your-account-access-to-docker) | Give your account access to Docker, or set up rootless Docker |
| [4](#4-install-curl-jq-and-cosign) | Install `curl`, `jq` and cosign |
| [5](#5-download-and-verify-the-release) | Download and verify the release files |
| [6](#6-configure-env) | Configure `.env`: bind address and server name |
| [7](#7-initialize-and-start) | Initialize and start |
| [8](#8-export-the-ca-and-the-token) | Export the CA and the token |
| [9](#9-check-the-instance-without-an-mcp-client) | Check the instance without an MCP client |
| [10](#10-connect-an-mcp-client) | Connect Claude Code, Codex or another MCP client |
| [11](#11-enroll-devices) | Enroll devices |

**Supported hosts.** Linux with Docker Engine and the Compose plugin: Ubuntu, Debian or Fedora Server (SELinux enforcing) on amd64 or arm64, or Raspberry Pi OS 64-bit on arm64 ([verified platform support](verified-support.md)). The commands below are written for Debian 13, Ubuntu 24.04 and 26.04, Fedora Server 44 and Raspberry Pi OS 64-bit. Docker Desktop is not supported. macOS and Windows run only MCP clients. The release is one NetOps image for linux/amd64 and linux/arm64; it contains no AI agents. Existing 0.x installations and data are separate and are not migrated.

Commands that start with `sudo` need an account with sudo rights. A line such as `<server-name>` in angle brackets is a placeholder that you replace; every other command runs as written.

## 1. Install Docker Engine

NetOps is qualified with Docker Engine and the Compose plugin from Docker's own package repository, installed as below. The Docker packages of the distribution itself and `podman-docker` are not the qualified path; on a host that has them, remove them first as described in [Docker's installation guide](https://docs.docker.com/engine/install/).

Debian 13, Ubuntu and Raspberry Pi OS 64-bit. The block reads the distribution from `/etc/os-release`; Raspberry Pi OS 64-bit reports itself as `debian` and uses Docker's Debian repository:

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL "https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg" -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

`docker-ce` brings the container runtime package of Docker's repository as a dependency. `dpkg --print-architecture` must print `amd64` or `arm64`; a 32-bit Raspberry Pi OS (`armhf`) is not supported.

Fedora Server 44:

```sh
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager addrepo --from-repofile https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

`docker-ce` brings the container runtime package of Docker's repository as a dependency. `dnf` imports Docker's signing key during the installation; its fingerprint is `060A 61C5 1B55 8A7F 742B 77AA C52F EB6B 621E 9F35`.

On Fedora 44 the installation can print SELinux policy messages such as `libsepol.context_from_string: could not create context structure`, `invalid context system_u:object_r:systemd_coredump_var_run_t:s0` and `Failed to commit changes to booleans: Success` while the package scripts load their policy. They do not stop the installation; [step 2](#2-fedora-enable-selinux-support-in-docker) checks that Docker runs with SELinux.

Check on every host:

```sh
sudo docker version --format '{{.Server.Version}}'
sudo docker compose version
```

The first command prints the Docker Engine version and the second `Docker Compose version v...`. Both must succeed.

## 2. Fedora: enable SELinux support in Docker

Skip this step on Debian, Ubuntu and Raspberry Pi OS. For rootless Docker on Fedora, skip it as well; [step 3](#3-give-your-account-access-to-docker) configures SELinux for the rootless daemon.

Keep SELinux enforcing; `getenforce` prints `Enforcing`. Docker Engine from Docker's repository does not apply SELinux labels to containers until its daemon configuration enables them, and an enforcing host alone does not prove that it does. Enable it before NetOps runs for the first time:

```sh
if sudo test -e /etc/docker/daemon.json; then echo "daemon.json exists: add \"selinux-enabled\": true to it by hand"; else printf '{"selinux-enabled": true}\n' | sudo tee /etc/docker/daemon.json; fi
sudo systemctl restart docker
sudo docker info --format '{{json .SecurityOptions}}'
```

The last command must list `"name=selinux"`. If `/etc/docker/daemon.json` already existed, add `"selinux-enabled": true` to its JSON object without removing other settings, then run the last two commands again. Do not disable SELinux. The supplied Compose file uses a named data volume; any additional bind mounts need correct SELinux labels and Unix permissions.

## 3. Give your account access to Docker

Run every Docker command of this guide from the same account and Docker context. Choose one of the two ways.

**Docker as root (rootful).** Either work as root, or add your account to the `docker` group, which gives it root-equivalent access to the host:

```sh
sudo usermod -aG docker "$USER"
```

The group applies only to new login sessions: log out and log in again (for SSH, open a new connection). Then, without `sudo`:

```sh
id -nG
docker info --format '{{.ServerVersion}}'
```

`id -nG` must list `docker`, and `docker info` must print the Docker Engine version.

**Rootless Docker.** Docker Engine in rootless mode is supported: the daemon runs as your account, without root. The rootless daemon replaces the system daemon for that account. Install its packages and stop the system daemon, as described in [Docker's rootless documentation](https://docs.docker.com/engine/security/rootless/):

On Debian, Ubuntu and Raspberry Pi OS:

```sh
sudo apt-get install -y uidmap docker-ce-rootless-extras
sudo systemctl disable --now docker.service docker.socket
sudo rm -f /var/run/docker.sock
```

On Fedora:

```sh
sudo dnf -y install docker-ce-rootless-extras policycoreutils-python-utils
sudo systemctl disable --now docker.service docker.socket
sudo rm -f /var/run/docker.sock
```

Log in as the account that will run NetOps directly, through SSH or the console, not with `su` or `sudo -i`: the rootless daemon is a systemd user service and needs that account's own login session.

On Fedora with SELinux enforcing, prepare the Docker data of that account before the first start of its daemon, that is before `dockerd-rootless-setuptool.sh install`. As that account:

```sh
mkdir -p ~/.local/share/docker ~/.config/docker
printf '{"selinux-enabled": true}\n' > ~/.config/docker/daemon.json
```

Then label the data like the system Docker data, still as that account:

```sh
sudo semanage fcontext -a -e /var/lib/docker "$HOME/.local/share/docker"
sudo restorecon -R "$HOME/.local/share/docker"
```

The shell expands `$HOME` before `sudo` runs, so both commands label the home directory of that account. If the account has no sudo rights, root runs them with `$HOME` replaced by the account's home directory, which `getent passwd <user> | cut -d: -f6` prints.

On every host, as the account that will run NetOps:

```sh
dockerd-rootless-setuptool.sh install
systemctl --user enable docker
sudo loginctl enable-linger "$USER"
```

Without `systemctl --user enable docker` and `loginctl enable-linger` the instance does not return after a host reboot; if the account has no sudo rights, run `loginctl enable-linger <user>` as root instead of the last command. The setup tool creates and selects the Docker context `rootless`. Check:

```sh
docker context show
docker info --format '{{json .SecurityOptions}}'
```

`docker context show` prints `rootless`, and the security options list `"name=rootless"` and, on Fedora, `"name=selinux"`. On Fedora, `ls -Zd ~/.local/share/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots` must show `container_file_t` once the daemon has started. Without the label every NetOps container fails with `exec /usr/local/bin/netops-start: permission denied`; with the label applied after the first daemon start, containers crash with exit code 139. To repair such an installation, stop the daemon (`systemctl --user stop docker`), run `sudo chcon -R -t container_file_t ~/.local/share/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots` and start the daemon again (`systemctl --user start docker`).

## 4. Install curl, jq and cosign

`curl` downloads the release, `jq` reads JSON output in later checks, and cosign verifies the maintainer's signature.

On Debian, Ubuntu and Raspberry Pi OS:

```sh
sudo apt-get install -y curl jq
```

On Fedora:

```sh
sudo dnf -y install curl jq
```

Verification needs cosign 2.5 or newer. Install the official Sigstore release of the 3.x series from [github.com/sigstore/cosign/releases](https://github.com/sigstore/cosign/releases); this guide was checked with v3.1.4, and a later 3.x release is used in the same way after changing `COSIGN_VERSION`. Distribution packages of cosign, such as `cosign` in Debian 13 and Ubuntu 26.04, print `devel` instead of a version in `cosign version`; use the official release so that you know which version runs. The release file `cosign_checksums.txt` holds the SHA-256 of every cosign package; `sha256sum` must print `OK` for the downloaded package before you install it.

Debian, Ubuntu and Raspberry Pi OS:

```sh
mkdir -p ~/cosign-install && cd ~/cosign-install &&
COSIGN_VERSION=3.1.4 &&
ARCH="$(dpkg --print-architecture)" &&
curl -fLO "https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION/cosign_${COSIGN_VERSION}_$ARCH.deb" &&
curl -fLO "https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION/cosign_checksums.txt" &&
sha256sum -c --ignore-missing cosign_checksums.txt &&
sudo apt-get install -y "./cosign_${COSIGN_VERSION}_$ARCH.deb" &&
cosign version &&
cd ~
```

`apt-get` can print a note that the download is performed unsandboxed as root because user `_apt` cannot read the file; it does not affect the installation.

Fedora:

```sh
mkdir -p ~/cosign-install && cd ~/cosign-install &&
COSIGN_VERSION=3.1.4 &&
ARCH="$(uname -m)" &&
curl -fLO "https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION/cosign-$COSIGN_VERSION-1.$ARCH.rpm" &&
curl -fLO "https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION/cosign_checksums.txt" &&
sha256sum -c --ignore-missing cosign_checksums.txt &&
sudo dnf -y install "./cosign-$COSIGN_VERSION-1.$ARCH.rpm" &&
cosign version &&
cd ~
```

On a default Fedora installation `dnf` may print `Warning: skipped OpenPGP checks for 1 package from repository: @commandline`: by default dnf does not check the signature of a package installed from a local file. The `sha256sum` check above verifies the package. `sha256sum` prints the package name followed by `OK`, and `cosign version` prints `GitVersion:    v3.1.4`. The checksum shows that the package matches the file list of the cosign release. To verify the cosign release signature as well, follow the section Verifying Cosign Releases of the [Sigstore installation documentation](https://docs.sigstore.dev/cosign/system_config/installation/). You can remove `~/cosign-install` afterwards.

## 5. Download and verify the release

The block creates an empty, private instance directory `~/netops`, downloads `compose.yaml`, `env.example`, the release manifest `netops-1.0.3-manifest.json`, `netops-1.0.3-SHA256SUMS` and `netops-1.0.3-SHA256SUMS.sigstore.json` from the GitHub release into it and verifies the maintainer's signature and every downloaded file. Run every following command in `~/netops`. The block stops at the first failed command: when `~/netops` already exists, nothing is downloaded, and cosign never runs on an incomplete download:

```sh
mkdir -m 700 ~/netops && cd ~/netops &&
(
  for f in compose.yaml env.example netops-1.0.3-manifest.json netops-1.0.3-SHA256SUMS netops-1.0.3-SHA256SUMS.sigstore.json; do
    curl -fLO "https://github.com/radek-cerny-soukr/netops/releases/download/v1.0.3/$f" || exit 1
  done
) &&
cosign verify-blob --bundle netops-1.0.3-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.3-SHA256SUMS &&
sha256sum -c --ignore-missing netops-1.0.3-SHA256SUMS
```

cosign prints `Verified OK` and sha256sum prints `OK` for `compose.yaml`, `env.example` and `netops-1.0.3-manifest.json`; cosign covers the checksum file and its bundle. If a download or a check fails, do not continue: remove the new directory with `cd ~ && rm -r ~/netops` and run the block again. If `mkdir` fails because `~/netops` already exists, do not remove it, since it can hold an existing instance; check what it holds first. Skipping the check does not make the files verified. `env.example` already pins the image by the index digest recorded in the manifest; keep that digest pin.

The manifest field `vulnerability_gate` summarizes the release scan. `needs-assessment` means that the scan found no fixable High or Critical vulnerability, which would be `fail` and block the release, and that every remaining finding ships with a written assessment in `netops-1.0.3-vulnerability-assessments.json` on the same release page; `pass` means that the scan found nothing. A release is never published with `fail`.

## 6. Configure .env

Create `.env` from the verified template. `umask 077` keeps the files you create from now on in this shell private:

```sh
umask 077
cp env.example .env
```

`.env` holds four values. Keep `NETOPS_IMAGE` exactly as pinned by digest in the release `env.example`. `NETOPS_PORT` is the host port (default `8443`). `NETOPS_BIND_IP` is the host address on which NetOps listens, and `NETOPS_SERVER_NAME` the DNS name that the MCP clients use and that the certificate carries. No bind address is selected implicitly, and IP certificate names and the unedited `env.example` placeholders are refused. Choose one of the two cases.

**MCP client on the same host.** This is the simplest setup and the one to start with: NetOps listens only on the loopback address and the clients use the name `localhost`:

```sh
sed -i -e 's/^NETOPS_BIND_IP=.*/NETOPS_BIND_IP=127.0.0.1/' -e 's/^NETOPS_SERVER_NAME=.*/NETOPS_SERVER_NAME=localhost/' .env
cat .env
```

`cat .env` shows `NETOPS_BIND_IP=127.0.0.1`, `NETOPS_PORT=8443`, `NETOPS_SERVER_NAME=localhost` and the unchanged `NETOPS_IMAGE` line with its `@sha256:` digest. The MCP URL is then `https://localhost:8443/mcp`.

**MCP clients on other machines.** Edit `.env` with a text editor: set `NETOPS_BIND_IP` to the host address on the network that the clients use (`ip -brief address` lists the addresses of the host) and `NETOPS_SERVER_NAME` to a DNS name. Create a DNS record, or a hosts entry on every client, that maps that name to the bind address. The server name is fixed at init: a different name later needs a new instance, so choose it now. The instance CA permits the configured DNS subtree and excludes all IPv4/IPv6 names; this restriction is required for actual client compatibility and prevents trusting unrelated IP services.

The clients must reach `NETOPS_PORT` on the bind address. With Docker as root, Docker creates its own packet-filter rules for a published port: rules of ufw do not restrict it, and with firewalld Docker adds a policy that forwards traffic from any zone to it (see [Docker packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)); `NETOPS_BIND_IP` is then what limits exposure. With rootless Docker the port is opened by a process of your account and the host firewall applies to it; on Fedora Server, whose firewalld blocks it by default, open it with `sudo firewall-cmd --permanent --add-port=8443/tcp && sudo firewall-cmd --reload` (use your `NETOPS_PORT`). Whatever the firewall, the check in [step 9](#9-check-the-instance-without-an-mcp-client), run from a client machine, shows whether the port is reachable.

**Details.** An `init` refused because of these `.env` values, an `--audit-budget` below 16 MiB or a `--syslog-port` outside 1–65535 writes no NetOps state. An `init` refused later, at the audit choice (input ending at a prompt, local audit not accepted, a missing or invalid syslog host, an invalid port typed at the prompt), leaves empty `admin`, `auditor`, `gateway` and `helper` directories in the state volume and sets mode 0711 on its root. The `Invalid certificate DNS name` diagnostic is shared by `NETOPS_SERVER_NAME` and `--syslog-host` validation. A repeated `init` uses them normally; a restore needs an empty volume (see [Back up and restore state](#back-up-and-restore-state)). In both cases Compose has already created the project's named volume (`<project>_netops-state`) and network for the `run` command; they stay until you remove them with Docker. When Compose itself rejects the configuration before `init` runs, for example `invalid ip address` for an unedited `NETOPS_BIND_IP`, nothing is created. While `NETOPS_SERVER_NAME` differs from the name fixed at init the instance refuses to start. `NETOPS_BIND_IP` and `NETOPS_PORT` can change; apply them with `docker compose up -d`, which recreates the container (`restart` keeps the old port mapping).

Compose uses the stable project name `netops`; moving the directory does not change the state volume. For multiple instances, give each instance its own directory with its own `.env` (a distinct `NETOPS_PORT`, and its own `NETOPS_SERVER_NAME` where needed) and use a different explicit `docker compose -p <instance>` on every command. A command without `-p` or `COMPOSE_PROJECT_NAME` addresses the project `netops`, whichever directory it runs in. Commands quoted in NetOps messages, such as `docker compose logs netops` or `docker compose run --rm netops audit recover`, are written without `-p`; for an additional instance add its `-p <instance>` to them as well. Never run two instances against one state volume.

## 7. Initialize and start

`init` creates the instance CA, the token and the private state, and asks where the audit goes. NetOps records every MCP request and response in an audit before it acts; choose the target now:

- **TLS syslog receiver (recommended).** Prepare a dedicated receiver archive before init and the first start that filters RFC5424 APP-NAME exactly `netops` and preserves MSG bytes plus one LF. Keep other applications and older 1.0 full-record archives separate. Verify the actual TLS/template/storage behavior as the receiver service account, and ensure NetOps cannot change retained receiver data; see [Syslog audit receiver](#syslog-audit-receiver) and [syslog delivery](architecture-1.0.md#syslog-delivery).
- **Local audit.** NetOps keeps the audit in its state volume, in at most 256 MiB by default; you accept this explicitly because it consumes disk.

Run init, start the instance and show its state:

```sh
docker compose run --rm netops init && docker compose up -d --wait && docker compose ps
```

The first command downloads the image from `ghcr.io`; no registry login is needed. Docker Compose reports its own progress on standard error, mixed with the output of `init` in a terminal: the first `run` lists the network, the volume and the image download, each `docker compose run` may print `Container netops-netops-run-<id> Creating` and `Container netops-netops-run-<id> Created` before the output of NetOps, and `up` prints such lines for `netops-netops-1`. These lines come from Compose, not from NetOps; the outputs that this guide describes are those of NetOps. Interactive `init` asks in this order:

1. `TLS syslog receiver (recommended; leave blank to choose local audit):` — enter the DNS name of the receiver, or press Enter for local audit.
2. With a receiver: `TLS syslog port [6514]:` — press Enter for 6514 or enter the port.
3. Without a receiver: init prints the disk warning of local audit and asks `Type LOCAL to accept local audit:` — type `LOCAL` in capitals. Any other answer stops init.

`init` then prints the connection details (`MCP URL`, the `Authorization` header form and how to export the CA) and ends with `No network device is enrolled. ...`. `docker compose ps` must show the service `netops` with the status `Up ... (healthy)`.

Without a terminal, for example in a script, choose the audit explicitly: `init --audit syslog --syslog-host <host> [--syslog-port <port>]` or `init --audit local --accept-local-audit`. Ending the input at an interactive prompt (EOF) stops init with `init needs an interactive terminal`.

**Commands in scripts.** Typed by hand in a terminal, the commands of this guide run as shown. In a script, or whenever standard input is not your terminal, add `-T` to `docker compose run` and `docker compose exec` and redirect every other `docker compose` command, such as `up` and `ps`, with `< /dev/null` as well; keep intentional JSON or snapshot input redirections on commands that read those inputs. Run scripts from a file: when a shell script itself arrives through stdin, Compose run can consume its later lines even with `-T`. The check blocks from step 9 on already use this form; the blocks of steps 7 and 8 are meant to be typed in a terminal and are shown without it. In a script, step 7 with local audit is:

```sh
docker compose run --rm -T netops init --audit local --accept-local-audit < /dev/null && docker compose up -d --wait < /dev/null && docker compose ps < /dev/null
```

Both audit inputs and outputs consume disk. The default local budget is 256 MiB, rotating 16 MiB segments, with a maximum age of seven days; the budget can shorten retained history. A syslog queue does not drop old records to make room: once full, new operations are blocked. With local audit, measure usage with `netops audit stats`; on an instance initialized with syslog audit it shows only the local queue of records not yet delivered, so measure on the receiver. Size the deployment for its actual traffic. TLS delivery alone does not prove receiver persistence. Repeating init preserves CA, token and data. On an initialized instance it still checks `.env`, `--audit-budget` and `--syslog-port` as above and refuses a changed `NETOPS_SERVER_NAME`, but does not check `--syslog-host`, so an invalid value is accepted; otherwise it prints the connection details and `Already initialized; CA, token and data preserved.` and exits 0 without a warning: it does not apply `--audit`, `--accept-local-audit`, `--syslog-host`, `--syslog-port`, `--audit-budget` or `--disable-admin`. To move a local-audit instance to a syslog receiver, use `configure syslog` as described below; the audit budget and the Admin choice stay as chosen at the first init.

## 8. Export the CA and the token

Export the public instance CA to `netops-ca.pem` and read the bearer token into the environment variable `NETOPS_TOKEN` of this shell. The token is the only credential an MCP client needs; `init` and the start output never print it, and `token show` is the command that does:

```sh
docker compose run --rm netops ca > netops-ca.pem &&
NETOPS_TOKEN="$(docker compose run --rm netops token show)" &&
export NETOPS_TOKEN &&
docker compose run --rm netops connection
```

Run the complete block and check its exit status (`echo $?` prints `0`) before continuing; each command runs only after the preceding one succeeds. `connection` prints the MCP URL, for example `MCP URL: https://localhost:8443/mcp`, and the expiry of the instance CA. The token lives only in this shell: in a new shell, `cd ~/netops`, run `umask 077` and repeat the block. Never write the token into a file, a command line or a client configuration file.

In a script, the same block is:

```sh
cd ~/netops &&
umask 077 &&
docker compose run --rm -T netops ca < /dev/null > netops-ca.pem &&
NETOPS_TOKEN="$(docker compose run --rm -T netops token show < /dev/null)" &&
export NETOPS_TOKEN &&
docker compose run --rm -T netops connection < /dev/null
```

With `umask 077` on the first line of the script block, or set above in the same interactive shell, a new `netops-ca.pem` is created with mode 600; an existing file keeps its mode. It holds only the public instance CA certificate; an MCP client that runs under another local account needs read access to this file.

## 9. Check the instance without an MCP client

These checks need no AI client and no client account. In the instance directory:

```sh
docker compose exec -T netops netops health < /dev/null
docker compose exec -T netops netops version < /dev/null
```

`health` prints `ready` and `version` prints `1.0.3`. Set `NETOPS_URL` to the MCP URL printed by `connection`; for a client on the same host:

```sh
NETOPS_URL=https://localhost:8443/mcp
```

A request without the token must be refused with HTTP status 401:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' --cacert netops-ca.pem \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -X POST "$NETOPS_URL" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

It prints `401`. A request with the token must be accepted with HTTP status 200. The header is passed to curl through standard input, so the token does not appear on a command line:

```sh
printf 'Authorization: Bearer %s\n' "$NETOPS_TOKEN" |
  curl -sS -o /dev/null -w '%{http_code}\n' --cacert netops-ca.pem -H @- \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -X POST "$NETOPS_URL" -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl-check","version":"1"}}}'
```

It prints `200`. A curl error instead of a status code means that the client did not reach NetOps: a name that does not resolve, a port blocked by a firewall, or a CA file that does not match. Run the same two requests from a client machine, with `netops-ca.pem` copied there, to check the network path of a remote client.

The tool list needs no MCP session. Request it with the token and count the tools:

```sh
printf 'Authorization: Bearer %s\n' "$NETOPS_TOKEN" |
  curl -sS --cacert netops-ca.pem -H @- \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -X POST "$NETOPS_URL" -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' |
  jq '.result.tools | length'
```

It prints `26`: 13 Helper, 7 Auditor and 6 Admin tools. On an instance initialized with `init --disable-admin` it prints `20`, without the Admin tools.

Finally read the audit summary:

```sh
docker compose run --rm -T netops audit stats < /dev/null
```

It prints one JSON object. With local audit, `records` counts the stored audit records, including the `initialize` and `tools/list` requests and their responses above; with syslog audit it counts only the records not yet delivered to the receiver. `unauthenticated_rejections` summarizes refused requests without a valid token: it is `null` until the first such request has been refused, and after the 401 check above it is an object whose `counts` include `authentication_required`. Refused requests are counted, never stored.

List the audited requests with their time and method:

```sh
docker compose run --rm -T netops audit export < /dev/null |
  jq -r 'select(.direction == "request" and (.payload | type) == "object") | [.time, .payload.method] | @tsv'
```

With local audit it prints one line for `initialize` and one for `tools/list`. The filter in [First call and its audit record](#first-call-and-its-audit-record) lists only tool calls (`tools/call`).

## 10. Connect an MCP client

Each client needs three things: the MCP URL printed by `connection`, the token in the environment variable `NETOPS_TOKEN` and the CA file `netops-ca.pem`. Claude Code reads the CA from `NODE_EXTRA_CA_CERTS`, Codex from `CODEX_CA_CERTIFICATE`. Sign in to each client with its own provider account; NetOps supplies no client credentials. Other MCP clients must enable normal CA/SAN verification. Never disable TLS verification.

### Claude Code

To run Claude Code on the NetOps host, install it as described in the [official Claude Code setup](https://code.claude.com/docs/en/setup). Its native installer places `claude` in `~/.local/bin`; when the installer reports that this directory is not on `PATH`, run `export PATH="$HOME/.local/bin:$PATH"` and then `claude --version`. On a host without a browser, run `claude setup-token` on a machine with a browser and approve access there; it prints a long-lived token for a Pro, Max, Team or Enterprise plan, which you set as `CLAUDE_CODE_OAUTH_TOKEN` in the environment of the shell that starts `claude` on the host, without writing it to a file or a command line ([Claude Code authentication](https://code.claude.com/docs/en/authentication#generate-a-long-lived-token)).

From the instance directory, in the shell where `NETOPS_TOKEN` is exported ([step 8](#8-export-the-ca-and-the-token)), replace the URL with the one printed by `connection` (for a client on the same host `https://localhost:8443/mcp`):

~~~sh
export NODE_EXTRA_CA_CERTS="$PWD/netops-ca.pem"
claude mcp add-json -s user netops '{"type":"http","url":"https://<server-name>:<port>/mcp","headers":{"Authorization":"Bearer ${NETOPS_TOKEN}"}}'
claude mcp list
~~~

The configuration stores the reference `${NETOPS_TOKEN}`, not the token itself; Claude Code reads the value from the environment when it starts. `claude mcp list` exits with status 0 even when it cannot connect; read the status it prints for `netops`, which must be `✔ Connected`.

### Codex

For Codex, from the instance directory export the CA path in the environment used to start the client and configure the HTTP server as described in the [official MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli). Replace the URL with the one printed by connection; keep the token in the environment rather than the configuration file. The Codex CLI reads the TOML below from `~/.codex/config.toml`; `codex mcp list` then lists `netops` with its URL, `NETOPS_TOKEN` and `Bearer token`, and `codex mcp get netops` shows `enabled_tools: helper_status`:

~~~sh
export CODEX_CA_CERTIFICATE="$PWD/netops-ca.pem"
~~~

~~~toml
cli_auth_credentials_store = "file"

[mcp_servers.netops]
url = "https://<server-name>:<port>/mcp"
bearer_token_env_var = "NETOPS_TOKEN"
required = true
enabled_tools = ["helper_status"]

[mcp_servers.netops.tools.helper_status]
approval_mode = "approve"
~~~

`cli_auth_credentials_store = "file"` is a top-level key and must stay above the first table; it makes Codex keep its own provider sign-in, the credentials Codex uses for its model account, in `auth.json` in the Codex home directory rather than in an operating system credential store. It concerns only that sign-in: the NetOps token is a separate credential that Codex reads from `NETOPS_TOKEN` through `bearer_token_env_var`; it does not belong in `config.toml` or `auth.json`. `codex exec` runs with the approval policy `never` and cannot ask before a tool call, so `approval_mode = "approve"` allows `helper_status` without a prompt. `enabled_tools` lists the NetOps tools this configuration enables; add further tools, each with its own approval decision, when you need them. With `required = true`, `codex exec` stops with `required MCP servers failed to initialize` when it cannot reach or authenticate to NetOps, instead of continuing without its tools.

### First call and its audit record

Make the first call from the same shell, in the instance directory, with `NETOPS_TOKEN` and the client's CA variable exported as above. Both commands run without an interactive session, grant permission for `helper_status` explicitly and take no standard input:

~~~sh
claude -p 'Call the helper_status tool of the netops MCP server exactly once with no arguments. Then reply with only the word DONE.' --allowedTools mcp__netops__helper_status --model claude-haiku-4-5-20251001 < /dev/null
codex exec --strict-config --skip-git-repo-check --ephemeral --sandbox read-only --model gpt-6.1-sol 'Call the helper_status tool of the netops MCP server exactly once with no arguments. Then reply with only the word DONE.' < /dev/null
~~~

Claude Code names the tool `mcp__netops__helper_status`. Both commands name their model with `--model`, because the model decides how the client carries out the prompt. `codex exec` refuses to run outside a Git repository unless `--skip-git-repo-check` is given, appends piped standard input to the prompt, and with `--strict-config` refuses unknown fields in `config.toml` instead of ignoring them; `--ephemeral` does not persist session files, and `--sandbox read-only` selects the read-only sandbox for any shell command the model runs.

Exit status 0 and the reply `DONE` do not prove that the tool was called: a model can answer without calling it. The proof is in the audit, which records each call as a request record naming `helper_status` and a response record with the same `correlation`. List the tool calls with their time (UTC), tool name and whether a response was recorded:

```sh
docker compose run --rm -T netops audit export < /dev/null |
  jq -rs '(map(select(.direction == "response") | {(.correlation): true}) | add // {}) as $answered
    | .[] | select(.direction == "request" and (.payload | type) == "object" and .payload.method == "tools/call")
    | [.time, .payload.params.name, (if $answered[.correlation] then "response" else "no response" end)]
    | @tsv'
```

Each call of the client must appear as a line with `helper_status` and `response`. With syslog audit, delivered records leave the local queue; look for them at the receiver.

### Tools to try without a device

Each role answers without an enrolled device. To try another tool, replace `helper_status` in the prompt and in `--allowedTools` (for Codex in `enabled_tools`, with its own `approval_mode` table):

| Role | Tool | Arguments | Answer on a new instance |
|---|---|---|---|
| Helper | `helper_status` | none | The status of the Helper role, with no enrolled aliases yet |
| Helper | `read_query_catalog` | none | The read-only queries of each platform, about 119 kB |
| Auditor | `list_rules` | none | The rules of the configured catalog, by default the 25 FortiOS rules |
| Auditor | `rule_detail` | `rule_id`, an ID from `list_rules` | One rule with remediation, evidence fields and known false positives |
| Auditor | `audit_status` | none | No devices yet |
| Admin | `admin_status` | none | The error result `admin_not_configured` until Admin is configured |

Every other tool needs an enrolled device alias or a stored operation.

### Clients on other machines

A client on another machine, such as macOS or Windows, needs only the public `netops-ca.pem`, the token and a name resolution for the server name. Copy `netops-ca.pem` to the client. Give the token to the client through a channel you trust and set it as `NETOPS_TOKEN` in the environment of the shell that starts the client, without writing it to a file or a command line. Editing the hosts file needs administrator rights (`/etc/hosts` with `sudo` on macOS, `C:\Windows\System32\drivers\etc\hosts` from an elevated shell on Windows); without them use a DNS record. In Windows PowerShell 5.1 the Claude Code command above loses its inner quotes and fails with `Invalid configuration: : Invalid input`; use the stop-parsing form and avoid double quotes in `claude -p` prompts there:

~~~powershell
$env:NODE_EXTRA_CA_CERTS = "$PWD\netops-ca.pem"
claude --% mcp add-json -s user netops "{\"type\":\"http\",\"url\":\"https://<server-name>:<port>/mcp\",\"headers\":{\"Authorization\":\"Bearer ${NETOPS_TOKEN}\"}}"
claude mcp list
~~~

### Open WebUI

Open WebUI v0.12.3 (`ghcr.io/open-webui/open-webui@sha256:a537bbe1e6b428820f52ed4a029d7fff97062e24d5cf32c365fba36fd0542def`) was tested as an MCP client with the local models Laguna XS 2.1 Q4 and gpt-oss-120b MXFP4, served by llama.cpp `llama-server` with a 16,384-token context; with each model 10 of 10 calls used the correct tool and arguments, and Laguna XS once miscounted a result (26 instead of 25 rules). Add NetOps in the admin settings under Integrations, External Tool Servers, as a connection of type MCP (Streamable HTTP) with the URL `https://<server-name>:<port>/mcp` and Auth Bearer with the NetOps token as the key. Open WebUI 0.12 and later trusts the instance CA through the environment variable `AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL=/path/netops-ca.pem` (in 0.9.x the variable accepts only true or false). When Open WebUI runs in a container, the server name must resolve to the NetOps address inside it, through DNS or `--add-host <server-name>:<bind-ip>`; a NetOps instance bound to `127.0.0.1` is not reachable from inside another container, so bind it to a host address the container can reach. With all roles enabled it loads 26 tools: 13 Helper, 7 Auditor and 6 Admin. In the audit Open WebUI reports the `clientInfo` `mcp 0.1.0`, the default name of the Python MCP SDK. With a wrong token NetOps answers 401, but Open WebUI skips the server silently and the chat continues without NetOps tools; the UI shows only `Failed to connect to MCP server` and the connection check `400 Failed to create MCP client`, and the model may then invent a result. After changing the token, check the connection and look for a `tools/call` in the audit. `read_query_catalog` returns about 119 kB (about 23,000 tokens), which does not fit into a 16,384-token context; this is a limit of the client context, not a NetOps error.

## 11. Enroll devices

No device is implicitly enrolled. Start with `helper_status` and `read_query_catalog`; enrollment is an operator action. Prepare private JSON outside the source repository and protect it with mode 600. Helper input has exactly `inventory` and `vault`. Use the complete [Helper configuration example](helper-configuration.md), including its mandatory `helper` section; the generic [Core inventory](../components/netops-core/docs/inventory.md) example alone is not a Helper enrollment. Credentials follow [Core vault](../components/netops-core/docs/vault.md). Auditor accepts `tenant` and `catalog`, with an optional `inventory`/`vault` pair for collection through `netops configure auditor`; changing them preserves the finished store and restores the existing FortiOS/EXOS catalog selection. Admin input requires `config` and `vault`, with optional private `notification_topic`, following the [Admin configuration](admin-configuration.md). State and operation-audit paths are set inside the Admin's private directory; vault references point only to its private vault. Separate role credentials are intentional.

Stop the instance before changing role configuration or running offline operator workflows:

```sh
docker compose stop
docker compose run -T --rm netops configure helper < helper-private.json
docker compose run -T --rm netops configure admin < admin-private.json
docker compose up -d --wait
```

## Instance CA lifetime

Automatic server-leaf renewal does not replace the CA. The instance CA is valid for 730 days from init or its last rotation; `connection` shows its expiry date and the remaining whole days, so directly after init it prints 729 days. From 30 days before expiry `connection` and the gateway log warn, and from 14 days the healthcheck reports the instance unhealthy; without rotation the instance stops during its last seven days.

## Syslog audit receiver

Every record is sent as `netops-syslog-part/1` envelopes with its persistent record ID, zero-based part numbers, total and whole-record SHA256. Each message includes a 55-byte header and is at most 1618 bytes, within the enforced 2048-byte interoperability cap; the raw record limit remains 8 MiB including LF. The complete queued record stays until transport hand-over; an interrupted attempt can leave duplicate parts at the receiver. A successful delivery is a TLS transport result, not a receiver acknowledgement. For a receiver with a private CA use the existing stopped-instance `configure syslog < syslog-trust.json` flow; TLS verification stays enabled.

Keep an immutable dedicated NetOps MSG-only JSON-lines part archive, filtering RFC5424 APP-NAME exactly `netops`, with exact MSG bytes plus one LF, separate from other applications and older 1.0 full-record archives. Actual template/byte-preservation E2E checks on arm64 and amd64 verified default-limit rsyslog 8.2504 and 8.2512 with the gtls and the ossl driver and syslog-ng 4.12, each receiver running in a container. The [delivery format and receiver conditions](architecture-1.0.md#syslog-delivery) describe the boundary. Enlarging receiver limits to 9 MiB is not a substitute for this format. A receiver template must not prepend spaces, truncate or reserialize the MSG. The receiver must discard an incomplete frame left by a restart or a connection reset; a partial line stored before a record is complete makes the reconstruction of every record that completes only after that line fail with exit 2, and records completed earlier report `late_invalid` (exit 3); a full NetOps 1.0 message stored in the part archive by mistake has the same effect.

Store the parts with the template, filter and storage rules below. The [complete receiver configurations](architecture-1.0.md#syslog-delivery) add their unchanged one-way TLS settings.

rsyslog with the gtls driver:

~~~
template(name="netopsmsg" type="string" string="%msg%\n")
ruleset(name="netopsparts") {
  if $app-name == "netops" then {
    action(type="omfile" file="/var/log/netops-audit-parts.jsonl" template="netopsmsg" fileCreateMode="0640")
  }
}
~~~

rsyslog with the ossl driver:

~~~
template(name="netopsmsg" type="string" string="%msg%\n")
ruleset(name="netopsparts") {
  if $app-name == "netops" then {
    action(type="omfile" file="/var/log/netops-audit-parts.jsonl" template="netopsmsg" fileCreateMode="0640")
  }
}
~~~

syslog-ng:

~~~
filter f_netops { "${PROGRAM}" eq "netops"; };
destination d_netops_parts { file("/var/log/netops-audit-parts.jsonl" template("${MSG}\n") perm(0640)); };
log { source(s_tls6514); filter(f_netops); destination(d_netops_parts); };
~~~

A distribution setting that reduces repeated messages, such as `$RepeatedMsgReduction on` in the Ubuntu rsyslog configuration, can store consecutive identical retried parts only once; reconstruction does not need them, but its summary line must not be written to the part archive.

Reassemble one explicit record offline from a copy of its part archive into a new private output file. Copy the part archive to `~/netops-backup/receiver-parts.jsonl` first (create the private directory with `mkdir -p -m 700 ~/netops-backup`) and replace `<record-id>` with that record's 32-lowercase-hex ID:

~~~sh
(
  umask 077
  set -C
  docker compose run --rm -T netops audit reassemble --record-id <record-id> < "$HOME/netops-backup/receiver-parts.jsonl" > "$HOME/netops-backup/reassembled-record.json"
)
~~~

The command reads only stdin and emits the exact original record, including LF, after reading the entire archive successfully. It requires no instance state, token, vault or running service. Preserve the source archive unchanged. The first complete consistent SHA-valid selected set is frozen in receiver line order. Exact retries are idempotent; a later conflicting part or alternative set cannot replace those bytes. A unique foreign string ID is skipped before validating its remaining fields.

Exit 0 means clean output. Exit 3 means the output is the same frozen record and stderr contains compact ASCII JSONL warnings with schema `netops-syslog-reassembly-warning/1`, code `late_conflict` or `late_invalid`, and original `line_number`. Keep that diagnostic as tamper evidence and inspect the original archive; do not discard the valid output merely because later data conflicted. Before completion, invalid/unattributable rows or selected conflicts are errors. Exit 2 writes no record bytes on an argument, validation or input-read failure, including an input-read failure after warnings; a stdout write failure also ends with exit 2. Keep the diagnostic: `reassembly_validation_error line_N` identifies the original offending/completion line, `after_line_N` identifies missing/incomplete EOF, `reassembly_read_error after_line_N` counts consumed lines, and `reassembly_argument_error line_0` means an invalid explicit ID before reading. A wrong whole SHA fails immediately on completion, not at EOF. Never overwrite the original archive or normalize malformed rows. A stdout write failure can leave a partial new output file; inspect its status and preserve the archive.

## Switch from local audit to syslog

The audit target, budget (`init --audit-budget <bytes>`, default 256 MiB, at least 16 MiB) and seven-day local retention are chosen at init. `configure syslog` switches a local-audit instance to a TLS syslog receiver; earlier local segments then stay readable with `audit tail` and `audit export` but are neither forwarded nor rotated. No NetOps command removes them: the seven-day retention that ages them out runs only in local-audit mode, so after the switch they stop shrinking and their disk use sits beside, not inside, the running `--audit-budget`, which afterward enforces only the queue. Every `audit` read of that instance includes them together with the queue: `audit stats` counts the earlier segments plus the queued records, and an entry that `audit pending` lists from an earlier segment stays listed; settle it as described below. Record `audit stats` while the instance is still stopped directly after the switch, so the queue is empty: a later reading's `records` and `bytes` are the frozen archive plus whatever the queue holds then, so their difference from that first reading is the queue's size at the later reading; this holds only against that first reading of an empty queue; `mean_record_bytes` and `unauthenticated_rejections` are not additive and do not work this way. To keep these reads limited to the queue, choose syslog audit at the first init. There is no command that returns a syslog instance to local audit. Undelivered syslog records stay queued and are retried; the gateway log reports a failing receiver once and the healthcheck reports the instance unhealthy when the oldest queued record is older than five minutes.

## Day-to-day operation

To run the healthcheck by hand, use `docker compose exec netops netops health` on the running instance; it prints `ready`. The check connects to the gateway at 127.0.0.1:8443 inside the serving container and queries its role workers, so `docker compose run --rm netops health`, which starts a separate container without a gateway, cannot pass and ends with `netops: Operation failed; inspect private state and audit before retrying; operation failed without automatic retry`.

Admin is enabled by default and refuses device changes until configured. The existing Admin safeguards, explicit request IDs, limits and audit requirements remain. If an operation's result is unknown or its response audit fails, do not repeat a write automatically. Inspect the pending correlation and the actual device state first.

```sh
docker compose run --rm netops audit tail
docker compose run --rm netops audit pending
docker compose run --rm netops audit stats
```

`audit pending` lists every operation whose outcome the client may not know: requests without a recorded response, interrupted operations, responses withheld because the token changed, and Admin results `unknown` or `revert-failed`. With local audit these commands read the retained segments. On an instance initialized with syslog audit they read only the local queue of records not yet delivered (after `configure syslog`, also the earlier local segments, see above); a delivered record is removed from it, so look for unresolved correlations on the syslog receiver. While the instance is running, a command can fail when an audit file changes during the read; run it again, or stop the instance for a consistent read. Before deciding that recovery is needed, stop the instance and repeat the read.

A pending entry with the outcome `response withheld because the token changed; the operation may have completed; inspect status and the device` belongs to a request that was dispatched while the token was rotated: the client received `token_rotated` instead of the result, and the audit holds no response record for it. The entry stays in `audit pending` as long as its request record is retained; a restart does not remove it, `audit recover` only quarantines an incomplete final record, and no command marks an entry as resolved. To settle it, find the request with the same `correlation` in `audit export`, which shows its tool and arguments, then check the outcome: for an Admin tool read `admin_status` with the original `request_id` argument and inspect the actual device. The `request_id` field of `audit pending` is the JSON-RPC message ID, not that Admin argument.

Audit records are read in deterministic segment and queue order, which can differ from chronological event order if the system clock moves backward. Audit output is escaped for terminals. `audit export` writes JSONL for external processing. Audit times are in UTC. `audit` without an action (`audit show`) prints every retained record in the same form; `audit tail` prints the last 100 records, and `--lines N` changes that number (a larger N is limited to 10000 and 0 or a negative N shows no records; fewer records are shown when fewer are retained). `netops version` prints the product version, and `netops selftest` prints the version and the MCP tool names of each role as JSON (13 Helper, 7 Auditor and 6 Admin tools). Redaction is explicit; audit is parsed protocol content rather than a raw byte transcript. Device output is sensitive even after credential redaction.

The `jq` filter in [First call and its audit record](#first-call-and-its-audit-record) lists each MCP tool call with its time, tool name and whether a response with the same `correlation` was recorded.

Restart or stop the instance:

```sh
docker compose restart
docker compose stop
```

To replace the token, run `docker compose run --rm netops token rotate`, then `token show` again and update every client. The new token is accepted immediately without a restart and the previous one is refused; a response to an operation that was running during the change is withheld and listed by `audit pending`. The rotation command itself is not written to the audit.

Rotate the instance CA before it expires, with the instance stopped, then replace the CA at every MCP client:

```sh
docker compose stop
docker compose run --rm netops ca rotate
docker compose run --rm netops ca > netops-ca.pem
docker compose up -d --wait
```

Rotation issues a new CA and server key under the same server name; the token and role data are unchanged and the previous CA and server pair, including the previous CA private key, stay in a private `retired-ca-*` directory of the state volume until the operator removes them. Clients that trust only the previous CA refuse the connection. Once every client trusts the new CA, remove the previous CA from the clients' trust stores and delete the `retired-ca-*` directory while the instance is stopped:

~~~sh
docker compose stop
docker compose run --rm --user 51000:51000 --entrypoint sh netops -c 'rm -r /var/lib/netops/gateway/retired-ca-*'
docker compose up -d --wait
~~~

This removal is a plain shell command, not a NetOps operator command: `--entrypoint sh` replaces the image entrypoint, and `--user 51000:51000` runs the shell as the gateway UID that owns `/var/lib/netops/gateway` and the mode-0700 `retired-ca-*` directory created by `ca rotate`. The rule in [Operator identity](#operator-identity-and-initial-admin-choice) not to add `--user` applies to initialization and protected operator actions, which refuse a non-root container user. Read-only `netops audit` commands can run as the gateway UID that owns their files.

A client that keeps trusting the previous CA stays exposed to its key. If rotation is interrupted, the instance refuses to start because the CA and server certificate files are missing or do not match; run `ca rotate` again.

If a local audit write was interrupted, for example by power loss, the instance refuses to start and `docker compose logs netops` reports an incomplete final audit record; on a running instance the healthcheck reports it. `audit tail`, `pending`, `stats` and `export` skip the incomplete bytes, name the segment and exit with status 1 whenever they meet an incomplete or invalid record. The supplied `restart: unless-stopped` policy can leave Compose showing `Restarting`; `up --wait` then fails. Stop the instance before recovery as below:

```sh
docker compose stop
docker compose run --rm netops audit recover
docker compose up -d --wait
```

Recovery moves only the incomplete trailing bytes to a private `incomplete-*.partial` file in the audit directory and records the recovery in the audit; nothing is deleted, and nothing is changed when a complete record is invalid. Quarantine files are outside the audit budget and retention and stay until the operator removes them after review. An operation whose response was not recorded may still have completed: check `audit pending` and the actual device state before repeating any write.

NetOps keeps its state in private files and directories and does not correct a changed owner or mode of them itself; every start gives the volume root `/var/lib/netops` and `/run/netops` owner root and mode 0711 again, creates a missing role directory and gives an instance lock owned by root to the gateway user. Every start refuses a gateway configuration that cannot be read as a private file, with `Initialized private state cannot be read safely; initialize a new instance or use the matching release to inspect existing state`, an audit directory `gateway/audit` that exists but is not a directory owned by the gateway user with mode 0700, with `Unsafe audit directory ownership or permissions`, and a rejection summary `gateway/audit/rejections.json` that exists, also as a dangling symbolic link, but cannot be read or is invalid. The Auditor role, and with it the instance, refuses to start when `auditor/config.json` exists, also as a dangling symbolic link, but cannot be read; only a missing file selects the default tenant and catalog. NetOps 1.0.0 used the default tenant and catalog also for a dangling symbolic link. Operator commands refuse a state file that its owner cannot read: `ca`, `connection`, `token show` and the `audit` reads report `Private file permissions are required`, and `token rotate`, a repeated `init`, `configure`, `ca rotate`, `audit recover` and the `admin` and `auditor` commands report the message about the gateway configuration above; `connection` reports a CA file that it cannot read as missing or unreadable. [Refused first start](#refused-first-start) describes private files, who is affected and what to correct. A repeated `init` on an initialized instance does not prepare or check the state directories; every start does.

To move an existing instance to a new release, back it up and follow [Upgrade from the previous release](#upgrade-from-the-previous-release). Never use `docker compose down -v` as an update step.
## Back up and restore state

Stop the source instance before copying its complete named volume. The archive contains private CA keys, the bearer token, role credentials and device data. Keep the archive and its source manifest together in a private directory outside source checkouts, plus the verified Compose file, .env and image digest separately. The manifest contains metadata and hashes, not file contents.

First set the source instance, its Compose project and the backup file. The values below fit an instance in `~/netops` with the default project `netops`, as this guide installs it; for another instance set `SOURCE_COMPOSE` to its `compose.yaml` and `SOURCE_PROJECT` to its actual project name. A backup file is never overwritten: for a later backup choose a new name in `BACKUP_FILE`.

~~~sh
SOURCE_COMPOSE="$HOME/netops/compose.yaml"
SOURCE_PROJECT=netops
BACKUP_DIR="$HOME/netops-backup"
BACKUP_FILE="$BACKUP_DIR/netops-state.tar"
mkdir -p -m 700 "$BACKUP_DIR"
~~~

Then run the backup block in the same shell. It records numeric owners, groups, permission modes and regular-file checksums while the source is stopped, before creating the archive:

~~~sh
STATE_MANIFEST='import hashlib
import json
import stat
from pathlib import Path

base = Path("/var/lib/netops")
rows = []
for path in [base, *sorted(base.rglob("*"))]:
    info = path.lstat()
    regular = stat.S_ISREG(info.st_mode)
    assert regular or stat.S_ISDIR(info.st_mode)
    assert not regular or info.st_nlink == 1
    digest = None
    if regular:
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
    rows.append([path.relative_to(base).as_posix(), info.st_uid, info.st_gid,
                 stat.S_IMODE(info.st_mode), info.st_size if regular else None, digest])
print(json.dumps(rows, separators=(",", ":")))'
docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" stop &&
(
  umask 077
  set -C
  test ! -e "$BACKUP_FILE" &&
  test ! -e "$BACKUP_FILE.source-manifest.json" &&
  docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" run --rm -T --entrypoint python netops -B -c "$STATE_MANIFEST" < /dev/null > "$BACKUP_FILE.source-manifest.json" &&
  docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" run --rm -T --entrypoint tar netops -C /var/lib/netops -cpf - . < /dev/null > "$BACKUP_FILE"
)
~~~

The complete command must succeed before treating these files as a backup. A failed manifest or tar command can leave partial new files; do not restore them or overwrite an earlier backup. Investigate the failure and use a new backup filename for another attempt. After a routine backup, start the source instance again with `docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" up -d --wait`; during an upgrade keep it stopped.

For a restore, prepare a separate instance directory with the verified image and release files of the release you restore into (the same release for a plain restore, the new release for an upgrade), the same server name and port, and its own .env. Use a different Compose project name so Docker creates a new state volume. An `init` run in the target project before can have left a skeleton in its volume (see above); restore needs an empty target and refuses any other. If the target volume is not empty, choose another new project name instead; do not remove an existing volume to make room for a restore. Keep the original stopped if it still exists and do not run init on the target. The original volume is not needed: the comparison uses the source manifest saved with the backup. Add the project name to the `.env` of the target as `COMPOSE_PROJECT_NAME`, for example with `printf 'COMPOSE_PROJECT_NAME=netops-restored\n' >> .env` in its directory. Compose reads it from the `.env` beside the `compose.yaml` it uses, so every `docker compose` command for that directory, including the commands without `-p` in this guide and those quoted in NetOps messages, addresses the restored instance; `-p` overrides it.

Set the variables in the shell used for recovery: `BACKUP_FILE` is the backup to restore, `RESTORED_COMPOSE` the `compose.yaml` of the prepared target directory and `RESTORED_PROJECT` the project name in its `.env`. Replace `<target-directory>` with the absolute path of that directory:

~~~sh
BACKUP_FILE="$HOME/netops-backup/netops-state.tar"
RESTORED_COMPOSE="<target-directory>/compose.yaml"
RESTORED_PROJECT=netops-restored
~~~

Then run the restore block in the same shell. The repeated manifest code is the same calculation as in the backup block. Extraction requires an empty target, and every following step, including start, depends on success of the previous step:

~~~sh
STATE_MANIFEST='import hashlib
import json
import stat
from pathlib import Path

base = Path("/var/lib/netops")
rows = []
for path in [base, *sorted(base.rglob("*"))]:
    info = path.lstat()
    regular = stat.S_ISREG(info.st_mode)
    assert regular or stat.S_ISDIR(info.st_mode)
    assert not regular or info.st_nlink == 1
    digest = None
    if regular:
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
    rows.append([path.relative_to(base).as_posix(), info.st_uid, info.st_gid,
                 stat.S_IMODE(info.st_mode), info.st_size if regular else None, digest])
print(json.dumps(rows, separators=(",", ":")))'
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
~~~

A missing backup or manifest, a nonempty target, failed extraction or any metadata/checksum difference stops the chain before startup. A nonempty target stops it at the emptiness check with a Python traceback that ends in `AssertionError`; that means the target state volume is not empty. Keep the restored manifest private beside the backup.

After start, run these checks in the same shell as the restore block, with the restored project. In a new shell, first set `RESTORED_COMPOSE` and `RESTORED_PROJECT` to the same values:

~~~sh
docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" ps &&
docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" exec -T netops netops health < /dev/null &&
docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" run --rm -T netops connection < /dev/null &&
docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" run --rm -T netops audit stats < /dev/null
~~~

All commands must exit successfully; the service must be healthy and connection must show the server name and port of the source instance (in the upgrade, the MCP URL noted before the backup). Check the local history reported by audit stats, or, for syslog audit, verify the retained history at the receiver: on an instance initialized with syslog audit, audit stats then describes only the undelivered local queue; an instance switched to syslog audit after init still counts its frozen local segments in that history (see above). Use the original public CA, token and existing MCP client configuration to repeat the role reads used before the backup, including Auditor findings when present. Health alone does not verify role data. Confirm the expected role configuration and data before removing the source or backup. The [upgrade from the previous release](#upgrade-from-the-previous-release) uses this restore with the files of the new release.

## Upgrade from the previous release

NetOps 1.0.3 upgrades the state of NetOps 1.0.2, the immediately preceding release. It refuses state of any other product version or state schema; there is no upgrade that skips a release and no downgrade. An instance of NetOps 1.0.1 is upgraded to 1.0.2 first, with the [upgrade procedure of the 1.0.2 quickstart](https://github.com/radek-cerny-soukr/netops/blob/v1.0.2/docs/quickstart-1.0.md#upgrade-from-the-previous-release), and verified before the upgrade to 1.0.3; an instance of NetOps 1.0.0 is upgraded to 1.0.1 first, as that procedure describes. NetOps 1.0.3 sends syslog audit in the same format as 1.0.2: a receiver configured for 1.0.2 stays as it is. The upgrade restores a backup of the 1.0.2 instance into a new, separate 1.0.3 instance and leaves the 1.0.2 instance, its directory and its state volume unchanged for a rollback. The new instance keeps the server name and port, the CA, the token, role configuration and data, and the audit of the backup; MCP clients keep their configuration, token and CA file. The upgrade has four steps:

1. Check the 1.0.2 instance, stop it and back it up, as described in [Before the upgrade](#before-the-upgrade).
2. [Download and verify the new release](#download-and-verify-the-new-release), then prepare a clean 1.0.3 instance in a new directory, with the same server name and port and a `.env` with the 1.0.3 image, as described in [Prepare the 1.0.3 instance](#prepare-the-103-instance).
3. Restore the backup into it, as described in [Restore and start the 1.0.3 instance](#restore-and-start-the-103-instance).
4. Start it: the last command of the restore block starts the 1.0.3 instance. Then [verify the upgrade](#verify-the-upgrade).

The 1.0.2 quickstart installs a new instance in `~/netops` with the default project `netops`; its upgrade from 1.0.1 puts the instance in `~/netops-1.0.2` with the project `netops-102`. While their containers exist, also stopped ones, Docker shows the project and the directory of the `compose.yaml` of every NetOps instance on the host:

```sh
docker ps -a --filter label=com.docker.compose.service=netops --format '{{.Label "com.docker.compose.project"}} {{.Label "com.docker.compose.project.working_dir"}} {{.Status}}'
```

Each line prints a project, its directory and the container status, for example `netops /home/<user>/netops` followed by the status. A line with the project `netops-102` is a 1.0.2 instance upgraded from 1.0.1; the line with the project `netops` then belongs to the stopped 1.0.1 instance that this upgrade kept for its rollback, not to the 1.0.2 instance. Without a `netops-102` line, the 1.0.2 instance uses the project `netops` or the project name that you gave it. Its directory is `OLD_INSTANCE` below and its project is `SOURCE_PROJECT`; the `version` check in [Before the upgrade](#before-the-upgrade) must print `1.0.2`.

Run the blocks of this section in order in one shell; they use the variables that the following block sets. The blocks of [Back up and restore state](#back-up-and-restore-state) are not part of this sequence: they set `BACKUP_FILE` to another file. Its values fit a 1.0.2 instance in `~/netops` with the default project `netops`, as this guide installs it. If the 1.0.2 instance is in another directory, change `OLD_INSTANCE`; if it uses another project name, through `-p` or `COMPOSE_PROJECT_NAME`, set `SOURCE_PROJECT` to that name (an instance upgraded from 1.0.1 by the 1.0.2 quickstart is in `~/netops-1.0.2` and uses `netops-102`). The 1.0.3 instance gets the new project `netops-103` in the new directory `~/netops-1.0.3`; see [Explicit project names](#explicit-project-names). You may change these values too: `NEW_RELEASE` and `NEW_INSTANCE` to absolute paths of directories that do not exist yet, `BACKUP_DIR` to another absolute path, and `RESTORED_PROJECT` to another valid Compose project name that no existing project uses, because the restore needs an empty volume. The following blocks use only these variables; where this section names `~/netops-1.0.3-release`, `~/netops-1.0.3` or `~/netops-backup`, or says that a command prints `netops-103`, read your value instead. `umask 077` keeps the files that the following blocks create private, including `netops-ca.pem` in [Verify the upgrade](#verify-the-upgrade). In a new shell, run this block again before you continue:

```sh
umask 077
OLD_INSTANCE="$HOME/netops"
SOURCE_COMPOSE="$OLD_INSTANCE/compose.yaml"
SOURCE_PROJECT=netops
NEW_RELEASE="$HOME/netops-1.0.3-release"
NEW_INSTANCE="$HOME/netops-1.0.3"
RESTORED_COMPOSE="$NEW_INSTANCE/compose.yaml"
RESTORED_PROJECT=netops-103
BACKUP_DIR="$HOME/netops-backup"
BACKUP_FILE="$BACKUP_DIR/netops-1.0.2-state.tar"
mkdir -p -m 700 "$BACKUP_DIR"
```

### Before the upgrade

First check that the 1.0.2 instance runs NetOps 1.0.2 and is healthy:

```sh
docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" ps
docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" exec -T netops netops version < /dev/null
docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" exec -T netops netops health < /dev/null
docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" run --rm -T netops connection < /dev/null
docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" run --rm -T netops audit pending < /dev/null
```

`version` prints `1.0.2` and `health` prints `ready`. If the instance reports an incomplete final audit record, run `audit recover` as described in [Day-to-day operation](#day-to-day-operation) with the previous release before the upgrade. Note the MCP URL that `connection` prints: the verification of the new instance compares it. Note the entries that `audit pending` lists (NetOps prints nothing when there are none, Compose may print `Container ... Creating` and `Container ... Created` lines on standard error, see step 7); the upgrade keeps every entry. Before it converts the state, the first start of the new release makes the checks listed in [Refused first start](#refused-first-start).

Back up the instance: run the backup block of [Back up and restore state](#back-up-and-restore-state), the block that starts with `STATE_MANIFEST=`, unchanged in this shell. It uses `SOURCE_COMPOSE`, `SOURCE_PROJECT` and `BACKUP_FILE` from the block at the start of the upgrade; do not run the block before it, which sets the values of a routine backup. The backup block stops the instance. Keep the 1.0.2 instance directory with its `compose.yaml` and `.env` and its state volume unchanged, do not start the 1.0.2 instance again and do not remove it until the upgraded instance is verified: it is the rollback. Keep the backup as well.

### Syslog receiver

NetOps 1.0.3 does not change the syslog audit format or the receiver requirements of 1.0.2. Keep the receiver, its configuration and its part archive unchanged. Do not empty the NetOps queue: the backup holds it, and 1.0.3 sends the retained records in the same part format.

### Download and verify the new release

The block creates the new, empty directory `~/netops-1.0.3-release` (`NEW_RELEASE`), downloads `compose.yaml`, `env.example`, `netops-1.0.3-manifest.json`, `netops-1.0.3-SHA256SUMS` and `netops-1.0.3-SHA256SUMS.sigstore.json` from the 1.0.3 GitHub release into it, not into the instance directory, and verifies them there in the same way as for a new installation. It stops at the first failed command, also when the directory already exists:

```sh
mkdir -m 700 "$NEW_RELEASE" && cd "$NEW_RELEASE" &&
(
  for f in compose.yaml env.example netops-1.0.3-manifest.json netops-1.0.3-SHA256SUMS netops-1.0.3-SHA256SUMS.sigstore.json; do
    curl -fLO "https://github.com/radek-cerny-soukr/netops/releases/download/v1.0.3/$f" || exit 1
  done
) &&
cosign verify-blob --bundle netops-1.0.3-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.3-SHA256SUMS &&
sha256sum -c --ignore-missing netops-1.0.3-SHA256SUMS
```

All commands must succeed: cosign prints `Verified OK` and sha256sum prints `OK` for `compose.yaml`, `env.example` and `netops-1.0.3-manifest.json`.

### Prepare the 1.0.3 instance

The block creates the new, empty instance directory `~/netops-1.0.3` (`NEW_INSTANCE`), copies `compose.yaml` and `env.example` from the verified release directory into it and writes its `.env`: `NETOPS_IMAGE` exactly as pinned in the verified 1.0.3 `env.example`, which pins the index digest recorded in `netops-1.0.3-manifest.json`, the lines `NETOPS_BIND_IP`, `NETOPS_PORT` and `NETOPS_SERVER_NAME` of the `.env` of the 1.0.2 instance, and `COMPOSE_PROJECT_NAME` with the project of the new instance. It only reads the files of the 1.0.2 instance and stops at the first failed command, also when the directory already exists:

```sh
mkdir -m 700 "$NEW_INSTANCE" && cd "$NEW_INSTANCE" &&
cp "$NEW_RELEASE/compose.yaml" "$NEW_RELEASE/env.example" . &&
umask 077 &&
grep '^NETOPS_IMAGE=' env.example > .env &&
grep -E '^NETOPS_(BIND_IP|PORT|SERVER_NAME)=' "$OLD_INSTANCE/.env" >> .env &&
printf 'COMPOSE_PROJECT_NAME=%s\n' "$RESTORED_PROJECT" >> .env &&
cat .env
```

`cat .env` prints five lines: the 1.0.3 image, the bind address, port and server name of the 1.0.2 instance and `COMPOSE_PROJECT_NAME=netops-103`. Check the image pin and the project name of the new directory:

```sh
grep '^NETOPS_IMAGE=' "$NEW_RELEASE/env.example" .env
docker compose config --format json | jq -r .name
```

The two image lines are identical apart from the file name in front of them, and the second command prints `netops-103`. If it fails with `Set NETOPS_BIND_IP`, `Set NETOPS_PORT` or `Set NETOPS_SERVER_NAME`, the `.env` of the 1.0.2 instance lacks that line; add it to the new `.env` with the value that the 1.0.2 instance uses.

Do not run `init` in the new instance.

### Restore and start the 1.0.3 instance

Restore the backup: run the restore block of [Back up and restore state](#back-up-and-restore-state), the block that starts with `STATE_MANIFEST=` and ends with `up -d --wait`, unchanged in this shell, then the check block that follows it. They use `BACKUP_FILE`, `RESTORED_COMPOSE` and `RESTORED_PROJECT` from the block at the start of the upgrade; do not run the block before the restore block, which sets the values of a plain restore. The restore block starts the instance as its last command, after the restored state matches the manifest of the backup.

Do not run `init` and do not run `docker compose down -v` at any point of the upgrade. The first start of the new release converts the restored state: it makes the checks in [Refused first start](#refused-first-start), the later ones under the instance lock after it reads the gateway configuration again, and then replaces only its recorded product version, `1.0.2`, with `1.0.3`. Every other setting, the CA, the token, role data and the existing audit records stay as they are, and later starts do not change the configuration again. A process of the new release started while another process still runs on the same state, for example with `docker compose run` or `docker run`, is refused with `An existing instance is using this state; stop it before starting or upgrading` and changes nothing.

Until this first start, the restored state still belongs to 1.0.2. Operator commands of the new release that change state, including `init`, `token rotate`, `configure`, `ca rotate` and `audit recover`, refuse it with `State belongs to NetOps 1.0.2; start NetOps 1.0.3 to upgrade it before running this command. Do not reinitialize existing state` and change nothing; `connection`, `ca`, `token show` and the `audit` reads keep working. Run the start that this message asks for in the 1.0.3 instance directory, where `.env` names the 1.0.3 project, for example `cd "$NEW_INSTANCE" && docker compose up -d --wait`. An interrupted procedure can be completed by repeating its remaining steps.

### Verify the upgrade

Run these commands in the directory of the 1.0.3 instance. They need no `-p`: its `.env` names the project `netops-103`, and every later command of this guide in that directory addresses the 1.0.3 instance in the same way:

```sh
cd "$NEW_INSTANCE"
docker compose exec -T netops netops version < /dev/null
docker compose exec -T netops netops health < /dev/null
docker compose run --rm -T netops connection < /dev/null
docker compose run --rm -T netops audit tail < /dev/null
docker compose run --rm -T netops audit pending < /dev/null
docker compose run --rm -T netops ca < /dev/null > netops-ca.pem
```

`version` prints `1.0.3`, `health` prints `ready` and `connection` prints the same MCP URL as the `connection` of the 1.0.2 instance that you noted before the backup. The hint `(add -p <instance> before run for an additional instance)` that `connection` prints does not apply in this directory: its `.env` names the project, so the commands need no `-p`. The upgrade keeps the instance CA, and the last command exports it into the 1.0.3 directory; point MCP clients that read `netops-ca.pem` from the old directory, for example through `NODE_EXTRA_CA_CERTS`, to `$NEW_INSTANCE/netops-ca.pem` before you remove the old directory. The `instance_start` audit record of the converting start names both versions as `"upgrade": {"from": "1.0.2", "to": "1.0.3"}`; later starts have no `upgrade` field. With local audit, list the `instance_start` records with their time and content:

```sh
docker compose run --rm -T netops audit export < /dev/null | jq -c 'select(.direction == "instance_start") | {time, payload}'
```

The line of the converting start contains `"upgrade":{"from":"1.0.2","to":"1.0.3"}`; the lines before it are earlier starts that the audit still retains. For a 1.0.2 instance upgraded from 1.0.1 they include the starts of the 1.0.1 instance and the converting start of that upgrade with its own `"upgrade":{"from":"1.0.1","to":"1.0.2"}`; retention and the audit budget can have removed older lines. With syslog audit, `audit export` holds only the records not yet delivered (and, after a switch from local audit, the earlier local segments), so the line of the converting start is usually not there: look for the `instance_start` record with the `upgrade` field in the archive of the receiver instead.

The converting start writes this record only after every role is ready. If it stops before it writes the record, for example because a role refused to start (see [Refused first start](#refused-first-start)) or after an interruption, no audit record has the `upgrade` field: later starts do not convert again. No audit record then names the upgrade or its time. Only indirect evidence remains that the instance changed release: the last `instance_start` or `instance_stop` record before the upgrade names `"version": "1.0.2"`, and the next `instance_start` record names `"version": "1.0.3"`. Look for these records in audit history that you kept: the backup from [Before the upgrade](#before-the-upgrade), an `audit export` or, with syslog audit, the archive of the receiver. `audit tail` shows only the last 100 records by default, and local audit removes old segments after the retention period and when the audit budget is full, so the record from before the upgrade can be missing. The syslog header carries no host name, so at a receiver that several instances share the header does not show which instance the records belong to. Without such kept history the audit cannot show the change. After a first start that was not interrupted and that no role refused, a missing `upgrade` field is a defect; report it. With local audit `audit pending` still lists the entries from before the upgrade; with syslog audit an entry leaves the local queue once it is delivered, so look for it at the receiver. Then make one call with each MCP client without changing its configuration, for example the first `helper_status` call above, and find its request and response: with local audit in `audit tail` or `audit export`, with syslog audit at the receiver.

### Explicit project names

The 1.0.2 instance keeps its project: `netops`, or the name it uses with `-p` or `COMPOSE_PROJECT_NAME`; it is `SOURCE_PROJECT` of the backup. The 1.0.3 instance uses the new project `netops-103`, because the restore needs an empty volume, and its `.env` names it as `COMPOSE_PROJECT_NAME`. Compose reads that line from the `.env` beside the `compose.yaml` it uses, so every `docker compose` command for the 1.0.3 instance directory, also without `-p` and also the commands quoted in NetOps messages, addresses the 1.0.3 instance and its volume; `-p` overrides it. A command for a directory whose `.env` names no project, such as the 1.0.2 instance directory `~/netops` of this guide, addresses the project `netops` and its volume. The directory `~/netops-1.0.2` of a 1.0.2 instance upgraded from 1.0.1 names `netops-102` in its `.env` and addresses that project; in that case the project `netops` is the stopped 1.0.1 instance. Do not run `init` in a project with an empty volume.

### Several operators of one instance

The default Compose project `netops` is shared by every directory and every user on the host. A previous `compose.yaml` and `.env` in another directory or account still address the project `netops`: the 1.0.2 instance or, for a 1.0.2 instance upgraded from 1.0.1 (project `netops-102`), the stopped 1.0.1 instance. `docker compose` there can start that instance again on its unchanged state and the same port, and its `token rotate` changes only the token of that state. A `compose.yaml` and `.env` copied from `~/netops-1.0.2` address the project `netops-102` of the 1.0.2 instance in the same way. All operators of one instance switch to the 1.0.3 instance directory, whose `.env` names its project, and coordinate the downtime. Keep the 1.0.2 instance stopped while 1.0.3 runs. An independent instance uses its own explicit `-p` project and its own port.

### Refused first start

Before the first start of the new release converts the state, it checks the state in the order of the list below and stops at the first check that fails. A refused first start does not convert the state: the gateway configuration still records `1.0.2`, and `docker compose logs netops` reports the reason as `netops: <reason>; operation failed without automatic retry`. As for an incomplete audit record, the supplied restart policy can leave Compose showing `Restarting`, and `up --wait` then fails. The first start refuses:

- a gateway configuration `gateway/config.json` that is missing: `NetOps is not initialized; run docker compose run --rm netops init first`; that cannot be read as a private file of the gateway user or is not valid JSON or holds a duplicate key, NaN or Infinity: `Initialized private state cannot be read safely; initialize a new instance or use the matching release to inspect existing state`; or that records another state schema or a product version other than `1.0.2` and `1.0.3`: `Unsupported state schema; use the matching NetOps release and its verified recovery procedure` or `State belongs to another product version; automatic upgrade or downgrade is refused. Use the verified release procedure`. A container that runs as a user other than root and the gateway user, for example with a `--user` override, cannot read an existing gateway configuration and is refused here with the second message;
- what every start of NetOps 1.0 checks before it uses the state: a container that does not run as root but can read the gateway configuration, for example with `--user 51000`: `Initialization and the short start bootstrap require the declared container user and capabilities`; a state path `/var/lib/netops` that is a symbolic link to a directory: `State must be a real directory`; data in it other than the role directories `gateway`, `helper`, `auditor` and `admin`: `State contains data outside the NetOps 1.x layout; 0.x volumes are not migrated or modified`; a runtime directory `/run/netops` that is missing: `Operation failed; inspect private state and audit before retrying`, or that is not a real directory: `State and runtime must be real directories`; a role directory in `/var/lib/netops` that is not a directory owned by its role user with mode 0700, or in `/run/netops` with mode 0755: `Unsafe state directory ownership or permissions`. Before it checks the role directories, the start gives `/var/lib/netops` and `/run/netops` owner root and mode 0711, and it creates a missing role directory;
- an instance lock `gateway/instance.lock` that is not a single regular file, is owned by a user other than the gateway user or root, or has permissions for group or others, with the messages for files below; a missing lock is created and a lock owned by root is given to the gateway user. A lock that another process of the same state holds: `An existing instance is using this state; stop it before starting or upgrading`. Under the lock the start reads the gateway configuration again, with the messages of the first item;
- audit limits in the gateway configuration outside the supported range: `Invalid audit disk budget or retention`;
- an audit directory `gateway/audit` that exists but is not a directory owned by the gateway user with mode 0700, for example a directory with mode 0750 or 0755, or a symbolic link: `Unsafe audit directory ownership or permissions`;
- a rejection summary `gateway/audit/rejections.json` that exists, also as a dangling symbolic link, but is not a private file of the gateway user, is larger than 4096 bytes, is not valid JSON or is not a JSON object whose `counts` object holds `authentication_required` and `https_required`, with the messages for files and content below; and a rejection summary with a count that is not an integer from 0 to 9223372036854775807: `Invalid rejection summary`;
- with local audit, an audit segment `gateway/audit/*.jsonl` that is not a private file of the gateway user, with the messages for files below, or that ends with an incomplete final audit record: `Incomplete final audit record` followed by the advice to run `audit recover`;
- a `NETOPS_SERVER_NAME` whose IDNA form, compared without letter case, differs from that of the name the instance was initialized with (so neither a difference only in letter case nor the `xn--` form of the same name is refused, and names that the IDNA codec of Python maps to the same form, such as `ß` and `ss`, count as the same): `NETOPS_SERVER_NAME is <new name> but the instance CA and certificate are bound to <name>; restore the previous value: the server name is fixed at init and a different name needs a new instance`; a value that the IDNA codec of Python cannot encode is refused with the text of that error instead;
- CA and server certificate files `gateway/ca.pem`, `gateway/ca.key`, `gateway/server.pem` and `gateway/server.key` that are missing, are not private files of the gateway user, cannot be read or do not match: `Instance CA or server certificate files are missing or do not match, for example after an interrupted CA rotation` followed by the advice to run `ca rotate`; and, when the server certificate expires within 2 days, a CA that expires within 7 days: `Instance CA expires within 7 days and cannot renew the server certificate` followed by the same advice;
- an Auditor configuration `auditor/config.json` that exists, also as a dangling symbolic link, but is not a private file of the Auditor user, is larger than 4 MiB, is not valid JSON, is not a JSON object or does not hold text values for `tenant` and `catalog`, with the messages for files and content below;
- with Admin enabled, an Admin configuration `admin/config.json` that is missing, with `Operation failed; inspect private state and audit before retrying`, or that is not a private file of the Admin user, is larger than 4 MiB, is not valid JSON or is not a JSON object, with the messages for files and content below. With Admin disabled it is not read.

A private file is a single regular file, neither a symbolic link nor a file with further hard links, owned by the user of its role (gateway 51000, Auditor 51002, Admin 51003), readable by that user and without permissions for group or others; modes 0600 and 0400 are private. Unless the list names another message, a file that is not private is refused with `Unexpected file owner`, `Private file permissions are required` or `A single-link regular file is required`, a file above its size limit with `File exceeds its documented size limit`, a file that changes while it is read with `File changed during read` or `File length changed during read`, and a symbolic link or a file that cannot be opened for a reason other than being missing with `Operation failed; inspect private state and audit before retrying`, or with `NetOps could not access required files; check ownership and permissions` when access is denied. In the same way, unless the list names another message, content that the JSON parser refuses is reported with the message of the parser, and other invalid content with only an error type: a missing key such as `counts`, `tenant` or `catalog` with `KeyError`, a JSON value of the wrong type, for example a list instead of an object or a number instead of text, with `TypeError` and, for the Admin configuration, with `AttributeError`, and very deep nesting with `RecursionError`. A gateway configuration edited by hand is refused only where a check in the list cannot use a setting, in the same way, with the text of the error or only its error type, for example a removed `audit` setting or its `mode`, or a removed `server_name` or `admin_enabled` setting, with `KeyError`. A removed audit limit `budget_bytes`, `segment_bytes` or `retention_seconds` uses its default, and an audit limit is converted to an integer before the range check. These messages do not name the file; check the files and directories in the order of the list. A missing audit directory, a missing rejection summary and a missing Auditor configuration pass; the Auditor then uses the default tenant and catalog.

State that NetOps created passes the checks of files and directories in this list: NetOps writes these files with mode 0600 for the user of their role and creates the audit directory with mode 0700 for the gateway user. A refusal by one of these checks therefore points to a file or directory that was changed by hand, for example its owner, its mode or a symbolic link in its place, or to state restored with other owners or modes; NetOps does not correct them. NetOps 1.0.2 makes the checks of the gateway state in this list, from the audit limits to the CA and server certificate files, on every start, so they refuse state of a 1.0.2 instance that started and reported `ready` only when it was changed or restored with other owners or modes after that start. Stop the instance, give the file or directory from the list the owner and mode described here and start the new release again. Do not run `init`, and keep the backup until the upgraded instance is verified.

The first start checks the Auditor and the Admin configuration only as far as the list says: as a private file of the role user that holds a JSON object and, for the Auditor, text values for `tenant` and `catalog`. The roles of the previous release refuse such a configuration when they start; the new release refuses it already before the conversion, so the state is not converted. Everything else that the roles need is checked only by the roles after the conversion, when they start or when they handle a call, for example the values of `tenant` and `catalog`, such as a value with a NUL character or an unknown catalog, the Auditor store `auditor/store.sqlite` and, when the Admin configuration lists devices, the complete Admin configuration. A first start that a role refuses when it starts has already converted the state to 1.0.3, and the instance does not start: `docker compose logs netops` reports `RuntimeError` for the gateway and, for the role, one of the messages above or only an error type such as `ConfigurationError`. Such a start writes no `instance_start` audit record: the converting start writes that record, with the `upgrade` field, only after every role is ready. After the correction the next start does not convert again and records no `upgrade` field, so no audit record names the upgrade; [Verify the upgrade](#verify-the-upgrade) describes the indirect evidence that remains without that field. Stop the instance, correct the configuration and start the instance again, or restore the backup as described in [Rollback](#rollback).

### Interrupted first start

After a power loss or a killed container during the first start of the new release, the gateway configuration is either still the previous one or completely converted. A private temporary file whose name starts with `.netops-` can remain in the state volume. It is not authoritative state and not a commit; NetOps neither reads nor removes it automatically. Start the instance again with the new release and verify it as above. If the configuration was still the previous one, that start converts it and, once every role is ready, records the `upgrade` field. The audit lacks the `instance_start` record that names the previous version whenever the configuration was converted but the converting start stopped before it wrote that record, which it writes only after every role is ready, for example after an interruption or because a role refused to start; a later start then does not convert again and does not record an `upgrade` field. [Verify the upgrade](#verify-the-upgrade) describes the indirect evidence that remains for such an upgrade. A first start that one of the checks in [Refused first start](#refused-first-start) refuses, for example because of an incomplete final audit record, a changed `NETOPS_SERVER_NAME`, missing, unreadable or mismatched CA and server certificate files, a CA that expires too soon to renew the server certificate, an audit directory or a state file with a changed owner or mode, or an unreadable Auditor or Admin configuration, is refused before the conversion: the gateway configuration still records `1.0.2`. Recover an incomplete final audit record with the release that the state belongs to: `audit recover` of the new release refuses state that is not yet converted, with the message above, and changes nothing.

### Rollback

A release refuses state that a newer release has started on. Setting `NETOPS_IMAGE` back to the previous digest is not a rollback: NetOps 1.0.2 then does not start, its log reports `State belongs to another product version; automatic upgrade or downgrade is refused. Use the verified release procedure`, and the state does not change. Do not edit the product version recorded in the state by hand; that is not a rollback either.

The way back is the 1.0.2 instance that the upgrade left unchanged. Its state is that of the backup and does not contain audit records written after it. Keep them before the rollback: stop the 1.0.3 instance and, with its project and Compose file, write the export to a new private file:

```sh
docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" stop &&
(
  umask 077
  set -C
  docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" run --rm -T netops audit export < /dev/null > "$BACKUP_DIR/netops-audit-after-upgrade.jsonl"
)
```

With local audit the export holds the records written after the backup. With syslog audit, records already delivered are no longer in the export; keep the receiver archive, which holds them, together with the export, which holds only the records still queued and, after `configure syslog`, the earlier local segments. Keep the 1.0.3 instance stopped.

With syslog audit the receiver keeps its configuration and its part archive. The 1.0.2 instance sends the records of its queue again, also those that 1.0.3 already delivered; the persistent record ID identifies each repeated record.

Then start the 1.0.2 instance with its own Compose file and project and check it with the commands of [Before the upgrade](#before-the-upgrade):

```sh
docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" up -d --wait &&
docker compose -f "$SOURCE_COMPOSE" -p "$SOURCE_PROJECT" ps
```

The 1.0.2 instance has the state, CA, token and audit of the backup; the records written after the backup exist only in the export and, with syslog audit, in the receiver archive. Both instances use the same port: keep the 1.0.3 instance stopped and never run both at once. Remove the 1.0.3 instance and its volume with `docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" down -v` only after the rollback is verified and the export is kept. If the 1.0.2 instance or its volume was changed, restore the backup as described in [Back up and restore state](#back-up-and-restore-state) with the 1.0.2 release files instead.

## Auditor operator workflows

Configure a private Auditor tenant/catalog and optionally its own inventory/vault with the stopped instance. The smallest valid `auditor-private.json` is the one init writes:

~~~json
{"tenant": "default", "catalog": "fortios"}
~~~

`tenant` is your own label for this audit scope (a string without the U+001F character, which separates finding-fingerprint components) and `catalog` is `fortios` or `exos`. To collect from devices, add `inventory` and `vault` together, using the shared inventory/vault schemas linked above, including the device's auditor section. Auditor credentials remain separate from Helper and Admin. The following offline workflow evaluates a snapshot from stdin and stores its finished findings in the protected Auditor store; it does not contact a device. Exit codes for findings retain their existing meaning (a report with findings can return a nonzero code). `snapshot.cfg` is the FortiOS configuration text printed by `show`, which `collect` reads over SSH with console output set to `standard`; for `--platform exos` it is the output of `show configuration`. The release contains no sample snapshot. A management rule that an operator policy requires is evaluated only when the snapshot contains its configuration section; see the [management-policy reference](../components/netops-auditor/docs/management-policy.md).

~~~sh
docker compose stop
docker compose run -T --rm netops configure auditor < auditor-private.json
docker compose run -T --rm netops auditor run --platform fortios --device example-device --config - --json < snapshot.cfg
docker compose run --rm netops auditor status --device example-device --json
docker compose up -d --wait
~~~

The configured tenant and the private persistent store are defaults for run, collect and status: for these three commands NetOps supplies `--tenant` and `--store` (and for collect `--inventory`) from the configuration, so the normal workflow does not pass them although `auditor run --help` lists them as required; an explicit value still overrides the default. With `--config -`, NetOps copies standard input to a private temporary file `/var/lib/netops/auditor/.snapshot-*` for the run and removes it afterwards; an error about the snapshot, such as a parse error, names that file. For an explicitly configured device, replace the offline run command with:

~~~sh
docker compose run --rm netops auditor collect --device example-device --json
~~~

Collection uses the Auditor's private inventory and vault and verifies device SSH host keys or HTTPS certificates. No credential is copied from another role. Finished findings are then read through the authenticated MCP endpoint. Changing tenant/catalog preserves the store; it changes which tenant/catalog the MCP reader selects. `run --sarif` prints the report as SARIF on standard output instead of text or `--json`. NetOps 1.0 places operator files in the container only through `configure` (JSON on standard input), `auditor import-snapshot`, `auditor import-policy` and `auditor run --config -`; a path such as `/dev/stdin` is refused under the Auditor UID with `Permission denied`. The engine options and commands that read other operator files inside the container, `--suppressions` of `run` and `collect`, `merge-sarif` and `schema-check` (see [measured schema rules](../components/netops-auditor/docs/cis-mapping.md#measured-schema-rules)), therefore have no supported way to receive their input files and are not a supported operator workflow in NetOps 1.0. NetOps supplies defaults only for the `--tenant`, `--store` and `--inventory` options described above. Operator workflows are refused while NetOps is running.

Each finished finding has a state, defined in the [Auditor MCP tools](../components/netops-auditor/docs/tools.md#finding-states) reference. A finding stays `new` on every later run until it is accepted into the device baseline: add `--baseline-accept --accepted-by <name> --note <text>` to `run` or `collect`. That run accepts every finding it records and still reports them as `new`; later runs report them as `open-known`. A run that is not completely evaluated, for example when collection detects recognized truncation or a missing configured required_sections entry, is refused with `cannot accept a baseline from an unevaluated audit` and is not recorded.

### Private snapshot and policy files

Import reusable inputs while the instance is stopped. Importing an input does not run an audit or create finished findings; use run or collect to evaluate it. Contents travel only through stdin; imports run under the isolated Auditor UID and create mode-0600 files in its private state. Names contain 1–64 ASCII letters, digits, underscores or hyphens and start with a letter or digit. Existing names are refused; use a new name for changed input.

~~~sh
docker compose run -T --rm netops auditor import-snapshot --name example-device < snapshot.cfg
docker compose run -T --rm netops auditor import-policy --name example-policy --platform fortios < operator-policy.json
~~~

The commands print only their private destinations: /var/lib/netops/auditor/inputs/example-device.conf and /var/lib/netops/auditor/inputs/example-policy.policy.json. A snapshot must be UTF-8 and at most 64 MiB; import does not certify completeness. A policy must match the declared platform, pass the existing strict policy validation and be at most 256 KiB; FortiOS and EXOS policy examples and every field are in the [management-policy reference](../components/netops-auditor/docs/management-policy.md). No bind mount or broader role permissions are needed.

For the file collection channel, set the Auditor inventory source to the printed snapshot path, retain its required_sections, and use the normal collect command. To apply the imported policy, add --policy /var/lib/netops/auditor/inputs/example-policy.policy.json to run or collect. Choose the policy before the device's first run or collect: a device already evaluated without it, or with another policy, is refused with `operator policy differs from this device history; use a separate store for the new policy`, and MCP reads only the configured store, not a separate one. Configure the inventory through configure auditor as above. Imports and finished results persist in the same named volume across restart. Changing a policy still requires a separate store as described in the management-policy reference; importing a new filename does not migrate existing history.


### Operator identity and initial Admin choice

Run Docker commands as the host operator authorized to control Docker. Inside the image, initialization and operator workflows use the default container user for their short permission setup; role work then runs under its isolated UID. Do not add a --user override to these operator commands. A non-root container UID is refused before an operator write.

Admin is enabled on a new instance by default. To omit its worker and MCP tools, use `init --disable-admin` during the first initialization (the tool count of step 9 is then `20` instead of `26`); the offline `configure admin` and `admin` operator commands remain available and `admin doctor` still contacts the configured device, with the same audit selection as the normal init workflow. Repeating init preserves this initial choice and existing state; the flag is not a request to discard or recreate a configured volume.

Helper, Auditor and Admin configure workflows first record only the intended role and configure action through the gateway audit identity. No submitted configuration or credentials are copied into that intent event. Audit failure refuses installation of role inputs. The intent event alone does not certify successful validation or installation.

## Removing an instance

To stop and remove the serving container and its Compose network while retaining the named state volume:

~~~sh
docker compose down
~~~

Starting the same project with docker compose up -d --wait attaches that retained volume again. For permanent removal, first make and verify the backup you intend to retain, then run:

~~~sh
docker compose down -v
~~~

This removes the project's named state volume, including its configuration, CA and keys, token, role data and retained local audit. Restoration then requires the backup. Remove private operator input files, exported certificates and client configuration separately when they are no longer needed. For an additional instance, use its explicit -p project name on every command as described above.

To remove the NetOps image as well, run in the instance directory, before you delete `.env`:

~~~sh
docker image rm "$(sed -n 's/^NETOPS_IMAGE=//p' .env)"
~~~

Then remove the instance directory, `netops-ca.pem` copies on the clients and the client configuration: `claude mcp remove -s user netops` for Claude Code, and the `[mcp_servers.netops]` tables in `~/.codex/config.toml` for Codex. Docker itself, cosign and the client applications stay installed; remove them with the package manager when you no longer need them.
