# NetOps 1.0 quickstart

Use Linux with Docker Engine and the Compose plugin on a supported host: Ubuntu, Debian or Fedora Server (SELinux enforcing) on amd64 or arm64, or Raspberry Pi OS 64-bit on arm64 ([verified platform support](verified-support.md)). macOS and Windows run only MCP clients. The supported release is one NetOps image for linux/amd64 or linux/arm64. The image contains no AI agents. Existing 0.x installations and data are separate and are not migrated.

Run all Docker commands below from the same account and Docker context with access to the Docker daemon (root or an explicitly authorized account). On a new host, finish Docker installation and access setup first, then verify `docker info` succeeds in that shell before continuing.

Install Docker Engine and the Compose plugin from your distribution's packages or as described in [Docker's installation guide](https://docs.docker.com/engine/install/). To use Docker from a non-root account, add it to the `docker` group with `sudo usermod -aG docker "$USER"`, which gives that account root-equivalent access to the host, then log out and back in: the group applies only to new login sessions. Alternatively use rootless mode as described next.

Docker Engine in rootless mode is supported. Install it as that user with `dockerd-rootless-setuptool.sh install` as described in [Docker's rootless documentation](https://docs.docker.com/engine/security/rootless/), run every command below as that user in the environment the tool prints, and enable start at boot with `systemctl --user enable docker` and, as root, `loginctl enable-linger <user>`; without them the instance does not return after a host reboot. On Fedora with SELinux enforcing prepare the Docker data of that user before the first start of its daemon, that is before `dockerd-rootless-setuptool.sh install`. As that user:

```sh
mkdir -p ~/.local/share/docker ~/.config/docker
printf '{"selinux-enabled": true}\n' > ~/.config/docker/daemon.json
```

Then as root label the data like the system Docker data:

```sh
semanage fcontext -a -e /var/lib/docker /home/<user>/.local/share/docker
restorecon -R /home/<user>/.local/share/docker
```

Only then run `dockerd-rootless-setuptool.sh install`. `ls -Zd ~/.local/share/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots` must then show `container_file_t`. Without the label every NetOps container fails with `exec /usr/local/bin/netops-start: permission denied`; with the label applied after the first daemon start, containers crash with exit code 139. To repair such an installation stop the daemon (`systemctl --user stop docker`), run as root `chcon -R -t container_file_t` on that `snapshots` directory and start the daemon again.

Download `compose.yaml`, `env.example`, the release manifest `netops-1.0.1-manifest.json`, `netops-1.0.1-SHA256SUMS` and `netops-1.0.1-SHA256SUMS.sigstore.json` from the same GitHub release into an empty directory. Verify the maintainer's signature and every downloaded file before continuing. This needs cosign 2.5 or newer: Debian 13 and Ubuntu 26.04 package it as `cosign` (check the packaged version with `dpkg-query -W cosign`; the distribution build prints `devel` in `cosign version`); on other hosts use the official Sigstore release.

```sh
for f in compose.yaml env.example netops-1.0.1-manifest.json netops-1.0.1-SHA256SUMS netops-1.0.1-SHA256SUMS.sigstore.json; do
  curl -fLO "https://github.com/radek-cerny-soukr/netops/releases/download/v1.0.1/$f" || break
done
cosign verify-blob --bundle netops-1.0.1-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.1-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.1-SHA256SUMS
```

All commands must succeed: cosign prints `Verified OK` and sha256sum prints `OK` for `compose.yaml`, `env.example` and `netops-1.0.1-manifest.json`; cosign covers the checksum file and its bundle. `env.example` already pins the image by the index digest recorded in the manifest; keep that digest pin when updating. Skipping the check does not make the files verified.

```sh
umask 077
cp env.example .env
```

Compose uses the stable project name `netops`; moving the directory does not change the state volume. For multiple instances, give each instance its own directory with its own `.env` (a distinct `NETOPS_PORT`, and its own `NETOPS_SERVER_NAME` where needed) and use a different explicit `docker compose -p <instance>` on every command. A command without `-p` or `COMPOSE_PROJECT_NAME` addresses the project `netops`, whichever directory it runs in. Commands quoted in NetOps messages, such as `docker compose logs netops` or `docker compose run --rm netops audit recover`, are written without `-p`; for an additional instance add its `-p <instance>` to them as well. Never run two instances against one state volume.

Edit `.env`: keep `NETOPS_IMAGE` exactly as pinned by digest in the release `env.example`, set `NETOPS_BIND_IP` to the host address you explicitly want to expose, `NETOPS_PORT` to the host port, and `NETOPS_SERVER_NAME` to the exact DNS name your MCP clients will use (IP certificate names and the unedited `env.example` placeholder are refused). An `init` refused because of these `.env` values, an `--audit-budget` below 16 MiB or a `--syslog-port` outside 1–65535 writes no NetOps state. An `init` refused later, at the audit choice (input ending at a prompt, local audit not accepted, a missing or invalid syslog host, an invalid port typed at the prompt), leaves empty `admin`, `auditor`, `gateway` and `helper` directories in the state volume and sets mode 0711 on its root. The `Invalid certificate DNS name` diagnostic is shared by `NETOPS_SERVER_NAME` and `--syslog-host` validation. A repeated `init` uses them normally; a restore needs an empty volume (see [Back up and restore state](#back-up-and-restore-state)). In both cases Compose has already created the project's named volume (`<project>_netops-state`) and network for the `run` command; they stay until you remove them with Docker. When Compose itself rejects the configuration before `init` runs, for example `invalid ip address` for an unedited `NETOPS_BIND_IP`, nothing is created. No bind address is selected implicitly. The server name is fixed at init: while `NETOPS_SERVER_NAME` differs from it the instance refuses to start, and a different name needs a new instance. `NETOPS_BIND_IP` and `NETOPS_PORT` can change; apply them with `docker compose up -d`, which recreates the container (`restart` keeps the old port mapping). Create a local DNS or client hosts entry mapping that name to the bind address; for a client on the same host, use `NETOPS_BIND_IP=127.0.0.1` with `NETOPS_SERVER_NAME=localhost`. The instance CA permits the configured DNS subtree and excludes all IPv4/IPv6 names. This restriction is required for actual client compatibility and prevents trusting unrelated IP services. On Fedora keep SELinux enforcing and use the official Docker Engine repository. Verify `docker info` includes `name=selinux` in its security options; an enforcing host alone does not prove Docker applies container labels. If it is absent, add `"selinux-enabled": true` to `/etc/docker/daemon.json`, merging it with any existing settings or creating the file if it does not exist, and restart Docker before installing NetOps. Do not discard other daemon settings or disable SELinux. The supplied Compose uses a named data volume; any additional bind mounts require correct SELinux labels and Unix permissions.

If you choose syslog audit, prepare a dedicated receiver archive before init and the first 1.0.1 start that filters RFC5424 APP-NAME exactly `netops` and preserves MSG bytes plus one LF. Keep other applications and older 1.0 full-record archives separate. Verify the actual TLS/template/storage behavior as the receiver service account, and ensure NetOps cannot change retained receiver data; see [syslog delivery](architecture-1.0.md#syslog-delivery).

```sh
docker compose run --rm netops init && docker compose up -d --wait && docker compose ps
```

Init reads its answers from standard input. Scripts must choose the audit mode explicitly. Run scripts from a file; when a shell script itself arrives through stdin, Compose run can consume its later lines even with -T. Redirect commands that need no input with < /dev/null, for example `docker compose run --rm -T netops init --audit local --accept-local-audit < /dev/null`. Keep intentional JSON or snapshot input redirections on commands that read those inputs. Init recommends a TLS syslog receiver and asks for it interactively; without a terminal choose explicitly with `init --audit syslog --syslog-host <host> [--syslog-port <port>]` or `init --audit local --accept-local-audit`. Ending the input at an interactive prompt (EOF) stops init with the same `init needs an interactive terminal` message. Choosing local audit requires explicit acceptance of its disk warning: enter uppercase `LOCAL` at the interactive acceptance prompt. Both inputs and outputs consume disk. The default local budget is 256 MiB, rotating 16 MiB segments, with a maximum age of seven days; the budget can shorten retained history. A syslog queue does not drop old records to make room: once full, new operations are blocked. With local audit, measure usage with `netops audit stats`; on an instance initialized with syslog audit it shows only the local queue of records not yet delivered, so measure on the receiver. Size the deployment for its actual traffic. TLS delivery alone does not prove receiver persistence. Repeating init preserves CA, token and data. On an initialized instance it still checks `.env`, `--audit-budget` and `--syslog-port` as above and refuses a changed `NETOPS_SERVER_NAME`, but does not check `--syslog-host`, so an invalid value is accepted; otherwise it prints the connection details and `Already initialized; CA, token and data preserved.` and exits 0 without a warning: it does not apply `--audit`, `--accept-local-audit`, `--syslog-host`, `--syslog-port`, `--audit-budget` or `--disable-admin`. To move a local-audit instance to a syslog receiver, use `configure syslog` as described below; the audit budget and the Admin choice stay as chosen at the first init.

Export only the public CA and obtain the token through an explicit operator command. The init/start output never includes its value.

```sh
docker compose run --rm netops ca > netops-ca.pem &&
NETOPS_TOKEN="$(docker compose run --rm netops token show)" &&
export NETOPS_TOKEN &&
docker compose run --rm netops connection
```

Run the complete block and check its exit status before starting a client. Each command runs only after the preceding command succeeds.

With the `umask 077` set above in the same shell, `netops-ca.pem` is created with mode 600; in a new shell set `umask 077` again first. It holds only the public instance CA certificate; an MCP client that runs under another local account needs read access to this file.

To run Claude Code on the NetOps host, install it as described in the [official Claude Code setup](https://code.claude.com/docs/en/setup). Its native installer places `claude` in `~/.local/bin`; when the installer reports that this directory is not on `PATH`, run `export PATH="$HOME/.local/bin:$PATH"` and then `claude --version`. On a host without a browser, run `claude setup-token` on a machine with a browser and approve access there; it prints a long-lived token for a Pro, Max, Team or Enterprise plan, which you set as `CLAUDE_CODE_OAUTH_TOKEN` in the environment of the shell that starts `claude` on the host, without writing it to a file or a command line ([Claude Code authentication](https://code.claude.com/docs/en/authentication#generate-a-long-lived-token)).

Use the displayed HTTPS Streamable HTTP URL, the Authorization header sourced from `NETOPS_TOKEN`, and the CA file. Claude Code uses `NODE_EXTRA_CA_CERTS`; Codex uses `CODEX_CA_CERTIFICATE`; configure its HTTP server with `bearer_token_env_var = "NETOPS_TOKEN"` as described in the [official MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli). For Claude Code, with `NETOPS_TOKEN` exported as above and the URL from `connection`:

~~~sh
export NODE_EXTRA_CA_CERTS="$PWD/netops-ca.pem"
claude mcp add-json -s user netops '{"type":"http","url":"https://<server-name>:<port>/mcp","headers":{"Authorization":"Bearer ${NETOPS_TOKEN}"}}'
claude mcp list
~~~

`claude mcp list` exits with status 0 even when it cannot connect; read the status it prints for `netops`.

A client on another machine, such as macOS or Windows, needs only the public `netops-ca.pem`, the token and a name resolution for the server name. Copy `netops-ca.pem` to the client. Give the token to the client through a channel you trust and set it as `NETOPS_TOKEN` in the environment of the shell that starts the client, without writing it to a file or a command line. Editing the hosts file needs administrator rights (`/etc/hosts` with `sudo` on macOS, `C:\Windows\System32\drivers\etc\hosts` from an elevated shell on Windows); without them use a DNS record. In Windows PowerShell 5.1 the command above loses its inner quotes and fails with `Invalid configuration: : Invalid input`; use the stop-parsing form and avoid double quotes in `claude -p` prompts there:

~~~powershell
$env:NODE_EXTRA_CA_CERTS = "$PWD\netops-ca.pem"
claude --% mcp add-json -s user netops "{\"type\":\"http\",\"url\":\"https://<server-name>:<port>/mcp\",\"headers\":{\"Authorization\":\"Bearer ${NETOPS_TOKEN}\"}}"
claude mcp list
~~~

For Codex, from the instance directory export the CA path in the environment used to start the client and configure the HTTP server as described in the official MCP configuration linked above. Replace the URL with the one printed by connection; keep the token in the environment rather than the configuration file. The Codex CLI reads the TOML below from `~/.codex/config.toml`; `codex mcp list` then lists `netops` with its URL, `NETOPS_TOKEN` and `Bearer token`, and `codex mcp get netops` shows `enabled_tools: helper_status`:

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

Sign in to each client with its own provider account; NetOps supplies no client credentials. Make the first call from the same shell, in the instance directory, with `NETOPS_TOKEN` and the client's CA variable exported as above. Both commands run without an interactive session, grant permission for `helper_status` explicitly and take no standard input:

~~~sh
claude -p 'Call the helper_status tool of the netops MCP server exactly once with no arguments. Then reply with only the word DONE.' --allowedTools mcp__netops__helper_status --model claude-haiku-4-5-20251001 < /dev/null
codex exec --strict-config --skip-git-repo-check --ephemeral --sandbox read-only --model gpt-6.1-sol 'Call the helper_status tool of the netops MCP server exactly once with no arguments. Then reply with only the word DONE.' < /dev/null
~~~

Claude Code names the tool `mcp__netops__helper_status`. Both commands name their model with `--model`, because the model decides how the client carries out the prompt. `codex exec` refuses to run outside a Git repository unless `--skip-git-repo-check` is given, appends piped standard input to the prompt, and with `--strict-config` refuses unknown fields in `config.toml` instead of ignoring them; `--ephemeral` does not persist session files, and `--sandbox read-only` selects the read-only sandbox for any shell command the model runs. Each call is recorded in the audit as a request record naming `helper_status` and a response record with the same `correlation`; check it with `docker compose run --rm netops audit tail`.

Each role answers without an enrolled device, so the same commands can try it: replace `helper_status` in the prompt and in `--allowedTools` (for Codex in `enabled_tools`, with its own `approval_mode` table). The Helper tool `read_query_catalog` lists the read-only queries of each platform; the Auditor tools `list_rules` and `audit_status` list the audit rules and the audit freshness of the enrolled devices, none yet; the Admin tool `admin_status` returns the error result `admin_not_configured` until Admin is configured as described below.

Other MCP clients must enable normal CA/SAN verification. Never disable TLS verification.

Open WebUI v0.12.3 (`ghcr.io/open-webui/open-webui@sha256:a537bbe1e6b428820f52ed4a029d7fff97062e24d5cf32c365fba36fd0542def`) was tested as an MCP client with the local models Laguna XS 2.1 Q4 and gpt-oss-120b MXFP4, served by llama.cpp `llama-server` with a 16,384-token context; with each model 10 of 10 calls used the correct tool and arguments, and Laguna XS once miscounted a result (26 instead of 25 rules). Add NetOps in the admin settings under Integrations, External Tool Servers, as a connection of type MCP (Streamable HTTP) with the URL `https://<server-name>:<port>/mcp` and Auth Bearer with the NetOps token as the key. Open WebUI 0.12 and later trusts the instance CA through the environment variable `AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL=/path/netops-ca.pem` (in 0.9.x the variable accepts only true or false). When Open WebUI runs in a container, the server name must resolve to the NetOps address inside it, through DNS or `--add-host <server-name>:<bind-ip>`. With all roles enabled it loads 26 tools: 13 Helper, 7 Auditor and 6 Admin. In the audit Open WebUI reports the `clientInfo` `mcp 0.1.0`, the default name of the Python MCP SDK. With a wrong token NetOps answers 401, but Open WebUI skips the server silently and the chat continues without NetOps tools; the UI shows only `Failed to connect to MCP server` and the connection check `400 Failed to create MCP client`, and the model may then invent a result. After changing the token, check the connection and look for a `tools/call` in the audit. `read_query_catalog` returns about 119 kB (about 23,000 tokens), which does not fit into a 16,384-token context; this is a limit of the client context, not a NetOps error.

Automatic server-leaf renewal does not replace the CA. The instance CA is valid for 730 days from init or its last rotation; `connection` shows its expiry date and the remaining whole days, so directly after init it prints 729 days. From 30 days before expiry `connection` and the gateway log warn, and from 14 days the healthcheck reports the instance unhealthy; without rotation the instance stops during its last seven days.

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

Reassemble one explicit record offline from a copy of its part archive into a new private output file. Replace the sample ID with that record's 32-lowercase-hex ID:

~~~sh
(
  umask 077
  set -C
  docker compose run --rm -T netops audit reassemble --record-id 0123456789abcdef0123456789abcdef < /absolute/private/path/receiver-parts.jsonl > /absolute/private/path/reassembled-record.json
)
~~~

The command reads only stdin and emits the exact original record, including LF, after reading the entire archive successfully. It requires no instance state, token, vault or running service. Preserve the source archive unchanged. The first complete consistent SHA-valid selected set is frozen in receiver line order. Exact retries are idempotent; a later conflicting part or alternative set cannot replace those bytes. A unique foreign string ID is skipped before validating its remaining fields.

Exit 0 means clean output. Exit 3 means the output is the same frozen record and stderr contains compact ASCII JSONL warnings with schema `netops-syslog-reassembly-warning/1`, code `late_conflict` or `late_invalid`, and original `line_number`. Keep that diagnostic as tamper evidence and inspect the original archive; do not discard the valid output merely because later data conflicted. Before completion, invalid/unattributable rows or selected conflicts are errors. Exit 2 writes no record bytes on an argument, validation or input-read failure, including an input-read failure after warnings; a stdout write failure also ends with exit 2. Keep the diagnostic: `reassembly_validation_error line_N` identifies the original offending/completion line, `after_line_N` identifies missing/incomplete EOF, `reassembly_read_error after_line_N` counts consumed lines, and `reassembly_argument_error line_0` means an invalid explicit ID before reading. A wrong whole SHA fails immediately on completion, not at EOF. Never overwrite the original archive or normalize malformed rows. A stdout write failure can leave a partial new output file; inspect its status and preserve the archive.

The audit target, budget (`init --audit-budget <bytes>`, default 256 MiB, at least 16 MiB) and seven-day local retention are chosen at init. `configure syslog` switches a local-audit instance to a TLS syslog receiver; earlier local segments then stay readable with `audit tail` and `audit export` but are neither forwarded nor rotated. No NetOps command removes them: the seven-day retention that ages them out runs only in local-audit mode, so after the switch they stop shrinking and their disk use sits beside, not inside, the running `--audit-budget`, which afterward enforces only the queue. Every `audit` read of that instance includes them together with the queue: `audit stats` counts the earlier segments plus the queued records, and an entry that `audit pending` lists from an earlier segment stays listed; settle it as described below. Record `audit stats` while the instance is still stopped directly after the switch, so the queue is empty: a later reading's `records` and `bytes` are the frozen archive plus whatever the queue holds then, so their difference from that first reading is the queue's size at the later reading; this holds only against that first reading of an empty queue; `mean_record_bytes` and `unauthenticated_rejections` are not additive and do not work this way. To keep these reads limited to the queue, choose syslog audit at the first init. There is no command that returns a syslog instance to local audit. Undelivered syslog records stay queued and are retried; the gateway log reports a failing receiver once and the healthcheck reports the instance unhealthy when the oldest queued record is older than five minutes.

To run the healthcheck by hand, use `docker compose exec netops netops health` on the running instance; it prints `ready`. The check connects to the gateway at 127.0.0.1:8443 inside the serving container and queries its role workers, so `docker compose run --rm netops health`, which starts a separate container without a gateway, cannot pass and ends with `netops: Operation failed; inspect private state and audit before retrying; operation failed without automatic retry`.

No device is implicitly enrolled. Start with `helper_status` and `read_query_catalog`; enrollment is an operator action. Prepare private JSON outside the source repository and protect it with mode 600. Helper input has exactly `inventory` and `vault`. Use the complete [Helper configuration example](helper-configuration.md), including its mandatory `helper` section; the generic [Core inventory](../components/netops-core/docs/inventory.md) example alone is not a Helper enrollment. Credentials follow [Core vault](../components/netops-core/docs/vault.md). Auditor accepts `tenant` and `catalog`, with an optional `inventory`/`vault` pair for collection through `netops configure auditor`; changing them preserves the finished store and restores the existing FortiOS/EXOS catalog selection. Admin input requires `config` and `vault`, with optional private `notification_topic`, following the [Admin configuration](admin-configuration.md). State and operation-audit paths are set inside the Admin's private directory; vault references point only to its private vault. Separate role credentials are intentional.

Stop the instance before changing role configuration or running offline operator workflows:

```sh
docker compose stop
docker compose run -T --rm netops configure helper < helper-private.json
docker compose run -T --rm netops configure admin < admin-private.json
docker compose up -d --wait
```

Admin is enabled by default and refuses device changes until configured. The existing Admin safeguards, explicit request IDs, limits and audit requirements remain. If an operation's result is unknown or its response audit fails, do not repeat a write automatically. Inspect the pending correlation and the actual device state first.

```sh
docker compose run --rm netops audit tail
docker compose run --rm netops audit pending
docker compose run --rm netops audit stats
```

`audit pending` lists every operation whose outcome the client may not know: requests without a recorded response, interrupted operations, responses withheld because the token changed, and Admin results `unknown` or `revert-failed`. With local audit these commands read the retained segments. On an instance initialized with syslog audit they read only the local queue of records not yet delivered (after `configure syslog`, also the earlier local segments, see above); a delivered record is removed from it, so look for unresolved correlations on the syslog receiver. While the instance is running, a command can fail when an audit file changes during the read; run it again, or stop the instance for a consistent read. Before deciding that recovery is needed, stop the instance and repeat the read.

A pending entry with the outcome `response withheld because the token changed; the operation may have completed; inspect status and the device` belongs to a request that was dispatched while the token was rotated: the client received `token_rotated` instead of the result, and the audit holds no response record for it. The entry stays in `audit pending` as long as its request record is retained; a restart does not remove it, `audit recover` only quarantines an incomplete final record, and no command marks an entry as resolved. To settle it, find the request with the same `correlation` in `audit export`, which shows its tool and arguments, then check the outcome: for an Admin tool read `admin_status` with the original `request_id` argument and inspect the actual device. The `request_id` field of `audit pending` is the JSON-RPC message ID, not that Admin argument.

Audit records are read in deterministic segment and queue order, which can differ from chronological event order if the system clock moves backward. Audit output is escaped for terminals. `audit export` writes JSONL for external processing. Audit times are in UTC. `audit` without an action (`audit show`) prints every retained record in the same form; `audit tail` prints the last 100 records, and `--lines N` changes that number (a larger N is limited to 10000 and 0 or a negative N shows no records; fewer records are shown when fewer are retained). `netops version` prints the product version, and `netops selftest` prints the version and the MCP tool names of each role as JSON (13 Helper, 7 Auditor and 6 Admin tools). Redaction is explicit; audit is parsed protocol content rather than a raw byte transcript. Device output is sensitive even after credential redaction.

To list each MCP tool call with its time, tool name and whether a response with the same `correlation` was recorded:

```sh
docker compose run --rm -T netops audit export < /dev/null |
  jq -rs '(map(select(.direction == "response") | {(.correlation): true}) | add // {}) as $answered
    | .[] | select(.direction == "request" and (.payload | type) == "object" and .payload.method == "tools/call")
    | [.time, .payload.params.name, (if $answered[.correlation] then "response" else "no response" end)]
    | @tsv'
```

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

Stop the source instance before copying its complete named volume. The archive contains private CA keys, the bearer token, role credentials and device data. Choose a new absolute backup filename in an existing private directory outside source checkouts (create it first, for example with `mkdir -m 700`). Keep the archive and its source manifest together, plus the verified Compose file, .env and image digest separately. The manifest contains metadata and hashes, not file contents.

From the source instance directory, set SOURCE_PROJECT to its actual Compose project name and BACKUP_FILE to that private filename. This records numeric owners, groups, permission modes and regular-file checksums while the source is stopped, before creating the archive:

~~~sh
SOURCE_COMPOSE="$PWD/compose.yaml"
SOURCE_PROJECT=netops
BACKUP_FILE=/absolute/private/path/netops-state.tar
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

For a restore, prepare a separate instance directory with the verified image and release files of the release you restore into (the same release for a plain restore, the new release for an upgrade), the same server name and port, and its own .env. Use a different Compose project name so Docker creates a new state volume. An `init` run in the target project before can have left a skeleton in its volume (see above); restore needs an empty target and refuses any other. If the target volume is not empty, choose another new project name instead; do not remove an existing volume to make room for a restore. Keep the original stopped if it still exists and do not run init on the target. The original volume is not needed: the comparison uses the source manifest saved with the backup.

Set the paths again in the shell used for recovery. The repeated manifest code is the same calculation as in the backup block. Extraction requires an empty target, and every following step, including start, depends on success of the previous step:

~~~sh
BACKUP_FILE=/absolute/private/path/netops-state.tar
RESTORED_COMPOSE=/absolute/path/to/restored/compose.yaml
RESTORED_PROJECT=netops-restored
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

All commands must exit successfully; the service must be healthy and connection must show the original server name and port. Check the local history reported by audit stats, or, for syslog audit, verify the retained history at the receiver: on an instance initialized with syslog audit, audit stats then describes only the undelivered local queue; an instance switched to syslog audit after init still counts its frozen local segments in that history (see above). Use the original public CA, token and existing MCP client configuration to repeat the role reads used before the backup, including Auditor findings when present. Health alone does not verify role data. Confirm the expected role configuration and data before removing the source or backup. The [upgrade from the previous release](#upgrade-from-the-previous-release) uses this restore with the files of the new release.

## Upgrade from the previous release

NetOps 1.0.1 upgrades the state of NetOps 1.0.0, the immediately preceding release. It refuses state of any other product version or state schema; there is no upgrade that skips a release and no downgrade. The upgrade restores a backup of the 1.0.0 instance into a new, separate 1.0.1 instance and leaves the 1.0.0 instance, its directory and its state volume unchanged for a rollback. The new instance keeps the server name and port, the CA, the token, role configuration and data, and the audit of the backup; MCP clients keep their configuration, token and CA file. The upgrade has five steps:

1. Check the 1.0.0 instance, stop it and back it up, as described in [Before the upgrade](#before-the-upgrade).
2. If the instance uses syslog audit, switch the receiver, as described in [Switch the syslog receiver](#switch-the-syslog-receiver).
3. [Download and verify the new release](#download-and-verify-the-new-release), then prepare a clean 1.0.1 instance in a new directory, with the same server name and port and a `.env` with the 1.0.1 image, as described in [Prepare the 1.0.1 instance](#prepare-the-101-instance).
4. Restore the backup into it, as described in [Restore and start the 1.0.1 instance](#restore-and-start-the-101-instance).
5. Start it: the last command of the restore block starts the 1.0.1 instance. Then [verify the upgrade](#verify-the-upgrade).

Commands in this section without `-p` address the default project `netops`. If the 1.0.0 instance uses another project name, add its `-p <instance>` to them; see [Explicit project names](#explicit-project-names).

### Before the upgrade

Run the commands of this section in the instance directory, where the previous release's `compose.yaml` and `.env` are. First check that the instance runs NetOps 1.0.0 and is healthy:

```sh
docker compose ps
docker compose exec -T netops netops version < /dev/null
docker compose exec -T netops netops health < /dev/null
docker compose run --rm -T netops audit pending < /dev/null
```

`version` prints `1.0.0` and `health` prints `ready`. If the instance reports an incomplete final audit record, run `audit recover` as described above with the previous release before the upgrade. Note the entries that `audit pending` lists; the upgrade keeps every entry. The new release checks the state before it converts it and refuses some state that the previous release starts and reports as `ready`, for example an audit directory with mode 0750; see [Refused first start](#refused-first-start).

Back up the instance with the backup block in [Back up and restore state](#back-up-and-restore-state), with `SOURCE_PROJECT` set to the project the instance uses (`netops` unless you use `-p`). The block stops the instance. Keep the 1.0.0 instance directory with its `compose.yaml` and `.env` and its state volume unchanged, do not start the 1.0.0 instance again and do not remove it until the upgraded instance is verified: it is the rollback. Keep the backup as well.

### Switch the syslog receiver

If this instance uses syslog, before the first 1.0.1 start switch the receiver to the [dedicated NetOps MSG-only part archive](architecture-1.0.md#syslog-delivery), filtered by APP-NAME `netops`. Keep the receiver configuration of 1.0.0, which a rollback needs. Preserve the older 1.0 full-record archive separately and verify the new receiver storage template. Do not empty the NetOps queue: the backup holds it, and 1.0.1 sends the retained 1.0.0 queued records in the new part format. After starting, reassemble their exact bytes, including LF and whole SHA, as well as new records; the persistent record ID keeps retries idempotent.

### Download and verify the new release

Download `compose.yaml`, `env.example`, `netops-1.0.1-manifest.json`, `netops-1.0.1-SHA256SUMS` and `netops-1.0.1-SHA256SUMS.sigstore.json` from the 1.0.1 GitHub release into a new empty directory, not into the instance directory. Verify them there in the same way as for a new installation:

```sh
for f in compose.yaml env.example netops-1.0.1-manifest.json netops-1.0.1-SHA256SUMS netops-1.0.1-SHA256SUMS.sigstore.json; do
  curl -fLO "https://github.com/radek-cerny-soukr/netops/releases/download/v1.0.1/$f" || break
done
cosign verify-blob --bundle netops-1.0.1-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.1-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.1-SHA256SUMS
```

All commands must succeed: cosign prints `Verified OK` and sha256sum prints `OK` for `compose.yaml`, `env.example` and `netops-1.0.1-manifest.json`.

### Prepare the 1.0.1 instance

Create a new, empty instance directory for 1.0.1; do not use the directory of the 1.0.0 instance. Copy `compose.yaml` and `env.example` from the verified release directory into it and create `.env` there as for a new installation:

```sh
umask 077
cp env.example .env
```

Edit `.env` by hand: set `NETOPS_BIND_IP`, `NETOPS_PORT` and `NETOPS_SERVER_NAME` to the values in the `.env` of the 1.0.0 instance and keep `NETOPS_IMAGE` exactly as pinned in the verified new `env.example`, which pins the index digest recorded in `netops-1.0.1-manifest.json`. Set `NEW_RELEASE` to the absolute path of the verified directory and print both image lines; apart from the file name in front of them they must be identical:

```sh
NEW_RELEASE=/absolute/path/to/verified/netops-1.0.1
grep '^NETOPS_IMAGE=' "$NEW_RELEASE/env.example" .env
```

Do not run `init` in the new instance.

### Restore and start the 1.0.1 instance

Restore the backup with the restore block in [Back up and restore state](#back-up-and-restore-state), with `BACKUP_FILE` set to the backup of [Before the upgrade](#before-the-upgrade), `RESTORED_COMPOSE` set to the `compose.yaml` of the new directory and `RESTORED_PROJECT` set to a new project name that differs from the project of the 1.0.0 instance, for example `netops-restored`. Run the check block that follows it. The restore block starts the instance as its last command, after the restored state matches the manifest of the backup.

Do not run `init` and do not run `docker compose down -v` at any point of the upgrade. The first start of the new release converts the restored state: it makes the checks in [Refused first start](#refused-first-start), the later ones under the instance lock after it reads the gateway configuration again, and then replaces only its recorded product version, `1.0.0`, with `1.0.1`. Every other setting, the CA, the token, role data and the existing audit records stay as they are, and later starts do not change the configuration again. A process of the new release started while another process still runs on the same state, for example with `docker compose run` or `docker run`, is refused with `An existing instance is using this state; stop it before starting or upgrading` and changes nothing.

Until this first start, the restored state still belongs to 1.0.0. Operator commands of the new release that change state, including `init`, `token rotate`, `configure`, `ca rotate` and `audit recover`, refuse it with `State belongs to NetOps 1.0.0; start NetOps 1.0.1 to upgrade it before running this command. Do not reinitialize existing state` and change nothing; `connection`, `ca`, `token show` and the `audit` reads keep working. An interrupted procedure can be completed by repeating its remaining steps.

### Verify the upgrade

Run these commands with the project and Compose file of the 1.0.1 instance:

```sh
docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" exec -T netops netops version < /dev/null
docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" exec -T netops netops health < /dev/null
docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" run --rm -T netops connection < /dev/null
docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" run --rm -T netops audit tail < /dev/null
docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" run --rm -T netops audit pending < /dev/null
```

`version` prints `1.0.1`, `health` prints `ready` and `connection` shows the same server name, port and URL as before. The `instance_start` audit record of the converting start names both versions as `"upgrade": {"from": "1.0.0", "to": "1.0.1"}`; later starts have no `upgrade` field. The converting start writes this record only after every role is ready. If it stops before it writes the record, for example because a role refused to start (see [Refused first start](#refused-first-start)) or after an interruption, no audit record has the `upgrade` field: later starts do not convert again. No audit record then names the upgrade or its time. Only indirect evidence remains that the instance changed release: the last `instance_start` or `instance_stop` record before the upgrade names `"version": "1.0.0"`, and the next `instance_start` record names `"version": "1.0.1"`. Look for these records in audit history that you kept: the backup from [Before the upgrade](#before-the-upgrade), an `audit export` or, with syslog audit, the archive of the receiver. `audit tail` shows only the last 100 records by default, and local audit removes old segments after the retention period and when the audit budget is full, so the record from before the upgrade can be missing. The syslog header carries no host name, so at a receiver that several instances share the header does not show which instance the records belong to. Without such kept history the audit cannot show the change. After a first start that was not interrupted and that no role refused, a missing `upgrade` field is a defect; report it. With local audit `audit pending` still lists the entries from before the upgrade; with syslog audit an entry leaves the local queue once it is delivered, so look for it at the receiver. Then make one call with each MCP client without changing its configuration, for example the first `helper_status` call above, and find its request and response: with local audit in `audit tail` or `audit export`, with syslog audit at the receiver.

### Explicit project names

The 1.0.0 instance keeps its project: `netops`, or the name it uses with `-p <instance>` or `COMPOSE_PROJECT_NAME`; use it as `SOURCE_PROJECT` of the backup. The 1.0.1 instance uses another project name, because the restore needs an empty volume. Use that name with `-p` in every Compose command of the 1.0.1 instance, also in the commands quoted in NetOps messages. A command without it addresses the project `netops` and its volume, whichever directory it runs in. Do not run `init` in a project with an empty volume.

### Several operators of one instance

The default Compose project `netops` is shared by every directory and every user on the host. A previous `compose.yaml` and `.env` in another directory or account still address the 1.0.0 instance: `docker compose` there can start it again on its unchanged 1.0.0 state and the same port, and its `token rotate` changes only the token of the 1.0.0 state. All operators of one instance switch to the 1.0.1 instance directory and its project name and coordinate the downtime. Keep the 1.0.0 instance stopped while 1.0.1 runs. An independent instance uses its own explicit `-p` project and its own port.

### Refused first start

Before the first start of the new release converts the state, it checks the state in the order of the list below and stops at the first check that fails. A refused first start does not convert the state: the gateway configuration still records `1.0.0`, and `docker compose logs netops` reports the reason as `netops: <reason>; operation failed without automatic retry`. As for an incomplete audit record, the supplied restart policy can leave Compose showing `Restarting`, and `up --wait` then fails. The first start refuses:

- a gateway configuration `gateway/config.json` that is missing: `NetOps is not initialized; run docker compose run --rm netops init first`; that cannot be read as a private file of the gateway user or is not valid JSON or holds a duplicate key, NaN or Infinity: `Initialized private state cannot be read safely; initialize a new instance or use the matching release to inspect existing state`; or that records another state schema or a product version other than `1.0.0` and `1.0.1`: `Unsupported state schema; use the matching NetOps release and its verified recovery procedure` or `State belongs to another product version; automatic upgrade or downgrade is refused. Use the verified release procedure`. A container that runs as a user other than root and the gateway user, for example with a `--user` override, cannot read an existing gateway configuration and is refused here with the second message;
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

State that NetOps created passes the checks of files and directories in this list: NetOps writes these files with mode 0600 for the user of their role and creates the audit directory with mode 0700 for the gateway user. A refusal by one of these checks therefore points to a file or directory that was changed by hand, for example its owner, its mode or a symbolic link in its place, or to state restored with other owners or modes; NetOps does not correct them. The previous release starts some of this state and its healthcheck reports `ready`, for example with an audit directory of mode 0750. Stop the instance, give the file or directory from the list the owner and mode described here and start the new release again. Do not run `init`, and keep the backup until the upgraded instance is verified.

The first start checks the Auditor and the Admin configuration only as far as the list says: as a private file of the role user that holds a JSON object and, for the Auditor, text values for `tenant` and `catalog`. The roles of the previous release refuse such a configuration when they start, except an Auditor configuration that the previous release treated as absent, such as a dangling symbolic link; the new release refuses it already before the conversion, so the state is not converted. Everything else that the roles need is checked only by the roles after the conversion, when they start or when they handle a call, for example the values of `tenant` and `catalog`, such as a value with a NUL character or an unknown catalog, the Auditor store `auditor/store.sqlite` and, when the Admin configuration lists devices, the complete Admin configuration. A first start that a role refuses when it starts has already converted the state to 1.0.1, and the instance does not start: `docker compose logs netops` reports `RuntimeError` for the gateway and, for the role, one of the messages above or only an error type such as `ConfigurationError`. Such a start writes no `instance_start` audit record: the converting start writes that record, with the `upgrade` field, only after every role is ready. After the correction the next start does not convert again and records no `upgrade` field, so no audit record names the upgrade; [Verify the upgrade](#verify-the-upgrade) describes the indirect evidence that remains without that field. Stop the instance, correct the configuration and start the instance again, or restore the backup as described in [Rollback](#rollback).

### Interrupted first start

After a power loss or a killed container during the first start of the new release, the gateway configuration is either still the previous one or completely converted. A private temporary file whose name starts with `.netops-` can remain in the state volume. It is not authoritative state and not a commit; NetOps neither reads nor removes it automatically. Start the instance again with the new release and verify it as above. If the configuration was still the previous one, that start converts it and, once every role is ready, records the `upgrade` field. The audit lacks the `instance_start` record that names the previous version whenever the configuration was converted but the converting start stopped before it wrote that record, which it writes only after every role is ready, for example after an interruption or because a role refused to start; a later start then does not convert again and does not record an `upgrade` field. [Verify the upgrade](#verify-the-upgrade) describes the indirect evidence that remains for such an upgrade. A first start that one of the checks in [Refused first start](#refused-first-start) refuses, for example because of an incomplete final audit record, a changed `NETOPS_SERVER_NAME`, missing, unreadable or mismatched CA and server certificate files, a CA that expires too soon to renew the server certificate, an audit directory or a state file with a changed owner or mode, or an unreadable Auditor or Admin configuration, is refused before the conversion: the gateway configuration still records `1.0.0`. Recover an incomplete final audit record with the release that the state belongs to: `audit recover` of the new release refuses state that is not yet converted, with the message above, and changes nothing.

### Rollback

A release refuses state that a newer release has started on. Setting `NETOPS_IMAGE` back to the previous digest is not a rollback: NetOps 1.0.0 then does not start, its log reports `State belongs to another product version; automatic upgrade or downgrade is refused. Use the verified release procedure`, and the state does not change. Do not edit the product version recorded in the state by hand; that is not a rollback either.

The way back is the 1.0.0 instance that the upgrade left unchanged. Its state is that of the backup and does not contain audit records written after it. Keep them before the rollback: stop the 1.0.1 instance and, with its project and Compose file, write the export to a new private file:

```sh
docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" stop &&
(
  umask 077
  set -C
  docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" run --rm -T netops audit export < /dev/null > /absolute/private/path/netops-audit-after-upgrade.jsonl
)
```

With local audit the export holds the records written after the backup. With syslog audit, records already delivered are no longer in the export; keep the receiver archive, which holds them, together with the export, which holds only the records still queued and, after `configure syslog`, the earlier local segments. Keep the 1.0.1 instance stopped.

If the instance uses syslog audit, return the receiver to the configuration of 1.0.0, with its enlarged message size limits and its separate 1.0 archive, before the 1.0.0 instance starts, and keep the part archive unchanged. The 1.0.0 instance sends the records of its queue again as whole records, also those that 1.0.1 already delivered as parts.

Then start the 1.0.0 instance in its own directory and check it with the commands of [Before the upgrade](#before-the-upgrade):

```sh
docker compose up -d --wait && docker compose ps
```

The 1.0.0 instance has the state, CA, token and audit of the backup; the records written after the backup exist only in the export and, with syslog audit, in the receiver archive. Both instances use the same port: keep the 1.0.1 instance stopped and never run both at once. Remove the 1.0.1 instance and its volume with `docker compose -f "$RESTORED_COMPOSE" -p "$RESTORED_PROJECT" down -v` only after the rollback is verified and the export is kept. If the 1.0.0 instance or its volume was changed, restore the backup as described in [Back up and restore state](#back-up-and-restore-state) with the 1.0.0 release files instead.

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

Admin is enabled on a new instance by default. To omit its worker and MCP tools, use init --disable-admin during the first initialization; the offline `configure admin` and `admin` operator commands remain available and `admin doctor` still contacts the configured device, with the same audit selection as the normal init workflow. Repeating init preserves this initial choice and existing state; the flag is not a request to discard or recreate a configured volume.

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
