# NetOps 1.0 quickstart

Use Linux with Docker Engine and the Compose plugin. The supported release is one NetOps image for linux/amd64 or linux/arm64. The image contains no AI agents. Existing 0.x installations and data are separate and are not migrated.

Run all Docker commands below from the same account and Docker context with access to the Docker daemon (root or an explicitly authorized account). On a new host, finish Docker installation and access setup first, then verify `docker info` succeeds in that shell before continuing.

Download `compose.yaml`, `env.example`, the release manifest `netops-1.0.0-manifest.json`, `netops-1.0.0-SHA256SUMS` and `netops-1.0.0-SHA256SUMS.sigstore.json` from the same GitHub release into an empty directory. Verify the maintainer's signature and every downloaded file before continuing. This needs cosign 2.5 or newer: Debian 13 and Ubuntu 26.04 package it as `cosign` (check the packaged version with `dpkg-query -W cosign`; the distribution build prints `devel` in `cosign version`); on other hosts use the official Sigstore release.

```sh
cosign verify-blob --bundle netops-1.0.0-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.0-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.0-SHA256SUMS
```

Both commands must succeed: cosign prints `Verified OK` and sha256sum prints `OK` for every downloaded file. `env.example` already pins the image by the index digest recorded in the manifest; keep that digest pin when updating. Skipping the check does not make the files verified.

```sh
umask 077
cp env.example .env
```

Compose uses the stable project name `netops`; moving the directory does not change the state volume. For multiple instances, give each instance its own directory with its own `.env` (a distinct `NETOPS_PORT`, and its own `NETOPS_SERVER_NAME` where needed) and use a different explicit `docker compose -p <instance>` on every command. A command without `-p` or `COMPOSE_PROJECT_NAME` addresses the project `netops`, whichever directory it runs in. Commands quoted in NetOps messages, such as `docker compose logs netops` or `docker compose run --rm netops audit recover`, are written without `-p`; for an additional instance add its `-p <instance>` to them as well. Never run two instances against one state volume.

Edit `.env`: keep `NETOPS_IMAGE` exactly as pinned by digest in the release `env.example`, set `NETOPS_BIND_IP` to the host address you explicitly want to expose, `NETOPS_PORT` to the host port, and `NETOPS_SERVER_NAME` to the exact DNS name your MCP clients will use (IP certificate names are refused). An `init` refused because of these `.env` values, an `--audit-budget` below 16 MiB or a `--syslog-port` outside 1–65535 writes no NetOps state. An `init` refused later, at the audit choice (input ending at a prompt, local audit not accepted, a missing or invalid syslog host, an invalid port typed at the prompt), leaves empty `admin`, `auditor`, `gateway` and `helper` directories in the state volume and sets mode 0711 on its root. The `Invalid certificate DNS name` diagnostic is shared by `NETOPS_SERVER_NAME` and `--syslog-host` validation. A repeated `init` uses them normally; a restore needs an empty volume (see [Back up and restore state](#back-up-and-restore-state)). In both cases Compose has already created the project's named volume (`<project>_netops-state`) and network for the `run` command; they stay until you remove them with Docker. When Compose itself rejects the configuration before `init` runs, for example `invalid ip address` for an unedited `NETOPS_BIND_IP`, nothing is created. No bind address is selected implicitly. The server name is fixed at init: while `NETOPS_SERVER_NAME` differs from it the instance refuses to start, and a different name needs a new instance. `NETOPS_BIND_IP` and `NETOPS_PORT` can change; apply them with `docker compose up -d`, which recreates the container (`restart` keeps the old port mapping). Create a local DNS or client hosts entry mapping that name to the bind address; for a client on the same host, `localhost` can be used. The instance CA permits the configured DNS subtree and excludes all IPv4/IPv6 names. This restriction is required for actual client compatibility and prevents trusting unrelated IP services. On Fedora keep SELinux enforcing and use the official Docker Engine repository. Verify `docker info` includes `name=selinux` in its security options; an enforcing host alone does not prove Docker applies container labels. If it is absent, add `"selinux-enabled": true` to `/etc/docker/daemon.json`, merging it with any existing settings or creating the file if it does not exist, and restart Docker before installing NetOps. Do not discard other daemon settings or disable SELinux. The supplied Compose uses a named data volume; any additional bind mounts require correct SELinux labels and Unix permissions.

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

With the `umask 077` set above, `netops-ca.pem` is created with mode 600. It holds only the public instance CA certificate; an MCP client that runs under another local account needs read access to this file.

Use the displayed HTTPS Streamable HTTP URL, the Authorization header sourced from `NETOPS_TOKEN`, and the CA file. Claude Code uses `NODE_EXTRA_CA_CERTS`; Codex uses `CODEX_CA_CERTIFICATE`; configure its HTTP server with `bearer_token_env_var = "NETOPS_TOKEN"` as described in the [official MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli). For Claude Code, with `NETOPS_TOKEN` exported as above and the URL from `connection`:

~~~sh
export NODE_EXTRA_CA_CERTS="$PWD/netops-ca.pem"
claude mcp add-json -s user netops '{"type":"http","url":"https://<server-name>:<port>/mcp","headers":{"Authorization":"Bearer ${NETOPS_TOKEN}"}}'
claude mcp list
~~~

For Codex, from the instance directory export the CA path in the environment used to start the client and configure the HTTP server as described in the official MCP configuration linked above. Replace the URL with the one printed by connection; keep the token in the environment rather than the configuration file. The Codex CLI reads the TOML below from `~/.codex/config.toml`; `codex mcp list` then lists `netops` with its URL, `NETOPS_TOKEN` and `Bearer token`:

~~~sh
export CODEX_CA_CERTIFICATE="$PWD/netops-ca.pem"
~~~

~~~toml
[mcp_servers.netops]
url = "https://<server-name>:<port>/mcp"
bearer_token_env_var = "NETOPS_TOKEN"
~~~

Other MCP clients must enable normal CA/SAN verification. Never disable TLS verification. Automatic server-leaf renewal does not replace the CA. The instance CA is valid for 730 days from init or its last rotation; `connection` shows its expiry date and the remaining whole days, so directly after init it prints 729 days. From 30 days before expiry `connection` and the gateway log warn, and from 14 days the healthcheck reports the instance unhealthy; without rotation the instance stops during its last seven days.

For a receiver with a private CA, stop the instance and run `docker compose run -T --rm netops configure syslog < syslog-trust.json` before starting it. The JSON contains `host`, optional `port` (6514) and optional public `ca_pem`. No bind mount or TLS verification bypass is required. The syslog queue remains bounded and durable. The verified receiver is rsyslog 8.2512 with the gtls network stream driver (package rsyslog-gnutls); the ossl driver (rsyslog-openssl) is not supported. A successful delivery is a TLS transport hand-over, not a receiver acknowledgement; see [Syslog delivery](architecture-1.0.md#syslog-delivery).

Before choosing syslog audit, configure the receiver for records of up to 8 MiB plus framing. Version 1.0.0 supports explicitly configured rsyslog 8.2512 with gtls, `maxMessageSize="9m"` and imtcp `MaxFrameSize="9437184"`; default receiver settings are insufficient. Larger messages exceed RFC 5425's minimum interoperability baseline and a receiver may truncate or discard them. Follow the [receiver configuration and size limitation](architecture-1.0.md#syslog-delivery) and verify complete records at the receiver.

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

Audit records are read in deterministic segment and queue order, which can differ from chronological event order if the system clock moves backward. Audit output is escaped for terminals. `audit export` writes JSONL for external processing. `audit` without an action (`audit show`) prints every retained record in the same form; `audit tail` prints the last 100 records, and `--lines N` changes that number (a larger N is limited to 10000 and 0 or a negative N shows no records; fewer records are shown when fewer are retained). `netops version` prints the product version, and `netops selftest` prints the version and the MCP tool names of each role as JSON (13 Helper, 7 Auditor and 6 Admin tools). Redaction is explicit; audit is parsed protocol content rather than a raw byte transcript. Device output is sensitive even after credential redaction.

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

For subsequent supported 1.x updates: stop the old instance, preserve the same named data volume, replace only the verified manifest/image digest and release configuration, then start and verify tools plus audit. A running old instance over the same state is rejected. Follow the documented sequence through intermediate releases for older supported versions; skipping versions is not promised. For the first 1.0.0 there is no earlier 1.x upgrade. Never use `docker compose down -v` as an update step.

## Back up and restore state

Stop the source instance before copying its complete named volume. The archive contains private CA keys, the bearer token, role credentials and device data. Choose a new absolute backup filename in a private directory outside source checkouts. Keep the archive and its source manifest together, plus the verified Compose file, .env and image digest separately. The manifest contains metadata and hashes, not file contents.

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

The complete command must succeed before treating these files as a backup. A failed manifest or tar command can leave partial new files; do not restore them or overwrite an earlier backup. Investigate the failure and use a new backup filename for another attempt.

For a restore, prepare a separate instance directory with the same verified image and release configuration, the same server name and port, and its own .env. Use a different Compose project name so Docker creates a new state volume. An `init` run in the target project before can have left a skeleton in its volume (see above); restore needs an empty target and refuses any other. If the target volume is not empty, choose another new project name instead; do not remove an existing volume to make room for a restore. Keep the original stopped if it still exists and do not run init on the target. The original volume is not needed: the comparison uses the source manifest saved with the backup.

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

All commands must exit successfully; the service must be healthy and connection must show the original server name and port. Check the local history reported by audit stats, or, for syslog audit, verify the retained history at the receiver: on an instance initialized with syslog audit, audit stats then describes only the undelivered local queue; an instance switched to syslog audit after init still counts its frozen local segments in that history (see above). Use the original public CA, token and existing MCP client configuration to repeat the role reads used before the backup, including Auditor findings when present. Health alone does not verify role data. Confirm the expected role configuration and data before removing the source or backup. Restoring a backup is separate from upgrading a release.

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

For the file collection channel, set the Auditor inventory source to the printed snapshot path, retain its required_sections, and use the normal collect command. To apply the imported policy, add --policy /var/lib/netops/auditor/inputs/example-policy.policy.json to run or collect. Choose the policy before the device's first run or collect: a device already evaluated without it, or with another policy, is refused with `operator policy differs from this device history; use a separate store`, and MCP reads only the configured store, not a separate one. Configure the inventory through configure auditor as above. Imports and finished results persist in the same named volume across restart. Changing a policy still requires a separate store as described in the management-policy reference; importing a new filename does not migrate existing history.


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
