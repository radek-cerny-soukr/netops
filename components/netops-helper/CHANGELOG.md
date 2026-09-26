# Changelog

The latest entry describes the current source version; earlier entries are historical source records. Use the repository release index for current downloads and commit history for superseded source. See the [release procedure](docs/releasing.md).

## 0.3.7 - 2026-09-26

- Pin `netops-core==0.2.5`: the host key scan asks for one key type at a time, so an IOS-XE device with five VTY lines is no longer refused (every call failed through the 0.3.6 runner on IOS-XE 17.18.2), and it copes with the comment line the OpenSSH 10.0p2 `ssh-keyscan` of the image writes to standard output.
- Accept `legacy_ssh: "rsa-sha1-dh14"` and pass it to the host key scan, so classic Cisco IOS devices that offer only SHA-1 key exchange become reachable; SHA-1 key exchange stays off for every other device. Measured on IOSv 15.9(3)M12 and IOSvL2 15.2.
- Accept `Ethernet<slot>/<port>` (abbreviation `Et`, 0-15) as a physical interface of `cisco_ios` and `cisco_xe`, the naming of Cisco router ports and of the IOL images.
- Report CLI refusals of Cisco IOS and IOS-XE (`Line has invalid autocommand "<command>"`, exit status 0), Arista EOS (`% Invalid input ... at line N`), Junos (`error: syntax error, ...`, `error: unknown command: ...`, `error: permission denied: ...`, `error: the <name> subsystem is not running`, exit status 0) and NX-OS (`Syntax error while parsing '...'`, `% Permission denied for the role`) as `device_cli_error`, as for FortiOS and ExtremeXOS; 0.3.6 returned them as successful reads. ExtremeXOS `Method is not implemented on this platform.` is `device_cli_error` as well.
- Publish the package on PyPI as `netops-helper`, for the client side: `pyproject.toml` gains the README as the package description, project URLs and classifiers, and declares the licence as the SPDX expression `MIT` with `license-files`; the README links its documents by absolute URLs and says at the top that the server runs as the container image, not from that installation. `.github/workflows/publish-pypi.yml` accepts `netops-helper/v*` tags.
- Documentation: the first live measurements of `arista_eos`, `juniper_junos`, `juniper_junos_els`, `cisco_xe`, `cisco_ios` and `cisco_nxos` on the vendors' virtual images, with the result of every catalogue query, in [live lab measurements](../../docs/lab-measurements-2026-09-25.md) and the [verified support matrix](../../docs/verified-support.md); measured sections in the vendor CLI references, the read-only account page and the reference index; the complete list of recognized CLI refusals in the security model, the tools reference and the README.

## 0.3.6 - 2026-09-21

- Accept `"parameters": null` in `ssh_read` as an absent key. The proxy refused it in argument validation and in the pre-auth scope check, although the server signature and the advertised tool schema allow `null`. A slot-less query now forwards, a query that needs a slot is still refused as `policy_scope`, and lists, strings, numbers and `null` slot values stay `invalid_params`; the new contract check failed on the unmodified proxy.
- Ship `restart: "no"` in `compose.yaml`. Docker no longer starts the container on its own, so after a reboot it stays stopped until the egress bundle is applied and checked. The persistence section of the egress documentation describes the unit that applies, checks and then starts the container, measured through a reboot, and how to recover when a manual change leaves the managed chain behind (`foreign_chain_collision`). Containers created from earlier releases keep `unless-stopped` until recreated.
- Document the DNS channel that remains with `allow_dns: false`: a unique name reached the upstream resolver through the Docker daemon while the managed chain saw nothing. For deployments with literal IP targets only, a Compose `dns` entry pointing at the documentation address `192.0.2.1` closes it; measured with the managed chain dropping the forwarded queries and `ssh_read` timing unchanged.
- Recommend `cli-show disable` for the Helper's FortiOS account. With `cli-show enable` a bare `show` returned the complete configuration, which the read-only requirements forbid, while every FortiOS catalogue query is a `get` or `diagnose` command. NetOps Auditor keeps `cli-show` under its own identity.
- Document that `sslvpn_sessions` and `sslvpn_statistics` are absent on FortiGate models without SSL VPN (Agentless VPN removed on 2 GB RAM models per the FortiOS 8.0.0 release notes) and report `device_cli_error` there; the catalogue descriptions say so.
- Describe how to use the published OCI archive: `docker load` accepts it only with the containerd image store; the classic store refuses it.

## 0.3.5 - 2026-09-21

- Make the malformed-request regression portable across Python parser builds. Deep, syntactically valid JSON arrays can reach the JSON-RPC object check (`-32600`) or hit the decoder nesting limit (`-32700`); both remain refused. Malformed JSON, invalid encoding and oversized input still require the exact parse-error category. The test explicitly exercises both decoder outcomes and confirms a valid request succeeds afterward. Runtime behavior and access boundaries are unchanged.
- Retain the fixes and eight opt-in diagnostics documented under 0.3.4 below. Core remains pinned at 0.2.3 and the runtime remains Python 3.14.7.

## 0.3.4 - 2026-09-21

- Add eight opt-in queries: EXOS `vlan_details` and `dhcp_snooping_entries`; FortiOS `certificate_details`; controller `managed_switch_status`, `managed_switch_poe`, `managed_switch_mac`, `managed_switch_stacking` and `managed_switch_lldp`. Selectors require separate `vlans`, `certificates` or `managed_switches` inventories and independent proxy/server checks. No query is enabled automatically.
- Document the direct CLI evidence and its limits. EXOS VLAN reads preserve valid status 250. Four controller queries returned data with an administrator account; restricted-profile permissions remain unverified. Stacking was correctly refused on non-stacking hardware, and a positive test remains outstanding. The new queries have not been verified end-to-end through MCP. No FortiAP query is added.
- Report known FortiOS/EXOS CLI refusals as `device_cli_error`, including FortiOS errors with SSH status zero; preserve the actual status and bounded sanitized output, audit failure and prevent failed-result pagination caching.
- Retain only credentials needed by the selected target or runner. The JSON store is still parsed transiently in full; separate trust domains require separate stores.
- Enforce FTP/FTPS listing bounds of 500 names, 2,000,000 received bytes and one 30-second deadline, closing both channels on failure. Plain FTP acknowledgement and TLS verification remain required.
- Pin Core 0.2.3, refresh runtime dependencies including FastMCP 4.0.5, and apply available Debian package upgrades during image builds.
- Move the ARM64 container and Helper CI to digest-pinned Python 3.14.7 to fix CVE-2026-82049. Regenerate both Helper locks without further package-version changes and add malicious/valid TAR regressions. The host interpreter remains the operator's responsibility.
- Record 361 passing tests and 321 subtests on Python 3.14.7, clean source-export installation and positive/negative MCP checks in the final image. The Python 3.13 toolbox passes 360 tests and skips the runtime-specific TAR regression, which is checked separately in the shipped image.
- Disclose the dated scan: 0 active Critical, 50 High, 58 Medium, 10 Low, 68 Negligible and 1 Unknown matches, plus the existing accepted Critical OpenSSH exception. Remaining findings are not claimed fixed; see [known vulnerabilities](docs/known-vulnerabilities.md).


Versions on this page name the Helper component; tags use `netops-helper/vX.Y.Z`.

## 0.3.3 - 2026-09-20

Follows `netops-core` 0.2.2, pinned as `netops-core==0.2.2`. The proxy is installed as a command,
and the egress apply helper works on a host whose `iptables-save` is the nftables one.

- `netops-helper-proxy` is installed as a console script. The proxy moved into the package as
  `netops_helper.proxy` (with `netops_helper.proxy_sanitize`), and `scripts/remote_mcp_proxy.py`
  stays as the launcher that runs it from an unpacked archive without installing anything. A client
  is now configured with a command rather than an absolute path into an archive.
- The proxy no longer requires its own file to be executable when it authenticates the runner with
  a key. It hands the runner password to the client by re-executing itself as the askpass program,
  and the check for that was made before the credential kind was known, so an installed proxy -
  whose module file has no execute bit - refused to start even with a key. The program is now the
  first executable entry point among `sys.argv[0]` and the module file, and it is required only for
  a password.
- `scripts/apply_egress_rules.py` called `iptables-save --wait 10`. That utility has no such option
  in iptables 1.8.10, so the apply step ended in `host_command_failed` on any host with the
  nftables-based tools, and the documented installation could not be completed there. The option is
  gone, the lock the script already holds is what serialises it, and the fake runner in the tests
  now rejects options the real utility does not know.
- `ssh_read` is documented as taking the catalogue platform name, the one `target_scope` reports,
  not the canonical inventory name.
- `installation.md` and the root README say that the helper archive needs the core archive
  installed beside it: its vendored copy of `netops_core` is there for the image build and does not
  satisfy the pin for `pip`.
- `known-vulnerabilities.md` records that CVE-2026-82049 is a package match without a reachable
  path: the flaw is in `tarfile`, which no runtime source and no release script imports.
- `read-only-accounts.md` states what was measured on Unleashed 200.13: its configuration context has
  no command that creates a second administrator or assigns a role, so the platform cannot offer a
  read-only account at all. That is a property of the device, and an enrollment always carries the one
  administrator.
- The support matrix records three live measurements taken with this code: the `linux` platform
  answering `kernel` and `hostname` on a real host, SNMPv2c against ExtremeXOS with a temporary
  read-only community, and the EXOS rule catalogue running over a live `collect`.

## 0.3.2 - 2026-09-20

Follows `netops-core` 0.2.1, pinned as `netops-core==0.2.1`.

- The proxy startup preflight and `scripts/check_operator_config.py` now share one function,
  `netops_helper.legacy_configuration.legacy_configuration_detail`, to detect a leftover
  `target-policy.json` or a retired `NETOPS_*` variable: the preflight used to accept a
  configuration directory the proxy then refused at startup, and both paths now fail closed with
  the same explanation before either one touches a device or the network
  (`docs/onboarding.md`).
- The image is built on a refreshed digest of the `python:3.13.15-slim-trixie` base image. The scan
  of the rebuilt image carries one reviewed Critical entry under `ignoredMatches` (CVE-2026-60002 in
  `openssh-client`, the accepted exception) and actively 51 High, 58 Medium, 10 Low, 68 Negligible
  and 1 Unknown entries under `matches`; the seven Critical entries of the base image that the gate
  used to ignore are fixed in the refreshed base and no longer appear. `docs/known-vulnerabilities.md`
  now describes the current image only: its scan, the one exception and its end condition, and why
  two `openssh-client` entries the scanner rates High describe `sshd` code the image does not carry.
- `docs/read-only-accounts.md` and the repository's `docs/verified-support.md` record that the
  slotted `inline_power_port` query was measured under the user-level ExtremeXOS account (exit
  status 0, 195 bytes for one enrolled port), so every query of that catalogue has now met the
  device under that account; `docs/configuration.md` lists `ruckus_unleashed` among the canonical
  `ssh_platform` names.

## 0.3.1 - 2026-09-20

Follows `netops-core` 0.2.0, pinned as `netops-core==0.2.0`.

- The release export's `compose.yaml` now builds from the archive root (`context: .`) with the
  Dockerfile's own defaults, instead of `context: ../..`: an unpacked archive builds with
  `docker compose build --pull=false` on its own, without the two build arguments the
  in-repository Compose file passes. `scripts/check_public_release.py` gates the exported `build:`
  block itself - the context, the Dockerfile relative to it, and `CORE_PACKAGE_DIR/__init__.py` -
  so a compose file that stops building stops the release, not just the running container.
- The image installs the packaged askpass program, `netops_core/askpass.py`, as
  `/usr/local/bin/netops-askpass`, and sets `NETOPS_ASKPASS_PROGRAM` to it, so password
  authentication keeps working under this Compose file's `noexec` `/tmp` and `/run`
  (`docs/installation.md`).

## 0.3.0 - 2026-09-19

The helper moves onto `netops-core`, the shared access layer of the family. Enrollment is now one inventory and one credential store shared with the other components, host key trust is a pin instead of a file, and the runner is named by a file of its own.

### Breaking changes

- `ssh_read` runs the OpenSSH client of `netops-core` instead of Netmiko. The dependency, the imports, the read-only FortiOS subclass and the device-type table are gone, and no vendor session driver sits between the catalogue and the device any more. Two modes: one `ssh` process per command (`netops_core.ssh.run_command`) for every platform with an exec channel, and one `ssh -tt` pseudo-terminal (`netops_core.session.Session`) for a platform without one. Which mode a platform uses is a table in the code, never a field of the configuration.
- `extreme_exos` is the only platform with a preamble: `disable cli paging` is sent as its own command before the query, the way the auditor sends it. Every other platform sends the catalogue command and nothing else, FortiOS included, which is why FortiOS still requires the externally verified `output standard`.
- The host key pin is verified with `netops_core.hostkey.scan` (one `ssh-keyscan` against the enrolled address) for both `ssh_read` and `sftp_stat`.
- `sftp_stat` runs the OpenSSH `sftp` client of `netops-core` (`netops_core.sftp.stat`) instead of asyncssh, with the hardening options, the workspace, the askpass file and the `legacy_ssh` profile of the `ssh` path. **asyncssh is gone** from the imports, from `pyproject.toml` and from `requirements.txt`; the helper now has no SSH library at all, only the client. The image needs `sftp` beside `ssh` and `ssh-keyscan`, and the health check refuses to report healthy without it.
- **The answer of `sftp_stat` changed shape.** It now carries `kind` (`file`, `symlink`, `other` or `directory`) and, for a directory, `entry_count` instead of `size`/`mode`/`modified_utc` - never the names of the entries, because the client has no `ls -d` and lists a directory's content. For everything else it carries `size`, `mode` and `modified_ls`. `modified_utc` is gone: the client prints the timestamp with the precision of `ls` (`Sep 10 02:26`, or `Sep 10  2024` for an older path, in the client's time zone), which is not a unix modification time, and the field is named after what it is.
- The SFTP batch is a single `ls -ln` of one quoted path written to the client's standard input, never a `-b` file: measured on 17 September 2026 with OpenSSH 9.2p1, `-b` makes `sftp` append `BatchMode=yes` to the `ssh` command line, and `BatchMode=yes` disables the askpass program a password authentication needs. `netops_core.sftp` refuses a path carrying a quote, a line break, a NUL or leading or trailing whitespace before it writes that line, after the helper has checked the path against the enrolled roots.
- The answer of an exec `ssh_read` has the device prompt removed by the shared `netops_core.prompt`, which knows `#` and the `$` a FortiOS read-only account answers with (measured 17 September 2026, FortiOS 8.0.0). Only the first line and trailing lines equal to that prompt are touched, on the platforms the table names; everywhere else it changes nothing, and the pseudo-terminal path of Ruckus Unleashed is untouched.
- New platform `ruckus_unleashed` with four parameter-free queries (`show sysinfo`, `show ethinfo`, `show ap all`, `show wlan all`). It is the platform without an exec channel: the helper answers its in-shell login, discards every byte of that phase, sends `enable`, sends the query and ends by closing the terminal - never `exit`, which saves in a configuration context. `show config`, the `debug` context and `show performance ...` are deliberately excluded.
- `ssh_read` results carry `transport` (`exec` or `pty`) and `rc`, and both fields reach the audit record. A device command that ends with a non-zero status returns its output instead of failing; only a failure of the client itself (exit status 255, timeout, refused negotiation) fails the call.
- The SFTP evidence is a substituted `sftp` on `PATH` as well: `tests/test_engine_safety.py` asserts the argument vector, the environment, the bytes of the batch, the known-hosts line, the absence of the secret from both argument vector and environment, the legacy options only with an enrolled profile, and a directory answered with a count and no name.
- The wire evidence moves from Netmiko to the client: `tests/test_fortios_wire_safety.py` and `tests/test_netmiko_wire_safety.py` are replaced by `tests/test_ssh_wire_safety.py`, which substitutes `ssh` and `ssh-keyscan` on `PATH` and asserts per platform the exact argument vector, the environment, the known-hosts line, the askpass path of a password, the mode of a key file, the legacy options only with an enrolled profile, and the bytes of the terminal conversation.
- The image installs `openssh-client`; without `ssh` and `ssh-keyscan` the health check fails.
- Proxy: a transport diagnostic on standard error is written only when the SSH child exits non-zero or times out; a clean end of the session no longer reports `ssh_transport` because the remote server wrote its start-up banner to standard error.
- The device enrollment moves to `inventory.json`, the device document of `netops_core.inventory` (file version 2). A device belongs to the helper when its `helper` section is an object; the alias a client uses is the device `name`.
- The credentials move to `vault.json`, the credential document of `netops_core.vault` (file version 2). A device names a record of kind `password` or `ssh-key`, and SNMP is a separate record of kind `snmp-community` named by the new optional `snmp_credential`.
- `target-policy.json`, `NETOPS_TARGET_POLICY_PATH`, `NETOPS_KNOWN_HOSTS_PATH` and `NETOPS_MASTER_ALIAS` are gone. A run that finds one of those files or variables fails closed and names the new files; there is no fallback and no migration tool.
- There is no `known_hosts` file on either side. Every device carries `host_key_fingerprint` in the inventory, and the server verifies that pin against the key the device offers before any credential is used.
- The runner is described by `runner.json` (`version`, `host`, `port`, `credential`, `host_key_fingerprint`); it has no inventory entry and can never be addressed as a target. Its pin is verified locally with `ssh-keyscan` before `ssh` starts.
- The firewall inputs move to `egress-policy.json`, exactly the eight fields of the former reserved `_egress` object, and the egress generator reads the inventory and that file only, never the vault. Its manifest records `inventory_sha256` and its command line takes `--inventory` instead of `--vault`.
- The proxy-to-server envelope is version 0.3.0: it carries `credential_kind`, `secret` and `host_key_fingerprint`, and the old `known_hosts` and `password` keys are refused as unsupported fields, so an old proxy fails closed instead of half-working.
- The audit field `target` is renamed `device`, and the dead fields `max_hops` and `use_basic_auth` are gone.
- SSH and SFTP refuse `ssh-rsa` host keys and SHA-1 key exchange for every device unless the common inventory field `legacy_ssh` names the `rsa-sha1` exception for that one device; a profile requires a host key pin.
- Key authentication is supported for devices and for the runner: the private key text lives in the credential store and reaches the OpenSSH `ssh` and `sftp` clients only as a mode-`600` file in a private temporary directory that is removed with the operation.
- `target_scope` renames `ssh_host_key_enrolled` to `host_key_pinned`, which is always true because a device without a pin is refused, and replaces `snmp_configured` with `snmp_enrolled`.

### Connection pacing

- Every SSH-family connection the server opens to one device - a keyscan, an exec `ssh`, a PTY session, an `sftp` call - now goes through exactly one queue per `(address, port)`, never in parallel; a connection waits until a per-platform spacing has passed since that device's previous connection started. The spacing is a table in the code, `_CONNECTION_SPACING_SECONDS`, the same way the transport table is: FortiOS carries five seconds, and a platform absent from the table carries none. This is the fix for the 26-connections-in-a-row refusal recorded in `docs/read-only-accounts.md`.
- The host key line a keyscan returns is now cached for ten minutes per `(address, port, host_key_fingerprint)`, capped at 64 entries. A cache hit skips the keyscan connection entirely, so a query after the first against an already-scanned FortiOS device needs only the `ssh` connection, not both. A client failure forgets the cached line for that device so the next call scans again, and a host key that actually changed is reported by name instead of surfacing as an unrelated client failure.
- `sftp_stat` is paced by the target's enrolled `ssh_platform`, since the tool has no query-platform argument of its own.

### Catalogue

- Catalogue: +10 FortiOS, +15 EXOS queries, measured with read-only accounts. The catalogue grows from 253 to 278 named templates; FortiOS goes from 30 to 40 and Switch Engine from 32 to 47. FortiOS gains `ntp_status`, `system_top`, `autoupdate_status`, `autoupdate_versions`, `sslvpn_sessions`, `sslvpn_statistics`, `firewall_auth_users`, `ips_filter_status`, `ips_anomaly_status` and `av_outbreak_stats`; Switch Engine gains `stacking`, `stacking_support`, `inline_power`, `inline_power_port`, `access_list_counters`, `qos_profiles`, `licenses`, `ntp`, `sntp_client`, `sessions`, `elrp`, `mcast_cache_summary`, `mirror`, `edp_neighbors` and `stp_detail`. Every one of them except the slotted `inline_power_port` was run on 17 September 2026 against FortiOS 8.0.0 and ExtremeXOS 33.7.1 with a read-only account and ended with exit status 0; `inline_power_port` is accepted from the documented grammar and awaits its own live test.
- `system_top` pins all three arguments of `diagnose sys top`. The vendor default iteration count is unlimited, so the read policy now refuses every `diagnose sys top` form but the fixed `diagnose sys top 1 5 1` snapshot, even if one is added to the catalogue.
- The measured refusals are recorded as facts, not as candidates: `execute dhcp lease-list` (`Unknown action 0`, the `execute` branch stays excluded), `show stacking configuration` and `show inline-power info ports all` (`%% Unrecognized command` on 33.7.1), `show accounts` (no permission for a user-level account) and `show ip-security dhcp-snooping entries` (`%% Incomplete command`; it needs a VLAN and Phase 1 has no VLAN inventory type).

### Documentation and packaging

- `docs/vendor-cli-references/ruckus-unleashed.md` records the new platform. Its vendor guide is reachable only behind a vendor login, so the source registry carries no URL for it and states the date the syntax was run on a device instead; the renderer and the release gate accept that third source kind and nothing else without a link.
- `docs/read-only-accounts.md` replaces the Netmiko session-driver caveat with what the client actually sends, and adds a Ruckus Unleashed section saying plainly that no read-only account model was verified on that device and that its `show` commands sit in the same context as `reboot`. The FortiOS paragraph no longer claims that `ssh-rsa` is refused everywhere; the `legacy_ssh` exception has existed since 13 September 2026.

- `docs/configuration.md` is rewritten around the four operator files and links the shared `docs/inventory.md` and `docs/vault.md` of `netops-core` for the common parts; `config/target-policy.example.json` is replaced by `config/inventory.example.json`, `config/egress-policy.example.json`, `config/runner.example.json` and `config/vault.example.json`.
- The client installs `components/netops-core/src` and `components/netops-helper/src`, and the image is built from the repository root.
- New module `src/netops_helper/inventory.py` holds the frozen `HelperSection` and every cross-check, shared by the proxy and the egress generator.

### Known vulnerability shipped unfixed

- **The image carries CVE-2026-60002 in `openssh-client` and this release does not fix it.** The transport of 0.3.0 is the OpenSSH client, so the image installs the `openssh-client` package of the digest-pinned Debian trixie base, and the version trixie ships (`1:10.0p1-7+deb13u4` at the release scan of 18 September 2026) has a Critical use-after-free in the `ssh` client that a *server* can trigger by changing its host key during a key re-exchange. The fix is upstream OpenSSH 10.4; trixie stays on 10.0 and Debian rates the issue no-DSA, minor, so no package update fixes it and this project cannot fix it either without leaving the pinned distribution. It is accepted as a reviewed, dated exception: the only servers the client ever talks to are enrolled devices with a pinned host key, every call is one short unprivileged process in a read-only container with all capabilities dropped, and a device that triggers the bug is a compromised enrolled device, which the security model already treats as hostile input. Read `docs/known-vulnerabilities.md` before deploying; an operator who cannot accept that exposure must rebuild the image on a base that ships OpenSSH 10.4 or newer, or not deploy this release. The exception is re-reviewed at every release and dropped the moment trixie ships OpenSSH 10.4 or newer.

## 0.2.3 - 2026-09-12

Structural release for the move into the `netops` monorepo. No tool surface, query catalogue, policy schema, dependency, or runtime behaviour changes; every source file of the component is byte-identical to 0.2.2.

### Release engineering

- Move the component into `components/netops-helper/`. Paths inside the release archive are unchanged, so `src/`, `tests/`, `scripts/`, `docs/`, and `config/` keep their layout.
- Drop `SECURITY.md`, `CONTRIBUTING.md`, and `.github/workflows/ci.yml` from the component release archive. They are repository-level files of the `netops` monorepo and are checked by the repository gate `scripts/check_release.py`.
- Carry `LICENSE` as a component copy; the repository gate verifies that every component copy is byte-identical to the repository `LICENSE`.
- Split `.gitignore`: the deployment-specific entries (`config/target-policy.json`, container trust material) stay with the component, the repository-wide ones (`vault.json`, `known_hosts`, `.env`, build output) move to the repository root.
- Move the repository-level checks out of `scripts/check_public_release.py`: workflow SHA pinning, the CI contract, and "no tracked file outside the release allowlist" now run in `scripts/check_release.py` over the whole monorepo, where they can see every component instead of only this one.

## 0.2.2 - 2026-09-12

Release engineering release for the repository rename and the component tag scheme. No tool surface, query catalogue, policy schema, dependency, or runtime behaviour changes.

### Release engineering and tests

- Rename the repository to `radek-cerny-soukr/netops`; the old `netops-helper` URLs redirect. Update the OCI `org.opencontainers.image.source` label and its release test to the new URL.
- Tag component releases as `netops-helper/v<version>` with the release title `netops-helper <version>`. Earlier releases used an unprefixed tag scheme. Those tags have since been removed under the current retention policy; their source commits remain in history.

### Fixes

- Write the `.gitignore` entries for `vault.json`, `known_hosts`, and `.env` as real lines. They were committed as a single line containing literal `\n` sequences, so those ignore rules were never applied.

## 0.2.1 - 2026-09-11

Hardening release driven by an independent code audit of 0.2.0. No tool surface, query catalogue, or policy schema changes; every finding was fixed with a regression test and verified in the ARM64 toolbox.

### Security

- Hand the runner password to the askpass helper once over a per-session abstract Unix socket with peer-UID checking instead of exporting it into the `ssh` process environment for the whole session.
- Redact every message the server emits, including notifications, server-initiated requests, and responses with unknown ids, using all credentials, SNMP communities, and authentication envelopes seen during the session.
- Treat the injected `auth_context` envelope as a secret so that an echoed envelope can no longer expose a target password.
- Open the device SSH/SFTP TCP connection to the egress-verified address and pass the hostname to Netmiko and asyncssh only for host-key matching, removing the second unverified DNS resolution.
- Stop the community and bearer redaction patterns at line breaks, add Cisco type-7 (`key 7`, `md5 7`, `password 7`, `key-string 7`) and pre-shared secret patterns to the server redactor, and redact bare `token=` assignments in the proxy.
- Bind the SSH continuation cache key to the credential digest and reject symlinked or non-regular vault files.

### Robustness

- Survive malformed or oversized client lines: deeply nested JSON no longer terminates the proxy, and lines above 1 MiB are rejected with a parse error.
- Guard the final `child.wait` after `kill` and expand `~` in `NETOPS_*` path variables.
- Record the canonical platform name in both audit records of an operation.

### Egress firewall

- Emit the ICMP echo-request rule with the numeric type that `iptables-save` renders (`--icmp-type 8`); bundles with `allow_icmp: true` previously failed the post-apply check and rolled back.
- Require the DOCKER-USER jump to be the first FORWARD rule in both the checker and the apply helper; an earlier ACCEPT would bypass the managed chain.
- Document embedded-DNS traffic outside the managed chain, the absence of reboot persistence together with a oneshot unit example, and fail-closed behaviour on iptables backend mismatch.

### Release engineering and tests

- Pin the upstream Netmiko session preparation on the wire for Cisco IOS/IOS-XE/NX-OS, Arista EOS, Junos, Junos ELS, Extreme EXOS, and Linux with a real Paramiko server, alongside the existing FortiOS wire test.
- Make the SFTP path-confinement test discoverable by pytest and scan `query_catalog/` in the write-marker contract.
- Fail the public release gate on tracked or unignored files outside the export allowlist, on credential-shaped material, and on CGNAT, link-local, ULA, and `.local`-style private network markers; scan lock, requirements-in, shell, and config files; ignore `vault.json`, `known_hosts`, and `.env`.
- Uninstall `pip` from the runtime image after the hash-locked install and add OCI title, source, and licence labels.
- State in the security model that the server validates envelope shape and policy, not origin, and document the per-alias rate window and the fixed engine limits and timeouts.

## 0.2.0 - 2026-09-10

Second public release. This release keeps phase 1 deliberately read-only while making the enrolled diagnostic scope discoverable and substantially expanding bounded troubleshooting coverage.

### Breaking capability boundary

- Remove the generic `https_get` and `sftp_read_text` body-read tools from Phase 1. Retain certificate-only `tls_probe`, metadata-only `sftp_stat`, and directory-name-only `ftp_list`.
- Remove the `route_trace` traceroute tool that 0.1.0 registered. Bounded reachability now relies on `icmp_probe`, `tcp_probe`, and enrolled routing, neighbor, and forwarding queries; the release gate rejects any tool reintroducing it.
- Reject the legacy `https_endpoints` target-policy key as an unknown field instead of silently ignoring it. Deployments upgrading from 0.1.0 must remove that key before enrollment succeeds.
- Reserve HTTP response bodies, remote file contents, and any future configuration read for a separately designed Phase 2 threat model and execution boundary.

### Operability

- Add alias discovery to `helper_status` and a credential-free but topology-sensitive `target_scope` view of each enrolled inventory, metadata/listing root, and egress destination.
- Distinguish proxy policy, credential, vault-permission, rate-limit, transport, and remote-process failures, and derive fixed categorized transport diagnostics from sanitized SSH stderr without relaying the raw stream.
- Raise the default per-target request budget for normal troubleshooting and keep SSH continuation pages within one bounded snapshot instead of reconnecting or rerunning the command.
- Add stable SSH snapshot digests, explicit pagination metadata, a bounded cache lifetime, and fail-closed handling when complete SSH output exceeds the two-megabyte safety ceiling.

### Query policy

- Replace the small shared network catalogue with one authoritative modular registry for Linux, FortiOS, Extreme Switch Engine, Cisco IOS, IOS-XE and NX-OS, Arista EOS, and Junos with and without ELS.
- Add reviewed operational queries for interfaces, routes, neighbors, forwarding tables, discovery protocols, link aggregation, spanning tree, environmental state, HA and routing protocols where supported.
- Bind every parameterized query to typed per-target inventories with vendor-specific interface grammars and canonical IPv4/IPv6 validation.
- Publish deterministic query metadata, descriptions, typed slots, and high-volume scheduling hints from the same registry used by authorization and rendering. Vendor source references are published in the generated catalogue documentation, not in the runtime metadata.
- Continue to forbid running, startup, full, backup, and exported configuration; arbitrary CLI, general log browsing, debug, capture, support bundles, shell, remote file-content access, and write or maintenance actions remain outside phase 1. Traceroute leaves phase 1 with `route_trace`.

### Security

- Give SNMPv2c a dedicated optional `snmp_community`; never fall back to the SSH password and reject enrollment that reuses the same secret.
- Inject only host-key records matching the selected target and harden the proxy SSH invocation against user configuration, forwarding, multiplexing, proxying, environment forwarding, and interactive terminal allocation.
- Remove the temporary askpass executable; credentials now remain in a bounded child environment and are removed before remote container execution.
- Write a durable audit `started` record before every device operation and a linked terminal record afterward; an unavailable mandatory audit sink fails closed with an explicit audit error.
- Refine best-effort redaction so ordinary log prose remains readable while explicit password, community, token, private-key, and FortiOS encrypted-payload forms are removed.
- Keep the FortiOS no-paging-write driver and add a mock SSH wire test that verifies only the enrolled diagnostic command reaches the channel.

### Egress and deployment

- Give the Docker bridge a stable host interface name, disable IPv6 on that network, and add secret-free schema-validated generation, transactional application, rollback, and live checking of IPv4 DOCKER-USER egress rules.
- Derive egress destinations from the enrolled vault and policy, support a documented RFC1918-only intermediate profile, and require applying and checking host rules before the helper container starts.
- Document the residual runner INPUT path, the intentionally external bridge, private/self-signed CA image workflow, complete vulnerability-report burden, and upstream Netmiko session-preparation risk.
- Document the separate runner and target vault records, shared target credentials across SSH/SFTP/FTP transports, exact global egress schema, stock runner authentication contract, and FTPS pin semantics.

### Release assurance

- Expand dependency-free policy parity, proxy, query-catalogue, vendor-reference, sanitizer, egress, audit, pagination, and supply-chain contracts.
- Generate the public query catalogue deterministically and fail the release when registry, documentation, proxy, authorization, generator, or engine policy diverges.
- Make the public source export an integrity-manifested allowlist and recursively reject phase-1 configuration export or write implementations.
- Require the full runtime suite, including the FortiOS wire test, in hosted CI and the isolated ARM64 release gate.

## 0.1.0 - 2026-09-09

First public release.

### Security model

- Bind HTTPS GET to exact per-target path, port, and Basic-auth policy entries.
- Use a FortiOS read-only session driver which skips Netmiko paging writes and disables SHA-1 KEX.
- Audit every device-touching tool with secret-free operation metadata.
- Use a generic system-trust healthcheck and reject hard-coded environment trust files in release checks.
- Reject the runner master alias as a target and confine FTP/FTPS paths to configured read roots.
- Harden JSON-RPC proxy shape, error, batch, duplicate-ID, and bidirectional ID handling.
- Expand best-effort secret patterns, add per-target request limiting, and cache SSH continuation pages.
- Document the standard bridge's unrestricted egress as a residual risk requiring host/network ACLs.

- Ship phase 1 as a standalone read-only MCP server with no write, prepare/apply, upload, restart, or configuration tools.
- Require externally enforced read-only target accounts and explicit per-target enrollment.
- Replace raw and exact-string command input with named query templates and typed, inventory-bound slots.
- Preserve diagnostic IP, IPv6, MAC, hostname, username, email, and serial values while redacting explicit credentials, tokens, private keys, and FortiOS `ENC` payloads.
- Add explicit byte pagination and whole-content digests instead of silent 4 kB truncation.
- Mark device responses as untrusted data and require a dedicated read-only agent/session without broader tools.
- Keep the distribution agent-vendor neutral and expose the server through standard MCP stdio.
- Use verified SSH host keys, an isolated non-root/read-only container, secret-free bounded audit logs, hash-locked dependencies, a digest-pinned base image, SBOM generation, and release checks.

### Scope

- Provide bounded DNS, TCP, ICMP, traceroute, TLS, HTTPS, SSH, SNMP, SFTP-read, and FTPS/FTP-list diagnostics.
- Document deliberate non-capabilities, read-only account requirements, target inventory policy, prompt-injection handling, release procedures, and residual risks.
