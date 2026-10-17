# Installation and configuration

**Upgrade to 0.2.8:** Admin 0.2.8 changes the profile files and invalidates existing enrollment bindings for every device, including FortiOS and ExtremeXOS. After upgrading, run enrollment again for each device before applying changes. Enrollment uses the change budget.

These instructions install netops-admin 0.2.8 from its matching versioned source assets. Verify the release checksums and provenance before installation.

`netops-admin` runs on a host with Python 3.13 or newer that can reach the managed devices over SSH. It needs `netops-core` and `netops-auditor` of exactly the pinned versions beside it, and `fastmcp` only for the MCP surface.

## Install

Install from the release assets of the three components. Every file is verified against the signed checksums of its release page before it is installed.

This guide installs the signed GitHub source assets. PyPI publication is a separate workflow after GitHub; verify that all exact pinned versions are available before selecting that channel. The GitHub installation and its signed source checks remain usable independently of the index.

### From the release archives

1. Download the source archive of each component with the release `SHA256SUMS` and its Sigstore bundle from its release page: `netops-core` 0.2.9, `netops-auditor` 0.2.12 and `netops-admin` 0.2.8. Verify the bundle with [cosign](https://github.com/sigstore/cosign) and the archive against `SHA256SUMS`, and stop if either check fails. [Tools on the installing host](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#tools-on-the-installing-host) shows how to get `cosign` and Python:

   ```sh
   for release in netops-core:0.2.9 netops-auditor:0.2.12 netops-admin:0.2.8; do
     component=${release%%:*}
     version=${release#*:}
     base="https://github.com/radek-cerny-soukr/netops/releases/download/${component}%2Fv${version}"
     for name in source.tar.gz release-SHA256SUMS release-SHA256SUMS.sigstore.json; do
       curl -fsSLO "${base}/${component}-${version}-${name}" || exit 1
     done
     cosign verify-blob \
       --bundle "${component}-${version}-release-SHA256SUMS.sigstore.json" \
       --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
       --certificate-oidc-issuer https://github.com/login/oauth \
       "${component}-${version}-release-SHA256SUMS" || exit 1
     sha256sum --check --ignore-missing "${component}-${version}-release-SHA256SUMS" || exit 1
   done
   ```

   Each archive must report `Verified OK` from `cosign` and `OK` from `sha256sum`. The certificate identity and issuer are the maintainer's GitHub account, the same for every component; [Verifying a release](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#verifying-a-release) describes the check for any release asset. Then unpack the three archives; each unpacks into a directory of its own name and carries its own `SHA256SUMS` for the files inside it, which `sha256sum` checks in that directory; step 4 runs the gate of the unpacked admin archive, which also holds its file set against `release-manifest.json`:

   ```sh
   tar -xzf netops-core-0.2.9-source.tar.gz || exit 1
   (cd netops-core-0.2.9 && sha256sum -c SHA256SUMS) || exit 1
   tar -xzf netops-auditor-0.2.12-source.tar.gz || exit 1
   (cd netops-auditor-0.2.12 && sha256sum -c SHA256SUMS) || exit 1
   tar -xzf netops-admin-0.2.8-source.tar.gz || exit 1
   (cd netops-admin-0.2.8 && sha256sum -c SHA256SUMS) || exit 1
   ```

2. Run the installation as a regular user with sudo permission to create the application directory. Create `/opt/netops-admin` owned by that user before creating the virtual environment; the application directory is public code, while credentials and runtime configuration belong in separate private directories. The code-installation commands below use a local `umask 022`, even if the login shell defaults to `0002`; generated console scripts must not be writable by group or other. This does not change the shell umask used later for private configuration. Create a virtual environment with Python 3.13 or newer and install the pinned dependencies with their hashes; the first command stops when `python3` is older. The lock also carries the test and SBOM tools; `fastmcp` and its dependencies are the only ones the program uses.

   ```sh
   python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else "Python 3.13 or newer is required")' || exit 1
   sudo install -d -m 0755 -o "$(id -un)" -g "$(id -gn)" /opt/netops-admin || exit 1
   (umask 022; python3 -m venv /opt/netops-admin/venv) || exit 1
   (umask 022; /opt/netops-admin/venv/bin/python -m pip install --require-hashes -r netops-admin-0.2.8/requirements-release.lock) || exit 1
   ```

3. Install the three components without resolving dependencies again. `pip` writes build metadata (`*.egg-info`) into the directory it installs from, so install from copies and keep the unpacked archives unchanged; the gate of an archive refuses any file outside its release selection.

   ```sh
   build_dir=$(mktemp -d ./netops-build.XXXXXXXXXX) || exit 1
   cp -r netops-core-0.2.9 netops-auditor-0.2.12 netops-admin-0.2.8 "$build_dir/" || exit 1
   (umask 022; /opt/netops-admin/venv/bin/python -m pip install --no-deps "$build_dir/netops-core-0.2.9" "$build_dir/netops-auditor-0.2.12" "$build_dir/netops-admin-0.2.8") || exit 1
   rm -rf -- "$build_dir" || exit 1
   ```

   If installation stops, restore the missing prerequisite or network access and repeat steps 2 and 3. Step 3 creates a fresh build directory on each attempt, so files left by an earlier build cannot enter the installed packages. After a successful installation it removes only that attempt's source copies; an interrupted attempt may leave its disposable directory behind. Keep the verified source archives unchanged.

4. Check the installation and the unpacked archive:

   ```sh
   /opt/netops-admin/venv/bin/python -c 'from os import access,stat,X_OK; from stat import S_ISREG; from sys import argv,exit; p=argv[1]; s=stat(p); exit(0 if S_ISREG(s.st_mode) and access(p,X_OK) and not s.st_mode & 0o022 else "Unsafe askpass permissions")' /opt/netops-admin/venv/bin/netops-askpass || exit 1
   /opt/netops-admin/venv/bin/netops-admin --version || exit 1
   (cd netops-admin-0.2.8 && /opt/netops-admin/venv/bin/python -B scripts/check_gates.py) || exit 1
   (cd netops-admin-0.2.8 && /opt/netops-admin/venv/bin/python -B -m pytest -q -p no:cacheprovider) || exit 1
   ```

After configuration, complete [enrollment and the first change](operations-020.md). Enrollment is mandatory and requires notification and audit export.

### Installing without sudo

The existing virtual-environment installation also works in a user-owned directory. Choose `$HOME/.local/share/netops-admin` instead of `/opt/netops-admin`: create it as that user with `install -d -m 0700 "$HOME/.local/share/netops-admin"`, omit the `sudo install` command, and substitute the absolute user path in every environment, pip, askpass check, CLI and MCP command in steps 2-4 above. Keep `umask 022` on environment creation and pip installation so generated askpass launchers are not group- or other-writable; retain the pinned hash lock, fresh build-copy procedure and permission check. Keep credentials and runtime configuration in separate private directories. This alternative requires Python 3.13 or newer and venv to be available already; provisioning host prerequisites and a system log-shipper service may still require elevated privileges.

### Upgrading

Before upgrading or starting a new Admin version against a state directory, stop every older Admin CLI, MCP server, and service process using that directory. Older versions do not participate in the new flock on a file descriptor for the state directory itself and may still be writing an atomic temporary file when the new store initialization cleans orphaned temporary files. Mixed old/new version concurrency on one state directory is unsupported. Concurrent processes running the new version coordinate through flock on that directory descriptor; no persistent lock file is created.

The enrollment binding covers every profile file of the installed package, not only the profiles of the device's platform: `enrollment.binding()` hashes all of them together with the device, accounts, firmware, notification and export settings. An upgrade that changes any profile file therefore invalidates the enrollment of every device, FortiOS and ExtremeXOS alike. 0.2.5 was such an upgrade, because it enabled the FortiOS address group and DHCP reservation profiles on 8.0.0 build0167; 0.2.6 and 0.2.7 change no profile file. After it, `doctor` reports the enrollment as missing and `apply` refuses each device until `netops-admin enroll --config ... --device ... --probe ...` passes on it again; the enrollment counts against the device's change budget. At the same time, start `scripts/export_status.py` with `--audit-file` (see [Audit export and notification](#audit-export-and-notification)), so that the status names the audit log the destination reads; a status without it is still accepted, and `doctor` notes that it does not name the audit file.

## Write account on the device

Each managed device needs a dedicated write account that logs in with a key and is not used for anything else. The key is created on the admin host and never leaves it.

- FortiOS: an access profile with `fwgrp custom` (`address read-write`), `sysgrp custom` with `admin`, `cfg`, `mnt` and `upd` `read-write`, all other groups `read`, `cli-get`, `cli-show` and `cli-config` enabled, `cli-exec` and `cli-diagnose` disabled, and a trusted host limited to the admin host. Why `admin read-write` is needed and what it allows: [execution.md](execution.md#write-account-on-fortios).
- ExtremeXOS: an `admin` account with an RSA user key (`create sshd2 user-key`, `configure sshd2 user-key … add user`); the password hash given at creation should have no known password. Save the configuration only after a login with the key succeeded.

Each device also needs a read-only check account with its own key, created by a person with an administrator account, never by the write account:

- FortiOS: an access profile with `fwgrp read`, `cli-get` and `cli-show` enabled and every other group `none`, the trusted host limited to the admin host. The write account sees this account because its profile contains the check profile; name both in `accounts`.
- ExtremeXOS: a `user` level account with its own RSA user key and no known password.

The private keys go into a credential store of `netops-core` (`docs/vault.md` of that component) as a credential of kind `ssh-key` with the account as `login`. The file is read by the admin host only; keep it mode 0600 and never print it.

On FortiOS 8.0.0, operator provisioning of a local account can prompt for the current administrator password both after setting the new password and when committing the account with `next`. Complete these interactive confirmations before testing the key. Do not feed a 7.6 provisioning command list blindly into 8.0.0, disable reauthentication, or put the operator password into an Admin request or rollback script. Account provisioning is an operator procedure outside the Admin profiles. See the [FortiOS 8.0.0 local authentication guide](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/562247).

For DHCP operations, the write profile additionally needs `netgrp custom` with `netgrp-permission cfg read-write` (other network permissions can remain read), and the check profile needs `netgrp read`. These are network-wide permissions, not permissions limited to DHCP.

## Configuration file

One JSON file, mode 0600, names everything the tool may touch. The MCP server reads its path from the variable `NETOPS_ADMIN_CONFIG`; the command line takes `--config`.

```json
{
  "version": 1,
  "state_dir": "/var/lib/netops-admin/state",
  "audit_file": "/var/lib/netops-admin/audit/audit.jsonl",
  "export_status_file": "/run/netops-admin/export-status.json",
  "notify": {"server": "https://ntfy.example.invalid", "topic_file": "/etc/netops-admin/topic.env", "timeout_seconds": 10},
  "limits": {"changes_per_device_per_hour": 6, "changes_per_day": 40},
  "devices": {
    "example-firewall": {
      "platform": "fortios", "address": "192.0.2.1", "host_key_fingerprint": "SHA256:<pin of the device host key>",
      "vault": "/etc/netops-admin/vault.json", "credential": "example-firewall-rw", "check_credential": "example-firewall-check",
      "accounts": ["replace-me-check", "replace-me-write"], "safeguard_seconds": 180, "confirm_margin_seconds": 45,
      "protected": {"firewall address": ["all", "none"]}
    },
    "example-switch": {
      "platform": "exos", "address": "192.0.2.2", "host_key_fingerprint": "SHA256:<pin of the device host key>",
      "vault": "/etc/netops-admin/vault.json", "credential": "example-switch-rw", "check_credential": "example-switch-check",
      "firmware": "33.7.1.6", "legacy_ssh": "rsa-sha1", "accounts": ["replace-me-check", "replace-me-write"]
    }
  }
}
```

| Field | Meaning |
|---|---|
| `state_dir` | journal of operations, request evidence, device locks and blocks |
| `audit_file` | local audit log (JSON Lines, created mode 0640); it is the record, the exported copy is a supplement |
| `export_status_file` | status of the log shipper queue written by `scripts/export_status.py`; without it `audit_delivery` is `not-configured` and the export limits are not enforced |
| `export_status_require_audit_file` | optional boolean, `true` or `false` (default `false`); `true` refuses a status that does not name `audit_file`, with the reason `export status does not name the audit file (export_status_require_audit_file is enabled)`; `doctor` and `admin_status` show the value under `configuration` (see [Audit export and notification](#audit-export-and-notification)) |
| `notify` | ntfy server and a file holding `NTFY_TOPIC=<topic>`; `timeout_seconds` is a number from 1 to 60 (default 10); `x509_strict: false` relaxes only the additional RFC 5280 checks of Python |
| `limits` | overrides of the defaults in [execution.md](execution.md#limits) |
| `devices.<alias>.host_key_fingerprint` | OpenSSH `SHA256:` pin; every connection checks the device key against it |
| `devices.<alias>.firmware` | required for ExtremeXOS and compared with `show version` before each change |
| `devices.<alias>.check_credential` | required: the credential of the read-only check account; it must log in as another account than `credential` |
| `devices.<alias>.check_address` | optional: another management address of the same device for the check account, so the check takes another path |
| `devices.<alias>.accounts` | ExtremeXOS: required, the account names explicitly present in `create account` / `configure account` rows of `show configuration`; implicit accounts are outside this list. FortiOS: the administrators the write account sees, by default only itself; name the check account here |
| `devices.<alias>.legacy_ssh` | `rsa-sha1` for a device that offers only an `ssh-rsa` host key; `rsa-sha1-dh14` for one that also offers only SHA-1 key exchange. The profile applies to the host key scan as well as to `ssh`, see [SSH transport](../../netops-core/docs/ssh.md). No profile of this component lists such a device yet |
| `devices.<alias>.safeguard_seconds` | 60 to 900, default 180; `confirm_margin_seconds` 15 to that value minus 15, default 45 |
| `devices.<alias>.audit_policy` | absolute path to the operator-owned Auditor policy; see [examples](operations-020.md) |
| `devices.<alias>.protected` | table → names the tool refuses to touch, including objects that refer to them: an address group with such a member, a port tagged or untagged in such a VLAN (its VLAN membership and its display string) and a VLAN that holds such a port are not changed either. A name counts under any table, compared without letter case; see [planning](planning.md#refusal-rules) |

**Admin 0.2.8 contract:** `export_status_require_audit_file` and its `doctor`/MCP reporting are available in Admin 0.2.8. The setting defaults to `false`. Admin 0.2.7 does not provide this setting.

### ExtremeXOS account fingerprint boundary

The expected `accounts` list is compared with names parsed from explicit `create account` and `configure account` commands in `show configuration`. The enrollment fingerprint hashes only explicit `create account`, `configure account`, `create sshd2` and `configure sshd2` rows. An implicit factory `admin` with no such row is absent from both the parsed list and the fingerprint; changes not represented by these rows are outside this check. This configuration-row fingerprint is not a complete account inventory or proof that every credential and permission is unchanged. Include `admin` in the expected list only when it is explicitly represented by an account row.

## Audit export and notification

The audit log is shipped by a standard log shipper; the tool only reads the status file of its queue. For syslog-ng, `scripts/export_status.py --destination <destination> --output <status file>` reads the queue counter of the destination and is meant to run as root every 20 seconds from a timer. A stale, unreadable or over-limit status refuses new changes before any mutation. Start it with `--audit-file <audit file>`, the absolute path of the file the destination reads, equal to `audit_file` of the configuration: the status then names that file, and a configuration whose `audit_file` differs refuses the status (`the export status covers another audit file`). Every instance with its own audit log therefore needs its own destination, exporter and status file. Without `--audit-file`, the status omits its audit-file name. By default, `export_status_require_audit_file` is `false`, so an unnamed status is accepted with a `doctor` warning. Set this top-level option to `true` when the deployment must bind queue status to the configured audit log: an unnamed status is then rejected through the same admission path as a status naming another file. A matching name remains accepted. There is no CLI flag for this setting. `doctor` displays its configured value, and the Admin MCP `admin_status` config summary includes it. The exporter refuses to write the status file and its `<status file>.pending-since` companion over an existing FIFO, device node, socket or directory: it leaves it untouched and exits 1 with `export status not written`. A symbolic link there is replaced as before, never followed.

## MCP client

Register the server with an MCP client as a stdio command; it inherits nothing from the client but the variables given here:

```json
{
  "command": "/opt/netops-admin/venv/bin/python",
  "args": ["-B", "-m", "netops_admin.mcp_server"],
  "env": {"NETOPS_ADMIN_CONFIG": "/etc/netops-admin/admin.json"}
}
```

The server answers `initialize` with `serverInfo` `{"name": "netops-admin", "version": "0.2.8"}`, the name and version of the installed package.

If the client disconnects during an operation, the server finishes that operation before it exits; the result stays readable with `admin_status` or `netops-admin status`.

## Network

The tool does not restrict its own egress. Allow the admin host to reach only the managed devices over SSH, the notification server and the log collector, and allow the devices to accept the write account only from the admin host.
