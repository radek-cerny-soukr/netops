# Installation and configuration

`netops-admin` runs from source on a Python 3.13 host that can reach the managed devices over SSH. It needs `netops-core` and `netops-auditor` of exactly the pinned versions beside it, and `fastmcp` only for the MCP surface.

## Install

1. Download the source archives of the three components from their releases in the repository: `netops-core` 0.2.3, `netops-auditor` 0.2.5 and `netops-admin` 0.2.0. Verify each archive against its `release-SHA256SUMS` and the Sigstore bundle, then unpack them.
2. Create a virtual environment with Python 3.13 and install the pinned dependencies with their hashes. The lock also carries the test and SBOM tools; `fastmcp` and its dependencies are the only ones the program uses.

   ```sh
   python3.13 -m venv /opt/netops-admin/venv
   /opt/netops-admin/venv/bin/python -m pip install --require-hashes -r netops-admin-0.2.0/requirements-release.lock
   ```

3. Install the three components without resolving dependencies again. `pip` writes build metadata (`*.egg-info`) into the directory it installs from, so install from copies and keep the unpacked archives unchanged; the gate of an archive refuses any file outside its release selection.

   ```sh
   cp -r netops-core-0.2.3 netops-auditor-0.2.5 netops-admin-0.2.0 build/
   /opt/netops-admin/venv/bin/python -m pip install --no-deps build/netops-core-0.2.3 build/netops-auditor-0.2.5 build/netops-admin-0.2.0
   ```

4. Check the installation and the unpacked archive:

   ```sh
   /opt/netops-admin/venv/bin/netops-admin --version
   (cd netops-admin-0.2.0 && /opt/netops-admin/venv/bin/python -B scripts/check_gates.py)
   (cd netops-admin-0.2.0 && /opt/netops-admin/venv/bin/python -B -m pytest -q -p no:cacheprovider)
   ```

After configuration, complete [enrollment and the first change](operations-020.md). Enrollment is mandatory and requires notification and audit export.

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
    "fw-lab": {
      "platform": "fortios", "address": "192.0.2.1", "host_key_fingerprint": "SHA256:<pin of the device host key>",
      "vault": "/etc/netops-admin/vault.json", "credential": "fw-lab-rw", "check_credential": "fw-lab-check",
      "accounts": ["netops-check", "netops-rw"], "safeguard_seconds": 180, "confirm_margin_seconds": 45,
      "protected": {"firewall address": ["all", "none"]}
    },
    "sw-lab": {
      "platform": "exos", "address": "192.0.2.2", "host_key_fingerprint": "SHA256:<pin of the device host key>",
      "vault": "/etc/netops-admin/vault.json", "credential": "sw-lab-rw", "check_credential": "sw-lab-check",
      "firmware": "33.7.1.6", "legacy_ssh": "rsa-sha1", "accounts": ["admin", "netops-check", "netops-rw"]
    }
  }
}
```

| Field | Meaning |
|---|---|
| `state_dir` | journal of operations, request evidence, device locks and blocks |
| `audit_file` | local audit log (JSON Lines, created mode 0640); it is the record, the exported copy is a supplement |
| `export_status_file` | status of the log shipper queue written by `scripts/export_status.py`; without it `audit_delivery` is `not-configured` and the export limits are not enforced |
| `notify` | ntfy server and a file holding `NTFY_TOPIC=<topic>`; `x509_strict: false` relaxes only the additional RFC 5280 checks of Python |
| `limits` | overrides of the defaults in [execution.md](execution.md#limits) |
| `devices.<alias>.host_key_fingerprint` | OpenSSH `SHA256:` pin; every connection checks the device key against it |
| `devices.<alias>.firmware` | required for ExtremeXOS and compared with `show version` before each change |
| `devices.<alias>.check_credential` | required: the credential of the read-only check account; it must log in as another account than `credential` |
| `devices.<alias>.check_address` | optional: another management address of the same device for the check account, so the check takes another path |
| `devices.<alias>.accounts` | ExtremeXOS: required, the complete list of accounts on the switch. FortiOS: the administrators the write account sees, by default only itself; name the check account here |
| `devices.<alias>.legacy_ssh` | `rsa-sha1` for a device that offers only an `ssh-rsa` host key |
| `devices.<alias>.safeguard_seconds` | 60 to 900, default 180; `confirm_margin_seconds` 15 to that value minus 15, default 45 |
| `devices.<alias>.audit_policy` | absolute path to the operator-owned Auditor policy; see [examples](operations-020.md) |
| `devices.<alias>.protected` | table → names the tool refuses to touch, including objects that refer to them |

## Audit export and notification

The audit log is shipped by a standard log shipper; the tool only reads the status file of its queue. For syslog-ng, `scripts/export_status.py --destination <destination> --output <status file>` reads the queue counter of the destination and is meant to run as root every 20 seconds from a timer. A stale, unreadable or over-limit status refuses new changes before any mutation.

## MCP client

Register the server with an MCP client as a stdio command; it inherits nothing from the client but the variables given here:

```json
{
  "command": "/opt/netops-admin/venv/bin/python",
  "args": ["-B", "-m", "netops_admin.mcp_server"],
  "env": {"NETOPS_ADMIN_CONFIG": "/etc/netops-admin/admin.json"}
}
```

If the client disconnects during an operation, the server finishes that operation before it exits; the result stays readable with `admin_status` or `netops-admin status`.

## Network

The tool does not restrict its own egress. Allow the admin host to reach only the managed devices over SSH, the notification server and the log collector, and allow the devices to accept the write account only from the admin host.
