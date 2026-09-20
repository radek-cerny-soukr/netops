# Onboarding

A first-time path from nothing to one read-only diagnostic call, linking to the documents that carry the actual rules instead of repeating them. [Installation](installation.md) remains the complete, authoritative procedure; this page is the short path through it plus the one command that catches a mistake in the operator files before anything is connected.

1. Read [Installation](installation.md) once, start to finish, before touching a device or a target account. It names the three trust zones this page will not repeat.
2. Create one dedicated, read-only account per target platform and verify on the real access path that it denies configuration mode, file writes, and shell escape - see [Read-only accounts](read-only-accounts.md) and [Installation §1](installation.md#1-prepare-target-accounts).
3. Install `netops_core` and `netops_helper` on the proxy host, or put their `src` directories on `PYTHONPATH` - see [Installation §2](installation.md#2-install-the-shared-access-layer-on-the-proxy-host).
4. Assemble the four operator files under `$XDG_CONFIG_HOME/netops-helper` (or the `NETOPS_*` paths), following [Configuration - the four operator files](configuration.md#the-four-operator-files) and, for the vault, [credentials and protocol use](configuration.md#credentials-and-protocol-use):
   - copy `config/inventory.example.json` to `inventory.json` and replace every documentation address, name, and pin;
   - create `vault.json` at mode `600` or `400`;
   - copy `config/egress-policy.example.json` to `egress-policy.json`;
   - copy `config/runner.example.json` to `runner.json`.
5. Run the [preflight command](#preflight-command) below. Fix whatever it names and re-run it until it passes.
6. Continue with [Installation §4 onward](installation.md#4-build-and-create-stopped-docker-resources): build the image, generate and apply the egress bundle, and start the service only after the checks, exactly in that order. The preflight command does not replace the egress review or the live negative tests; it only catches mistakes in the four files themselves, earlier and without touching anything.
7. Connect one dedicated read-only MCP session and follow [Installation §9, Validate the deployment](installation.md#9-validate-the-deployment).

## Preflight command

Run this after step 4 above, and again after any later edit to the four files, before repeating step 6:

```bash
python3 scripts/check_operator_config.py
```

It reads the same four files at the same `NETOPS_*`/`XDG_CONFIG_HOME` paths the proxy uses (pass `--inventory`, `--vault`, `--egress-policy`, or `--runner` to point it at files elsewhere first). Without contacting a device or opening a network connection, it confirms: the four files exist and vault permissions are mode `600` or `400`; all four parse and are the current schema; every helper-enrolled device carries the fields the helper section requires; every credential a device or the runner names actually exists in the vault, with a kind the helper accepts; the runner file names a valid host-key pin; and, when the egress policy profile is `lan-constrained`, that every enrolled device's address is covered by a declared LAN CIDR.

It stops at the first problem it finds. On success it prints `operator_config_check=passed devices=<n> credentials=<n>`. On failure it prints `operator_config_check=failed detail=<file>: <field or reason>`, naming the file and the field but never a credential value or a whole file, and exits with a non-zero status.

## Migrating an older (schema 1) configuration

Enrollment moved to the current shape - `inventory.json` and `vault.json` at file version 2, with the separate `egress-policy.json` and `runner.json`; see the top of [Configuration](configuration.md#the-four-operator-files) and the note at [Installation §3.6](installation.md#3-prepare-configuration-and-trust-on-the-proxy-host). A file still carrying `"version": 1`, or a leftover `target-policy.json`, is refused by name; there is no automatic migrator, and the preflight command will not silently reinterpret it either - it fails closed exactly like the proxy.

To move a `version: 1` (or pre-family, single-file) configuration forward without ever risking the original secrets:

1. **Copy, never edit in place.** Copy `inventory.json` and `vault.json` to new working paths outside the live configuration directory with a plain file copy, before changing a single field. Do not open and re-save the originals in a tool that might leave a backup or swap file next to them.
2. Reshape the **copies**, field by field, to match [Configuration - the four operator files](configuration.md#the-four-operator-files) and `config/inventory.example.json` / `config/vault.example.json`: bump `version` to `2`, add every field the current schema now requires (the helper section's `egress` object in particular), and remove every field the loader no longer accepts. Edit the JSON structure directly with a local editor; do not paste a vault entry's `value`, or any other file content, into a chat, an issue, a ticket, or any tool other than that editor - a value is a secret regardless of which schema version the file around it claims.
3. If the old configuration held everything in one `target-policy.json`, split its egress and runner data out into their own new files - see [Configuration - the egress policy file](configuration.md#the-egress-policy-file) and [the runner file](configuration.md#the-runner-file) for the exact shape each one now takes.
4. Set the vault copy's permissions to `600` or `400` before validating it; a permissive mode is refused before the content is even read.
5. **Validate the copies before they are live** by pointing the preflight command at them explicitly:

   ```bash
   python3 scripts/check_operator_config.py \
     --inventory /path/to/new/inventory.json \
     --vault /path/to/new/vault.json \
     --egress-policy /path/to/new/egress-policy.json \
     --runner /path/to/new/runner.json
   ```

   Repeat steps 2-4 until this passes.
6. **Replace only after it passes**: move the validated copies onto the live configured paths (a same-filesystem `mv` is atomic). Before the confirmation run below, move any leftover `target-policy.json` (and the old `version: 1` `inventory.json`/`vault.json`, if the atomic `mv` did not already overwrite them) out of the live configuration directory to the same backup location as the originals, with a plain file move - never delete them yet, and never leave them beside the new files. The preflight and the proxy startup path both call one shared check before touching a device, and it refuses a live configuration directory that still holds `target-policy.json` or has a retired `NETOPS_*` variable set, exactly as it would for a first-time enrollment; also unset any of those variables still exported in the shell that will run the service. Then run the preflight command again with no arguments to confirm the live files - and only those - are the ones just validated. Only then restart the service, following the guarded sequence in [Installation §7](installation.md#7-start-the-service-only-after-the-check).
7. Once the new files are confirmed live and working, securely delete the backed-up old `version: 1` files and `target-policy.json` moved aside in the previous step. Do not leave two live-looking copies of the vault on disk at once.
