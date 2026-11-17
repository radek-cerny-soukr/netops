NetOps 1.0.11 follows NetOps 1.0.10. It removes the remaining conversion paths for data from before NetOps 1.0 (Auditor `migrate-store` and `migrate-suppressions`, Admin plans of 0.x), returns a failed Junos change at once with a plain commit that the device timer cannot undo, makes the release signing tool print its whole check table when the release manifest lacks a key, limits the release tooling to the 1.0.x series and describes an installation without sudo rights.

## Changes in 1.0.11

### Removed

- Auditor no longer converts stores and suppression files of the format before NetOps 1.0: the operator commands `auditor migrate-store` and `auditor migrate-suppressions` are removed, and the Auditor command line refuses them (`invalid choice`, exit status 2). A store without a schema version or with a schema version other than 2 is refused before any write, also before the switch to WAL, and its file stays unchanged: `store schema version N, expected 2; this store format is not supported`, or `store holds audit tables without a schema version, expected 2; this store format is not supported`. The Auditor MCP server refuses such a store with `this store format is not supported` instead of pointing to the conversion. A suppression file of version 1 is refused with `unknown suppression file version 1, expected 2`. Stores and suppression files written by NetOps 1.0.x have version 2 and are not affected. Covered by automated tests only; no installed instance with an old store was checked.
- Admin refuses a plan written by Admin 0.x: the content-only `plan_sha256` of plans and journal records before 1.0.10 is accepted only from Admin 1.0.x, so such a plan is refused with `plan content does not match its plan_sha256`. Plans and journal records of 1.0.x before 1.0.10 stay readable for verify, recover and undo. Covered by automated tests only.

### Changed and fixed

- Admin Junos: the immediate return after a failed write or readback now commits the inverse lines with a plain commit (`netops-<id>-revert`) instead of `commit confirmed`. Measured live on vJunos-switch 26.2R1.7: the expiry of a `commit confirmed` timer returns the configuration before the newest `commit confirmed`, not before the first one. In 1.0.10, an immediate return interrupted before its confirmation (process killed, unreadable snapshot, unproven confirmation) therefore let the timer bring the change back; Admin reported `revert-failed` or `unknown`, never `reverted`, but the port stayed changed. `admin recover` takes the own `-revert` row as the end of the timer. The Admin configuration guide adds a manual check after `unknown` or `revert-failed`. Verified with automated tests on measured device outputs and one live run of the operator command line on the lab switch (forced readback failure, returned with `reverted`).
- Release signing tool (`release/sign/netops-release-sign.ps1`): a release manifest without a key, for example without the arm64 platform or one of its files, no longer stops `-CheckOnly` with a PowerShell error. The checks of that key are FAIL rows with the reason, the other checks still run, the whole table and `OVERALL: FAIL` are printed, and nothing is signed. A missing checksum list, more or less than one release manifest, an unreadable manifest and an unsupported version are FAIL rows as well; without a verified checksum list no other file is read, and `OVERALL: FAIL` is printed without a checksum. The tool signs only the 1.0.x series from 1.0.11 on; 1.0.10, 1.0.9, 1.1.0 and 0.x are refused with `this signing tool signs the netops 1.0.x series from 1.0.11 on, not <version>`. Verified with the signing tool tests. The `-CheckOnly` runs in PowerShell 7.4 and Windows PowerShell 5.1 on the 1.0.10 release files used a development state of the tool that still accepted 1.0.10: the complete files passed every row, and a copy without the arm64 platform or without its gate file printed the FAIL rows and `OVERALL: FAIL`. The tool in this release refuses the 1.0.10 files. No signature was made.
- Release tooling: the candidate manifest, the placeholder gate and the source gate accept only the product versions 1.0.x, and the daily CVE workflow stops before any download when the latest release tag is not 1.0.x. The standalone QA packaging scripts of the component releases before 1.0 (release artifacts, SBOM) and the checks that only they used are removed; the AST, SSH, catalog, privacy, import and profile checks of the components are kept.
- Tests: a new contract test of the optional Admin adapter hooks and new response redaction tests against a frozen copy of the 1.0.8 proxy; the Admin MCP test no longer uses a deprecated FastMCP attribute; the Helper public-source check no longer reports a vendor name inside a hyphenated field name; the Auditor coverage baseline follows the removed code. The unused Helper constant `ENVELOPE_VERSION` is removed, and the message of the Admin and Auditor MCP servers without fastmcp names the complete NetOps image instead of `requirements-mcp.txt`. Product behaviour unchanged.
- Documentation: quickstart (Docker set up by the host administrator; step 4 without sudo: `jq` from the host administrator and cosign as a program of the own account in `~/.local/bin`, checked with `sha256sum`; `jq` as a prerequisite of step 9; the Compose messages on standard error explained before the step 8 block; the CA export hint of `init` and `connection` is the terminal form; files without `Verified OK` are not a verified release), README (the same notes on sudo and Compose, ExtremeXOS port admin state and PoE cycle in the Admin scope), Admin configuration (Junos immediate return, manual check after `unknown` or `revert-failed`), verified support (Junos measurement). The cosign block without sudo was run once on Debian 13 lab machines (amd64 and arm64) under an account that also had sudo rights; the block does not use them.
- Update version metadata, the 1.0.10 → 1.0.11 upgrade pin and the upgrade guide ([Upgrade from 1.0.10](#upgrade-from-1010)).

The classifier replay baseline (`components/netops-helper/tests/fixtures/output_status_baseline.json`) holds 1057 captured texts.

1.0.11 has no MCP API change; the empty declaration is `release/acceptance/api-changes-1.0.10-1.0.11.json`.

## Security

The security-related changes of 1.0.11 make returns and refusals stricter; they do not add a command or write path. A failed Junos change that Admin returns at once is no longer brought back by the device timer when the return is interrupted: the inverse is committed with a plain commit, which ends the own timer. The signing tool never signs when a check fails, also when the release manifest lacks a key, and signs only the 1.0.x series from 1.0.11 on. The Auditor refuses a store in an old format before any write instead of converting it. Admin Junos writes still go through the existing preview, `plan_sha256`, enrollment, journal and audit controls. These notes do not assert the result of the review or scan of the 1.0.11 release candidate.

### Known dependency findings

1.0.11 changes no dependency, lock file or image base. The findings and their assessments are those listed in the [1.0.10 release notes](notes-1.0.10.md#known-dependency-findings) unless the release scan shows otherwise. The release scan of both architectures and the assessments covered by the signed checksum list are part of the candidate acceptance, and these notes do not assert their result.

## Upgrade from 1.0.10

Follow [Upgrade from the previous release](../docs/quickstart-1.0.md#upgrade-from-the-previous-release):

1. Check the 1.0.10 instance, stop it and create its backup and state manifest.
2. Download and verify the 1.0.11 release files. Prepare a separate instance directory and a new Compose project with the same server name and port, and download the 1.0.11 image.
3. Restore the backup into an empty target volume and compare it with the source manifest before the first start. Keep the original instance and backup.
4. Start the new instance. The first start converts only the recorded product version from 1.0.10 to 1.0.11 under the instance lock and writes an `instance_start` audit record with `upgrade` from 1.0.10 to 1.0.11. A second start skips conversion. CA, keys, token, role data and connection details are unchanged.

Do not run `init` on the restored state. Only 1.0.10 is accepted as the previous release; upgrade 1.0.9 to 1.0.10 first.

For rollback, stop 1.0.11, preserve its audit records written after the backup, and start the unchanged 1.0.10 instance; see [Rollback](../docs/quickstart-1.0.md#rollback).

What changes for operators:

- Auditor: `auditor migrate-store` and `auditor migrate-suppressions` are gone; scripts that call them fail. A store or suppression file in the format before NetOps 1.0 is refused without a change (see above). A store that still needs the conversion must be converted with `auditor migrate-store` of 1.0.10 before its backup.
- Admin: a plan written by Admin 0.x is refused with `plan content does not match its plan_sha256`; run a new preview.
- Admin Junos: no change of the device entry is needed. After a Junos operation of 1.0.10 that ended `revert-failed` or `unknown`, check the port as described in the manual check of the [Admin configuration](../docs/admin-configuration.md#juniper-junos-interface-description-admin-state-and-access-vlan).
- Enrollments made with 1.0.10 stay valid after the upgrade: an enrollment is bound to the enrollment protocol and to the SHA-256 of every Admin profile file, and 1.0.11 changes neither, so a device needs `admin enroll` again only when its device entry, its accounts, its firmware or the Admin notification or status file settings change.

## Known limitations

- Admin Junos: the immediate return with a plain commit was run live once (a forced readback failure); an immediate return interrupted after its commit and an unreadable snapshot after it are verified with the simulated device of the unit tests only. A `commit confirmed` of someone else above the change makes the expiry keep the change, which Admin reports as `revert-failed`; this follows from the measured rule and is covered by automated tests only. The MCP tools were not called live.
- Auditor: 1.0.11 has no conversion of a store or suppression file in the format before NetOps 1.0; the refusal is covered by automated tests only.
- Quickstart without sudo: the cosign block was run once on Debian 13 lab machines (amd64 and arm64) under an account that also had sudo rights; an account without them was not used.
- The limitations listed in the [1.0.10 release notes](notes-1.0.10.md#known-limitations) still apply; for Junos, the immediate return is now the plain commit described above.

## Acceptance

The acceptance of 1.0.11 consists of: repository, release-tooling and acceptance-tooling tests, installed-image tests and the engine regression of the four roles on amd64 and arm64; Actions candidate checks; installation by following the quickstart on the [supported platforms](../README.md#supported-platforms); `release/acceptance/upgrade-check.sh` from 1.0.10 to 1.0.11 against `release/acceptance/api-changes-1.0.10-1.0.11.json`; the MCP client checks; release signing with checksum, registry and vulnerability checks. The results are acceptance reports (`acceptance-*.json`) covered by the signed checksum list.

Before the candidate, each change was tested on the lab PC (engine image, no network) on its own source before it was merged: the Auditor change with the Auditor suite (2077 passed); the removal of the QA packaging with the core (1543 passed), Helper (7306 passed, 501 subtests), Auditor (2107 passed) and Admin (2533 passed) suites; the Admin plan change with the Helper (7306 passed) and Admin (2534 passed) suites; the release tooling with the release suite (207 tests); the signing tool with its tests (94 and 6) and the release version tests (3), and with `-CheckOnly` in PowerShell 7.4 and Windows PowerShell 5.1; the documentation with the root tests (14 OK); the Junos fix with the Admin suite (2538 passed) and the root tests (14 OK). The Junos timer was measured live on vJunos-switch 26.2R1.7 (two scenarios), and the fixed Admin passed one live operator command line run with a forced readback failure (`reverted`, the configuration equal before and after, also after the time of the original timer). The test-only changes passed their own test files. These notes describe the required checks and do not assert that publication acceptance has passed.

## Verify this release

```sh
cosign verify-blob --bundle netops-1.0.11-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.11-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.11-SHA256SUMS
```
