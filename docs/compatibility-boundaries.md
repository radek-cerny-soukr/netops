# Compatibility boundaries

NetOps compatibility claims are limited to a documented platform/build, operation, account policy and input contract. Generic vendor, model and firmware identifiers may define that scope.

## Catalogue and parser coverage

A catalogue entry identifies a bounded operation. Parser and schema fixtures establish their exact input shapes, not support for every firmware variant. Each target must satisfy enrollment and the component's documented model/build and permission requirements.

## Synthetic and software-image coverage

A synthetic regression verifies its controlled case. A software image can exercise protocol and configuration behavior but does not establish physical forwarding, ASIC, sensor, timing or every convergence path.

## Read and change boundaries

Read-only accounts must deny persistent writes and privileged escapes. Where a platform requires an administrator credential for a bounded collector or explicitly documented role, the tool contract does not reduce the credential's device privilege. Admin change profiles require their own safeguard, lock, journal, prediction and rollback-proof boundaries.

## Approved limitations of 1.0.5

Each limitation was accepted for this release; the measurement it rests on is named.

- **ExtremeXOS `$(` in an inverse command (Admin).** ExtremeXOS X440-G2 33.7.1.6-patch1-11 rewrites `$(x)` to `$x` when the UPM safeguard runs, with or without a backslash, so escaping does not stop it. Admin therefore refuses on ExtremeXOS every plan whose inverse command contains `$(` before the first write. Measured on that X440-G2 build: `$5`, `$x`, `${x}` and parentheses were restored literally, direct CLI writes keep `$(` literally.
- **FortiOS administrator rules under a read-only collector (Auditor).** On FortiOS a read-only account sees only itself in `system admin`. `fortios.mgmt.default-admin-account` and `fortios.mgmt.admin-no-trusthost` therefore stay `not-evaluated` with `admin-visibility-unproven` and `auditor run` ends with exit code 3; the complete evaluation needs a collector account with the `super_admin` profile (see [Account model](account-model.md)). Measured by `tests/test_rule_sections.py` (`test_an_admin_list_without_a_super_admin_is_not_evaluated`, `test_a_run_over_a_read_only_view_is_incomplete`), which run the rules on a snapshot without a `super_admin` administrator.
- **FortiADC Auditor coverage.** On FortiADC-KVM 7.6.7 build0676 the Auditor ends with exit code 3 and `evaluation_complete` is `false`, so zero findings is not a clean audit. A `show` export evaluates 2 of the 8 rules; the other six are `visibility:access-profile-unverified` and `fortiadc.tls.factory-certificate` is `factory-provenance-unproven`. A full export evaluates 6 of the 8; `fortiadc.mgmt.plaintext-admin-access` stays `visibility:networking` and `fortiadc.tls.factory-certificate` stays `factory-provenance-unproven`. Measured on 1 November 2026 by the installed Auditor on a `show` and a `full` snapshot of that device (`rule_status` of both reports).
- **Upgrade audit record.** (a) After an interrupted converting start the record carries the time of the completing start, not of the conversion. (b) A stop between writing the record and removing `gateway/upgrade-pending.json` can produce a duplicate record with `"resumed": true`. (c) With syslog audit the record exists only at the receiver, not in `audit export`. Case (a) is covered by `test_interrupted_converting_start_is_recorded_by_next_start` (`tests/v1/test_upgrade_previous_release.py`: the converting start is killed before its record, the next start writes it with `"resumed": true`). Case (b) follows from the documented order of operations (record first, removal of the file after it) and is not covered by a test. Case (c) follows from `audit export` holding only records not yet delivered. Details in the [quickstart](quickstart-1.0.md).

## Timing and recovery

Device timer semantics are platform-specific. Missing or incomplete proof never establishes successful return. Host monotonic elapsed time is bounded within one boot, and wall-clock changes across reboot are outside that guarantee.

## Deployment verification

Verify the exact model, full build, credential permissions, egress, catalogue scope, safeguards and result interpretation before deployment. Unsupported or unspecified paths remain unsupported or unspecified. A compatibility record does not certify every environment or production exploitability.
