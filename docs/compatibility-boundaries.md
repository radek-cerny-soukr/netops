# Compatibility boundaries

NetOps 1.0.12 applies nine compatibility boundaries.

## Catalogue and parser coverage

1. **Catalogue scope.** Each entry defines a bounded operation. Enrollment controls which targets, commands and parameters are available.
2. **Parser and schema inputs.** Fixtures establish the specific input shapes they exercise. Exact schema bindings retain their model and firmware requirements.

## Synthetic and software-image coverage

3. **Synthetic evidence.** A fake transport or a synthetic fixture exercises the case it was built for. Replay uses an earlier device capture.
4. **Software images.** A virtual image can establish protocol and configuration behavior. Physical forwarding, ASICs, PoE, optics and convergence require their own measurements.

## Read and change boundaries

5. **Account privilege.** Device permissions control visibility and writes. An administrator-bounded collector or role still has the privilege of its enrolled device account.
6. **Change proof.** Admin checks the approved plan, takes a lock and journals the operation. Configuration changes require prediction, readback and proof of return where applicable. Scoped operational clears are irreversible.

## Deployment verification

7. **Timing and recovery.** Safeguard timers follow the device's semantics. Host monotonic time bounds elapsed time within one boot. Incomplete evidence leaves the outcome unverified.
8. **Deployment verification.** Qualify the model, operation, credential permissions, egress scope and safeguard in the environment where they will be used. Unsupported or unspecified paths remain unsupported or unspecified.

## Firmware support warnings

9. **Untested versions.** Helper and Admin operations that report `firmware_support` can continue on an identified device with status `untested`. Permissions, safety checks and technical refusals still apply. If the required identity cannot be read, the operation can still be refused. FortiADC Auditor reports an informational finding for an untested FortiADC identity, while missing metadata or another product prevents evaluation of the other rules. See [verified support](verified-support.md#live-verification-of-netops-1012).

## Approved limitations of 1.0.5

These historical measurements use the NetOps 1.0.5 rule catalogue and release path.

- **ExtremeXOS `$(` in an inverse command (Admin).** ExtremeXOS X440-G2 33.7.1.6-patch1-11 rewrites `$(x)` to `$x` when the UPM safeguard runs, with or without a backslash, so escaping does not stop it. Admin therefore refuses on ExtremeXOS every plan whose inverse command contains `$(` before the first write. Measured on that X440-G2 build: `$5`, `$x`, `${x}` and parentheses were restored literally, direct CLI writes keep `$(` literally.
- **FortiOS administrator rules under a read-only collector (Auditor).** On FortiOS a read-only account sees only itself in `system admin`. `fortios.mgmt.default-admin-account` and `fortios.mgmt.admin-no-trusthost` therefore stay `not-evaluated` with `admin-visibility-unproven` and `auditor run` ends with exit code 3; the complete evaluation needs a collector account with the `super_admin` profile (see [Account model](account-model.md)). Measured by `tests/test_rule_sections.py` (`test_an_admin_list_without_a_super_admin_is_not_evaluated`, `test_a_run_over_a_read_only_view_is_incomplete`), which run the rules on a snapshot without a `super_admin` administrator.
- **FortiADC Auditor coverage.** On the measured FortiADC-KVM 7.6.7 build0676, `show` evaluated 2 of 8 rules and left `visibility:access-profile-unverified` actionable gaps, so exits 3. The measured `full` export evaluated 6 of 8: `fortiadc.tls.factory-certificate` stays `factory-provenance-unproven`, an inherent gap that no export can close, and `fortiadc.mgmt.plaintext-admin-access` has `visibility:networking`, which follows from the access profile of the collector account. Every visibility gap is actionable, so on the measured device `auditor run` exits 3 until the collector has the `read` right for `networking` (and for the other areas); with a complete read-only profile only the factory certificate remains and the run exits 0 (covered by `tests/v1/test_fortiadc_profile_coverage.py`, which uses the helper fixture with `read` on all areas and a synthetic snapshot). Both reports retain `evaluation_complete: false` and list gaps in `coverage`, so zero findings does not establish complete coverage. Other required gaps, including identity and export visibility, exit 3. The original rule statuses were measured on 1 November 2026; exit behavior follows their classification. On 9 November 2026 the export with defaults of the same device read by a system administrator (`is-system-admin yes`, enrolled as `admin-bounded`) evaluated 7 of 8 rules: the only gap was the inherent `factory-provenance-unproven` and `auditor run` exited 0 in JSON, SARIF and text; the `show` export of that account exited 3 with `default-undocumented` gaps. The joined pages of both exports had exactly the declared size and SHA-256 (220,487 and 16,576 bytes).
- **Upgrade audit record.** (a) After an interrupted converting start the record carries the time of the completing start, not of the conversion. (b) A stop between writing the record and removing `gateway/upgrade-pending.json` can produce a duplicate record with `"resumed": true`. (c) With syslog audit the record exists only at the receiver, not in `audit export`. Case (a) is covered by `test_interrupted_converting_start_is_recorded_by_next_start` (`tests/v1/test_upgrade_previous_release.py`: the converting start is killed before its record, the next start writes it with `"resumed": true`). Case (b) follows from the documented order of operations (record first, removal of the file after it) and is not covered by a test. Case (c) follows from `audit export` holding only records not yet delivered. Details in the [quickstart](quickstart-1.0.md).
