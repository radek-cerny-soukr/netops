# Admin 0.2.0 review and validation

Review date: 24 September 2026. Scope: request parsing, planning and inverses, enrollment and identity, predicted/observed audit, rollback confirmation and recovery, notification/export, and source distribution.

## Corrections made

- Audit the complete prediction before any safeguard installation; require the management checks needed by the selected operation and an explicit EXOS port VLAN allowlist.
- Compare configuration outside the target across the parsed snapshot, preserve ordering outside known unordered tables, and exclude only the current safeguard from the comparison.
- Bind FortiOS account identity to referenced access-profile permissions, not just administrator entries. A changed profile invalidates enrollment and the stored account baseline.
- Verify cleanup and saving after rollback; save when recovering an interrupted confirmation and block further changes if saving fails.
- Record notification transport exceptions durably. Reject NaN, infinity, future timestamps and invalid queue counts in exporter status.
- Match identifiers to the entire input, bound list-valued requests, and summarize address/MAC and long member changes in exported audit events.
- Require persistent UPM execution and attempt all inverse commands after a partial write; verify the persistable snapshot as well as the live port.
- Handle measured EXOS output: the separate Untagged header, grouping syntax, and ambiguous missing-VLAN diagnostics. Ambiguous absence requires a complete VLAN inventory.
- Normalize only the measured opaque ciphertext fields described in [operations](operations-020.md#snapshot-comparison-boundary); retain structure and administrator comparison.
- Isolate Auditor histories across operator policies so removing a policy cannot resolve its old findings; detect group cycles with a linear graph traversal.

## Validation

The source suites passed 313 Admin tests and 1,127 Auditor tests before packaging. These include independent device models for each new operation and inverse, rejected requests before a write, unavailable checks, actual simulated timer execution, interrupted recovery and failed saving.

Live validation on FortiGate 60F / FortiOS 7.6.7 build3704 exercised enrollment, address create/cleanup, static group member removal and undo, DHCP reservation create/update/delete and undo, and on-device timer return after deliberate check-read loss for groups and reservations. The test addresses were not leased; temporary network permissions were separately approved and restored afterwards. Configuration returned to the pre-series state under the documented ciphertext comparison boundary.

Live regression on FortiGate 80F / FortiOS 8.0.0 build0167 exercised enrollment with real timed rollback, address create/update/unset-comment/delete and undo, then actual timer return for update, delete and create after deliberate check-read loss. Separate temporary key accounts were restricted to the test host; they and their profiles were removed afterwards. The privileged configuration comparison returned to the original baseline under the documented ciphertext boundary. Ten additional execution tests prove that unsupported group/DHCP operations, mismatched configured firmware and unmeasured 8.0 builds cannot send mutation commands.

EXOS validation used an unused physical port on X440-G2 / 33.7.1.6: enrollment, tagged add/remove and undo, native move and undo, then combined membership rollback with persistent UPM mode after deliberate check-read loss. The test VLANs were removed and the complete switch configuration returned byte for byte. The final measurement record is summarized in the repository's [verified support](../../../docs/verified-support.md).

Configuration verification is not packet forwarding, a DHCP lease acquisition, or proof of all builds in a firmware family. Every device/build must pass its own enrollment. FortiOS 8.0.0 build0167 was regressed above for the address profile; the new group/DHCP profiles do not claim 8.0.0 support.
