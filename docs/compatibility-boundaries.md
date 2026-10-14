# Compatibility boundaries

NetOps compatibility claims are limited to a documented platform/build, operation, account policy and input contract. Generic vendor, model and firmware identifiers may define that scope.

## Catalogue and parser coverage

A catalogue entry identifies a bounded operation. Parser and schema fixtures establish their exact input shapes, not support for every firmware variant. Each target must satisfy enrollment and the component's documented model/build and permission requirements.

## Synthetic and software-image coverage

A synthetic regression verifies its controlled case. A software image can exercise protocol and configuration behavior but does not establish physical forwarding, ASIC, sensor, timing or every convergence path.

## Read and change boundaries

Read-only accounts must deny persistent writes and privileged escapes. Where a platform requires an administrator credential for a bounded collector or explicitly documented role, the tool contract does not reduce the credential's device privilege. Admin change profiles require their own safeguard, lock, journal, prediction and rollback-proof boundaries.

## Timing and recovery

Device timer semantics are platform-specific. Missing or incomplete proof never establishes successful return. Host monotonic elapsed time is bounded within one boot, and wall-clock changes across reboot are outside that guarantee.

## Deployment verification

Verify the exact model, full build, credential permissions, egress, catalogue scope, safeguards and result interpretation before deployment. Unsupported or unspecified paths remain unsupported or unspecified. A compatibility record does not certify every environment or production exploitability.
