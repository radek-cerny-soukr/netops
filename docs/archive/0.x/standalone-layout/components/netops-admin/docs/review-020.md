# Admin profile compatibility review

The profile contracts cover bounded address, address-group, DHCP-reservation and ExtremeXOS port operations with a separately enrolled check account and an on-device inverse. A successful configuration comparison is not proof of packet forwarding, lease acquisition or every licensed feature.

- FortiOS 7.6.7 build3704 is an explicit profile boundary.
- FortiOS 8.0.0 build0167 support is scoped to the documented operation; Admin 0.2.5 introduced address-group and DHCP-reservation support for that exact build.
- ExtremeXOS 33.7.1.6 and the documented virtual-image profile have separate model, permission and persistence boundaries.
- Every deployment must complete enrollment for its exact model and build. Unknown firmware, unavailable check reads and uncalibrated inverses do not inherit support.
- Interruption and unrelated configuration changes can leave a device blocked and require recovery or manual review. A matching encrypted snapshot cannot establish the plaintext of opaque certificate or wireless fields.

See [compatibility boundaries](../../../docs/compatibility-boundaries.md), [execution contracts](execution.md) and [operation scope](operations-020.md).
