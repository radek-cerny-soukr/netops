# FortiOS taxonomy fixture provenance

The six rule triplets under `../rules/fortios.*/` use derived examples and documentation-only
addresses and names. Positive and negative cases use the default-elided syntax of `show`.
The third case exercises a missing or restricted field or table. The tests supply visibility
separately. The default-elided REST and offline regressions use `../fortios_clean.conf`
and the documented SNMP and SSH blocks. The FortiOS 7.6.8 section inventory in
`../real-sections/fortigate-60f-7.6.8.txt` shows that some default-only sections and empty tables are omitted.

See the [vendor CLI references](../../../docs/fortios.md#cli-references) for each rule.

`ro.txt` and `full-redacted.txt` are derived replays of the visibility pattern described in
`docs/channels.md`. The common headers follow the existing `../real-sections/` inventories, and
the administrator syntax follows `../rules/fortios.mgmt.default-admin-account/positive.conf`.
The account, profiles, and safeguard are examples. Empty sections and object differences are
intentional to model visibility and exercise coverage.
