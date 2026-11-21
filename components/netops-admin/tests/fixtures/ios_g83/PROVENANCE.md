# IOS XE DHCP fixtures for G83

Captured on 2026-11-20 UTC against d-iolxe IOL XE 17.18.2 (GNS3 TCP 2257) and d-iolxe-l2 IOL-L2 XE 17.18.2 (TCP 2258). The commands, timestamps, changes and restoration checks are in [capture.log](../../../../../task-evidence/g83/capture.log). The switch was read only.

- `pool-absent`, `pool-created` and `pool-updated` are the exact pool section queries with `end` selected. `host-hardware` and `host-client` are the corresponding manual pool sections. `exclusion-created` is the exact global exclusion query with `end` selected.
- `relay-before` and `relay-after` are the targeted running configuration of Ethernet0/2, without and with the helper. `ip-interface-before` and `ip-interface-after` are the matching privilege-1 operational reads.
- `pool-operational` and `binding-*` are privilege-1 `show ip dhcp pool NETOPS-G83-POOL` and `show ip dhcp binding`. `l2-pool-operational` shows an absent pool. `*-denied` captures a real refusal of the same pool section read by the privilege-1 accounts.
- `version` and `l2-version` identify the measured firmware and images.

The Helper's `tests/support/anonymize_fixture.py --check` processed the whole set together with the source host names and port description supplied explicitly. The terminal command echo and prompt were removed when capturing the answer. Trailing horizontal whitespace was trimmed afterwards. The synthetic hexadecimal client identifier was entered for the test. The positive lease-count variant and truncated-read variants used by the tests are derived from the recorded answers.
