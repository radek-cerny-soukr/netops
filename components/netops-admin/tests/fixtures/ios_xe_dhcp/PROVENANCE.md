# IOS XE DHCP fixtures for xe dhcp

Captured on 2026-11-20 UTC against Cisco IOL XE 17.18.2 IOL XE 17.18.2 and Cisco IOL-L2 XE 17.18.2 IOL-L2 XE 17.18.2. The commands, timestamps, changes and restoration checks are in capture.log (private measurement record, not published). The switch was read only.

- `pool-absent`, `pool-created` and `pool-updated` are the exact pool section queries with `end` selected. `host-hardware` and `host-client` are the corresponding manual pool sections. `exclusion-created` is the exact global exclusion query with `end` selected.
- `relay-before` and `relay-after` are the targeted running configuration of Ethernet0/2, without and with the helper. `ip-interface-before` and `ip-interface-after` are the matching privilege-1 operational reads.
- `pool-operational` and `binding-*` are privilege-1 `show ip dhcp pool NETOPS-xe dhcp-POOL` and `show ip dhcp binding`. `l2-pool-operational` shows an absent pool. `*-denied` captures a real refusal of the same pool section read by the privilege-1 accounts.
- `version` and `l2-version` identify the measured firmware and images.

The Helper's `tests/support/anonymize_fixture.py --check` processed the whole set together with the source host names and port description supplied explicitly. The terminal command echo and prompt were removed when capturing the answer. Trailing horizontal whitespace was trimmed afterwards. The synthetic hexadecimal client identifier was entered for the test. The positive lease-count variant and truncated-read variants used by the tests are derived from the recorded answers.
