# NX-OS G104

Captured over pinned SSH on the GNS3 Nexus 9300v (NX-OS 9.3(12), d-nxos) on 2026-11-19. The `base-` files precede the test change, `configured-` use management as the server transport VRF, and `default-` use the default transport VRF. All three snapshots of these scoped commands are from the live device.

- `*-ntp-config.txt`, `*-syslog-config.txt`, `*-dns-config.txt` are the targeted includes of the NTP, logging, and DNS statements in running-config, read with netops-admin.
- `*-ntp-peers.txt`, `*-ntp-source.txt`, `*-logging-servers.txt`, and `*-logging-source.txt` are `show ntp peers`, `show ntp source-interface`, `show logging server`, and `show logging source-interface`, read with netops-ro.
- `*-hosts.txt` is `show hosts` (netops-admin). NX-OS refused it to netops-ro.
- `configured-diff.txt` is `show running-config diff` before returning the test changes, with sensitive context rows masked. The row counts and the configuration statements under test are preserved.
- `removed-diff.txt` captures the deletion of the G104 syslog test line from running-config while it was still present in startup-config. This NX-OS 9.3(12) hunk prints only the old body followed by the new range.
- `b04-nx-a-logging-source.txt` and `b04-nx-b-logging-source.txt` are pinned NX-OS 9.3(12) output of `show logging source-interface` (netops-ro) on the two B04 switches on 2026-11-19.
- The anonymizer in `components/netops-helper/tests/support/anonymize_fixture.py` processed the captures as a group with the approved test addresses preserved. An empty file is an actual successful empty command response. Tests that truncate or modify a response derive it from these fixtures.

## Task netops-20261121-749 (public source gate of 1.0.12)

The test servers (first written outside the documentation ranges) are 198.51.100.10/.20/.30 in every
fixture and in `test_nxos_g104.py`.
