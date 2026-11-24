# ios dhcp IOS DHCP fixtures

Captured on 2026-11-19 on GNS3 Cisco IOSv 15.9(3)M12 (IOSv 15.9(3)M12) and the read-only peer Cisco IOL XE 17.18.2 (IOL XE 17.18.2).
The source commands and cleanup hash are recorded in a private measurement record. The anonymizer
`components/netops-helper/tests/support/anonymize_fixture.py --check` processed the targeted captures together.

- `ios-pools*.txt` came from `show running-config | section ^ip dhcp pool NETOPS-ios dhcp-`. The empty pool was
  present before the two populated test pools. The third capture was taken after clearing the host identifier.
- `ios-pool-check-*.txt` came from `show running-config | section ^ip dhcp pool NETOPS-ios dhcp-POOL$|^end$`.
- `ios-excl-check-*.txt` came from `show running-config | include ^ip dhcp excluded-address 198[.]51[.]165[.]10$|^end$`
  (the measurement used backslash escapes for dots). `ios-exclusions.txt` contains the single address and range.
- `ios-interface-*.txt` came from `show running-config interface GigabitEthernet0/2`.
  `ios-relay-*.txt` and `xe-interface.txt` came from `show ip interface` on the two sides of the blue link.
- `ios-binding-*.txt` came from `show ip dhcp binding` (empty, manual with hardware address, manual with client ID).
  `ios-dhcp-pool.txt` and `ios-dhcp-host.txt` came from `show ip dhcp pool <name>`.
- `ios-ro-config-refused.txt` is the privilege-1 refusal of the targeted running-configuration query.
- `*-version.txt` came from `show version | include Version`.
- `ios-subnet-replace-refused.txt` is the IOSv response to setting the /25 while the /24 remained on the same
  pool. `ios-pool-narrowed.txt` came from the targeted pool section after removing the old network with its
  exact address and mask, then setting the new network and the changed options. Measurement (private measurement record, not published)
