# IOS XE management diagnostics

Pinned SSH exec reads on 2026-11-19, GNS3 Cisco IOL XE 17.18.2 (IOL XE
17.18.2 fc3) and Cisco IOL-L2 XE 17.18.2 (IOL-L2 XE 17.18.2 fc3). Each JSON includes
`show version`, `show privilege` and all nine xe management commands for `netops-ro`
and `netops-admin`. The recording recipe redacted credentials before applying
`tests/support/anonymize_fixture.py` to hostnames, addresses, serial numbers
and usernames. No terminal or device settings were changed.

Neither node had AAA servers configured and SNMP was disabled. The following
small vendor-output excerpts cover populated data using documentation addresses.

- `aaa_servers.out`: anonymized excerpt from the sample RADIUS server status in
  [IOS XE 17.18.x RADIUS Server Load Balancing](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/configuration_guide/sec/b_1718_sec_9300_cg/radius_server_load_balancing.html).
- `tacacs_statistics.out`: anonymized excerpts from the
  [Cisco Security Command Reference, show tacacs](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s5.html).
  [IOS XE 17.18.x Configuring TACACS+](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/software/release/17-18/configuration_guide/sec/b_1718_sec_9500_cg/configuring_tacacs_.html)
  confirms the same command.
- `snmp_statistics.out`: excerpts from the
  [IOS XE 17 SNMP Configuration Guide, ASR 920](https://www.cisco.com/c/en/us/td/docs/routers/asr920/configuration/guide/snmp/17-1-1/b-snmp-xe-17-1-asr920/b-snmp-xe-17-1-asr920_chapter_00.html).
- The tests derive paging and credential cases by adding a pager or synthetic
  canaries to recorded output. Those additions are security probes, not captures.

The empty AAA test adds the measured OpenSSH stderr line `Connection to … closed
by remote host.`, with the host replaced by the fixture's documentation IP.
The device returned only CRLFs on stdout and rc 0 on both nodes.

`snmp_engine_id.out` is the anonymized local/remote example from the
[Cisco SNMP Support Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/snmp/command/nm-snmp-cr-book/nm-snmp-cr-s1.html).
[IOS XE 17.14.x SNMP configuration](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9400/software/release/17-14/configuration_guide/nmgmt/b_1714_nmgmt_9400_cg/configuring_simple_network_management_protocol.html)
confirms those fields for the IOS XE command.
