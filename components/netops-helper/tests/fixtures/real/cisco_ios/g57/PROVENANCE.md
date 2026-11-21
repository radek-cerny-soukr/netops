# G57 · Cisco IOS operational captures

- `iosv/` and `iolxe/` contain SSH exec output captured on 2026-11-19 from d-iosv (IOS 15.9(3)M12, Gi0/2) and d-iolxe (IOS XE 17.18.2, Eth0/2), using the lab admin account and pinned SSH host keys. The command names match the query names. `version.out` uses `show version | include Cisco IOS`. Whitespace-only captures contain the SSH CLI response for unconfigured facilities. The `qos_queues` outputs are command refusals.
- `vendor/qos_policy.out` is the hierarchical VLAN-policy example under `show policy-map interface`. [Cisco IOS QoS command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/qos/command/qos-cr-book/qos-s4.html)
- `vendor/qos_queues.out` is the full `show mls qos interface … statistics` example. [Catalyst 2960-X IOS 15.2(6)E QoS command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15_2_6_e/command_reference/b_1526_2960x_cr/qos_commands.html)
- `vendor/nat_translations.out` and `vendor/nat_statistics.out` are the translation overload and address-pool examples. [Cisco IOS 15.2S NAT configuration guide](https://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr_nat/configuration/15-2s/iadnat-monmain.html)
- `vendor/ikev1_sa.out`, `vendor/ikev2_sa.out` and `vendor/ipsec_sa.out` are the ISAKMP active/standby, IPv4 IKEv2 and IPsec SA examples in the Cisco IOS Security Command Reference. [Cisco IOS security command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s3.html)

All captures were processed with `tests/support/anonymize_fixture.py --check`. Vendor excerpts omit prompts and trim trailing line whitespace. Tests derive negative cases by cutting or appending to these captures.

`vendor/nat_translations_xe.out` and `vendor/nat_statistics_xe.out` use the full-pool example from the Cisco Catalyst 8000 troubleshooting guide. Prompts and the two editorial comments were removed before anonymization. [Cisco IOS XE NAT troubleshooting guide](https://www.cisco.com/c/en/us/support/docs/ip/network-address-translation-nat/226027-troubleshoot-nat-on-cat8000-platforms.html)

`iosv/login_banner.out` is the IOSv license greeting from OpenSSH stderr with rc 0. The IOL XE close notice used in the companion test uses the test target address. Both were identified during the live MCP comparison.

`ro_*.out` files are the independently captured `netops-ro` replies with status 0. They include the refusals for the three crypto commands. The admin account had documented IKEv1 headers and an explicit IPsec absence notice. Only QoS policy, NAT translations, NAT statistics and IKEv2 returned blank successful replies.

- `vendor/ikev2_sa_hsrp.out` is the primary router's `show crypto ikev2 sa` reply from scenario 1. The prompt is omitted and endpoint addresses use the RFC 5737 documentation ranges. [Cisco IOS XE HSRP and IKEv2 verification](https://www.cisco.com/c/en/us/support/docs/ip/hot-standby-router-protocol-hsrp/222200-configure-ipsec-redundancy-with-hsrp-for.html)
- `vendor/qos_policy_two_rate.out` is the Serial3/0 reply from the Two-Rate Traffic Policing example under `show policy-map interface`, with the prompt omitted and common leading indentation removed. The partial and unknown-counter tests derive their replies from this capture. [Cisco IOS QoS command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/qos/command/qos-cr-book/qos-s4.html)
- `vendor/qos_policy_single_rate.out` is the single-rate, two-color `hardware-example` reply from the Rate and Burst Sizes Programmed in Hardware section. The command and the editorial footnote marker on the CIR line are omitted. [Cisco IOS XE QoS Packet Policing](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/qos/b-quality-of-service/m_qos-policing.html)
- The wrapped-key regression derives its two replies from `vendor/ipsec_sa.out` by appending synthetic key values with matching suffixes.
