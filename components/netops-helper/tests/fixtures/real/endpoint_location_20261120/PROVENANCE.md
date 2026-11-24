# endpoint location read-only captures, 2026-11-20

- FortiGate 80F HA FG-80F HA, FortiOS 8.0.2 build0251; two managed FortiSwitch 224E-POE, FortiSwitchOS 8.0.1 build0069. FortiGate CLI as `fixture-reader` over pinned OpenSSH. Each key in `fortigate-ha.json` identifies the command. The observed management lease, ARP and VLAN 100 FDB entry for the AP on port 3 share one anonymous identity.
- EXOS ExtremeXOS VM 33.6.1.14 and ExtremeXOS VM peer 33.6.1.14 (EXOS-VM 33.6.1.14, `netops-ro`), and X440-G2 (33.7.1.6, SSH key for `ai-login`). Each JSON key identifies its command.
- Anonymised with `tests/support/anonymize_fixture.py` (one map across FortiOS captures; one per EXOS switch). Removed SSH framing and projected the DHCP and configuration columns unrelated to endpoint location. The FortiSwitch port statistics were read with the `port3` selector and replayed under the corresponding unfiltered query. No passwords, tokens or configuration outside the indicated projections are included.
