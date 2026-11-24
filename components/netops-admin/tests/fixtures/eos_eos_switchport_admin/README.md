# Arista cEOS 4.36.1F outputs for eos switchport admin (1.0.12)

Measured on cEOS 4.36.1F-48405728.4361F (GNS3 `netops-emulated environment`, node Arista cEOS 4.36.1F) on the free test port
Ethernet12 and test VLANs 3990-3992, verification. The raw transcripts and scripts are private. They document the full running configuration read back under the commit timer, the MAC table and VLAN reads, and the live Admin operation. The check-account answers from that operation are published here as `show-vlan-id-3992__unnamed.txt`, `show-dot1x-interface-Ethernet12__auto.txt` and `show-interfaces-Ethernet12-switchport__trunk-phone-tagged.txt`.

`show...` answers of the check account `netops-ro` (privilege 1) and the `show running-config` parts of the write
account were cut from the echo and the prompt and went through
`components/netops-helper/tests/support/anonymize_fixture.py --check` (only the MAC addresses of
`show-mac-address-table-vlan-10__learned.txt` changed). `show-vlan-id-3999__missing-exec-rc1.txt` is the stdout of the
ssh exec answer (exit status 1) for a missing VLAN. The descriptions are test texts written in the lab.
