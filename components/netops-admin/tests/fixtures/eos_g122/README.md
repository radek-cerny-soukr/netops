# Arista cEOS 4.36.1F outputs for G122 (1.0.12)

Measured on cEOSLab 4.36.1F-48405728.4361F (GNS3 `netops-d-lab`, node d-ceos, DNAT 2253) on the free test port
Ethernet12 and test VLANs 3990-3992, task netops-20261118-491. Raw captures and the scripts are in
`task-evidence/g122/` of that task (`raw/probe6-readback.txt`: readback under a commit-timer safeguard that returned the
whole running configuration; `raw/probe7-mac-vlan.txt`, `raw/probe8-vlan-exec-status.jsonl`; `live/live1`: the Admin
live run, whose check-account answers give `show-vlan-id-3992__unnamed.txt`, `show-dot1x-interface-Ethernet12__auto.txt`
and `show-interfaces-Ethernet12-switchport__trunk-phone-tagged.txt`).

`show ...` answers of the check account `netops-ro` (privilege 1) and the `show running-config` parts of the write
account were cut from the echo and the prompt and went through
`components/netops-helper/tests/support/anonymize_fixture.py --check` (only the MAC addresses of
`show-mac-address-table-vlan-10__learned.txt` changed). `show-vlan-id-3999__missing-exec-rc1.txt` is the stdout of the
ssh exec answer (exit status 1) for a missing VLAN. The descriptions are test texts written in the lab.
