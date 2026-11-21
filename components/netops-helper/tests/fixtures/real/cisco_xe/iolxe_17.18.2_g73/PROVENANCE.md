Captured on 2026-11-19 via pinned SSH on GNS3 `d-iolxe-l2` (IOL L2,
TCP 2258) and `d-iolxe` (IOL router, TCP 2257), both IOS XE 17.18.2 fc3.
The files contain the command bodies from interactive privileged EXEC.
`l2-ro_port_security.out` comes from the read-only account via SSH EXEC.
Blanks are observed outputs. The invalid input in `l2-auth.out` and
`l2-dot1x.out` was also observed at privilege 15.

Anonymized together with `tests/support/anonymize_fixture.py --check`.
Addresses and MACs in tests use the corresponding anonymized literals;
ports and VLANs retain their observed values. Trailing horizontal
whitespace was removed. The lab's `blue` VRF and Ethernet0/1.10 on the
router provide the populated ARP and ND captures respectively.
The switch MAC scopes use Ethernet0/0, VLAN 99 and a learned MAC. The anonymiser keeps that
learned MAC as a well-known vendor address; in the three switch MAC table captures and the test it
is replaced by the documentation MAC 0000.5e00.5310.
Port security was read on Ethernet0/1 and interface ACL state on Ethernet0/0.
The additional SVI capture, l2-acl_svi.out, uses SSH EXEC and Vlan99.
