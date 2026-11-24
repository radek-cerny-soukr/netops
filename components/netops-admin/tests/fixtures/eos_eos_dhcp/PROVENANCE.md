# EOS DHCP fixtures

The JSON files with prefix `single-` are operational SSH outputs of `netops-ro` on Arista cEOS 4.36.1F (cEOS 4.36.1F-48405728.4361F) on 2026-11-19. Commands were `show ip dhcp relay | json` and `show dhcp server ipv4 | json`. The files pass through `components/netops-helper/tests/support/anonymize_fixture.py`.

CLI source for E27 and E28: [Arista EOS 4.36.2F, Configuring DHCP](https://www.arista.com/en/um-eos/eos-configuring-dhcp). The guide also documents rejecting overlapping pools and duplicate IPv4 reservations.

The `peer-a-` and `peer-b-` files contain the same two command captures from the two MLAG peers running cEOS 4.36.1F. `relay-config.txt` is the scoped running configuration of Vlan3950 and `relay-set.json` is the matching read-only operational capture. EOS normalized an explicit default destination VRF to the same line and JSON on the default-VRF test SVI.

`server-config.txt`, `server-after-delete.txt` and `server-empty-pool-config.txt` are captured with `show running-config section ^dhcp` by the write identity. `server-set.json`, `server-active.json`, `server-no-options.json` and `server-empty-pool.json` are the read-only JSON before/after enabling the DHCP server on Vlan3950 and with optional settings absent. The active capture reports the isolated SVI link as down. The configured DHCP objects were entirely within the test subnet.

The vendor documents `no ip helper-address <address>` as the single-server inverse and documents the optional server VRF. The unqualified inverse deletes all relay destinations. [Arista EOS 4.36.2F, IPv4](https://www.arista.com/en/um-eos/eos-ipv4?searchword=eos+24+7+dhcp+relay+across+vrf).

`server-invalid-exec.txt` captures the Arista cEOS 4.36.1F rejection of a deliberately invalid argument in a read-only show command (SSH rc 1). The capability-refusal test reuses this measured CLI error envelope for an unsupported operational show on both identities.
