# G42 ExtremeXOS fixtures

Captured 2026-11-19 UTC over pinned OpenSSH from port 10 on X440-G2-12p-10G4
(ExtremeXOS 33.7.1.6 patch1-11) and the GNS3 d-exos EXOS-VM (33.6.1.14).
Anonymized with `components/netops-helper/tests/support/anonymize_fixture.py --check`.

- `ports`, `port-10-info`, `port-10-config`, `port-10-vlan` are from
  `show ports no-refresh`, `show ports 10 information detail`,
  `show ports 10 configuration no-refresh`, and `show ports 10 vlan`.
- `poe-10-info`, `poe-10-detail`, `poe-16-info` are from `show inline-power info [detail] ports N`.
- `lldp`, `fdb`, `sessions`, and `route-VR-*` are from `show lldp neighbors`,
  `show fdb`, `show session`, and `show iproute vr VR-NAME`.
- `port-10-described` and `config-10-described` follow a temporary
  `configure ports 10 description-string "G42 Room 210 Test Desk"`.
  The configuration file fixture contains only the matching line from `show configuration vlan`.
- Stack cases use derived fixtures with the documented slot:port form and the measured
  standalone CLI layout. No stack was attached to the lab.
  [ExtremeXOS User Guide](https://documentation.extremenetworks.com/exos_32.6.3/GUID-41B51D50-7B27-432A-A7B7-D9DB47447A48.shtml)

Preexisting transport redaction markers inside CLI words were removed to restore
the original labels. Redacted address fields were replaced with documentation
addresses in the anonymized subnet for the relevant device.

## G42 r2

- `x440/arp-client.txt` is derived from the measured d-exos
  [`show iparp <ip> vr VR-Default` response](../exos_g50/arp-hit.out).
  The address and VLAN match the simulated X440 SSH client. The simulated
  return port can be varied to exercise the management path.
- `stack/poe-2-10-detail.txt` is derived from the measured
  `x440/poe-10-detail.txt` by changing the port identifier to `2:10`.
  The fake transport changes the configured and operational fields as the
  cycle progresses. [Vendor slot:port syntax](https://documentation.extremenetworks.com/exos_commands_32.6.3/GUID-7F5D92DA-1EDA-41F4-9373-5161AE4D4102.shtml)
