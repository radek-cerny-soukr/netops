# switch access control / EXOS

The captures are from GNS3 ExtremeXOS VM 33.6.1.14, ExtremeXOS 33.6.1.14, Core license, on 2026-11-19 under verification. `*-config.out` retains only the test VLAN's lines and their module markers from `show configuration` as the write account. All other captures were read as `netops-ro`. The configuration, pool, address range and relay answers are separate device responses.

- `*-vlan.out`: `show vlan netops-switch-access-control`
- `*-relay.out`: `show bootprelay configuration ipv4 vlan netops-switch-access-control`
- `*-pool.out`: `show vlan netops-switch-access-control dhcp-config`
- `*-server.out`: `show dhcp-server vlan netops-switch-access-control`

A zero-byte file is an observed successful empty answer. The disabled relay target in `relay-target-config.out` is absent from the operational answer until enabled. The CLI reset of the initial pool used `disable dhcp ports 10 vlan netops-switch-access-control` and `unconfigure vlan netops-switch-access-control dhcp`. The captures were anonymized together with `components/netops-helper/tests/support/anonymize_fixture.py --check`. The tests reuse the disabled, enabled and pool-configuration states and derive malformed answers by cutting or altering the captures. The complete base VLAN response had SSH exit status 250. The unsupported read case is derived from the invalid-input diagnostic measured when the switch refused the targeted lease reset.
