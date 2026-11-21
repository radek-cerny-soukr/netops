# IOS lab captures for G55

The fixtures correspond to the commands in [CLI verification](../../../../../../../task-evidence/g55/cli-verification.md).
Collected from the SSH exec channel with the pinned host keys. The account was
`netops-admin` except for `d-iosvl2-ro_port_security.out` (`netops-ro`).
Each hostname prefix identifies the lab image. The `version` files contain
the version line. Tests use the previously captured complete G51/G53 identity
outputs for the same images.

The repository's `tests/support/anonymize_fixture.py` was applied to the set of
captures. In tests, deliberately shortened copies used to simulate a cut or
pager are derived at runtime from these files.

The G55 review regression tests derive the Port-channel and TenGigabitEthernet
MAC table cases from `d-iosvl2-mac_port.out` by replacing the displayed port.
The FastEthernet port-security case uses `d-iosvl2-port_security.out`, whose
output has no interface column. The accepted MAC table interface types are in
[Cisco IOS 15.2(4)E show mac address-table interface](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750x_3560x/software/release/15-2_4_e/command/reference/CR_3750X/cli2.html).

The ND regression cases derive from `d-iosv-nd_global.out` by replacing the
Link-layer Addr and State with `-` and `INCMP` and using `Vlan10` in the SVI case.
These field values follow [Cisco IOS show ipv6 neighbors, table 215](https://www.cisco.com/c/en/us/td/docs/ios/ipv6/command/reference/ipv6_book/ipv6_15.html).
The positive empty secure MAC regression uses `d-iosvl2-secure_mac.out` as captured.
