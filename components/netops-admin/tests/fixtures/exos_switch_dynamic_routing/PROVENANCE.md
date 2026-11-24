# switch-dynamic-routing ExtremeXOS fixtures

Measured using a GNS3 ExtremeXOS VM 33.6.1.14 with a Core license. The write account read the configuration with `show configuration vlan`, `show configuration ospf`, `show configuration ospfv3` and `show configuration bgp`. It obtained the missing-policy response with `check policy switch-dynamic-routing-prefix`. The independent check account ran `show ospf`, `show ospfv3`, `show ospf area 0.0.0.15`, `show ospfv3 area 0.0.0.15`, `show ospf interfaces vlan netops-ospf`, `show ospfv3 interfaces vlan netops-ospf`, `show bgp` and `show bgp neighbor 198.51.100.2`.

The VLAN module includes only the assigned test VLAN. Test VLAN, test IPs and area from TASK.md were retained intentionally. Redacted lines from the vault wrapper and unrelated sensitive fields were removed. The files were passed through `components/netops-helper/tests/support/anonymize_fixture.py --check` and trailing padding was trimmed. The literal EUI-64 link-local prefix `fe80::/64` was restored after anonymization. Test derivations for an AS or policy value replace only the value within the measured CLI fields. They do not assert a live write was measured.

[Local-AS command and reset value](https://documentation.extremenetworks.com/exos_commands_22.6/GUID-E41F308E-1835-4D6E-B3E8-CF31F6E2DF1C.shtml), [BGP route-policy command](https://documentation.extremenetworks.com/exos_commands_32.6.3/GUID-E1D36F8D-A193-41EF-B8BF-12AD71D9897D.shtml), [check policy command and success response](https://documentation.extremenetworks.com/exos_commands_22.2/EXOS_21_1/EXOS_Commands_All/r_check-policy.shtml).

The single-line `valid-check-policy.out` fixture comes from the vendor command reference linked above.

## verification (public source gate of 1.0.12)

The dotted test area is written as 0.0.0.15 and the test peer network as 198.51.100.0/24 (peer.2, local.1)
in every fixture and in `test_exos_switch_dynamic_routing.py`; table columns are kept.
