# G46 ExtremeXOS fixtures

Measured using the GNS3 d-exos switch (ExtremeXOS 33.6.1.14, Core license, task netops-20261119-611). The write account read scoped modules with `show configuration vlan|ospf|ospfv3|bgp` and the missing-policy response with `check policy g46-prefix`. The independent check account read `show ospf[v3]`, `show ospf[v3] area [ID]`, `show ospf[v3] interfaces vlan netops-g46`, `show bgp` and `show bgp neighbor [198.51.100.2]`.

The VLAN module includes only the assigned test VLAN. Test VLAN, test IPs and area from TASK.md were retained intentionally. Redacted lines from the vault wrapper and unrelated sensitive fields were removed. The files were passed through `components/netops-helper/tests/support/anonymize_fixture.py --check` and trailing padding was trimmed. The literal EUI-64 link-local prefix `fe80::/64` was restored after anonymization. Test derivations for an AS or policy value replace only the value within the measured CLI fields. They do not assert a live write was measured.

[Local-AS command and reset value](https://documentation.extremenetworks.com/exos_commands_22.6/GUID-E41F308E-1835-4D6E-B3E8-CF31F6E2DF1C.shtml), [BGP route-policy command](https://documentation.extremenetworks.com/exos_commands_32.6.3/GUID-E1D36F8D-A193-41EF-B8BF-12AD71D9897D.shtml), [check policy command and success response](https://documentation.extremenetworks.com/exos_commands_22.2/EXOS_21_1/EXOS_Commands_All/r_check-policy.shtml).

The single-line `valid-check-policy.out` fixture comes from the vendor command reference linked above.

## Task netops-20261121-749 (public source gate of 1.0.12)

The dotted test area is written as 0.0.0.15 and the test peer network as 198.51.100.0/24 (peer .2, local .1)
in every fixture and in `test_exos_g46.py`; table columns are kept.
