# ExtremeXOS G41, 2026-11-18

`vm-*` comes from d-exos (EXOS-VM, 33.6.1.14, netops-admin).
`x440-*` comes from X440G2-12p-10G4 (33.7.1.6 patch1-11, ai-login).
Switch fixtures are projections of `show switch`. Running fixtures are derived from actual
`show configuration` byte streams. VLAN statements and fixed SSH/Telnet state lines are kept,
unlisted statements are replaced with opaque fixtures, and account values are replaced.
The switch names and VLAN aliases were processed by `tests/support/anonymize_fixture.py`.

`vm-dirty.out` is derived from `show configuration difference primary context 0`
after a temporary VLAN was created. Only the timestamp header values are replaced.
The clean command returned zero stdout bytes with rc 0. An unknown filename returned rc 254.

The `.out` extension keeps these derived captures outside the historical classifier matrix.
The live diff and capture parser tests replay them directly.

`vm-factory-default-switch.out` is derived from `vm-switch.out`. The booted field
replays the state after the first save in Extreme Networks knowledge base article 000088928 (Extreme support portal).

`documented-stack-prompt.out` projects the prompt from the [Switch Engine 33.7.1 stacking example](https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20User%20Guide/content/documents/Switch_Operating_Systems/Switch_Engine/User_Guide/show_stacking_config_command.shtml).
The test adds the terminal padding and synthesizes the dirty variant with the leading marker.
