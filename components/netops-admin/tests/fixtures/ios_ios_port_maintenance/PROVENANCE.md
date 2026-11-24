# Fixtures of ios port maintenance (IOS port bounce and PoE)

Measured (verification, GNS3 IOSvL2 15.2(20200924:215240), `netops-ro` / `netops-admin`, test port
GigabitEthernet1/2, raw output in a private measurement record; hostnames and prompts removed, nothing else changed):

| File | Origin |
|---|---|
| `show-interfaces-status__baseline.txt` | `show interfaces status` of `netops-ro`, the leading empty line of the exec answer kept |
| `show-interfaces-status-Gi1-2__notconnect.txt` | `show interfaces GigabitEthernet1/2 status`, port enabled, no peer |
| `show-interfaces-status-Gi1-2__disabled.txt` | the same after `shutdown` (Status disabled, Duplex and Speed `auto`) |
| `show-power-inline__exec-refused.txt` | `show power inline GigabitEthernet1/2` over SSH exec: `Line has invalid autocommand` (same for `netops-ro` and `netops-admin`; the node has no PoE) |
| `config__power-inline-never__invalid-input.txt` | the answer of the interactive configuration mode to `power inline never` (also `auto`, `static max 15400`): caret line and `% Invalid input detected at '^' marker.`; `power ?` answers `% Unrecognized command` |

Taken from the vendor documentation, NOT measured (the lab has no PoE hardware; the physical Catalyst has to be decided by the
administrator):

| File | Origin |
|---|---|
| `show-power-inline-Gi1-0-4__doc-auto-on.txt` | Cisco, "Troubleshooting Power over Ethernet (PoE) on Catalyst 9200", https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9200-series-switches/215636-troubleshooting-power-over-ethernet-poe.html, sample `show power inline gigabitEthernet 1/0/4` (columns Interface, Admin, Oper, Power (Watts), Device, Class, Max; Admin `auto`, Oper `on`) |
| `show-power-inline-Gi1-0-4__derived-never-off.txt` | DERIVED from the sample: Admin `off`, Oper `off`, 0.0 W, `n/a` (the rows of Gi1/0/1 in the same document) |
| `show-power-inline-Gi1-0-4__derived-static-on.txt` | DERIVED from the sample: Admin `static` (document: "Admin is the port's configured PoE mode"), Max 15.4 |

Command syntax from the Cisco Catalyst 9300 Command Reference (Interface and Hardware Commands, `power inline`):
`power inline {auto [max max-wattage] | never | port priority {high | low} | static [max max-wattage]}`; `no power inline
{auto | never | port priority {high | low} | static [max max-wattage]}` returns the port to its default; default
auto, maximum 30000 mW; the command applies to PoE-capable ports only, other ports reject it with an invalid-input error
(confirmed on IOSvL2: `% Invalid input detected at '^' marker.`).
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/command_reference/b_179_9300_cr/interface_and_hardware_commands.html
The bounce pause: the same Cisco guide recommends waiting 2 to 4 seconds between `shut` and `no shut`.

Measured read-only on the GNS3 IOL-L2 XE 17.18.2 node (Cisco IOL-L2 XE 17.18.2, `netops-ro`, same task, no write on this node):

| File | Origin |
|---|---|
| `show-interfaces-status__iolxe-l2.txt` | `show interfaces status`: the same columns, other widths (Port 13, Type `10/100/1000BaseTX`); the node refuses `show power inline` as well (`Line has invalid autocommand`) |
