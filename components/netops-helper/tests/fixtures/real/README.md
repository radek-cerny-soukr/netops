# Real device output (anonymised)

Complete output of the catalogue templates (and of the normalized-table commands,
which are catalogue templates too) as printed by physical EXOS switches and by
virtual lab devices on 2026-11-08 and 2026-11-09, read-only (`show` only), over SSH
exec without a pager. Layout `<os>/<model>_<version>[_n]/<query>.txt`; `index.json`
lists the rendered command, SSH exit status and line count per query. A second or
third switch with the same model and version gets `_2`, `_3`.

Anonymised with `tests/support/anonymize_fixture.py` and then renumbered into the
documentation ranges only, so that the source privacy gate (`release/check_source.py`)
accepts every file:

- MAC -> `00:00:5e:00:53:NN` (RFC 7042) in the spelling and case of the original, also
  inside bridge identifiers;
- IPv4 -> 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (RFC 5737). The subnets
  that carry the lab topology keep their host octets; the remaining ones (management
  network, syslog/NTP/SSH client hosts, vJunos internal interfaces) were numbered into
  free documentation addresses, so their subnet relation is approximate: the
  management /24 became `203.0.113.128/25`, an IOS classful header
  `X/8 is variably subnetted` names `192.0.2.0/8`;
- IPv6 -> `2001:db8::/32`, link-local `fe80::<n>`;
- host/LLDP names -> `hostNN`, port display strings -> `port-desc-NN`, user names ->
  `userNN`, serials keep their shape;
- VLAN names of the switches -> neutral names of the same length (`V10`, `V20`,
  `VL-30`, `VLAN40`, `V50`); the tags are real;
- the NTP server name -> `ntp.example.net`, the image path of the IOL node -> `unix:/images/`.

The mapping files hold real values and are not stored.
Host names that equal the model (SysName, LLDP System Name) are anonymised too; the model stays in `System Type` and in hardware descriptions.
Software versions, model names, VLAN tags and counters are real.
`log_messages`/`log_warnings` keep only the newest 150 messages.
`test_anonymize_fixture.py::test_committed_fixtures_hold_no_site_identifiers` runs the
residual check over every fixture under `tests/fixtures`, not only this directory.

Exit status is as the switch returned it (`index.json`): the complete output of
`show vlan <name>`, `show port <n> information detail` and
`show iproute ipv6 summary` ends with status 250 (the CLI's -6, see
`docs/vendor-cli-references/extreme-switch-engine.md`); `%% Unrecognized command`
ends with 254. Tables that are empty on these switches (IPv6 neighbours and
routes, MLAG, ELRP, ACL counters) are kept as printed; their populated
layouts come from the vendor documentation fixtures in `../tables`. LACP is empty
on the X435 and first X440G2, while `x440g2-12p-10g4_33.7.1.6_2` and `_3` each
have one populated LACP row (`lacp.txt`), parsed as an `aggregate` record.

## exos

| Directory | Switch | EXOS | Role |
|---|---|---|---|
| `x435-8p-4s_33.7.1.6` | X435-8P-4S | 33.7.1.6 | lab |
| `x440g2-12p-10g4_33.7.1.6` | X440G2-12p-10G4 | 33.7.1.6 | lab |
| `x440g2-12p-10g4_33.7.1.6_2` | X440G2-12p-10G4 | 33.7.1.6 | access switch (PoE devices, phone, AP, LACP uplink) |
| `x440g2-12p-10g4_33.7.1.6_3` | X440G2-12p-10G4 | 33.7.1.6 | distribution switch (firewall uplink, LACP) |

`ipv6_neighbor_address` was not run: none of the switches has an IPv6 neighbour. `show virtual-router` and `show edp ports all` (exit status 250) are not catalogue queries and are not stored.

X435 has no `show stacking`, `show mlag`; its outputs are stored as the switch
printed them (`%% Unrecognized command`).

## GNS3 lab (cisco_ios, arista_eos, exos/exosvm)

Captured 2026-11-08 on a GNS3 lab project (IOSv router, IOSvL2 switch, cEOS, EXOS-VM; SSH exec, no pager),
every catalogue template of the profile plus the lookup variants `route_lookup_connected|ospf|none|default`, with the
built-in read-only account (`netops-ro`: IOS privilege 1, EOS `network-operator`, EXOS `user`). `index.json` also names the
account. Where privilege 1 refused an IOS read (`Line has invalid autocommand`), the same command run by the lab admin
account is stored as `<query>.admin.txt` (`log_messages`, `stp_inconsistent`, `stp_summary` on the router); NetOps functions
use the read-only output only. Slotted templates ran with `Gi0/1` / `Ethernet1` / `1`, VLAN 10 (`Default` on EXOS) and a
neighbour address.

| Directory | Device | Software | Role |
|---|---|---|---|
| `cisco_ios/iosv_15.9.3M12` | IOSv | 15.9(3)M12 | router: OSPF to cEOS, dot1Q sub-interfaces, static host ARP |
| `cisco_ios/iosvl2_15.2.20200924` | IOSvL2 | 15.2(20200924:215240) | switch: trunks, SVIs, a one-port `Po1` (member without link) |
| `arista_eos/ceos_4.36.1F` | cEOS | 4.36.1F | switch and L3: OSPF, MSTP, static `Po1` (Et6) |
| `exos/exosvm_33.6.1.14` | EXOS-VM | 33.6.1.14 | switch, port 2 untagged in the host VLAN |

The lab has no real host: the end-to-end endpoint is a static one (ARP entry on the router, MAC entries on the three
switches, `create fdbentry` on EXOS port 2); the file with the static rows is the live output of that state. The
management network of the lab is shared, so LLDP shows more neighbours on the management ports than the data topology has.
What the virtual platforms cannot print (PoE, optics, environment, stack, err-disabled ports, populated BGP) is covered by the
documentation fixtures; the per-template result is in the generated tables of `docs/vendor-cli-references/cisco.md` and
`arista-eos.md`.

## GNS3 lab, second capture (2026-11-09): cisco_xe, cisco_nxos, juniper_junos_els, lab_endpoints

Captured the same way (SSH exec, `netops-ro`, no pager; Junos with the fixed ` | no-more`) on the lab nodes IOL XE 17.18.2 (router),
Nexus 9300v 9.3(12) (`network-operator`) and vJunos-switch 26.2R1.7 (`read-only`): every catalogue template of the profile plus the
`route_lookup_connected|ospf|none|static|default` variants. One anonymiser mapping covers all of them and the `lab_endpoints` set, so a
MAC, IP address or host name is the same everywhere in these directories (not across the first capture above).

| Directory | Device | Software | State during the capture |
|---|---|---|---|
| `cisco_xe/iolxe_17.18.2` | IOL XE router | 17.18.2 | OSPF with four neighbours, BGP neighbour that never comes up (Idle/Active), an unreachable NTP server, a static route |
| `cisco_nxos/nexus9300v_9.3.12` | Nexus 9300v | 9.3(12) | OSPF, BGP neighbour (Idle), vPC domain without peer link, `Po1` with one suspended member, NTP server, static MAC on `Ethernet1/2` |
| `juniper_junos_els/vjunosswitch_26.2R1.7` | vJunos-switch | 26.2R1.7 | OSPF, RSTP on `ge-0/0/0`, VRRP group on `irb.10`, an `ae0` whose member is down, NTP server, static MAC on access port `ge-0/0/1` |
| `lab_endpoints/{iosv,iosvl2,ceos}` | IOSv, IOSvL2, cEOS | as above | only the reads `locate_endpoint` uses, with the two static hosts (static ARP on the router, static MAC entries on IOSvL2 `Gi0/2`, cEOS `Ethernet3`/`Ethernet4`, Nexus `Ethernet1/2`, vJunos `ge-0/0/1.0`) |

All temporary lab configuration was removed after the capture and nothing was saved on any node. Differences to the first capture:

- Where the read-only account was refused and the lab admin account answered, the admin output is stored next to it as `<query>.admin.txt`:
  IOL `log_messages`, `stp_inconsistent`; Junos `log_messages`, `log_interactive_commands` (the admin file of those two was produced by `netops-ro` in a
  temporary class with `view trace maintenance` and `deny-commands`; the built-in `read-only` class is refused with `error: permission denied: log`).
- IOL is a router image: `interfaces`, `mac_table`, `vlans`, `lag_summary`, trunk, err-disable, PoE and stack reads answer `Line has invalid autocommand`, the admin account gets the same line.
- On the Nexus, HSRP, VRRP and DHCP snooping answer `Syntax error while parsing` (feature off, exit status 16); `show vpc orphan-ports` ends with exit status 244.
- The Nexus prints no LLDP neighbour on the data port (only `mgmt0`); the vJunos `route_lookup_default` is the answer for a prefix that only the default route covers.
- The IOL `version.txt` had a double space after the host name (anonymiser column fill) that was reduced to one, as in the first capture.

## Port VLAN follow-up (2026-11-09)

Directories ending in `_pty` (or `_pty_2`, `_pty_3`) are follow-up live read-only
captures supplied with the task, not new device sessions by the parser tests.
`index.json` preserves command spelling, UTC, exit code and outcome. Only PTY
echo, prompt, ANSI and pager prompts were removed before processing through
`tests/support/anonymize_fixture.py` (Anonymizer and residual check); columns,
wrapped lists, VLAN tags, flags and CLI refusals remain. VLAN names and embedded
port descriptions were explicitly supplied to the anonymizer. No identity map
is retained. The directory's OS/version is the measured version.

`extreme_exos/` holds the new all-VLAN `vlan_detail` samples from EXOS-VM
33.6.1.14, X435 31.7.3.37 and three X440G2 33.7.1.6 devices. The prior EXOS
fixtures under `exos/` retain their original provenance. Successful NX-OS and
Junos membership uses the earlier exact-catalogue fixtures; the later PTY
plural-command refusals are retained with `_refused` names as negative cases.
IOSv/IOL router images refuse switching reads; no positive live IOS XE claim
is inferred from the shared IOS/IOS XE parser.

## Interface error counters (2026-11-09)

Additional `port_errors_capture_*.txt` files are anonymized 2026-11-09 source
captures supplied with the task, processed by `tests/support/anonymize_fixture.py`
with explicit prompt/user literals where terminal ANSI sequences hide a name.
No mapping is stored. Echo, prompts, consumed pager marks and Junos command-line
editing artifacts are retained and recognized without changing device settings.
The filtered Junos capture is a subset of `interface_details`; the existing full
extensive fixture is tested too. The NX-OS plural command verifies its refusal,
not the singular catalogue command. IOSvL2 contains no counter rows. Versions
and source limitations are recorded in the verified-support matrix.

The additional EXOS copies live in each version's `captures_20261109/` directory
with their own command/exit-status index, preserving the original canonical
query files and their existing index.

## fortinet

`fortinet/fortigate80f_8.0.2_build0251` holds read-only captures from a physical
FortiGate 80F HA primary on 2026-11-09, 22:48–22:49 UTC, FortiOS 8.0.2 build0251.
The FortiSwitch firmware was not captured. These existing catalogue diagnostic
reads are read-only; unlike the switch captures above, they use `diagnose`, not `show`.
`managed_switch_mac_all.txt` is the complete all-switch MAC listing (two switch
blocks, 12 rows each); the tests select one unchanged block when replaying a
serial-specific MAC request, whose invocation was not captured live.
`managed_switch_lldp_1.txt` and `_2.txt` are the complete serial-specific
`lldp neighbors-summary` captures (five neighbours and 23 empty slots each).
The original command echo contains one backspace editing artifact, retained here.
The serials, neighbour/prompt names, trunk identifiers and MACs were replaced with
`tests/support/anonymize_fixture.py`; the mapping was never saved. `index.json`
records commands, status, capture time and role. Source and fixture privacy gates
apply without exceptions. These are offline parser/proxy/worker replays, not new
live MCP measurements. Port-state and counter outputs are outside this task.

## FortiGate 80F (fortinet), 2026-11-09

| Directory | Device | Software | Output |
|---|---|---|---|
| `fortinet/fortigate80f_8.0.2` | FortiGate 80F (HA primary, single VDOM) | FortiOS 8.0.2 build0251 | `system_interfaces` (`get system interface`), the source of the `ip_interface` table |

Captured with a read-only account in one interactive SSH session (pager answered with the space key, no
configuration change); the command echo and the final prompt were removed. Anonymised with
`tests/support/anonymize_fixture.py` (SSID-named interface -> `ssid01`, addresses into the documentation
ranges: the first three /24 networks, those of `wan1`, `wan2` and `internal4`, keep their host octets; the other
addresses got free documentation addresses, so their subnet relation is not kept). The anonymiser widens the space after a replaced address; in this layout
two spaces separate the `key: value` fields, so the single space between address and mask and inside
`== [ name ]` was restored as the device printed it. The account name in `index.json` is anonymised too.
The same-day `show ip interface brief`, `show ipconfig` and `show interfaces terse` outputs of the GNS3 lab and the
EXOS switches repeat the stored outputs above and were not stored again.


## Parser follow-up (2026-11-10, task 81)

`arista_eos/ceos_4.36.1F/lldp_neighbors_detail_task81.txt` is the full new
read-only `show lldp neighbors detail`: nine neighbors, seven with day-old ages.
The accompanying JSON records command, UTC and exit status. New
`interfaces_details.txt` in IOSv 15.9(3)M12, IOSvL2 15.2(20200924) and IOL XE
17.18.2 contains the entire `show interfaces` response (7, 7 and 19 interfaces),
including logical/down interfaces and absent subinterface counters. JSON and
canonical indices record command, time, RO account and status. Captures used
verified pre-existing host keys and RO accounts via the lab test host; no
configuration or terminal setting was changed. All four outputs passed
`tests/support/anonymize_fixture.py --check` together; no identity map is stored.
EXOS connected/default regressions reuse the existing EXOS real route fixtures.
Nonzero IOS counter/queue values and plural day variants are explicitly
synthetic mutations in tests. The corrected fallback is replayed through the
worker with real captures, not claimed as a new live MCP measurement.

## Acceptance of 1.0.7 (2026-11-10)

`lab_endpoints_20261110/<node>/` holds the independent read-only CLI reads of the 1.0.7 acceptance on the seven
GNS3 nodes (IOSv, IOSvL2, IOL XE, cEOS, NX-OS, vJunos, EXOS-VM; 2026-11-10 08:53–08:54 UTC, `netops-ro`, OpenSSH
exec with a pinned host key, Junos with ` | no-more`): exactly the outputs `locate_endpoint` reads, including the
interface address tables (`ip_interfaces`, `ipconfig`, `interfaces`). `index.json` records command, exit status
and UTC. One `tests/support/anonymize_fixture.py` mapping covers all seven nodes (`--check` clean, mapping not
stored): the lab VLAN 10/20 subnets became 192.0.2.0/24 and 198.51.100.0/24 with their host octets, so the VLAN
interface of node `.N` is `192.0.2.N`; host names became `hostNN`; the lab VLAN names `D10`/`D20` are neutral and
stay. Identity (`show version`) was not part of this capture; the tests take it from the earlier captures of the
same images.

`fortinet/fortigate80f_8.0.2_build0251/captures_20261110/arp_table.txt` is the read-only `get system arp` of the
same FortiGate during the acceptance (09:20 UTC), transport prompt removed, anonymised together with the
acceptance-day MAC and LLDP reads of both FortiSwitches. Those reads have the same rows, order and flags as the
stored 2026-11-09 captures, so the MAC numbering is shared: the FortiAP is `00:00:5e:00:53:02` (`203.0.113.250`,
`ap-mgmt`) and the second FortiSwitch `00:00:5e:00:53:08`. The SSID-named interface became `ssid01`.

## Two lab EXOS, acceptance 08-exos (2026-11-10)

`exos/x435-8p-4s_33.7.1.6/captures_20261110/` and `exos/x440g2-12p-10g4_33.7.1.6/captures_20261110/` hold the
independent read-only CLI reads of the 1.0.7 acceptance on the lab X435-8P-4S and X440G2-12p-10G4 (2026-11-10 11:02–11:03 UTC, `netops-ro`, OpenSSH exec with a pinned host key): the outputs
`locate_endpoint` reads plus `show switch` (the identity supplement with SysName and System MAC). X435 port 1 is cabled
to X440 port 7. `index.json` records command, exit status and UTC. One `tests/support/anonymize_fixture.py` mapping
covers both switches (`--check` clean, mapping not stored), so the X440 SysName `host01` and System MAC
`00:00:5E:00:53:0C` are the same in the LLDP neighbour of the X435; the management /24 became 192.0.2.0/24 with the
host octets kept, the uplink display string `port-desc-01`. The VLAN names were renamed before as in the earlier
capture of the same switches (`VL-30`, `V20`, `VLAN40`, `V50`). Identity (`show version`) was not part of this
capture; the tests take it from the parent directory. This mapping is not the one of the parent directory.

Final acceptance 2026-11-10 17:18–17:22 UTC: the four EXOS directories contain
`captures_20261110_final/lag_summary.txt` (full read-only `show sharing`, rc 250).
The two residential X440G2 directories (`_2`, `_3`) also contain full FDB, LLDP,
ARP and interface-address captures from that acceptance. One anonymizer mapping
covers these 12 texts; index files retain only command, time, rc and line count.
No device configuration or terminal settings were changed. EXOS-VM regression
uses its real version capture with the lab's empty sharing monitor, an explicit
cross-device replay; no independent VM sharing text was available in the evidence.
