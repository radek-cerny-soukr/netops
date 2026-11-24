# Cisco NX-OS taxonomy fixtures

Each `../rules/cisco-nxos.*` directory contains three derived, synthetic fragments
for the registered rule. The common exec header, software version and
indentation follow the Admin 9.3(12) capture at
`components/netops-admin/tests/fixtures/nxos_9_3_12/show-running-config__baseline.txt`.
The original hostname, accounts, interfaces' assignments and secrets were
replaced with example names, synthetic port settings, documentation addresses
and `[redacted]`. Fragments omit unrelated commands. The test supplies
knowledge of a verified profile independently of the fragment.

| Rules | Syntax sources and changes |
|---|---|
| Management and AAA | Nexus 9000 Security 9.3(x) and NX-API CLI 10.1(x). The ACL addresses, login group, listener port and timeout are synthetic. The configured-but-unbound RADIUS group mirrors the case in the design. |
| SNMP | Nexus 9000 SNMP CLI 9.3(x) and the Admin baseline. DES preserves the implicit `priv` syntax, AES names the algorithm, and the third case masks the algorithm. The operational table regression derives from Cisco's 9.2(3) example. |
| Time and logging | Nexus 9000 System Management 9.3(x) and `components/netops-admin/tests/fixtures/nxos_nxos_services_admin/configured-ntp-config.txt` after O3. VRF, address, severity and NTP key binding vary across cases. |
| Discovery, switching and ports | Nexus 9000 Layer 2 Switching 9.3(x), Layer 2 Interfaces 9.3(x) and the Admin baseline. Port roles, VLAN IDs and guard settings are examples. DHCP snooping syntax follows the Security guide. |

The end-to-end replay also uses the existing baseline and
`ro__show-running-config-denied.txt` from that same Admin directory.
Canaries are artificial and are inserted only inside the test.

See [Cisco specifications by section](../../../docs/cisco-nxos.md#sources) for the versioned references.
