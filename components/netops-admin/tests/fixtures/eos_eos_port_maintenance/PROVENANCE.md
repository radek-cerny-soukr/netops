# Arista EOS outputs for eos port maintenance (1.0.12): bounce, PoE, speed and MTU

## Measured (cEOS 4.36.1F-48405728.4361F)

Measured in GNS3 on Arista cEOS 4.36.1F using test port Ethernet12 on 2026-11-18. The private captures contain the read-only help and show answers, the Ethernet12 MTU, speed, PoE and shutdown measurements, and the stdout, stderr and exit statuses of the SSH exec replies. The test changes were reverted and the running-configuration fingerprint matched the baseline. The captures were processed with `components/netops-helper/tests/support/anonymize_fixture.py` with the `--check` option. Anonymization changed the MAC address in `show-interfaces-Ethernet12__baseline.txt` and the hostname in the prompt.

| File | Source |
| --- | --- |
| `show-interfaces-Ethernet12-hardware.txt` | `show interfaces Ethernet12 hardware`, write account, rc 0 (probe3) |
| `show-interfaces-Ethernet12__baseline.txt` | `show interfaces Ethernet12`, write account, rc 0 (probe3) |
| `show-interfaces-Ethernet12-status__connected.txt`, `__disabled.txt` | `show interfaces Ethernet12 status`, check account `netops-ro` (probe3; probe2 after `shutdown`) |
| `show-poe-interface-Ethernet12__unavailable-exec-rc1.txt` | stdout of `show poe interface Ethernet12`, write account, exit status 1 (probe3) |
| `show-poe-interface-Ethernet12__ro-invalid-exec-rc1.txt` | the same for the check account (privilege 1): `% Invalid input` (probe3) |
| `show-running-config-interfaces-Ethernet12__*.txt` | `show running-config interfaces Ethernet12` after `mtu 9000`, `speed 100mfull`, `speed auto`, `shutdown` (probe2) |
| `interface-line-*.txt` | interactive session (prompt, line, answer): `mtu 9215` → `% Max MTU for Ethernet12 is 9214`, `speed auto 1g` → `% Cannot advertise...`, `poe disabled` → `% Unavailable command (not supported on this hardware platform)` (probe2) |
| `show-users-detail__ssh.json` | `show users detail \| json` through non-PTY SSH as `netops-admin`, verification-r3, 2026-11-18. The SSH peer was replaced with a documentation IP. The tests derive two topologies from the measured running configuration by moving Management0 to a VRF and installing a separate client gateway on Vlan20. [Arista EOS User Security](https://www.arista.com/en/um-eos/eos-user-security). |
| `show-management-ssh.txt` | `show management ssh` as `netops-admin`, verification-r3, 2026-11-18. The tests derive the case with exclusive SSH in the management VRF from this layout and the [SSH VRF configuration in the EOS manual](https://www.arista.com/en/um-eos/eos-session-management-commands). |

## Vendor documentation (Arista EOS User Manual, Ethernet Ports)

URL: https://www.arista.com/en/um-eos/eos-ethernet-ports (EOS 4.37.0F manual page, read 2026-11-18). The lab has no EOS
switch with PoE hardware, so the PoE layout is not measured.

| File | Source |
| --- | --- |
| `show-poe-interface-Ethernet46__arista-doc.txt` | example of `show poe` (`show poe interface ethernet 46`, Command Mode Privileged EXEC). The web page renders the upper row of the two-row header flattened as `PSELLDPPowerGrantedPort` (upper labels PSE, LLDP, Power, Granted, Port over Enabled, Enabled, Limit, Power, State); kept literally. Prompt lines dropped. |
| `show-poe-interface-Ethernet46__disabled-derived.txt` | **derived**, not measured and not in the manual: the documented layout with PSE Enabled `False`, Port State `disabled` and zero power, as the parser expects a port after `poe disabled`. The real state name of a disabled port on EOS is not documented. |
| `show-interfaces-Ethernet2-18-hardware__arista-doc.txt` | example of `show interfaces hardware` (`show interfaces ethernet 2,18 hardware`, Command Mode EXEC; `auto` in Speed/Duplex = autonegotiation). Prompt lines dropped. |
| `show-interfaces-Ethernet4-1-hardware__arista-doc.txt` | example of `show interfaces ethernet 4/1 hardware` (speeds with lane counts, `(default)`); the line `* = Requires speed group setting change` before the port name dropped. |

Command syntax from the same page: `poe disabled`, `no poe disabled`, `default poe disabled` (Interface-Ethernet
Configuration); `speed mode`, `no speed`, `default speed` (Interface-Ethernet Configuration).
