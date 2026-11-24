# Network overview answers measured on 2026-11-23

PROVENANCE: live read-only captures of the catalogue commands that `network_overview` runs, taken on lab
devices on 2026-11-23 over SSH (`show`/`get`/`diagnose`/`execute ... contract` only, no configuration change).
`index.json` names the command, the SSH exit status where an exec channel reported one, and the account.
FortiOS and FortiADC answers come from one held interactive session each; the prompt lines are removed.

| Source directory | Device | Answer |
|---|---|---|
| `ceos_4.36.1F` | Arista cEOSLab 4.36.1F | `show poe` of the container image: `% Invalid input at line 1` (exit 1) |
| `fortigate60f_7.6.8` | FortiGate-60F 7.6.8 build3744 with one FortiSwitch-108E 7.4.9 | PoE summary of a switch without PSE ports, `wtp-status` without managed access points (empty), port statistics whose SFP and internal ports print `Address is <MAC>,` without `None loopback` |
| `fortiadc-kvm_7.6.7` | FortiADC-KVM 7.6.7 build0676 | `execute autoupdate contract` |

Anonymised by hand: FortiSwitch and FortiADC serial numbers keep their shape (`S108ENTQ00000001`,
`FDVMELTM00000001`), MAC addresses become `00:00:5E:00:53:NN` (RFC 7042), the FortiADC account, user ID and company
become `user01@example.net`, `1000001` and `Example`. Contract codes, levels, dates and every other byte are
unchanged.

This directory holds the `ceos_4.36.1F` answers; the table above lists all three directories of the capture.
