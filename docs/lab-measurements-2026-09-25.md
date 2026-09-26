# Live lab measurements, 25 September 2026

This page combines the catalogue measurements behind the [verified support matrix](verified-support.md#live-lab-measurements-25-september-2026) with the later [functional and fault tests](#functional-and-fault-tests-t-067). Both series ran on 25 September 2026; the records were reconciled on 26 September. The catalogue series covers Arista EOS, Juniper Junos (both profiles), Cisco IOS-XE, IOS, NX-OS and EXOS-VM. The follow-up adds actual traffic, controlled failures and recovery. The query tables retain the observations of their original run; later results do not overwrite them.

The measurements cover `netops-helper` and, for one platform, `netops-auditor`. `netops-admin` was not run against these images: its profiles list the exact FortiOS and ExtremeXOS builds they were measured on, and none of these images is one of them.

## Comparing the two series

| Question | Catalogue series | Functional series T-067 | Combined interpretation |
| --- | --- | --- | --- |
| What was being tested? | Every query of each selected Helper catalogue; transport and CLI-answer handling. | Selected reads checked against actual traffic, controlled faults and independent CLI observations. | Breadth of command compatibility and depth of observed behavior are separate evidence. |
| Which software comparison? | Released Helper 0.3.6/Core 0.2.3 versus successive branch fixes; released and branch Auditor/Core comparison. | The deployed `0.3.7-rc2-t052` candidate and its source checkout. | T-067 strengthens candidate evidence; it does not validate forwarding on the released Helper or a new release artifact. |
| How broad was coverage? | Ten virtual image variants, seven Helper platform profiles; an additional narrow FortiOS regression check. | Four overlapping instances; forwarding mainly on cEOS and Nexus, LLDP also on vEOS, collection on EXOS. | Do not add profile rows, clones, endpoints and test attempts to obtain a device count. The four T-067 instances are not four extra image variants. |
| Was the data path independently exercised? | Some links populated protocol tables; application traffic and recovery were not measured. | Identifiable HTTP, ICMP, DHCP and negative VLAN/trunk/port tests; distinct management and data paths. | Selected empty-table reads now have complementary evidence against real operational state. BGP/OSPF and redundant LACP/STP still lack functional validation here. |
| What did failed calls mean? | Live runs exposed transport problems, CLI refusals with exit status zero, legacy SSH incompatibility and interface-grammar gaps. | Failures also came from the UDP underlay, premature recovery probes, unsupported SVI ACL attachment and harness mistakes. | Keep product defects, environment prerequisites, unsupported functions and invalid test attempts separate. A FAIL count cannot classify their cause. |
| What changed for NX-OS LLDP? | The 9300v returned exit 244 and no neighbour information. | No neighbour on the first trunk setup; a real neighbour on both actual trunk ports with the native VLAN allowed. | Earlier empty output was a topology observation, not proof that LLDP is unsupported. The exact frame-loss mechanism was not captured. |
| How did Auditor access differ? | SSH-key authentication; released and branch snapshots were byte-identical within that pair. | Password authentication; same missing-syslog rule, different snapshot hash. | Both collection paths were exercised. Neither key-only account configuration nor identical configuration across both series follows from this. |
| How were negative scope tests interpreted? | Junos logical-interface queries initially received a physical interface and were correctly refused. | Proxy injection/unenrolled-interface negatives passed; accidental NX-OS query and EOS parameter mistakes were corrected before repeats. | Intended rejection proves a boundary; an accidental malformed test request does not prove a product defect. |
| What was restored or persisted? | Image preparation identified persistent storage and boot requirements. | cEOS saved/unsaved configuration across a container restart, traffic recovery, configuration comparisons and cleanup were checked. | This adds useful operational evidence, but direct preparation/restore commands do not constitute an Admin apply/rollback test. |

Taken together, the records support catalogue and transport compatibility over a broad virtual-image set, plus observed forwarding and recovery on a smaller subset. They do not support a claim that all NetOps components, all catalogue functions, physical devices or the pending release are fully validated. Successful reads of an empty or unsupported subsystem must remain distinguishable from a working feature.

## Software under test

| Label | What ran |
| --- | --- |
| **0.3.6** | The released `netops-helper` 0.3.6 through its deployed runner (container image `sha256:2474a577...`, Python 3.14.7, OpenSSH 10.0p2 inside it) and the stdio proxy of the same release with `netops-core` 0.2.3. |
| **branch** | The source that was then released as `netops-helper` 0.3.7 and `netops-core` 0.2.5 (the changes listed under [Changes that came out of the run](#changes-that-came-out-of-the-run)), deployed before the release as a candidate: the 0.3.6 runner image with its `/app/src` replaced by the branch source, so the same Python and the same OpenSSH 10.0p2, and the stdio proxy running the branch source. It is evidence for the fixes, not the release build; the released 0.3.7 image has to be measured again. The one change made after the measurement, the ExtremeXOS `Method is not implemented on this platform.` refusal, is not in these columns. |

Every catalogue `ssh_read` call went the way a real one goes: an MCP `ssh_read` request from the client to the stdio proxy, the proxy's own checks against the enrolled inventory, the runner, then OpenSSH to the device over the network. No part of that path was substituted. Functional-test preparation and independent traffic checks used consoles and endpoint tools; Auditor collection used its own SSH channel. Those operations were not Helper MCP calls or Admin execution.

## Lab

- **Emulation:** GNS3 server 3.0.6 in an Ubuntu 24.04 virtual machine on VMware ESXi 7.0 Update 3, with nested virtualisation, QEMU 8.2.2 with KVM, Docker for the container image, and GNS3's IOL support for the two IOL binaries. A second GNS3 3.0.6 server of the same build on another ESXi host ran the vJunos and the Nexus 9300v runs marked "branch", because the first host did not have the memory to run vJunos and both Nexus images at once.
- **Management network:** each device's management port sits on a GNS3 NAT node; the device's SSH port is forwarded to it, so the runner reaches each device on its own TCP port.
- **Catalogue-series data links:** a few point-to-point links between the images (EOS to Junos as a two-member LACP bundle, EOS to IOL, IOL to IOL-L2, IOL-L2 to IOSvL2, IOSvL2 to IOSv) so that the ARP, LLDP, CDP, LACP and interface queries have something to report. That series did not measure application traffic or recovery over those links. The later T-067 topology and traffic measurements are described below.

### Images

| Platform | Image file | Version reported by `show version` | GNS3 node | Memory | Boot time on this lab |
| --- | --- | --- | --- | --- | --- |
| `arista_eos` | `ceos64-lab:4.36.1F` (Docker image imported with `docker import`) | EOS `4.36.1F-48405728.4361F` | Docker | - | about 3 minutes |
| `arista_eos` | `vEOS64-lab-4.36.1F.qcow2` with `Aboot-veos-8.0.2.iso` | EOS 4.36.1F | QEMU | 2 GB | about 15 minutes |
| `juniper_junos`, `juniper_junos_els` | `vJunos-switch-26.2R1.7.qcow2` | Junos 26.2R1.7, model `ex9214` | QEMU, 4 vCPU | 5 GB | about 13 to 25 minutes |
| `cisco_xe` | `Cisco-IOL-XE-17.18.02.bin` | IOS XE 17.18.2, `X86_64BI_LINUX-ADVENTERPRISEK9-M` | IOL | template default | about 30 seconds |
| `cisco_xe` | `Cisco-IOL-L2-XE-17.18.02.bin` | IOS XE 17.18.2, `X86_64BI_LINUX_L2-ADVENTERPRISEK9-M` | IOL | template default | about 30 seconds |
| `cisco_ios` | `IOSv-15.9-3-M12.qcow2` | IOS 15.9(3)M12, `VIOS-ADVENTERPRISEK9-M` | QEMU | template default | about 3 minutes |
| `cisco_ios` | `IOSvL2-2020.qcow2` | IOS 15.2(20200924:215240), `vios_l2-ADVENTERPRISEK9-M` | QEMU | template default | about 3 minutes |
| `cisco_nxos` | `nexus9300v.9.3.12.qcow2` | NX-OS 9.3(12) | QEMU, UEFI, SATA disk | 8 GB | about 6 minutes |
| `cisco_nxos` | `nexus9500v.9.3.12.qcow2` | NX-OS 9.3(12) | QEMU, UEFI, SATA disk | 8 GB | about 6 minutes |
| `extreme_exos` | `EXOS-VM_33.6.1.14.qcow2` | ExtremeXOS 33.6.1.14 | QEMU | template default | - |

The Arista, Juniper and Cisco images come from the vendors' own download portals (Cisco's from the free Cisco Modeling Labs reference platform bundle); EXOS-VM is published by Extreme Networks on GitHub. None of them is redistributed here.

### Settings the images needed

These are properties of the images on this kind of lab, not of NetOps, but without them the images do not come up or do not keep their configuration:

- **cEOS:** the container needs `systemd.setenv=MGMT_INTF=eth0` in its start command, or no `Management0` interface exists, and a persistent volume for `/mnt/flash`, or closing the project loses the configuration and the SSH host key.
- **vEOS:** boots from the Aboot ISO (boot order CD first) and needs the host CPU model passed through (`-cpu host`); without it the image stops with `CPU does not support x86-64-v2`. After the first start `zerotouch cancel`, or the configuration is not kept.
- **vJunos-switch:** under nested virtualisation it runs only with `-cpu host,pmu=off`; with plain `-cpu host` the inner QEMU fails on `kvm_put_msrs` and the image powers itself off after a minute. Stop it with `request system power-off` before stopping the node, or the next boot runs a file system check that takes three quarters of an hour.
- **IOL and IOL-L2:** the images have five VTY lines (`line vty 0 4`), which is what made the parallel host key scan fail (see below). Changing the NVRAM size of an existing node erases its configuration. The IOL-L2 template ships its ports shut down.
- **IOSv and IOSvL2:** offer only SHA-1 key exchange methods and an `ssh-rsa` host key, so a current OpenSSH client needs `KexAlgorithms=+diffie-hellman-group14-sha1` to talk to them at all.
- **Nexus 9300v and 9500v:** UEFI firmware, 8 GB of memory, a SATA disk; answer `yes` to abort Power On Auto Provisioning on first boot. The HSRP, VRRP and vPC commands exist only after `feature hsrp`, `feature vrrp` and `feature vpc`. In T-067 the 9300v initially stopped in the loader because its boot variable was missing. The existing image was booted and `boot nxos bootflash:/nxos.9.3.12.bin` saved. Current and next-boot settings were checked; a subsequent Nexus reboot was not measured.

## Device preparation

On every image the helper account is a dedicated local user that logs in with an SSH public key (the ExtremeXOS account also keeps a password as a fallback), with the least privilege the platform offers without a custom role. The SHA-256 fingerprint of the device's SSH host key was written into the inventory as its pin before the first call. The snippets use `<name>`, `<ed25519 key>` and `<rsa key>` for the account name and the public key.

| Platform | Account | Configuration used |
| --- | --- | --- |
| Arista EOS (cEOS, vEOS) | privilege 1, role `network-operator`, ed25519 key | `username <name> privilege 1 role network-operator nopassword`, `username <name> ssh-key <ed25519 key>` |
| Junos (vJunos-switch) | login class `read-only`, ed25519 key | `set system login user <name> class read-only authentication ssh-ed25519 "<ed25519 key>"`, `set system services ssh`; on this release the root account needs an encrypted password even with a root SSH key |
| IOS-XE (IOL, IOL-L2) and IOS (IOSv, IOSvL2) | privilege 1, RSA 3072 key | `ip domain name <domain>`, `crypto key generate rsa general-keys modulus 3072`, `ip ssh version 2`, `username <name> privilege 1`, then `ip ssh pubkey-chain` / `username <name>` / `key-string` with the key; `line vty` with `login local` and `transport input ssh` |
| NX-OS (9300v, 9500v) | role `network-operator`, RSA 3072 key | `username <name> role network-operator`, `username <name> sshkey <rsa key>` |
| ExtremeXOS (EXOS-VM) | user level, RSA key | `create account user <name>` (password asked for at the prompt, kept only as a fallback), `create sshd2 user-key <key name> <rsa key>`, `configure sshd2 user-key <key name> add user <name>`; the factory `user` account was deleted |

The inventory entries used these per-device SSH exceptions, and no others:

| Image | `legacy_ssh` | Why |
| --- | --- | --- |
| IOSv, IOSvL2 | `rsa-sha1-dh14` | SHA-1 key exchange only, `ssh-rsa` host key |
| EXOS-VM 33.6.1.14 | `rsa-sha1` | `ssh-rsa` host key only |
| all others | none | current key exchange and host key algorithms |

### What each account was refused

Checked with the same account and key, straight over SSH, before the catalogue run:

| Platform | Command tried | Device answer | Exit status |
| --- | --- | --- | --- |
| Arista EOS (cEOS) | `show running-config`, `configure`, `bash` | `% Invalid input (privileged mode required) at line 1` | 1 |
| Arista EOS (cEOS) | an unknown command | `% Invalid input at line 1` | 1 |
| Junos | `configure` | `error: unknown command: configure` | 0 |
| Junos | `show configuration system login` | `error: permission denied: system` | 0 |
| Junos | an unknown command | `error: syntax error, expecting <command>: ...` | 0 |
| IOS-XE, IOS | `show running-config`, `configure terminal`, an unknown `show` | `Line has invalid autocommand "<command>"` | 0 |
| NX-OS | `show running-config` | `% Permission denied for the role` | 30 |
| NX-OS | an unknown command | `Syntax error while parsing '<command>'` | 16 |

A refusal with exit status 0 is the reason the helper now reads the answer, not only the status: see [Changes that came out of the run](#changes-that-came-out-of-the-run).

## Method

Each run called every query of the platform's catalogue once through MCP `ssh_read`, one after another, and recorded the helper's answer: success with the device's exit status and output, or the helper's error. Queries that take a value used one enrolled value of the right kind:

| Platform | Values used |
| --- | --- |
| Arista EOS | interface `Ethernet1`; an IPv4 and an IPv6 address of a neighbour |
| Junos | physical interface `ge-0/0/0`, logical interface `irb.10`; an IPv4 and an IPv6 address |
| IOS-XE | `Ethernet0/1` on both images, `Loopback0` on the router image, `Vlan20` on the L2 image; an IPv4 and an IPv6 address. In a separate branch run `interface_details` for `Ethernet0/1` answered with exit status 0 on both images |
| IOS | `GigabitEthernet0/1`; an IPv4 and an IPv6 address |
| NX-OS | `Ethernet1/1`; an IPv4 address and an IPv6 link-local address |
| ExtremeXOS | port `1`, VLAN `Default`; an IPv4 address and an IPv6 link-local address |

How to read the cells: `exit N` means the helper returned the device's answer with exit status `N`; `device_cli_error` means the helper reported the answer as a CLI refusal, with the output kept for the caller; `outside enrolled scope` means the proxy refused the request before any connection (MCP error `-32009`); `connection refused` and `host key scan failed` are the helper's transport errors. "then" separates a first call from a repeat after the cause was dealt with, as explained under each table. A non-zero exit status does not by itself establish a failed read: several platforms end ordinary reads that way. Conversely, a returned answer or `ok: true` does not prove a feature works. Inspect the text to distinguish ordinary data, an empty or inactive feature, and a refused or unsupported command. The EXOS stacking answer below reports an unimplemented feature even though the helper returned it as a successful read.

## Results

### Arista EOS

| Query | Command | cEOS-lab 4.36.1F, 0.3.6 | cEOS-lab 4.36.1F, branch | vEOS-lab 4.36.1F, 0.3.6 | vEOS-lab 4.36.1F, branch |
| --- | --- | --- | --- | --- | --- |
| `arp_entry` | `show ip arp {address}` | exit 0 | exit 0 | exit 0 | exit 0 |
| `arp_table` | `show ip arp` | exit 0 | exit 0 | exit 0 | exit 0 |
| `bgp_summary` | `show ip bgp summary` | exit 0 | exit 0 | exit 1 | exit 1 |
| `clock` | `show clock` | exit 0 | exit 0 | exit 0 | exit 0 |
| `environment` | `show system environment all` | exit 1 | exit 1 | exit 1 | exit 1 |
| `hostname` | `show hostname` | exit 0 | exit 0 | exit 0 | exit 0 |
| `interface_details` | `show interfaces {interface}` | exit 0 | exit 0 | exit 0 | exit 0 |
| `interface_errors` | `show interfaces {interface} counters errors` | exit 0 | exit 0 | exit 0 | exit 0 |
| `interface_optics` | `show interfaces {interface} transceiver` | exit 0 | exit 0 | exit 0 | exit 0 |
| `interfaces` | `show interfaces status` | exit 0 | exit 0 | exit 0 | exit 0 |
| `inventory` | `show inventory` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ip_interfaces` | `show ip interface brief` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ipv6_bgp_summary` | `show ipv6 bgp summary` | exit 0 | exit 0 | exit 1 | exit 1 |
| `ipv6_interfaces` | `show ipv6 interface brief` | exit 0 | exit 0 | exit 1 | exit 1 |
| `ipv6_neighbor` | `show ipv6 neighbors {address}` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ipv6_neighbors` | `show ipv6 neighbors` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ipv6_route_lookup` | `show ipv6 route {address}` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ipv6_route_summary` | `show ipv6 route summary` | exit 0 | exit 0 | exit 0 | exit 0 |
| `lacp_peer_interface` | `show lacp interface {interface} peer` | exit 0 | exit 0 | exit 0 | exit 0 |
| `lacp_peers` | `show lacp peer` | exit 0 | exit 0 | exit 0 | exit 0 |
| `lag_summary` | `show port-channel dense` | exit 0 | exit 0 | exit 0 | exit 0 |
| `lldp_neighbors` | `show lldp neighbors` | exit 0 | exit 0 | exit 0 | exit 0 |
| `lldp_neighbors_interface` | `show lldp neighbors {interface}` | exit 0 | exit 0 | exit 0 | exit 0 |
| `mac_table` | `show mac address-table` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ospf_neighbors` | `show ip ospf neighbor` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ospf_neighbors_interface` | `show ip ospf neighbor {interface}` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ospfv3_neighbors` | `show ipv6 ospf neighbor` | exit 0 | exit 0 | exit 0 | exit 0 |
| `route_lookup` | `show ip route {address}` | exit 0 | exit 0 | exit 0 | exit 0 |
| `route_summary` | `show ip route summary` | exit 0 | exit 0 | exit 0 | exit 0 |
| `stp_interface` | `show spanning-tree interface {interface}` | exit 0 | exit 0 | exit 0 | exit 0 |
| `stp_root` | `show spanning-tree root` | exit 0 | exit 0 | exit 0 | exit 0 |
| `version` | `show version` | exit 0 | exit 0 | exit 0 | exit 0 |
| `vlans` | `show vlan` | exit 0 | exit 0 | exit 0 | exit 0 |

First line of each answer that was not a plain exit 0:

- `bgp_summary` (vEOS-lab 4.36.1F, 0.3.6; vEOS-lab 4.36.1F, branch): `% BGP inactive at line 1`
- `environment` (cEOS-lab 4.36.1F, 0.3.6; cEOS-lab 4.36.1F, branch; vEOS-lab 4.36.1F, 0.3.6; vEOS-lab 4.36.1F, branch): `% There seem to be no power supplies connected. at line 1`
- `ipv6_bgp_summary` (vEOS-lab 4.36.1F, 0.3.6; vEOS-lab 4.36.1F, branch): `% BGP inactive at line 1`
- `ipv6_interfaces` (vEOS-lab 4.36.1F, 0.3.6; vEOS-lab 4.36.1F, branch): `% No IPv6 configured interfaces at line 1`

cEOS is a container and has no power supplies, so `show system environment all` ends with `% There seem to be no power supplies connected.` and exit status 1. On the unconfigured vEOS the same holds for the environment query, and BGP and IPv6 were not configured, so their summaries end with exit status 1 as well. These stay successful reads in the branch: EOS reports an unconfigured feature this way, and the answer is what the caller asked for. Only `% Invalid input` is a refusal.

### Junos, `juniper_junos`

| Query | Command | vJunos-switch 26.2R1.7, 0.3.6 | vJunos-switch 26.2R1.7, branch |
| --- | --- | --- | --- |
| `arp_interface` | `show arp no-resolve interface {interface} \| no-more` | outside enrolled scope, then exit 0 (`irb.10`) | exit 0 |
| `arp_table` | `show arp no-resolve \| no-more` | exit 0 | exit 0 |
| `bgp_summary` | `show bgp summary \| no-more` | exit 0 | exit 0 |
| `chassis_alarms` | `show chassis alarms \| no-more` | exit 0 | exit 0 |
| `environment` | `show chassis environment \| no-more` | exit 0 | exit 0 |
| `hardware` | `show chassis hardware \| no-more` | exit 0 | exit 0 |
| `interface_details` | `show interfaces {interface} extensive \| no-more` | exit 0 | exit 0 |
| `interface_optics` | `show interfaces diagnostics optics {interface} \| no-more` | exit 0 | exit 0 |
| `interfaces` | `show interfaces terse \| no-more` | exit 0 | exit 0 |
| `ipv6_neighbors` | `show ipv6 neighbors \| no-more` | exit 0 | exit 0 |
| `ipv6_neighbors_interface` | `show ipv6 neighbors interface {interface} \| no-more` | outside enrolled scope, then exit 0 (`irb.10`) | exit 0 |
| `ipv6_route_lookup` | `show route {address} detail \| no-more` | exit 0 | exit 0 |
| `lacp_interface` | `show lacp interfaces {interface} \| no-more` | exit 0 | exit 0 |
| `lacp_interfaces` | `show lacp interfaces \| no-more` | exit 0 | exit 0 |
| `lldp_neighbors` | `show lldp neighbors \| no-more` | exit 0 | exit 0 |
| `lldp_neighbors_interface` | `show lldp neighbors interface {interface} \| no-more` | exit 0 | exit 0 |
| `ospf_neighbors` | `show ospf neighbor \| no-more` | exit 0 | exit 0 |
| `ospf_neighbors_interface` | `show ospf neighbor interface {interface} \| no-more` | outside enrolled scope, then exit 0 (`irb.10`) | exit 0 |
| `ospfv3_neighbors` | `show ospf3 neighbor \| no-more` | exit 0 | exit 0 |
| `ospfv3_neighbors_interface` | `show ospf3 neighbor interface {interface} \| no-more` | outside enrolled scope, then exit 0 (`irb.10`) | exit 0 |
| `route_lookup` | `show route {address} detail \| no-more` | exit 0 | exit 0 |
| `route_summary` | `show route summary \| no-more` | exit 0 | exit 0 |
| `system_alarms` | `show system alarms \| no-more` | exit 0 | exit 0 |
| `uptime` | `show system uptime \| no-more` | exit 0 | exit 0 |
| `version` | `show version \| no-more` | exit 0 | exit 0 |

The four queries marked "outside enrolled scope, then exit 0" take a logical interface (`junos_logical_interface` in the catalogue). The first run passed the physical interface `ge-0/0/0`, and the proxy refused it before connecting, as designed; with the logical interface `irb.10` enrolled they answered with exit status 0. The branch run used `irb.10` from the start.

### Junos, `juniper_junos_els`

| Query | Command | vJunos-switch 26.2R1.7, 0.3.6 | vJunos-switch 26.2R1.7, branch |
| --- | --- | --- | --- |
| `arp_interface` | `show arp no-resolve interface {interface} \| no-more` | outside enrolled scope, then exit 0 (`irb.10`) | exit 0 |
| `arp_table` | `show arp no-resolve \| no-more` | exit 0 | exit 0 |
| `bgp_summary` | `show bgp summary \| no-more` | exit 0 | exit 0 |
| `chassis_alarms` | `show chassis alarms \| no-more` | exit 0 | exit 0 |
| `environment` | `show chassis environment \| no-more` | exit 0 | exit 0 |
| `hardware` | `show chassis hardware \| no-more` | exit 0 | exit 0 |
| `interface_details` | `show interfaces {interface} extensive \| no-more` | exit 0 | exit 0 |
| `interface_optics` | `show interfaces diagnostics optics {interface} \| no-more` | exit 0 | exit 0 |
| `interfaces` | `show interfaces terse \| no-more` | exit 0 | exit 0 |
| `ipv6_neighbors` | `show ipv6 neighbors \| no-more` | exit 0 | exit 0 |
| `ipv6_neighbors_interface` | `show ipv6 neighbors interface {interface} \| no-more` | outside enrolled scope, then exit 0 (`irb.10`) | exit 0 |
| `ipv6_route_lookup` | `show route {address} detail \| no-more` | exit 0 | exit 0 |
| `lacp_interface` | `show lacp interfaces {interface} \| no-more` | exit 0 | exit 0 |
| `lacp_interfaces` | `show lacp interfaces \| no-more` | exit 0 | exit 0 |
| `lldp_neighbors` | `show lldp neighbors \| no-more` | exit 0 | exit 0 |
| `lldp_neighbors_interface` | `show lldp neighbors interface {interface} \| no-more` | exit 0 | exit 0 |
| `mac_table` | `show ethernet-switching table \| no-more` | exit 0 | exit 0 |
| `ospf_neighbors` | `show ospf neighbor \| no-more` | exit 0 | exit 0 |
| `ospf_neighbors_interface` | `show ospf neighbor interface {interface} \| no-more` | outside enrolled scope, then exit 0 (`irb.10`) | exit 0 |
| `ospfv3_neighbors` | `show ospf3 neighbor \| no-more` | exit 0 | exit 0 |
| `ospfv3_neighbors_interface` | `show ospf3 neighbor interface {interface} \| no-more` | outside enrolled scope, then exit 0 (`irb.10`) | exit 0 |
| `route_lookup` | `show route {address} detail \| no-more` | exit 0 | exit 0 |
| `route_summary` | `show route summary \| no-more` | exit 0 | exit 0 |
| `stp_bridge` | `show spanning-tree bridge \| no-more` | exit 0 | exit 0 |
| `system_alarms` | `show system alarms \| no-more` | exit 0 | exit 0 |
| `uptime` | `show system uptime \| no-more` | exit 0 | exit 0 |
| `version` | `show version \| no-more` | exit 0 | exit 0 |
| `virtual_chassis` | `show virtual-chassis status \| no-more` | exit 0 | `device_cli_error` |
| `vlans` | `show vlans brief \| no-more` | exit 0 | exit 0 |

First line of each answer that was not a plain exit 0:

- `virtual_chassis` (vJunos-switch 26.2R1.7, branch): `error: the virtual-chassis-control subsystem is not running`

`show virtual-chassis` answers `error: the virtual-chassis-control subsystem is not running` on a switch that is not a virtual chassis member, with exit status 0. Helper 0.3.6 returned that as a successful read; 0.3.7 reports it as `device_cli_error`, the same as the other `error:` answers of Junos.

### Cisco IOS-XE, `cisco_xe`

The released 0.3.6 answered every call on both IOL images with `the device refused the connection`: its host key scan opened one connection per key type at once and took all five VTY lines. Core 0.2.5 scans one key type at a time; the branch results:

| Query | Command | IOL 17.18.2 router, branch | IOL-L2 17.18.2, branch |
| --- | --- | --- | --- |
| `arp_table` | `show ip arp` | exit 0 | exit 0 |
| `bgp_summary` | `show ip bgp summary` | exit 0 | exit 0 |
| `cdp_neighbors` | `show cdp neighbors detail` | exit 0 | exit 0 |
| `clock` | `show clock` | exit 0 | exit 0 |
| `cpu` | `show processes cpu` | exit 0 | exit 0 |
| `environment` | `show environment all` | `device_cli_error` | `device_cli_error` |
| `hsrp_summary` | `show standby brief` | exit 0 | exit 0 |
| `interface_details` | `show interfaces {interface}` | exit 0 | exit 0 |
| `interface_errors` | `show interfaces {interface} counters errors` | `device_cli_error` | exit 0 |
| `interfaces` | `show interfaces status` | `device_cli_error` | exit 0 |
| `inventory` | `show inventory` | exit 0 | exit 0 |
| `ip_interfaces` | `show ip interface brief` | exit 0 | exit 0 |
| `ipv6_interfaces` | `show ipv6 interface brief` | exit 0 | exit 0 |
| `ipv6_neighbors` | `show ipv6 neighbors` | exit 0 | exit 0 |
| `ipv6_route_lookup` | `show ipv6 route {address}` | exit 0 | exit 0 |
| `lacp_neighbors` | `show lacp neighbor` | exit 0 | exit 0 |
| `lag_summary` | `show etherchannel summary` | `device_cli_error` | exit 0 |
| `lldp_neighbors` | `show lldp neighbors detail` | exit 0 | exit 0 |
| `mac_table` | `show mac address-table` | `device_cli_error` | exit 0 |
| `memory` | `show processes memory` | exit 0 | exit 0 |
| `ospf_neighbors` | `show ip ospf neighbor` | exit 0 | exit 0 |
| `route_lookup` | `show ip route {address}` | exit 0 | exit 0 |
| `route_summary` | `show ip route summary` | exit 0 | exit 0 |
| `stp_summary` | `show spanning-tree summary` | exit 0 | exit 0 |
| `version` | `show version` | exit 0 | exit 0 |
| `vlans` | `show vlan brief` | `device_cli_error` | exit 0 |
| `vrrp_summary` | `show vrrp brief` | exit 0 | exit 0 |

First line of each answer that was not a plain exit 0:

- `environment` (IOL 17.18.2 router, branch; IOL-L2 17.18.2, branch): `Line has invalid autocommand "show environment all"`
- `interface_errors` (IOL 17.18.2 router, branch): `Line has invalid autocommand "show interfaces Ethernet0/1 counters errors"`
- `interfaces` (IOL 17.18.2 router, branch): `Line has invalid autocommand "show interfaces status"`
- `lag_summary` (IOL 17.18.2 router, branch): `Line has invalid autocommand "show etherchannel summary"`
- `mac_table` (IOL 17.18.2 router, branch): `Line has invalid autocommand "show mac address-table"`
- `vlans` (IOL 17.18.2 router, branch): `Line has invalid autocommand "show vlan brief"`

The router image has no switching commands (`show interfaces status`, `show vlan brief`, `show mac address-table`, `show etherchannel summary`), no `counters errors` form of `show interfaces` and no environment sensors; the L2 image lacks only the environment command. IOS-XE answers each with `Line has invalid autocommand "<command>"` and exit status 0, which helper 0.3.7 reports as `device_cli_error`.

### Cisco IOS, `cisco_ios`

The released 0.3.6 could not reach either image: both offer only SHA-1 key exchange, which it refuses for every device, so the host key scan failed before any command. The branch, the source of Core 0.2.5 and helper 0.3.7, with `legacy_ssh: "rsa-sha1-dh14"` on these two devices only:

| Query | Command | IOSv 15.9(3)M12, branch | IOSvL2 15.2(20200924), branch |
| --- | --- | --- | --- |
| `arp_table` | `show ip arp` | exit 0 | exit 0 |
| `bgp_summary` | `show ip bgp summary` | exit 0 | exit 0 |
| `cdp_neighbors` | `show cdp neighbors detail` | exit 0 | exit 0 |
| `clock` | `show clock` | exit 0 | exit 0 |
| `cpu` | `show processes cpu` | exit 0 | exit 0 |
| `environment` | `show env all` | `device_cli_error` | `device_cli_error` |
| `hsrp_summary` | `show standby brief` | exit 0 | exit 0 |
| `interface_details` | `show interfaces {interface}` | exit 0 | exit 0 |
| `interface_errors` | `show interfaces {interface} counters errors` | `device_cli_error` | exit 0 |
| `interfaces` | `show interfaces status` | `device_cli_error` | exit 0 |
| `inventory` | `show inventory` | exit 0 | exit 0 |
| `ip_interfaces` | `show ip interface brief` | exit 0 | exit 0 |
| `ipv6_interfaces` | `show ipv6 interface brief` | exit 0 | exit 0 |
| `ipv6_neighbors` | `show ipv6 neighbors` | exit 0 | exit 0 |
| `ipv6_route_lookup` | `show ipv6 route {address}` | exit 0 | exit 0 |
| `lacp_neighbors` | `show lacp neighbor` | `device_cli_error` | exit 0 |
| `lag_summary` | `show etherchannel summary` | `device_cli_error` | exit 0 |
| `lldp_neighbors` | `show lldp neighbors detail` | exit 0 | exit 0 |
| `mac_table` | `show mac address-table` | `device_cli_error` | exit 0 |
| `memory` | `show processes memory` | exit 0 | exit 0 |
| `ospf_neighbors` | `show ip ospf neighbor` | exit 0 | exit 0 |
| `route_lookup` | `show ip route {address}` | exit 0 | exit 0 |
| `route_summary` | `show ip route summary` | exit 0 | exit 0 |
| `stp_summary` | `show spanning-tree summary` | `device_cli_error` | exit 0 |
| `version` | `show version` | exit 0 | exit 0 |
| `vlans` | `show vlan brief` | `device_cli_error` | exit 0 |
| `vrrp_summary` | `show vrrp brief` | exit 0 | exit 0 |

First line of each answer that was not a plain exit 0:

- `environment` (IOSv 15.9(3)M12, branch; IOSvL2 15.2(20200924), branch): `Line has invalid autocommand "show env all"`
- `interface_errors` (IOSv 15.9(3)M12, branch): `Line has invalid autocommand "show interfaces GigabitEthernet0/1 counters errors"`
- `interfaces` (IOSv 15.9(3)M12, branch): `Line has invalid autocommand "show interfaces status"`
- `lacp_neighbors` (IOSv 15.9(3)M12, branch): `Line has invalid autocommand "show lacp neighbor"`
- `lag_summary` (IOSv 15.9(3)M12, branch): `Line has invalid autocommand "show etherchannel summary"`
- `mac_table` (IOSv 15.9(3)M12, branch): `Line has invalid autocommand "show mac address-table"`
- `stp_summary` (IOSv 15.9(3)M12, branch): `Line has invalid autocommand "show spanning-tree summary"`
- `vlans` (IOSv 15.9(3)M12, branch): `Line has invalid autocommand "show vlan brief"`

IOSv is a router image: the switching commands, `show lacp neighbor`, `show spanning-tree summary`, the `counters errors` form and `show env all` do not exist on it. IOSvL2 lacks only the environment command.

### Cisco NX-OS, `cisco_nxos`

| Query | Command | 9300v 9.3(12), 0.3.6 | 9300v 9.3(12), branch | 9500v 9.3(12), 0.3.6 | 9500v 9.3(12), branch |
| --- | --- | --- | --- | --- | --- |
| `arp_table` | `show ip arp` | exit 0 | exit 0 | exit 0 | exit 0 |
| `bgp_sessions` | `show bgp sessions` | exit 0 | exit 0 | exit 0 | exit 0 |
| `cdp_neighbors` | `show cdp neighbors detail` | exit 0 | exit 0 | exit 0 | exit 0 |
| `clock` | `show clock` | exit 0 | exit 0 | exit 0 | exit 0 |
| `cpu` | `show processes cpu` | exit 0 | exit 0 | exit 0 | exit 0 |
| `environment` | `show environment` | exit 0 | exit 0 | exit 0 | exit 0 |
| `hsrp_summary` | `show hsrp summary` | exit 16, then exit 0 | exit 0 | exit 0 | exit 0 |
| `interface_details` | `show interface {interface}` | exit 0 | exit 0 | exit 0 | exit 0 |
| `interface_errors` | `show interface {interface} counters errors` | exit 0 | exit 0 | exit 0 | exit 0 |
| `interfaces` | `show interface status` | exit 0 | exit 0 | exit 0 | exit 0 |
| `inventory` | `show inventory` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ip_interfaces` | `show ip interface brief` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ipv6_interfaces` | `show ipv6 interface brief` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ipv6_neighbors` | `show ipv6 neighbor` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ipv6_route_lookup` | `show ipv6 route {address}` | exit 0 | exit 0 | exit 0 | exit 0 |
| `lacp_neighbors` | `show lacp neighbor` | exit 0 | exit 0 | exit 0 | exit 0 |
| `lag_summary` | `show port-channel summary` | exit 0 | exit 0 | exit 0 | exit 0 |
| `lldp_neighbors` | `show lldp neighbors detail` | exit 244 | exit 244 | exit 0 | exit 0 |
| `mac_table` | `show mac address-table` | exit 0 | exit 0 | exit 0 | exit 0 |
| `memory` | `show processes memory` | exit 0 | exit 0 | exit 0 | exit 0 |
| `ospf_neighbors` | `show ip ospf neighbors` | exit 0 | exit 0 | exit 0 | exit 0 |
| `route_lookup` | `show ip route {address}` | exit 0 | exit 0 | exit 0 | exit 0 |
| `route_summary` | `show ip route summary` | exit 0 | exit 0 | exit 0 | exit 0 |
| `stp_summary` | `show spanning-tree summary` | exit 0 | exit 0 | exit 0 | exit 0 |
| `version` | `show version` | exit 0 | exit 0 | exit 0 | exit 0 |
| `vlans` | `show vlan` | exit 0 | exit 0 | exit 0 | exit 0 |
| `vpc_peer_keepalive` | `show vpc peer-keepalive` | exit 16, then exit 0 | exit 0 | exit 0 | exit 0 |
| `vpc_role` | `show vpc role` | exit 16, then exit 0 | exit 0 | exit 0 | exit 0 |
| `vpc_status` | `show vpc brief` | exit 16, then exit 0 | exit 0 | exit 0 | exit 0 |
| `vrrp_summary` | `show vrrp summary` | exit 16, then exit 0 | exit 0 | exit 0 | exit 0 |

First line of each answer that was not a plain exit 0:

- `lldp_neighbors` (9300v 9.3(12), 0.3.6; 9300v 9.3(12), branch): `ERROR: No neighbour information`

On the 9300v the HSRP, VRRP and vPC commands answered `Syntax error while parsing '<command>'` with exit status 16 until `feature hsrp`, `feature vrrp` and `feature vpc` were enabled; afterwards they answered with exit status 0 (the 9500v run and both branch runs were made with the features enabled). `lldp_neighbors` on the 9300v ends with `ERROR: No neighbour information` and exit status 244 because its data ports had no LLDP neighbour in that run; it is a complete answer and stays a successful read. T067-034 later obtained an actual neighbour after allowing the native VLAN at both ends of the cEOS-Nexus trunk. The exit-244 cells describe the earlier topology, not a lack of LLDP support. NX-OS 9.3(12) offers current key exchange and an RSA host key with `rsa-sha2-256`, so no `legacy_ssh` exception was needed.

### ExtremeXOS on EXOS-VM, `extreme_exos`

| Query | Command | EXOS-VM 33.6.1.14, 0.3.6 | EXOS-VM 33.6.1.14, branch |
| --- | --- | --- | --- |
| `access_list_counters` | `show access-list counter` | exit 0 | exit 0 |
| `arp_address` | `show iparp {address}` | exit 0 | exit 0 |
| `arp_interface` | `show iparp port {interface}` | exit 0 | exit 0 |
| `arp_table` | `show iparp` | exit 0 | exit 0 |
| `cpu_monitoring` | `show cpu-monitoring` | exit 0 | exit 0 |
| `dhcp_snooping_entries` | `show ip-security dhcp-snooping entries vlan {vlan}` | exit 0 | exit 0 |
| `diagnostics` | `show diagnostics` | exit 0 | exit 0 |
| `edp_neighbors` | `show edp` | exit 0 | exit 0 |
| `elrp` | `show elrp` | exit 0 | exit 0 |
| `fans` | `show fans` | exit 0 | exit 0 |
| `inline_power` | `show inline-power` | exit 0 | exit 0 |
| `inline_power_port` | `show inline-power info ports {interface}` | exit 0 | exit 0 |
| `interface_details` | `show port {interface} information detail` | exit 250 | exit 250 |
| `interface_rx_errors` | `show ports {interface} rxerrors no-refresh` | exit 0 | exit 0 |
| `interface_statistics` | `show ports {interface} statistics no-refresh` | exit 0 | exit 0 |
| `interface_transceiver` | `show ports {interface} transceiver information detail` | exit 0 | exit 0 |
| `interface_tx_errors` | `show ports {interface} txerrors no-refresh` | exit 0 | exit 0 |
| `ipv6_neighbor_address` | `show neighbor-discovery cache ipv6 {address}` | exit 250 | exit 250 |
| `ipv6_neighbors` | `show neighbor-discovery cache ipv6` | exit 0 | exit 0 |
| `ipv6_route_summary` | `show iproute ipv6 summary` | exit 250 | exit 250 |
| `lacp` | `show lacp` | exit 0 | exit 0 |
| `licenses` | `show licenses` | exit 0 | exit 0 |
| `lldp_interface` | `show lldp port {interface} neighbors` | exit 0 | exit 0 |
| `lldp_interface_details` | `show lldp port {interface} neighbors detailed` | exit 0 | exit 0 |
| `lldp_neighbors` | `show lldp neighbors` | exit 0 | exit 0 |
| `mac_interface` | `show fdb ports {interface}` | exit 0 | exit 0 |
| `mac_table` | `show fdb` | exit 0 | exit 0 |
| `mcast_cache_summary` | `show mcast cache summary` | exit 0 | exit 0 |
| `memory` | `show memory` | exit 0 | exit 0 |
| `mirror` | `show mirror` | exit 0 | exit 0 |
| `ntp` | `show ntp` | exit 0 | exit 0 |
| `ports` | `show ports no-refresh` | exit 0 | exit 0 |
| `ports_configuration` | `show ports configuration no-refresh` | exit 0 | exit 0 |
| `power` | `show power` | exit 0 | exit 0 |
| `processes` | `show process` | exit 0 | exit 0 |
| `qos_profiles` | `show qosprofile` | `device_cli_error` (exit 254) | `device_cli_error` (exit 254) |
| `route_summary` | `show iproute summary` | exit 250 | exit 250 |
| `sessions` | `show session` | exit 0 | exit 0 |
| `sharing` | `show sharing` | exit 250 | exit 250 |
| `sntp_client` | `show sntp-client` | exit 0 | exit 0 |
| `stacking` | `show stacking` | exit 250 | exit 250 |
| `stacking_support` | `show stacking-support` | `device_cli_error` (exit 254) | `device_cli_error` (exit 254) |
| `stp_detail` | `show stpd detail` | exit 0 | exit 0 |
| `stp_summary` | `show stpd` | exit 0 | exit 0 |
| `switch` | `show switch` | exit 0 | exit 0 |
| `temperature` | `show temperature` | exit 0 | exit 0 |
| `version` | `show version` | exit 0 | exit 0 |
| `vlan_details` | `show vlan {vlan}` | exit 250 | exit 250 |
| `vlan_summary` | `show vlan` | exit 0 | exit 0 |

First line of each answer that was not a plain exit 0:

- `interface_details` (EXOS-VM 33.6.1.14, 0.3.6; EXOS-VM 33.6.1.14, branch): `Port: 1`
- `ipv6_neighbor_address` (EXOS-VM 33.6.1.14, 0.3.6; EXOS-VM 33.6.1.14, branch): `VR Destination`
- `ipv6_route_summary` (EXOS-VM 33.6.1.14, 0.3.6; EXOS-VM 33.6.1.14, branch): `=================ROUTE SUMMARY=================`
- `qos_profiles` (EXOS-VM 33.6.1.14, 0.3.6; EXOS-VM 33.6.1.14, branch): `%% Incomplete command`
- `route_summary` (EXOS-VM 33.6.1.14, 0.3.6; EXOS-VM 33.6.1.14, branch): `=================ROUTE SUMMARY=================`
- `sharing` (EXOS-VM 33.6.1.14, 0.3.6; EXOS-VM 33.6.1.14, branch): `Load Sharing Monitor`
- `stacking` (EXOS-VM 33.6.1.14, 0.3.6; EXOS-VM 33.6.1.14, branch): `Method is not implemented on this platform.`
- `stacking_support` (EXOS-VM 33.6.1.14, 0.3.6; EXOS-VM 33.6.1.14, branch): `%% Unrecognized command: "show stacking-support"`
- `vlan_details` (EXOS-VM 33.6.1.14, 0.3.6; EXOS-VM 33.6.1.14, branch): `VLAN Interface with name Default created by user`

Exit status 250 with a complete answer is ordinary for these reads on ExtremeXOS, as on the physical X440-G2 measured earlier. Two answers are specific to the virtual switch: `show qosprofile` is incomplete on EXOS-VM (`%% Incomplete command`) and `show stacking-support` does not exist on it; both are `device_cli_error`, with exit status 254, in the released helper already. `show stacking` answers `Method is not implemented on this platform.` with exit status 250. Helper 0.3.6 and the measured candidate returned that as a successful read with the status; helper 0.3.7 reports it as `device_cli_error`, like the two above. That change was made after the measurement, so the table still shows exit 250.

### FortiOS

The branch runner was also run against the lab FortiGate 60F with FortiOS 7.6.7 build3704 that the deployed runner already serves: `system_status`, `performance` and `interface_details` answered with exit status 0, the host key being found by the new one-type-at-a-time scan.

### `netops-auditor` on EXOS-VM

Released Auditor 0.2.7 with Core 0.2.4 collected the configuration of the EXOS-VM through its `ssh` channel, with `legacy_ssh: "rsa-sha1"` and a separate administrator account authenticated with an SSH key in that run, evaluated the 9 EXOS rules and reported one finding, `exos.logging.no-syslog-target`, which is correct for a switch without a syslog target. Core 0.2.5, then still the branch, produced a byte-identical snapshot within that comparison. The later T067-035 collector used a password credential and found the same missing-syslog rule. Its snapshot hash differed; equality across the two series is not claimed. The account was not reprovisioned in T-067, and no live finding-injection/removal experiment was performed.

## Functional and fault tests (T-067)

### Scope and provenance

The catalogue tables cover **10 virtual image variants and 7 Helper platform profiles**. Both Junos profiles use the same image; a clone on another host or a second Helper version does not add an image variant. T-067 exercised **four virtual network instances**: cEOS, vEOS, Nexus 9300v and EXOS-VM. These overlap the catalogue series and must not be added to its image count. Three Linux endpoints supplied real traffic; they are not additional switch platforms.

T-067 used the deployed Helper candidate `0.3.7-rc2-t052`, with source reference `6cfe0f54782f8401ed8c1b64b6e05ddc6d30d7b0`, through the actual proxy and runner. Auditor/Core collection used that source checkout. Documentation commit `0f79ea7` was not another software measurement. Versions were cEOS `4.36.1F-48405728.4361F` (engineering build), vEOS 4.36.1F and NX-OS 9.3(12). The original catalogue version output identifies EXOS-VM 33.6.1.14; T-067 collected that lab instance but did not independently complete a version query.

The retained record has **56 JSON attempt records: 40 PASS and 16 FAIL**, plus an initial manual entry for unavailable lab prerequisites. These include setup, harness mistakes, repetitions and cleanup. They are not 56 independent product features or a product pass rate. Corrected repetitions have new IDs; original failures remain. The full operator record and sanitized JSON evidence are retained in the project workspace. This portable report summarizes them without copying management addresses, credentials or host-specific deployment details.

### Topology and method

On the first host, a Linux client and HTTP server connected to cEOS access ports. Tests moved the server between two isolated VLANs, changed trunk membership, disabled a data port and introduced two routed VLAN interfaces. A temporary DHCP server ran only in the isolated test VLAN. Endpoints had no default route that could bypass the measured path.

For the two-host test, the local server port was shut down. The path was Linux client -> cEOS access port -> cEOS trunk -> GNS3 UDP tunnel -> Nexus trunk on the second host -> Nexus access port -> remote Linux HTTP server. A distinct response marker identified the remote server. Management used a separate path. A cEOS-vEOS data link on the first host provided another real LLDP neighbour.

A fault test required a working positive baseline, a failing data probe during the fault, and recovery after undo. Independent ICMP/HTTP checks were compared with Helper output where applicable. Initial cross-host attempts lacked that baseline because the underlay firewall denied the UDP tunnel. A narrowly scoped temporary allowance enabled the subsequent positive and fault tests; the allowance was removed afterwards. Preparation and rollback commands were direct operator actions, not NetOps Admin tests.

### Results by scenario

| Record IDs | Procedure and expected effect | Observed result and limit |
| --- | --- | --- |
| T067-003, 004 | ICMP and identifiable HTTP within a VLAN; read VLAN, MAC and interface state. | PASS: actual traffic and populated Helper output agreed. |
| T067-005, 006 | Move the server to another VLAN and return it. | PASS: isolation blocked data; restoration recovered data; management remained available. |
| T067-007, 008 | Shut and restore the server port. | PASS: data probes and Helper port state followed the change. |
| T067-009, 010, 011 | Tag the server interface, exclude its VLAN on the trunk, then restore it. | PASS: traffic passed, failed under exclusion, then recovered. |
| T067-012, 013 | Request an unenrolled interface and an injected command parameter; separately try privileged CLI operations with the read-only account. | PASS: proxy scope checks and device-level refusal of running-config, configuration mode and shell. |
| T067-014, 015 | Disable and restore SSH while retaining the data path. | PASS: Helper reported loss and recovered with the same host-key pin; HTTP continued during the SSH outage. |
| T067-016 | Route between two test VLANs; inspect routes, IP interfaces and ARP. | PASS: actual forwarding and both endpoint ARP entries. This was inter-VLAN routing, not BGP/OSPF convergence. |
| T067-017, 018 | Attach an outbound SVI ACL to block HTTP but permit ICMP. | FAIL: cEOS rejected the attachment as unsupported. Passing traffic afterwards was a control after rejection, not proof of removing an effective ACL. |
| T067-019, 020, 021 | Obtain a DHCP lease and HTTP response; request the same lease again; isolate the client in another VLAN. | PASS: acquisition, repeated acquisition and negative isolation. No timed T1/T2 renewal or relay test. |
| T067-023 | Read LLDP over the cEOS-vEOS data link. | PASS: neighbours on the actual connected data ports. |
| T067-024, P05, 024R | Establish traffic across two hosts and two vendors. | Initial FAIL from the UDP underlay deny; repeated ICMP/HTTP and both Helper version reads PASS after the temporary allowance. |
| T067-025, 025R, 034 | Read LLDP across the cEOS-Nexus trunk; repeat with its native VLAN allowed at both ends. | Initially no neighbours; final PASS on the actual trunk ports. This is a setup-dependent observation, not a precise diagnosis of where frames were lost. |
| T067-026, 026R | Disable the cross-host trunk while checking separate management. | First attempt was invalid as a fault test: no positive baseline and an unsupported NX-OS `hostname` query. Repeat with a working baseline and `version` PASS: data failed, management remained readable. |
| T067-027, 027R, 032 | Restore the trunk and measure HTTP recovery. | Early checks failed. In the controlled repetition the last failed poll ended at 19.15 s and the first successful one at 21.40 s after polling began following the enable command. This is not an exact convergence timestamp or redundant failover test. |
| T067-028, 028R, 028R2 | Send three ICMP probes with a 1472-byte payload and check HTTP. | Early attempts preceded a working/restored path; final repetition after recovery PASS. Without DF this does not prove unfragmented outer UDP delivery. |
| T067-029, 030, 031; 029R, 030R, 031R | Save a description, change it without saving, restart cEOS, verify the saved marker and traffic, then restore the baseline. | Saved configuration, HTTP and Helper version already recovered in the first run; a malformed `interfaces` parameter failed. The complete corrected repetition PASS. Container persistence, not physical ASIC reboot or an Admin transaction. |
| T067-033, 035 | Prepare EXOS through the console, then run the separate SSH Auditor collector. | Console preparation FAIL; Auditor collection PASS with one medium-severity missing-syslog finding. No live insertion/removal of a finding. |
| T067-036 through 040 | Restore configurations and Helper scope; remove the temporary underlay allowance. | PASS: EOS configuration comparisons, byte-identical original cEOS startup-config, Nexus test-port/VLAN cleanup, restored inventory scope and underlay denial. Nexus boot-variable repair retained. |
| T067-041, 042, 043 | Stop appliances, close projects and shut down the GNS3 VMs. | Initial expectation that built-in clouds report stopped failed. OS-bearing nodes stopped, projects closed, both guest shutdowns separately confirmed. Topology retained. |

Preparation records P01/P02 concern EOS command separators (LF worked where semicolons and CR did not), P03 harness handling of an inline SSH key, P04 the missing Nexus boot variable, and P05 the underlay deny. They are not evidence of product failures. Successful repetitions do not erase those records.

### Reproduction and remaining limits

Prepare separate management, isolated endpoint VLANs, persistent cEOS flash storage, a valid Nexus boot-image setting and a UDP path between GNS3 hosts. Verify a positive data baseline and actual neighbour ports before fault injection. For the measured cross-vendor LLDP setup, allow the native VLAN at both ends. Wait for observed traffic recovery instead of assuming a four-second delay is sufficient.

The Linux endpoints used FRR/BusyBox tools. Their mutable container tag was not accompanied by a recorded image digest, so byte-identical endpoint reproduction is not established. Nested images and an engineering build demonstrate behavior in this lab, not vendor certification of the environment. Hardware forwarding, PoE, physical optics/error behavior, production throughput and latency were not tested.

T-067 did not exercise forwarding on Junos, IOS, IOS-XE or Nexus 9500v, redundant LACP/STP failover, BGP/OSPF convergence, DHCP renewal timers, AAA, or an Admin apply/rollback operation. Earlier catalogue responses for these topics remain command/transport evidence; they do not fill these functional gaps. No new release build was measured during the documentation merge.

## Changes that came out of the run

Each of these came with tests that fail on the code before it:

| Released in | Component | Change |
| --- | --- | --- |
| Core 0.2.5 | `netops-core` | The host key scan asks for `ed25519`, then `ecdsa`, then `rsa`, one connection at a time, stops at the pinned key and shares one timeout. An empty answer, which `ssh-keyscan -t` gives with exit status 1 when the device has no key of that type, moves on to the next type. |
| Helper 0.3.7 | `netops-helper` | IOS and IOS-XE `Line has invalid autocommand`, EOS `% Invalid input`, Junos `error: syntax error`, `error: unknown command`, `error: permission denied` and `error: the ... subsystem is not running` are reported as `device_cli_error`. |
| Core 0.2.5, Auditor 0.2.8, Admin 0.2.3 | `netops-core`, `netops-auditor`, `netops-admin` | The per-device profile `legacy_ssh: "rsa-sha1-dh14"`: the `rsa-sha1` options plus `KexAlgorithms=+diffie-hellman-group14-sha1`. For such a device the host key is read by one `ssh` connection that offers no authentication at all, into a private temporary known-hosts file, then checked against the pin; the auditor and the admin pass the profile to the scan. |
| Helper 0.3.7 | `netops-helper` | Accepts `rsa-sha1-dh14`; `cisco_ios` and `cisco_xe` accept `Ethernet<slot>/<port>` (abbreviation `Et`, 0 to 15); NX-OS `Syntax error while parsing` and `% Permission denied for the role` are `device_cli_error`. |
| Core 0.2.5 | `netops-core` | OpenSSH 10.0p2 `ssh-keyscan` writes its `# host SSH-2.0-...` comment to standard output even when it finds no key; a scan answer counts only when it holds a line that is not a comment. |
| Helper 0.3.7 | `netops-helper` | ExtremeXOS `Method is not implemented on this platform.` is `device_cli_error`, decided after the measurement. |

## Not measured

- Physical Arista, Juniper or Cisco devices. EXOS-VM does not expand the separately measured physical ExtremeXOS coverage; the FortiOS regression check above is not a new full-device validation.
- NX-OS 10.x, the catalogue baseline (the images are 9.3(12)); a Junos routing platform (the image is an EX-family switch); IOS-XE on Catalyst hardware.
- AAA, TACACS+ or RADIUS command authorization on any of these platforms: every account was local.
- The released versions that will carry the branch fixes: the "branch" columns are a candidate build.

- The functional gaps described under [T-067](#reproduction-and-remaining-limits), including hardware forwarding and Admin execution on these images.
