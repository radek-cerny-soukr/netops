# Identity text fixtures

Selected operational lines from public examples, with hostnames and serials replaced
by `lab-*` / `LAB*`; unrelated sections omitted. Supplemental outputs are separate
from version output. These parser fixtures do not qualify hardware or account rights.

- IOS: [Cisco Catalyst 2960 show version](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960/software/release/12-2_44_se/command/reference/cr/cli2.pdf).
- IOS XE: [Cisco Catalyst 9300 system management](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/sys_mgmt/b_179_sys_mgmt_9300_cg.html). Version and uptime fields retain the text layout; hostname/serial anonymized.
- NX-OS: [Cisco show version public parser example](https://github.com/CiscoTestAutomation/genieparser/issues/920); [Nexus 9336C example](https://docs.netapp.com/us-en/ontap-systems-switches/switch-cisco-9336c-fx2/install-nxos-software-9336c-cluster.html).
- EOS: [Arista CLI, show version](https://www.arista.com/en/um-eos/eos-command-line-interface-cli).
- Junos: [Juniper SRX upgrade examples](https://www.juniper.net/documentation/us/en/software/junos/srx-upgrade/srx-upgrade.pdf); ELS model variation follows [show version](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-version.html).
- EXOS: [Extreme hardware compatibility, X620 example](https://www.extremenetworks.com/support/compatibility-matrices/summit-extremeswitching-and-e4g-components-extremexos-software-support), [show version](https://documentation.extremenetworks.com/exos_32.2/GUID-C9F3FABF-4209-4023-BC5A-0914CCCB91D8.shtml).

Short fixtures cover only identity fields; synthetic negative cases live in tests.

- IOS XE ISR (`cisco_xe_isr4331.txt`): selected show version lines from [Cisco ISR 4000 flash memory guide](https://www.cisco.com/c/en/us/td/docs/routers/access/4400/flashmemory/isr4000_flashmem.pdf), hostname and serial anonymized. The Catalyst XE fixture is a synthetic field-layout variation; the ISR fixture preserves the documented version/model/uptime lines.

## Complete `show version` outputs (`full_*.txt`)

Whole published examples, only hostname/serial replaced by `lab-*`/`LAB*`:

- `full_cisco_ios_3660.txt`: classic IOS router, [Cisco IOS Configuration Fundamentals Command Reference, show version, Cisco 3660 example](https://www.cisco.com/c/en/us/td/docs/ios/fundamentals/command/reference/cf_book/cf_s4.html) (`... processor (revision 1.0) with ...`).
- `full_cisco_nxos_n5548.txt`: Nexus 5548 `Chassis ("...")` form with kickstart/BIOS lines, [Cisco-hosted N5548UP switch configurations](https://www.cisco.com/c/dam/en/us/td/docs/solutions/Enterprise/collaboration/Remote_Expert/config/N5548UP_switch_configs.pdf) (login banner and unrelated `show` sections omitted).
- `full_arista_eos_dcs7150.txt`: [Arista EOS CLI, Viewing the Model Number](https://www.arista.com/en/um-eos/eos-command-line-interface-cli); serial and MAC replaced.
- `full_extreme_exos.txt`: first example of [ExtremeXOS show version](https://documentation.extremenetworks.com/exos_32.2/GUID-C9F3FABF-4209-4023-BC5A-0914CCCB91D8.shtml); serial replaced.
- `full_juniper_junos_mx480.txt`: MX480 example of [Juniper show version](https://www.juniper.net/documentation/us/en/software/junos/junos-overview/topics/ref/command/show-version.html); the page itself elides the rest of the module list.

## Synthetic layout fixtures

`synthetic_cisco_xe_stack_16.txt` (IOS XE 16.x Catalyst stack table, `Switch uptime`, control-processor uptime) and `synthetic_juniper_junos_vc_mixed.txt` (virtual chassis with `fpc0:`/`fpc1:` blocks and mixed EX4300 models) follow the vendor layouts but are not copies of a published output.
Model strings for Catalyst 1000 (`cisco C1000-24T-4G-L (ARM) processor`), IOSv (`Cisco IOSv (revision 1.0) with`), Arista `CCS-720XP-48ZC2`, `AWE-` and Junos `vqfx-10000` are exercised in tests as single lines; the ISR line `Cisco CISCO2901/K9 (revision 1.0) with 999424K/49152K bytes of memory` is quoted from [Cisco, Compare Features to Select the Best Software Release](https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-software-releases-121-t/15071-choosing-ios.html).
