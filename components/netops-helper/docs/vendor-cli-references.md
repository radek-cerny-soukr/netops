# Vendor CLI reference index

Initial source audit: 2026-09-09. Scoped EXOS/FortiOS additions and their measured limits were reviewed on 2026-09-21. The Arista, Juniper and Cisco profiles were run against virtual images on 2026-09-25 ([live lab measurements](../../../docs/lab-measurements-2026-09-25.md)); other profiles retain their dated evidence.

These records preserve official vendor URLs and the audit decisions used to build the conservative Phase-1 query whitelist. They do not copy vendor manuals, command-reference chapters, or complete PDF content.

The exact machine-checked commands, typed slots, volume labels, descriptions, and per-query source links are in the [generated query catalog](query-catalog.md); its public source-ID registry is [`query-sources.json`](query-sources.json).

## Audited profiles

| Platform / profile key | Documentation baseline | Source record | Live-wire status |
|---|---|---|---|
| `fortinet` (`fortios` alias) | FortiOS 7.6.x and 8.0.0 | [Fortinet FortiOS](vendor-cli-references/fortinet-fortios.md) | The earlier 40-query catalogue has live read-only evidence; six additions have separate CLI evidence, with controller restricted-profile checks still outstanding. Validate each deployed appliance, firmware, VDOM and role. |
| `extreme_exos` (`extreme_switch_engine` alias) | Switch Engine 33.7.1 | [Extreme Networks Switch Engine](vendor-cli-references/extreme-switch-engine.md) | The earlier 47-query catalogue has dated live read-only evidence; two additions have direct CLI observations. All 49 queries were also run on 25 September 2026 against the EXOS-VM 33.6.1.14 virtual switch. See the source record and support matrix for scope; validate the deployed model and AAA path. |
| `cisco_ios` | Catalyst IOS 15.2(7)E on Catalyst 2960-X | [Cisco IOS, IOS-XE, and NX-OS](vendor-cli-references/cisco.md) | All 27 queries run on 25 September 2026 against IOSv 15.9(3)M12 and IOSvL2 15.2 with a privilege-1 account, with the `rsa-sha1-dh14` profile of Core 0.2.5 and helper 0.3.7 (these images speak SHA-1 key exchange only); commands an image lacks are `device_cli_error`. No Catalyst hardware, parser view or AAA authorization measured. |
| `cisco_xe` | Catalyst IOS-XE 17.15.x on Catalyst 9300 | [Cisco IOS, IOS-XE, and NX-OS](vendor-cli-references/cisco.md) | All 27 queries run on 25 September 2026 against the IOL and IOL-L2 17.18.2 images with a privilege-1 account; they need the one-type-at-a-time host key scan of Core 0.2.5 (five VTY lines). No Catalyst hardware or AAA authorization measured. |
| `cisco_nxos` | Nexus 9000 NX-OS 10.5(x) | [Cisco IOS, IOS-XE, and NX-OS](vendor-cli-references/cisco.md) | All 30 queries run on 25 September 2026 against Nexus 9300v and 9500v NX-OS 9.3(12) with role `network-operator`, through the released helper. NX-OS 10.x, hardware and AAA remain unmeasured. |
| `arista_eos` | EOS 4.36.x, primarily 4.36.2F | [Arista EOS](vendor-cli-references/arista-eos.md) | All 33 queries run on 25 September 2026 against cEOS-lab and vEOS-lab 4.36.1F with role `network-operator`, through the released helper. Hardware, licensed features and AAA remain unmeasured. |
| `juniper_junos` | Junos OS 23.4R2 common cross-family profile | [Juniper Junos](vendor-cli-references/juniper-junos.md) | All 25 queries run on 25 September 2026 against vJunos-switch 26.2R1.7 with login class `read-only`, through the released helper. Routing platforms, hardware and AAA remain unmeasured. |
| `juniper_junos_els` | Junos OS 23.4R2 EX/QFX ELS superset | [Juniper Junos](vendor-cli-references/juniper-junos.md) | All 29 queries run on 25 September 2026 against vJunos-switch 26.2R1.7 (model `ex9214`) with login class `read-only`, through the released helper. Physical EX/QFX models remain unmeasured. |
| `ruckus_unleashed` | Unleashed 200.13 | [Ruckus Unleashed](vendor-cli-references/ruckus-unleashed.md) | Source and one device run on 16 September 2026; the four accepted commands and the pseudo-terminal login are pinned by the wire test. A read-only account model on the device is not verified. |

Source review establishes documented syntax and helps reject unsafe, secret-bearing, mutating, or unbounded command families. It does not prove that a particular hardware model, software image, feature license, local RBAC role, or TACACS+/RADIUS policy accepts a command. It also does not prove what an SSH driver transmits during login, paging setup, command execution, or cleanup.

## Updating an audit

When adding a command or supporting a newer vendor release:

1. Select an explicit product and software baseline; do not infer compatibility from a shared command name.
2. Verify exact syntax, operational privilege, model and licence scope, output bounds, side effects, and secret exposure using current first-party documentation.
3. Record the primary URL, accepted or excluded decision, reason, high-volume classification, and any deferred live-test condition in the appropriate vendor file.
4. Update the implementation and its literal catalogue oracle in the same reviewed change. Slots must remain typed and inventory-bound.
5. Test the exact read-only account and AAA policy on the intended model, then perform a bytes-on-wire test covering prompts, paging, command echo, timeouts, and session cleanup.
6. Update the audit date only for the profiles and decisions actually re-reviewed.

A source-only finding must stay deferred when exact syntax, output safety, AAA behavior, or wire behavior remains uncertain.
