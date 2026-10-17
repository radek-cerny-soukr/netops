# Vendor CLI reference index

The references describe platform-specific query grammar, account requirements and compatibility limits. A documented virtual-image profile is not universal model or firmware support.

These records preserve official vendor URLs and the audit decisions used to build the conservative Phase-1 query whitelist. They do not copy vendor manuals, command-reference chapters, or complete PDF content.

The exact machine-checked commands, typed slots, volume labels, descriptions, and per-query source links are in the [generated query catalog](query-catalog.md); its public source-ID registry is [`query-sources.json`](query-sources.json).

## Audited profiles

| Platform / profile key | Documentation baseline | Source record | Live-wire status |
|---|---|---|---|
| `fortinet` (`fortios` alias) | FortiOS 7.6.x and 8.0.0 | [Fortinet FortiOS](vendor-cli-references/fortinet-fortios.md) | The earlier 40-query catalogue has live read-only evidence; six additions have separate CLI evidence, with controller restricted-profile checks still outstanding. Four diagnostic state views have native SSH observations on VM 7.6.7/8.0.0 dated 2026-10-04; restricted-role Helper validation remains pending. Validate each deployed appliance, firmware, VDOM and role. |
| `extreme_exos` (`extreme_switch_engine` alias) | Switch Engine 33.7.1 | [Extreme Networks Switch Engine](vendor-cli-references/extreme-switch-engine.md) | The earlier 47-query catalogue has dated live read-only evidence; two additions have direct CLI observations. All 49 queries of that catalogue were also run on 25 September 2026 against the EXOS-VM 33.6.1.14 virtual switch; `sharing` has since been withdrawn and the current catalogue has 48. See the source record and support matrix for scope; validate the deployed model and AAA path. |
| `cisco_ios` | Catalyst IOS 15.2(7)E on Catalyst 2960-X | [Cisco IOS, IOS-XE, and NX-OS](vendor-cli-references/cisco.md) | IOSv 15.9(3)M12 and IOSvL2 15.2 virtual-image scope, privilege-1 account and explicit rsa-sha1-dh14 profile; unavailable commands are device_cli_error. Catalyst hardware, parser views and AAA require separate validation. |
| `cisco_xe` | Catalyst IOS-XE 17.15.x on Catalyst 9300 | [Cisco IOS, IOS-XE, and NX-OS](vendor-cli-references/cisco.md) | IOS-XE 17.18.2 IOL router/L2 image scope with privilege-1 accounts; sequential host-key scans and exact enabled features apply. Catalyst hardware and AAA require separate verification. |
| `cisco_nxos` | Nexus 9000 NX-OS 10.5(x) | [Cisco IOS, IOS-XE, and NX-OS](vendor-cli-references/cisco.md) | Nexus 9300v/9500v NX-OS 9.3(12) virtual-image scope with network-operator role. NX-OS 10.x, physical hardware and AAA require independent enrollment. |
| `arista_eos` | EOS 4.36.x, primarily 4.36.2F | [Arista EOS](vendor-cli-references/arista-eos.md) | EOS 4.36.1F virtual-image scope with network-operator role; hardware, licensed features and AAA require separate validation. |
| `juniper_junos` | Junos OS 23.4R2 common cross-family profile | [Juniper Junos](vendor-cli-references/juniper-junos.md) | vJunos-switch 26.2R1.7 scope with read-only login class; routing platforms, physical hardware and AAA require separate validation. |
| `juniper_junos_els` | Junos OS 23.4R2 EX/QFX ELS superset | [Juniper Junos](vendor-cli-references/juniper-junos.md) | vJunos-switch 26.2R1.7 ELS profile with reported model identifier ex9214 and read-only login class. A virtual model identifier does not establish physical EX/QFX support. |
| `ruckus_unleashed` | Unleashed 200.13 | [Ruckus Unleashed](vendor-cli-references/ruckus-unleashed.md) | Source and one device run on 16 September 2026; the four accepted commands and the pseudo-terminal login are pinned by the wire test. A read-only account model on the device is not verified. |

Source review establishes documented syntax and helps reject unsafe, secret-bearing, mutating, or unbounded command families. It does not prove that a particular hardware model, software image, feature license, local RBAC role, or TACACS+/RADIUS policy accepts a command. It also does not prove what an SSH driver transmits during login, paging setup, command execution, or cleanup.

EXOS show sharing is excluded on both VM and physical platforms; historical measurements do not establish current support. See [the measured restriction](vendor-cli-references/extreme-switch-engine.md#unsupported-show-sharing).

## Updating an audit

When adding a command or supporting a newer vendor release:

1. Select an explicit product and software baseline; do not infer compatibility from a shared command name.
2. Verify exact syntax, operational privilege, model and licence scope, output bounds, side effects, and secret exposure using current first-party documentation.
3. Record the primary URL, accepted or excluded decision, reason, high-volume classification, and any deferred live-test condition in the appropriate vendor file.
4. Update the implementation and its literal catalogue oracle in the same reviewed change. Slots must remain typed and inventory-bound.
5. Test the exact read-only account and AAA policy on the intended model, then perform a bytes-on-wire test covering prompts, paging, command echo, timeouts, and session cleanup.
6. Update the audit date only for the profiles and decisions actually re-reviewed.

A source-only finding must stay deferred when exact syntax, output safety, AAA behavior, or wire behavior remains uncertain.
