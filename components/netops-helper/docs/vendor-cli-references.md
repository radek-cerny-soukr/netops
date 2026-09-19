# Vendor CLI reference index

Audit date: 2026-09-09.

These records preserve official vendor URLs and the audit decisions used to build the conservative Phase-1 query whitelist. They do not copy vendor manuals, command-reference chapters, or complete PDF content.

The exact machine-checked commands, typed slots, volume labels, descriptions, and per-query source links are in the [generated query catalog](query-catalog.md); its public source-ID registry is [`query-sources.json`](query-sources.json).

## Audited profiles

| Platform / profile key | Documentation baseline | Source record | Live-wire status |
|---|---|---|---|
| `fortinet` (`fortios` alias) | FortiOS 7.6.x and 8.0.0 | [Fortinet FortiOS](vendor-cli-references/fortinet-fortios.md) | FortiOS session safety has a dedicated wire test; each appliance, firmware, VDOM, query, and read-only role still requires target validation. |
| `extreme_exos` (`extreme_switch_engine` alias) | Switch Engine 33.7.1 | [Extreme Networks Switch Engine](vendor-cli-references/extreme-switch-engine.md) | Source-reviewed; live model, read-only AAA, paging, and bytes-on-wire validation remain required. |
| `cisco_ios` | Catalyst IOS 15.2(7)E on Catalyst 2960-X | [Cisco IOS, IOS-XE, and NX-OS](vendor-cli-references/cisco.md) | Source-reviewed; live model/image, CLI-view or AAA authorization, paging, and bytes-on-wire validation remain required. |
| `cisco_xe` | Catalyst IOS-XE 17.15.x on Catalyst 9300 | [Cisco IOS, IOS-XE, and NX-OS](vendor-cli-references/cisco.md) | Source-reviewed separately from IOS; live target and wire validation remain required. |
| `cisco_nxos` | Nexus 9000 NX-OS 10.5(x) | [Cisco IOS, IOS-XE, and NX-OS](vendor-cli-references/cisco.md) | Source-reviewed separately from IOS/IOS-XE; live Nexus model, feature, AAA, and wire validation remain required. |
| `arista_eos` | EOS 4.36.x, primarily 4.36.2F | [Arista EOS](vendor-cli-references/arista-eos.md) | Source-reviewed; live model, licensed-feature, RBAC/AAA, paging, and bytes-on-wire validation remain required. |
| `juniper_junos` | Junos OS 23.4R2 common cross-family profile | [Juniper Junos](vendor-cli-references/juniper-junos.md) | Source-reviewed; live product-family, login-class/AAA, fixed-pipe, and bytes-on-wire validation remain required. |
| `juniper_junos_els` | Junos OS 23.4R2 EX/QFX ELS superset | [Juniper Junos](vendor-cli-references/juniper-junos.md) | Source-reviewed as an explicit switch-only superset; model capability and live wire validation remain required before selection. |
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
