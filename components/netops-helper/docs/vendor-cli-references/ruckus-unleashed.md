# Ruckus Unleashed CLI references

## Review baseline and limits

- Vendor: Ruckus.
- Product and document title: Ruckus Unleashed 200.13 CLI Reference Guide.
- Reviewed version: Unleashed 200.13.
- Verification date: 2026-09-16.
- Catalog module: `src/netops_helper/query_catalog/ruckus.py`.

The exact machine-checked templates and per-query source records are in the [generated query catalog](../query-catalog.md); the source-ID records are in [`query-sources.json`](../query-sources.json).

This vendor guide is reachable only behind a vendor support login, so no public URL is recorded for it and the registry carries no link for this profile. The four accepted commands were therefore also run once on an Unleashed access point on 16 September 2026 and answered with the documented syntax; that date is what the catalogue row states. Nothing here records which device that was.

Source review plus one device run establish syntax. They are not proof that another Unleashed release, model, or account permits a command. Everything the access point returns is sensitive, untrusted device data: WLAN names, radio and client counts, addresses, and access-point identity disclose operational detail.

## Accepted Phase-1 queries

The table is the conservative Phase-1 whitelist. The first four queries take no parameter. Selected client, radio, AP and WLAN reads were run read-only on an R610 access point with Ruckus Unleashed 200.15.6.212.27 on 17 November 2026. Rows with the inventory slot `none`, such as `clients`, take no parameter. The parameterised variants take the values named in the table: a lower-case MAC literal, or an AP device name (`wtp_ids`) or WLAN name (`wlan_names`) that is enrolled or was listed by `access_points` / `wlans` on the same target. An absent object answers `The entry '...' could not be found.`, which the Helper reports as a refusal. `high-volume` follows the generated catalogue definition: a scheduling advisory for collections that grow with the network and can require continuation. `normal` is not a bounded-output promise.

| Query name | Exact command template | Inventory slot | Volume | Primary reference |
| --- | --- | --- | --- | --- |
| `system_info` | `show sysinfo` | none | normal | R-CLI-UNLEASHED-200-13 |
| `ethernet_info` | `show ethinfo` | none | normal | R-CLI-UNLEASHED-200-13 |
| `access_points` | `show ap all` | none | high-volume | R-CLI-UNLEASHED-200-13 |
| `wlans` | `show wlan all` | none | high-volume | R-CLI-UNLEASHED-200-13 |
| `clients` | `show current-active-clients all` | none | high-volume | R-CLI-UNLEASHED-200-13 |
| `client_detail` | `show current-active-clients mac {mac}` | `literal.wifi_mac_literal` | normal | R-CLI-UNLEASHED-200-13 |
| `client_performance` | `show performance station mac {mac}` | `literal.wifi_mac_literal` | normal | R-CLI-UNLEASHED-200-13 |
| `radio_performance_24` | `show performance ap-radio2-4 mac {ap_mac}` | `literal.wifi_mac_literal` | normal | R-CLI-UNLEASHED-200-13 |
| `radio_performance_5` | `show performance ap-radio5 mac {ap_mac}` | `literal.wifi_mac_literal` | normal | R-CLI-UNLEASHED-200-13 |
| `rogue_devices` | `show rogue-devices` | none | high-volume | R-CLI-UNLEASHED-200-13 |
| `events` | `show events` | none | high-volume | R-CLI-UNLEASHED-200-13 |
| `events_activities` | `show events-activities` | none | high-volume | R-CLI-UNLEASHED-200-15 |
| `mesh_topology` | `show mesh topology` | none | high-volume | R-CLI-UNLEASHED-200-15 |
| `access_point` | `show ap mac {ap_mac}` | `literal.wifi_mac_literal` | normal | R-CLI-UNLEASHED-200-13 |
| `access_point_by_name` | `show ap devname {wtp_id}` | `wtp_ids.fortios_wtp_id` | normal | R-CLI-UNLEASHED-200-13 |
| `wlan` | `show wlan name {wlan}` | `wlan_names.ruckus_wlan_name` | normal | R-CLI-UNLEASHED-200-13 |
| `ping` | `ping {address}` | `addresses.ipv4_address` | normal | R-CLI-UNLEASHED-200-13 |
| `l2_acls` | `show l2acl all` | none | high-volume | R-CLI-UNLEASHED-200-13 |
| `mgmt_acls` | `show mgmt-acl all` | none | normal | R-CLI-UNLEASHED-200-13 |
| `l3_acls` | `show l3acl all` | none | high-volume | R-CLI-UNLEASHED-200-13 |
| `aaa_servers` | `show aaa all` | none | normal | R-CLI-UNLEASHED-200-13 |
| `dhcp_relays` | `show dhcp all` | none | normal | R-CLI-UNLEASHED-200-13 |
| `static_routes` | `show static-route all` | none | normal | R-CLI-UNLEASHED-200-13 |
| `config_settings` | `show config` | none | high-volume | R-CLI-UNLEASHED-200-13 |

The Ruckus Unleashed 200.15 CLI Reference Guide documents the event and mesh topology queries. The R610 on Ruckus Unleashed 200.15.6.212.27 answered both on 18 November 2026. The event query matched the existing `events` alias on that device.

`ping` (18 November 2026, Ruckus Unleashed 200.15.6.212.27): the device `help` lists only `ping <IP-ADDR/DOMAIN-NAME>` and `ping <IP-ADDR/DOMAIN-NAME> -s <NUMBER>` (packet size). There is no count or time option; the device always sends three echo requests and, when nothing answers, ends after about 12 seconds. The catalogue renders only an enrolled IPv4 literal (no host name, no `-s`). It is a probe from the master AP management plane, not from a client data path.

## Excluded families

- A free `show config`, the raw configuration dump and every other configuration display or export: the configuration boundary of Phase 1 holds for this platform too, and the Unleashed dump carries pre-shared keys and RADIUS secrets. The only exception is `config_settings` above: it runs the fixed `show config` and returns only the common settings sections named in its catalogue description, with every other section withheld and every secret redacted.
- Everything inside the `debug` context, `remote_ap_cli` first: it is a raw command channel to an access point, which is exactly what Phase 1 must not offer.
- `show performance` families other than `ap-radio2-4`, `ap-radio5` and `station` (on 200.13 the command answered with its header only; the three accepted forms returned counters on Ruckus Unleashed 200.15.6.212.27).
- Every `set`, `enable`/`disable`, `reboot`, `upgrade`, `restart` and support-bundle family.

## Deferred findings

- A second Unleashed release: the default reference is the 200.13 guide. Selected commands were verified live on an R610 with Ruckus Unleashed 200.15.6.212.27 in the scope described above. Other releases and models have not been verified.

## Limitations

- The `show` commands of this platform live in the same privileged context as `reboot` and the configuration commands; the context is reached with `enable`. A vendor-native role that permits only the four accepted commands has not been verified on the device - see [Read-only accounts](../read-only-accounts.md#ruckus-unleashed).
- The device has no exec channel: it answers `ssh host command` with an error and has to be driven on a pseudo-terminal, and it asks for the password a second time inside its own shell. What the helper sends there is pinned by `tests/test_ssh_wire_safety.py`.
- The access point offers only the `ssh-rsa` host key algorithm, so it is reachable only with the named per-device exception `legacy_ssh: "rsa-sha1"` and its host key pin.
