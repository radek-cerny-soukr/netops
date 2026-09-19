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

The table is the conservative Phase-1 whitelist. No accepted query takes a parameter, so no inventory slot exists for this profile and no caller value reaches the command line. `high-volume` follows the generated catalogue definition: a scheduling advisory for collections that grow with the network and can require continuation. `normal` is not a bounded-output promise.

| Query name | Exact command template | Inventory slot | Volume | Primary reference |
| --- | --- | --- | --- | --- |
| `system_info` | `show sysinfo` | none | normal | R-CLI-UNLEASHED-200-13 |
| `ethernet_info` | `show ethinfo` | none | normal | R-CLI-UNLEASHED-200-13 |
| `access_points` | `show ap all` | none | high-volume | R-CLI-UNLEASHED-200-13 |
| `wlans` | `show wlan all` | none | high-volume | R-CLI-UNLEASHED-200-13 |

## Excluded families

- `show config` and every other configuration display or export: the configuration boundary of Phase 1 holds for this platform too, and the Unleashed dump carries pre-shared keys and RADIUS secrets.
- Everything inside the `debug` context, `remote_ap_cli` first: it is a raw command channel to an access point, which is exactly what Phase 1 must not offer.
- `show performance ...`: on the reviewed release the command answered with its header only, so it would enrol a query with no measured output.
- Every `set`, `enable`/`disable`, `reboot`, `upgrade`, `restart` and support-bundle family.

## Deferred findings

- Client, radio, and per-WLAN statistics families: the syntax was not run on a device and their output size is unmeasured, so they stay out until both are done.
- A second Unleashed release: the catalogue was verified against 200.13 only.

## Limitations

- The `show` commands of this platform live in the same privileged context as `reboot` and the configuration commands; the context is reached with `enable`. A vendor-native role that permits only the four accepted commands has not been verified on the device - see [Read-only accounts](../read-only-accounts.md#ruckus-unleashed).
- The device has no exec channel: it answers `ssh host command` with an error and has to be driven on a pseudo-terminal, and it asks for the password a second time inside its own shell. What the helper sends there is pinned by `tests/test_ssh_wire_safety.py`.
- The access point offers only the `ssh-rsa` host key algorithm, so it is reachable only with the named per-device exception `legacy_ssh: "rsa-sha1"` and its host key pin.
