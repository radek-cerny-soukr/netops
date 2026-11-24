# overview_h1 – FortiOS network overview captures (2026-11-22)

Origin of every key in `captures.json`. Keys are `<platform>/<catalogue query or monitor>/<scenario>`.

## Device and accounts

FortiGate-80F active-passive HA pair, primary member, FortiOS 8.0.2 build0251; two FortiLink FortiSwitch
224E-POE 8.0.1 build0069; three FortiAP (one connected, two disconnected), FortiAP 8.0.1 build0085.
SSH: read-only lab account `fixture-reader`, one held interactive session per capture phase (strict ED25519 pin,
no key scan, the `--More--` pager answered with a space, no console setting changed). REST: read-only API
token `fixture-api-reader`, the DER certificate SHA-256 pin checked before the token was sent. Nothing on the
device was changed.

| Phase | UTC | Session | Keys |
|---|---|---|---|
| CLI 1 | 2026-11-22 20:44:03–20:44:07 | one SSH session, 20 commands | `system_status/80f_ha_primary`, `performance/80f`, `ha_status/80f_active_passive`, `hardware_sensors/80f_psu1_absent`, `autoupdate_versions/80f`, `physical_interfaces/80f`, `system_interfaces/80f`, `interface_list/80f`, `managed_switch_status/switch1`, `managed_switch_poe/switch1`, `managed_switch_port_stats/switch1_full`, `managed_switch_stacking/switch1_refused`, `switch_fan_health/switch1`, `managed_switch_port_stats/switch2_full`, `wifi_ap_status/80f_three_aps` |
| CLI 2 | 2026-11-22 20:45:27 | one SSH session, 4 commands | `interface_details/80f_wan1`, `interface_details/80f_internal1`, `interface_hardware/80f_wan1` |
| REST | 2026-11-22 20:43–20:47 | one pinned HTTPS GET each | `switch_status/80f_live` (`/api/v2/monitor/switch-controller/managed-switch/status`), `switch_health/80f_live` (`…/managed-switch/health-status`), `managed_ap/80f_live` (`/api/v2/monitor/wifi/managed_ap`), `ap_status/80f_live` (`/api/v2/monitor/wifi/ap_status`) |

The commands are the catalogue commands of the query named in the key (`managed_switch_port_stats` without the
optional `port`, `wifi_ap_status` without `wtp_id`). `managed_switch_stacking/switch1_refused` is the device
answer for a FortiSwitch 224E-POE (`is not a stacking switch`, return code -7622).

## Preparation

1. CLI: carriage returns removed; the command echo line and the trailing prompt removed, as
   `netops_core.prompt.cleaned` removes them. REST: the JSON document as received; in `switch_status` the
   per-port `ports` lists and `faceplate_xml` are removed (same projection as
   `real/fortinet/fortigate80f_8.0.2_build0251/firewall_inventory_20261117/managed_switch_status.json`).
2. `tests/support/anonymize_fixture.py --check` in one run over all 22 inputs (rc 0): serial numbers of the
   FortiGate pair, the switches and the access points (explicit `--serial`), host, cluster, interface, tunnel
   and alias names of the lab (explicit `--name`), MAC, IPv4 and IPv6 addresses. The mapping file stayed on the
   lab test host and is not in the repository. Model codes in version strings (`S224EP`, `FP231K`) are models,
   not identifiers, and stay.
3. The anonymiser widened the gap after a shortened name in four `== [ <name> ]` headings of
   `system_interfaces/80f`; that gap was set back to the one space the device prints. Nothing else changed.
4. Counters, versions, builds, dates, uptimes, sensor readings and PoE values are real.

## Derived negative copies

The tests in `T/test_network_overview_fortinet.py` build these from the real captures above; they are marked
there with `derived(...)` and are not stored separately:

- duplicated `switch_health` row (ambiguous join by serial);
- `ap_status` with `wtp_active` raised by one (summary disagrees with the listed access points);
- a `managed_switch_port_stats` text cut in the middle of a port block (interrupted output);
- a `switch_status` envelope with `vdom` other than `root` (refused envelope);
- a duplicated `switch_status` row with another `status`, in both orders (ambiguous status serial);
- `interface_list/80f` without the block of the admin-up hardware switch (incomplete link listing);
- `interface_details/80f_wan1` under eight further enrolled names, and the 60F 7.6.8
  `firewall_routing_20261118` `interface_details_wan1` with `rxe` raised to 7 for a ninth name (detail cap).

Other inputs of the tests come from existing fixtures: the 60F 7.6.8 `get system interface` answer of
`real/fortinet/fortigate60f_7.6.8_multivdom/transcripts.json` (`94-A-extra`) with the `physical_interfaces`
capture of `real/fortinet/firewall_routing_20261118/captures.json` (`60f`), and the MCLAG ICL and trunk answers
of `T/test_switch_mclag.py` under the first switch serial.
