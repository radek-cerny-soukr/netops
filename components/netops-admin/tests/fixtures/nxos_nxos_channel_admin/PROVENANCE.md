# NX-OS nxos channel admin fixtures

Captured over pinned SSH from the Nexus 9300v lab running NX-OS 9.3(12) on 2026-11-19. The baseline used the write identity for targeted configuration reads. Operational commands are also available to the check identity when the corresponding feature is enabled. The shared tool `components/netops-helper/tests/support/anonymize_fixture.py --check` anonymised the captures.

| Fixture | Switch and command |
|---|---|
| `empty-channels.json` | Nexus 9300v, NX-OS 9.3(12), `show port-channel summary \| json`, exit 0 with zero bytes when no channel exists |
| `ethernet-up-admin.json` | Nexus 9300v, NX-OS 9.3(12), `show interface Ethernet1/48 \| json`, administrative state up and link down |
| `ethernet-status.txt`, `ethernet-config.txt` | Nexus 9300v, NX-OS 9.3(12), `show interface Ethernet1/48 status`, `show running-config interface Ethernet1/48` |
| `absent-channel.txt` | Nexus 9300v, NX-OS 9.3(12), `show interface port-channel 140 \| json`, exit 16 when absent |
| `lacp-off.txt`, `vpc-off.txt` | Nexus 9300v, NX-OS 9.3(12), `show feature \| include lacp`, `show feature \| include vpc` |
| `channels.json`, `vpc.json`, `keepalive.json` | nexus-peer-a, `show port-channel summary \| json`, `show vpc brief \| json`, `show vpc peer-keepalive \| json` |
| `peerlink-config.txt`, `vpc-channel-config.txt`, `vpc-domain-config.txt` | nexus-peer-a, targeted `show running-config interface port-channel 200`, `show running-config interface port-channel 128`, `show running-config vpc` |
| `vpc-secondary.json` | nexus-peer-b, `show vpc brief \| json` |
| `lacp-on.txt`, `scheduler-off.txt`, `scheduler-b-off.txt` | nexus-peer-a/b, targeted `show feature` filters for LACP and scheduler |
| `bounce-down.json` | Nexus 9300v, NX-OS 9.3(12), `show interface Ethernet1/48 \| json` during the confirmed bounce |
| `channel-empty.json`, `channel-status.txt`, `channel-switchport.txt` | Nexus 9300v, NX-OS 9.3(12), `show port-channel summary \| json`, `show interface port-channel140 status`, `show interface port-channel140 switchport` while the authorized Po140 existed |
| `nexus-peer-a__show-feature.json`, `nexus-peer-b__show-feature.json` | Full `show feature` on each switch-pair peer after the scheduler was permanently enabled, captured over pinned SSH on 2026-11-19. Feature rows contain no device or customer identifiers. The JSON arrays preserve the measured line endings and trailing spaces. |

The fake transport derives a dormant LACP member from the switch-pair member row and the real empty channel row,
and derives a dormant vPC assignment and an empty domain from the switch-pair vPC table. The membership and
vPC writes were unavailable in the live lab. The peer-link and keepalive tests adapt the measured switch-pair
shape to the test object's state. Truncation cases deliberately omit data from the captured shapes.

`vpc-unconfigured-vendor.txt` is the unconfigured-domain status line from Cisco's Nexus 9336C-FX2
9.3(3) CLI example. [Cisco vPC troubleshooting, §3.2](https://community.cisco.com/t5/tkb-%E3%83%87%E3%83%BC%E3%82%BF-%E3%82%BB%E3%83%B3%E3%82%BF%E3%83%BC-%E3%83%89%E3%82%AD%E3%83%A5%E3%83%A1%E3%83%B3%E3%83%88/nexus-%E3%82%B7%E3%83%AA%E3%83%BC%E3%82%BA-vpc-%E3%81%AE%E3%83%88%E3%83%A9%E3%83%96%E3%83%AB%E3%82%B7%E3%83%A5%E3%83%BC%E3%83%86%E3%82%A3%E3%83%B3%E3%82%B0/ta-p/4076902)

## Unpaired domain, missing peer-link and STP port type (2026-11-22)

Captured over pinned SSH on 2026-11-22 with the check identity (`netops-ro`) for JSON and the write identity for
targeted configuration reads. Addresses of the keepalive destination are replaced by documentation addresses.

| Fixture | Switch and command |
|---|---|
| `vpc-feature-without-domain.json` | single Nexus 9000v, NX-OS 9.3(12), `show vpc brief \| json` with `feature vpc` and no domain |
| `vpc-unpaired-domain.json`, `keepalive-unpaired-domain.json` | single Nexus 9000v, NX-OS 9.3(12), `show vpc brief \| json` and `show vpc peer-keepalive \| json` after `vpc domain 967` with a keepalive to an unused on-link address (no peer): no `TABLE_*`, no `vpc-end`, no table headers |
| `vpc-without-peer-link.json` | second switch of the vPC pair, `show vpc brief \| json` with the keepalive `peer-alive` and neither a peer-link nor vPC rows |
| `vpc-peer-link-only.json` | the same switch with `vpc peer-link` on a memberless trunk port-channel and no vPC rows: `TABLE_peerlink` and a single `vpc-end` string |
| `peer-link-stp-port-type.txt` | the same switch, targeted `show running-config interface port-channel201` after each step: `vpc peer-link` always leaves `spanning-tree port type network` (it replaces `edge trunk` or adds the line), `no vpc peer-link` removes any `spanning-tree port type` line |

The fake transport keeps deriving its answers from `vpc.json`, but drops the table headers and `vpc-end` exactly as
the captures above show when the domain has no peer-link and no vPC rows, and keeps one `vpc-end` string for a
peer-link without vPC rows. Its port-channel model follows `peer-link-stp-port-type.txt`.
