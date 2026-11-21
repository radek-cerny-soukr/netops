# NX-OS G101 fixtures

Captured over pinned SSH from the Nexus 9300v lab running NX-OS 9.3(12) on 2026-11-19. The baseline used the write identity for targeted configuration reads. Operational commands are also available to the check identity when the corresponding feature is enabled. The shared tool `components/netops-helper/tests/support/anonymize_fixture.py --check` anonymised the captures.

| Fixture | Switch and command |
|---|---|
| `empty-channels.json` | d-nxos, `show port-channel summary \| json`, exit 0 with zero bytes when no channel exists |
| `ethernet-up-admin.json` | d-nxos, `show interface Ethernet1/48 \| json`, administrative state up and link down |
| `ethernet-status.txt`, `ethernet-config.txt` | d-nxos, `show interface Ethernet1/48 status`, `show running-config interface Ethernet1/48` |
| `absent-channel.txt` | d-nxos, `show interface port-channel 140 \| json`, exit 16 when absent |
| `lacp-off.txt`, `vpc-off.txt` | d-nxos, `show feature \| include lacp`, `show feature \| include vpc` |
| `channels.json`, `vpc.json`, `keepalive.json` | b04-nx-a, `show port-channel summary \| json`, `show vpc brief \| json`, `show vpc peer-keepalive \| json` |
| `peerlink-config.txt`, `vpc-channel-config.txt`, `vpc-domain-config.txt` | b04-nx-a, targeted `show running-config interface port-channel 200`, `show running-config interface port-channel 128`, `show running-config vpc` |
| `vpc-secondary.json` | b04-nx-b, `show vpc brief \| json` |
| `lacp-on.txt`, `scheduler-off.txt`, `scheduler-b-off.txt` | b04-nx-a/b, targeted `show feature` filters for LACP and scheduler |
| `bounce-down.json` | d-nxos, `show interface Ethernet1/48 \| json` during the confirmed bounce |
| `channel-empty.json`, `channel-status.txt`, `channel-switchport.txt` | d-nxos, `show port-channel summary \| json`, `show interface port-channel140 status`, `show interface port-channel140 switchport` while the authorized Po140 existed |
| `b04-nx-a__show-feature.json`, `b04-nx-b__show-feature.json` | Full `show feature` on each B04 peer after the scheduler was permanently enabled, captured over pinned SSH on 2026-11-19. Feature rows contain no device or customer identifiers. The JSON arrays preserve the measured line endings and trailing spaces. |

The fake transport derives a dormant LACP member from the B04 member row and the real empty channel row,
and derives a dormant vPC assignment and an empty domain from the B04 vPC table. The membership and
vPC writes were unavailable in the live lab. The peer-link and keepalive tests adapt the measured B04
shape to the test object's state. Truncation cases deliberately omit data from the captured shapes.

`vpc-unconfigured-vendor.txt` is the unconfigured-domain status line from Cisco's Nexus 9336C-FX2
9.3(3) CLI example. [Cisco vPC troubleshooting, §3.2](https://community.cisco.com/t5/tkb-%E3%83%87%E3%83%BC%E3%82%BF-%E3%82%BB%E3%83%B3%E3%82%BF%E3%83%BC-%E3%83%89%E3%82%AD%E3%83%A5%E3%83%A1%E3%83%B3%E3%83%88/nexus-%E3%82%B7%E3%83%AA%E3%83%BC%E3%82%BA-vpc-%E3%81%AE%E3%83%88%E3%83%A9%E3%83%96%E3%83%AB%E3%82%B7%E3%83%A5%E3%83%BC%E3%83%86%E3%82%A3%E3%83%B3%E3%82%B0/ta-p/4076902)
