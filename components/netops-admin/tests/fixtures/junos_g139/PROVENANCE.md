# G139 Junos operational fixtures

The task captured operational output from `netops-ro` on d-vjunos, vJunos-switch 26.2R1.7, on 2026-11-19 UTC. The capture ran from PC-Radek through the pinned SSH endpoint. Outputs were passed through `components/netops-helper/tests/support/anonymize_fixture.py --check`. The capture commands are in `task-evidence/g139/capture.py` and `task-evidence/g139/live.py`.

- `route4-empty.json`, `route6-empty.json` are exact, empty operational route lookups.
- `route-present.json` is the IPv4 static route installed by the live run. Where a test changes a destination, preference or next hop, FakeJunos substitutes values into that measured report.
- `irb-empty.json` is a targeted lookup for an unconfigured unit. `irb-present.json` and `vlan-present.json` are targeted reports captured after the verified IRB creation on VLAN 3920. FakeJunos substitutes configuration values into these shapes.
- `vrrp-detail-empty.json` and `vrrp-empty.txt` are the structured and text answers when there are no configured VRRP groups. `vrrp-target-error.txt` shows the rejection of the targeted detail syntax.
- `vlan-empty.json` is the report for an absent VLAN. A configured VLAN with no L3 binding is a distinct state.
- `vrrp-configured.txt` is the real `show vrrp detail` response for group 139 on the reserved IRB after commit confirmed. The interface had no active VLAN members and the VRRP state was `bringup`.
