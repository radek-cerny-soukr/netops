The JSON and set-format files in this directory were captured on vJunos-switch
(vJunos-switch ex9214, Junos 26.2R1.7) on 2026-11-19 over pinned SSH. See
the fixture capture commands and restoration hash (private measurement record, not published).
The control account ran the operational commands. The administrator account ran
only scoped configuration reads for the saved fixtures. The lab probe used
irb.3920, which had no Layer 2 link. The OSPFv2 response was empty even with the
interface configured. The OSPFv3 response displayed the configured passive
interface, area and metric. Captures were anonymized with
`components/netops-helper/tests/support/anonymize_fixture.py --check`.

`bgp-neighbor-vendor.txt` is an adapted excerpt of the Juniper CLI Reference
example for an established neighbor with import policy. Addresses, ASNs, type
and names are replaced and irrelevant fields are omitted.
[show bgp neighbor](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-bgp-neighbor.html)

`management-route.json` came from the administrator's targeted
`show route <management peer> active-path | display json` on the same device,
with the management subnet redacted by the same anonymizer.

`bgp-group-vendor.txt` is an adapted excerpt of the documented group display,
with the name, type, counts and ASNs substituted. Unit replay of the neighbor
for the group import and neighbor override tests varies the configured policies
and uses Active state. [show bgp group](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-bgp-group.html)

## verification (public source gate of 1.0.12)

The dotted test area is written as `0.0.0.7` and the test /32 prefixes as 203.0.113.x/32 (same host numbers)
in these captures and in `test_junos_junos_system_services.py`; the earlier values were refused by the public source gate.

## 1.0.13: BGP without a license (measured 2026-11-22)

Captured on the same vJunos-switch 26.2R1.7 (no BGP license, no `routing-options autonomous-system`) by a live
measurement through Admin; the device answers were logged verbatim, the echo, the `[edit]` context line and the
prompt are removed as in `../README.md`.

- `commit-confirmed-10__bgp-license-warning.txt`: the write account's answer to the change commit
  `commit confirmed 10 comment "..."` that created an external group with a peer AS.
- `show-bgp-group-summary__license-not-running.txt`: the check account's `show bgp group summary | no-more` before the
  group existed.
- `show-bgp-group__license-empty.txt`: the check account's `show bgp group <new group> | no-more` right after that
  commit (the group had no neighbour): only the license warning.

Derived in `test_junos_junos_system_services.py`: the simulation puts the measured warning block in front of the
answer of every commit that changes BGP and leaves it configured (measured: the change commit had it, the empty
safeguard commit and the inverse commit that removed the group had none), replays
`bgp-group-vendor.txt` after the measured warning row, and replaces the warning by `warning: statement has no contents;
ignored` for the negative test. Juniper's vJunos-switch deployment guide (Limitations) says the BGP license warning
can be ignored.

## 1.0.13: BGP with a local AS (measured 2026-11-23)

Captured on the same vJunos-switch 26.2R1.7, still without a BGP license, after the lab administrator configured a
local AS (`routing-options autonomous-system`); the check account's answers during live Admin runs were logged verbatim
(row by row) and the echo and prompt are removed as above. The lab's local AS is replaced by the documentation AS
64500 (RFC 5398) in every file below (`Local AS: 64500`, `Local: unspecified AS 64500`); both numbers have five digits,
so the columns stay aligned. The peer AS numbers 64512 and 64513 are the values of the test requests.

- `show-bgp-group__as-one-peer.txt`: `show bgp group <group> | no-more` after the batch that created the external group
  (peer AS 64512) together with its first neighbour `192.0.2.57` (peer AS 64512).
- `show-bgp-group-summary__as-one-group.txt`, `show-bgp-summary__as-one-peer.txt`: the summaries in that state.
- `show-bgp-neighbor__as-first-peer.txt`: `show bgp neighbor 192.0.2.57 | no-more` in that state.
- `show-bgp-neighbor__as-second-peer.txt`: `show bgp neighbor 192.0.2.58 | no-more` after a second neighbour with peer
  AS 64513 was added to the group.
- `show-bgp-group__as-peer-as-override.txt`: `show bgp group <group> | no-more` after a batch whose only neighbour had
  peer AS 64513 while the group had 64512: the group line shows the neighbour's AS.

With the local AS the answers for a new group without neighbours and for every BGP read after the undo were
byte-identical to `show-bgp-group__license-empty.txt` and `show-bgp-group-summary__license-not-running.txt`, so the
simulation reuses those two files. Derived in `test_junos_junos_system_services.py`: the simulation chooses one of these
answers by the simulated configuration and refuses states that were not measured (for example a summary with two
neighbours).
