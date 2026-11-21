# Fixtures of G146 (Junos clear, J34-J37)

Real outputs: captured on d-vjunos (vJunos-switch ex9214, Junos 26.2R1.7, gns3-server 2256) on 2026-11-19 by task
netops-20261119-633 (raw captures `task-evidence/g146/znalost/`, `task-evidence/g146/raw/`), read by the control account
netops-ro and anonymised with `components/netops-helper/tests/support/anonymize_fixture.py --check`.

| File | Source |
|---|---|
| `counters-never.txt` | real `show interfaces ge-0/0/3 extensive` before the clear (`Statistics last cleared: Never`, output 1 packet / 323 bytes) |
| `counters-cleared.txt` | real, the same command about a second after `clear interfaces statistics ge-0/0/3` (time stamp, counters 0) |
| `counters-active.txt` | real `show interfaces ge-0/0/1 extensive` of a port with traffic (3383 / 54320 packets) |
| `counters-not-found.txt` | real answer for a missing port (`error: device ge-0/0/99 not found`) |
| `fdb-entry.txt` | real `show ethernet-switching table <mac> extensive` of one dynamic entry (`Time:` is the learning time) |
| `fdb-miss.txt` | real, empty answer for the same MAC after `clear ethernet-switching table <mac>` (also for an unknown MAC) |
| `fdb-table.txt` | real full table (a MAC in two VLANs shows the ambiguity) |
| `arp-hit.txt`, `arp-miss.txt`, `arp-table.txt` | real `show arp no-resolve expiration-time hostname <ip>` (TTE = seconds before expiry), empty miss, full table |
| `clear-arp-answer.txt` | real answer of `clear arp hostname <ip>` (`<ip>  deleted`) |
| `nd-empty.txt` | real empty answer of `show ipv6 neighbors host <ipv6>` (the lab switch has no IPv6 neighbor) |
| `bgp-not-running.txt` | real answer of `show bgp neighbor <ip>` on the unlicensed lab switch |

DERIVED (not measured, the lab cannot produce them):

* `nd-stale.txt`: an IPv6 neighbor row in the columns of the Juniper CLI Reference for `show ipv6 neighbors`
  (IPv6 Address, Linklayer Address, State, Exp, Rtr, Secure, Interface; states up, down, incomplete, reachable, stale,
  unreachable). https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ipv6-neighbors.html
  The row values are invented; the sample output of the page is empty.
* `bgp-established.txt`: adapted excerpt of the example of `show bgp neighbor`
  (https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-bgp-neighbor.html),
  with Number of flaps, Peer supports Refresh capability, Advertised prefixes and the Input/Output messages row
  (Total, Updates, Refreshes, Octets). The meaning of the Refreshes counter is NOT defined on the page; Admin treats a
  counter that does not rise as an unproven effect (result unknown), never as success.

Measured syntax (`?` on d-vjunos, `task-evidence/g146/znalost/help-clear-admin*.txt`): the plan notes differ from the
device for two commands: `clear ethernet-switching table <mac>` (the keyword `address` is refused) and
`clear ipv6 neighbors host <ipv6>` (a bare address is a syntax error).
