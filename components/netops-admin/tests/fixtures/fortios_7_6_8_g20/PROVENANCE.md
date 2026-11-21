# FortiOS 7.6.8 build3744 G20 captures (lab FortiGate-60F), 2026-11-20

Real CLI output of the lab FG-60F read and written with the account `netops-test-rw` in one held SSH session, answers
framed the way `netops_core.prompt.cleaned` leaves them (echo and prompt removed). Written objects: the DNS zone
`netops-g20.test` with two entries (type A and type PTR), and one DHCP reservation on the server of the interface
`quarantine`. Everything was deleted afterwards (see the task evidence). Anonymized with
`components/netops-helper/tests/support/anonymize_fixture.py --check` (IPv4 into documentation space, MAC into
`00:00:5e:00:53:NN`).

- `dns-zone-empty.txt`, `dns-zone-empty-full.txt`: `show system dns-database netops-g20.test` and the
  `show full-configuration` form of the zone without entry (the show omits type A, ttl 0 and status enable).
- `dns-zone-two-entries.txt`, `dns-zone-two-entries-full.txt`: the same after an A entry (id 1) and a PTR entry with
  ttl 300 (id 2).
- `dns-zone-missing.txt`: `show system dns-database nonexistent-zone` (`entry is not found in table`).
- `dns-entry-without-hostname-error.txt`: the device refusal when `next` ends an entry without hostname (-56).
- `dns-delete-missing-error.txt`: `delete 9` of an entry that does not exist (-3).
- `dhcp-server-empty.txt`: `show system dhcp server 3` (interface quarantine) without reservation.
- `dhcp-server-one-reservation.txt`, `dhcp-server-one-reservation-full.txt`: after one reservation with description.
- `dhcp-duplicate-error.txt`: the device refusal of a second reservation of the same address (-15).

The error files are the lines the device printed after `next`, cut from the session transcript.

## FG-37 lease captures (task 655, 2026-11-20)

Real output of the lab FG-60F (FortiOS 7.6.8 build3744), accounts `netops-test-ro` (reads) and `netops-test-rw`
(`execute dhcp lease-clear`), answers framed like `netops_core.prompt.cleaned` (echo and prompt removed). Anonymised by
hand with a fixed mapping (IPv4 into `192.0.2.x`, MAC into `00:00:5e:00:53:NN`, the serial number of the switch into
`SERIAL0000000001`, the host name of the lab client into `host-a`; column widths and tabs unchanged); the test client
`netops-g37-test` (a test client of the lab) keeps its host name.

- `lease-list-three-interfaces.txt`: `execute dhcp lease-list` with leases on `_default`, `fortilink` and `quarantine`.
- `lease-list-quarantine-only.txt`: `execute dhcp lease-list quarantine` (one section).
- `lease-list-after-clear.txt`: the full list after `execute dhcp lease-clear <ip>` of the `quarantine` lease.
- `lease-clear-success.txt`: the answer of a successful `execute dhcp lease-clear <ip>` is empty (prompt only).
- `lease-clear-no-lease.txt`: the answer for an address that holds no lease is empty as well.
