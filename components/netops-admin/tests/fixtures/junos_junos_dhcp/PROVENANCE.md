# junos dhcp fixtures (Junos DHCP pools, reservations, relay)

Measured on vJunos-switch running Junos 26.2R1.7. The raw logs are private. The captures use test objects and were collected without running the anonymizer. A separate cleanup pass
later remapped their values (see the last section); the public fixtures show the pool 198.51.100.0/24 and the MAC
reservation 00:00:5e:00:53:44.

- `pool-present.txt`, `relay-present.txt`: `show configuration access... | display set` and
  `show configuration forwarding-options dhcp-relay | display set` with the objects configured.
- `absent.txt`: the same read of a pool or relay group that does not exist (a blank answer, no error).
- `server-group-sorted.txt`: addresses entered as.200 then.100 are shown in ascending order (derived from the
  `show | compare` of p6; the `set` rendering follows the Junos set-format of `pool-present.txt`).
- `commit-check-*.txt`: the device refusals measured with `commit check` (nothing committed, `rollback 0`).

## verification (public source gate of 1.0.12)

The test objects were first written with two networks outside the documentation ranges and a
non-documentation MAC; they now use documentation values with the same host numbers. The fixtures contain the pool
198.51.100.0/24 and the MAC reservation 00:00:5e:00:53:44. The second documentation network 203.0.113.0/24 appears
only in `test_junos_junos_dhcp.py`: in refusal cases and as the preconfigured IRB address 203.0.113.1/24 in the test that
applies and undoes a relay-group interface change. The MAC variants 00:00:5e:00:53:45 and 00:00:5e:00:53:46 appear only there, in refusal cases.
