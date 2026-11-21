# FortiGate-60F 7.6.8 build3744: system interface and router static (1.0.12 G19, task 439)

Real output of the lab FortiGate-60F (FortiOS v7.6.8,build3744), read 2026-11-17 over SSH (account `ai-login`).

- `show-system-interface__baseline.txt`, `show-router-static__baseline.txt`: `show system interface` and
  `show router static` before the measurement, anonymised with `components/netops-helper/tests/support/anonymize_fixture.py`
  (IPv4 to RFC 5737, three site interface names to `host01..03`, three descriptions/comments to `port-desc-01..03`;
  the mapping stays outside the repository). Subnet relations between interfaces are not kept by the anonymiser.
- The other files are readbacks of the temporary test objects of the measurement (VLAN `n439-v` on `internal`,
  vlanid 3439, 198.51.100.1/29; route 439 to 203.0.113.0/24), already in documentation address space and not anonymised:
  - `show-system-interface-n439-v__created-role-undefined.txt`: created with `set role "undefined"`: FortiOS adds
    `device-identification enable` and `snmp-index`, omits the role; `diagnose sys cmdb refcnt` 0, delete succeeded.
  - `show-system-interface-n439-v__status-down-inherited-role-lan.txt`: created without a role: the VLAN inherits
    `role lan` from `internal`, and FortiOS creates `firewall address "n439-v address"`
    (`show-firewall-address-n439-v-address__auto-created-by-role-lan.txt`), which blocks the delete
    (`delete-system-interface__referenced.txt`, return code -23).
  - `show-router-static-439__created.txt`, `__disabled.txt`, `__dynamic-gateway.txt` (device wan2), `__not-found.txt`.

Every test object was removed; `show system interface` and `show router static` after the measurement equal the output before
(evidence `task-evidence/g19/60f-cli/` on the task branch).

## Task netops-20261121-749 (public source gate of 1.0.12)

The tests first used test networks outside the documentation ranges for the VLAN and route they create, because the
anonymised baseline fills 198.51.100.0/24 (dmz), 203.0.113.0/24 (the other interfaces) and 192.0.2.0/24 (route 21).
The anonymised mask of `dmz` is now 255.255.255.128 (its real subnet was not kept by the anonymiser anyway), and the
tests use the free half 198.51.100.128/25: VLAN 198.51.100.137/29 (gateway .138), route destination
198.51.100.192/26 (gateway update .194), the VLAN of `test_mcp_undo_unblock.py` 198.51.100.145/29.
