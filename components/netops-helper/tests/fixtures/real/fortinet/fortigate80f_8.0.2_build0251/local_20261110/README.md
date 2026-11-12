# FortiGate-local RO captures, 2026-11-10

FortiGate 80F, FortiOS 8.0.2 build0251, HA primary; SSH account `netops-test-ro`.
One exec read per command, strict existing ED25519 pin. No configuration or console changes.

- `physical.txt`: `get system interface physical`, eleven physical ports; link and negotiated speed/duplex.
- `lldp.txt`: `diagnose lldp rx neighbor summary`, two FortiSwitch neighbors on local a/b.
- `vlans.txt`: VLAN-only projection of `show system interface`, eight entries; name, VLAN ID, parent, configured IPv4.
- `bridge_empty.txt`: `diagnose netlink brctl name host internal`, accepted, empty hard-switch FDB.

SSH framing removed; serials, MACs and IPv4 addresses anonymized. Configuration
projection deliberately excludes every other setting. Physical layout also matches
the supplied 2026-11-09 capture. Alternative `diagnose lldprx neighbor summary` and
`get system lldp neighbors` were refused (parse error, device code -61).
Only the empty local bridge layout is qualified; populated FDB rows remain unparsed.
