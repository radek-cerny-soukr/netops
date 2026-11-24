# FortiOS 7.6.8 build3744 service tables (lab FortiGate-60F), 2026-11-23

Real CLI output of the lab FG-60F read by the check account of the Admin live run (read-only account, one held SSH
session, answers as `access.DeviceAccess.check_query` returns them: echo and prompt removed). The objects were written
and returned by Admin itself (preview, apply with the approved plan hash, readback, undo): the temporary VLAN
`netops-a1s` (status down), the DHCP server 7 on it, its address range 1, a secondary DNS server and a syslog facility.
Everything was returned afterwards (see the task evidence). Anonymized in one mapping with
`components/netops-helper/tests/support/anonymize_fixture.py --check` (IPv4 into documentation space; the host octets
of the test subnet are kept: interface and gateway `.1`, range `.100`-`.150`).

- `dhcp-server-created.txt`: `show system dhcp server 7` after the create with `status disable`; a server without a
  range prints no `config ip-range` (design A 1.5c).
- `dhcp-server-one-range.txt`: the same after the range `7:1` was created.
- `dhcp-server-enabled.txt`: after `status enable` (the default: show omits it).
- `dhcp-server-range-removed.txt`: after the undo of `status enable` and of the range (the shape of the create again).
- `dns-cleartext.txt`: `show system dns` in cleartext (the lab was prepared outside Admin: `protocol cleartext`; FortiOS
  then hides `server-hostname`). `dns-secondary.txt`: after the Admin update of `secondary`.
- `syslogd-initial.txt`, `syslogd-initial-full.txt`: `show` / `show full-configuration log syslogd setting` while syslog
  is disabled; the whole `show` (the snapshot of Admin) omits this section altogether.
- `syslogd-enabled.txt`: after the lab preparation outside Admin (`status enable`, one server);
  `syslogd-facility.txt`: after the Admin update of `facility`.
- `syslogd-enabled-full.txt`: `show full-configuration log syslogd setting` with `status enable`, read by the write
  account in the session of the lab preparation (the measured defaults: `mode udp`, `port 514`, `facility local7`,
  `format default`, `source-ip ''`); the server address anonymized by hand with the mapping of the files above.

Not stored (the output holds an excluded attribute of design A section 2, even at its default): `show
full-configuration system dhcp server 7` (`ddns-update`, `vci-match`, `filename`) and `show full-configuration system
dns` (`ssl-certificate`, `source-ip`, `fqdn-*`). The defaults the profiles use from them: DHCP `status enable`,
`lease-time 604800`, `dns-service specify` and `ntp-service specify` (not shown by `show` on the lab servers),
`timezone-option disable`, `server-type regular`; DNS `ip6-primary ::`, `ip6-secondary ::`, `protocol cleartext`
(`show` prints `protocol dot` on the lab before the preparation).
