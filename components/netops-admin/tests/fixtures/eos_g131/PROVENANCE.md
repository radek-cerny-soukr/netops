# Arista cEOS 4.36.1F outputs for G131 (1.0.12, EP14)

Read on 2026-11-20 from `d-ceos` (lab GNS3 server, DNAT 2253, port Ethernet12) and `b04-eos-a`/`b04-eos-b`
(PC-Radek GNS3, :2263/:2264, port Ethernet5) with the check account `netops-ro` (privilege 1), cEOSLab
4.36.1F-48405728.4361F. Source: `task-evidence/g131/raw/` (task netops-20261120-662). Files hold the answer of the
command without the echo: `*-status.txt` = `show interfaces X status`, `*-switchport.txt` = `show interfaces X switchport`,
`*-description.txt` = `show interfaces X description`, `*-vlan-missing.txt` = stdout of the ssh exec answer of
`show vlan id 3931` (exit status 1, VLAN absent). They went through
`components/netops-helper/tests/support/anonymize_fixture.py --check` (no change). The state "connected" is the real
state of the cEOSLab test ports (they carry no traffic, no MAC address and no LLDP neighbour).

`d-ceos-running-config-excerpt.txt`: the first 52 lines of `show running-config` of `d-ceos` (write account, 2026-11-20;
header, services, VLAN blocks 10/20/304, `aaa authorization` lines, the first interfaces) with a closing `end`. The three
`username` lines were deleted (they hold hashed secrets); no other account, secret or key line is present. The same session measured that `vlan 3931` / `name NETOPS-G131` is printed directly after
the block of VLAN 304 and before the `aaa authorization` lines (`task-evidence/g131/live-try3.jsonl`, diagnostics
`task-evidence/g131/live-diag2.jsonl`).
