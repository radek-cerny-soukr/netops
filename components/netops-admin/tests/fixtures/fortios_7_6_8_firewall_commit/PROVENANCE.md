# FortiGate-60F, FortiOS 7.6.8 build3744 (lab)

2026-11-20, verification (firewall commit). The objects `NETOPS-firewall commit-HOST`, `NETOPS-firewall commit-GROUP` and policy
`240024 / NETOPS-firewall commit-POLICY` were created by hand through one held SSH session of `fixture-operator` (pinned host key),
read back with `show firewall address|addrgrp|policy`, and deleted again in reverse order in the same lab session
(`show` of all four afterwards: `entry is not found in table`, the file `absent.txt`).
The files are those replies without the prompt echo. Only the three generated UUIDs are replaced by fixture values;
the object names, the documentation address `192.0.2.124` and the lab interfaces `netops-ipsec status` and `ipsec status-lo` are part of the test.
`policy-duplicate-name-refused.txt` is the device answer to `set name "netops-ipsec status-ping"` on a new policy whose name an
existing policy already uses (`Command fail. Return code -651`); the interactive harness went on with the next lines,
Admin stops at the refused line.
The behavioural fake in `test_fortios_firewall_commit.py` replays these replies when its simulated state equals the captured state.
