# IOS XE 17.18.2 · xe health lab captures

Pinned OpenSSH exec, 2026-11-19, GNS3 emulated environment Cisco IOL XE 17.18.2 (IOL L3) and Cisco IOL-L2 XE 17.18.2
(IOL L2). The file names record the node, role and corresponding catalogue query.
Both accounts were independently read with `show privilege` (1 and 15).
The clock file is `show clock`, the gateway and tracking files are the full
`show standby`, `show vrrp`, `show track` responses, including blank and rejected captures.

CPU and memory files retain the first ten lines of each full capture, including
the printed totals. The log files from the privileged account retain the
`Log Buffer (... bytes):` header and all subsequent lines. Anonymized with
`tests/support/anonymize_fixture.py --check`. The source buffer can start in
the middle of a line because IOS XE wraps it by bytes.

`iol-xe-router-ro-standby_client_close.out` is the OpenSSH client stderr for the
successful empty `show standby` exec on the router (exit 0, blank stdout).
