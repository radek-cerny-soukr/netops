# G54 IOS lab fixtures

Pinned OpenSSH exec on 2026-11-20 in the GNS3 D-lab. Node, account
role and query are in each file name. d-iosv ran IOS 15.9(3)M12 and
d-iosvl2 ran IOS 15.2(20200924:215240). The RO reads returned empty gateway and
tracking output on d-iosv, an invalid autocommand for logging and environment,
disabled NTP, and SLA 69 with Timeout. d-iosvl2 returned a header-only SLA read.

CPU and memory retain the first ten lines, including the aggregate totals.
The privileged log retains the buffer header, timestamps and tags. Message
bodies were removed except for ordinary link state changes. A wrapped fragment
or undecodable row can remain visible only as metadata or a redaction marker.
Captures were anonymized with `tests/support/anonymize_fixture.py --check`.

Tests also use the older IOSv capture `../iosv_15.9.3M12/log_messages.admin.txt`
for interface filtering, and the existing G72 Cisco examples for shared
IOS/IOS XE gateway and NTP layouts. The canary and pager cases are derived.

`d-iosv-ro-hsrp_group_54.out` is the allowlisted operational output of
`show standby GigabitEthernet0/3.3954 54` on 2026-11-20, with the virtual address
replaced by a documentation address. The configured-priority variant is derived.
