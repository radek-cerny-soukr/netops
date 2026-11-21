# IOS XE G84 fixture provenance

Task netops-20261120-669. Pinned SSH to GNS3 d-iolxe (2257) and d-iolxe-l2
(2258), Cisco IOS XE 17.18.2, on 2026-11-20.

- `*-services-base.txt`: `netops-admin`, `show running-config | include`
  with the hostname, time zone, NTP, syslog, DNS and end markers selected.
- `*-services-denied.txt`: `netops-ro`, `show running-config | include ^hostname |^end$`.
  The SSH exit status was 0 for the refusal on both nodes.
- `*-running-base.txt` and `*-startup-base.txt`: measured configuration framing,
  `version`, `hostname`, `clock timezone` and `end` only. Byte counts describe
  the original responses. The omitted lines were discarded in memory.

The fixtures were anonymized together with the Helper
`tests/support/anonymize_fixture.py --check`.

`*-services-changed.txt` record scoped administrator CLI output on both nodes
while the G84 service settings, NTP server, syslog destination and static host
were configured. Device identity and addresses were anonymized with the same
command as the baselines. The fake transport uses each device’s measured rows
and baseline response. Truncation and
protection checks are derived variations. See `task-evidence/g84` for live evidence.
