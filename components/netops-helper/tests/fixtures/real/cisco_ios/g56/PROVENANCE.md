# IOS and IOS XE management reads for G56

Pinned OpenSSH exec from PC-Radek, 2026-11-20. GNS3 d-iosv (2251,
15.9(3)M12), d-iosvl2 (2252, 15.2(20200924:215240)) and d-iolxe (2257,
17.18.2). Both netops-ro and netops-admin ran `show version` and the nine
catalogue commands. No CLI settings were changed. The captures keep the
software identification line from `show version` and the operational
command output, with device identifiers processed by
`tests/support/anonymize_fixture.py` after credential redaction.

The three devices had no visible AAA servers, zero RADIUS responses, and
disabled SNMP agents. The RO account received a CLI refusal for the SNMP
engine identifier. Documented populated AAA, TACACS and SNMP examples are
reused from [G74](../../cisco_xe/g74/PROVENANCE.md). The DNS cache excerpt
uses documentation addresses and anonymized hostnames, and is derived
from the [Cisco IOS show hosts command reference](https://www.cisco.com/c/en/us/td/docs/ios/fundamentals/command/reference/cf_book/cf_s2.html).
The pager and credential canaries added in tests are derived cases.
