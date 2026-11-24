# IOS configuration captures for router config

2026-11-19, read-only SSH exec on the GNS3 emulated environment. Both host keys
were checked against the enrolled RSA SHA-256 fingerprints.

| Prefix | Device | Release | Account |
|---|---|---|---|
| iosv | Cisco IOSv 15.9(3)M12 | Cisco IOS 15.9(3)M12 fc1 (VIOS-ADVENTERPRISEK9-M) | netops-admin |
| iosvl2 | Cisco IOSvL2 15.2 | Cisco IOS 15.2(20200924:215240) (vios_l2-ADVENTERPRISEK9-M) | netops-admin |

- `*-running.out` and `*-startup.out` replay `show running-config` and
  `show startup-config`. The Helper IOS stream redactor replaced opaque
  configuration lines before export. The existing `support/anonymize_fixture.py`
  anonymized hostnames and addresses and checked for residual identifiers.
  Line endings and trailing space were normalized. Size frames retain the
  device-reported original values.
- `*-version.out` preserves the IOS software and hardware identity lines from
  `show version`. Other lines were omitted.
- `*-native.out` is the no-change response to
  `show archive config differences nvram:startup-config system:running-config`.
- `*-refused.out` is the IOS autocommand refusal from `show running-config`
  as `netops-ro`. Its use for startup refusal is a derived case.
- Tests derive changed, truncated and redacted-size-adjusted captures from
  these files. The signed-line shape used in the changed case comes from the
  [Cisco IOS archive diff command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_through_show_fm_summary.html).
- The separate Catalyst identity replay uses the repository's
  `fixtures/identity/cisco_ios.txt`. The software header and hardware line
  without a revision field are documented in the
  [Catalyst 2960 show version example](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960/software/release/15-0_2_se/command/reference/cr2960/cli2.html).
