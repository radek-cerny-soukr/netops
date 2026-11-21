# IOS G66 fixture provenance

Task netops-20261119-620, 2026-11-19. Independent pinned SSH against GNS3 IOSv
15.9(3)M12 (d-iosv, port 2251) and IOL XE 17.18.2 (d-iolxe, port 2257).

- `*-base.txt` and `d-iosv-changed.txt` reproduce the relevant lines of
  `show running-config`. The inputs were filtered in memory to the framing and
  service lines. Other configuration lines and empty `!` separators were
  removed, so the byte count still describes the original response.
- `d-iosv-startup-base.txt` is a filtered `show startup-config` with the
  original NVRAM framing. The same filtering was used for the running view.
- `d-iosv-changed-ntp.txt` and `d-iosv-changed-hosts.txt` are measured
  privilege-1 `show ntp associations` and `show hosts` after lab changes.
  `d-iosv-denied.txt` is the privilege-1 `show running-config` refusal.
- The Helper `tests/support/anonymize_fixture.py --check` anonymized the files
  together to preserve relationships between configurations and commands.
- Tests derive transport responses by combining unchanged IOS transport
  fixtures with the measured global configuration lines. Truncation, secret
  changes and stale approvals are test variations applied to those fixtures.
