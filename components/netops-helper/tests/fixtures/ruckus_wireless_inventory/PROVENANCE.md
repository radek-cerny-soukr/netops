# Ruckus Unleashed wireless inventory fixtures

Device: R610 on Ruckus Unleashed 200.15.6.212.27 (single master AP), read-only `show` commands only.

- `show_*.out`: captured 2026-11-17 by preflight verification (`ref/vzory/wireless inventory-preflight/`), CR removed with a
  blank line between lines (capture artefact of that run; the Helper PTY body has no blank lines), client/rogue
  MACs and host names pre-anonymised there; lines holding pass/psk/secret/key were dropped there.
- `*_absent.out`, `ap_mac_uppercase.out`, `performance_radio*_header_only.out` (an intermittent answer of the
  radio performance reads without counters, seen once during the live check; a repeat had the counters): captured 2026-11-17 by verification (same device, same account, PTY,
  `\r` removed like the Helper `_pty_body`), first line is the device echo of the command.
- All files then passed through `tests/support/anonymize_fixture.py` with one shared mapping (kept outside the
  repository): MACs -> 00:00:5e:00:53:NN, IPv4 -> RFC 5737, SSIDs/WLAN names -> ssidNN, AP device name ->
  host01, AP description -> port-desc-01, serial -> 000000000001. `--check` passes.

The event regressions derive damaged header lines and a `User:` message from `show_events.out`. The
same derived history is replayed after the client fields from `show_current_active_clients_mac_CLIENT.out`
for the client-detail path. The WLAN regressions add terminal controls and simulated values to the R610
layout in `tests/v1/fixtures/ruckus_show_wlan_all.golden.txt`.
