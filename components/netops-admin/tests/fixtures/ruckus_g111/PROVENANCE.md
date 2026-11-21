# Ruckus Unleashed G111 fixtures (Admin)

Device: lab R610 on Ruckus Unleashed 200.15.6.212.27 (single master AP).

- `show_sysinfo.out`, `show_wlan_all.out`: read-only captures of 2026-11-19 (task netops-20261119-561), system ssh in a
  PTY with `enable`, CR removed. Secret values (lines naming passphrase, key, PSK, secret) replaced by `<redacted>`.
- `show_wlan_all_with_test.out`: the same listing while the lab test WLAN `netops-g111-test` existed (created
  disabled, open, VLAN 3999 by the capture session; a plain read of `show wlan all`).
- `cli_create_context.out`: transcript of the answers of the CLI while the test WLAN was created in `config` /
  `wlan netops-g111-test` (`type standard-usage`, `ssid`, `no service`, `vlan 3999`, `end`). The `open wpa2
  passphrase ...` line was refused in that capture (the `algorithm aes` part was missing, see `cli_errors.out`
  and the unit tests); the passphrase is shown as `<GENERATED>` by the capture tool, the real one never left memory.
- `cli_errors.out`: refusals of the CLI for `vlan 5000`, `vlan abc`, a 47 character SSID, a passphrase shorter
  than 8 characters, an empty `description`, an unknown command, `wlan` without a name, `abort`.
- `cli_delete.out`: `config`, `no wlan netops-g111-test`, `exit`.
- `cli_wpa2.out`: `open wpa2 passphrase <generated> algorithm aes` accepted in the context of the test WLAN, then `abort`.
- All files then passed through `components/netops-helper/tests/support/anonymize_fixture.py` (MAC, IPv4,
  serial, host name, SSIDs and WLAN names of the home WLANs -> `host0N`, `ssid0N`); `--check` passes. The name
  `netops-g111-test` belongs to the test WLAN and is kept.

## Task netops-20261121-749 (public source gate of 1.0.12)

The management address of the lab AP was removed from this note. `show sysinfo` prints Ruckus Unleashed 200.15.6.212.27 as
`200.15.6.212 build 27`; that string is the vendor version of the measured profiles, not an address (the source gate allows it like the EXOS versions).
