# Ruckus Unleashed G110 fixtures

Device: R610 on Ruckus Unleashed 200.15.6.212.27 (single master AP), read-only `show` commands only,
captured 2026-11-19 by task netops-20261119-548 over the PTY (`ssh -tt`, `enable`), CR removed, trailing prompt
removed, first line is the device echo of the command (as the Helper `_pty_body` keeps it).

- `show_l2acl_all.out`, `show_aaa_all.out`: real output (ACL with stations, AAA Local + Guest).
- `show_mgmt_acl_all.out`, `show_dhcp_all.out`, `show_static_route_all.out`, `show_l3acl_all.out`: real output of an
  unconfigured object type (heading only; `show l3acl all` prints nothing).
- `show_l3acl_bare_unrecognized.out`: real answer of the bare `show l3acl` (not a command; `show l3acl all` is).
- `show_config.out`: real `show config` (full tree). DERIVED: every value of a label naming a pass/secret/psk/key/
  community/token/phrase was replaced by `FAKE-SECRET-NN` before anything was stored (the real values never left
  the device session); `Dynamic PSK`/`Bypass Apple CNA Feature` states kept or set to `Disabled`.
- All files passed through `tests/support/anonymize_fixture.py` (`--check` clean): MACs -> 00:00:5e:00:53:NN, IPv4 ->
  RFC 5737, serial/SSID/names replaced; system name and WLAN names replaced by `site01`/`host01`/`ssidNN`.

- G110 r2 further anonymized AP `Device Name`, `Description`, `Location` and WLAN names/descriptions/group member
  references with `ap01`, `ap-description01`, `site-location01` and the existing `ssidNN` placeholders. The regression
  scans these labels, the AP block and WLAN group references. Empty optional geographic fields remain empty.
- `vendor_aaa.out`, `vendor_dhcp.out`, `vendor_wlan.out`: derived from the
  [RUCKUS Unleashed 200.15 CLI Reference Guide](https://support.alcadis.nl/Support_files/Ruckus/Unleashed/Manuals/Ruckus%20Unleashed%20200.15/Unleashed-200.15-Command-Line-Interface-Reference-Guide-RevA-20240115.pdf),
  pp. 49–51, 73–75. Example names and addresses are placeholders and secret values are synthetic. The WLAN fixture
  keeps only the fields needed for the regression. Tests derive enabled relay, assigned ACL and a second DHCP address
  by editing the applicable field.
- `vendor_l3_acl.out`: derived from the [RUCKUS Unleashed 200.15 CLI Reference Guide, p. 226](https://manuals.plus/m/828b9c31161b5ebb4c6f8e8274b818ad40c3290e2861c5ae1def74e19f54f3f3),
  using the same tree and ordered rule fields, with placeholder names and the privileged `show l3acl all` echo.
  The guide illustrates the tree with `show` from an L3 ACL context.
- `vendor_mgmt_acl.out`, `vendor_static_route.out`: derived from the
  RUCKUS Unleashed 200.6 CLI Reference Guide, pp. 44–45 (RUCKUS documentation PDF
  `unleashed-200.6-cli-guide-rev-a_20180607-1`).
  Names and addresses are placeholders. The management ACL fixture preserves one range and one single-address record.
