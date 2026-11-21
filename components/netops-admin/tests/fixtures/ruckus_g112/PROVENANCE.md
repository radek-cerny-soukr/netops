# Ruckus Unleashed G112 fixtures (Admin)

Device: lab R610 on Ruckus Unleashed 200.15.6.212.27 (single master AP).
Captured 2026-11-20 by task netops-20261120-660 with `task-evidence/g112/r610.py` (system ssh in a PTY with `enable`, CR removed,
`HostKeyAlgorithms=+ssh-rsa`, RSA pin SHA256:l4DQiCPD+95rkSotj3hWJqYeNuMFwx7yyZ2oLrQiw9E). Real output, not derived.

- `cli_wlan.out`: transcript in an UNSAVED `config-wlan` context of the lab test WLAN `netops-g112-test` (ended with `abort`): the
  accepted answers of `acl l2acl`, `acl l3acl`, `client-isolation isolation-on-ap`, `max-clients`, `rate-limit perssid_*`,
  `rate-limit uplink .. downlink ..`, their `no` forms, `dot1x wpa2|wpa3 algorithm AES auth-server name <aaa>`, `open wpa2|wpa3
  passphrase <random> algorithm aes`, and the `show` listing after each group. The passphrase was generated in the capture
  process and printed as `[redacted]`; lines naming passphrase/key/secret carry `<redacted>`. Used objects: test AAA
  `netops-g112-aaa`, test ACLs `netops-g112-acl` / `netops-g112-l3` (created for the run, removed at its end).
- `cli_wlan_errors.out`: refusals of the CLI (unknown RADIUS server, wrong rate/client values, wrong isolation word, short
  passphrase, DHCP relay address lines).
- `cli_dhcp_update.out`: the saving of a change to an EXISTING DHCP relay entry is refused by the firmware (`'is-partial' API body invalid`, nothing saved); an entry is changed by `no dhcp` and a new `dhcp` in the same context.
- `cli_dhcp.out`: DHCP relay server entry commands (`dhcp`, `first`, `second`, `no second`, `description`, `no dhcp`) and `show dhcp all`.
- All files passed through `components/netops-helper/tests/support/anonymize_fixture.py` (`--check` clean, names `netops-g112-*`
  kept; the SSID line of the test WLAN is shown as `ssid01`). Addresses are RFC 5737 documentation addresses chosen for the test.
- The empty `show dhcp all` of the unconfigured R610 is the G110 fixture `components/netops-helper/tests/fixtures/ruckus_g110/show_dhcp_all.out`.

## Task netops-20261121-749 (public source gate of 1.0.12)

The management address of the lab AP was removed from this note. `show sysinfo` prints Ruckus Unleashed 200.15.6.212.27 as
`200.15.6.212 build 27`; that string is the vendor version of the measured profiles, not an address (the source gate allows it like the EXOS versions).
