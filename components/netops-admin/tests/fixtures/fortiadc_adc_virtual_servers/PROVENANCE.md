# adc virtual servers FortiADC-KVM 7.6.7 CLI captures

FortiADC-KVM v7.6.7 build0676, FortiADC-KVM 7.6.7, 2026-11-19, verification.
These are interactive SSH command responses. The prompt at the end of
each response was removed in the files. The fake transport reinstates
the hostname anchor consumed by DeviceAccess before its final prompt suffix.
IPv4 addresses were replaced together with
`components/netops-helper/tests/support/anonymize_fixture.py --check`.

- `session-*.out` and `persistence-*.out` record the neutral filter,
  unfiltered list, verified VS/source selection, selected list, L4 clear,
  empty selected list, filter reset, and unfiltered readback. The SMTP entry
  was the target and the DNS entry remained. Both were seeded by test jump host.
- `waf-filter-default.out` and `waf-list-empty.out` record the idle filter
  and the empty table before the WAF test request. `waf-list-blocked.out`
  records a present block for the secondary test jump host address on LAB_VS_HTTPS.
  `waf-release.out` is the command response from a separate CLI measurement
  for that address. The confirmed unit case combines those measured frames
  with the empty table. The remaining-row case matches the live Admin
  readback, where an active-looking row was visible after release.
- The unit test derives the truncated frame from the measured listing by
  dropping the end of its final row.
- `waf-list-release-pending.out` preserves the interactive FortiADC-KVM 7.6.7 listing observed after the targeted
  release recorded in a private measurement record (FortiADC 7.6.7 build0676, 2026-11-19).
  The test source is anonymized to the same address as `waf-list-blocked.out`. The fresh listing
  at 38 seconds had only the header, as in `waf-list-empty.out`.
