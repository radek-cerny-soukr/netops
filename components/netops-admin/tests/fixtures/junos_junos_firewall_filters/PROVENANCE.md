# junos firewall filters Junos firewall filter fixtures

Real output of vJunos-switch (vJunos-switch ex9214, Junos 26.2R1.7), captured on 2026-11-19 UTC by verification
(the live run and its tool are in a private measurement record). The run went through the
public Admin path (preview, confirmed apply, readback, undo) on the reserved objects `NETOPS-junos firewall filters-*`, VLAN 3921 and
`irb.3921`. Raw outputs were passed through `components/netops-helper/tests/support/anonymize_fixture.py --check`
(addresses became documentation addresses, e.g. 192.0.2.0/24, 198.51.100.0/24, 2001:db8:2::/48).

- `ro-filters-*.json`: `show interfaces filters irb.3921 | display json | no-more` of `netops-ro` with no filter,
  an inet input filter, an inet input and output filter, and an inet plus inet6 input filter.
- `ro-show-firewall-denied.txt`: the answer of `netops-ro` to `show firewall filter...` (the read-only class has no
  `firewall` permission).
- `cfg-filter-*.txt`, `cfg-binding-*.txt`, `cfg-irb.txt`: `show configuration <path> | display set | no-more` of
  `netops-admin` after the verified commits (`cfg-filter-inet-reordered.txt` after the term order change that used
  `insert... term t-deny before term t-src`).
- `cfg-firewall-existing.txt`: the permanent junos security filter with a policer (a filter outside the profile).
- The FakeJunos in `test_junos_junos_firewall_filters.py` builds the binding report from `ro-filters-nofilter.json` and the tests assert
  that it equals the measured reports above.
