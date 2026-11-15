# ExtremeXOS port admin state and PoE outputs

Raw command outputs captured on physical hardware for the port admin state and the PoE cycle of
netops-admin: X435-8P-4S (prefix `x435__`, test port 8, port 9 without PoE) and X440-G2-12p-10G4
(prefix `x440__`, test port 10, port 13 without PoE), both ExtremeXOS 33.7.1.6-patch1-11, write account
with R/W role. The number in the file name is the step of the measurement; `pre` is before the change,
`dis` after `disable ports N` / `disable inline-power ports N`, `en` after the enable.

The files went through `components/netops-helper/tests/support/anonymize_fixture.py --check`: MAC
addresses are in the documentation range 00:00:5e:00:53:xx and LLDP system names are `hostNN`. Port
numbers, states, column layout and error texts are unchanged. The mapping file was not kept.

| File | Command |
|---|---|
| `*02-show-fdb.out` | `show fdb` |
| `*03-lldp.out` | `show lldp neighbors` |
| `*20-p-cfg-pre.out`, `x435__31-p-cfg-dis.out` | `show ports N configuration no-refresh` |
| `x435__21-p-info-pre.out`, `x435__32-p-info-dis.out` | `show ports N information detail` |
| `*23-ip-info-pre.out`, `x435__51-ip-info-dis.out` | `show inline-power info ports N` (51: about 1 s after disable, still searching) |
| `*25-ip-info-detail-pre.out`, `*52-ip-detail-dis.out` | `show inline-power info detail ports N` |
| `x435__59-ip-info-reset.out` | the same, during `reset inline-power ports N` (configured enabled, state disabled) |
| `x440__84-ip-detail-now.out` | the same, after a UPM safeguard without `configure cli mode persistent` (configured disabled, state searching) |
| `*27-ip-nopoe.out` | `show inline-power info ports N` on a port without PoE |
| `*60-ip-disable-nopoe.out` | `disable inline-power ports N` on a port without PoE |
| `x440__11c-ip-info.out` | `show inline-power info ports 1-16` (ports without PoE are left out) |
| `x435__11-ip-info-all.out` | `show inline-power info ports all` (refused) |
| `x435__47-disable-bad.out` | `disable ports 99` (refused) |
| `*36-cfgvlan-dis.out`, `x435__44-cfgvlan-en.out` | `show configuration vlan` with and without `disable port N` |
