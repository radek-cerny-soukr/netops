# FortiADC adc pool members r2 captures (copied, not re-captured)

Byte-identical copies of real FortiADC-KVM 7.6.7 answers (FortiADC-KVM v7.6.7 build0676) kept with Helper. The provenance,
the anonymisation and the measurement context are documented next to the originals.

| File | Origin (components/netops-helper/tests/fixtures/real/fortiadc/) | Command |
|---|---|---|
| `vs-cr-show.out` | `fortiadc-kvm_7.6.7_adc_content_routing_20261117/` (verification) | `show load-balance virtual-server LAB_VS_HTTPS` |
| `cr1-full.out`, `cr2-full.out` | same | `show full-configuration load-balance content-routing NETOPS_TEST_CR1|2` |
| `cr-missing.out` | same | `show load-balance content-routing NETOPS_TEST_CR_MISSING` |
| `vs-stat-cr.out` | same | `diagnose server-load-balance vs_stat vdom root vs LAB_VS_HTTPS` |
| `schedule_pool_sp_a_full.txt` | `fortiadc-kvm_7.6.7_schedule_20261114/` (verification) | `show full-configuration load-balance schedule-pool netops-173-sp-a` |
| `vs_stat_schedule_exec.txt` | same | `diagnose server-load-balance vs_stat vdom root vs netops-173-vs` |

Derived in the tests (marked there): the adc pool members virtual-server listing with the `LAB_VS_HTTPS` block replaced by the
block of `vs-cr-show.out` (or by a `schedule-list enable` block naming `netops-173-sp-a`), a content-routing answer
whose pool name is replaced, and vs_stat answers whose `hc_state: UP` is replaced by `DOWN`.
