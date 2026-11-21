# Real FortiADC output: content routing, session/persistence filters, read profile (2026-11-17)

FortiADC-KVM v7.6.7 build0676 (GA.M), standalone, root VDOM, lab device VM220, 2026-11-17 14:09–14:16 UTC (device
clock PST). Task netops-20261117-445-r2 (G28 ADC-C04/C08/C13). Backends VM221/222 up, all use-case virtual servers
HEALTHY; client VM201 sent an HTTP loop (4 keep-alive connections) to VS_APP_HTTP and HTTPS to LAB_VS_HTTPS.

Temporary lab objects (removed after the task): content-routing `NETOPS_TEST_CR1` (l7, http-host-header
`app.lab.test` -> POOL_APP) and `NETOPS_TEST_CR2` (l7, http-request-url `/` -> POOL_APP), bound to `LAB_VS_HTTPS`
with `content-routing-list NETOPS_TEST_CR1 NETOPS_TEST_CR2` and `load-balance-persistence LB_PERSIS_SRC_ADDR`.
Session/persistence filters were set only for the measurement and cleared (`filter show` flag 0) after each read.

Transport: one interactive SSH terminal per batch (paramiko PTY, host key pinned), admin = built-in system
administrator; `ro-*` files = account `netops-read` (access profile netops-read, six areas `read`) logged in
through VM201 after its trusted hosts were extended. Each file holds the echoed command, the answer and the next
prompt. `\r` removed by the capture tool. `*-help.out`: answer of `<command> ?`; the redisplayed command line and
its terminal control bytes (ESC[K, NUL) were removed.

Anonymised on PC-Radek: `tests/support/anonymize_fixture.py fixraw/*.txt --out fixanon --keep FortiADC-KVM --map
<outside repo> --check` (rc 0, one mapping for all files). The invalid literal `10.76.1.300` of
`session-filter-invalid-ip.out` (not an address, so the anonymiser keeps it) was replaced by `203.0.113.300` by hand.

| File | Command | Note |
|---|---|---|
| `vs-cr-full.out` / `vs-cr-show.out` | `show full-configuration` / `show load-balance virtual-server LAB_VS_HTTPS` | no `load-balance-pool` line |
| `cr1-full.out`, `cr2-full.out` | `show full-configuration load-balance content-routing NETOPS_TEST_CR1|2` | `config  match-condition` |
| `cr-missing.out` | `show load-balance content-routing NETOPS_TEST_CR_MISSING` | `Entry '…' is not found!` |
| `vs-stat-cr.out`, `slb-load-cr.out` | `diagnose server-load-balance vs_stat vdom root vs LAB_VS_HTTPS`, `slb_load` | still print POOL_APP |
| `session-list-http.out`, `session-list-udp.out` | `diagnose server-load-balance session list` | 16 words per row |
| `persistence-list.out` | `diagnose server-load-balance persistence list` | 13 words per row |
| `session-filter-vs-source.out` | `… session filter show` after `filter 'vs-name VS_APP_HTTP source-ip <client>'` | flag 1010 |
| `session-list-vs-source.out` | `… session list` under that filter | |
| `session-filter-two-args.out` | `filter show` after `filter 'vs-name VS_APP_HTTP' 'rs-name RS_B'` | only the first argument applied (1000) |
| `session-filter-range.out` | `filter show` after `filter 'source-ip <a> <b>'` | flag 10, range |
| `session-filter-vs-rs.out` | `filter show` after `filter 'vs-name LAB_VS_HTTPS rs-name RS_A'` | flag 3000 |
| `session-filter-vs-source-rs.out` / `session-list-vs-source-rs.out` | vs + source + rs | flag 3010 |
| `session-list-other-client.out` / `persistence-list-other-client.out` | list under `source-ip` of an unused client | header only |
| `session-filter-invalid-ip.out` | `filter 'source-ip 10.76.1.300'` | `… is invalid filter option …` |
| `persistence-filter-rs-refused.out` | `persistence filter 'rs-name RS_A'` | persistence has no rs-name |
| `persistence-filter-source.out`, `persistence-filter-vs-source.out`, `persistence-filter-vs.out` | `persistence filter show` | `filter flag:` without space; 10 / 1010 / 1000 |
| `persistence-list-vs-source.out` | `persistence list` under vs + source | |
| `*-filter-cleared.out` | `filter show` after `filter clear` | flag 0, all `any` |
| `session-filter-help.out`, `persistence-filter-help.out` | `… filter ?` | |
| `ro-*-refused.out` | the catalogue diagnose reads as netops-read | `Parsing error at 'server-load-balance'`, -284 |
| `ro-diagnose-help.out` | `diagnose ?` as netops-read | only `<Enter>` |
| `ro-performance.out`, `ro-show-content-routing.out` | `get system performance`, `show load-balance content-routing NETOPS_TEST_CR1` as netops-read | allowed |

Integration 461 (2026-11-17): the fixture files were renamed from `*.txt` to `*.out` (repository convention); contents unchanged.
