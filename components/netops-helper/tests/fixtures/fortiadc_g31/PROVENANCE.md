# FortiADC G31 captures

The source is ProxmoxLAB VM220 running FortiADC-KVM 7.6.7 build0676, read on 2026-11-18 over pinned SSH through VM201. The original output was handled in memory. The projections preserve command framing and the relevant configuration records. The pager erasure sequence was removed and site identifiers were anonymized with `tests/support/anonymize_fixture.py`. The certificate's ENC payload and key filename were replaced with fixture-only strings.

| Fixture | CLI source and projection |
| --- | --- |
| `status.out` | `get system status`, Version records only |
| `certificate.out` | `show full-configuration system certificate local <object>`, selected fields |
| `persistence.out` | `show full-configuration load-balance persistence LB_PERSIS_SRC_ADDR` |
| `profile.out` | `show full-configuration load-balance profile LB_PROF_TCP` |
| `ssl-profile.out` | `show full-configuration load-balance real-server-ssl-profile LB_RS_SSL_PROF_DEFAULT`, selected fields |
| `interface.out` | `show full-configuration system interface port1`, selected fields |
| `defaults-omitted.out` | `show load-balance profile LB_PROF_TCP`, empty object table for a built-in profile |
| `absent.out` | `show full-configuration load-balance profile netops-g31-does-not-exist`, prompt only |
| `full-projection.out` | `show full-configuration`, derived projection for archive framing tests. The additional top-level system and closing block delimiters come from `tests/v1/fixtures/fortiadc_7_6_7_full_export.conf`, the anonymized Helper export of a complete VM220 capture. |

The tests derive a truncated response by removing the terminal prompt or closing records from these captures.
