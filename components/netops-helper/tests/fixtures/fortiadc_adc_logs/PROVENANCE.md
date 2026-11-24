# FortiADC adc logs captures

Read on 2026-11-17 from FortiADC-KVM 7.6.7, FortiADC-KVM 7.6.7 build0676. Independent
OpenSSH CLI used test jump host as a TCP transit. The commands were `get system status`,
`execute log filter type <type>`, `execute log filter subtype <subtype>`,
`execute log display <startline>`, `execute log filter clear` and filter readback.

`health.out` is event/health_check, `admin.out` event/admin, `configuration.out`
event/configuration, `system*.out` event/system and `waf.out` attack/waf.
The traffic captures are the responses for traffic/slb_http and
traffic/slb_layer4 at offset 0. Both contained only the search header.
`missing-selectors.out` is display 0 after clearing the filter.
`status.out` contains the version line of the real status response.

The bodies omit terminal framing, WAF request details and configuration values.
`tests/support/anonymize_fixture.py --check`  anonymized addresses,
account names and selected virtual-server and pool names. No traffic or health
change was generated for these captures.

## Positive traffic pages (verification)

Read on 2026-11-17 19:51–19:53 UTC from FortiADC-KVM 7.6.7 (FortiADC-KVM 7.6.7 build0676)
after local traffic logging was enabled (`config log setting local`,
`traffic-log-status enable`, `traffic-log-category slb`). Traffic came from
the test jump host client through VS_APP_HTTP (HTTP/80), LAB_VS_HTTPS (HTTPS/443) and the
Layer 4 VS LAB_VS_SMTP (TCP/25) to the backends FortiADC-KVM peer A/FortiADC-KVM peer B (RS_A/RS_B).

`traffic-http-page{0,20,40}.out` are `execute log display 0|20|40` with
traffic/slb_http, `traffic-layer4-page{0,20,40,80}.out` the same with
traffic/slb_layer4; page 80 is the last, partial page (12 rows). Each body is the
unchanged terminal body after the command echo (search header, rows, the two
blank lines and the display footer). Anonymised with an explicit mapping:
client 203.0.113.253, VS address 203.0.113.252, SNAT 198.51.100.1, backends
198.51.100.11/.12; virtual servers host10 (HTTP), host11 (HTTPS), host12 (L4).
Real-server names RS_A/RS_B, ports, byte counters and request fields are as read.
