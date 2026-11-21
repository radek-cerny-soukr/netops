# Cisco hardware QFP examples

Cisco IOS XE outputs with command prompts and trailing whitespace removed. Processed with `tests/support/anonymize_fixture.py`. No IOS XE release is identified for the QFP traffic and drop snapshots.

| Fixture | Cisco platform and source |
|---|---|
| `drops.out`, `utilization_crypto.out` | ISR 4000 / ASR 1000, [Troubleshoot Interface Packet Drops in IOS XE Routers](https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-ios-xe-sd-wan/224129-troubleshoot-interface-packet-drops-in.html). Crypto/IO layout is from the documented `summary` variant. |
| `utilization.out` | ASR 1000, [Throughput Issues on ASR 1000 Series Router](https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-aggregation-services-routers/200674-Throughput-issues-on-ASR1000-Series-rout.html). |
| `version.out` | ASR 1000, [Understand Configuration Register Usage on all Routers](https://www.cisco.com/c/en/us/support/docs/routers/10000-series-routers/50421-config-register-use.html). IOS XE 16.10.01a identity header, independent of drop and utilization examples. |
