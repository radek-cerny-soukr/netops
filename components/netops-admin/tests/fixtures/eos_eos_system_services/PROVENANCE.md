# Arista cEOS 4.36.1F, cEOS 4.36.1F-48405728.4361F

Measured 2026-11-19 in the approved emulated-environment. The configuration was read by
`netops-admin`. Operational output was read by `netops-ro`.

| Files | Command and conditions |
|---|---|
| before-ntp, settled-ntp | `show ntp associations \| json`, before addition and after initialization of a test server with `source Loopback0`. Its reachability is zero. |
| before-logging, after-logging | Header of `show logging`, before and after addition of a default UDP/514 host. The facility table and log buffer are omitted. |
| before-dns, after-dns | `show ip name-server \| json`, before and after addition of one server in the default VRF. |
| before-hosts | `show hosts \| json`, without an IP domain name. |
| after-config | Targeted running-config lines for the three test objects. |
| clean-diff | `show running-config diffs` while the fixtures' three servers were active and startup-config was unchanged. Context payload replaced with `[context]` before retention. |
| ro-diff-denied | `show running-config diffs` using the read-only account. The empty diff on the privileged account was zero bytes. |

The test IPs were mapped by
`components/netops-helper/tests/support/anonymize_fixture.py --check` with
a shared mapping. The operator fixtures do not include account configuration.

The capture wrapper masked a substring in the fixed JSON field names of
`before-hosts.txt`. The fixture restores only the literal schema labels
`domainName` and `domainList`, both with empty values. The logging headers
have trailing spaces trimmed.

The fake transport derives candidate logging levels, facilities and an IP
domain by replacing only the corresponding scalar in a measured header or
JSON object. It derives nonzero DNS priorities from the measured
`priority` field using the range in the
[EOS 4.36.1F command reference](https://www.arista.com/en/um-eos/eos-switch-administration-commands).
These variants are unit evidence.
