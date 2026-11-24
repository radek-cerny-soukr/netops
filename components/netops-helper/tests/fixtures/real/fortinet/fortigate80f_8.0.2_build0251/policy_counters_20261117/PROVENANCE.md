Captured 2026-11-17 UTC from FortiGate 80F HA HA FG-80F, FortiOS 8.0.2 build0251:
`GET /api/v2/monitor/firewall/policy`, RO API token; HTTP 200.
Raw response acquired independently (private measurement record)
Anonymised  with tests/support/anonymize_fixture.py --check (rc 0),
then UUIDs replaced by documentation UUIDs. No counter, timestamp, policy ID,
array shape, status or version was generated. Five returned rules include policy
1 with zero counters (last_used absent), three used explicit rules, and implicit
policy 0. Policy names/configuration are not present in this monitor response.
Error/incomplete test cases are labelled mutations of this response.
No configuration, reset, traffic generation or HA change was performed.
