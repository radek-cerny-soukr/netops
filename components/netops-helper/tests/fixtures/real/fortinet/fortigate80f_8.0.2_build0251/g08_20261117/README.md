# G08 RO captures, 2026-11-17 (IT-case)

FortiGate 80F HA primary, FortiOS 8.0.2 build0251; two managed FortiSwitch 224E-POE 8.0.1 build069.
SSH account `netops-test-ro` (one exec read, strict ED25519 pin) and REST RO API token `netops-test-api-ro`.
Nothing on the device was changed.

- `captures.json` key `user_devices`: `diagnose user device list`, 18 device blocks; SSH framing removed the way
  `netops_core.prompt.cleaned` removes it (prompt prefix of the first line, trailing prompt).
- `captures.json` key `refused_parse_error`: the RO account's answer to `get user device-store` (8.0.2 has no such
  command): the FortiOS refusal shape `command parse error` / `Command fail. Return code -61`, framing removed.
- `managed_switch_status.json`: `GET /api/v2/monitor/switch-controller/managed-switch/status`; projection: the
  per-port `ports` lists and `faceplate_xml` of each switch are removed, everything else is verbatim.
- `managed_switch_health.json`: `GET /api/v2/monitor/switch-controller/managed-switch/health-status`, verbatim.

Anonymized with `tests/support/anonymize_fixture.py --check` (MAC, IPv4/IPv6, host names, interface name of the
client VLAN, serials). The mapping file stayed on the lab test host and is not in the repository.
The RO SSH account is refused `execute switch-controller get-conn-status` (`command parse error`, -61) and
`get user device-store` does not exist on 8.0.2; neither is a catalogue query.

The CLI text is stored in `captures.json`, not as a `.txt` file: every `*.txt` under `tests/fixtures` is a capture of
the historical classifier baseline (`output_status_baseline.json`, oracle revision 1fad86c), which this capture is not
part of (same rule as `real/live_178`). The fixture privacy check reads the JSON strings like `.txt` files.
