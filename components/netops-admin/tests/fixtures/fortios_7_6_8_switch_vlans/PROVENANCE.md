# FortiGate 60F, FortiOS 7.6.8 build3744

Captured on 2026-11-20 through the pinned SSH connection to the lab FortiGate with a FortiLink-managed switch. The shared `components/netops-helper/tests/support/anonymize_fixture.py` anonymized the switch serial, MAC addresses and descriptions.

- `config.txt` is `show switch-controller managed-switch <serial>` with only the switch/port hierarchy and the selected port fields retained.
- `port1.txt` and `port5.txt` are scoped `diagnose switch-controller switch-info port-stats <serial> <port>` outputs. `port4.txt` is the extracted port block and switch header of the same command run without a port argument.
- `lldp.txt` is the anonymized `diagnose switch-controller switch-info lldp neighbors-summary <serial>` output.
- `trunk.txt` is `diagnose switch-controller switch-info trunk status <serial>`.
- `mac.txt` is `diagnose switch-controller switch-info mac-table <serial>`.
- Test transformations of these captures simulate refused, truncated or altered output and the state transitions the fake device applies.
