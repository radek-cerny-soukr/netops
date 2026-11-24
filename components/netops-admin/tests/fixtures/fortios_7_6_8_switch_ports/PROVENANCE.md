# FortiGate 60F, FortiOS 7.6.8 build3744

Captured over pinned SSH on 2026-11-20 using the independent read account.

- `managed-vlans.txt` retains the observed managed-switch and port layout and selected VLAN and FortiLink attributes from `show switch-controller managed-switch`.
- `interfaces.txt` retains the relevant interface entries and VLAN/FortiLink fields from `show system interface`.
- `port5.txt` is the output of `diagnose switch-controller switch-info port-stats <serial> port5`.
- `poe-summary.txt` and `poe-port.txt` are the hardware refusals from `diagnose switch-controller switch-info poe summary <serial>` and `diagnose switch-controller switch-info poe detail <serial> port5`.

The shared Helper anonymizer processed these captures. The masked serial was aligned with the earlier switch vlans trunk and MAC captures for the same switch. Only the allowlisted fields were kept for configuration.

- `poe-powered.txt` retains the switch, port, power and final current lines from the Fortinet 108E-POE example for `diagnose switch-controller switch-info poe detail` on FortiGate. Its published serial was already masked and the cut-off state label in the detailed example was completed using the corresponding summary row. Tests derive the same output shape for port5 and for simulated power transitions. [Fortinet PoE diagnostics](https://community.fortinet.com/fortigate-3/technical-tip-how-to-collect-status-of-poe-ports-on-a-managed-fortiswitch-from-fortigate-cli-227377)
