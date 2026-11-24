FortiGate-60F lab, FortiOS 7.6.8 build 3744, 2026-11-18, interface addressing verification.
The fixture is a projection of the real response to `POST /api/v2/monitor/system/config/backup?scope=global`.
It retains the header shape and two entries from `config system interface`, with only the approved public fields.
The operator login was substituted before export from the lab; the projection was checked with
`components/netops-helper/tests/support/anonymize_fixture.py --check`. It is a transport fixture and cannot
restore a device. No full configuration or credential values were transferred from the lab.
