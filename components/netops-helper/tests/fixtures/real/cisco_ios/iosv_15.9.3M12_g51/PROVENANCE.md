# G51 live IOSv captures

Captured 2026-11-17 on GNS3 IOSv SSH port 2251, IOS 15.9(3)M12, netops-admin (only show commands). Fixtures anonymized on PC-Radek with `tests/support/anonymize_fixture.py --name d-iosv --check`. Commands and return codes: `task-evidence/g51/commands.json` and `capture-receipt.jsonl` at repository root. IPv4/IPv6 brief were captured with netops-ro via `discover.json`.

OSPF is active (four neighbors, including two FULL adjacencies), IPv4 CEF has a connected entry. IPv6, VRF, BGP, BFD and PBR are not configured. Blank replies and `% BGP not active` are retained as negative evidence, never as successful populated-table fixtures. Configuration and pagination were not changed.
