# router routing live IOSv captures

Captured 2026-11-17 on GNS3 IOSv, IOS 15.9(3)M12, netops-admin (only show commands). The captures were processed with the fixture anonymizer (`components/netops-helper/tests/support/anonymize_fixture.py`) with residual checking enabled. The source commands and return codes are in the private measurement records. The read-only account captured the IPv4 and IPv6 interface briefs.

OSPF is active (four neighbors, including two FULL adjacencies), IPv4 CEF has a connected entry. IPv6, VRF, BGP, BFD and PBR are not configured. Blank replies and `% BGP not active` are retained as negative evidence, never as successful populated-table fixtures. Configuration and pagination were not changed.
