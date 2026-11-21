Measured 2026-11-17, GNS3 d-iolxe DNAT 2257, IOS XE 17.18.2,
netops-ro independent OpenSSH exec (capture.py in task-evidence/g69).
Commands also checked as netops-admin; no configuration or terminal changes.
Anonymized on PC-Radek with tests/support/anonymize_fixture.py --check.

Empty captures are actual successful empty CLI responses. BGP is not active;
blue VRF does not exist; IPv6 has only FF00::/8 receive route and no interface
addresses. These captures do not demonstrate populated VRF/BGP/BFD/PBR/IPv6
interface tables. Rejected command variants are retained as negative evidence.
No guessed or manually populated outputs are included.
Adjacency encapsulation frames additionally pass through
`task-evidence/g69/anonymize_encapsulation.py`: embedded destination/source MACs
are mapped to AABBCC documentation MACs, preserving dot1Q and Ethernet type bytes.
