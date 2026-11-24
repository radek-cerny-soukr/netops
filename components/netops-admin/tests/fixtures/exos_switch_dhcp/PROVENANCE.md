# ExtremeXOS switch dhcp

Captured 2026-11-19 from the GNS3 ExtremeXOS VM 33.6.1.14 EXOS-VM (33.6.1.14) and the
X440-G2-12p-10G4 lab switch (33.7.1.6-patch1-11). The filename records
the command and the state. Operational output and the selected-file
diff were read as `netops-ro`. Running service lines were selected in
memory from the write-account configuration. Diff excerpts contain
only lines for temporary targets. Empty syslog output with SSH status
0 means no destinations. Both switches were restored to their original
running configuration.

The test addresses were replaced with documentation addresses by
`components/netops-helper/tests/support/anonymize_fixture.py`. Site
names and the configured SNTP hostname were anonymized with the same
tool. Output has trailing padding removed.

`x440-dns-client__removed.txt` is the complete status-0 SSH answer
captured by both accounts on 2026-11-19 at 18:56 UTC after confirmed
removal of the test resolver. The remaining DHCP domain and address
have been replaced with documentation values.
