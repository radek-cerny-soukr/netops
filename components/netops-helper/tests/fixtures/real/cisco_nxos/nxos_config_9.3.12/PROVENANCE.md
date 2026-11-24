# NX-OS 9.3(12) config fixtures for nxos config

Independently pinned OpenSSH exec captures, 2026-11-19, from Nexus 9300v, NX-OS 9.3(12) (GNS3 emulated environment)
and nexus-peer-a/b (GNS3 switch-pair). All three targets reported Nexus9000 C9300v with NX-OS 9.3(12).
Commands were `show running-config`, `show startup-config`, `show running-config diff`
and a `| count` for each configuration. The backup and Helper comparison use the same native syntax.
Cisco command references are listed in nxos config command evidence (private measurement record, not published).

Configurations were redacted in memory with the Helper NX-OS allowlist, then passed through
`tests/support/anonymize_fixture.py`. The capture script restores only static command-frame syntax
and labels of timestamps with fixed placeholders. The refusal excerpt retains only the generic
device failure line from a separate netops-ro attempt (return code 30). Original hashes and return
codes are in `capture.json`. Empty diff files are complete responses with status 0. The Nexus 9300v, NX-OS 9.3(12)
capture had a nonempty native diff, so no empty fixture was saved for nexus9300v. The historical
nonempty context diff is the pinned Admin lab fixture `nxos_9_3_12/show-running-config-diff__unsaved.txt`.
The Nexus 9300v, NX-OS 9.3(12) running capture has 226 lines. Its later physical count read reported 217, so both
original outputs are retained for the mismatch regression. The diff tests that pair the earlier
running capture with startup derive the count of that exact redacted capture.

The physical Nexus 9336C and 5548 identity fixtures come from `fixtures/identity/`, with links to
their published sources in that directory. Tests which pair those identities with the virtual
switch's configuration exercise the public command and warning path with a derived pairing.
