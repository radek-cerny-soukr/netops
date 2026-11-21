# NX-OS 9.3(12) config fixtures for G98

Independently pinned OpenSSH exec captures on PC-Radek, 2026-11-19, from d-nxos (GNS3 D-lab)
and b04-nx-a/b (GNS3 B04). All three targets reported Nexus9000 C9300v with NX-OS 9.3(12).
Commands were `show running-config`, `show startup-config`, `show running-config diff`
and a `| count` for each configuration. The backup and Helper comparison use the same native syntax.
Cisco command references are listed in [G98 command evidence](../../../../../../../task-evidence/g98/commands.md).

Configurations were redacted in memory with the Helper NX-OS allowlist, then passed through
`tests/support/anonymize_fixture.py`. The capture script restores only static command-frame syntax
and labels of timestamps with fixed placeholders. The refusal excerpt retains only the generic
device failure line from a separate netops-ro attempt (return code 30). Original hashes and return
codes are in `capture.json`. Empty diff files are complete responses with status 0. The d-nxos
capture had a nonempty native diff, so no empty fixture was saved for d-nxos. The historical
nonempty context diff is the pinned Admin lab fixture `nxos_9_3_12/show-running-config-diff__unsaved.txt`.
The d-nxos running capture has 226 lines. Its later physical count read reported 217, so both
original outputs are retained for the mismatch regression. The diff tests that pair the earlier
running capture with startup derive the count of that exact redacted capture.

The physical Nexus 9336C and 5548 identity fixtures come from `fixtures/identity/`, with links to
their published sources in that directory. Tests which pair those identities with the virtual
switch's configuration exercise the public command and warning path with a derived pairing.
