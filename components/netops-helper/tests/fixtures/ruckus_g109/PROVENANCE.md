# G109 Ruckus Unleashed fixtures

The six `show_*.out` files were captured on 2026-11-18 from a standalone R610 on Ruckus Unleashed
200.15.6.212.27. The system SSH PTY used the pinned host key. Only privileged `show` commands ran.
Blank capture separators, prompts and trailing spaces were removed. The support tool
`tests/support/anonymize_fixture.py` was applied with a shared mapping for IPs, MACs, SSIDs, AP identity,
serial and description, with an additional explicit replacement for the mesh name and AP labels in
event messages. No mapping is stored with the fixtures.

`show events` and `show events-activities` returned identical bodies in that session. The mesh capture
contains a topology header only. The same AP reported `Mesh: Status= Disabled` in `show ap all`.

`mesh_topology_vendor.out` is adapted from the Ruckus Unleashed 200.15 CLI Reference Guide
(800-73555-001 Rev A, p. 94). The network name and addresses were replaced. Line breaks and
indentation were restored from the labels in the PDF example. The lab reproduced only the empty
topology form. [Manufacturer guide](https://manuals.plus/m/828b9c31161b5ebb4c6f8e8274b818ad40c3290e2861c5ae1def74e19f54f3f3)

`mesh_disconnect_vendor.out` is a documentation-derived `Activity` record. The mesh-to-root disconnect
wording follows the RUCKUS Unleashed 200.15 Syslog Event Message Reference Guide (800-73557-001 Rev A,
p. 20). The surrounding CLI fields and `AP[name MAC]` placeholders follow the live events capture.
The timestamp, severity and AP identities are fixture values. [Manufacturer guide, p. 20](https://support.alcadis.nl/Support_files/Ruckus/Unleashed/Manuals/Ruckus%20Unleashed%20200.15/Unleashed-200.15-Syslog-Event-Message-Reference-Guide-RevA-20240115.pdf#page=20)

The tests derive incomplete and unknown responses by removing or changing lines of a capture.
The absent AP response is the G107 capture of the same firmware with the requested MAC updated.
