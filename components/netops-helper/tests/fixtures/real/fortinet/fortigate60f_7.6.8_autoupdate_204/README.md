# FortiGate 60F FortiOS 7.6.8: autoupdate (verification)

Source: `ref/50-global-cli-post-s4b.out`, lines 141–386, the body of
`diagnose autoupdate versions` in `config global`, task dated 2026-11-14.
CR transport artefacts were removed; anonymized  using
`tests/support/anonymize_fixture.py --check` (rc 0). Only the FDS IP address
needed replacement. All 31 package blocks and the non-package FDS Address
block are retained, including their original version and expiry fields.
