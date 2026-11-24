# cEOS eos config configuration captures

GNS3 `netops-emulated environment` node Arista cEOS 4.36.1F, cEOS 4.36.1F-48405728.4361F.
Captured on 2026-11-18. `running.out` and `startup.out` are projections of the
baseline SSH exec output of `show running-config` and `show startup-config`.
`running-changed.out` adds two unattached test ACLs and one prefix list.
`diff-empty.out` and `diff-changed.out` are the corresponding native EOS
`show running-config diffs` captures. The latter preserves hunk dimensions
and prefixes, with normalized header paths and sensitive context withheld.
The CLI rendered TCP port 443 as `https`. The test objects were removed
and independent SHA-256 comparisons confirmed the two configurations returned
to their original states.

The capture filter preserves the framing, line count, indentation and selected
ACL and routing statements. Other configuration lines were replaced by opaque
placeholders in memory before writing any file. The startup timestamp was normalized.
`tests/support/anonymize_fixture.py
--check --name Arista cEOS 4.36.1F` mapped visible identifiers across the fixtures.
`startup-denied.out` is the privilege-1 account's rc 1 stdout.
`privilege-admin.out` and `privilege-ro.out` are exact `show privilege` outputs.
Version identity is reused from `../ceos_4.36.1F/version.txt`.
