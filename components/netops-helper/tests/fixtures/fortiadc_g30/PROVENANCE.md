# FortiADC VM220 7.6.7 build0676, 2026-11-19 UTC

- `rest.json` contains allowed fields of real HTTPS GET responses in the global VDOM, collected on PC-Radek with the pinned TLS certificate. The fixture has no login reply, cookies or key material. The capture retains the SAN extension and omits the other extensions. See `task-evidence/g30/probe-rest.py`.
- `acme.out` is the frame and certificate fields from `get system certificate local`. `groups.out` is `show full-configuration system certificate local_cert_group`, with a completed pager marker removed.
- All three captures were processed together by `tests/support/anonymize_fixture.py --check` with the custom certificate, group, profile and SAN names supplied as explicit name literals. Trailing whitespace was removed from the CLI fixtures after anonymization. Derived negative cases are identified in the tests.
