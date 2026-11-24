NetOps 1.0.9 follows NetOps 1.0.8. It adds configuration captures and `config_diff` for ExtremeXOS, Cisco and Arista, FortiOS IPv6 route lookup and multi-VDOM reads, NX-OS vPC and EOS/EXOS MLAG views, ExtremeXOS optics and chassis summaries, Wi-Fi AP backhaul correlation and FortiADC schedule-pool triage. The Auditor gains `findings_summary` and collection while NetOps runs; Admin gains `expected_plan_sha256`, `admin_undo_preview`, the measured FortiOS `firewall service custom` profile and ExtremeXOS port admin-state and PoE cycles.

Editorial change after release: lab identifiers removed, no change in content.

## Changes in 1.0.9

### Added

- Helper can correlate a tunneled Wi-Fi client with its AP/radio and the AP's switch backhaul. The switch port belongs to the AP, not to the tunneled client; missing station, VLAN or forwarding evidence remains explicit.
- Configuration captures add narrowly gated ExtremeXOS, Cisco IOS, IOS XE, NX-OS and Arista EOS full views. Each requires explicit configuration access, a supported live identity and device permission for the fixed command. Allowlisted visible lines survive; credentials and unclassified lines become markers. Device refusal returns `device-refused`, never an empty snapshot. See [identities and account requirements](../docs/helper-configuration.md#configuration-captures-on-exos-cisco-and-arista).
- `config_diff` compares snapshots on those five platforms with a shortest line edit script (Myers). Limits of 3000 changed lines, bounded comparison work and configuration memory refuse oversized comparisons with `config_diff_limit_exceeded`. Hidden content is not compared (`hidden_lines_compared: false`); changes to hidden-line counts do not invalidate an otherwise comparable pair. Incompatible scope, firmware or profile returns `config_snapshot_incomparable`. FortiOS/FortiADC retain positional comparison.
- ExtremeXOS optics/DOM and chassis summaries expose the measured metrics and partial evidence; physical DOM evidence is limited to X440G2 and does not qualify X435 optics or virtual hardware sensors.
- FortiOS `ipv6_route_lookup` adds scoped IPv6 destination lookup with explicit identity and parsing limits; it does not add IPv6 routes to Linux normalization.
- NX-OS vPC and EOS/EXOS MLAG summaries and members accompany the fixed `ssh_read` catalogue queries. They are not `switch_read` tables; active peer topologies remain documentation-derived where captures only show inactive, empty or refused states.
- FortiOS multi-VDOM catalogue, normalized-table and routing/VPN/health triage reads verify the session VDOM and context, label `data_scope`, and fail closed on ambiguous identity, context or interface ownership. Only the enrolled current VDOM is read. Device-wide session counters stay device-wide; multi-VDOM `config_read` with `redaction="minimal"` and `triage_flow` remain unsupported. A per-VDOM administrator logged in through an interface of its VDOM reads that VDOM directly once the device proves the login context, and reads beyond its VDOM return `vdom_admin_global_scope_unavailable` (verified live on the FortiGate-60F 7.6.8 build3744 on 2026-11-15, source 7bec0b7, 112/112 checks passed). Full `config_read` reads the global/VDOM structure as visible to the account (`config_scope: device-account-visible`, `vdom-coverage-not-verified`), without selecting a VDOM context or assigning the capture to a single VDOM. See [scope and refusals](../docs/helper-configuration.md#fortios-multi-vdom-reads).
- FortiADC SLB triage follows `schedule-list` through schedule-pool and schedule-group views, returning sourced candidate pools. Statistics may name an old stored pool, so the result does not claim an active pool, historical selection or backend health from those references. Schedule-window activity is not calculated; content routing remains unsupported.
- Auditor supports `collect`, `run` and `status` through `docker compose exec` while NetOps runs. A private store lock serializes writers; MCP reads see a committed state. Collection/run write preflight and result audit records. Configuration and imports still require the stopped instance, and commands share container resource limits.
- Auditor `findings_summary` returns brief last-run findings across devices with severity/state/rule filters, bounded output, truncation and counts before/after filtering. Without a rule filter its totals match per-device `list_findings` totals under the same severity/state filters. It has no paging or historical detail. `audit_status` and `list_findings` also return `suppressions_configured`; it is `false` in 1.0, which has no supported way to supply a suppression file.
- Admin `expected_plan_sha256` optionally binds apply to the approved preview: a fresh substantive plan mismatch is refused with `plan_changed` before writes. It does not replay preview commands and does not apply to schema transactions.
- Admin `admin_undo_preview` and CLI `admin undo --preview` show checks and impact without applying undo; actual undo remains an operator action. After an undo has run, undo preview is refused with `undo_already_done`; repeating the identical operator undo returns its stored result.
- Opt-in FortiOS `firewall service custom` supports create/update/delete and undo, measured end-to-end on 7.6.8 build3744 (`cli-script`) and 8.0.2 build0251 HA (`webhook`). The profile is measured and no longer provisional. Referenced/protected services are guarded. Policy enable/disable continues to use the existing policy `status` update. Service safeguard POST rollback, SIGKILL/recovery and whole-management-path loss remain unmeasured for this table.
- ExtremeXOS port `admin-state` updates and operator-only PoE cycles use the persistent UPM safeguard with operations gated to ExtremeXOS 33.7.1.6 (patch level and model are not checked); measured only on 33.7.1.6-patch1-11 on X435-8P-4S/X440G2. Unreadable LLDP/FDB usage refuses disabling with `port_usage_unreadable`; a non-PoE port returns `poe_not_capable` (on the switches the live run still got `unspecified_refusal`, fixed afterwards and covered by automated tests, not repeated live). Device commands were measured on X435/X440G2; Admin disable/undo, safeguard revert after loss of the check account and a PoE cycle ran on the two switches on 2026-11-14 (source 72c1fca; 9 of 10 scenarios passed), with the check account reading the PoE state. Real powered-device recovery time, the `delivering` state and `port_usage_unreadable` on a switch remain unmeasured.

### Changed and fixed

- Use the current Compose `no-new-privileges=true` syntax. Refresh the pinned Python/Alpine base digest and compatible dependencies (FastMCP 4.1.3, PySNMP 7.1.32, cryptography 50.0.2). This does not claim that every dependency vulnerability is fixed or that release scans/signatures are complete.
- Release assessment matching preserves package version and type, preventing another version's assessment from being overwritten during merging.
- FortiOS multi-VDOM reads refuse an enrolled VDOM with `vdom_not_found` only when `get system status` counts exactly one VDOM (the session's own), otherwise still `vdom_scope_required`, and the `auth` advice of a FortiOS target with `diagnostic_vdoms` adds that a per-VDOM administrator must log in through an interface of its own VDOM, on every read path including table reads (`switch_read`, `locate_endpoint`).
- FortiOS flow/policy triage accepts an unknown source port without inventing one, and reports ambiguity when the available evidence cannot choose a policy.
- Preserve the earlier response-redaction protections, including Unicode whitespace/line-boundary cases. Failed secondary reads in normalized-table joins retain their error classification. CDP recognizes record boundaries, advertised totals, non-Cisco remote-port IDs and phone TLVs; Linux stateless/stale FDB entries normalize as dynamic. An Auditor store mismatch message identifies the Auditor workflow.
- Reconcile support documentation with the carried-forward read-only EXOS acceptance of 1.0.8 and restrict FortiSwitch claims to measured 224E-POE operations and topology. Correct endpoint dates, EXOS naming, the `lag_summary` requirement and the measured SLB durations (about 61/71/81 seconds: healthy HTTP virtual server, a DOWN member, HTTPS/TLS virtual server; FortiADC-KVM 7.6.7, 2026-11-10). These are not upper bounds: a virtual server with `schedule-list` took 81–86 s (2026-11-14). Document Linux VXLAN `dst` FDB and `sit0` link forms as `unparsed` coverage limitations.
- Update version metadata, the 1.0.8 → 1.0.9 upgrade pin and the upgrade guide ([Upgrade from 1.0.8](#upgrade-from-108)).

The classifier replay baseline (`components/netops-helper/tests/fixtures/output_status_baseline.json`) holds 1057 captured texts.

The MCP API changes of these items (new tools, new arguments and changed role responses) are declared in `release/acceptance/api-changes-1.0.8-1.0.9.json`.

## Security

The security-related changes of 1.0.9 tighten what NetOps returns and which scope it reads; they do not add an arbitrary command or write path. Response redaction keeps every character that the released 1.0.8 chain hid, including Unicode whitespace and line-boundary cases; where the current chain cannot reproduce that floor, for example for a JSON document nested in a string value, the output is withheld instead of returned. The new ExtremeXOS, Cisco and Arista configuration captures return only allowlisted visible lines: credentials and unclassified lines become markers, NX-OS and EOS captures also hide recognizable password hashes and Cisco type 7 values (including a value followed by punctuation), and `config_diff` does not compare hidden content. A FortiOS per-VDOM administrator reads only its own VDOM once the device proves the login context, global and cross-VDOM reads return `vdom_admin_global_scope_unavailable`, a request for another VDOM is refused with `vdom_scope_required` (or `vdom_not_found` when the device proves that VDOM absent), and ambiguous identity, context or interface ownership fails closed. These notes do not assert the result of the review or scan of the 1.0.9 release candidate.

### Known dependency findings

The pinned Python/Alpine base digest and compatible dependencies (FastMCP 4.1.3, PySNMP 7.1.32, cryptography 50.0.2) are refreshed. This does not claim that every dependency vulnerability is fixed or that release scans and signatures are complete.

The 1.0.9 image still carries the findings of 1.0.8 in components taken from its base image whose owners have not released a fix that NetOps can build on. A local scan on 2026-11-15 of an image built from the 1.0.9 source at commit 243c14f (later changes touch only tests, documentation and the evidence text of one Admin profile) found the same packages and CVEs on amd64 and arm64 (Python 3.14.10, SQLite 3.53.4, BusyBox 1.37.0), each with a written assessment. They remain because the fixed versions are not released for the base image (Python 3.14.11 was not yet released, and Alpine 3.24 still supplied `sqlite-libs` 3.53.4-r0 and BusyBox 1.37.0-r31 when checked against python.org and the Alpine 3.24 package index on 2026-11-15). A written assessment is not a repair and not a claim of zero CVEs.

| Component | CVE | Status |
|---|---|---|
| Python 3.14.10 | CVE-2026-103995 (HTTP client accepts `+61`, `6_1` as chunk sizes) | Flaw remains in the interpreter; no fixed 3.14 release was available when checked on 2026-11-15. NetOps does not reach it: since 1.0.8 Helper and Auditor reject such chunk sizes; the Admin notification sender does not read response bodies. |
| Python 3.14.10 | CVE-2025-15367 (`poplib`) | No fixed 3.14 release was available when checked on 2026-11-15; NetOps does not use `poplib`. |
| Python 3.14.10 | CVE-2026-116566 (NUL in `getaddrinfo`) | Fixed in the unreleased 3.14.11. Host names come only from the operator's own configuration. |
| Python 3.14.10 | CVE-2026-119170 (`hashlib`, OpenSSL in FIPS mode only) | Fixed in the unreleased 3.14.11. NetOps does not configure FIPS mode. |
| SQLite 3.53.4 (`sqlite-libs`) | CVE-2026-119371 to CVE-2026-119379, CVE-2026-119591 | Fixed upstream in 3.54.0, not in Alpine 3.24. Reachable at most through a crafted Auditor store file placed in the instance's private state or backups, which already requires control of that state; no client or device can supply SQL or a database. Since 1.0.8 the store type check refuses a view in place of an expected table. |
| SQLite 3.53.4 (`sqlite-libs`) | CVE-2026-119586 (`.recover` of the `sqlite3` shell) | **No released upstream fix** is recorded in the assessment, including 3.54.1. NetOps links the library only and never runs the shell. |
| BusyBox 1.37.0 | CVE-2025-60876 (`wget`) | Not fixed in Alpine 3.24. NetOps never runs `wget`. |

Impact per the assessments (`netops-1.0.9-vulnerability-assessments.json`): the HTTP framing finding concerns responses from an enrolled device whose certificate or pinned fingerprint was verified before the token is sent and whose body is bounded (Helper 2 MiB and 10 s; Auditor byte budget). A deployment that treats the enrolled HTTPS peer as untrusted is not covered by the assessments.

## Upgrade from 1.0.8

Follow [Upgrade from the previous release](../docs/quickstart-1.0.md#upgrade-from-the-previous-release):

1. Check the 1.0.8 instance, stop it and create its backup and state manifest.
2. Download and verify the 1.0.9 release files. Prepare a separate instance directory and a new Compose project with the same server name and port, and download the 1.0.9 image.
3. Restore the backup into an empty target volume and compare it with the source manifest before the first start. Keep the original instance and backup.
4. Start the new instance. The first start converts only the recorded product version from 1.0.8 to 1.0.9 under the instance lock and writes an `instance_start` audit record with `upgrade` from 1.0.8 to 1.0.9. A second start skips conversion. CA, keys, token, role data and connection details are unchanged.

No inventory or credential change is needed. Do not run `init` on the restored state. Only 1.0.8 is accepted as the previous release; upgrade 1.0.7 to 1.0.8 first.

For rollback, stop 1.0.9, preserve its audit records written after the backup, and start the unchanged 1.0.8 instance; see [Rollback](../docs/quickstart-1.0.md#rollback). A direct downgrade of a converted volume is not supported.

## Known limitations

- Admin writes for Junos, Arista and Cisco are deferred to 1.0.10; no arbitrary CLI write API is added.
- The scope limits stated with each change above apply; in particular, FortiOS multi-VDOM `config_read` with `redaction="minimal"` and `triage_flow` remain unsupported.
- `findings_summary` has no paging or historical detail. `expected_plan_sha256` does not apply to schema transactions.
- For FortiOS `firewall service custom`, the service safeguard POST rollback, SIGKILL/recovery and whole-management-path loss remain unmeasured. For ExtremeXOS port admin-state and PoE cycles, real powered-device recovery time, the `delivering` state and `port_usage_unreadable` on a switch remain unmeasured, and the `poe_not_capable` fix was not repeated live.

## Acceptance

The acceptance of 1.0.9 consists of: repository, release-tooling and acceptance-tooling tests, installed-image tests and the engine regression of the four roles on amd64 and arm64; Actions candidate checks; installation by following the quickstart on the [supported platforms](../README.md#supported-platforms); `release/acceptance/upgrade-check.sh` from 1.0.8 to 1.0.9 against `release/acceptance/api-changes-1.0.8-1.0.9.json` (the new tools `admin_undo_preview` and `findings_summary`, the optional arguments `expected_plan_sha256` of `admin_apply` and `source_port` of `triage_flow`, the `admin_preview` description, the queries `ipv6_route_lookup` and `mlag_interfaces` in the query catalogue and the `audit_status` field `suppressions_configured`); the MCP client checks; release signing with checksum, registry and vulnerability checks. The results are acceptance reports (`acceptance-*.json`) covered by the signed checksum list. These notes describe the required checks and do not assert that publication acceptance has passed.

## Verify this release

```sh
cosign verify-blob --bundle netops-1.0.9-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.9-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.9-SHA256SUMS
```
