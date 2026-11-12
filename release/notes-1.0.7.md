NetOps 1.0.7 follows NetOps 1.0.6. It adds read-only Wi-Fi and flow diagnostics, switch/router profiles and normalized tables, improves Auditor coverage reporting and Admin diagnostics, and fixes paged-output secret disclosure. The product remains one container with Helper, Auditor and Admin behind one audited HTTPS MCP endpoint. The syslog audit format and receiver requirements are unchanged.

- Correlate late ARP/ND MACs against saved endpoint MAC tables and reuse auxiliary captures; expose per-alias read caps, cache failed hostname supplements and avoid ownership retries after transport failures. Preserve FortiSwitch all-VLAN configuration with explicit FortiLink context, clear NX-OS connected/local IP gateways and return only active Junos detail routes, consistently with whole-table reads.
- Clarify that Auditor exit 3 is driven by required rule coverage, not every export visibility limitation: networking can be actionable while an unrelated user-area limitation can permit exit 0; retain separate export metadata checks.

- Correct the public SLB triage duration to the measured HTTP, DOWN-member and HTTPS/TLS scenarios (about 61/71/81 seconds), explain timeout headroom and optional progress, and refresh flow-session and SSH Wi-Fi join-time provenance notes.

- Wi-Fi triage distinguishes exact VAP ids from broadcast SSIDs, preserves current REST and matching event ids, and reports ambiguous SSID profiles as missing evidence instead of a false VAP-down fault.

- Wi-Fi neighbor filtering, ordering and summary signal now use only AP/radio observers with channel overlap; summaries name the observers of that signal and full reads retain all observations.

- Scale endpoint location to 64 enrolled targets with eight concurrent device readers, a shared deadline and explicit unfinished-target coverage while preserving audited read-only verdicts.

- Prevent device-output ReDoS in Junos error counters, NX-OS identity, switch tables and wireless parsers with linear token validation and adversarial regressions.

- Response redaction now masks complete community values using original SNMP context while preserving the 1.0.6 secrecy floor, avoids redundant passes, and reports full-capture device refusals as safe `-32602` errors.

- The new OSPF neighbor table uses lowercase canonical `state` values (`full`, `2way`, `exstart`, etc.). EOS `2 WAYS`, NX-OS `TWOWAY` and Junos `2Way` all normalize to `2way`.
- Preserve the full 1.0.6 helper → proxy → worker redaction chain before terminal cleanup and repeat it afterwards; bound ANSI string controls to one line and 4096 characters, retaining the payload of unfinished controls.

- Name the real cause of every failed SSH device read (`unreachable`, `timeout`, `connection_refused`, `host_key_unavailable` only for a host that answered without a usable key, `host_key_mismatch`, `auth`, `disconnected` and the other fixed classes) with fixed advice in `error_code`/`error` of `ssh_read`, `schema_read`, `switch_read`, `locate_endpoint`, `config_read`, `fortios_diagnostics` including the FortiADC recipes and the triage tools, and in the Helper audit `detail`, instead of `host_key`, `ssh_unavailable` or `Role operation failed`. The client's closing message alone decides the class and any `legacy_ssh` advice, so a login banner, even one naming `no matching`, never turns a refused login into `negotiation` (also for the `sftp_stat` reason). Every resolver failure of the target name (`EAI_NONAME`, `EAI_NODATA`, `EAI_FAIL`, `EAI_AGAIN` and the others) is `dns` by its type, before any text.

- Parse every member of real EXOS sharing groups, attach a safe transport cause to failed normalized reads and their audit, and distinguish enrolled LLDP neighbors with `endpoint_not_seen_on_neighbor_target`.

- Permit FortiADC real-server object reads, distinguish local triage refusals from device reads, give health-check follow-ups enough time, normalize EXOS load-sharing groups and document measured SLB durations and call queuing.

- Optional `helper.fortios_rest_port` selects management HTTPS independently of SSH
  (default 443, whole number 1–65535); resolver, egress, socket and HTTPS use it,
  enrollment refuses a port outside TCP egress, and `target_scope` reports it.
  Match FortiGate `admin-sport` when 443 serves SSL VPN. The Wi-Fi REST guide
  retains the administrator checklist and recommends the verified 80F 8.0.2
  build0251 minimum: `wifi read` + `loggrp read`, other groups `none` including
  `authgrp`, all `cli-*` disabled; all-read is an alternative. Omit `set vdom`
  for single-VDOM; use it only for multi-VDOM provisioning. Token generation
  requires an administrator with API-user rights.

- Wi-Fi triage selects significant history instead of the newest five events, reports absent MACs with history and a cause or unknown, and samples signal three times with min/max/last. It separates client link/signal from shared radio utilization/retries, keeps unknown measurement ages null, and documents per-target serialization and the 15-read REST triage reservation. Successful warning-level handshakes are not authentication failures.
- Wi-Fi diagnostics now prefer read-only REST wireless history, continue when history is unavailable, enrich client identity and filter exact hostnames. Configurable signal/SNR heuristics include explanatory findings; both triage views show AP/radio RF evidence and explicitly unknown common measurement age with a separate wired/LLDP gap. Link RX/TX rates, traffic and client retry/discard are distinct; relevant neighbor summaries deduplicate BSSIDs and full observations remain available. Client timelines show coverage and downgrade errors older than the last observed association, even if a later snapshot fails. See [Wi-Fi REST](../docs/fortios-wifi-rest.md) for the complete contract.

## Changes in 1.0.7

- Accept the real NX-OS trunk forwarding continuation `none` after the disabled-VTP notice, preserving allowed VLANs and native tagging in `port_vlan`.

- `fortios_diagnostics` now defaults to a 10-second timeout (previously 5 seconds), allowing FortiADC `nslookup` to complete a cold DNS cache lookup.

- Hide SNMP communities and auth/priv credentials across FortiOS/FortiADC/EXOS, retain credential keywords and numbered PSK labels without weakening the 1.0.6 redaction floor, and accept real FortiOS minimal syntax with safe `redaction-unverifiable` client errors.

- Normalize multiword EOS and other OSPF neighbor states with five preserved live captures, add field/hint guidance to invalid proxy arguments, and strip ANSI escapes and C0 terminal controls except newline/tab from device output before hashing, paging and client delivery.

- Parse Junos day/week route ages and wrapped IPv6 prefixes, explain a missing Junos interface_errors selector with -32602 and an enrolled-interface hint, and recognize FortiOS log search progress as status metadata.

- Fix day-old cEOS LLDP ages, EXOS connected next-hop semantics and IOS/XE error-counter fallback to separately authorized whole `show interfaces`, with incomplete empty results and anonymized real-output regression coverage.
- Add `port_vlan` access/trunk/routed membership tables, read-only EXOS VLAN detail, IOS trunk-aware VLAN membership and endpoint VLAN tagging evidence.
- `switch_read(table="interface_errors", interface=...)` adds cumulative port error/discard counters and available flap evidence from IOS/XE, NX-OS, EOS, EXOS and Junos, with explicit source coverage and no new permissions.
- FortiOS `switch_read` explains unsupported tables, normalizes IPv4 lookup/table routes and adds enrolled FortiSwitch link/speed, cumulative errors/drops and explicitly configured VLAN membership to endpoint location, verified by replay of read-only FortiGate 80F 8.0.2 build0251 captures.
- IOS / IOS XE empty IPv4 route lookups fall back to the authorized routing table and select the longest matching prefix.
- `locate_endpoint` recognizes an enrolled target's own interface from local/interface ARP or already-read interface addresses and returns `own_interface_of_target` with target/interface evidence. Unresolved transit MACs may check enabled IPv4 ARP within the existing 40-read/60-second budget; GNS3 replay resolves both router IP and MAC in 28 reads.
- Table interface names and filters share canonical long forms: EOS Ma0/Management0, Et/Ethernet, Po/Port-Channel and NX-OS Eth/Ethernet.
- `locate_endpoint` reads ARP/ND first for an IP and all MAC tables before auxiliary switching reads, then LLDP only on switches holding the MAC and interface, port VLAN, LACP and VLAN reads only for ports without an LLDP switch neighbour, so the seven-node GNS3 lab fits in 28 of the 40 reads.
- `locate_endpoint` finds the own interface of EOS, NX-OS, Junos, EXOS and FortiOS targets in their enabled `ip_interface` read when nothing else located the endpoint, treats a FortiAP LLDP neighbour (`B,W,R,S` or a FortiAP/FAP name) as an AP, and on FortiLink reads nothing behind trunks or the switch's own `internal` port and the port state and VLAN configuration only for the edge, so the IT-case AP and FortiSwitch MAC need 8 and 3 reads (about 45 and 20 seconds at 5 s per FortiOS read) instead of reaching the 60-second deadline.
- `locate_endpoint` treats an LLDP neighbour without capabilities whose system name is the host name (sysName, without case or domain) of another enrolled target as that switch, so two enrolled EXOS in a row give `transit` on their link and `located` at the edge port instead of `incomplete`; the own addresses of both lab EXOS are `own_interface_of_target` on their read-only outputs.
- `switch_read` table `ip_interface` (interface, IPv4 address, prefix length, SVI VLAN, admin/oper state, VRF where printed) for IOS, IOS XE, NX-OS (mask from the connected route), EOS, EXOS, Junos and FortiOS (new read-only template `system_interfaces`: `get system interface`), with an optional `interface` filter; an IOS/IOS XE target declared as router reads the `interface` table from `show ip interface brief`.

- Wi-Fi triage reads station-filtered REST history before the 200-row bound,
  reports exact retained-window coverage and uses English diagnostic messages.
- Operating-radio REST utilisation, retries, noise and interference can complete
  RF evidence when a DFS operating channel is absent from background scan rows.
- Failed client/AP REST joins return no partial client records; triage preserves
  precise REST failure codes in missing evidence.
- Wi-Fi review fixes retain partial signal evidence, classify DHCP/auth failures, bound significant history, expose client-supplied hostname trust and keep controller-wide neighbors as context. RSSI below the severe threshold is a fault only when both minimum and final values remain below it. AP utilization has its own age; common radio age stays unknown.

- Seven new tools: `switch_read`, `locate_endpoint`, `triage_flow`, `wifi_clients`, `wifi_aps_live`, `wifi_rogue` and `wifi_triage`; 39 tools with Admin, 33 without it. Wi-Fi REST reads require a separately enrolled read-only token, a pinned certificate or CA and the fixed GET allowlist. Without enrollment, existing SSH diagnostics continue and REST reads return `unsupported`.
- It adds FortiOS read-only Wi-Fi queries and normalized Wi-Fi records, client event correlation and bounded flow triage. Lookup prefixes are optional canonical CIDRs in `lookup_prefixes`; a prefix does not enroll the addresses inside it, and egress policy is unchanged. Not every parameter needs an inventory entry: literal VLAN/MAC and Wi-Fi event parameters are checked for their form, `wtp_id` can come from an earlier `wifi_ap_status`, and `triage_flow` allows its own `src`, `dst`, `port` and `proto` for that one call ([details](../docs/helper-configuration.md#optional-helper-fields)).
- It adds EXOS, Cisco IOS/IOS XE/NX-OS, Arista EOS and Junos/ELS profiles, daily operational queries and normalized interface, VLAN, MAC, ARP/ND, LLDP, routing, OSPF/BGP, LAG and STP tables through `switch_read` and `locate_endpoint`. `enabled_queries` authorizes individual catalogue reads; `device_types` selects the readers used by `locate_endpoint`. The catalogue contains 547 templates; measured and documentation-only coverage per operating system is in [Helper coverage by OS](../docs/verified-support.md#helper-coverage-by-os-netops-107), and device permission limits in the [read-only account guide](../components/netops-helper/docs/read-only-accounts.md).
- The new operational tables use [canonical value names](../components/netops-helper/docs/normalization.md#operational-value-names), including `direct` → `connected` and `TWOWAY` → `2way`, with documented handling of unknown values.
- Five text-only troubleshooting prompts; triage progress notifications are audited and sent when the MCP client supplies a progress token (the call is then answered as `text/event-stream` that ends with the result).
- New authenticated `GET /healthz` on the HTTPS port: local audit, syslog queue and role state (`ok`, `degraded` or HTTP 503 `failed`); it never contacts managed devices. A successful health read is not audited; a query-string rejection and a failure are. Scope refusals report the field and parameter name, never the value. `ssh_read`, `switch_read` and `locate_endpoint` publish their argument limits in `inputSchema` and name the field and its rule in `-32602` errors; `configure helper` names the refused device position and field.
- Password SSH authentication uses the password method first and falls back to keyboard-interactive, for command, terminal and SFTP sessions. OTP/MFA, repeated password prompts and host-key questions are refused. With a wrong password, a device offering both methods can count two failed authentications toward its lockout policy. Helper SSH-family connections to FortiOS and FortiADC start at least five seconds apart per target, automatically.
- Auditor queries reuse evaluated-run lookups and load requested comparisons directly. Status now includes `coverage`; FortiADC factory-certificate provenance alone no longer makes `auditor run` exit 3. Automation must also inspect `coverage`, `inherent_gaps`, `actionable_gaps` and `evaluation_complete`: exit code 0 alone does not mean complete coverage.
- Admin refusals include stable reason codes; `doctor --local` checks only local readiness and reports remote readiness as unverified.
- `config_read` and `config_diff` hashes and byte counts now describe exactly the joined pages; in 1.0.6 the response redaction could change exported lines after hashing, which broke the FortiADC export for the Auditor. The engine now applies the response redaction, preserving credential keywords and canonical numbered PSK/community markers, to the whole export before hashing, so a `set password` line arrives as `set password [REDACTED]`. SNMP community strings are additionally hidden after the legacy helper → proxy → worker chain settles, then the chain settles again; no credential hidden by 1.0.6 is revealed. A value-less `unset password` keeps the following line. The FortiADC Auditor accepts every Helper limitation name, and the export with defaults of an account that sees every area exits 0 with only the inherent factory-certificate gap. The quickstart describes the FortiADC export and metadata workflow.
- `fortios_diagnostics` applies the `count`, `timeout` and `max_bytes` bounds of each recipe (`session_list` up to 50 records) and names the refused field; `triage_slb` returns a structured `ssh_unavailable` or `timeout` result when the target is unreachable; every triage result states its `vantage`.
- Paged `ssh_read` and `schema_read` hashes, byte counts and offsets describe fully redacted output. Continuation refusals return stable tool errors; schema output is redacted structurally and successful concatenated pages remain valid JSON. Restart paged reads at offset 0 after upgrading.
- `tls_probe` reports a presented certificate that could not be verified under `unverified_certificate`; `pin_match` is reported only on the enrolled `fortios_rest_port` using the enrolled target's own name. `tls_probe` defaults to 443; for REST on 8443 pass `port=8443` explicitly. Consumers must distinguish it from a verified certificate.
- Response redaction that would alter a page withholds it as `page_changed_by_redaction`; an SSH continuation without its snapshot returns `ssh_pagination_snapshot_required` instead of an internal error. Restart at offset 0.
- Helper and the separate `locate_endpoint` worker share private per-target SSH locks: sessions serialize and FortiOS/FortiADC connection starts observe the same five-second spacing across both paths.
- `switch_read` and REST Wi-Fi tools now publish record/offset/byte limits and return bounded pages with `has_more`, `next` and full/returned counts. Capture `status: "truncated"` is independent of `has_more`: an incomplete capture can fit on one page with `has_more: false`. Oversized individual records fail as `result_too_large` with `has_more: false` and `next: null`. Existing 1.0.6 paging fields are unchanged. Record continuations read fresh data and consume the normal rate budget. `wifi_rogue.limit` is shared across rogue and interfering rows. A FortiOS route request without `ip` returns `-32602` naming `ip`; an unconfigured protocol is a valid `not_applicable` (`ok: true`, MCP `isError: false`).
- `triage_flow` preserves `restore_unverified` and `scope_refused` with `failed_step: session`, an incomplete verdict and session-filter cleanup guidance. Endpoint worker/audit failures return `ok: false` with explicit codes and audit failure stops further reads. REST Wi-Fi has distinct TLS/pin, HTTP 401/403, timeout, HTTP 5xx, invalid JSON, envelope, size, encoding and configuration error codes; the older coarse `error_subcode` remains for compatibility.
- The log result window is 200 device lines before byte paging: EXOS keeps leading newest messages; IOS/IOS XE/NX-OS/EOS/Junos/ELS keep trailing newest lines, so the IOS logging header may be absent. Metadata exposes the truncation. Endpoint location reserves `min(40, helper.rate_limit.requests, 7 + exos + vlan_reads + managed_reads * managed_switches)` reads per alias. `exos` is 1 on EXOS, otherwise 0; `vlan_reads` is 1 when the profile's port-VLAN query is enabled, plus 1 on campus profiles (IOS/IOS XE/NX-OS/EOS) or EXOS for its join. `managed_reads` is 2 (MAC/LLDP), plus 1 with FortiOS `managed_switch_port_stats`, plus 2 when both `managed_switch_port_vlans` and `interface_vlan_ids` are enabled. The worker caps actual reads per alias at that reservation, including identity and joins; exhaustion returns incomplete coverage with `target_read_limit`. The reservation permits a call to start under the default 30-request limit, but does not guarantee completion. FortiOS connection starts on one FortiGate are at least 5 seconds apart; at the observed roughly 5.6 seconds per read, about ten reads fit the 59.5-second deadline. An IP lookup with all edge queries needs at least N + 6 reads for N managed switches when only one switch needs edge details: roughly four switches can complete under these conditions. Larger sites, including twelve or thirty switches, return partial findings with incomplete coverage when the deadline or read limit is reached; startup time, latency and additional matched switches can reduce this capacity. Unused reservations are not refunded: a reservation of 30 blocks subsequent calls to that alias for the rest of its 60-second rate window, even if fewer reads run. Each alias uses its own total `rate_limit`, without the triage sublimit; if any alias lacks the reservation the whole call is refused with `rate_limit` and no alias is charged. Enabling flow lookup queries deliberately permits arbitrary validated IPv4 flow literals for that call; session reads still require the recipe and enrolled ingress interface ([scope](../docs/helper-configuration.md#optional-helper-fields)).
- ReDoS fixes bound Wi-Fi key/value whitespace, Junos LACP/route age, EOS/Junos LLDP and CLI diagnostic/pager matching and multiline refusal whitespace. Refusal classification matches `1fad86c`: device patterns search the complete output independently of `command`; existing checks in identity reads, schema snapshots and sequential reads retain these rules. The historical matrix covers 1023 texts (1012 earlier texts plus five live OSPF, four FortiGate-local and two NX-OS port VLAN captures), FortiGate-80F, FortiADC and Ruckus, all 11 profiles plus no profile, rc 0/1/250 and three command variants. Only normalized table reads protect `permission_denied`, `unsupported` and `not_applicable` when data rows parse: unknown lines give `unparsed`, otherwise `ok`; incomplete coverage carries `refusal_like_line_in_data` in `coverage.warnings` and `warnings` without line text. The exception never overrides `transport_error` or a nonzero rc that would otherwise fail, and keeps refusal states when no rows parse. Junos ELS MAC/VLAN joins retain warnings and unknown lines from both sources. Endpoint location checks read status and `refusal_like_line_in_data` before asserting an edge or `not_found_in_checked_data`; catalogue-only `coverage.complete` field gaps do not block correlation. The warning appears in `missing` even with `unparsed`. Limits, timeout and a final pager take precedence, including a pager appended to the final data line without a following newline as in `1fad86c`. The 72 raw classifier differences in the two complete Junos ELS logs (`log_messages`, `log_interactive_commands`) remain `truncated` → `ok` at rc 0, otherwise `transport_error` except successful EXOS rc 250. Raw SSH reads already removed that Junos artifact; they now also remove its standalone and blank erasure lines before the log limit, preserving all 200 messages and correct `line_limit` metadata instead of returning 198 with a false truncation warning.
- Fixes include FortiADC diagnostic dispatch, IOS XE identity, Junos route/ARP/LLDP parsing, endpoint-location deadlines and partial results, device permission reporting, and fixture anonymization. Catalogue permissions and lab measurement tables are updated.
- NetOps 1.0.7 upgrades an existing NetOps 1.0.6 installation (state included); see below.

See the [CHANGELOG](../CHANGELOG.md) for the authoritative list.

## Security

**Affected versions: NetOps up to and including 1.0.6.** The `ssh_read` and `schema_read` tools could disclose a known session or transport secret when a device printed that value and it straddled a page boundary. A client with access to those reads could reconstruct the value by joining two pages, even though each page passed response redaction independently.

NetOps 1.0.7 redacts the complete output in the engine with all known target, session and transport secrets **before hashing and pagination**. The private redaction context is absent from public tool schemas and cannot be supplied by clients. Response redaction and page-change checks remain additional safeguards.

Upgrade to 1.0.7 and restart paged reads at offset 0. If the exposure conditions occurred, rotate the affected session/transport credentials and review retained client output and audit access.

## Upgrade from 1.0.6

Follow [Upgrade from the previous release](../docs/quickstart-1.0.md#upgrade-from-the-previous-release):

1. Check the 1.0.6 instance, stop it and create its backup and state manifest.
2. Download and verify the 1.0.7 release files. Prepare a separate instance directory and a new Compose project with the same server name and port, and download the 1.0.7 image.
3. Restore the backup into an empty target volume and compare it with the source manifest before the first start. Keep the original instance and backup.
4. Start the new instance. The first start converts only the recorded product version from 1.0.6 to 1.0.7 under the instance lock and writes an `instance_start` audit record with `upgrade` from 1.0.6 to 1.0.7. A second start changes nothing. CA, keys, token, role data and connection details are unchanged.

No manual inventory or credential changes are required. Enrolling the read-only Wi-Fi REST API token in the NetOps vault and trusting the device certificate, `lookup_prefixes`, `device_types` (endpoint-location readers) and additional `enabled_queries` are optional additions for new functionality. Keyboard-interactive fallback and connection spacing apply automatically.

Do not run `init` on the restored state. State of any other product version is refused: upgrade only from 1.0.6; a 1.0.5 installation must first be upgraded to 1.0.6.

For rollback, stop 1.0.7, preserve its audit records written after the backup, and start the unchanged 1.0.6 instance; see [Rollback](../docs/quickstart-1.0.md#rollback). A direct downgrade of a converted volume is not supported.

## Known limitations

- Support is bounded by enrolled scope, device permissions and measured query coverage. Unsupported commands and partial parsing remain explicit; Junos log access requires permission to the specific file beyond the built-in `read-only` class. See the vendor notes and read-only account guide.
- Wrong-password keyboard-interactive fallback may consume two device authentication attempts; OTP/MFA is unsupported.
- Base-image vulnerabilities and their applicability must be assessed from the candidate's per-architecture scan and signed assessments. The 1.0.6 scan is historical evidence, not a new 1.0.7 scan.

## Acceptance

The acceptance of 1.0.7 consists of these checks:

- Repository unit and release tests, installed-image tests including state-version/previous-release/start regressions, acceptance tooling tests and candidate acceptance suites on amd64 and arm64.
- Engine regression image and component suites for the changed engines, including redaction, paging, transport, inventory and normalized tables.
- `release/acceptance/upgrade-check.sh` from 1.0.6 to 1.0.7 with nonempty Helper, Auditor and Admin data and rollback to the unchanged 1.0.6 instance. Whole tool definitions and role responses are compared by JSON pointer against `release/acceptance/api-changes-1.0.6-1.0.7.json`; undeclared or stale changes fail the check. Auditor `coverage` is an intentional response addition; elapsed age is normalized.
- Installation and upgrade/rollback by following the README and quickstart, independent review, and release signing with checksum, registry and vulnerability checks on the candidate.

The results are acceptance reports (`acceptance-*.json`) covered by the signed checksum list. The maintainer signs only a release whose required reports pass; a candidate without that signature is not a release. These notes describe the required checks and do not assert that publication acceptance has already passed.

## Verify this release

```sh
cosign verify-blob --bundle netops-1.0.7-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.7-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.7-SHA256SUMS
```
