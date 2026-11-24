# Compatibility boundaries

NetOps 1.0.13 applies nine compatibility boundaries.

## Catalogue and parser coverage

1. **Catalogue scope.** Each entry defines a bounded operation. Enrollment controls which targets, commands and parameters are available.
2. **Parser and schema inputs.** Fixtures establish the specific input shapes they exercise. Exact schema bindings retain their model and firmware requirements.

## Synthetic and software-image coverage

3. **Synthetic evidence.** A fake transport or a synthetic fixture exercises the case it was built for. Replay uses an earlier device capture.
4. **Software images.** A virtual image can establish protocol and configuration behavior. Physical forwarding, ASICs, PoE, optics and convergence require their own measurements.

## Read and change boundaries

5. **Account privilege.** Device permissions control visibility and writes. An administrator-bounded collector or role still has the privilege of its enrolled device account.
6. **Change proof.** Admin checks the approved plan, takes a lock and journals the operation. Configuration changes require prediction, readback and proof of return where applicable. Scoped operational clears are irreversible.

## Deployment verification

7. **Timing and recovery.** Safeguard timers follow the device's semantics. Host monotonic time bounds elapsed time within one boot. Incomplete evidence leaves the outcome unverified.
8. **Deployment verification.** Qualify the model, operation, credential permissions, egress scope and safeguard in the environment where they will be used. Unsupported or unspecified paths remain unsupported or unspecified.

## Firmware support warnings

9. **Untested versions.** Helper and Admin operations that report `firmware_support` can continue on an identified device with status `untested`. Permissions, safety checks and technical refusals still apply. If the required identity cannot be read, the operation can still be refused. FortiADC Auditor reports an informational finding for an untested FortiADC identity, while missing metadata or another product prevents evaluation of the other rules. See [verified support](verified-support.md#live-verification-of-netops-1012).

## Approved limitations of 1.0.5

These historical measurements use the NetOps 1.0.5 rule catalogue and release path.

- **ExtremeXOS `$(` in an inverse command (Admin).** ExtremeXOS X440-G2 33.7.1.6-patch1-11 rewrites `$(x)` to `$x` when the UPM safeguard runs, with or without a backslash, so escaping does not stop it. Admin therefore refuses on ExtremeXOS every plan whose inverse command contains `$(` before the first write. Measured on that X440-G2 build: `$5`, `$x`, `${x}` and parentheses were restored literally, direct CLI writes keep `$(` literally.
- **FortiOS administrator rules under a read-only collector (Auditor).** On FortiOS a read-only account sees only itself in `system admin`. `fortios.mgmt.default-admin-account` and `fortios.mgmt.admin-no-trusthost` therefore stay `not-evaluated` with `admin-visibility-unproven` and `auditor run` ends with exit code 3; the complete evaluation needs a collector account with the `super_admin` profile (see [Account model](account-model.md)). Measured by `tests/test_rule_sections.py` (`test_an_admin_list_without_a_super_admin_is_not_evaluated`, `test_a_run_over_a_read_only_view_is_incomplete`), which run the rules on a snapshot without a `super_admin` administrator.
- **FortiADC Auditor coverage.** On the measured FortiADC-KVM 7.6.7 build0676, `show` evaluated 2 of 8 rules and left `visibility:access-profile-unverified` actionable gaps, so exits 3. The measured `full` export evaluated 6 of 8: `fortiadc.tls.factory-certificate` stays `factory-provenance-unproven`, an inherent gap that no export can close, and `fortiadc.mgmt.plaintext-admin-access` has `visibility:networking`, which follows from the access profile of the collector account. Every visibility gap is actionable, so on the measured device `auditor run` exits 3 until the collector has the `read` right for `networking` (and for the other areas); with a complete read-only profile only the factory certificate remains and the run exits 0 (covered by `tests/v1/test_fortiadc_profile_coverage.py`, which uses the helper fixture with `read` on all areas and a synthetic snapshot). Both reports retain `evaluation_complete: false` and list gaps in `coverage`, so zero findings does not establish complete coverage. Other required gaps, including identity and export visibility, exit 3. The original rule statuses were measured on 1 November 2026; exit behavior follows their classification. On 9 November 2026 the export with defaults of the same device read by a system administrator (`is-system-admin yes`, enrolled as `admin-bounded`) evaluated 7 of 8 rules: the only gap was the inherent `factory-provenance-unproven` and `auditor run` exited 0 in JSON, SARIF and text; the `show` export of that account exited 3 with `default-undocumented` gaps. The joined pages of both exports had exactly the declared size and SHA-256 (220,487 and 16,576 bytes).
- **Upgrade audit record.** (a) After an interrupted converting start the record carries the time of the completing start, not of the conversion. (b) A stop between writing the record and removing `gateway/upgrade-pending.json` can produce a duplicate record with `"resumed": true`. (c) With syslog audit the record exists only at the receiver, not in `audit export`. Case (a) is covered by `test_interrupted_converting_start_is_recorded_by_next_start` (`tests/v1/test_upgrade_previous_release.py`: the converting start is killed before its record, the next start writes it with `"resumed": true`). Case (b) follows from the documented order of operations (record first, removal of the file after it) and is not covered by a test. Case (c) follows from `audit export` holding only records not yet delivered. Details in the [quickstart](quickstart-1.0.md).

## Known limitations

- 1.0 starts from a clean installation; it does not upgrade or migrate 0.x installations or data.
- NetOps runs as one instance in one container (`compose.yaml` defines the single service `netops`). There is no high-availability or clustering mode and no state shared between instances, and there is no graphical user interface: access is through MCP clients and the operator commands.
- On FortiOS the Auditor collects with a `super_admin` administrator, which can also write; restrict it with `trusthost`. A read-only profile hides other accounts' entries without saying so. See [account model](account-model.md#auditor).
- Each role reads its device credentials only from its own private vault, a single JSON document (see [Core vault](../components/netops-core/docs/vault.md)); the same device login can be enrolled in several roles, and NetOps does not compare them ([account model](account-model.md)).
- The roles are isolated as processes and files inside one container, not against the host administrator or the container runtime.
- Authenticated requests with bodies above 64 KiB or uncertain body framing are processed one at a time across roles, so they can queue behind another large request; other authenticated requests share the remaining slots within the limit of 16.
- The request body has a 60-second receipt deadline. Since 1.0.3 the gateway has a separate 60-second deadline for the whole buffered, audited MCP response send sequence, not for each chunk. This does not bound execution time or prove that the client application read the response. During body delivery a receive watcher also detects ASGI disconnect events. An observed disconnect, timeout, cancellation, receive-channel or send-channel failure attempts an interruption record when the audit is writable, and the operation slot is released. A small buffered send or a close after the monitored phase may go unobserved; inspect `audit pending` before repeating an operation. See the [1.0.3 response-delivery notes](../release/notes-1.0.3.md#response-delivery).
- An incomplete local audit write blocks further operations until `netops audit recover` runs while the instance is stopped. A full syslog queue blocks new operations, and an interrupted send can deliver records to the receiver more than once.
- Syslog records remain bounded at 8 MiB and use numbered 1024-byte parts with a persistent record ID and whole SHA256. Messages are at most 1618 bytes including their header. Configure a dedicated receiver archive filtered by RFC5424 APP-NAME `netops`, preserving exact MSG+LF, before the first start. Offline `audit reassemble --record-id` freezes the first complete SHA-valid set in archive order: later conflicts or invalid rows preserve its bytes and produce typed warnings/exit 3; earlier validation or input-read errors give exit 2 without record output. Keep older 1.0 full-record archives separately. Native default-limit storage checks verified rsyslog 8.2504 and 8.2512 with gtls and ossl and syslog-ng 4.12 on arm64 and amd64, each receiver running in a container.
- There is no supported provisioning path for the schema registry/library files of Helper `schema_read`, the extra input files of Auditor `--suppressions`, `merge-sarif` and `schema-check`, or file-based Admin offline and schema workflows.
- `ftp_list` is refused before any device contact, and no configuration enables it. Its engine checks the requested path against the target's `sftp_roots` only lexically, as a canonical absolute path equal to a root or below it; unlike `sftp_stat`, it does not let the server resolve the path, so a symbolic link below a root that leads out of it would not be refused.
- FortiExtender modem queries, Catalyst 9800, SRX diagnostics and the physical PoE or DOM cases identified in the support matrix have automated coverage only. FortiGate optics are not part of 1.0.13. The matrix lists the measured hardware and software-image scope.
- The process-profile acceptance check samples at a nominal 50 ms interval and can miss short-lived processes; see the [1.0.1 release notes](../release/notes-1.0.1.md) for the exact attribution rule.

## Disclaimer

NetOps is open-source software provided **"as is", without warranty of any kind**, as stated in the [MIT license](../LICENSE). You use it entirely **at your own risk**. The author currently has no plans to offer a commercial NetOps product or paid support. The MIT license permits commercial use, forks and redistribution.

- **No liability.** The [MIT license](../LICENSE) disclaims liability for the software's authors or copyright holders for claims, damages or other liability arising from the software or its use, including changes that the Admin role makes to network devices.
- **No obligation to support or fix.** There is no service-level agreement and no commitment to provide support, answer questions, fix defects or security issues, publish updates or keep the project maintained. Any fix or release is voluntary and may never happen.
- **Your responsibility.** Before any production use, you are responsible for evaluating NetOps in your environment, verifying device accounts and permissions, keeping configuration backups, testing changes, and following your organization's policies and applicable law.
- **Not a vendor product.** NetOps is not a product of Fortinet, Extreme Networks, Cisco, Arista, Juniper, Ruckus or any other vendor whose devices or software it supports, nor of the vendors of the MCP clients and models named in this documentation. These vendors bear no responsibility for defects or errors in NetOps or for its effects on their devices, and they provide no support for it. Product and company names are trademarks of their respective owners and are used only to describe compatibility.
- **No certification.** Published tests, qualification results and supported-platform lists describe their documented scope and observations. They are not a guarantee, certification or fitness-for-purpose statement for your deployment.
- **Forks and redistributions.** Anyone may fork or redistribute NetOps under the MIT license, including commercially. Such versions are not provided, endorsed or supported by the author, and they create no obligation on the author's part toward their users.
