NetOps 1.0.4 follows NetOps 1.0.3. It adds conservative FortiOS configuration captures and comparisons, bounded diagnostics without a schema registry, a paginated query catalogue and the first FortiADC Helper read. The product remains one container with Helper, Auditor and Admin behind one audited HTTPS MCP endpoint. The syslog audit format and receiver requirements are unchanged.

## Changes in 1.0.4

- Helper adds `config_read` and `config_diff` for explicitly enrolled FortiOS configuration sections. Captures verify the live identity and single-root VDOM context, redact configuration values incrementally and keep bounded snapshots and comparisons in process memory. Completed captures and comparisons can be paged without rereading the device. Opaque comparisons can report changes to hidden values without returning those values. See [configuration captures](https://github.com/radek-cerny-soukr/netops/blob/v1.0.4/docs/helper-configuration.md#optional-configuration-captures).
- Configuration streaming handles the initial FortiOS exec prompt and the matching final prompt; unexpected framing is refused. The proxy allows the bounded configuration operation to finish within its existing tool deadline.
- The existing `fortios_diagnostics` tool runs enrolled ping, traceroute, sniffer, session and flow recipes without a schema registry. It verifies an exact measured hardware/version/build identity, a single root VDOM and interface ownership before starting. Explicit VDOM selection and multi-VDOM remain refused. Recipes retain their limits, timer interruption and verified cleanup. FortiGate-VM64 with FortiOS 8.0.2 build 0251 is an explicit identity; this does not enable other 8.0.x models or builds.
- `read_query_catalog` adds platform and query-prefix filters, offset/limit pagination and a page-data byte bound. Follow `next_offset` to read all results and restart if `catalog_sha256` changes. A default call returns a page rather than the complete catalogue.
- FortiADC is a separate Helper platform. `ssh_read` verifies the live product before returning catalogue output; the first qualified function is `system_status` on FortiADC-KVM 7.6.7 build 0676. This does not qualify FortiADC Auditor collection or Admin writes.
- The Helper exposes 15 tools, including the two configuration tools; the complete product exposes 28 tools with Admin enabled and 22 with Admin disabled.
- Admin profiles refuse FortiOS 8.0.2 build 0251 before installing a safeguard or applying a change. Its device-side configuration rollback is not qualified. See [verified support](https://github.com/radek-cerny-soukr/netops/blob/v1.0.4/docs/verified-support.md).

## Upgrade from 1.0.3

Follow [the upgrade procedure](https://github.com/radek-cerny-soukr/netops/blob/v1.0.4/docs/quickstart-1.0.md#upgrade-from-the-previous-release):

1. Check the 1.0.3 instance, stop it and create its backup and state manifest.
2. Download and verify the 1.0.4 release files. Prepare a separate instance directory and a new Compose project with the same server name and port.
3. Restore the backup into an empty target volume and compare it with the source manifest before the first start. Keep the original instance and backup.
4. Start the new instance. The first start converts only the recorded product version from 1.0.3 to 1.0.4 under the instance lock. Verify the version, health, existing role data, CA, token and audit with the original clients.

Do not run `init` on the restored state. The syslog receiver and its part archive stay unchanged. State of any other product version or state schema is refused: upgrade 1.0.2 to 1.0.3 first with the [1.0.3 procedure](https://github.com/radek-cerny-soukr/netops/blob/v1.0.4/release/notes-1.0.3.md#upgrade-from-102), and follow the earlier release procedures in order for older instances. There is no skipped-release upgrade or downgrade.

For rollback, stop 1.0.4, preserve its audit records written after the backup as described in [Rollback](https://github.com/radek-cerny-soukr/netops/blob/v1.0.4/docs/quickstart-1.0.md#rollback), and start the unchanged 1.0.3 instance. Changing the new instance's image back to the old digest does not restore its state.

## Documentation and release process

The quickstart makes failed Compose checks and partial audit exports explicit, limits the upgrade audit tail to five records and keeps the backup and restore variable blocks distinct. Step 6 of the quickstart starts in `~/netops`, so it also works in a new shell, and the upgrade check describes the audit tail by the history of the instance. Test tooling bounds signing-test subprocesses, validates worker mode and retains unittest outcomes. The process-profile acceptance check accepts a health check that the container runtime has started but not yet handed to the container shim only with full proof of that runtime parent and only for 200 ms, proves the parent of a short-lived runtime helper before the helper's own record disappears, and names the reason when it fails. The source gate refuses a README that describes another release and workflows that name another candidate branch, and CI no longer repeats the checks that the release candidate workflow runs on candidate branches. These changes do not alter device permissions.

## Acceptance

NetOps 1.0.4 adds Helper functions and is accepted in proportion to its change: CI suites and engine tests of the candidate image in GitHub Actions on amd64 and arm64, a blind installation by the README and the quickstart on Fedora Server 44 and Debian 13 on amd64, a blind upgrade from 1.0.3 to 1.0.4 on amd64, read-only checks of the new Helper functions on FortiGate-60F with FortiOS 7.6.8 build 3744, FortiGate-VM64 with FortiOS 8.0.2 build 0251 and FortiADC-KVM 7.6.7 build 0676, and an independent code review. Ubuntu, Raspberry Pi OS, arm64 hosts and rootless Docker were not installed by a blind run for 1.0.4. The acceptance reports covered by the signed checksum list record the results.

## Known limitations

- Configuration captures require explicit scope, pinned SSH identity and a device account with CLI get/show permission. Diagnostics additionally require diagnose/execute permission; inventory opt-in does not grant device privileges. CLI configuration can remain disabled.
- Configuration values are withheld conservatively. Captures and comparison handles are bounded and do not survive a process restart. The fixed limits in [Helper configuration](https://github.com/radek-cerny-soukr/netops/blob/v1.0.4/docs/helper-configuration.md) apply; this release adds no policy override for them.
- Bounded diagnostics accept only the explicit identities in the implementation and require a single root VDOM. Reaching the time limit with no packet output is not proof of forwarding or destination reachability.
- FortiADC qualification covers the documented Helper `system_status` read. Auditor support and live Admin pool-member changes are not qualified.
- FortiOS 8.0.2 build 0251 Admin changes are refused. Measurements of another model, build or release do not establish support.
- An interrupted converting first start can leave converted state without an audit record naming the upgrade; the [quickstart](https://github.com/radek-cerny-soukr/netops/blob/v1.0.4/docs/quickstart-1.0.md#refused-first-start) explains recovery and the remaining evidence.
- Existing process isolation, audit persistence and syslog retry limitations remain as described in [security](https://github.com/radek-cerny-soukr/netops/blob/v1.0.4/SECURITY.md). Device output remains sensitive after credential redaction.

## Install

Follow [the quickstart](https://github.com/radek-cerny-soukr/netops/blob/v1.0.4/docs/quickstart-1.0.md). Download and verify the signed release files, configure the bind address, port and server name, then initialize and start a new instance. An upgrade uses the restore procedure above.

## Verify this release

```sh
cosign verify-blob --bundle netops-1.0.4-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.4-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.4-SHA256SUMS
```

The checksum list covers `compose.yaml`, `env.example`, the release manifest, which records the image index and per-architecture digests, the acceptance manifest, the per-architecture SBOMs, vulnerability scans and scan gate results, the vulnerability assessments and the acceptance reports (`acceptance-*.json`); the checksum list itself is the complete list of covered files. `env.example` already pins the image by that index digest. A download is verified only after both commands succeed.
