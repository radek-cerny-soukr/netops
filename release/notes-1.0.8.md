NetOps 1.0.8 follows NetOps 1.0.7. It adds CDP neighbours and Linux tables to `switch_read`, makes `locate_endpoint` read Linux neighbour and bridge tables, fixes FortiOS route and VLAN parsing, hardens the Auditor store and the two HTTP response readers, makes the Admin Doctor read the journal once per request, and documents the minimum requirements and the platforms on which the installation procedure was run. The product remains one container with Helper, Auditor and Admin behind one audited HTTPS MCP endpoint. The syslog audit format and receiver requirements are unchanged.

## Changes in 1.0.8

- `switch_read(table="cdp_neighbor")` returns the CDP neighbours of Cisco IOS, IOS XE and NX-OS from the opt-in `cdp_neighbors` query: local port, full Device ID, neighbour port, management IP, platform and CDP capabilities as text (not LLDP letters). Unrecognized lines and incomplete blocks lower `coverage`; a target without the enabled query is refused before any transport.
- Linux gains `switch_read` tables from its existing catalogue queries: `interface`, `ip_interface`, `route` (IPv4), `neighbor_l3` and `mac_entry` (`bridge_fdb`). A fresh `uname -a` verifies Linux before every read. MTU, MAC and state of one interface need the opt-in `interface_link` query with the interface enrolled, then `switch_read(table="interface", interface=...)`. The Linux `addresses` command and description stay unchanged from 1.0.7 (`ip -brief address`): IP and prefix come from this brief output; enabled `links` adds MAC and administrative state and enabled `routes` adds the IPv4 default gateway in the same `switch_read`. Unsupported route lines are reported by `route` and do not discard a recognized default gateway from `ip_interface`. Linux has no VLAN or LLDP table. Unknown lines lower `coverage`.
- For Linux targets, fresh `ssh_read` calls also verify identity with `uname -a` before the requested query (one extra SSH connection, except for the `kernel` query, whose `uname -a` is the probe itself). An invalid Linux identity is refused with `product_identity`; responses include `normalized` and `status`. The identity probe is not charged separately to the per-target rate limit: a fresh `ssh_read` costs one slot; cached continuation pages cost none.
- New optional fields: `interface.mac`, `interface.mtu`, `ip_interface.mac` and `ip_interface.gateway` (the IPv4 default gateway via the same interface on Linux when `routes` is enabled). They are null on platforms that do not supply them and do not lower `coverage` there. Declared in `release/acceptance/api-changes-1.0.7-1.0.8.json`.
- `locate_endpoint` reads the Linux `neighbors` query (IPv4 and IPv6) on `router` and `firewall` targets and `bridge_fdb` on `switch` targets. A neighbour proves no edge: when a Linux host has the endpoint as a neighbour but no matching bridge port, the result stays `incomplete` (`bridge_port_not_observed`; without any switch reader `no_enrolled_switch_reader`) unless another enrolled switch locates the endpoint, and missing LLDP evidence leaves a port `unverified`.
- FortiOS routes with recursive next hops (BGP) and summary or Null routes are parsed, the route code legends of FortiOS 7.6 and 8.0 are accepted, and `set` lines directly inside a nested configuration node of the interface configuration (such as `config ipv6`) no longer make VLAN entries unparsed.
- A FortiGate Wi-Fi client in tunnel mode (the SSID default) is expected not to be learned on the switches between its access point and controller because its traffic is carried in CAPWAP to the FortiGate. This is consistent with the lab result (`not_found_in_checked_data`), but the SSID mode and cause were not confirmed. Locally bridged SSIDs were not tested. Use `wifi_clients` with the client MAC or `wifi_triage` to find the access point and radio, then locate the access point.
- `compose.yaml` takes the CPU limit from `NETOPS_CPUS` (default 2). Docker refuses `cpus: 2` on a host with one CPU; set `NETOPS_CPUS=1` there. See [Minimum requirements](../README.md#minimum-requirements).
- Wi-Fi REST (Helper) and the FortiOS REST collector (Auditor) reject a chunk-size line that is not plain hexadecimal (`+61`, `6_1`, `0x61`, blanks, `-0`) before any body is processed. The Python 3.14.10 standard-library parser still accepts these spellings (CVE-2026-103995), so NetOps checks the line itself; valid chunks, chunk extensions and the byte budget behave as before. Chunk-size lines must end with CRLF; bare LF and whitespace before `;` (for example `61 ;ext`) are refused. Regression tests cover both readers.
- The Auditor store validates the type of every expected schema object (table, index) when it is opened, migrated or read read-only. A view or other object in place of an expected table is refused with a message naming the object; the schema NetOps creates is unchanged. A store missing an expected table or index is refused by the read-only server with a message naming the object; open it writable (`auditor run` or `auditor status`) to restore it.
- The local part of Admin `doctor` (also run by `doctor --local`) validates and parses each journal record once per request instead of three times. Order, rejection of a corrupted journal and the fresh evaluation of the time budgets are unchanged, nothing is kept between requests, and `apply` still reads the journal itself.
- Response redaction spans now follow `sort_keys` ordering and tuples. A direct serialization test of these shapes left a marked synthetic value unmasked on the 1.0.7 code; no shipped tool response path producing these shapes was identified in the review. Regression tests also pin the value-less `unset password` exception and the audit class of a failed `switch_read`.
- Wi-Fi triage documentation states what a failed or empty last signal sample leaves in `chain`, `missing` and the verdict, how the 15-read REST reservation behaves, and when an old client error is only a historical notice.
- Release tooling: a fixable High or Critical scan finding passes the release gate and the daily rescan only with a dated assessment that records that the fixed version is not yet released, with a source link. Version metadata, the 1.0.7 → 1.0.8 upgrade pin and the build lock (`setuptools` 84.2.1, build time only) are updated; the base image and all runtime packages are those of 1.0.7. CI runs the four-role engine regression and keeps the full logs. The classifier replay baseline now holds 1029 captured texts.

## What was checked on devices and lab images

These results come from development builds before the release candidate; device reads used read-only accounts, while Admin used its separately enrolled accounts. They do not qualify a later rebuilt image.

- **CDP:** the output of `show cdp neighbors detail` of Cisco IOS (two images), IOS XE and NX-OS lab images returned the correct local and remote port, neighbour name and management IP in `cdp_neighbor` (4, 4, 3 and 3 neighbours), compared with the CLI.
- **Linux:** five tables (`interface`, `ip_interface`, `route`, `neighbor_l3`, `mac_entry`) of an Ubuntu 24.04.5 host (kernel 6.8.0-147-generic, iproute2 6.1.0), with 3, 6, 4, 17 and 13 rows, matched independent CLI reads, and six further checks of the per-address default gateway also passed. That build read `ip_interface` from `ip address show`; the released `ip -brief address` form is covered by the CLI captures of 2026-11-13 below. A neighbour's NUD state can change between reads, so IP, MAC and interface were compared. The forwarding database of that host held only static entries; in the tests a bridge port from a synthetic dynamic FDB row is returned as `unverified` with the result `incomplete`, never as a located edge.
- **Linux capture replay follow-up (2026-11-13):** read-only CLI output from Ubuntu 24.04.5 (kernel 6.8.0-147-generic), a clean Debian 13.7 cloud VM (6.12.111+deb13-cloud-amd64) and Proxmox VE on Debian 13.7 (7.0.14-28-pve) supplies 23 captures and 168 independent manual records. The three `linux_*_batch_b.json` scenarios are replayed through the real proxy request/response paths and engine, with MAC/prefix/gateway joins on each host (26 tests). Proxmox bridge and bridge-port metadata are captured; VLAN metadata has unit-test coverage only because no VLAN was present, and bond metadata is not recognized and lowers `coverage`. The clean Debian VM had no `bridge` executable, so its FDB capture expects rc 127 / `transport_error`. This is replay of fresh CLI output, not a new live MCP qualification.
- **FortiOS routes and VLANs:** the live reads of a FortiGate 80F (FortiOS 8.0.2) and a FortiGate 60F (FortiOS 7.6.8) first showed the unparsed route and VLAN shapes that this release fixes. The fix is checked by replaying the stored CLI captures (32 and 13 routes, 7 and 9 VLANs, no unparsed line); the 80F VLAN capture is a reconstruction from the independent `get system interface` output, not a raw `show system interface`. These replays are not a new live run.
- **Wi-Fi:** on a FortiGate with two access points, `wifi_clients`, `wifi_aps_live`, `wifi_rogue` and `wifi_triage` matched the independent REST and CLI reads. The client's own MAC was in neither of two switch forwarding databases, which is consistent with the tunnel-mode behaviour above; the SSID mode itself was not recorded. The failed-sample variants of the Wi-Fi triage documentation are covered by tests, not by a live run.
- **Admin Doctor:** `doctor --local` and full `doctor` passed on runtime 1.0.8 configured for a FortiGate 60F in the G3/G4 live round; the local command checks local state without contacting the device.
- **HTTP reader coverage:** the G2 Wi-Fi round exercised the Helper REST reader containing the chunk-size validation check, on dev-1.0.8 against a FortiGate with two access points. Successful ordinary REST reads are documented; the evidence does not record whether the responses were chunked. Rejection of malformed chunk-size lines is covered by tests, not a live-device test.
- **Not run live for 1.0.8:** `NETOPS_CPUS=1` on a host with one physical CPU. The one-vCPU VM measurement used `cpus: 1`; the environment variable was checked on a larger host.

## Supported platforms

The runs used the 1.0.7 quickstart text and released image on the platforms below, and were not performed by an independent tester. The virtual-machine runs followed those commands except that `cat .env` was replaced by `grep`. On the physical ARM single-board computer, Docker was already installed; Compose and cosign were placed in a private directory, with an isolated instance directory and Compose project. Its restart check was Compose `down`/`up`, not a host reboot. All final checks passed; the physical Pi initially had a transient healthcheck failure and became healthy within about a minute. See [Supported platforms](../README.md#supported-platforms).

| Platform | Docker | Note |
|---|---|---|
| Ubuntu 26.04.1 LTS, amd64 | Engine, rootful | includes host restart |
| Ubuntu 24.04.5 LTS, amd64 | Engine, rootful and rootless | rootless without host restart |
| Debian 13, amd64 | Engine, rootless | includes host restart (linger) |
| Raspberry Pi OS Lite 64-bit, arm64 | Engine, rootful | Raspberry Pi OS userland in a virtual machine with a Debian kernel |
| Raspberry Pi OS 64-bit on physical arm64 hardware (single-board computer) | Docker 29.8.0, Compose plugin | real hardware, vendor kernel 6.12.115, 4 KiB pages, loopback port; Compose down/up only |

Not verified: kernels with 16 KiB pages, 32-bit Raspberry Pi OS, and the Docker installation steps on physical hardware (the hardware already had Docker; the installation steps were run in the virtual machine). The hardware run used an isolated test instance and a separate Compose project.

## Minimum requirements

`linux/amd64` or `linux/arm64`; Docker Engine with the Compose plugin; 1 vCPU (set `NETOPS_CPUS=1` on a host with one CPU), 2 GiB RAM and 2 GiB free disk. The 2 GiB RAM and 2 GiB disk figures were set with headroom above measured usage (peak about 350 MiB RAM, Docker image disk usage about 240 MB); 1 vCPU has no headroom: it is the configuration on which the VM measurement, with a Compose copy set to `cpus: 1`, started and passed. The measurement basis, network ports and limits are in [Minimum requirements](../README.md#minimum-requirements).

## Security

No secret-disclosure issue in a shipped tool response was found for 1.0.8. The first two security-related changes (the chunk-size check and the store type check) close a response-framing gap and a store-validation gap in NetOps itself; they do not change what a client can ask for or what a device may be asked to do.

### Known dependency findings

The 1.0.8 image still carries findings in components taken from its base image whose owners have not released a fix that NetOps can build on. We did not wait for them: every fix available for the base image was applied, and the findings below remain because the fixed versions are not released for the base image (Python 3.14.11 was not yet released when checked on 2026-11-12). A written assessment is not a repair and not a claim of zero CVEs.

| Component | CVE | Status |
|---|---|---|
| Python 3.14.10 | CVE-2026-103995 (HTTP client accepts `+61`, `6_1` as chunk sizes) | Flaw remains in the interpreter; no fixed 3.14 release was available when checked on 2026-11-12. NetOps no longer reaches it: Helper and Auditor reject such chunk sizes (see above); the Admin notification sender does not read response bodies. |
| Python 3.14.10 | CVE-2025-15367 (`poplib`) | No fixed 3.14 release was available when checked on 2026-11-12; NetOps does not use `poplib`. |
| Python 3.14.10 | CVE-2026-116566 (NUL in `getaddrinfo`) | Fixed in the unreleased 3.14.11. Host names come only from the operator's own configuration. |
| Python 3.14.10 | CVE-2026-119170 (`hashlib`, OpenSSL in FIPS mode only) | Fixed in the unreleased 3.14.11. NetOps does not configure FIPS mode. |
| SQLite 3.53.4 (`sqlite-libs`) | CVE-2026-119371 to CVE-2026-119379, CVE-2026-119591 | Fixed upstream in 3.54.0, not in Alpine 3.24. Reachable at most through a crafted Auditor store file placed in the instance's private state or backups, which already requires control of that state; no client or device can supply SQL or a database. The store type check above refuses a view in place of an expected table. |
| SQLite 3.53.4 (`sqlite-libs`) | CVE-2026-119586 (`.recover` of the `sqlite3` shell) | **No released upstream fix**, including 3.54.1. NetOps links the library only and never runs the shell. |
| BusyBox 1.37.0 | CVE-2025-60876 (`wget`) | Not fixed in Alpine 3.24. NetOps never runs `wget`. |

Impact per the assessments shipped with the release (`netops-1.0.8-vulnerability-assessments.json`): the HTTP framing finding concerns responses from an enrolled device whose certificate or pinned fingerprint was verified before the token is sent and whose body is bounded (Helper 2 MiB and 10 s; Auditor byte budget). A deployment that treats the enrolled HTTPS peer as untrusted is not covered by the assessments.

## Upgrade from 1.0.7

Follow [Upgrade from the previous release](../docs/quickstart-1.0.md#upgrade-from-the-previous-release):

1. Check the 1.0.7 instance, stop it and create its backup and state manifest.
2. Download and verify the 1.0.8 release files. Prepare a separate instance directory and a new Compose project with the same server name and port, and download the 1.0.8 image.
3. Restore the backup into an empty target volume and compare it with the source manifest before the first start. Keep the original instance and backup.
4. Start the new instance. The first start converts only the recorded product version from 1.0.7 to 1.0.8 under the instance lock and writes an `instance_start` audit record with `upgrade` from 1.0.7 to 1.0.8. A second start skips conversion. CA, keys, token, role data and connection details are unchanged.

No inventory or credential change is needed. To read the new tables, enable `cdp_neighbors` on Cisco targets or the Linux queries named above on Linux targets; both are optional. Do not run `init` on the restored state. Only 1.0.7 is accepted as the previous release; upgrade 1.0.6 to 1.0.7 first.

For rollback, stop 1.0.8, preserve its audit records written after the backup, and start the unchanged 1.0.7 instance; see [Rollback](../docs/quickstart-1.0.md#rollback). A direct downgrade of a converted volume is not supported.

## Known limitations

- The limits of 1.0.7 apply: enrolled scope, device permissions and measured coverage; keyboard-interactive fallback can use two authentication attempts; no OTP/MFA.
- The dependency findings listed above remain until their owners release fixes.
- Linux tables have CLI captures from Ubuntu 24.04.5, Debian 13.7 cloud and Proxmox VE on Debian 13.7; distributions beyond these were not measured. The Debian cloud capture has no FDB coverage because `bridge` is unavailable. Linux has no VLAN or LLDP table, IPv6 routes, multipath and blackhole routes are not normalized, and a bridge port found by `locate_endpoint` stays `unverified`, never a located edge. Unsupported route lines remain visible in `route` and do not discard a recognized default gateway from `ip_interface`.
- FortiSwitch port state is measured on FortiSwitch 224E-POE only; ExtremeXOS X435/X440 are measured on lab captures with a read-only account.
- The RAM and disk minimums include headroom above measurements on a virtual machine and a single-host Docker run; these measurements are not a throughput or long-run load test.

## Acceptance

The acceptance of 1.0.8 consists of: repository, release-tooling and acceptance-tooling tests, installed-image tests and the engine regression of the four roles on amd64 and arm64; Actions candidate checks; installation by following the quickstart on the platforms above; `release/acceptance/upgrade-check.sh` from 1.0.7 to 1.0.8 against `release/acceptance/api-changes-1.0.7-1.0.8.json` (the `table` argument of `switch_read`; the query catalogue is unchanged); the MCP client checks; a short check of the three roles including Admin apply and undo on the final digest; independent code review and release signing with checksum, registry and vulnerability checks. The results are acceptance reports (`acceptance-*.json`) covered by the signed checksum list. These notes describe the required checks and do not assert that publication acceptance has passed.

## Verify this release

```sh
cosign verify-blob --bundle netops-1.0.8-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.8-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.8-SHA256SUMS
```
