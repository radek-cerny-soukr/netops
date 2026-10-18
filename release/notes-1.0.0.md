NetOps 1.0.0 is one product: a single container image that runs the Helper, Auditor and Admin roles behind one audited HTTPS MCP endpoint. Earlier releases shipped four separately installed components; their releases and PyPI packages stay available unchanged, but 1.0 does not upgrade or migrate 0.x installations or data.

## What you get

- One multi-architecture image for `linux/amd64` and `linux/arm64`, pinned by digest in the release `env.example`.
- One MCP endpoint over Streamable HTTP, always HTTPS, protected by a bearer token. The instance creates its own certificate authority with name constraints and renews its short-lived server certificate automatically.
- Every request and response is written to the audit before it is executed or delivered. If the audit cannot be written, the operation is refused (`audit_unavailable`) and an unknown Admin write is never retried automatically. The audit can go to a TLS syslog receiver (recommended) or to a local, size-limited log.
- The roles run as separate processes under their own user IDs with no Linux capabilities, on a read-only root filesystem, with CPU, memory and process limits. A short start-up bootstrap uses the few capabilities listed in `compose.yaml` to prepare protected state and then drops all of them.
- Refused, failed or uncertain operations are MCP errors (`isError`) with their full result content.
- The instance CA is valid for 730 days and is rotated explicitly with `netops ca rotate`; an interrupted local audit write is recovered with `netops audit recover`. Both run while the instance is stopped and are recorded in the audit.

## Requirements

Linux with Docker Engine and the Compose plugin: Ubuntu, Debian, Fedora Server or Raspberry Pi OS 64-bit, natively or in a Linux virtual machine. Docker Desktop is not supported as the runtime. MCP clients connect over the network from any system.

- The server name in `.env` must be a DNS name that clients resolve; IP addresses are refused because common MCP clients do not accept IP names under a constrained CA. A local DNS entry or a hosts-file entry on each client is enough.
- On Fedora and other SELinux hosts, enable SELinux support in the Docker daemon (`"selinux-enabled": true`); the quickstart shows how to verify it.

## Known limitations

- Authenticated requests with bodies above 64 KiB or uncertain body framing are processed one at a time across roles, so they can queue behind another large request. Other authenticated requests can use the remaining slots within the shared limit of 16.
- 1.0 starts from a clean installation; it does not upgrade or migrate 0.x installations or data.
- Docker Engine in rootless mode is not part of the qualified platform matrix.
- The roles are isolated as processes and files inside one container, not against the host administrator or the container runtime.
- An incomplete local audit write blocks further operations until `netops audit recover` runs while the instance is stopped. A full syslog queue blocks new operations, and an interrupted send can deliver records to the receiver more than once.
- The opt-in FortiOS `managed_switch_stacking` and `managed_switch_poe` queries have no positive result on stacking- or PoE-capable hardware. Virtual device images do not establish physical hardware behavior.
- The process-profile acceptance check uses a nominal 50 ms sampling interval and can miss processes that start and exit between observations. A previously unknown process that exits after its first observation but before its second may be attributed to a Docker exec runtime helper, up to four such cases per sample. This requires its recorded identity and parent PID, an older pinned `runc exec` parent tied to the same container (the shim's cgroup, UID 0, host PID namespace and reference-matching executable bytes), confirmation that the parent was alive after the child's first observation, and fresh confirmation that the child is absent. This proof is weaker: the child is not observed alive a second time, and its own executable and PID namespace need not have been observed. Missing required evidence, any recorded contradiction or a fifth such case fails the check.

Details: [verified support](https://github.com/radek-cerny-soukr/netops/blob/v1.0.0/docs/verified-support.md) and [security](https://github.com/radek-cerny-soukr/netops/blob/v1.0.0/SECURITY.md).

## Install

Follow [the quickstart](https://github.com/radek-cerny-soukr/netops/blob/v1.0.0/docs/quickstart-1.0.md). In short: download `compose.yaml`, `env.example`, `netops-1.0.0-manifest.json`, `netops-1.0.0-SHA256SUMS` and `netops-1.0.0-SHA256SUMS.sigstore.json` from this release, verify them, set the bind address, port and server name, then run `init` and start the service.

Device enrollment is an explicit operator step described in [Helper configuration](https://github.com/radek-cerny-soukr/netops/blob/v1.0.0/docs/helper-configuration.md). An inventory written for 0.x needs the 1.0 Helper section and the English device roles `perimeter`, `internal` and `lab`.

## Verify this release

```sh
cosign verify-blob --bundle netops-1.0.0-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.0-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.0-SHA256SUMS
```

The checksum list covers the release manifest, which records the image index and per-architecture digests, the SBOMs, the vulnerability scans and their assessments, and the acceptance reports of every tested platform. `env.example` already pins the image by that index digest. A download is verified only after both commands succeed.

## Security

Every release candidate is built once in GitHub Actions and the same digests are tested, accepted and published without a rebuild. Each architecture is scanned; a fixable High or Critical finding blocks the release and every other finding, of any severity, ships with a written assessment (`netops-1.0.0-vulnerability-assessments.json`). SBOMs cover the application, its Python dependencies and the operating-system packages. The container maps to the CIS Docker Benchmark v1.6.0 as described in [docs/security/cis-docker-benchmark.md](https://github.com/radek-cerny-soukr/netops/blob/v1.0.0/docs/security/cis-docker-benchmark.md).
