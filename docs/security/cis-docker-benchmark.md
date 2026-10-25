# CIS Docker Benchmark map

NetOps maps the [CIS Docker Benchmark v1.6.0](https://www.cisecurity.org/benchmark/docker) to its container image and to the Compose deployment it ships. This is a self-assessment with evidence, not a certification.

Evidence sources:

- `docker-bench-security` v1.6.1 (commit `ba0b402ea56aafbb9a56f09cc13ee629160c58b6`, implements CIS Docker Benchmark v1.6.0), run by `release/acceptance/cis_bench.sh` against a NetOps instance started with the shipped `compose.yaml` on Debian 13 amd64 with Docker Engine 29.9.1 from the official Docker repository. The script runs it twice: once without filters (`cis-all`) and once limited to the image and runtime checks of the NetOps container (`-c container_images,container_runtime -i netops`, `cis-netops`). The filtered run is the evidence for sections 4 and 5.
- The release acceptance suites in `release/acceptance/` (`redteam.py`, `blackbox.py`, `failclosed.py`), run in GitHub Actions on both architectures for every candidate.

Sections 1 to 3 cover the host and the Docker daemon. They are the operator's responsibility and outside the image; the relevant recommendations are listed at the end. Sections 4 and 5 are mapped item by item.

## Section 4 — container images and build file

| Item | Result | Evidence or justification |
|---|---|---|
| 4.1 User for the container | PASS (justified) | The image and Compose start the container as UID 0 (`USER 0:0`, `user: "0:0"`). A short bootstrap prepares state permissions with a minimal capability set, then runs the gateway and the Helper, Auditor and Admin roles as UID/GID 51000–51003 with all capability sets empty and `NoNewPrivs` set (`redteam.py` `process-profile`). No long-running process runs as root; the healthcheck and one-off operator commands start as root (see 5.4). |
| 4.2 Trusted base images | PASS (manual) | Official `python:3.14.9-alpine3.24` image pinned by digest in the `Dockerfile`. |
| 4.3 Unnecessary packages | PASS (manual) | Alpine base plus `openssh-client` only; `pip` is removed from the final image. The image also carries the `tests/v1` unit tests in `/opt/netops/tests` (`Dockerfile`), which the candidate workflow runs inside the image with `python -m unittest`. The SBOM lists every OS and Python package. |
| 4.4 Scanned and rebuilt | PASS (manual) | Every candidate is scanned on both architectures (Grype, `release/scan_gate.py`); a fixable High/Critical finding blocks the release, and every other finding, of any severity, needs a written non-exploitability assessment for its exact package version, shipped as `netops-X.Y.Z-vulnerability-assessments.json`. The digests of the latest release are rescanned daily against its assessments. |
| 4.5 Docker Content Trust | N/A | Docker Content Trust (Notary v1) is not used. Releases are pinned by image digest and the release manifest binding those digests is signed with Sigstore by the maintainer; the documented verification step checks that signature. |
| 4.6 HEALTHCHECK in the image | PASS | `HEALTHCHECK` runs `netops health` (strict TLS to the gateway, readiness of every role and of the audit storage) and Compose declares the same check; `docker compose up --wait` reports the service healthy. |
| 4.7 Update instructions alone | PASS | `apk upgrade` and `apk add` run in the same layer. |
| 4.8 setuid and setgid removed | PASS | The candidate workflow checks on both architectures the image filesystem (except `/proc`, `/sys`, `/dev`) as root for any regular file with a setuid or setgid bit (`redteam.py` `no-setuid-files`); a found or unreadable path fails the check. |
| 4.9 COPY instead of ADD | PASS | The `Dockerfile` uses `COPY` only. |
| 4.10 Secrets in the build file | PASS (manual) | No secret is used at build time; image history contains no token, password or key material. Instance secrets are created by `init` in the data volume. |
| 4.11 Verified packages | PASS (manual) | Alpine packages are signed by the distribution; Python packages are installed with `pip --require-hashes --only-binary=:all:` from one locked dependency set. |
| 4.12 Signed artifacts validated | release condition | A release is published only after the maintainer has signed its checksum list with Sigstore; the installation guide verifies that signature and every file hash before use. |

## Section 5 — container runtime

| Item | Result | Evidence or justification |
|---|---|---|
| 5.1 Swarm mode | PASS | Not used. |
| 5.2 AppArmor profile | PASS | Docker's default profile applies on supported hosts with Docker as root where AppArmor is enabled. For rootless Docker the default profile applies only where the host allows rootless AppArmor; no further confinement is claimed. |
| 5.3 SELinux options | PASS | On SELinux hosts the container runs as `container_t` with per-container MCS categories when the Docker daemon has SELinux support enabled (`"selinux-enabled": true`; Docker Engine from the official repository leaves it off by default). Named-volume data can carry the shared label `container_file_t:s0`; process MCS categories do not establish private-volume isolation. An account authorized to control the owning Docker daemon can mount the state in another container, consistent with the trusted-runtime boundary in [SECURITY.md](../../SECURITY.md). |
| 5.4 Capabilities restricted | PASS | `cap_drop: [ALL]`; the bootstrap keeps only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID`, `SETPCAP` and drops them before serving; the long-running gateway and role processes have empty capability sets. The healthcheck and one-off `docker compose run` operator commands start as root with this set: the healthcheck, `configure`, `ca rotate`, `audit recover` and the `admin`/`auditor` commands drop it; `init`, `ca` export, `token`, `connection` and the reading `audit` commands keep it until they exit. |
| 5.5 Privileged containers | PASS | Not privileged. |
| 5.6 Sensitive host directories | PASS | Only a named data volume is mounted. |
| 5.7 sshd in containers | PASS | No SSH server; `openssh-client` is used for device access. |
| 5.8 Privileged ports | PASS | The container listens on 8443. |
| 5.9 Only needed ports | PASS (justified) | Exactly one published port, the HTTPS MCP endpoint, bound to the address the operator sets in `NETOPS_BIND_IP`. The benchmark tool reports every open port for manual review. |
| 5.10 Host network namespace | PASS | Not shared. |
| 5.11 Memory limit | PASS | `mem_limit: 1g`. |
| 5.12 CPU limit | PASS | `cpus: 2`. |
| 5.13 Read-only root filesystem | PASS | `read_only: true` with declared `tmpfs` mounts. |
| 5.14 Bound to a host interface | PASS | Compose refuses to start without `NETOPS_BIND_IP`; there is no implicit `0.0.0.0` binding. |
| 5.15 Restart policy `on-failure:5` | N/A (justified) | `restart: unless-stopped` so that the endpoint returns after a host reboot; an `on-failure` policy would leave it stopped. Configuration errors are rejected by `init` before the service starts. |
| 5.16–5.18 PID, IPC namespaces, host devices | PASS | Not shared; no devices. |
| 5.19 ulimits | INFO | Docker defaults; process count is limited by `pids_limit`. |
| 5.20 Mount propagation | PASS | Not shared. |
| 5.21 UTS namespace | PASS | Not shared. |
| 5.22 seccomp | PASS | Docker's default profile. |
| 5.23–5.24 `docker exec` options | N/A | Operational guidance for administrators; NetOps operator commands use `docker compose run` with the image's own entry point. |
| 5.25 cgroup usage | PASS | Default cgroup parent. |
| 5.26 Additional privileges | PASS | `no-new-privileges:true`. |
| 5.27 Health checked at runtime | PASS | Compose health check (see 4.6). |
| 5.28 Latest image | N/A | Releases are pinned by digest on purpose. |
| 5.29 PIDs cgroup limit | PASS | `pids_limit: 128`. |
| 5.30 Default bridge | PASS | Compose creates a project network. |
| 5.31 Host user namespace | PASS | Not shared. |
| 5.32 Docker socket | PASS | Never mounted. |

## Sections 1–3 — host and daemon (operator)

The image cannot enforce these. Operators should follow their platform's hardening; items with a direct effect on NetOps: keep the host patched (1.1.x), audit the Docker daemon and its files (1.1.3–1.1.18), restrict inter-container traffic on the default bridge (2.2), enable user namespace remapping where supported (2.9), forward Docker logs centrally (2.13; NetOps' own audit should go to a TLS syslog receiver), set `no-new-privileges` as a daemon default (2.14), enable live restore (2.15) and disable the userland proxy (2.16). On Fedora and other SELinux hosts enable `"selinux-enabled": true` in `/etc/docker/daemon.json`.
