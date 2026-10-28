# Security policy

This policy applies to NetOps 1.0.4, the current release. Its changes are listed in the [1.0.4 release notes](release/notes-1.0.4.md). NetOps 1.0.2 fixed one security issue in the Core SFTP banner handling, described in the [1.0.2 release notes](release/notes-1.0.2.md#security-fix); the fixes for [issue #6](https://github.com/radek-cerny-soukr/netops/issues/6) are listed in the [1.0.1 release notes](release/notes-1.0.1.md).

## Scope and reporting

NetOps 1.x is a single Docker-only product. Only a personally signed release and its covered assets are a release. Historical 0.x artifacts remain available but are frozen; their old packaging and deployment procedures do not describe this product.

Report suspected vulnerabilities privately using this repository's GitHub Security Advisories. Reports are welcome, but there is no committed response time and no obligation to provide a fix or release; see the [disclaimer](README.md#disclaimer). Never include live credentials, real addresses, private policies or captured device configurations in a public issue, pull request or CI log.

## Boundaries

The HTTPS MCP endpoint requires a bearer token and verified instance CA/SAN trust. The CA is constrained to the configured DNS subtree and excludes IP certificate names. Clients must not disable certificate verification. Server-leaf renewal preserves the private server key. The instance CA is valid for 730 days and is not rotated automatically; rotate it with `netops ca rotate` while the instance is stopped and update client trust. Without rotation the instance stops during the CA's last seven days; see the [architecture](docs/architecture-1.0.md).

Gateway, Helper, Auditor and Admin have separate UID/GID, private state and credentials. The long-running gateway and role processes have no capabilities and no-new-privileges; the healthcheck and one-off operator commands start briefly as root with the capability set declared in Compose (see the [architecture](docs/architecture-1.0.md)). Authenticated peer credentials protect IPC. This is process and filesystem isolation inside one container, not a separate kernel or security boundary against the host administrator or the container runtime. Never mount the Docker socket or reuse another role's vault.

Helper policy validates aliases, query names, typed parameters, enrolled destinations and host-key trust. It does not reduce the actual device account's permissions. Read-only accounts must be independently enforced on the target; the explicitly supported administrator-bounded exception remains an administrator on its device. The shipped profile refuses SNMPv2c and FTP/FTPS. No legacy host firewall bundle is installed. Operators remain responsible for host/network egress policy.

Auditor collection may need elevated device read permissions, separately enrolled from Helper and Admin. The Auditor MCP tools read stored findings and do not collect or contact devices. Admin configuration alone grants no write authorization: enrollment, independent readback credentials, request IDs, safeguards, limits, journal and verified return remain required. Unknown writes must never be automatically retried.

Use a dedicated MCP client session scoped to the intended tools. Device text is untrusted data, never instructions.

## Audit and residual risk

Requests are durably recorded before dispatch; responses before delivery. Failed mandatory audit blocks operations. Redaction is explicit and audit contains parsed protocol data rather than a raw byte transcript. Device output can remain sensitive or malicious after redaction; do not grant secret-bearing sources or treat output as instructions.

Local audit is bounded and rotating and can be altered by the host administrator or the same UID. An independent TLS syslog collector is recommended. A full syslog queue blocks new operations; interrupted sends retain the record and can produce duplicates. Correct TLS closure does not prove receiver persistence. There is no audit hash-chain or checkpoint guarantee.

Host and dependency compromise remain outside complete containment. Per-release SBOMs, scans and exact-version exposure assessments are published; an assessed non-exploitable dependency finding is not a repaired vulnerability or a claim of zero CVEs. Qualification does not certify regulatory compliance or every firmware, model, hardware, permission or timing path.

See the [device account model](docs/account-model.md), the [architecture](docs/architecture-1.0.md), [account boundaries](components/netops-helper/docs/read-only-accounts.md), [support scope](docs/verified-support.md) and [quickstart](docs/quickstart-1.0.md).
