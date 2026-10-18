# NetOps

NetOps 1.0 is one Docker-only product combining network diagnostics, configuration audits and bounded reversible changes. It exposes one token-protected HTTPS Streamable HTTP MCP endpoint. Device output is untrusted data; every supported HTTPS MCP request and response passes through a mandatory durable audit boundary. Offline Admin operator workflows use a private operation log after a mandatory gateway-audit preflight.

Start with the [NetOps 1.0 quickstart](docs/quickstart-1.0.md). Supported runtime hosts use Linux Docker Engine on Ubuntu, Debian, Fedora Server with SELinux enforcing or Raspberry Pi OS 64. The image supports linux/amd64 and linux/arm64; Raspberry Pi OS is arm64. macOS and Windows can host Linux guests or run MCP clients. Docker Desktop is not a supported NetOps runtime.

The container contains Core, Helper, Auditor and Admin, not AI agents. Role processes have separate UID and credential directories. Admin is enabled by default; no device is enrolled implicitly. Users explicitly configure device scope and credentials before device operations. Existing safeguards and measured firmware/schema contracts remain in force.

Use the image digest and configuration files from one personally signed release manifest. Download verification, installation, first MCP use, audit, restart and every supported upgrade are release gates. A successful source import or selftest is only its stated evidence scope. The [architecture](docs/architecture-1.0.md) describes isolation, redaction, durable ordering and the limits of syslog protection.

Version 1.0 does not migrate 0.x data or modify 0.x volumes. Previously published component releases remain available and unchanged. The new product is not published to PyPI by default.

A release is the user's personally signed checksum list together with the assets it covers. A candidate branch, digest, build or CI run without that signature is not a release.

NetOps is an open-source project by Radek Černý, distributed under the MIT license. Claude Code and Codex assist implementation and independent review; compatible MCP clients remain vendor-neutral.
