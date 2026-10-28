# Fortinet FortiADC CLI references

## Review baseline and limits

- Vendor: Fortinet.
- Product and document title: FortiADC 7.6.7 CLI Reference.
- Reviewed version: FortiADC 7.6.7.
- Verification date: 2026-10-27.
- Catalog module: `src/netops_helper/query_catalog/fortiadc.py`.
- Contract of this first slice: `docs/fortiadc-f1-contract.md` in the repository.

The exact machine-checked templates and per-query source links are in the [generated query catalog](../query-catalog.md); the source-ID records are in [`query-sources.json`](../query-sources.json).

These references establish the vendor-documented command syntax and its purpose. They are not proof that a particular appliance, firmware build, administrator profile or virtual image permits the command. The vendor page shows an example output taken from FortiADC 7.4.1; the synthetic fixtures of the tests make no claim about complete status formatting. A sanitized measured status through the actual transport is still outstanding.

The returned data is sensitive operational evidence. The status output can expose the serial number, hostname, HA mode and firmware and signature database versions. It remains untrusted device output even when the command is read-only.

## Accepted Phase-1 queries

The table is the conservative first-slice whitelist. The profile has exactly one query, it takes no parameter, and no caller value reaches the command line. `normal` is not a bounded-output promise.

| Query name | Exact command template | Inventory slot | Volume | Primary references |
| --- | --- | --- | --- | --- |
| `system_status` | `get system status` | none | normal | F-ADC-CLI-76, F-ADC-GET-SYSTEM-STATUS-76 |

Primary sources: [FortiADC 7.6.7 CLI Reference](https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference) and its page [get system status](https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/379949/get-system-status).

The page documents the syntax `get system status` and an example whose `Version:` line reads `FortiADC-VM v7.4.1,build0310,231030 (GA.F)`. The hardware field starting `FortiADC-` is what the platform identity check in `netops_core.platforms.require_identity` relies on.

## FortiRAG provenance

The cited pages were compared with the copies kept in FortiRAG, the maintainers' local corpus of Fortinet documents. The corpus is not part of this repository; the paths below are relative to its document root.

- Product: FortiADC.
- Exact version: 7.6.7. The corpus holds no FortiADC 7.6.0 document, and the registry no longer cites 7.6.0.
- Compared on: 2026-10-27, against the vendor pages online on the same day.
- The vector index of FortiRAG was not verified; the comparison used the stored files and their SHA-256 digests only.

| Source ID | Vendor URL | FortiRAG copy | SHA-256 |
| --- | --- | --- | --- |
| F-ADC-CLI-76 | https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference | fortinet-docs/FortiADC/7.6/cli-reference.pdf (manifest version 7.6.7) | ea7ac3cda6140e5e98cb6a8750b4ffc2c162e351211e4e5a2b9798c421c6f7a8 |
| F-ADC-GET-SYSTEM-STATUS-76 | https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/379949/get-system-status | fortinet-docs/FortiADC/7.6.7/web-20261019/11-fortiadc-7.6.7-cli-reference-379949-get-system-status.html (fetched 2026-10-19) | 311be651a39bcfc5db2ade9b3ca269ab1c4eb0dafa6d76faed1b61aef240fae9 |
| F-ADC-GET-SYSTEM-STATUS-76 | https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/379949/get-system-status | fortinet-docs/FortiADC/7.6.7/web-20261019/11-fortiadc-7.6.7-cli-reference-379949-get-system-status.txt (text of the same page) | 0573f62380b5945754ce8dcbcb3b80da333dde5451ce59a988dbf8ef023d4142 |

Both the stored copy and the live page of 2026-10-27 document the syntax `get system status` and the same example `Version:` line; neither contains a text about refused commands.

## Excluded families

- Every `config` command and every `execute` command: the profile is read-only.
- Configuration display and backup (`show`, `show full-configuration`, backup and export): the configuration boundary of Phase 1 holds for this platform too.
- Debug, diagnose and packet-capture families, log and support-bundle retrieval, shells and file display.
- Arbitrary CLI: raw command text is never accepted as a query name.

## Deferred findings

- A wider FortiADC catalogue (interfaces, HA, routing, virtual servers, real servers, health checks, statistics) stays out until each command has measured output on a laboratory FortiADC and a reviewed contract.
- A read-only administrator profile and its AAA behaviour on FortiADC: not verified.
- FortiADC versions other than 7.6.7 (other maintenance releases and other major versions): not compared; the registry cites none of them.

## Limitations

- Identity is established from the hardware field of one `Version:` record: `FortiADC-` selects this profile and other products are refused before the query is sent. `ssh_read` implements this gate as described in the section `Transport wiring of ssh_read` of the F1 contract; its source tests use synthetic responses and still need a matching and a mismatched response from a laboratory device through the real transport.
- CLI refusal texts of FortiADC are not documented in the CLI Reference and not measured, so `engine._CLI_REFUSALS` has no `fortiadc` entry (contract section `CLI refusal classification of fortiadc`). A refused identity command carries no `Version:` record and is reported as `product_identity`. The measurement to run on a laboratory FortiADC is listed in that section.
- No FortiADC appliance or virtual machine has been queried through the Helper yet; the profile has no live-wire evidence.
- The SSH transport is the exec channel. A laboratory FortiADC VM (`FortiADC-KVM v7.6.7`) was measured in the F0c run of 2026-10-26 (run report not part of the repository) with a separate tool: the exec form without a terminal (`-T`) is accepted with exit status 0 and the answer is framed like an interactive shell. The first line begins `<hostname> # ` followed by `Version: ...`, and the output ends with the line `<hostname> # ` without a newline. The Helper removes both prompts in `netops_core.prompt` (contract section F1-WIRE-PROMPT) before it checks the identity. This is one observation on one VM and firmware; the source tests use a synthetic host name and no captured bytes, and the Helper itself has not run against a FortiADC.
- Cost and permissions: `system_status` is the identity probe and takes one SSH connection. The account needs the right to run `get system status`; whether a restricted FortiADC administrator profile has it is not verified.
