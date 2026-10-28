# Verified platform support

Qualification uses local Docker state volumes; network-backed state storage, including NFS, is not qualified.

Compatibility is scoped to the exact platform, firmware build, model, account policy and operation documented by each component. Catalogue presence does not qualify every deployment. Software-image or synthetic results do not establish hardware forwarding, sensor or every timing path. Each target must satisfy its component's enrollment requirements.

## Host operating system

NetOps deployment hosts run Linux with Docker Engine and Compose. Supported host families are Ubuntu, Debian and Fedora Server on amd64 and arm64, and Raspberry Pi OS 64-bit on arm64. Fedora requires Docker SELinux support with the host enforcing. Docker Engine runs as root or in rootless mode. macOS and Windows are supported only as MCP client hosts (Claude Code, Codex); they are not supported or tested as NetOps servers. The [single-product quickstart](quickstart-1.0.md) is the only installation path. Engines are not separately installed. Support is bounded by the exact current release qualification; no platform inherits PASS from an older candidate.

## FortiOS bounds

Documented FortiOS contracts distinguish 7.6.7 build3704 and 8.0.0 build0167. FortiGate 60F, FortiGate 80F and FortiGate-VM64-KVM model scopes remain separate; software-image coverage does not establish physical forwarding or every firmware variant. Preserve the exact schema's model/build, reference semantics, conditionals, nested configuration, protected objects and restart requirements.

Helper reads use their documented catalogue and account policy. The opt-in FortiOS `managed_switch_stacking` and `managed_switch_poe` queries have no positive result: the tested switch is neither stacking- nor PoE-capable, so behavior on such hardware is unverified (see the [FortiOS reference](../components/netops-helper/docs/vendor-cli-references/fortinet-fortios.md)). Auditor SSH and REST collection require the [collector channel](../components/netops-auditor/docs/channels.md) permissions. Admin supports enrolled address, address-group, DHCP-reservation and explicitly bounded schema operations only; in NetOps 1.0 schema operations have no supported way to receive their binding files (see [Admin MCP tools](admin-configuration.md#mcp-tools)). Safeguard installation, readback, prediction and return proof remain mandatory.

Baseline measurements on 2026-10-27 ran NetOps 1.0.3, not this release, and do not qualify 1.0.4. On FortiGate 60F with FortiOS 7.6.8 build3744, measured paths passed: Helper catalogue reads, Auditor collection, baseline and MCP calls, and Admin address create/update/delete, address-group membership update and DHCP-reservation create/update/delete, with enrollment and operator undo. Device and account restrictions remain explicit refusals. On FortiGate-VM64 with FortiOS 8.0.2 build0251, measured Helper reads and Auditor collection, baseline and MCP calls passed. The current Admin profiles do not enable 8.0.2 build0251: address, address-group and DHCP-reservation apply paths reject that firmware during profile validation, before installing a safeguard or applying a device change. Device-side rollback is not qualified for this firmware: on FortiOS 8.0.2 build0251 a `config system auto-script` entry whose script contains a configuration command was refused with `Script contain unavailable command(s)`, while a script with only a `get` command was accepted (measured on 2026-10-27 on FortiGate-VM64 and on a physical FortiGate 80F HA pair), so the on-box safeguard that Admin installs cannot restore configuration on that build.

## EXOS bounds

ExtremeXOS contracts distinguish 33.7.1.6, 33.7.1.6-patch1-11 and the 33.6.1.14 virtual-image scope. Generic hardware model identifiers include Extreme X435-8P-4S, X440-G2-12p and X440-G2-12p-10G4; a model contract does not imply support for every firmware or device in the family. Virtual-image behavior does not establish physical forwarding, sensor or save behavior.

Helper catalogues keep their platform-specific diagnostic exclusions. Auditor full configuration collection requires administrator privilege. Admin supports only enrolled VLAN, port display-string and port-membership profiles. Safeguard confirmation requires its own identity and a complete count-and-row listing. A count without rows never proves absence.

The account fingerprint covers explicit create/configure configuration rows; implicit accounts and changes outside those rows are outside that fingerprint. It is not a complete account or privilege inventory.

## FortiADC bounds

FortiADC-KVM 7.6.7 build0676 (virtual image, standalone) is the only FortiADC scope. The Helper exposes one query, `system_status` (`get system status`); before returning it, the Helper confirms that the live device identifies itself as FortiADC and removes the CLI prompt that frames the exec answer. Verified on 2026-10-27 against FortiADC-KVM v7.6.7 build0676 with a read-only account: the positive read returns rc 0 with the prompt removed; a query outside the catalogue, another platform name, a wrong host key pin and an unknown alias are refused; a FortiADC enrolled as FortiOS is refused before any query output is returned. The Auditor has no FortiADC support. The Admin `pool-member` operation is not qualified on a live device.

## Other platforms

Helper catalogues distinguish Arista EOS 4.36.1F, Cisco NX-OS 9.3(12), IOS-XE 17.18.2, IOS 15.9(3)M12 and IOS 15.2(20200924), and Junos 26.2R1.7 scope. Arista EOS container images (cEOS), virtual EOS images, Cisco virtual images and virtual Junos images do not establish corresponding physical hardware support. A CLI answer with a nonzero transport status differs from a device CLI error; neither extends compatibility to another build or command.

Linux read and diagnostic paths retain their documented distribution, architecture and permission requirements. Ruckus Unleashed retains the explicit administrator-bounded role and catalogue boundary; the catalogue does not reduce the device credential's privileges. A read catalogue or native timer on another platform does not imply Admin execution support there.

## Clock and state boundaries

FortiOS and ExtremeXOS safeguards can follow device-clock changes. Admin requires verified removal or return evidence tied to its own safeguard. Incomplete listings or missing proof do not establish success; unverified return leaves the operation unknown and the device blocked. FortiOS gives Admin no device proof that its stitch ran: when the state after the fire time and grace differs from the state before the change, Admin keeps a still installed stitch and reports unknown with the device blocked; only when the stitch is no longer installed does the operation end as revert-failed. A person removes a kept stitch after checking the device; a new change is refused while it is installed. A forward clock jump before a FortiOS safeguard is loaded can therefore leave an unreturned change as unknown, with a stitch that may never run.

Host-side elapsed budgets use monotonic time within one boot; across reboot, trusted elapsed time is not guaranteed. Shared admission locks and the journal preserve request identity, but separate journal/index files do not imply filesystem atomicity between those files.

## Operator responsibility

Verify the exact model, full firmware build, credential permissions, egress, catalogue scope, safeguard behavior and result interpretation before use. Unsupported or unspecified paths remain unsupported or unspecified. Full configuration collectors may need administrator credentials; fixed collector commands and the pinned device identity define that channel's read boundary. Keep collector credentials separate from Helper accounts and from the Auditor MCP surface.

Local-file auditing needs no device credential or connection, while workflow setup and result upload may use the network. Compatibility does not certify complete corpus recall, all hardware variants, every account grant or production exploitability. [Compatibility boundaries](compatibility-boundaries.md) describe the evidence classes and limits.
