# Verified platform support

Compatibility is scoped to the exact platform, firmware build, model, account policy and operation documented by each component. Catalogue presence does not qualify every deployment. Software-image or synthetic results do not establish hardware forwarding, sensor or every timing path. Each target must satisfy its component's enrollment requirements.

## Host operating system

NetOps deployment hosts run Linux. Windows and macOS are not supported deployment targets. POSIX process, filesystem and permission interfaces are required; see the [Core release requirements](../components/netops-core/docs/releasing.md). Distribution, architecture and optional dependency requirements belong to each component's installation instructions.

## FortiOS bounds

Documented FortiOS contracts distinguish 7.6.7 build3704 and 8.0.0 build0167. FortiGate 60F, FortiGate 80F and FortiGate-VM64-KVM model scopes remain separate; software-image coverage does not establish physical forwarding or every firmware variant. Preserve the exact schema's model/build, reference semantics, conditionals, nested configuration, protected objects and restart requirements.

Helper reads use their documented catalogue and account policy. Auditor SSH and REST collection require the [collector channel](../components/netops-auditor/docs/channels.md) permissions. Admin supports enrolled address, address-group, DHCP-reservation and explicitly bounded schema operations only. Safeguard installation, readback, prediction and return proof remain mandatory.

## EXOS bounds

ExtremeXOS contracts distinguish 33.7.1.6, 33.7.1.6-patch1-11 and the 33.6.1.14 virtual-image scope. Generic hardware model identifiers include Extreme X435-8P-4S, X440-G2-12p and X440-G2-12p-10G4; a model contract does not imply support for every firmware or device in the family. Virtual-image behavior does not establish physical forwarding, sensor or save behavior.

Helper catalogues keep their platform-specific diagnostic exclusions. Auditor full configuration collection requires administrator privilege. Admin supports only enrolled VLAN, port display-string and port-membership profiles. Safeguard confirmation requires its own identity and a complete count-and-row listing. A count without rows never proves absence.

The account fingerprint covers explicit create/configure configuration rows; implicit accounts and changes outside those rows are outside that fingerprint. It is not a complete account or privilege inventory.

## Other platforms

Helper catalogues distinguish Arista EOS 4.36.1F, Cisco NX-OS 9.3(12), IOS-XE 17.18.2, IOS 15.9(3)M12 and IOS 15.2(20200924), and Junos 26.2R1.7 scope. Arista EOS container images (cEOS), virtual EOS images, Cisco virtual images and virtual Junos images do not establish corresponding physical hardware support. A CLI answer with a nonzero transport status differs from a device CLI error; neither extends compatibility to another build or command.

Linux read and diagnostic paths retain their documented distribution, architecture and permission requirements. Ruckus Unleashed retains the explicit administrator-bounded role and catalogue boundary; the catalogue does not reduce the device credential's privileges. A read catalogue or native timer on another platform does not imply Admin execution support there.

## Clock and state boundaries

FortiOS and ExtremeXOS safeguards can follow device-clock changes. Admin requires verified removal or return evidence tied to its own safeguard. Incomplete listings or missing proof do not establish success; unverified return leaves the operation unknown and the device blocked. A forward clock jump before a FortiOS safeguard is loaded can leave an unreturned change as revert-failed.

Host-side elapsed budgets use monotonic time within one boot; across reboot, trusted elapsed time is not guaranteed. Shared admission locks and the journal preserve request identity, but separate journal/index files do not imply filesystem atomicity between those files.

## Operator responsibility

Verify the exact model, full firmware build, credential permissions, egress, catalogue scope, safeguard behavior and result interpretation before use. Unsupported or unspecified paths remain unsupported or unspecified. Full configuration collectors may need administrator credentials; fixed collector commands and the pinned device identity define that channel's read boundary. Keep collector credentials separate from Helper accounts and from the Auditor MCP surface.

Local-file auditing needs no device credential or connection, while workflow setup and result upload may use the network. Compatibility does not certify complete corpus recall, all hardware variants, every account grant or production exploitability. [Compatibility boundaries](compatibility-boundaries.md) describe the evidence classes and limits.
