# Shared identity and normalization (1.0.8)

Every fresh SSH catalogue read on EXOS, IOS, IOS XE, NX-OS, EOS and Junos first
runs the existing `version` template (`show version`, with the fixed `| no-more`
suffix on Junos). No terminal setting changes or JSON fallback are introduced.
Only the operating system is verified: its signature and version must parse. IOS and
IOS XE are distinct. Model, serial number and uptime are read as data; the hardware
model never decides whether a device may be read, so there are no model-family
tables. A model that cannot be read stays null with a warning.

The OS profiles (`cisco_ios`, `cisco_xe`, `cisco_nxos`, `arista_eos`,
`juniper_junos`, `juniper_junos_els`, `extreme_exos`, `linux`) apply equally to a
switch, router or firewall; Junos has common and ELS catalogues. EOS is EOS and Junos is Junos on any box. The device
type is a per-target inventory attribute instead: `helper.device_types`, a unique list
drawn from `switch`, `router`, `firewall` (default empty). A catalogue template may
carry a `group` naming one of these types; it can then be listed in `enabled_queries`
only for a target that declares that type, and the inventory is rejected otherwise.
Templates without a group suit every device type; no catalogue template has a group
in this release. The attribute enables template groups
and is never checked against the model. A command a particular box does not know
returns `unsupported` or `permission_denied`, according to the platform response;
this does not reject the target.
The `*_router` profile names of the earlier draft were never released: use the OS
profile and `"device_types": ["router"]` instead (no migration of stored inventories
is needed, because the router names were not accepted by any release).
Each enabled query remains explicitly selected per inventory target.

`switch_read(table="port_vlan")` records `port` (canonical interface name),
`mode` (`access`, `trunk`, `routed`, `unknown`), `access_vlan` (integer or null),
`native_vlan` (integer or null), `tagged_vlans` (sorted unique integer list or
null when not supplied), and `oper_status` (`up`, `down`, or null).
Access and routed ports have an empty tagged list. A trunk's native VLAN is
the untagged VLAN actually carried: an IOS/EOS/NX-OS native default excluded
from allowed VLANs is null. Tagged membership uses the allowed list rather than
only active or STP-forwarding VLANs, excludes the carried native VLAN, and does
not promise that traffic is forwarding. Junos logical units stay distinct; the
ELS Tagging column and numeric TAG supply membership, and DN marks a down port.
EXOS Tag/Untag sections are joined across VLANs, including wrapped port lists;
a port with tagged members is trunk, its untagged member is native, otherwise
it is access. The EXOS active flag establishes up; absence of that flag alone
does not establish physical down (the enabled `ports` read supplies that).
Access/native nulls are legitimate for the other modes. Missing membership or
link state keeps coverage incomplete. No configured routed VLAN turns an EXOS
physical switch port into a routed port.

The normalized tables of `switch_read` and the readers of `locate_endpoint` follow
the same model ([tools.md](tools.md#normalized-tables-switch_read)): the parser is
chosen by the OS profile, a table the catalogue or the box does not provide is
`unsupported`, and a template group needs the declared device type. `locate_endpoint`
takes ARP/ND (for an IP only) from `router`/`firewall` targets and MAC tables from `switch` targets
(a layer-3 switch declares both). A target that is no reader (no declared type, or no
enabled query for it) makes the proxy refuse the call with `policy_scope`; the same
target handed directly to the worker is not read and is reported as
`device_type_not_declared`.

A refusal stops before the requested query and preserves `error_code:
product_identity` with a stable `reason`: `identity_os_mismatch`,
`identity_ambiguous` (conflicting software version), `identity_unparsed`, or
`identity_<result status>`. No rejected device output is returned.
FortiOS/FortiADC retain their existing product check.

A `version` response includes `normalized.identity`: `hostname`, `model`,
`serial_number`, `os_version`, `uptime` (reported text). Missing fields are null;
no uptime or serial is guessed. A conflicting descriptive field becomes null with a
`identity_<field>_ambiguous` warning. On Junos, a virtual chassis or dual-RE reply
(`fpc0:`/`re0:` blocks) is read from the first member block. NX-OS `model` is the SKU
only (`C9336C-FX2`, `Nexus5548`). Fixed implicit identity supplements use the same
catalogue and run only when the query is in the target's `enabled_queries`: EXOS
`switch`, EOS `hostname`, Junos `hardware` and `uptime`. A supplement that is not
enabled is skipped with the warning `identity_source_<query>_not_enabled` and the
field stays a coverage gap. A failed supplement (denied, unsupported, timeout, ...)
is recorded in `sources[].status` and `warnings`; it never replaces the state of the
successful `version` read (`ok`, or `unparsed` while fields are missing). The
read-only role must permit the enabled supplements. This is parser coverage, not a
live qualification claim.

Identity `coverage` (`complete`, `parsed_fields`, `missing_fields`) is meaningful only
for `version`; other queries return it empty and `complete: false` until a parser exists.

`normalized` has `schema_version: 1`, `profile`, UTC `captured_at`, `status`,
`identity`, `sources[]` (`query`, SHA-256 of the complete redacted captured text,
`status`), `coverage` (`complete`, `parsed_fields`, `missing_fields`) and
`warnings[]`. Identity metadata survives snapshot pagination without a new read.
Supplemental errors carry no invented source text; their digest is of the empty
capture. Hashes refer to captured text, not device wire bytes or unredacted secrets.

CLI classification follows 1.0.6 (`1fad86c`): device patterns search for refusal
lines anywhere in the complete output, for all profiles and all read paths.
`permission_denied`, `unsupported` and `not_applicable` are independent of the
optional `command` metadata. Existing refusal checks in identity reads, schema snapshots,
diagnostic shell answers/navigation and sequential reads use the same patterns.
Recipes that previously only parsed identity without checking refusal lines
retain that behavior.

The narrow table exception applies in `normalized_query`, `switch_read` and
`locate_endpoint` only to `permission_denied`, `unsupported` and `not_applicable`
when the parser returns data rows. It never overrides `transport_error` or a
nonzero rc that would fail without the refusal-like line (including EXOS 250
with an error marker). The parser treats that line as ordinary unknown data:
status is `unparsed` when unknown lines remain, otherwise `ok`. Coverage is
incomplete and `coverage.warnings` and `warnings` contain
`refusal_like_line_in_data`, without the line text. Unknown lines remain in
`unparsed`. Parsing precedes local filters and pagination; even a page or filter
returning no records retains the capture warning. The Junos ELS MAC/VLAN join
also retains warnings and unknown lines from `vlans`; after a join fills every
missing field, it removes the obsolete `fields_absent_in_catalogue_output` warning.
`locate_endpoint` uses status (`ok`/`empty`) and `refusal_like_line_in_data`
to decide read completeness, rather than
`coverage.complete` or catalogue field gaps. The warning is explicit in `missing`
even at status `unparsed`; it prevents a definitive `not_found_in_checked_data`
verdict and prevents a confirmed edge for MAC/LLDP/LAG reads. Auxiliary interface/VLAN
field gaps alone do not affect the verdict. Existing MAC/port and LLDP capability
rules still decide the edge (see [Endpoint location](tools.md#endpoint-location-locate_endpoint)). With no parsed rows,
the original refusal/rc status remains. Capture limits, terminal pagers and
timeouts take precedence. Identity checks and raw `ssh_read` have no table exception.

The ReDoS fixes bound Wi-Fi key/value whitespace, Junos LACP/route age,
EOS/Junos LLDP, CLI diagnostic/pager matching and multiline refusal whitespace
(`^[^\S\n]*` keeps leading whitespace on its own line). A pager at the end of the
capture is `truncated`, including one appended to the final data line without a
newline, as in `1fad86c`. A standalone final prompt may have trailing blank lines. An appended marker followed by a newline, or any marker followed by later data, is not a terminal pager. The historical classifier matrix covers 1023 texts (1012 earlier texts plus five live OSPF, four FortiGate-local and two NX-OS port VLAN captures):
all real captures, FortiGate-80F files and HA responses, FortiADC export, Ruckus
transcript, identity, documentation and table fixtures. It checks all 11 profiles
plus no profile at rc 0/1/250, with three `command` variants. Linux network captures and manual expectations are now included in the unified replay collection.

Refusal detection matches `1fad86c` on every capture. The retained pager rule
necessarily changes two complete Junos ELS logs (`log_messages` and
`log_interactive_commands`): `truncated` → `ok` at rc 0, and to `transport_error`
at rc 1/250, except EXOS rc 250 which is `ok` under its historical success rule.
These 72 raw status differences are separate from the parsed-table exception.
Raw `ssh_read` already removed this Junos artifact before classification; the
product correction now also removes its standalone line and following blank
erasure line before limiting logs, returning all 200 messages with
`line_limit.truncated: false` instead of 198 and a false `log_line_limit` warning.
Table tests reproduce an IOS LLDP description containing `% Permission denied`
and check real refusal shapes on every profile.

| Status | Meaning |
|---|---|
| `ok` | Parser recognized the checked output; field gaps and a protected refusal-like data line can still make coverage incomplete |
| `empty` | No output/records were returned |
| `not_applicable` | Adapter establishes that the feature does not apply, including a protocol that is not configured (`% BGP not active`, Junos `BGP is not running`, `warning: lacp subsystem not running - not needed by configuration.`) |
| `unsupported` | Device reports an unavailable command/feature: `% Incomplete command`, `% Ambiguous command`, NX-OS `% Invalid command`, `% Invalid input` on EOS, Junos `unknown command` |
| `permission_denied` | Explicit CLI/AAA refusal (`% Authorization failed/denied`, `% Permission denied`, Junos `error: permission denied`, EXOS permission text), and on IOS/IOS XE the `% Invalid input` that a read-only view gives for a hidden command and `Line has invalid autocommand`; because an IOS/IOS XE image without the command (a router image without switching commands) answers the same way, such a result carries `hint`: the command was refused by the account or does not exist on this image |
| `unparsed` | Output contains unknown lines (including protected refusal-like lines) or identity cannot be verified |
| `truncated` | Capture is incomplete: capture limit, or a pager prompt (`--More--`, `---(more N%)---`, `Press <SPACE> to continue`) at the end of the capture, including one appended to the final data line without a following newline; a standalone final prompt may have trailing blank lines, and a marker followed by later data does not count. A page boundary of a complete capture is not `truncated` |
| `timeout` | Read deadline elapsed |
| `transport_error` | Connection/process failed |

`status` is also returned at the top level. Legacy `ok` describes the existing
SSH operation; consumers of structured data must inspect normalized status and
coverage. Reads in these OS profiles that have no normalized table adapter stay raw
text. FortiOS, FortiADC and Ruckus preserve their existing response
contracts. A parsed identity may be complete while its raw version text is paginated;
its envelope describes the complete capture. `not_applicable` is reserved for
adapters with positive evidence; an empty result does not imply it.

`normalization.normalize_port` produces a canonical name, parent (`physical`),
logical unit and aggregate flag. Gi/GigabitEthernet, Eth/Ethernet and
Po/Port-channel/Port-Channel aliases compare equally; Junos `ge-0/0/1.0` remains distinct from
`ge-0/0/1`, and EXOS `1:5` stays intact. LAG, ae and Port-channel numbers across
vendors are not assumed equivalent. This module normalizes observed values;
existing platform-specific command argument validators remain authoritative.
The result has `kind`: `physical`, `aggregate` or `other`. Besides Gi/Fa/Te, the
aliases cover Twe/TwentyFiveGigE, Fo/FortyGigabitEthernet, Hu/HundredGigE and
Tw/TwoGigabitEthernet (Tw is 2.5G, Twe is 25G), and Junos channelized `xe-0/0/0:1`.
A safe name that is not a physical port (`Vlan10`, `Loopback0`, `mgmt0`, `irb.10`)
is returned unchanged with `kind: "other"` instead of an exception; unsafe text
still raises `ValueError`.
MAC colon, hyphen, dotted and twelve-hex forms normalize to `aa:bb:cc:dd:ee:ff`.

Typed template building blocks (no additional commands in this change):

| Kind | Validation and enrollment |
|---|---|
| `vlan_id` | Canonical decimal 1–4094; literal, no inventory lookup |
| `mac_literal` | Exactly one MAC; canonicalized as above; literal |
| `ip_literal` | IPv4/IPv6 literal, no DNS or zone IDs; CIDR only with explicit `Slot.lookup_only=True` on a passive show template |
| `vrf` | Exact member of `read_inventory.vrfs` |
| `vr` | Exact member of `read_inventory.virtual_routers` |
| `routing_instance` | Exact member of `read_inventory.routing_instances` |

Literal slots declare `Slot(None, kind)`. Routing context names use one ASCII
alphanumeric token with `_.:-`, at most 64 characters; there are no wildcards,
whitespace, quotes, pipes, semicolons or control characters. Existing address
slots still require enrolled canonical host addresses and reject CIDR. Lookup
CIDRs canonicalize to network prefixes and are never used as connection targets.


## Operational value names

OS parsers use the same value names for equivalent known observations. The values
below describe mappings, not closed schema enums; a syntactically accepted value
without a known equivalent can pass through as described below.

| Field | Canonical values / mapping |
|---|---|
| Route `protocol` | known names in lower case; `direct` → `connected`, `is-is` → `isis`, `ospf3` (Junos) and `ospfv3` (NX-OS) and EOS `O3` → `ospf`; NX-OS process suffixes such as `ospf-1` and `ospfv3-1` are removed |
| OSPF `state` | `down`, `attempt`, `init`, `2way`, `exstart`, `exchange`, `loading`, `full`; EOS `2 WAYS`, IOS/XE `2WAY`, NX-OS `TWOWAY` and Junos `2Way` → `2way` (DR roles remain separate); EXOS has no normalized OSPF binding and returns `unsupported` |
| OSPF `role` | `DR`, `BDR`, `DROTHER`, or null when absent |
| BGP `state` | `Idle`, `Connect`, `Active`, `OpenSent`, `OpenConfirm`, `Established`; `Idle(admin)` and `Idle(prefixlimit)` retain the reason: IOS/IOS XE/NX-OS `Idle (Admin)` → `Idle(admin)`, `Idle (PfxCt)` → `Idle(prefixlimit)`, NX-OS `Shut (Admin)` → `Idle(admin)` (case-insensitive; compact spellings also accepted); numeric prefix counts and `Estab`/`Establ` mean `Established` |
| LAG `protocol` | `lacp` → `LACP`, `pagp` → `PAgP`, `static` → `Static` (case-insensitive); `-` and `none` → null |
| LAG `status` | `up`, `down`, `not in use`, or null when unavailable |
| LAG member `state` | `bundled`, `down`, `standalone`, `hot-standby`, `suspended`, `waiting`, `unsuitable`, `default`, `min-links`, `failed`, `not-in-use`, `incompatible`, `transmit-disabled`, `in-use`, `bfd-wait`, `module-removed`, `unknown` |
| STP `role` | `designated`, `root`, `alternate`, `backup`, `master`, `disabled`, `boundary` |
| STP `state` | `forwarding`, `blocking`, `learning`, `listening`, `discarding`, `disabled`, `broken` |
| Interface `oper_status` | `up`, `down`; Linux also preserves `unknown`, `dormant`, `lowerlayerdown`, `notpresent` and `testing` |
| IP interface (`ip_interface`) fields | `interface`: shared port normalizer (`Gi0/1.10` → `GigabitEthernet0/1.10`); Linux, EXOS VLAN and FortiOS names retain their spelling. `ip`: one IPv4 address per record, or IPv4/IPv6 on Linux; `prefix_length`: 0–32 (0–128 for IPv6), null without a mask (IOS/IOS XE/NX-OS without the connected interface route; Junos without `/n`); `vlan_id`: SVI VLAN (`Vlan10`, `irb.10`) or EXOS tag of the same-named VLAN, null for subinterfaces, FortiOS VLAN interfaces and Linux; `admin_status`, `oper_status`: `up`/`down`, plus the Linux operational states above (IOS `administratively down`, EOS `admin down`, NX-OS `admin-down`, EXOS without flag `E` → admin `down`; Protocol, `protocol-` or EXOS flag `U` → oper). FortiOS `status` is configured state; `oper_status` is null. `vrf`: NX-OS VRF heading only, null elsewhere |

Unknown-value handling depends on the accepted command layout:

- Route protocols are not merged when there is no known equivalent. IOS/IOS XE
  detail lookups take the first word and lowercase it; EOS route-code fallbacks and
  Junos detail lookups lowercase the protocol; NX-OS lowercases and takes the text
  before the first `-` (with `is-is` / `is-is-<process>` mapped to `isis`). EXOS
  preserves an unknown origin code exactly. Junos whole-table entries and IOS route
  codes must be recognized; an unknown one is reported in `unparsed`.
- IOS/IOS XE populated IPv6 detail lookups (`Routing entry for`, `Known via`,
  `Routing paths`) support IPv6 next hops and interfaces, ECMP and directly
  connected paths. `Known via "ospf <process>"` becomes `ospf`, including
  OSPFv3. This layout is tested with documentation fixtures only; all live
  IOS/IOS XE IPv6 lookups in the repository report `% Route not found`.
- EOS maps complete source codes: `C` → `connected`, `S` → `static`,
  `K` → `kernel`, `O`/`O3` (including `IA`, `E1`, `E2`, `N1`, `N2`) →
  `ospf`, `B`/`B I`/`B E` → `bgp`, `I`/`I L1`/`I L2` → `isis`,
  `R` → `rip`, `A`/`A B`/`A O` → `aggregate`, `DH` → `dhcp`.
  Other complete codes pass through in lower case: `L` (VRF leaked) → `l`,
  `DP` → `dp`, `RC` → `rc`, `CL` → `cl`, `NG` → `ng`, `V` → `v`,
  `M` → `m`, `G` → `g`. In particular, EOS `L` does not mean `local`.
- Known route names that remain distinct include `connected`, `local`, `static`,
  `rip`, `ospf`, `bgp`, `eigrp`, `isis`, `am`, `hsrp`, `bootp`, `unknown`,
  `hardcoded`, `blackhole`, `icmp`, `kernel`, `aggregate`, `dhcp`, `mobile`,
  `odr`, `nhrp`, `lisp`, `application`, `access`, `igmp`, `pim`, `evpn`,
  `l2circuit`, `ldp`, `rsvp` and `multicast`, where the OS layout provides them.
  This is an open list, not a route-protocol enum.
- Unknown OSPF states in IOS/IOS XE, EOS and NX-OS retain their text converted to
  uppercase; their role must still be recognized. Junos OSPF accepts the named
  states in the table and reports other state rows in `unparsed`.
- Unknown LAG protocol tokens on IOS/IOS XE, EOS and NX-OS pass through with their
  original case, after removing a trailing single-character flag such as `(a)`.
  Junos LACP always reports `LACP`. Unknown member flags or unrecognized BGP/STP
  states and roles remain `unparsed`; the open value lists do not make an unknown
  CLI layout parseable. Interface status and LAG status/member states are derived
  from recognized layout fields and flags, not arbitrary text passthrough.

Blocking and discarding keep their reported STP meaning. Missing values stay null;
no state is inferred from an absent row. EXOS `aggregate` reports only `name` and
`member_count`, so it provides no LACP member state. These operational record
schemas have no `raw_*` fields; the captured source text retains the vendor spelling
and its source hash. Value mapping does not change result-status classification.

EOS LLDP discovery/change ages accept `H:MM:SS` and `N day(s), H:MM:SS`;
these metadata lines do not reduce neighbor coverage. EXOS direct/connected
routes normalize the local VLAN Gateway address to `next_hop: null`, preserve
the VLAN in `interface` and report `protocol: connected`; routed next hops
remain addresses.

For an empty IOS / IOS XE IPv4 route lookup, `source: longest_prefix_from_table` identifies the fallback selection from `route_table`; route record fields retain their normal meaning.

`interface_errors.port` uses canonical port names. `rx_errors`, `crc`,
`tx_errors`, `discards_in`, `discards_out`, `link_flaps` and `carrier_transitions`
are integer cumulative counters since the last device counter reset; zero is
measured and `null` means absent. RX/TX totals are used only when printed:
subcategories can overlap and are never summed. `crc` maps FCS/FCS-Err on
EOS/Cisco, Rx Crc on EXOS and receive CRC/Align on Junos (including alignment
errors). `last_flap` preserves the device timestamp and relative age as text,
including `Never`; no absolute time is invented. `link_flaps` and
`carrier_transitions` remain distinct; absent counters stay `null`. Fields other
than `port` are optional for coverage because platforms expose different
counters. Unknown lines still make coverage incomplete. IOS/XE falls back to the
separately authorized whole `show interfaces` on unsupported, denied or empty
counter output. Input queue drops and total output drops are used only when
printed; unknown protocol drops are not aggregate discards. Last input/output
and interface resets are not flap evidence. No port records means `ok: false`
and incomplete coverage, including an empty local port filter. See the
[table sources](tools.md#normalized-tables-switch_read).

## Managed FortiSwitch tables

For the `fortinet` profile, `switch_read` binds `mac_entry` to `managed_switch_mac`
and `lldp_neighbor` to `managed_switch_lldp`. Both require `managed_switch`, a serial
in the target's existing `read_inventory.managed_switches`, and the corresponding
enabled query; proxy and worker validate the same catalogue slot as `locate_endpoint`.
The top-level `managed_switch` identifies the selected switch. Record fields retain
the common schema: MAC `mac`, `vlan_id`, `port`, `type`, `vlan_name`; LLDP
`local_port`, `neighbor`, `neighbor_port`, `management_ip`, `capabilities`.
MAC flags supply `dynamic`/`static`; a trunk entry keeps `type: "trunk"` and its
reported trunk name in `port`. The optional `vlan_name` is null. The captured
FortiOS 8.0.2 build0251 summary supplies no LLDP `management_ip`, which stays null
with incomplete field coverage; compact capability letters become canonical
comma-separated codes. Rows without an advertised neighbour are skipped. Unknown
lines preserve their original line numbers, even when MAC/VLAN filters exclude
all records. The earlier documented layouts remain accepted.

`interface` and `interface_errors` require the same serial and the opt-in
`managed_switch_port_stats` query. `interface` gives `name`, HW/SW combined
`admin_status`, line-protocol `oper_status` and speed (`1000M`); VLAN/trunk and
unreported description stay null. `interface_errors` maps input/output errors
and drops to `rx_errors`, `tx_errors`, `discards_in`, `discards_out`. CRC, last
flap and flap/carrier counts stay null because port-stats does not print them.
An `interface` selector for these two tables is rendered as the optional `port`
slot and must be in `managed_switch_ports`; without it the selected switch is read.

`port_vlan` requires `managed_switch_port_vlans` and `interface_vlan_ids`.
The fixed `show switch-controller managed-switch SERIAL` and `show system
interface` reads are configuration. The response and records carry
`source: configuration`; `vlan`/`allowed_vlans`/`untagged_vlan_names` retain the
configured names, which are resolved by explicit `vlanid`, never by guessing from
a name. `native_vlan` is the configured `vlan`, `untagged_vlans` contains it and
allowed VLANs explicitly in `untagged-vlans`, and `tagged_vlans` contains the
remaining allowed VLANs. Unresolved names keep membership unknown. Link state
stays null and field coverage incomplete on this configuration table. Device
refusal yields `unsupported` with a reason. `locate_endpoint` reads port-stats
independently and labels its VLAN evidence `source: configuration`.

FortiOS IPv4 `route` binds to the existing `route_lookup` with an enrolled `ip`,
or `routing_table` without one. The lookup reuses `triage_routing.route_lookup`;
the whole-table adapter preserves ECMP and VRF and maps to the same `prefix`,
`next_hop`, `interface`, `protocol`, `vrf` fields. Connected routes have no gateway.
Unsupported FortiOS tables return `status: unsupported`, `data.field: table` and
`data.supported_tables` before contacting a device.

The two FortiSwitch configuration queries expose a local projection of the VLAN fields also through `ssh_read`; unrelated fields are omitted, malformed configuration lines are reported by line number without their values, and source hashes describe this projected, redacted text.

`neighbor_l3.type` is optional ownership evidence. IOS/IOS XE IPv4 ARP rows
with age `-`, a MAC and a printed interface carry `type: interface`; static
rows without an interface and learned neighbors carry null. Other profiles do
not infer ownership from a static/permanent age alone. `locate_endpoint` reports
`own_interface_of_target` and `own_interfaces` (target, interface, IP, MAC and
source table) for matching local/interface evidence or an address of an already
read interface. An unresolved MAC seen only on transit links (or with no switch
reader) may consult enrolled IPv4 ARP readers; ordinary MAC edge lookups do not.
The same 40-read/60-second budget includes these reads and identity checks.
Multiple target owners remain ambiguous. Transit evidence stays in `findings`,
without claiming `edge_beyond_enrolled_targets` when an enrolled owner is known.

Interface names use the shared canonical long form in every normalized table,
including `interface`, `port_vlan`, `ip_interface`, `neighbor_l3`, `mac_entry`,
LLDP local ports, VLAN port lists, routes, LAG names/members, STP and error
counters. EOS `Ma0` and `Management0` become `Management0` (kind `other`),
`Et1` becomes `Ethernet1`, `Po1`/`Port-Channel1` become `Port-channel1`, and
NX-OS `Eth1/1` becomes `Ethernet1/1`. The `interface` filters of `port_vlan`,
`ip_interface` and `interface_errors` accept either short or long spelling and
compare the same canonical value after capture classification. This is local
normalization; command-slot authorization remains unchanged. Vendor-specific
names such as NX-OS `mgmt0`, Junos `ge-0/0/0.0` and EXOS VLAN names retain their
identity. Source text and hashes keep the original spelling.

Failed normalized transport reads carry an allowlisted `error_code` (`unreachable`, `timeout`, `dns`, `connection_refused`, `host_key_unavailable`, `host_key_mismatch`, `negotiation`, `auth`, `auth_method_unsupported`, `disconnected`, `output_limit`, `exit_status` or `transport_failure`) and the fixed advice of that class in `error`, in the result and in locate `missing`, with the same class in per-read audit `detail`, without exception or device text; a host key that cannot be read is followed by one credential-free SSH probe, so a host that does not answer is `unreachable`, `timeout` or `connection_refused` and only a host that answered without a usable key is `host_key_unavailable`; an enrolled LLDP neighbor matched by alias, verified sysName/hostname or enrolled management address yields `endpoint_not_seen_on_neighbor_target` instead of `edge_beyond_enrolled_targets` when no endpoint edge is observed.

Device output drops ANSI escape sequences and C0 controls except newline and tab before hashing, paging and client delivery; other text is preserved subject to existing secret redaction.

## Linux network normalization

Linux is an identity profile verified from the existing `uname -a` command
(internal `version` lookup aliases `kernel`; it is not a public query). The normalized network tables and their catalogue
sources, optional MAC/MTU fields, IPv6 address/ND handling and measured coverage
are described in [Linux normalized network tables](tools.md#linux-normalized-network-tables).
A missing field remains null and is reported by the shared coverage rules;
Linux does not invent VLAN/trunk membership or administrative state from
`ip -brief address` output. In the same `switch_read`, IP and prefix come from
`addresses`, enabled `links` adds MAC and administrative state, and enabled
`routes` adds the IPv4 default gateway. The public query catalogue preserves
the 1.0.7 commands and descriptions.
