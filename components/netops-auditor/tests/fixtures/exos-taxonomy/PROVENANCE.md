# ExtremeXOS taxonomy fixture provenance

Each triple under `../rules/exos.<area>.<check>/` is derived. The inputs
retain module headers and command tokens, with deliberate order changes
to exercise overrides. The `not-evaluated.conf` cases omit the relevant
decisive command or auxiliary evidence. The test supplies only the
applicable intent and explicit visibility evidence. Addresses are RFC 5737
examples, names and port lists are illustrative, and secret values are
synthetic `SECRET-DATA` placeholders.

| Rules | Primary syntax source and derivation |
| --- | --- |
| `mgmt.http-enabled` | Switch Engine 33.7.1 HTTP. Explicit enable, disable override and a configuration with only HTTPS. |
| `mgmt.idle-timeout` | EXOS 32.6.3 idle timer and EXOS 22.5 legacy form. Legacy and current forms with synthetic limits. |
| `mgmt.lockout` | EXOS 32.1 lockout and EXOS 31.7.3 policy readback. Global and per-user commands in both orders. |
| `mgmt.access-acl` | EXOS 33.6.1 SSH2 profiles and EXOS 31.4 sample policies. Synthetic policy names and ordered source entries. |
| `aaa.external-login` | EXOS 32.1 RADIUS and EXOS 32.6.3 TACACS+. Secondary-only management server and explicit activation states. |
| `snmp.v1v2c-community`, `snmp.v3-auth-priv` | EXOS 32.1 access, EXOS 32.4 USM, Switch Engine 32.1 groups, EXOS 30.2 VACM. Both community forms and a synthetic USM group with two security levels. |
| `time.ntp-auth` | Switch Engine 32.7.1 NTP authentication and EXOS 32.2 server/peer. Source with no key, matching trusted key, and absent key material. |
| `logging.syslog-level` | EXOS 32.6.3 target filter and the existing `../exos_clean.conf`. An explicit VR, `only`, and a filter whose contents are unavailable. |
| `services.edge-discovery` | EXOS 32.2 LLDP and EXOS 32.1 EDP. Global defaults and overrides represented by explicit port commands. |
| `l2.bpdu-guard` | EXOS 32.6.3 STPD membership and Switch Engine 32.2 BPDU Restrict. Synthetic VLAN and domain with a narrower disable override. |
| `l2.default-vlan`, `ports.unused-up` | EXOS 32.4 VLAN membership and the existing native-port fixture. Replace untagged membership with tagged, and set or clear administrative port state. |
| `l2.dhcp-snooping` | EXOS 32.3 DHCP snooping. Synthetic client and trusted ports with an explicit narrower violation-action override. |
| `l2.storm-control` | Switch Engine 33.7.1 flooded traffic limits. A finite broadcast limit, `no-limit` override and a multicast-only row. |

Source URLs are listed in the [vendor references](../../../docs/exos.md#vendor-references).

The archived, already redacted EXOS configuration and NTP command
captures are reused from Helper fixtures. They retain their original
scope and provenance. The refusal replay uses the existing one-line
diagnostic on the SSH transport boundary.
