# Live scenarios of task 178 (GNS3 D-lab, 2026-11-14), used by task 186

Source: the raw CLI records `cli.jsonl` of task 178 (not included) (independent `ssh` exec reads next
to the NetOps MCP calls; the `config_diff` scenario of 1.0.9 item 07 and the MLAG/vPC views of item 10).
Every file was sanitized and anonymised with `tests/support/anonymize_fixture.py` (host names `hostNN`, user names
`userNN`, IPv4 into the RFC 5737 ranges; the anonymiser keeps column alignment, so a few replaced words are
followed by extra spaces).  The mapping file was deleted after the run.

All captures are stored in `captures.json` (key = the name below without `.txt`, value = the captured text), not
as `.txt` files: every `*.txt` under `tests/fixtures` is also a capture of the classifier baseline
(`test_classification_baseline`, `output_status_baseline.json`), which these new captures are not part of.
The fixture privacy check (`test_anonymize_fixture`) reads the JSON strings like `.txt` files.

## `config_diff/...` - `show running-config`, account netops-admin (task 178, run r2)

| File | Device | 178 record | Note |
|---|---|---|---|
| `iosv_base.txt` | IOSv 15.9(3)M12 | `07-iosv-r2:cli-B` | before the change |
| `iosv_changed.txt` | IOSv 15.9(3)M12 | `07-iosv-r2:cli-C` | after `interface GigabitEthernet0/3` / `description netops-178` |
| `iosv_reverted.txt` | IOSv 15.9(3)M12 | `07-iosv-r2:cli-D` | after `no description` |
| `iolxe_base.txt` | IOL XE 17.18.2 | `07-iolxe-r2:cli-B` | before the change |
| `iolxe_changed.txt` | IOL XE 17.18.2 | `07-iolxe-r2:cli-C` | after `interface Ethernet0/3` / `description netops-178` |
| `iolxe_reverted.txt` | IOL XE 17.18.2 | `07-iolxe-r2:cli-D` | after `no description` |
| `nxos_base.txt` | N9300v 9.3(12) | `07-nxos-r2:cli-B` | before the change |
| `nxos_changed.txt` | N9300v 9.3(12) | `07-nxos-r2:cli-C` | after `interface Ethernet1/48` / `description netops-178` |
| `nxos_reverted.txt` | N9300v 9.3(12) | `07-nxos-r2:cli-D` | after `no description` |

The device rewrote its own header lines between the reads (`Current configuration : N bytes`,
`! Last configuration change ...`, NX-OS `!Running configuration last done at:` and `!Time:`), and the IOS/IOS XE
exec channel printed three or two leading empty lines; both are kept as captured.  IOSv and IOL XE sent CRLF
line ends, NX-OS LF; the files hold LF and the tests restore CRLF for IOSv and IOL XE.

DERIVED edits (the task 178 log had already replaced each credential line by `<REDACTED-LINE>`): those lines
were rewritten as synthetic credential lines with the sentinel values of the public tests
(`enable secret 9 $9$SECRET-ENABLE-SENTINEL`, `username ... password 0 SECRET-PASSWORD-SENTINEL`, NX-OS
`username ... password 5 SECRET-PASSWORD-SENTINEL  role ...`, `snmp-server user <user> <role> auth md5
0xSECRET-SNMP-SENTINEL priv 0xSECRET-SNMP-SENTINEL localizedkey`, `ssh key rsa 2048`, IOL XE trustpoint
` hash sha256`); the IOL XE self-signed certificate body was replaced by `A` characters of the same shape.
No other line was edited.

## Other files

- `ceos_4.36.1F_mlag_interfaces_no_ports.txt` - cEOS 4.36.1F `show mlag interfaces`, account netops-ro
  (`s10-r2:ceos:mlag_interfaces`, SHA-256 of the raw output `5c89fe58...cf9e` as in 178), MLAG not configured.
- `iosv_15.9.3M12_show_running_config_ro.txt`, `iolxe_17.18.2_show_running_config_ro.txt` - the complete
  answer (rc 0) of IOSv and IOL XE to `show running-config` on the read-only account netops-ro (`discover:iosv`,
  `discover:iolxe`), CRLF stored as LF, no final line feed as captured.
