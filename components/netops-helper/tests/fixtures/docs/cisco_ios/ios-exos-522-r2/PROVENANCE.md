# EtherChannel fixtures

- `asr901_load_balance.out` is the SSH response body from the Cisco ASR 901 command-reference example on page 1-154. The missing-continuation case removes the final line at its line boundary. [Cisco ASR 901 command reference](https://www.cisco.com/c/en/us/td/docs/wireless/asr_901/Command/Reference/asr901_cmdref/Cmdref_asr901.pdf#page=154)
- `catalyst2950_load_balance.out` is the response body from the Catalyst 2950 lab example with IOS 12.1(6)EA2c. Removing the final newline simulates a cutoff. The alternate destination method is derived from the Catalyst 2950 forwarding methods listed on the same page. [Cisco Catalyst 2950 lab example](https://www.cisco.com/c/en/us/support/docs/lan-switching/etherchannel/22422-144.html)
- The test changes only the version token in the existing IOS identity fixture to exercise version-independent parsing. The `15.1(2)SNG` token is from the ASR 901 command history. [Cisco ASR 901 command reference](https://www.cisco.com/c/en/us/td/docs/wireless/asr_901/Command/Reference/asr901_cmdref/Cmdref_asr901.pdf)

## STDERR fixtures

- `tacacs_denied.out` is the CLI line from Cisco's IOS TACACS+ denial example. The replay uses the line on stderr with blank stdout and exit code 0 as specified by [the review](../../../../../../../ref/RESULT-522-r2-rv.md). [Cisco IOS TACACS+ configuration example](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/200208-Configure-ISE-2-0-IOS-TACACS-Authentic.html)
- [`openssh_pq_warning.stderr`](../../../transport/openssh_pq_warning.stderr) copies the captured X440 OpenSSH warning from the Admin `exos_port_poe` fixtures with LF line endings. The host-key notice uses a documentation address. Unknown diagnostics are synthetic. Empty table bodies retain the headings from each platform's existing `tables` fixture or the legend and headings from the [IOS LACP example](../g53/lacp_internal.out).
