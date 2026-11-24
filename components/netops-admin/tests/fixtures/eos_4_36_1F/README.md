# Arista cEOS 4.36.1F outputs

Command outputs measured on cEOS 4.36.1F-48405728.4361F (in the virtual topology node, test port Ethernet10) for the EOS
adapter of netops-admin. All files except `show-running-config__baseline.txt` come from the measurement of verification (`fixtures/` of that measurement: the clean output without echo and prompt);
`show-running-config__baseline.txt` is `show running-config` read in verification before any change
(privilege 15 after `enable`, the echo line and the prompt removed).

The files went through `components/netops-helper/tests/support/anonymize_fixture.py --check`: host names are
`hostNN`, addresses are in the documentation ranges, account names `admin`, `netops-admin` and `netops-ro` are
kept. The secret hashes of the `username` lines were replaced by `<REDIGOVANO>` while reading, before the file was
written; the check still reports `credential:username-secret` for these three lines, because it matches any
`username... secret...` line. The mapping file was not kept.

`tests/fake_eos.py` builds every answer from these files; a row of the MAC table (port with learned addresses) and
an LLDP row for Ethernet10 are the only answers derived from a measured layout rather than measured themselves.
