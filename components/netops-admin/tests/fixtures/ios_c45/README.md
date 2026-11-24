# Cisco IOS and IOS XE outputs (in the virtual topology, 2026-11-16)

Command outputs of four lab nodes for the IOS adapter of netops-admin: `iosv` (IOSv 15.9(3)M12, router, test port
GigabitEthernet0/2), `iosvl2` (IOSvL2 15.2(20200924:215240), switch, GigabitEthernet1/0), `iolxe` (IOL XE 17.18.2,
router, Ethernet0/2) and `iolxe-l2` (IOL-L2 XE 17.18.2, switch, Ethernet0/1).

All files except the three `__exec` files come from the measurement of verification
(a private measurement record, the clean output without echo and prompt). The `__exec` files were read in verification with one SSH exec command of the write account before any change: `show running-config`,
`show tcp brief` and `show vlan id 10` (the empty lines before the answer are kept).

Changes before the anonymisation: the secret hashes of the `username` and `enable secret` lines were replaced by
`<REDIGOVANO>` while reading; the hexadecimal body of the self-signed certificate of IOL XE (running configuration and
the startup/running difference) was replaced by one line of zeros. The files then went through
`components/netops-helper/tests/support/anonymize_fixture.py --check` with one mapping for all four nodes (kept outside
the repository): host and domain names are `hostNN`, addresses are in the documentation ranges, serial numbers are
replaced, account names `netops-admin` and `netops-ro` are kept. The check reports only `credential:username-secret`
for the redacted `username... secret` lines. Corrections after the anonymiser: the addresses of `show tcp brief`
(`A.B.C.D.port`, which the anonymiser does not recognise) were mapped by hand to the same documentation addresses, the
LLDP rows whose cut Device ID runs into the Local Intf column were rebuilt with a 20-character name, and the spaces that
the anonymiser added after shortened addresses in `ip address` lines were removed.

The files `configure-revert-now__ok.txt` and `configure-revert-now__nothing-pending.txt` of every node were added
unchanged from the same measurement in verification-r2 (they name only the archive file and, on IOSvL2,
the returned lines of the test port).

`tests/fake_ios.py` builds every answer from these files; the archive and revert-timer answers after a change, the
rows of the MAC table (port with learned addresses) and the extra LLDP/CDP rows are composed in the measured layout.
