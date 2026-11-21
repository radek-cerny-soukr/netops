# G76 IOS XE configuration captures

The GNS3 d-lab nodes d-iolxe (2257) and d-iolxe-l2 (2258) were read on 2026-11-19 using pinned OpenSSH on PC-Radek. Both ran IOS XE 17.18.2 fc3. The capture receipts are in `task-evidence/g76/capture.log`.

- `*-running.out` and `*-startup.out` were captured with `netops-admin`, passed through the existing IOS stream redactor, then anonymized with `tests/support/anonymize_fixture.py`. Line endings are LF. The size fields were recalculated after redaction to preserve the observed wire convention of one byte more than the configuration body.
- `*-native.out` retains the Cisco status lines and the indentation and signs of changed statements. Configuration text is masked, including the self-signed certificate ID. The router's measured native differences are within a self-signed certificate chain.
- `*-version.out` contains the identity and hardware lines only. `*-refused.out` records the actual privilege-1 refusal to execute `show running-config`.
- `c9300-version.out` is an excerpt of the [Cisco Catalyst 9300 system management guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/configuration_guide/sys_mgmt/b_1718_sys_mgmt_9300_cg.pdf).
- `c9800-version.out` is an excerpt of the [Cisco Catalyst 9800 command reference](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr.pdf), with line wrapping removed. There is no hardware line in the excerpt.
