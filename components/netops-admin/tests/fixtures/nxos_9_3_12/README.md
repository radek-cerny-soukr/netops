# Cisco NX-OS 9.3(12) outputs

Command outputs measured on a Nexus 9000v (N9K-C9300v, NX-OS 9.3(12), GNS3 lab node, test port Ethernet1/48) for
the NX-OS adapter of netops-admin. Files ending in `__*.txt` and the help-free command answers come from the
measurement of tasks netops-provoz-20261116-314 and 317 (`ref/mereni-c6/fixtures` and `ref/mereni-c6/replace/fixtures`:
the clean output without echo and prompt). Changes made while copying:

- the host name `d-nxos` is `host05`, the source address of `show users` is in 192.0.2.0/24 and the serial number of
  `show version` is `0SSSSS0001S`; the MAC addresses of the MAC table, the switch MAC and the OSPF router id of the
  `show running-config diff` answer went through `components/netops-helper/tests/support/anonymize_fixture.py`
  (documentation ranges; the mapping file was not kept);
- `show-interface-Eth1-48-switchport__baseline.txt`: the measurement had already left out nine `private-vlan` lines
  (an over-broad secret pattern of its first phase, see its RESULT.md); they are not in the copy either;
- `show-running-config__baseline.txt` is the anonymised `show running-config` of the same node read over ssh exec by
  the Helper in task 178 (`components/netops-helper/tests/fixtures/real/live_178/captures.json`,
  `config_diff/nxos_base`) with the line `feature scheduler` added after `cfs eth distribute`: the lab precondition
  of the adapter, enabled once in task 318 (the measured `show running-config diff` shows the line at that place);
- `show-feature.txt` is the `show feature` answer of the same node (Helper fixture `nexus9300v_9.3.12/features.txt`,
  read by the check account), where `scheduler` is `disabled`; the simulated switch sets it from its state.

`tests/fake_nxos.py` builds every answer from these files; the scheduler job and schedule blocks of the running
configuration, the rows of a MAC table with learned addresses and an LLDP row for a test port are derived from the
measured layouts (`show-running-config-diff__unsaved.txt`, `show-running-config-section-scheduler__*.txt`).
