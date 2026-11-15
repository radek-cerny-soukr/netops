# Real FortiADC output: virtual server with schedule-list (2026-11-14)

FortiADC-KVM v7.6.7 build 0676 (GA.M), standalone, root VDOM, lab device, 2026-11-14 17:08–17:12 UTC
(device clock PST, Saturday). Temporary lab objects `netops-173-*`: pools `netops-173-pool-a` (member RS_A)
and `netops-173-pool-b` (member RS_B), schedule groups `netops-173-sg-now` (weekly-recurring, Saturday
00:00–23:59, the window was active) and `netops-173-sg-off` (Wednesday, not active), schedule-pool entries
`netops-173-sp-a` (sg-now -> pool-a) and `netops-173-sp-b` (sg-off -> pool-b), virtual server `netops-173-vs`
with `schedule-list enable` and `schedule-pool-list netops-173-sp-a netops-173-sp-b`. All objects were
removed afterwards. Not synthetic.

Reads: `show full-configuration` and `diagnose server-load-balance` over the SSH exec channel (the exec
channel keeps the FortiADC pager `--More-- \r<spaces>\r` and prompt lines `FortiADC-KVM # `), one read
over a PTY. Bytes are kept as captured (CR of the pager and of the PTY included); the only change is the
anonymiser (`tests/support/anonymize_fixture.py`, run with `newline=''` so CR bytes stay, no map,
residual check 0): the virtual-server address became `192.0.2.10` in the two `vs_schedule_*` files.
No other byte differs from the capture.

| File | Command | Note |
|---|---|---|
| `vs_schedule_full.txt` | `show full-configuration load-balance virtual-server netops-173-vs` | no `load-balance-pool` line at all |
| `schedule_pool_full.txt` | `show full-configuration load-balance schedule-pool` | two named entries |
| `schedule_pool_sp_a_full.txt` | `show full-configuration load-balance schedule-pool netops-173-sp-a` | object view |
| `schedule_group_full.txt` | `show full-configuration system schedule-group` | `config  schedule-member` with two spaces, `edit "1"` |
| `schedule_group_sg_now_full.txt` | `show full-configuration system schedule-group netops-173-sg-now` | object view |
| `pool_a_full.txt` | `show full-configuration load-balance pool netops-173-pool-a` | `config  pool_member` with two spaces |
| `vs_stat_schedule_exec.txt` | `diagnose server-load-balance vs_stat vdom root vs netops-173-vs` | `no rs for this vs`, no pool block |
| `vs_stat_schedule_pty.txt` | the same over a PTY, up to the next prompt | same body without the exec prompt line |
| `slb_load_schedule_exec.txt` | `diagnose server-load-balance slb_load` | `no rs for this vs` under the virtual server |
| `vs_schedule_stored_pool_full.txt` | as `vs_schedule_full.txt`, after `load-balance-pool netops-173-pool-b` was stored | byte-identical: the stored pool is hidden |
| `vs_stat_stored_pool_exec.txt` | vs_stat in that state, schedule window active | names `netops-173-pool-b`, empty `last-state-change-time` |
| `slb_load_stored_pool_exec.txt` | slb_load in that state | names `netops-173-pool-b` |
| `vs_stat_stored_pool_offwindow_exec.txt` | vs_stat with no schedule window active (sg-now moved to Wednesday) | `availability:DEAD`, still `netops-173-pool-b` |

The stored pool was set with `schedule-list disable`, `set load-balance-pool netops-173-pool-b`,
`schedule-list enable` (with `schedule-list enable` the CLI refuses `set load-balance-pool`, return code -284).
The active schedule then selected sp-a -> pool-a, yet vs_stat and slb_load name pool-b: vs_stat names the
stored field, not the pool the schedule selects. No traffic was sent through the virtual server.

SHA-256 of the stored files:

```
2c5df4a3e4803125fa3779b5524cc81eeed44d45c5b56393a3d3de5ffd33f1f5  pool_a_full.txt
2152d54876383c0052fc392348853e9d2b33be4a7cb1cf8eb968593e20384c9c  schedule_group_full.txt
cd04a2c2eb7aedba2c284f2e17667a71e36760271b22ceac3ec0f73c45d522a9  schedule_group_sg_now_full.txt
4e4696f3569b9d5adb9c72f2799b6b51ec55a122a0c0f56946d2d5eb7a7c0cfc  schedule_pool_full.txt
682fc76477cfeae7a1539ba6e0ea5c8c1001938f3f5915be6c46828b1ab10a3d  schedule_pool_sp_a_full.txt
db01cee0911347a8da4ecbd7d7146bab82340e3a686587f06a3bde7bf3d77e4c  slb_load_schedule_exec.txt
4f6434d5a686853bbc828140f8cc5bfb105ef688e9e7df6af4d7fa959ed6b04b  slb_load_stored_pool_exec.txt
985eeeafce48ec73abf7a063b53bb301d2ffe475e2176fbb4d46b362140e6d29  vs_schedule_full.txt
985eeeafce48ec73abf7a063b53bb301d2ffe475e2176fbb4d46b362140e6d29  vs_schedule_stored_pool_full.txt
095b0939900701625b11367db6691be1a607a63ee16a6c09e660a56cd0b76b8f  vs_stat_schedule_exec.txt
fdc7b01f7548b66402218dd17a97bd278fd02b430f43d33ea8d1d0d7bacc03be  vs_stat_schedule_pty.txt
731b87c10f457364503c3141183129ce997a0af52cade3d16a4c25eb66b9e34e  vs_stat_stored_pool_exec.txt
bfd864232de818c591ff36fc9493aade6293d7c0bab72247f3843b78a157f7d4  vs_stat_stored_pool_offwindow_exec.txt
```
