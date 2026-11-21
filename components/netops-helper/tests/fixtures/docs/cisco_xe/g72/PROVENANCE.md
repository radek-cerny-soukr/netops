# Cisco examples for G72

The fixtures retain the operational fields used by the assertions. Unneeded
rows and fields are omitted and IP addresses and serial numbers are anonymized.

- `environment.out` — Catalyst 9300 IOS XE 17.15, **show environment**. [Cisco command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/interface_and_hardware_commands.html)
- `platform_resources.out` — Catalyst 9600 IOS XE 17.9, **show platform resources**. [Cisco command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9600/software/release/17-9/command_reference/b_179_9600_cr/interface_and_hardware_commands.html)
- `hsrp_detail.out` — IOS XE Catalyst SD-WAN 17.x, standby router with tracked object. [Cisco HSRP guide](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/17-x/systems-interfaces/systems-interfaces-guide-17-x/hot-standby-router-protocol.html)
- `vrrp_detail.out` — IOS XE 17.x, VRRP Object Tracking Verification. [Cisco VRRP guide](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ntw-servs/b-network-services/m_fhp-vrrp-0.html)
- `vrrp3_detail.out` — IOS XE Catalyst SD-WAN 17.x, VRRP Interface Tracking verification. [Cisco systems and interfaces guide](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/17-x/systems-interfaces/systems-interfaces-guide-17-x.pdf)
- `object_tracking.out` — IOS XE, track object with IP SLA state. [Cisco Enhanced Object Tracking guide](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/ip-addressing/ip-addressing/m_iap-eot-xe.html)
- `ntp_status.out` — IOS XE 17.x, Verifying Network Time Protocol. [Cisco NTP guide](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/m_bsm-time-calendar-set.html)
- `ntp_associations.out` — IOS and IOS XE, example with multiple peers. [Cisco command output](https://www.cisco.com/c/en/us/support/docs/technical-details/220303-verify-ntp-status-with-the-show-ntp-asso.html)

The log interface regression uses the separately captured IOSv
`iosv_15.9.3M12/log_messages.admin.txt` in this repository. Its link-event
interface indices are adapted to the enrolled Catalyst interface syntax.
Other derived cases remove a required device line, append a pager marker,
alter the clock, or substitute a made-up HSRP credential canary.
