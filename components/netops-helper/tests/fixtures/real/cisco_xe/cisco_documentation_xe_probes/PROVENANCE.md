# Cisco IOS / IOS XE traceroute documentation

- `trace_alternate_ip.out` derives from the R1-to-R2 loopback trace in the **Demonstration** section of Cisco's [Traceroute behavior on Cisco routers IOS/IOS-XE](https://community.cisco.com/t5/networking-knowledge-base/traceroute-behavior-on-cisco-routers-ios-ios-xe/ta-p/3163669). It uses the first measurement of the single hop to match xe probes's one probe per hop.
- `trace_mpls_label.out` derives from the initial failed traceroute in Cisco's [Verify MPLS Layer 3 VPN Forwarding](https://www.cisco.com/c/en/us/support/docs/multiprotocol-label-switching-mpls/mpls/220921-verify-mpls-layer-3-vpn-forwarding.html). The capture retains five hops to match xe probes's TTL limit.
- `trace_mpls_stack.out` derives from the four-hop successful traceroute in the forwarding path section of the same Cisco document. The two-label stack uses substitute label values.

These are vendor documentation examples. IPv4 addresses were mapped to RFC 5737 networks. The test transport supplies the command echo and final prompt.
