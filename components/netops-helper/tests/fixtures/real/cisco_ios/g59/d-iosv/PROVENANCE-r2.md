# VRF blue captures for review 674-r2

Read on d-iosv from PC-Radek with the pinned host key and the netops-ro account.

- `vrf_cef` comes from `show ip cef vrf blue PEER detail`. The IPv4 subnet and peer were mapped to the documentation range used in `vrf_rib`. The transient adjacency reference was zeroed.
- The ingress interface capture is reused from `cisco_ios/g55/d-iosv-acl_port.out`.
