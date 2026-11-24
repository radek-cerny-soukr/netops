# VRF blue captures for review

Read on Cisco IOSv 15.9(3)M12 with the pinned host key and the netops-ro account.

- `vrf_cef` comes from `show ip cef vrf blue PEER detail`. The IPv4 subnet and peer were mapped to the documentation range used in `vrf_rib`. The transient adjacency reference was zeroed.
- The ingress interface capture is reused from [`iosv-acl_port.out`](../../router-security/iosv-acl_port.out).
