# VRF blue captures for review

Read on Cisco IOL XE 17.18.2 with the pinned host key and the netops-ro account.

- `vrf_cef` comes from `show ip cef vrf blue PEER detail`. The IPv4 subnet and peer were mapped to the documentation range used in `vrf_rib`. The transient adjacency reference was zeroed.
- `vrf_ip_interface` comes from `show ip interface Ethernet0/2`. The interface address was mapped to the same documentation subnet.
