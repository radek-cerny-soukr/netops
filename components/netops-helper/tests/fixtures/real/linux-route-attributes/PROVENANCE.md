# Linux route attributes

Captured on 2026-11-22 on Debian 13 under WSL with iproute2 6.15.0.
The WSL host route tables were inspected read-only. The files here came from
a separate network namespace created with `unshare -rn`.

```sh
ip link add dummy0 type dummy
ip addr add 192.0.2.2/24 dev dummy0
ip link set dummy0 up
ip nexthop add id 41 via 192.0.2.1 dev dummy0
ip route add default nhid 41 proto static metric 100 mtu 1400 advmss 1360
ip route add 198.51.100.0/24 via 192.0.2.3 dev dummy0 proto static onlink
ip route add 203.0.113.0/24 table 100 via 192.0.2.1 dev dummy0 proto static mtu 1450
ip route show > routes-ipv4.txt
ip route show table all > routes-ipv4-all.txt
ip -6 route show table all > routes-ipv6.txt
ip nexthop > nexthops.txt
```

`tests/support/anonymize_fixture.py --check` anonymized generated link-local
IPv6 addresses. Explicit IPv4 `--keep` values preserve the documentation
addresses and their prefix alignment. Trailing spaces were removed.
`routes-ipv4.txt` is the Helper catalogue output. The other files document
the attribute syntax and the kernel's nexthop object.
