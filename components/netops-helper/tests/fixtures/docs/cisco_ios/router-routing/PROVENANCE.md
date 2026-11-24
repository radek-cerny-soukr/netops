# router routing vendor examples

Retrieved 2026-11-17 from Cisco command references; factual CLI output only. All text fixtures processed by `tests/support/anonymize_fixture.py --check`. Not live measurements. Ellipses in BGP neighbor are present in Cisco's example. Route-map is one complete sequence excerpt from a multi-sequence output. No output syntax was invented.

| Fixtures | Source |
|---|---|
| bgp_neighbor, bgp_prefix, bgp_advertised_routes | https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/command/irg-cr-book/bgp-s1.html (examples at lines 2655–2675, 309–320, 2534–2540 as retrieved) |
| ipv6_route_table | https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-s5.html (392–412) |
| ipv6_interface_details | https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-s2.html (2133–2152) |
| bgp_ipv6_summary | https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-s1.html (961–964) |
| ospfv3_neighbors | https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-s4.html (2203–2206) |
| bfd_neighbors, route_maps | https://www.cisco.com/c/en/us/td/docs/ios/iproute_pi/command/reference/iri_book/iri_pi2.html (1826–1873, 5298–5314) |
| vrfs, vrf_ip_interfaces | https://www.cisco.com/c/en/us/td/docs/ios/qos/command/reference/qos_book/qos_s3.html (8114–8127, 8186–8199) |
| ip_interface_secondary | https://www.cisco.com/en/US/docs/ios/security/command/reference/sec_i2.pdf (show ip interface ethernet 0 example, SEC-1313) |

The test reuses the existing IOS route lookup documentation fixture and measured IOSv ARP fixture for the shared body syntax of VRF replies; this does not qualify live VRF operation. `bgp_routes` currently has a real inactive-process negative only; a configured received-routes example is still required.
