# nxos forwarding path Nexus 9300v captures

Captured from Nexus 9300v, NX-OS 9.3(12) and nexus-peer-a with the lab read-only account on 2026-11-19 (NX-OS 9.3(12)). The existing anonymizer remapped addresses, MACs and host identities in one batch. Trailing whitespace and the decorative FIB slot underline were removed.

| Suffix | Command | Nexus 9300v, NX-OS 9.3(12) rc | nexus-peer-a rc |
|---|---|---|---|
| version | `show version` | 0 | 0 |
| port | `show interface Ethernet1/2` or `show interface Port-channel128` | 0 | 0 |
| rib | `show ip route <destination>` | 0 | 0 |
| stp | `show spanning-tree interface <interface> detail` | 0 | 0 |
| lldp | `show lldp neighbors interface <interface> detail` | 244 | 16 |
| vpc | `show vpc brief` | — | 0 |
| fib | `show forwarding ipv4 route` | 244 | 244 |
| acl | `show ip access-lists summary` | 0 | 0 |
| arptable | `show ip arp` | 0 | — |

Tests derive an incomplete lookup by removing the best next-hop line from Nexus 9300v, NX-OS 9.3(12) RIB output. Its original prefix and reported path count are preserved.
