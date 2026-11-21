# IOS XE G71 lab captures

Captured 2026-11-19 on GNS3 IOL-L2 and IOL (both IOS XE 17.18.2) over pinned
SSH with `netops-admin` (privilege 15) and `netops-ro` (privilege 1). The
fixtures preserve CLI response bodies, with terminal echo, prompt and paging
markers removed. Identifiers were replaced with `tests/support/anonymize_fixture.py`.
An empty file is an empty CLI response. The connected IOL-L2 ports with CDP/LLDP
use Ethernet0/0. Its active scoped STP example used Ethernet2/0.
On the router, the scoped neighbor examples with actual entries use Ethernet0/1
(LLDP) and Ethernet0/2 (CDP).
