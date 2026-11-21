# FortiGate-60F, FortiOS 7.6.8 build3744

2026-11-20, task netops-20261120-679, one pinned SSH session for each of `netops-test-ro` and `netops-test-rw`.
The read-only account supplied the object-specific `show firewall vip`, `show firewall ippool` and
`show firewall policy` replies. The capture and acceptance harness is under `task-evidence/g23/`.
`anonymize-captures.py` uses `components/netops-helper/tests/support/anonymize_fixture.py` to replace the
interface and the mapped test-host IP, and assigns fixture UUIDs. The object names, ports and documentation IPs
belong to the test. The absence replies are unmodified apart from the trailing newline.

The unit test derives truncated and contradictory replies from those files to test completeness. Its
VIP-group setup follows [Fortinet's CLI example](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/157796/configuring-vip-groups)
with the captured VIP as the member. The lab's VIP group table was empty.
