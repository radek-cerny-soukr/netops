# IOS XE 17.18.2 probe captures

Captured on 2026-11-18 from GNS3 Cisco IOL XE 17.18.2 (IOL XE 17.18.2 fc3) with pinned OpenSSH, using an interactive EXEC session. The files contain the command bodies between the echo and prompt. The fixture named `loopback4_ping` uses Loopback0. The other global-table source captures use Ethernet0/1.10 and the VRF source captures use Ethernet0/2. The `loss` cases use an unused destination on the blue link. The `bad_vrf` and `bad_source` files use an absent VRF and interface on the privileged account. Files prefixed `ro_` were captured with the lab read-only account, which rejects extended probes. The tests reuse the real xe routing `version.out` for the same IOL XE release.

The fixture output was anonymized as one batch, with trailing horizontal whitespace trimmed with `tests/support/anonymize_fixture.py --check`. Destinations are in RFC 5737 and RFC 3849 space. The unit tests derive their incomplete samples by removing measured lines or appending a pager marker.

verification re-captured the `ping_bad_source` and `trace_bad_source` rejection bodies on Cisco IOL XE 17.18.2 and captured `show_privilege_admin.out` from `show privilege` in the same login. The privilege test also derives a lower-level response from this file to verify the handling of unconfirmed authorization.

Independent syntax references are Cisco's [ping command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/monitor_event-trace_through_Q.html) and [traceroute command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/Cisco_IOS_Configuration_Fundamentals_Command_Reference/test_cable-diagnostics_through_xmodem.html). The live EXEC captures establish the exact inline forms.
