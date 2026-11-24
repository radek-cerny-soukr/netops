# Juniper CLI reference excerpts

- `dhcp_server_details.out` retains selected fields from the ACI Interface Set Configured sample. The fixture anonymizer replaces the client address. [Juniper DHCP server binding](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-dhcp-server-binding-command.html)
- `dns_answer.out` comes from the forward lookup sample. [Juniper show host](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-host.html)

The priority and subsecond selector test derives its timestamp and priority shape from the two Juniper logging examples. It uses interface tokens in the message body to exercise exact filtering. [Timestamp and priority format](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging.html) · [Explicit timestamp example](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-option-logging-events-firewall-facility.html)

- `dhcp_relay_statistics_ex.out` is the EX Series example with the CLI prompt removed. [Juniper DHCP relay statistics](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-dhcp-relay-statistics.html)
- `snmp_statistics_output_traps.out` is the documented example with the CLI prompt and trailing blank lines removed. [Juniper SNMP statistics](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-snmp-statistics.html)
- The test responses to `| count` are derived from the corresponding fixtures and use the documented `Count: N lines` framing. [Junos CLI User Guide, Counting the Number of Lines of Output](https://www.juniper.net/documentation/us/en/software/junos/cli/cli.pdf)
- The SSH error regression keeps the chronological prefix of the real `log_messages.admin.txt` capture in `vjunosswitch_26.2R1.7` and adds two same-second rows from the review reproduction and one fallback case. Their login, credential and address are test data. The review reproduction is a private record (not published).
