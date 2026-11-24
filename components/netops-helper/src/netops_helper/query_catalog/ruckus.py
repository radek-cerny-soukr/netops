"""Curated Ruckus Unleashed diagnostic queries (phase 1 on Ruckus Unleashed 200.13; wireless inventory client, radio, AP and WLAN
reads, wireless path bounded ping from the master AP and wireless network services ACL, AAA, DHCP relay and static route reads, measured on R610 on
Ruckus Unleashed 200.15.6.212.27)."""

from __future__ import annotations

from .model import LITERAL, NO_SLOTS, Query, Slot


# wireless inventory: object reads take a lower-case MAC literal or an AP device name / WLAN name that is enrolled in the
# target inventory or was listed by this target in `access_points` / `wlans` (never a free string).
CLIENT_MAC = {"mac": Slot(LITERAL, "wifi_mac_literal")}
AP_MAC = {"ap_mac": Slot(LITERAL, "wifi_mac_literal")}

QUERIES: dict[str, Query] = {
    "system_info": Query(
        "show sysinfo",
        NO_SLOTS,
        "Show controller identity, model, version, and uptime.",
    ),
    "ethernet_info": Query(
        "show ethinfo",
        NO_SLOTS,
        "Show the Ethernet port state of the access point.",
    ),
    "access_points": Query(
        "show ap all",
        NO_SLOTS,
        "Summarize every access point of the Unleashed network. A successful empty output means no AP entries were reported.",
        empty_allowed=True,
        high_volume=True,
    ),
    "wlans": Query(
        "show wlan all",
        NO_SLOTS,
        "Summarize every configured WLAN service.",
        high_volume=True,
    ),
    "clients": Query(
        "show current-active-clients all",
        NO_SLOTS,
        "List connected Wi-Fi clients with IP, host name, AP, BSSID, WLAN, VLAN, channel, radio and signal.",
        high_volume=True,
    ),
    "client_detail": Query(
        "show current-active-clients mac {mac}",
        CLIENT_MAC,
        "Show one connected client with its traffic and retry-drop counters and recent events; "
        "no client record means the client is not connected now.",
    ),
    "client_performance": Query(
        "show performance station mac {mac}",
        CLIENT_MAC,
        "Show the estimated capacity, downlink and uplink the controller reports for one client.",
    ),
    "radio_performance_24": Query(
        "show performance ap-radio2-4 mac {ap_mac}",
        AP_MAC,
        "Show 2.4 GHz radio capacity, throughput, RF pollution, authorized clients and other APs of one AP.",
    ),
    "radio_performance_5": Query(
        "show performance ap-radio5 mac {ap_mac}",
        AP_MAC,
        "Show 5 GHz radio capacity, throughput, RF pollution, authorized clients and other APs of one AP.",
    ),
    "rogue_devices": Query(
        "show rogue-devices",
        NO_SLOTS,
        "List active, known and blocked rogue devices with channel, radio, encryption, SSID and last detection.",
        high_volume=True,
    ),
    "events": Query(
        "show events",
        NO_SLOTS,
        "Show the most recent controller events and activities the device keeps.",
        high_volume=True,
    ),
    "events_activities": Query(
        "show events-activities",
        NO_SLOTS,
        "List up to 300 controller events and activities, including any recorded client, radio and authentication events.",
        high_volume=True,
    ),
    "mesh_topology": Query(
        "show mesh topology",
        NO_SLOTS,
        "Show current mesh root and member APs, channel and uplink and downlink signal as reported by Unleashed.",
        high_volume=True,
    ),
    "access_point": Query(
        "show ap mac {ap_mac}",
        AP_MAC,
        "Show one access point (radios, channel, width, power, LAN ports) selected by its MAC address.",
    ),
    "access_point_by_name": Query(
        "show ap devname {wtp_id}",
        {"wtp_id": Slot("wtp_ids", "fortios_wtp_id")},
        "Show one access point selected by a device name that is enrolled or was listed by access_points.",
    ),
    "wlan": Query(
        "show wlan name {wlan}",
        {"wlan": Slot("wlan_names", "ruckus_wlan_name")},
        "Show one WLAN service selected by a name that is enrolled or was listed by wlans.",
    ),
    # wireless path (R02): the Unleashed CLI ping has no count or time option; measured on Ruckus Unleashed 200.15.6.212.27
    # it always sends three echo requests and ends after about 12 s when nothing answers. Only an enrolled IPv4
    # literal is rendered (no host name, so no DNS lookup, and no `-s` packet size).
    "ping": Query(
        "ping {address}",
        {"address": Slot("addresses", "ipv4_address")},
        "Send the three ICMP echo requests of the Unleashed CLI from the master AP management plane to one "
        "enrolled IPv4 address; it says nothing about a client's data path.",
    ),
    # wireless network services (R10-R13): `show... all` lists of configured objects. On an unconfigured object type the device prints only
    # the section heading (or nothing for `show l3acl all`), so an empty result is "nothing configured". The bare
    # `show l3acl` is not a command (the device answers "unrecognized or incomplete"); only the `all` form is used.
    "l2_acls": Query(
        "show l2acl all",
        NO_SLOTS,
        "List the L2/MAC access control lists (name, allow or deny restriction, listed station MAC addresses). An empty output means none is configured.",
        empty_allowed=True,
        high_volume=True,
    ),
    "mgmt_acls": Query(
        "show mgmt-acl all",
        NO_SLOTS,
        "List the management access control entries that restrict who may reach the controller management interface. "
        "A heading without entries or an empty output means none is configured.",
        empty_allowed=True,
    ),
    "l3_acls": Query(
        "show l3acl all",
        NO_SLOTS,
        "List the L3/L4/IP access control lists the model provides. An empty output means none is configured.",
        empty_allowed=True,
        high_volume=True,
    ),
    "aaa_servers": Query(
        "show aaa all",
        NO_SLOTS,
        "List the AAA servers (local database, guest, RADIUS, Active Directory, LDAP) with their non-secret settings; "
        "shared secrets and passwords are withheld. An empty output means none is configured.",
        empty_allowed=True,
    ),
    "dhcp_relays": Query(
        "show dhcp all",
        NO_SLOTS,
        "List the DHCP servers defined as relay targets for WLANs (not leases or reservations). An empty output means none is configured.",
        empty_allowed=True,
    ),
    "static_routes": Query(
        "show static-route all",
        NO_SLOTS,
        "List the configured static routes of the controller management plane. An empty output means none is configured.",
        empty_allowed=True,
    ),
    "config_settings": Query(
        "show config",
        NO_SLOTS,
        "Show the common settings of the controller (IP and DNS, NTP, syslog, SNMP, AAA, management and L2 ACL, DHCP "
        "relay, static routes) from the configuration display. Every other section is withheld and every secret "
        "(PSK, RADIUS secret, passwords, SNMP communities, token) is redacted; compare two captures to see a change.",
        high_volume=True,
    ),
}
