"""1.0.13 A1-S: the lab FortiGate-60F 7.6.8 build3744 for the service tables (system dhcp server and its address
ranges, system dns, log syslogd setting) on top of fake_fortios_tables.

The shape and the defaults come from the check account captures of fixtures/fortios_a1 (see PROVENANCE.md): show omits
an attribute at its default (show full-configuration prints it), a DHCP server without range has no ``config
ip-range``, syslogd prints an empty section while disabled. The interfaces carry the static subnets the DHCP checks
read (the base fake lists bare interface names only); the DHCP server 2 matches FortiSwitch and FortiExtender by VCI
as the lab server of the FortiLink interface does (an excluded attribute).
"""
from __future__ import annotations

import re

from fake_fortios_tables import FakeFortiOSTables, FakeFortiOSTablesWebhook, Table

SERVER, RANGE, DNS, SYSLOG = "system dhcp server", "system dhcp server/ip-range", "system dns", "log syslogd setting"
VLAN = "netops-a1s"
SERVER_DEFAULTS = {"status": "enable", "lease-time": "604800", "dns-service": "specify", "ntp-service": "specify",
                   "timezone-option": "disable", "server-type": "regular"}
# measured: show full-configuration log syslogd setting with status enable (fixtures/fortios_a1/syslogd-enabled-full.txt);
# the whole show omits the section while every attribute holds its default (syslogd-initial*.txt print it alone)
SYSLOG_DEFAULTS = {"status": "disable", "server": "", "mode": "udp", "port": "514", "facility": "local7",
                   "format": "default", "source-ip": ""}
DNS_DEFAULTS = {"primary": "0.0.0.0", "secondary": "0.0.0.0", "protocol": "cleartext", "ip6-primary": "::",
                "ip6-secondary": "::"}
SERVER_ORDER = ("status", "lease-time", "dns-service", "ntp-service", "default-gateway", "netmask", "interface",
                "start-ip", "end-ip", "timezone-option", "vci-match", "vci-string")
# name -> (ip, mode, status); wan1 takes its address by DHCP (the management path of the lab)
INTERFACES = {
    "wan1": (None, "dhcp", "up"),
    "internal": ("198.51.100.99 255.255.255.0", "static", "up"),
    "fortilink": ("203.0.113.1 255.255.255.0", "static", "up"),
    VLAN: ("192.0.2.1 255.255.255.0", "static", "down"),
}


def tables(server=True, cleartext=True, syslog=False):
    """The service tables of the lab: DHCP servers 1 (internal) and 2 (fortilink, VCI matching), the test server 7
    on the test VLAN (disabled, one range) when ``server``; DNS in cleartext (the lab after the preparation of the
    live run) or over TLS; syslogd disabled (all defaults) or, with ``syslog``, enabled with one server as in the lab
    before the live syslog run."""
    result = {
        SERVER: Table(defaults=SERVER_DEFAULTS, quoted_names=("interface", "vci-string"),
                      children=("ip-range", "reserved-address"), numeric_keys=True, order=SERVER_ORDER),
        DNS: Table("singleton", defaults=DNS_DEFAULTS, quoted_names=("server-hostname",)),
        SYSLOG: Table("singleton", defaults=SYSLOG_DEFAULTS, quoted_names=("server",)),
    }
    servers = result[SERVER].objects
    servers["1"] = {"attrs": {"dns-service": "default", "default-gateway": "198.51.100.99", "netmask": "255.255.255.0",
                              "interface": "internal"},
                    "children": {"ip-range": {"1": {"start-ip": "198.51.100.110", "end-ip": "198.51.100.210"}}}}
    servers["2"] = {"attrs": {"dns-service": "local", "ntp-service": "local", "default-gateway": "203.0.113.1",
                              "netmask": "255.255.255.0", "interface": "fortilink", "vci-match": "enable",
                              "vci-string": "FortiSwitch FortiExtender"},
                    "children": {"ip-range": {"1": {"start-ip": "203.0.113.2", "end-ip": "203.0.113.254"}}}}
    if server:
        servers["7"] = {"attrs": {"status": "disable", "default-gateway": "192.0.2.1", "netmask": "255.255.255.0",
                                  "interface": VLAN},
                        "children": {"ip-range": {"1": {"start-ip": "192.0.2.100", "end-ip": "192.0.2.150"}}}}
    result[DNS].attrs.update(primary="198.51.100.53", secondary="198.51.100.54", protocol="cleartext")
    if not cleartext:
        result[DNS].attrs.update(protocol="dot", **{"server-hostname": "dns.example.invalid"})
    if syslog:
        result[SYSLOG].attrs.update(status="enable", server="192.0.2.80")
    return result


class InterfacesMixin:
    """The system interface section with the static subnets of the lab (name, ip, mode, status)."""

    interface_rows = INTERFACES

    def interfaces_section(self):
        lines = ["config system interface"]
        for name, (ip, mode, status) in self.interface_rows.items():
            lines.append('    edit "%s"' % name)
            lines.append('        set vdom "root"')
            if mode != "static":
                lines.append("        set mode " + mode)
            if ip:
                lines.append("        set ip " + ip)
            if status != "up":
                lines.append("        set status " + status)
            lines.append("    next")
        return "\n".join(lines + ["end"]) + "\n"

    def with_interfaces(self, text):
        return re.sub(r"config system interface\n(?:    .*\n)*?end\n", lambda _m: self.interfaces_section(), text,
                      count=1)


def omit_default_singletons(device, text):
    """The whole show of FortiOS 7.6.8 omits a singleton section whose attributes all hold their defaults (measured:
    log syslogd setting while disabled); show <table> still prints the empty section."""
    for name, table in device.tables.items():
        if table.kind == "singleton" and all(table.defaults.get(attr) == value for attr, value in table.attrs.items()):
            text = text.replace("config %s\nend\n" % name, "")
    return text


class FakeFortiOSA1(InterfacesMixin, FakeFortiOSTables):
    def __init__(self, server=True, cleartext=True, syslog=False):
        super().__init__(tables(server, cleartext, syslog))
        self.interface_rows = dict(INTERFACES)

    def snapshot(self):
        return omit_default_singletons(self, self.with_interfaces(super().snapshot()))


class FakeFortiOSA1Webhook(InterfacesMixin, FakeFortiOSTablesWebhook):
    def __init__(self, server=True, cleartext=True, syslog=False):
        super().__init__(tables(server, cleartext, syslog))
        self.interface_rows = dict(INTERFACES)

    def snapshot(self):
        return omit_default_singletons(self, self.with_interfaces(super().snapshot()))
