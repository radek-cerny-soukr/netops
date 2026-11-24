"""1.0.13 A3: the FortiOS simulator for firewall address6, firewall addrgrp6 and router static6.

Built on fake_fortios_tables (show omits defaults, edit is an upsert, -23 for a referenced object) with the layout the
check account read on FortiGate-60F 7.6.8 build3744 (fixtures/fortios_a3, PROVENANCE.md):

- ``firewall address6`` holds ``all`` (::/0, shown with its uuid only) and ``none`` (``set ip6 ::/128``); an object
  gets a uuid when it is created, show prints ``uuid`` first and omits ``type ipprefix`` and ``ip6 ::/0``;
- ``firewall addrgrp6`` starts empty; members are printed in quotes;
- ``router static6`` holds route 1, the IPv6 default route (show omits ``dst ::/0``) through ``wan1``, the interface
  that carries the management path; show omits ``status enable``, ``distance 10``, ``gateway ::`` and
  ``blackhole disable``; a blackhole route is shown with ``set vrf 0`` (fixtures/fortios_a3/show-router-static6-blackhole.txt);
- ``wan1`` has an IPv6 address in its ``config ipv6`` section;
- policy 7 matches ``srcaddr6``/``dstaddr6`` ``all`` (active), as on the lab device.
"""
from __future__ import annotations

import re

from fake_fortios import quoted
from fake_fortios_tables import FakeFortiOSTables, FakeFortiOSTablesWebhook, Table

from netops_auditor import l1_fortios

ADDRESS6, GROUP6, ROUTE6 = "firewall address6", "firewall addrgrp6", "router static6"
WAN1_IPV6 = "2001:db8:1::2/64"
WAN1_GATEWAY = "2001:db8:1::1"
IDENTIFIED = (ADDRESS6, GROUP6)


def a3_tables():
    tables = {
        ADDRESS6: Table(defaults={"type": "ipprefix", "ip6": "::/0", "start-ip": "::", "end-ip": "::"},
                        quoted_names=("comment", "fqdn"),
                        order=("uuid", "type", "ip6", "start-ip", "end-ip", "fqdn", "comment")),
        GROUP6: Table(quoted_names=("member", "comment"), order=("uuid", "member", "comment"), print_empty=True),
        ROUTE6: Table(defaults={"status": "enable", "dst": "::/0", "gateway": "::", "distance": "10",
                                "blackhole": "disable"},
                      quoted_names=("device", "comment"), numeric_keys=True,
                      order=("status", "dst", "gateway", "device", "distance", "comment", "blackhole", "vrf")),
    }
    tables[ADDRESS6].objects["all"] = {"attrs": {"uuid": "00000000-0000-4000-8000-00005e005301"}, "children": {}}
    tables[ADDRESS6].objects["none"] = {"attrs": {"uuid": "00000000-0000-4000-8000-00005e005302", "ip6": "::/128"},
                                        "children": {}}
    tables[ROUTE6].objects["1"] = {"attrs": {"gateway": WAN1_GATEWAY, "device": "wan1",
                                             "comment": "IPv6 default route"}, "children": {}}
    return tables


class A3Mixin:
    def table_lines(self, name, key=None):
        # FortiOS prints a comment as one quoted string ("netops A3 test"), not one quoted word per token
        lines = super().table_lines(name, key)
        return [re.sub(r'^(\s+set comment )(".*")$', lambda m: m[1] + quoted(" ".join(l1_fortios.tokenize(m[2]))),
                       line) for line in lines]

    def _a3_init(self):
        self.policies["7"] = {"name": "ipv6-to-wan", "srcintf": "port1", "dstintf": "wan1",
                              "srcaddr6": "all", "dstaddr6": "all", "schedule": "always", "service": "ALL"}
        self.services.setdefault("ALL", {})

    def _identify(self):
        # FortiOS gives a new address6/addrgrp6 object a uuid, printed first
        for name in IDENTIFIED:
            for item in self.tables[name].objects.values():
                if "uuid" not in item["attrs"]:
                    item["attrs"] = {"uuid": self._uuid(), **item["attrs"]}
        # a blackhole route shows "set vrf 0" after blackhole (FortiOS 7.6.8, show and show full-configuration);
        # a route through a device has no vrf line
        for item in self.tables[ROUTE6].objects.values():
            attrs = item["attrs"]
            attrs.pop("vrf", None)
            if attrs.get("blackhole") == "enable":
                attrs["vrf"] = "0"

    def _a3_snapshot(self, text):
        # the IPv6 address of wan1 (config ipv6 below the interface)
        return text.replace('    edit "wan1"\n    next\n',
                            '    edit "wan1"\n        config ipv6\n            set ip6-address %s\n'
                            '        end\n    next\n' % WAN1_IPV6, 1)


class FakeFortiOSA3(A3Mixin, FakeFortiOSTables):
    """FortiOS 7.6.8 build3744 (cli-script safeguard) with the A3 tables."""

    def __init__(self, tables=None):
        super().__init__(a3_tables() if tables is None else tables)
        self._a3_init()

    def snapshot(self):
        return self._a3_snapshot(super().snapshot())

    def _run(self, lines, automatic=False):
        done = super()._run(lines, automatic)
        self._identify()
        return done


class FakeFortiOSA3Webhook(A3Mixin, FakeFortiOSTablesWebhook):
    """FortiOS 8.0.2 build0251 (webhook safeguard) with the A3 tables."""

    def __init__(self, tables=None):
        super().__init__(a3_tables() if tables is None else tables)
        self._a3_init()

    def snapshot(self):
        return self._a3_snapshot(super().snapshot())

    def _run(self, lines, automatic=False):
        done = super()._run(lines, automatic)
        self._identify()
        return done

