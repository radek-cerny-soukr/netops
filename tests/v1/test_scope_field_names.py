import types
import unittest

from netops_helper import proxy

EGRESS = {"allow_dns": True, "allow_icmp": True, "tcp_ports": [22], "tcp_port_ranges": [], "udp_ports": [], "udp_port_ranges": [],
          "tls_server_names": []}


def section(platform="fortinet", queries=("system_status", "route_lookup", "policy_lookup_ipv4"), egress=None,
            **inventory):
    return types.SimpleNamespace(
        egress=dict(EGRESS, **(egress or {})), ssh_platform=platform, enabled_queries=set(queries),
        catalog_platform=lambda: platform, read_inventory=inventory, sftp_roots=["/data"])


def refusal(tool, args, sect, entry=None):
    with unittest.TestCase().assertRaises(proxy.PolicyScopeError) as caught:
        proxy.Proxy._authorize_tool(tool, args, entry or types.SimpleNamespace(port=22, address="192.0.2.1"), sect)
    return caught.exception.data


POLICY = {"src_ip": "192.0.2.1", "src_port": "1000", "dst_ip": "192.0.2.2", "dst_port": "443",
          "protocol": "6", "device": "wan1", "pol_type": "policy"}
POLICY_INVENTORY = {"addresses": ["192.0.2.1", "192.0.2.2"], "flow_ports": ["1000", "443"], "ip_protocols": ["6"],
                    "interfaces": ["wan1"], "policy_types": ["policy"]}


def ssh(parameters, **changes):
    inventory = dict(POLICY_INVENTORY, **changes)
    return refusal("ssh_read", {"platform": "fortinet", "query": "policy_lookup_ipv4", "parameters": parameters},
                   section(**inventory))


class ScopeFieldsTest(unittest.TestCase):
    def test_second_slot_of_the_same_category_is_named(self):
        data = ssh(POLICY, addresses=["192.0.2.1"])
        self.assertEqual(data, {"field": "addresses", "parameter": "dst_ip", "parameters": ["dst_ip"]})
        data = ssh(POLICY, addresses=["192.0.2.2"])
        self.assertEqual(data["parameter"], "src_ip")

    def test_every_refused_parameter_is_collected_and_values_never_returned(self):
        data = ssh(dict(POLICY, device="wan9", pol_type="x"))
        self.assertEqual(data["parameters"], ["device", "pol_type"])
        self.assertEqual(data["parameter"], "device")
        data = ssh(POLICY, flow_ports=[])
        self.assertEqual(data["parameters"], ["src_port", "dst_port"])
        text = repr(ssh(dict(POLICY, device="wan9"), addresses=[]))
        for value in ("wan9", "192.0.2.2", "1000"):
            self.assertNotIn(value, text)

    def test_query_platform_and_parameter_set(self):
        args = {"platform": "fortinet", "query": "policy_lookup_ipv4", "parameters": POLICY}
        self.assertEqual(refusal("ssh_read", args, section(queries=("system_status",), **POLICY_INVENTORY)),
                         {"field": "enabled_queries"})
        self.assertEqual(refusal("ssh_read", args, section(platform="linux", **POLICY_INVENTORY)),
                         {"field": "platform"})
        missing = dict(args, parameters={k: v for k, v in POLICY.items() if k != "device"})
        self.assertEqual(refusal("ssh_read", missing, section(**POLICY_INVENTORY)), {"field": "parameters"})
        extra = dict(args, parameters=dict(POLICY, extra="x"))
        self.assertEqual(refusal("ssh_read", extra, section(**POLICY_INVENTORY)), {"field": "parameters"})

    def test_egress_and_paths(self):
        self.assertEqual(refusal("dns_probe", {}, section(egress={"allow_dns": False})), {"field": "egress"})
        self.assertEqual(refusal("icmp_probe", {}, section(egress={"allow_icmp": False})), {"field": "egress"})
        self.assertEqual(refusal("tcp_probe", {"port": 80}, section()), {"field": "egress"})
        self.assertEqual(refusal("sftp_stat", {"remote_path": "/etc/passwd"}, section()), {"field": "sftp_roots"})

    def test_other_tools_name_the_refused_field(self):
        diag = {"recipe": "ping", "address": "192.0.2.2", "interface": "wan1"}
        inventory = {"diagnostic_recipes": ["ping"], "addresses": ["192.0.2.2"], "interfaces": ["wan1"]}
        self.assertEqual(refusal("fortios_diagnostics", diag, section(**dict(inventory, interfaces=[]))),
                         {"field": "interfaces"})
        self.assertEqual(refusal("fortios_diagnostics", diag, section(platform="fortiadc", **inventory)),
                         {"field": "platform"})
        self.assertEqual(refusal("fortios_diagnostics", diag, section(queries=(), **inventory)),
                         {"field": "enabled_queries"})
        self.assertEqual(refusal("fortios_diagnostics", dict(diag, vdom="x"), section(**inventory)),
                         {"field": "diagnostic_vdoms"})
        self.assertEqual(refusal("schema_read", {"path": "system interface"}, section(schema_paths=[])),
                         {"field": "schema_paths"})
        self.assertEqual(refusal("triage_routing", {"address": "192.0.2.9"}, section(addresses=[])),
                         {"field": "addresses"})
        self.assertEqual(refusal("config_read", {"platform": "fortios"}, section(config_access=["compare"])),
                         {"field": "config_access"})
        slb = {"virtual_server": "vs1"}
        queries = proxy.TRIAGE_SLB_REQUIRED_QUERIES
        base = dict(config_access=["read"], adc_virtual_servers=["vs1"], adc_vdoms=["root"])
        self.assertEqual(refusal("triage_slb", slb, section(platform="fortiadc", queries=queries,
                                                           **dict(base, adc_virtual_servers=[]))),
                         {"field": "adc_virtual_servers"})
        self.assertEqual(refusal("triage_slb", slb, section(platform="fortiadc", queries=queries[:1], **base)),
                         {"field": "enabled_queries"})

    def test_fortiadc_diagnostics_name_the_refused_field(self):
        inventory = {"diagnostic_recipes": ["ping", "health_check_verify", "session_list"], "addresses": ["192.0.2.2"],
                     "adc_health_checks": ["HC1"], "diagnostic_virtual_servers": ["vs1"]}
        adc = {"recipe": "ping", "address": "192.0.2.2", "interface": ""}

        def fields(args, queries=("system_status",), egress=None, **changes):
            return refusal("fortios_diagnostics", args,
                           section(platform="fortiadc", queries=queries, egress=egress, **dict(inventory, **changes)))

        self.assertEqual(fields(adc, queries=()), {"field": "enabled_queries"})
        self.assertEqual(fields(adc, diagnostic_recipes=[]), {"field": "diagnostic_recipes"})
        self.assertEqual(fields(adc, addresses=[]), {"field": "addresses"})
        self.assertEqual(fields(dict(adc, recipe="health_check_verify", health_check="HC9")),
                         {"field": "adc_health_checks"})
        self.assertEqual(fields(adc, egress={"allow_icmp": False}), {"field": "egress"})
        logs = {"recipe": "session_list", "address": "vs9", "interface": ""}
        self.assertEqual(refusal("fortios_diagnostics", logs, section(platform="fortinet", **inventory)),
                         {"field": "platform"})

    def test_config_and_schema_tools_name_the_refused_field(self):
        self.assertEqual(refusal("config_read", {"platform": "fortiadc"}, section(config_access=["read"])),
                         {"field": "platform"})
        self.assertEqual(refusal("config_read", {"platform": "other"}, section(config_access=["read"])),
                         {"field": "platform"})
        self.assertEqual(refusal("config_diff", {"platform": "fortios"}, section(config_access=["read"])),
                         {"field": "config_access"})
        self.assertEqual(refusal("config_read", {"platform": "fortios"}, section(config_access=["read"]),
                                 types.SimpleNamespace(port=2222)), {"field": "egress"})
        self.assertEqual(refusal("schema_read", {"path": "system"}, section(platform="fortiadc", schema_paths=["system"])),
                         {"field": "platform"})
        self.assertEqual(refusal("schema_read", {"path": "system"}, section(queries=(), schema_paths=["system"])),
                         {"field": "enabled_queries"})

    def test_accepted_calls_do_not_raise(self):
        proxy.Proxy._authorize_tool("schema_read", {"path": "system"}, None,
                                    section(queries=("system_status",), schema_paths=["system"]))
        proxy.Proxy._authorize_tool(
            "ssh_read", {"platform": "fortinet", "query": "policy_lookup_ipv4", "parameters": POLICY}, None,
            section(**POLICY_INVENTORY))


class FortiADCRequestTest(unittest.TestCase):
    def test_log_and_state_recipes_reach_forwarding_and_unlisted_vs_is_refused(self):
        import json
        from unittest.mock import Mock

        recipes = ("system_event_logs", "waf_attack_logs", "session_list", "persistence_list")
        sect = section(platform="fortiadc", diagnostic_recipes=list(recipes),
                       diagnostic_virtual_servers=["vs1"], addresses=[])
        sect.rate_limit = {}
        entry = types.SimpleNamespace(port=22, address="192.0.2.1", credential="fixture")
        gateway = proxy.Proxy()
        gateway._target = Mock(return_value=(entry, sect, {}))
        gateway._credential = Mock(return_value=None)
        gateway._snmp_usm = Mock(return_value=None)
        gateway._auth_context = Mock(return_value="fixture-context")
        gateway._consume_rate_limit = Mock()
        gateway._session_secrets = Mock(return_value=())
        emitted = []
        gateway._emit = emitted.append

        def request(identifier, recipe, address, validate=True):
            args = {"target": "adc1", "recipe": recipe, "address": address, "interface": ""}
            if validate:
                self.assertEqual(gateway._validate_tool_arguments("fortios_diagnostics", dict(args)), args)
            raw = json.dumps({"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                              "params": {"name": "fortios_diagnostics", "arguments": args}}).encode()
            return gateway.request(raw)

        for index, recipe in enumerate(recipes):
            with self.subTest(recipe=recipe):
                forwarded = request(index, recipe, "vs1" if recipe.endswith("_list") else "")
                self.assertIsNotNone(forwarded)
                self.assertEqual(json.loads(forwarded)["params"]["arguments"]["recipe"], recipe)
        for index, recipe in enumerate(("session_list", "persistence_list"), 10):
            with self.subTest(recipe=recipe):
                self.assertIsNone(request(index, recipe, "vs9"))
                self.assertEqual(emitted[-1]["error"]["code"], -32009)
                self.assertEqual(emitted[-1]["error"]["data"],
                                 {"category": "policy_scope", "field": "diagnostic_virtual_servers"})
                self.assertNotIn("vs9", json.dumps(emitted[-1]))
        refused = (
            ("diagnostic_recipes", dict(diagnostic_recipes=[])),
            ("enabled_queries", dict(queries=())),
            ("platform", dict(platform="fortinet")),
        )
        for field, changes in refused:
            for index, recipe in enumerate(recipes):
                with self.subTest(field=field, recipe=recipe):
                    self.sect = section(**dict(dict(platform="fortiadc", diagnostic_recipes=list(recipes),
                                                    diagnostic_virtual_servers=["vs1"], addresses=[]), **changes))
                    self.sect.rate_limit = {}
                    gateway._target.return_value = (entry, self.sect, {})
                    self.assertIsNone(request(20 + index, recipe, "vs1" if recipe.endswith("_list") else ""))
                    self.assertEqual(emitted[-1]["error"]["code"], -32009)
                    self.assertEqual(emitted[-1]["error"]["data"]["field"], field)
        for index, recipe in enumerate(("system_event_logs", "waf_attack_logs"), 30):
            with self.subTest(recipe=recipe, address="vs1"):
                gateway._target.return_value = (entry, sect, {})
                self.assertIsNone(request(index, recipe, "vs1", validate=False))
                self.assertEqual(emitted[-1]["error"]["code"], -32602)
