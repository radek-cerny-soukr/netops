import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

VERIFY = Path(__file__).resolve().parents[1] / "verify_state.py"
TOKEN = "t0ken-" + "q" * 30
VAULT = "vault-" + "w" * 24


def tool(name, props=("target",), description=None):
    return {"name": name, "description": description or name + " tool",
            "inputSchema": {"type": "object", "properties": {p: {"type": "string"} for p in props}, "required": ["target"]},
            "outputSchema": {"type": "object"}}


BASE_TOOLS = [tool("helper_status", ()), tool("read_query_catalog", ("offset", "limit")), tool("ssh_read"), tool("target_scope")]
CATALOG = {"fortios": {"get_status": [], "arp_table": []}, "linux": {"kernel": [], "uptime": []}}


def fp(value):
    out = {"sha256": hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()}
    if value is None or isinstance(value, (bool, int, float)) or isinstance(value, str) and len(value) <= 64:
        out["value"] = value
    return out


def keys(**values):
    return {"/" + k.replace("__", "/"): fp(v) for k, v in values.items()}


def reply(content, error=False):
    return {"jsonrpc": "2.0", "id": 3, "result": {"structuredContent": content, "isError": error}}


def pages(catalog, size=2, total=None, sha="a" * 64):
    rows = [(p, q) for p in sorted(catalog) for q in sorted(catalog[p])]
    out = []
    for start in range(0, len(rows), size):
        part = rows[start:start + size]
        page = {"ok": True, "queries": {}, "query_metadata": {}, "total": len(rows) if total is None else total,
                "offset": start, "returned": len(part), "catalog_sha256": sha,
                "next_offset": start + size if start + size < len(rows) else None}
        for p, q in part:
            page["queries"].setdefault(p, {})[q] = catalog[p][q]
            page["query_metadata"].setdefault(p, {})[q] = {"description": q}
        out.append({"http": 200, "reply": reply(page)})
    return out


ADC_STATUS = {"device": "upgrade-adc", "run_id": 2, "findings_total": 0, "age_hours": 1.0,
              "coverage": {"complete": False,
                           "inherent_gaps": [{"rule_id": "fortiadc.tls.factory-certificate", "reason": "factory-provenance-unproven"}],
                           "actionable_gaps": [{"rule_id": "fortiadc.lb.pool-no-health-check", "reason": "visibility:networking"}]}}


def mcp(tools=None, catalog=None, scope=None, status_error=False, extra="", status=None, **page_args):
    catalog = CATALOG if catalog is None else catalog
    first = pages(catalog, 25, **page_args)[0]["reply"]
    return {"probes": {"no_token": 401, "token": 200, "wrong_token": 401},
            "calls": {"tools/list": {"http": 200, "reply": {"result": {"tools": copy.deepcopy(tools or BASE_TOOLS)}}},
                      "audit_status": {"http": 200, "reply": reply({"tenant": "default", "devices": [copy.deepcopy(ADC_STATUS), {"device": "upgrade-fw", "run_id": 1, "findings_total": 1, "age_hours": 1.0}]})},
                      "admin_status": {"http": 200, "reply": reply({"request_id": "upgrade-check-request", "change_id": "a" * 32, "status": "finished", "result": "confirmed"})},
                      "helper_status": {"http": 200, "reply": reply(dict({"ok": True, "version": "<v>", "note": extra}, **(status or {})), status_error)},
                      "target_scope": {"http": 200, "reply": reply(scope or {"target": "linux-a", "egress": "direct", "queries": ["kernel"]})},
                      "read_query_catalog": {"http": 200, "reply": first},
                      "read_query_catalog_pages": pages(catalog, **page_args),
                      "ssh_read_not_enrolled": {"http": 200, "reply": reply({"error": "not enrolled"}, True)}}}


def with_tool(name, **changes):
    tools = copy.deepcopy(BASE_TOOLS)
    for t in tools:
        if t["name"] == name:
            for path, value in changes.items():
                node = t
                keys = path.split(".")
                for k in keys[:-1]:
                    node = node[k]
                if value is None:
                    del node[keys[-1]]
                else:
                    node[keys[-1]] = value
    return tools


class ApiChanges(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_report(self, from_mcp, to_mcp, changes=None, versions=("1.0.5", "1.0.6"), raw=None):
        work, out = self.root / "work", self.root / "out"
        work.mkdir(exist_ok=True)
        out.mkdir(exist_ok=True)
        (work / "params.json").write_text(json.dumps({"FROM_IMAGE": "f", "TO_IMAGE": "t", "FROM_VERSION": "1.0.5",
                                                      "TO_VERSION": "1.0.6", "SERVER_NAME": "localhost", "PORT": "1", "NONCE": "n"}))
        (work / "from-mcp.json").write_text(json.dumps(from_mcp))
        (work / "to-mcp.json").write_text(json.dumps(to_mcp))
        (work / "to-logs.txt").write_text("log\n")
        (self.root / "token").write_text(TOKEN)
        (self.root / "vault").write_text(VAULT)
        declaration = self.root / "api-changes-1.0.5-1.0.6.json"
        declaration.unlink(missing_ok=True)
        if raw is not None:
            declaration.write_text(raw)
        elif changes is not None:
            declaration.write_text(json.dumps({"from": versions[0], "to": versions[1], "changes": changes}))
        subprocess.run([sys.executable, "-I", "-B", str(VERIFY), "report", "--work", str(work), "--out", str(out),
                        "--secret", str(self.root / "token"), "--secret", str(self.root / "vault"),
                        "--api-changes", str(declaration)], capture_output=True, text=True, timeout=60)
        doc = json.loads((out / "report.json").read_text())
        return {c["check"]: (c["result"], c["detail"]) for c in doc["checks"]}, doc, out

    def results(self, *args, **kwargs):
        checks = self.run_report(*args, **kwargs)[0]
        return checks["mcp-tools-list"], checks["mcp-role-responses"]

    def test_identical_api_without_declaration_passes(self):
        (tools, d1), (resp, d2) = self.results(mcp(), mcp())
        self.assertEqual((tools, resp), ("OK", "OK"), d1 + d2)

    def test_report_includes_nonempty_role_data_check(self):
        checks, doc, _ = self.run_report(mcp(), mcp())
        self.assertEqual(len(doc["checks"]), 19)
        self.assertIn("nonempty-auditor-admin", {c["check"] for c in doc["checks"]})
        self.assertEqual(len(checks), 19)

    def test_the_seeded_inherent_and_actionable_coverage_gaps_must_survive_the_upgrade(self):
        checks = self.run_report(mcp(), mcp())[0]
        self.assertEqual(checks["auditor-coverage-gaps-after-upgrade"][0], "OK")
        lost = mcp()
        lost["calls"]["audit_status"]["reply"]["result"]["structuredContent"]["devices"][0]["coverage"]["inherent_gaps"] = []
        self.assertEqual(self.run_report(mcp(), lost)[0]["auditor-coverage-gaps-after-upgrade"][0], "FAIL")

    def test_the_admin_seed_uses_a_result_the_admin_role_can_produce(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("populate_roles", VERIFY.parent / "populate_roles.py")
        populate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(populate)
        import inspect
        source = inspect.getsource(populate.seed_admin)
        self.assertIn('"result": "confirmed"', source)
        self.assertNotIn('"applied"', source)

    def test_undeclared_added_tool_fails(self):
        (tools, detail), _ = self.results(mcp(), mcp(BASE_TOOLS + [tool("triage_slb")]))
        self.assertEqual(tools, "FAIL")
        self.assertIn("undeclared: ['triage_slb added']", detail)

    def test_declared_added_tool_passes(self):
        change = [{"tool": "triage_slb", "kind": "added", "reason": "new read-only triage tool"}]
        (tools, detail), (resp, _) = self.results(mcp(), mcp(BASE_TOOLS + [tool("triage_slb")]), change)
        self.assertEqual((tools, resp), ("OK", "OK"), detail)

    def test_stale_added_declaration_fails(self):
        change = [{"tool": "triage_slb", "kind": "added", "reason": "new read-only triage tool"}]
        (tools, detail), _ = self.results(mcp(), mcp(), change)
        self.assertEqual(tools, "FAIL")
        self.assertIn("stale declaration: ['triage_slb added']", detail)

    def test_removed_tool_always_fails(self):
        for changes in (None, [{"tool": "ssh_read", "kind": "added", "reason": "x"}],
                        [{"tool": "ssh_read", "kind": "definition", "removed_keys": ["/name"], "reason": "x"}],
                        [{"tool": "ssh_read", "kind": "removed", "reason": "x"}]):
            with self.subTest(changes=changes):
                (tools, detail), _ = self.results(mcp(), mcp([t for t in BASE_TOOLS if t["name"] != "ssh_read"]), changes)
                self.assertEqual(tools, "FAIL")
                self.assertIn("ssh_read", detail)

    def test_undeclared_input_schema_change_fails(self):
        cases = {"added-param": with_tool("ssh_read", **{"inputSchema.properties.extra": {"type": "string"}}),
                 "removed-param": with_tool("ssh_read", **{"inputSchema.properties.target": None}),
                 "type-change": with_tool("ssh_read", **{"inputSchema.properties.target": {"type": "integer"}}),
                 "required": with_tool("ssh_read", **{"inputSchema.required": []}),
                 "output-schema": with_tool("ssh_read", **{"outputSchema": {"type": "array"}}),
                 "description": with_tool("ssh_read", description="other")}
        for name, tools in cases.items():
            with self.subTest(case=name):
                (result, detail), _ = self.results(mcp(), mcp(tools))
                self.assertEqual(result, "FAIL")
                self.assertIn("ssh_read definition", detail)

    def test_definition_change_declared_by_pointer_passes_and_only_that_pointer(self):
        tools = with_tool("ssh_read", description="new text", **{"inputSchema.properties.extra": {"type": "string"}})
        change = [{"tool": "ssh_read", "kind": "definition", "added_keys": keys(inputSchema__properties__extra={"type": "string"}),
                   "changed_keys": keys(description="new text"), "reason": "new input and description"}]
        (result, detail), _ = self.results(mcp(), mcp(tools), change)
        self.assertEqual(result, "OK", detail)
        tools[2]["inputSchema"]["required"] = []
        (result, detail), _ = self.results(mcp(), mcp(tools), change)
        self.assertEqual(result, "FAIL")
        self.assertIn("ssh_read definition changed_keys /inputSchema/required", detail)

    def test_wrong_field_or_stale_pointer_fails(self):
        tools = with_tool("ssh_read", **{"inputSchema.properties.extra": {"type": "string"}})
        for change in ([{"tool": "ssh_read", "kind": "definition", "changed_keys": keys(inputSchema__properties__extra={"type": "string"}), "reason": "x"}],
                       [{"tool": "ssh_read", "kind": "definition", "added_keys": keys(inputSchema__properties__extra={"type": "string"}, title="x"), "reason": "x"}]):
            with self.subTest(change=change):
                (result, detail), _ = self.results(mcp(), mcp(tools), change)
                self.assertEqual(result, "FAIL")
                self.assertIn("stale declaration: ['ssh_read definition", detail)

    def test_undeclared_response_key_fails(self):
        cases = {"added": {"target": "linux-a", "egress": "direct", "queries": ["kernel"], "limits": {}},
                 "removed": {"target": "linux-a", "queries": ["kernel"]},
                 "changed": {"target": "linux-a", "egress": "proxy", "queries": ["kernel"]}}
        for name, scope in cases.items():
            with self.subTest(case=name):
                _, (resp, detail) = self.results(mcp(), mcp(scope=scope))
                self.assertEqual(resp, "FAIL")
                self.assertIn("target_scope response", detail)

    def test_declared_response_key_does_not_hide_other_changes(self):
        change = [{"tool": "target_scope", "kind": "response", "added_keys": keys(limits={}), "reason": "new response field"}]
        _, (resp, detail) = self.results(mcp(), mcp(scope={"target": "linux-a", "egress": "direct", "queries": ["kernel"], "limits": {}}), change)
        self.assertEqual(resp, "OK", detail)
        _, (resp, detail) = self.results(mcp(), mcp(scope={"target": "linux-a", "queries": ["kernel"], "limits": {}}), change)
        self.assertEqual(resp, "FAIL")
        self.assertIn("target_scope response removed_keys /egress", detail)
        removed = change + [{"tool": "target_scope", "kind": "response", "removed_keys": ["/egress"], "reason": "105-X01 abc"}]
        _, (resp, detail) = self.results(mcp(), mcp(scope={"target": "linux-a", "queries": ["kernel"], "limits": {}}), removed)
        self.assertEqual(resp, "OK", detail)

    def test_stale_response_declaration_fails(self):
        for change in ([{"tool": "target_scope", "kind": "response", "added_keys": keys(limits={}), "reason": "new response field"}],
                       [{"tool": "read_query_catalog", "kind": "response", "removed_keys": ["/queries/linux/kernel"], "reason": "x"}]):
            with self.subTest(change=change):
                _, (resp, detail) = self.results(mcp(), mcp(), change)
                self.assertEqual(resp, "FAIL")
                self.assertIn("stale declaration: ['%s response" % change[0]["tool"], detail)

    def test_dynamic_key_value_is_masked_but_presence_and_type_compared(self):
        _, (resp, detail) = self.results(mcp(status={"uptime": 5, "time": "a"}), mcp(status={"uptime": 9, "time": "b"}))
        self.assertEqual(resp, "OK", detail)
        for name, (old, new, text) in {
                "added": ({}, {"uptime": 9}, "helper_status response added_keys /uptime"),
                "removed": ({"uptime": 5}, {}, "helper_status response removed_keys /uptime"),
                "type": ({"uptime": 5}, {"uptime": "5 days"}, "helper_status response changed_keys /uptime")}.items():
            with self.subTest(case=name):
                _, (resp, detail) = self.results(mcp(status=old), mcp(status=new))
                self.assertEqual(resp, "FAIL")
                self.assertIn("undeclared: ['%s']" % text, detail)
        change = [{"tool": "helper_status", "kind": "response", "added_keys": keys(uptime="<dynamic:number>"), "reason": "105-X02 abc"}]
        _, (resp, detail) = self.results(mcp(), mcp(status={"uptime": 9}), change)
        self.assertEqual(resp, "OK", detail)
        _, (resp, detail) = self.results(mcp(), mcp(status={"uptime": "9"}), change)
        self.assertEqual(resp, "FAIL")
        self.assertIn("different value: ['helper_status response added_keys /uptime']", detail)

    def test_declared_pointer_with_other_value_fails(self):
        tools = with_tool("ssh_read", description="other text")
        change = [{"tool": "ssh_read", "kind": "definition", "changed_keys": keys(description="new text"), "reason": "x"}]
        (result, detail), _ = self.results(mcp(), mcp(tools), change)
        self.assertEqual(result, "FAIL")
        self.assertIn("different value: ['ssh_read definition changed_keys /description']", detail)
        grown = copy.deepcopy(CATALOG)
        grown["fortios"]["ha_status"] = []
        right = {"queries__fortios__ha_status": [], "query_metadata__fortios__ha_status": {"description": "ha_status"}}
        cases = {"total": (dict(right), dict(catalog_sha256="b" * 64, total=6), "changed_keys /total"),
                 "literal-missing": (dict(right), {"/catalog_sha256": fp("b" * 64), "/total": {"sha256": fp(5)["sha256"]}}, "changed_keys /total"),
                 "literal-type": (dict(right), {"/catalog_sha256": fp("b" * 64), "/total": dict(fp(5), value="5")}, "changed_keys /total"),
                 "added-content": (dict(right, queries__fortios__ha_status=["x"]), dict(catalog_sha256="b" * 64, total=5),
                                   "added_keys /queries/fortios/ha_status")}
        for name, (added, changed, text) in cases.items():
            with self.subTest(case=name):
                c = [{"tool": "read_query_catalog", "kind": "response", "reason": "x", "added_keys": keys(**added),
                      "changed_keys": changed if name.startswith("literal") else keys(**changed)}]
                _, (resp, detail) = self.results(mcp(), mcp(catalog=grown, sha="b" * 64), c)
                self.assertEqual(resp, "FAIL")
                self.assertIn("different value: ['read_query_catalog response %s']" % text, detail)
        _, (resp, detail) = self.results(mcp(), mcp(scope={"target": "linux-a", "egress": "direct", "queries": ["kernel"], "limits": {"max": 1}}),
                                         [{"tool": "target_scope", "kind": "response", "added_keys": keys(limits={}), "reason": "x"}])
        self.assertEqual(resp, "FAIL")
        self.assertIn("different value: ['target_scope response added_keys /limits']", detail)

    def test_catalog_compared_over_all_pages_by_query_id(self):
        grown = copy.deepcopy(CATALOG)
        grown["fortios"]["ha_status"] = []
        added = [{"tool": "read_query_catalog", "kind": "response", "reason": "new query",
                  "added_keys": keys(queries__fortios__ha_status=[], query_metadata__fortios__ha_status={"description": "ha_status"}),
                  "changed_keys": keys(catalog_sha256="b" * 64, total=5)}]
        _, (resp, detail) = self.results(mcp(), mcp(catalog=grown, sha="b" * 64), added)
        self.assertEqual(resp, "OK", detail)
        _, (resp, detail) = self.results(mcp(), mcp(catalog=grown, sha="b" * 64))
        self.assertEqual(resp, "FAIL")
        self.assertIn("read_query_catalog response added_keys /queries/fortios/ha_status", detail)

    def test_removed_query_fails_unless_declared_removed(self):
        shrunk = copy.deepcopy(CATALOG)
        del shrunk["linux"]["kernel"]
        del shrunk["linux"]
        swap = copy.deepcopy(CATALOG)
        del swap["fortios"]["arp_table"]
        swap["fortios"]["ha_status"] = []
        growth_only = [{"tool": "read_query_catalog", "kind": "response", "reason": "x",
                        "added_keys": keys(queries__fortios__ha_status=[], query_metadata__fortios__ha_status={"description": "ha_status"})}]
        _, (resp, detail) = self.results(mcp(), mcp(catalog=swap), growth_only)
        self.assertEqual(resp, "FAIL")
        self.assertIn("read_query_catalog response removed_keys /queries/fortios/arp_table", detail)
        _, (resp, detail) = self.results(mcp(), mcp(catalog=shrunk))
        self.assertEqual(resp, "FAIL")
        self.assertIn("removed_keys /queries/linux", detail)
        declared = growth_only + [{"tool": "read_query_catalog", "kind": "response", "reason": "new query",
                                   "removed_keys": ["/queries/fortios/arp_table", "/query_metadata/fortios/arp_table"]}]
        _, (resp, detail) = self.results(mcp(), mcp(catalog=swap), declared)
        self.assertEqual(resp, "OK", detail)

    def test_query_named_like_a_dynamic_key_is_compared(self):
        shrunk = copy.deepcopy(CATALOG)
        del shrunk["linux"]["uptime"]
        _, (resp, detail) = self.results(mcp(), mcp(catalog=shrunk))
        self.assertEqual(resp, "FAIL")
        self.assertIn("removed_keys /queries/linux/uptime", detail)

    def test_incomplete_catalog_fails(self):
        for to in (mcp(total=9), dict(mcp(), calls=dict(mcp()["calls"], read_query_catalog_pages=mcp()["calls"]["read_query_catalog_pages"][:1]))):
            with self.subTest():
                _, (resp, detail) = self.results(mcp(), to)
                self.assertEqual(resp, "FAIL")
                self.assertIn("incomplete catalogue: ['read_query_catalog']", detail)

    def test_breaking_change_is_listed_in_summary(self):
        tools = with_tool("ssh_read", description="SNMPv3 only")
        change = [{"tool": "ssh_read", "kind": "definition", "changed_keys": keys(description="SNMPv3 only"), "breaking": True,
                   "reason": "SNMP v2c refused before network access"}]
        checks, doc, out = self.run_report(mcp(), mcp(tools), change)
        self.assertEqual(checks["mcp-tools-list"][0], "OK", checks["mcp-tools-list"][1])
        self.assertIn("BREAKING: ['ssh_read']", checks["mcp-tools-list"][1])
        self.assertIn("BREAKING ssh_read definition: SNMP v2c refused before network access", (out / "summary.txt").read_text())

    def test_declaration_does_not_excuse_error_reply(self):
        change = [{"tool": "helper_status", "kind": "response", "changed_keys": keys(note="y"), "reason": "x"}]
        _, (resp, detail) = self.results(mcp(), mcp(status_error=True, extra="y"), change)
        self.assertEqual(resp, "FAIL")
        self.assertIn("isError: ['helper_status']", detail)

    def test_invalid_declarations_fail_both_checks(self):
        good = {"tool": "triage_slb", "kind": "added", "reason": "new read-only triage tool"}
        keyed = {"tool": "ssh_read", "kind": "definition", "reason": "x", "added_keys": keys(a=1)}
        cases = {"versions": dict(changes=[good], versions=("1.0.4", "1.0.5")),
                 "kind": dict(changes=[dict(good, kind="renamed")]),
                 "old-kind": dict(changes=[dict(good, kind="response-shape")]),
                 "reason": dict(changes=[dict(good, reason=" ")]),
                 "extra-key": dict(changes=[dict(good, note="x")]),
                 "keys-on-added": dict(changes=[dict(good, added_keys=["/a"])]),
                 "no-keys": dict(changes=[good, dict(keyed, added_keys={})]),
                 "bad-pointer": dict(changes=[good, dict(keyed, added_keys={"a": fp(1)})]),
                 "pointer-list-without-value": dict(changes=[good, dict(keyed, added_keys=["/a"])]),
                 "bad-sha": dict(changes=[good, dict(keyed, added_keys={"/a": {"sha256": "x"}})]),
                 "no-sha": dict(changes=[good, dict(keyed, changed_keys={"/a": {"value": 1}})]),
                 "extra-expectation-key": dict(changes=[good, dict(keyed, added_keys={"/a": dict(fp(1), note=1)})]),
                 "removed-with-values": dict(changes=[good, dict(keyed, added_keys={}, removed_keys=keys(a=1))]),
                 "removed-not-list": dict(changes=[good, dict(keyed, removed_keys=7)]),
                 "duplicate-json-key": dict(raw='{"from": "1.0.5", "to": "1.0.6", "changes": [], "changes": []}'),
                 "breaking-type": dict(changes=[dict(good, breaking="yes")]),
                 "duplicate": dict(changes=[good, good]),
                 "duplicate-pointer": dict(changes=[good, keyed, dict(keyed, reason="y")]),
                 "not-json": dict(raw="{"),
                 "shape": dict(raw=json.dumps({"from": "1.0.5", "to": "1.0.6", "changes": [good], "extra": 1}))}
        for name, kwargs in cases.items():
            with self.subTest(case=name):
                (tools, detail), (resp, _) = self.results(mcp(), mcp(BASE_TOOLS + [tool("triage_slb")]), **kwargs)
                self.assertEqual((tools, resp), ("FAIL", "FAIL"), detail)
                self.assertIn("declaration", detail)

    def test_mcp_outputs_are_kept_masked_and_secret_in_reply_fails(self):
        checks, doc, out = self.run_report(mcp(), mcp())
        self.assertEqual(checks["no-token-or-password-in-logs"][0], "OK")
        self.assertTrue((out / "mcp-from.json").exists() and (out / "mcp-to.json").exists())
        checks, doc, out = self.run_report(mcp(extra=VAULT), mcp(extra=TOKEN))
        self.assertEqual(checks["no-token-or-password-in-logs"][0], "FAIL")
        for name in ("mcp-from.json", "mcp-to.json"):
            data = (out / name).read_text()
            self.assertNotIn(TOKEN, data)
            self.assertNotIn(VAULT, data)
            self.assertIn("<masked>", data)


if __name__ == "__main__":
    unittest.main()
