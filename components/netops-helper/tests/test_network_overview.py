"""Overview contract with a deterministic adapter and synthetic transport boundaries."""

import asyncio
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import sys
import time
from threading import Barrier, Event, Lock
from types import SimpleNamespace

import pytest

from netops.worker import HelperBridge
from netops_core import ssh
from netops_core.audit import Recorder
from netops_helper import audit, engine, proxy, server, wifi_rest
from netops_helper.overview import model, runner
from conftest import FORTIOS_STATUS, HOST_KEY_BLOB, HOST_KEY_PIN
import overview_fake_linux
from test_proxy_contracts import _device, _egress, _egress_policy, _inventory, _write

FIXTURES = Path(__file__).parent / "fixtures"
IDENTITY = (FIXTURES / "identity/linux.txt").read_text()
LINKS = json.loads((FIXTURES / "tables/linux.json").read_text())["interface"]
SECRET = "fixture-credential-overlap"
OTHER_SECRET = "credential-overlap"


def test_overview_is_the_new_public_tool():
    async def check():
        tools = await HelperBridge().tools(server.mcp)
        descriptor, = [item for item in tools if item["name"] == "network_overview"]
        return descriptor
    schema = asyncio.run(check())["inputSchema"]
    assert schema["additionalProperties"] is False
    assert not schema.get("required")
    assert set(schema["properties"]) == model.ARGUMENTS
    assert schema["properties"]["targets"]["uniqueItems"]
    assert schema["properties"]["groups"]["uniqueItems"]


def device(alias, number, *, types=("switch",), enabled=("kernel", "links"), requests=30, host=None):
    address = f"192.0.2.{number}"
    egress = dict(_egress(), addresses=[address], tcp_ports=[22], allow_dns=host is not None)
    section = {"ssh_platform": "linux", "account_role": "read-only", "enabled_queries": list(enabled),
               "device_types": list(types), "rate_limit": {"requests": requests, "window_seconds": 60},
               "egress": egress}
    return dict(_device(section, "linux"), name=alias, address=host or address, credential=f"reader-{number}")


@pytest.fixture
def setup(tmp_path, monkeypatch):
    bridge = HelperBridge()
    calls, handlers = [], {}

    def configure(*devices, extra_credentials=()):
        inv = _write(tmp_path / "inventory.json", _inventory(*devices))
        credentials = {entry["credential"]: {"kind": "password", "login": "reader",
                        "value": SECRET if index == 0 else OTHER_SECRET}
                       for index, entry in enumerate(devices)}
        credentials.update(extra_credentials)
        vault = _write(tmp_path / "vault.json", {"version": 2, "credentials": credentials}, 0o600)
        policy = _write(tmp_path / "egress.json", _egress_policy())
        monkeypatch.setattr(proxy, "INVENTORY", inv)
        monkeypatch.setattr(proxy, "VAULT", vault)
        monkeypatch.setattr(proxy, "EGRESS_POLICY", policy)
        monkeypatch.setattr(bridge.proxy, "_vault", lambda names=None: proxy.Proxy._vault(bridge.proxy, names))
        monkeypatch.setattr(bridge.proxy, "_load_egress_policy", lambda: proxy.Proxy._load_egress_policy(bridge.proxy))

    def transport(host, port, login, credential, pin, command, *, timeout_seconds, **options):
        calls.append((host, command))
        assert 0 < timeout_seconds <= model.READ_SECONDS
        if host in handlers:
            answer = handlers[host](command, timeout_seconds)
        else:
            answer = IDENTITY if command == "uname -a" else LINKS
        # A handler can answer (exit status, output) as the device's captured index records it.
        rc, answer = answer if isinstance(answer, tuple) else (0, answer)
        return ssh.Result(rc, answer.encode(), "", "", "")

    monkeypatch.setitem(sys.modules, "netops_helper.overview.linux", overview_fake_linux)
    monkeypatch.setattr(engine.core_hostkey, "scan", lambda *args, **kwargs: "test-pinned-key")
    monkeypatch.setattr(engine.core_ssh, "run_command", transport)
    audit_path = tmp_path / "operations.jsonl"
    monkeypatch.setattr(audit, "_RECORDER", Recorder(audit_path, "helper"))

    async def call(args):
        return await bridge.call(server.mcp, "network_overview", args)

    return SimpleNamespace(configure=configure, calls=calls, call=lambda args: asyncio.run(call(args)), async_call=call,
                           handlers=handlers, bridge=bridge, audit=audit_path)


def test_selection_pagination_and_bounded_operational_facts(setup):
    setup.configure(device("alpha", 10), device("bravo", 11, types=("router",)),
                    device("charlie", 12, types=()), dict(device("outside", 13), helper=None, auditor={}))
    first = setup.call({"limit": 2})
    assert not first["isError"], first
    result = first["structuredContent"]
    assert result["selection"] == {"matched": 3, "returned": 2, "remaining": 1, "next_after": "bravo", "unverified": 0}
    assert result["status"] == "partial"
    assert result["device_output_trust"] == "untrusted"
    assert [item["target"] for item in result["devices"]] == ["alpha", "bravo"]
    row = result["devices"][0]
    assert row["status"] == "complete"
    assert row["reachability"] == "reachable"
    assert row["interfaces"]["admin_up_down"] == [{"name": "docker0", "read_ids": ["links"]}]
    assert row["findings"][0]["code"] == "admin_up_link_down"
    assert result["summary"]["complete"] == 2
    assert json.loads(first["content"][0]["text"]) == result
    second = setup.call({"limit": 2, "after": "bravo"})["structuredContent"]
    assert second["selection"]["matched"] == 3
    assert [row["target"] for row in second["devices"]] == ["charlie"]
    selected = setup.call({"groups": ["switch"], "targets": ["alpha", "bravo", "outside", "unknown"]})["structuredContent"]
    assert [row["target"] for row in selected["devices"]] == ["alpha", "outside", "unknown"]
    assert [row["missing"][0]["reason"] for row in selected["devices"][1:]] == ["not_enrolled", "unknown_target"]
    empty = setup.call({"groups": ["firewall"]})["structuredContent"]
    assert empty["status"] == "complete" and empty["devices"] == []
    audit_rows = [json.loads(line) for line in setup.audit.read_text().splitlines()]
    counts = Counter(row["operation_id"] for row in audit_rows)
    assert set(counts.values()) == {2}
    assert SECRET not in setup.audit.read_text()


@pytest.mark.parametrize("invalid", [
    {"targets": ["same", "same"]}, {"targets": None}, {"groups": None}, {"groups": ["router", "router"]},
    {"limit": True}, {"limit": 1.0}, {"timeout_seconds": None}, {"timeout_seconds": 121},
    {"after": "x" * 129}, {"targets": ["x y"]}, {"overview_plan": {}}, {"auth_context": "private"},
])
def test_bad_arguments_are_rejected_before_any_read(setup, invalid):
    result = setup.call(invalid)
    assert result["isError"]
    assert json.loads(result["content"][0]["text"])["code"] == -32602
    assert setup.calls == []


def test_partial_target_policy_identity_and_unreachable_leave_other_results(setup):
    setup.configure(device("a-no-opt-in", 11, enabled=("kernel",)), device("b-wrong", 12),
                    device("c-lost", 13), device("z-good", 14))
    setup.handlers["192.0.2.12"] = lambda *args: "Cisco IOS Software"
    def unavailable(*args):
        raise ConnectionRefusedError()
    setup.handlers["192.0.2.13"] = unavailable
    result = setup.call({})["structuredContent"]
    no_opt_in, wrong, lost, good = result["devices"]
    assert no_opt_in["missing"][-1]["reason"] == "policy_scope"
    assert wrong["reachability"] == "reachable"
    assert {item["reason"] for item in wrong["missing"] if item["field"] == "version"} == {"identity_unverified"}
    assert lost["reachability"] == "unreachable"
    assert good["status"] == "complete"
    assert result["summary"]["partial"] == 3
    assert all((host, "ip -brief link") not in setup.calls for host in ("192.0.2.11", "192.0.2.12", "192.0.2.13"))


def test_rate_reservations_share_the_manual_window_and_are_atomic(setup):
    setup.configure(device("switch-a", 10, requests=3))
    manual = asyncio.run(setup.bridge.call(server.mcp, "ssh_read", {"target": "switch-a", "platform": "linux", "query": "kernel"}))
    assert not manual["isError"], manual
    first = setup.call({})["structuredContent"]["devices"][0]
    assert first["status"] == "complete"
    next_row = setup.call({})["structuredContent"]["devices"][0]
    assert next_row["duration_ms"] is None
    assert all(item["reason"] == "rate_limited" and item["retry_after_seconds"] > 0
               for item in next_row["missing"] if "read_id" in item)
    proxy_instance = proxy.Proxy()
    barrier = Barrier(2)
    def reserve():
        barrier.wait()
        return proxy_instance._consume_rate_limits(
            (("same", {"requests": 3, "window_seconds": 60}, (1, 2)),), triage=True, prefix=True,
        )[0][0]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(reserve) for _ in range(2)]
        assert sorted(future.result() for future in futures) == [0, 2]


def test_default_page_is_one_parallel_round_and_starts_every_target_at_once(setup):
    """A call without `limit` pages by the parallel width, so no target waits in a queue (10-target page: 45 s)."""
    setup.configure(*(device(f"unit-{number}", number) for number in range(10, 16)))
    gate = {"barrier": Barrier(model.MAX_PARALLEL)}

    def identity(command, timeout):
        if command == "uname -a" and gate["barrier"] is not None:
            gate["barrier"].wait(5)  # Every target of the page reads its identity before any of them continues.
        return IDENTITY if command == "uname -a" else LINKS
    for number in range(10, 16):
        setup.handlers[f"192.0.2.{number}"] = identity
    first = setup.call({})["structuredContent"]
    assert model.DEFAULT_LIMIT == model.MAX_PARALLEL == 4
    assert first["selection"] == {"matched": 6, "returned": 4, "remaining": 2, "next_after": "unit-13",
                                  "unverified": 0}
    assert [row["status"] for row in first["devices"]] == ["complete"] * 4
    assert first["status"] == "partial"  # Another page remains.
    gate["barrier"] = Barrier(2)
    second = setup.call({"after": first["selection"]["next_after"]})["structuredContent"]
    assert [row["target"] for row in second["devices"]] == ["unit-14", "unit-15"]
    assert second["selection"]["next_after"] is None and second["status"] == "complete"
    # An explicit limit keeps its meaning.
    gate["barrier"] = None
    assert setup.call({"limit": 5})["structuredContent"]["selection"]["returned"] == 5


def test_published_schema_states_the_default_page_size():
    async def check():
        tools = await HelperBridge().tools(server.mcp)
        descriptor, = [item for item in tools if item["name"] == "network_overview"]
        return descriptor["inputSchema"]["properties"]["limit"]
    limit = asyncio.run(check())
    assert (limit["default"], limit["minimum"], limit["maximum"]) == (4, 1, 64)


def test_adapter_recognized_answers_change_only_unparsed_captures(setup, monkeypatch):
    """A refused capture reaches the adapter; only an exact recognized answer becomes empty or not_applicable."""
    setup.configure(device("a-absent", 11), device("b-empty", 12), device("c-other", 13), device("d-timeout", 14))
    absent = "links: this platform has no link table"
    answers = {"192.0.2.11": (1, absent + "\n"), "192.0.2.12": (1, ""), "192.0.2.13": (1, "links: busy\n")}
    for host, answer in answers.items():
        setup.handlers[host] = lambda command, timeout, answer=answer: IDENTITY if command == "uname -a" else answer

    def late(command, timeout):
        if command == "uname -a":
            return IDENTITY
        raise TimeoutError()
    setup.handlers["192.0.2.14"] = late
    seen = []

    def recognizing(scope, reads):
        facts = overview_fake_linux.assemble(scope, reads)
        lines = model.refused_lines(reads["links"])
        seen.append(lines)
        if lines == [absent] or reads["links"].reason == "timeout":
            # The timeout claim shows that the frame never rewrites a reason other than unparsed.
            facts.answered_reads = {"links": "not_applicable"}
        elif lines == []:
            facts.answered_reads = {"links": "empty"}
        return facts
    monkeypatch.setitem(sys.modules, "netops_helper.overview.linux",
                        SimpleNamespace(plan=overview_fake_linux.plan, assemble=recognizing))
    rows = {row["target"]: row for row in setup.call({})["structuredContent"]["devices"]}
    links = {target: next(read for read in row["reads"] if read["id"] == "links") for target, row in rows.items()}
    assert links["a-absent"]["status"] == "empty"
    assert {"field": "interfaces.admin_up_down", "reason": "not_applicable", "read_id": "links"} in rows["a-absent"]["missing"]
    assert rows["a-absent"]["status"] == "complete"
    assert links["b-empty"]["status"] == "empty" and rows["b-empty"]["status"] == "complete"
    assert not [entry for entry in rows["b-empty"]["missing"] if entry.get("read_id") == "links"]
    # An unrecognized refusal stays unparsed.
    assert links["c-other"]["status"] == "incomplete"
    assert {"field": "interfaces.admin_up_down", "reason": "unparsed", "read_id": "links"} in rows["c-other"]["missing"]
    # The adapter named the other answers too, but a timeout is never rewritten.
    assert links["d-timeout"]["status"] == "failed"
    assert {"field": "interfaces.admin_up_down", "reason": "timeout", "read_id": "links"} in rows["d-timeout"]["missing"]
    assert rows["d-timeout"]["status"] == "partial"
    assert sorted(map(str, seen)) == sorted(map(str, ([absent], [], ["links: busy"], None)))


def test_unknown_answer_kind_is_invalid_adapter_output(setup, monkeypatch):
    setup.configure(device("broken", 11))
    setup.handlers["192.0.2.11"] = lambda command, timeout: IDENTITY if command == "uname -a" else (1, "x\n")

    def wrong(scope, reads):
        facts = overview_fake_linux.assemble(scope, reads)
        facts.answered_reads = {"links": "ok"}
        return facts
    monkeypatch.setitem(sys.modules, "netops_helper.overview.linux",
                        SimpleNamespace(plan=overview_fake_linux.plan, assemble=wrong))
    row, = setup.call({})["structuredContent"]["devices"]
    assert model.missing("device", "unparsed") in row["missing"] and row["status"] == "partial"


def test_fifth_target_waits_and_cancellation_keeps_it_off_the_wire(setup, monkeypatch):
    setup.configure(*(device(f"unit-{number}", number) for number in range(10, 15)))
    started, lock, four, release = set(), Lock(), Event(), Event()
    def blocked(host):
        def read(command, timeout):
            with lock:
                started.add(host)
                if len(started) == 4:
                    four.set()
            assert release.wait(4)
            return IDENTITY if command == "uname -a" else LINKS
        return read
    for number in range(10, 15):
        host = f"192.0.2.{number}"
        setup.handlers[host] = blocked(host)
    async def exercise():
        operation = asyncio.create_task(setup.async_call({"limit": 5}))
        try:
            assert await asyncio.to_thread(four.wait, 3)
            assert len(started) == 4
            operation.cancel()
            await asyncio.sleep(0.05)
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await operation
    asyncio.run(exercise())
    assert len(started) == 4
    assert all(command == "uname -a" for _, command in setup.calls)


def test_dns_timeout_uses_terminable_subprocess_and_never_opens_ssh(setup, monkeypatch):
    setup.configure(device("dns", 20, host="switch.example"))
    called = []
    real_run = subprocess.run
    def timeout(argv, **kwargs):
        if "switch.example" not in argv:
            return real_run(argv, **kwargs)
        called.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
    monkeypatch.setattr(engine.subprocess, "run", timeout)
    result = setup.call({})["structuredContent"]["devices"][0]
    assert len(called) == 1 and 0 < called[0] <= model.READ_SECONDS
    assert result["reads"][0]["status"] == "failed"
    assert result["missing"][-1]["reason"] == "timeout"
    assert not setup.calls


def test_output_limits_preserve_aliases_and_findings_references(setup, monkeypatch):
    alias = "n" * 128
    setup.configure(device(alias, 11), device("other", 12))
    def large(scope, reads):
        facts = overview_fake_linux.assemble(scope, reads)
        facts.fields["interfaces"]["admin_up_down"] = [
            {"name": "p" * 500 + str(index), "read_ids": ["links"]} for index in range(100)
        ]
        return facts
    monkeypatch.setitem(sys.modules, "netops_helper.overview.linux",
                        SimpleNamespace(plan=overview_fake_linux.plan, assemble=large))
    result = setup.call({})["structuredContent"]
    assert [row["target"] for row in result["devices"]] == [alias, "other"]
    for row in result["devices"]:
        assert row["status"] == "partial"
        assert len(row["interfaces"]["admin_up_down"]) == model.MAX_DETAILS
        assert len(row["findings"]) == model.MAX_DETAILS
        assert any(item["reason"] == "output_limit" and item["omitted_count"] > 0 for item in row["missing"])
        assert all(set(item["read_ids"]) <= {read["id"] for read in row["reads"]}
                   for item in row["findings"])
    assert model.encoded_size(result) <= model.MAX_OUTPUT


def test_missing_reason_list_matches_the_operator_documentation():
    from pathlib import Path
    document = (Path(__file__).parents[1] / "docs/tools.md").read_text()
    table = document.split("<!-- overview-reasons -->")[1]
    assert {line.split("`")[1] for line in table.splitlines() if line.startswith("| `")} == model.REASONS


def test_invalid_global_policy_and_unverified_group(setup):
    malformed = device("bad-group", 11, types=("wireless",))
    setup.configure(malformed, device("good", 12))
    selected = setup.call({"groups": ["switch"], "targets": ["bad-group", "good"]})["structuredContent"]
    assert selected["selection"]["unverified"] == 1
    assert selected["devices"][0]["missing"] == [{"field": "device", "reason": "group_unverified"}]
    implicit = setup.call({"groups": ["switch"]})["structuredContent"]
    assert implicit["selection"]["unverified"] == 1
    assert [row["target"] for row in implicit["devices"]] == ["good"]
    proxy.EGRESS_POLICY.write_text("{}")
    refused = setup.call({})
    assert refused["isError"]
    assert json.loads(refused["content"][0]["text"])["data"]["category"] == "policy_schema"


def test_wire_page_is_shortened_before_charging_a_skipped_alias(setup, monkeypatch):
    setup.configure(device("a" * 128, 11), device("b" * 128, 12), device("c" * 128, 13))
    monkeypatch.setattr(model, "MAX_MESSAGE", 2048 + 6000)
    result = setup.call({})["structuredContent"]
    page = result["selection"]
    assert 0 < page["returned"] < page["matched"]
    assert page["remaining"] == page["matched"] - page["returned"]
    assert page["next_after"] == result["devices"][-1]["target"]
    assert "c" * 128 not in setup.bridge.proxy.rate_history


def test_overview_ssh_lane_retries_a_busy_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "_lane_directory", lambda: tmp_path / "lanes")
    waits = []
    with engine._process_connection_lane("192.0.2.10", 22) as held:
        def release_lane(seconds):
            waits.append(seconds)
            engine.fcntl.flock(held, engine.fcntl.LOCK_UN)

        monkeypatch.setattr(engine, "_sleep", release_lane)
        budget = runner.Budget(time.monotonic() + model.READ_SECONDS, Event())
        token = engine._OVERVIEW_BUDGET.set(budget)
        try:
            with engine._process_connection_lane("192.0.2.10", 22):
                assert waits == [0.05]
        finally:
            engine._OVERVIEW_BUDGET.reset(token)


def test_one_read_timeout_preserves_completed_identity(setup):
    setup.configure(device("timeout", 11))
    def response(command, timeout):
        if command == "uname -a":
            assert 9 < timeout <= 10
            return IDENTITY
        raise TimeoutError()
    setup.handlers["192.0.2.11"] = response
    row = setup.call({})["structuredContent"]["devices"][0]
    assert row["version"]
    assert row["reachability"] == "reachable"
    assert row["status"] == "partial"
    assert row["reads"][1]["status"] == "failed"
    assert row["missing"][-1]["reason"] == "timeout"


@pytest.mark.parametrize("available", [True, False])
def test_fortinet_retains_one_session_and_redacts_rest_document_before_assembly(setup, monkeypatch, available):
    fortinet = device("controller", 21, enabled=("system_status", "performance"), types=("firewall",))
    fortinet.update(platform="fortios", host_key_fingerprint=HOST_KEY_PIN,
                    host_key="ssh-ed25519 " + HOST_KEY_BLOB)
    section = fortinet["helper"]
    section.update(ssh_platform="fortios", fortios_output_standard_verified=True,
                   account_role="admin-bounded", role_boundary="catalogue",
                   fortios_rest_credential="controller-monitor",
                   fortios_rest_certificate_sha256="c" * 64)
    section["egress"]["tcp_ports"].append(443)
    rest_secret = "synthetic-monitor-material"
    options = {"controller-monitor": {"kind": "api-token", "value": rest_secret}} if available else {}
    setup.configure(fortinet, device("peer", 22), extra_credentials=options)

    def read_plan(scope):
        return (model.ReadSpec("status", "system_status", ("version",)),
                model.ReadSpec("health", "switch_health", ("managed",), transport="https"),
                model.ReadSpec("performance", "performance", ("cpu",)))

    def facts(scope, reads):
        document = reads["health"].document
        if available:
            assert document["results"] == [{"nested": {"uptime": 72, "remark": "sample-<REDACTED>"}}]
        else:
            assert document is None
        return model.DeviceFacts({"version": "7.6.7", "managed": [] if available else None,
                                  "cpu": {"used_pct": 10, "sample_seconds": None}})

    events = []
    monkeypatch.setitem(sys.modules, "netops_helper.overview.fortinet", SimpleNamespace(plan=read_plan, assemble=facts))

    class Terminal:
        def run(self, command, **options):
            assert 0 < options["timeout_seconds"] <= model.READ_SECONDS
            events.append(command)
            data = FORTIOS_STATUS if command == "get system status" else "CPU states: 10% user"
            return engine.core_session.FortinetResult(0, data.encode(), "", "", "")

    @contextmanager
    def terminal(*args, **kwargs):
        events.append("connect")
        try:
            yield Terminal()
        finally:
            events.append("close")

    def monitor(auth, path, *, budget_seconds):
        assert 0 < budget_seconds <= model.READ_SECONDS
        assert path == wifi_rest.SWITCH_HEALTH
        events.append("GET")
        return {"status": "success", "http_method": "GET", "vdom": "root",
                "results": [{"nested": {"uptime": 72, "remark": "sample-" + OTHER_SECRET}}]}

    monkeypatch.setattr(engine.core_session, "fortinet_session", terminal)
    monkeypatch.setattr(wifi_rest, "get", monitor)
    result = setup.call({})["structuredContent"]["devices"][0]
    assert result["status"] == ("complete" if available else "partial"), result
    assert events == ["connect", "get system status", *(["GET"] if available else ()),
                      "get system performance status", "close"]
    if not available:
        assert result["missing"] == [model.missing("managed", "rest_unavailable", read_id="health")]
    assert result["reads"][1]["source"] == {"transport": "https", "monitor": "switch_health"}
    assert not any(value in json.dumps(result) for value in (rest_secret, OTHER_SECRET))


def test_stdio_overview_cancellation_needs_an_active_request(setup):
    setup.configure(device("switch-a", 11))
    stdio = proxy.Proxy()
    request = {"jsonrpc": "2.0", "id": "overview-a", "method": "tools/call",
               "params": {"name": "network_overview", "arguments": {}}}
    cancel = {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "overview-a"}}
    assert stdio.request(json.dumps(cancel).encode()) is None
    forwarded = stdio.request(json.dumps(request).encode())
    assert "overview_plan" in json.loads(forwarded)["params"]["arguments"]
    assert stdio.request(json.dumps(cancel).encode()) is not None
    assert stdio.request(json.dumps(cancel).encode()) is None
    assert not stdio.response(json.dumps({"jsonrpc": "2.0", "id": "overview-a", "result": {}}).encode())
    assert stdio.accepting()


def test_expired_queue_does_not_attempt_to_connect(setup, monkeypatch):
    setup.configure(*(device(f"unit-{number}", number) for number in range(10, 15)))
    started, lock, occupied, release = set(), Lock(), Event(), Event()
    offset = [0.0]
    monkeypatch.setattr(runner, "time", SimpleNamespace(monotonic=lambda: time.monotonic() + offset[0]))

    def block(host):
        def read(command, timeout):
            with lock:
                started.add(host)
                if len(started) == 4:
                    occupied.set()
            assert release.wait(4)
            return IDENTITY
        return read

    for number in range(10, 15):
        host = f"192.0.2.{number}"
        setup.handlers[host] = block(host)

    async def expire():
        operation = asyncio.create_task(setup.async_call({"timeout_seconds": 5, "limit": 5}))
        try:
            assert await asyncio.to_thread(occupied.wait, 3)
            offset[0] = 10
        finally:
            release.set()
        return await operation

    rows = asyncio.run(expire())["structuredContent"]["devices"]
    assert len(setup.calls) == len(started) == 4
    queued = [row for row in rows if row["duration_ms"] is None]
    assert len(queued) == 1
    assert [read["status"] for read in queued[0]["reads"]] == ["not_run", "not_run"]
    assert {item["reason"] for item in queued[0]["missing"] if "read_id" in item} == {"timeout"}


@pytest.mark.parametrize("damage", [
    lambda facts: facts.fields.update(version=object()),
    lambda facts: facts.fields.update(cpu={"used_pct": float("nan")}),
    lambda facts: facts.fields.update(interfaces={"scope": "device", "admin_up_down": {1, 2}, "with_errors": None}),
    lambda facts: facts.missing.append({"field": 7, "reason": "unparsed"}),
    lambda facts: facts.missing.append({"field": "cpu", "reason": "invented"}),
    lambda facts: facts.findings.append({"code": "x", "severity": "info", "field": ["cpu"], "read_ids": ["links"]}),
    lambda facts: facts.findings.append({"code": "x", "severity": {"bad": 1}, "field": "cpu"}),
    lambda facts: facts.fields.update(managed=[{"status": "complete"}, 3]),
    lambda facts: setattr(facts, "incomplete_reads", ("unknown-read",)),
], ids=["object", "nan", "set", "missing-field", "missing-reason", "finding-field", "finding-severity",
        "managed", "incomplete-read"])
def test_invalid_adapter_output_stays_in_its_own_row(setup, monkeypatch, damage):
    setup.configure(device("broken", 11), device("good", 12))

    def selective(scope, reads):
        facts = overview_fake_linux.assemble(scope, reads)
        if selective.calls == 0:
            damage(facts)
        selective.calls += 1
        return facts

    selective.calls = 0
    monkeypatch.setitem(sys.modules, "netops_helper.overview.linux",
                        SimpleNamespace(plan=overview_fake_linux.plan, assemble=selective))
    monkeypatch.setattr(model, "MAX_PARALLEL", 1)
    answer = setup.call({})
    assert not answer["isError"], answer
    result = answer["structuredContent"]
    broken, good = result["devices"]
    assert broken["target"] == "broken" and broken["status"] == "partial"
    assert broken["reachability"] == "reachable"
    assert model.missing("device", "unparsed") in broken["missing"]
    assert broken["version"] is None and broken["findings"] == []
    assert [read["status"] for read in broken["reads"]] == ["ok", "ok"]
    assert good["status"] == "complete" and good["version"]
    assert result["status"] == "partial" and result["summary"]["partial"] == 1
    assert json.loads(answer["content"][0]["text"]) == result


STDIO_SERVER = r'''
import sys, time
from netops_core import ssh
from netops_helper import engine, server

identity, overrun = open(sys.argv[1]).read(), float(sys.argv[2])
sys.path.insert(0, sys.argv[3])
import overview_fake_linux

def transport(host, port, login, credential, pin, command, *, timeout_seconds, **options):
    if command == "uname -a":
        return ssh.Result(0, identity.encode(), "", "", "")
    # A hung read whose transport ends a little after its own timeout.
    time.sleep(timeout_seconds + overrun)
    raise TimeoutError()

sys.modules["netops_helper.overview.linux"] = overview_fake_linux
engine.core_hostkey.scan = lambda *args, **kwargs: "test-pinned-key"
engine.core_ssh.run_command = transport
server.main()
'''


def test_stdio_proxy_waits_past_the_deadline_for_the_partial_page(setup, tmp_path, monkeypatch, capsys):
    """Real stdio path: proxy plan -> FastMCP server process -> runner with a hung fake read."""
    import os
    setup.configure(device("slow", 11))
    environment = dict(os.environ, NETOPS_HELPER_AUDIT_PATH=str(tmp_path / "server-audit.jsonl"))
    command = [sys.executable, "-B", "-c", STDIO_SERVER, str(FIXTURES / "identity/linux.txt"), "2.0",
               str(Path(__file__).parent)]
    stdio = proxy.Proxy()
    connection = proxy._ServerConnection(stdio, command, environment, (), None)
    controller = proxy._SessionController(stdio, lambda: connection if connection.start() else None)
    lines = []

    def answer(identifier, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            lines.extend(line for line in capsys.readouterr().out.splitlines() if line.strip())
            for line in lines:
                message = json.loads(line)
                if message.get("id") == identifier:
                    return message
            time.sleep(0.05)
        raise AssertionError(f"no answer for {identifier}: {lines}")

    assert controller.start()
    try:
        assert controller.forward(json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "client", "version": "1"}}}).encode() + b"\n")
        assert "result" in answer(0, 30)
        assert controller.forward(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        started = time.monotonic()
        assert controller.forward(json.dumps({"jsonrpc": "2.0", "id": "page", "method": "tools/call", "params": {
            "name": "network_overview", "arguments": {"timeout_seconds": 5}}}).encode() + b"\n")
        page = answer("page", 30)
        elapsed = time.monotonic() - started
    finally:
        controller.stop()
    assert "error" not in page, page
    result = page["result"]["structuredContent"]
    assert result["status"] == "partial"
    row, = result["devices"]
    assert row["version"] and row["reachability"] == "reachable"
    assert [read["status"] for read in row["reads"]] == ["ok", "failed"]
    assert model.missing("interfaces.admin_up_down", "timeout", read_id="links") in row["missing"]
    # The answer arrived after the requested deadline and inside the response reserve.
    assert 5 < elapsed < 5 + proxy.OVERVIEW_RESPONSE_GRACE_SECONDS
