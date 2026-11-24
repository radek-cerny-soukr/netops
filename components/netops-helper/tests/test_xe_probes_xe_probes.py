"""XE-PROBES MCP and Proxy checks using real IOS XE CLI output and a fake SSH transport."""

import asyncio
import json
import sys
from base64 import urlsafe_b64encode
from pathlib import Path

from fastmcp import Client
import pytest

from netops_helper import engine, server
from netops_helper.auth import AuthenticationContextError, TargetAuth
from netops_helper.read_policy import _validate_query_command, render_read_query
import test_proxy_contracts as contracts


REAL = Path(__file__).parent / "fixtures/real/cisco_xe"
FIXTURES = REAL / "iolxe_17.18.2_xe_probes"
CISCO = REAL / "cisco_documentation_xe_probes"
VERSION = (REAL / "iolxe_17.18.2_xe_routing/version.out").read_text()
PLATFORM = "cisco_xe"
CASES = {
    "global4_ping": ("ping", "198.51.100.1", None, None),
    "global4_ping_source": ("ping_source", "198.51.100.1", "Ethernet0/1.10", None),
    "blue4_ping": ("ping_vrf", "192.0.2.1", None, "blue"),
    "blue4_ping_source": ("ping_vrf_source", "192.0.2.1", "Ethernet0/2", "blue"),
    "global6_ping": ("ping_ipv6", "2001:db8:2::1", None, None),
    "global6_ping_source": ("ping_ipv6_source", "2001:db8:2::1", "Ethernet0/1.10", None),
    "blue6_ping": ("ping_ipv6_vrf", "2001:db8:1::1", None, "blue"),
    "blue6_ping_source": ("ping_ipv6_vrf_source", "2001:db8:1::1", "Ethernet0/2", "blue"),
    "global4_trace": ("traceroute", "198.51.100.1", None, None),
    "global4_trace_source": ("traceroute_source", "198.51.100.1", "Ethernet0/1.10", None),
    "blue4_trace": ("traceroute_vrf", "192.0.2.1", None, "blue"),
    "blue4_trace_source": ("traceroute_vrf_source", "192.0.2.1", "Ethernet0/2", "blue"),
    "global6_trace": ("traceroute_ipv6", "2001:db8:2::1", None, None),
    "global6_trace_source": ("traceroute_ipv6_source", "2001:db8:2::1", "Ethernet0/1.10", None),
    "blue6_trace": ("traceroute_ipv6_vrf", "2001:db8:1::1", None, "blue"),
    "blue6_trace_source": ("traceroute_ipv6_vrf_source", "2001:db8:1::1", "Ethernet0/2", "blue"),
    "loopback4_ping": ("ping_source", "198.51.100.1", "Loopback0", None),
    "blue4_ping_loss": ("ping_vrf_source", "192.0.2.250", "Ethernet0/2", "blue"),
    "blue6_ping_loss": ("ping_ipv6_vrf_source", "2001:db8:1::250", "Ethernet0/2", "blue"),
    "blue4_trace_loss": ("traceroute_vrf_source", "192.0.2.250", "Ethernet0/2", "blue"),
    "blue6_trace_loss": ("traceroute_ipv6_vrf_source", "2001:db8:1::250", "Ethernet0/2", "blue"),
    "ping_bad_vrf": ("ping_vrf", "192.0.2.1", None, "XE-PROBES-MISSING"),
    "trace_bad_vrf": ("traceroute_vrf", "192.0.2.1", None, "XE-PROBES-MISSING"),
    "ping_bad_source": ("ping_vrf_source", "192.0.2.1", "Loopback999", "blue"),
    "trace_bad_source": ("traceroute_vrf_source", "192.0.2.1", "Loopback999", "blue"),
}
DOC_TRACES = {
    "trace_alternate_ip": ("traceroute", "203.0.113.2", None, None),
    "trace_mpls_label": ("traceroute_source", "203.0.113.10", "Loopback1", None),
    "trace_mpls_stack": ("traceroute_source", "203.0.113.10", "Loopback1", None),
}
RO_CASES = ("global4_ping_source", "blue6_ping_source", "blue4_trace_source")
INVENTORY = {
    "addresses": sorted({case[1] for case in (*CASES.values(), *DOC_TRACES.values())}),
    "interfaces": ["Ethernet0/1.10", "Ethernet0/2", "Loopback0", "Loopback1", "Loopback999"],
    "vrfs": ["blue", "XE-PROBES-MISSING"],
}


def case_arguments(case):
    name, address, source, vrf = (CASES | DOC_TRACES)[case]
    params = {key: value for key, value in {"address": address, "source": source, "vrf": vrf}.items() if value}
    verb = "ping" if name.startswith("ping") else "traceroute"
    parts = [verb]
    if vrf:
        parts += ["vrf", vrf]
    if ":" in address:
        parts.append("ipv6")
    parts.append(address)
    if source:
        parts += ["source", source]
    parts.append("repeat 5 timeout 1" if verb == "ping" else "numeric timeout 1 probe 1 ttl 1 5")
    return name, params, " ".join(parts)


def make_proxy(tmp_path, *, read_only=False):
    module = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(module, tmp_path)
    section = contracts._section()
    section.update(
        ssh_platform=PLATFORM,
        account_role="read-only" if read_only else "admin-bounded",
        device_types=["router"],
        enabled_queries=sorted({case[0] for case in CASES.values()}),
        read_inventory=INVENTORY,
    )
    if not read_only:
        section["role_boundary"] = "catalogue"
    section["egress"]["tcp_ports"].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, PLATFORM)))
    return module.Proxy()


def device(tmp_path, monkeypatch, body, *, version=VERSION, read_only=False,
           banner="", banner_tail="", privilege=None):
    relay = make_proxy(tmp_path, read_only=read_only)
    calls = []
    commands = tmp_path / "pty-commands"

    def exec_read(auth, platform, command):
        assert platform == PLATFORM
        calls.append(command)
        return 0, version

    child = """
import sys
import time
from pathlib import Path

banner, banner_tail, prompt, body, privilege, log = sys.argv[1:]
if banner_tail:
    sys.stdout.write(banner)
    sys.stdout.flush()
    time.sleep(0.1)
    banner = banner_tail
sys.stdout.write(banner + prompt)
sys.stdout.flush()
with Path(log).open('w', buffering=1) as commands:
    for command in sys.stdin:
        commands.write(command)
        output = privilege if command.strip() == 'show privilege' else body
        if output == 'fixture: disconnect before prompt':
            break
        if output.endswith('--More--'):
            sys.stdout.write(output)
        else:
            sys.stdout.write(output.rstrip('\\n') + '\\n' + prompt)
        sys.stdout.flush()
"""
    spawn_pty = engine.core_session._spawn

    def spawn(call, env):
        del call
        prompt = "lab-router>" if read_only else "lab-router#"
        return spawn_pty([sys.executable, "-I", "-c", child, banner, banner_tail, prompt, body,
                          privilege or "", str(commands)], env)

    monkeypatch.setattr(engine, "_exec_read", exec_read)
    monkeypatch.setattr(engine, "host_key_line", lambda auth, address, platform: "192.0.2.10 ssh-ed25519 dGVzdA==")
    monkeypatch.setattr(engine.core_session, "_spawn", spawn)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    return relay, calls, commands


async def request(relay, client, query, params, *, identifier=1):
    forwarded = relay.request(contracts._request(identifier, "ssh_read", {
        "target": "device-a", "platform": PLATFORM, "query": query, "parameters": params,
    }))
    assert forwarded is not None, f"Proxy refused enrolled query {query}"
    message = json.loads(forwarded)
    arguments = message["params"]["arguments"]
    response = await client.call_tool("ssh_read", arguments)
    assert not response.is_error
    result = response.data
    wire = relay.response(json.dumps({
        "jsonrpc": "2.0", "id": message["id"],
        "result": {"structuredContent": result, "isError": False,
                   "content": [{"type": "text", "text": json.dumps(result)}]},
    }).encode())
    assert wire is not None
    return json.loads(wire)["result"]["structuredContent"]


def read(relay, query, params):
    async def run():
        async with Client(server.mcp) as client:
            return await request(relay, client, query, params)

    return asyncio.run(run())


@pytest.mark.parametrize("case", [name for name in CASES if "bad" not in name])
def test_measured_probe(tmp_path, monkeypatch, case):
    query, params, command = case_arguments(case)
    capture = case if case.endswith("_loss") or case == "loopback4_ping" else query
    body = (FIXTURES / f"{capture}.out").read_text()
    relay, calls, commands = device(tmp_path, monkeypatch, body)
    answer = read(relay, query, params)

    assert calls == ["show version"]
    assert commands.read_text().splitlines() == [command]
    assert answer["ok"] and answer["status"] == "ok"
    assert answer["untrusted_device_output"].strip() == body.strip()
    assert answer["complete"] and answer["normalized"]["coverage"]["complete"]
    assert answer["firmware_support"]["status"] == "tested"
    probe = answer["probe"]
    assert (probe["destination"], probe["source_interface"], probe["vrf"]) == (
        params["address"], params.get("source"), params.get("vrf"),
    )
    loss = case.endswith("_loss")
    if query.startswith("ping"):
        assert probe["sent"] == 5 and probe["received"] == (0 if loss else 5)
        assert probe["loss_percent"] == (100 if loss else 0)
        assert probe["reachable"] == (not loss)
        if "source" in params:
            expected_source = {"Ethernet0/1.10": ("198.51.100.7", "2001:db8:2::7"),
                               "Ethernet0/2": ("192.0.2.7", "2001:db8:1::7"),
                               "Loopback0": ("203.0.113.7", None)}
            assert probe["source_address"] == expected_source[params["source"]][":" in params["address"]]
    else:
        assert (probe["max_hops"], probe["probes_per_hop"], probe["timeout_seconds"]) == (5, 1, 1)
        assert probe["reached_destination"] == (not loss)
        assert probe["destination_replied"] == (not loss)
        if loss:
            assert probe["hops"] == [{"hop": i, "result": "*"} for i in range(1, 6)]


@pytest.mark.parametrize("case", [name for name in CASES if "bad" in name] + list(RO_CASES))
def test_measured_refusal(tmp_path, monkeypatch, case):
    is_ro = case in RO_CASES
    query, params, command = case_arguments(case)
    capture = "ro_" + query if is_ro else case
    path = FIXTURES / f"{capture}.out"
    bad_source = case.endswith("_bad_source")
    privilege = (FIXTURES / "show_privilege_admin.out").read_text() if bad_source else None
    relay, calls, commands = device(tmp_path, monkeypatch, path.read_text(), read_only=is_ro, privilege=privilege)
    answer = read(relay, query, params)

    assert not answer["ok"] and not answer["complete"]
    assert not answer["normalized"]["coverage"]["complete"]
    if bad_source:
        assert answer["error_code"] == "invalid_argument"
        assert answer["status"] == "unparsed"
        assert "source interface" in answer["error"]
    else:
        assert answer["status"] == ("not_applicable" if case.endswith("_bad_vrf") else "permission_denied")
    assert "probe" not in answer
    assert calls == ["show version"]
    assert commands.read_text().splitlines() == ([command, "show privilege"] if bad_source else [command])


def test_bad_source_requires_verified_privilege(tmp_path, monkeypatch):
    query, params, command = case_arguments("ping_bad_source")
    privilege = (FIXTURES / "show_privilege_admin.out").read_text().replace("level is 15", "level is 5")
    relay, _, commands = device(tmp_path, monkeypatch, (FIXTURES / "ping_bad_source.out").read_text(),
                                 privilege=privilege)
    answer = read(relay, query, params)

    assert not answer["ok"] and answer["status"] == "permission_denied"
    assert commands.read_text().splitlines() == [command, "show privilege"]


@pytest.mark.parametrize(("case", "hops", "reached", "mpls"), [
    ("trace_alternate_ip", 1, True, {}),
    ("trace_mpls_label", 5, False, {3: [16]}),
    ("trace_mpls_stack", 4, True, {2: [16, 17], 3: [16]}),
])
def test_documented_traceroute(tmp_path, monkeypatch, case, hops, reached, mpls):
    query, params, command = case_arguments(case)
    body = (CISCO / f"{case}.out").read_text()
    relay, _, commands = device(tmp_path, monkeypatch, body)
    answer = read(relay, query, params)

    assert answer["ok"] and answer["complete"]
    assert answer["probe"]["reached_destination"] is reached
    assert answer["probe"]["destination_replied"] is False
    measured = answer["probe"]["hops"]
    assert len(measured) == hops
    assert [row["result"] for row in measured] == [line.split(maxsplit=1)[1] for line in body.splitlines()
                                                    if line.lstrip()[:1].isdigit()]
    assert {row["hop"]: row["mpls_labels"] for row in measured if "mpls_labels" in row} == mpls
    assert commands.read_text().splitlines() == [command]


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("split_banner", [False, True], ids=["single-write", "split-after-notice"])
def test_login_banner_is_not_the_probe_prompt(tmp_path, monkeypatch, read_only, split_banner):
    query, params, command = case_arguments("global4_ping")
    body = (FIXTURES / "ping.out").read_text()
    # Synthetic login banner. The probe body is from the real IOL XE capture.
    banner = "##### Authorized access only #####\nnotice#"
    banner_tail = "\nnotice> More instructions\n"
    if not split_banner:
        banner += banner_tail
        banner_tail = ""
    relay, _, commands = device(tmp_path, monkeypatch, body, read_only=read_only,
                                 banner=banner, banner_tail=banner_tail)
    monkeypatch.setattr(engine, "_SSH_READ_TIMEOUT_SECONDS", 3.0)
    answer = read(relay, query, params)

    assert answer["ok"] and answer["complete"]
    assert answer["untrusted_device_output"].strip() == body.strip()
    assert commands.read_text().splitlines() == [command]


@pytest.mark.parametrize("case", ["blue6_ping_source", "blue6_trace_loss"])
@pytest.mark.parametrize("mutation", ["short", "unknown", "pager", "false_prompt"])
def test_incomplete_capture(tmp_path, monkeypatch, case, mutation):
    capture = "ping_ipv6_vrf_source" if case == "blue6_ping_source" else case
    body = (FIXTURES / f"{capture}.out").read_text()
    if mutation == "short":
        body = "\n".join(body.splitlines()[:4])
    elif mutation == "unknown":
        body += "unrecognized line\n"
    elif mutation == "pager":
        body += "--More--"
    else:
        body += "lab-router# is mentioned in this line\n"
    relay, _, _ = device(tmp_path, monkeypatch, body)
    query, params, _ = case_arguments(case)
    answer = read(relay, query, params)

    assert not answer["ok"] and not answer["complete"]
    assert not answer["normalized"]["coverage"]["complete"]
    assert answer["status"] == ("truncated" if mutation == "pager" else "unparsed")
    assert answer["error_code"] == "incomplete_output"
    assert "probe" not in answer


def test_untested_firmware_warns_and_runs(tmp_path, monkeypatch):
    query, params, command = case_arguments("blue6_ping_source")
    body = (FIXTURES / "ping_ipv6_vrf_source.out").read_text()
    relay, calls, commands = device(tmp_path, monkeypatch, body, version=VERSION.replace("17.18.2", "17.99.1"))
    answer = read(relay, query, params)

    assert answer["probe"]["received"] == 5
    assert answer["firmware_support"]["status"] == "untested"
    assert [warning["code"] for warning in answer["warnings"]] == ["firmware_untested"]
    assert calls == ["show version"]
    assert commands.read_text().splitlines() == [command]


@pytest.mark.parametrize("override", [
    {"address": "203.0.113.1"}, {"address": "192.0.2.1"}, {"address": "2001:db8:1::/64"},
    {"vrf": "elsewhere"}, {"source": "Ethernet0/3"}, {"source": "Ethernet0/2\nshow version"},
    {"source": "Ethernet0/2;reload"}, {"timeout": "0"},
])
def test_inventory_and_fixed_limits_at_both_boundaries(tmp_path, override):
    relay = make_proxy(tmp_path)
    query, params, _ = case_arguments("blue6_ping_source")
    bad = {**params, **override}
    wire = contracts._request(1, "ssh_read", {
        "target": "device-a", "platform": PLATFORM, "query": query, "parameters": bad,
    })
    emitted = []
    relay._emit = emitted.append
    assert relay.request(wire) is None and "error" in emitted[-1]
    with pytest.raises(ValueError):
        render_read_query(PLATFORM, query, bad, INVENTORY)


@pytest.mark.parametrize("command", [
    "ping vrf {vrf} ipv6 {address} repeat 50 timeout 1",
    "traceroute ipv6 {address} numeric timeout 1 probe 1 ttl 1 30",
    "traceroute vrf {vrf} {address}",
])
def test_policy_refuses_unbounded_templates(command):
    with pytest.raises(RuntimeError):
        _validate_query_command(PLATFORM, command)


def test_admin_bounded_role_cannot_enable_unrelated_queries(tmp_path):
    relay = make_proxy(tmp_path)
    query, params, _ = case_arguments("blue6_ping_source")
    forwarded = relay.request(contracts._request(1, "ssh_read", {
        "target": "device-a", "platform": PLATFORM, "query": query, "parameters": params,
    }))
    assert forwarded is not None
    envelope = contracts._envelope(forwarded)
    envelope["enabled_queries"].append("version")
    encoded = urlsafe_b64encode(json.dumps(envelope).encode()).decode().rstrip("=")
    with pytest.raises(AuthenticationContextError):
        TargetAuth.decode("device-a", encoded)

    inventory = tmp_path / "inventory.json"
    document = json.loads(inventory.read_text())
    document["devices"][0]["helper"]["enabled_queries"].append("version")
    contracts._write(inventory, document)
    emitted = []
    relay._emit = emitted.append
    assert relay.request(contracts._request(2, "ssh_read", {
        "target": "device-a", "platform": PLATFORM, "query": "version",
    })) is None
    assert emitted[-1]["error"]["data"]["category"] == "role_rejected"


def test_admin_bounded_role_cannot_use_another_device_tool(tmp_path):
    relay = make_proxy(tmp_path)
    contracts._assert_policy_error(relay, contracts._request(1, "tcp_probe", {
        "target": "device-a", "port": 22,
    }))


def test_probe_disconnect_before_final_prompt(tmp_path, monkeypatch):
    query, params, command = case_arguments("global4_ping")
    relay, _, commands = device(tmp_path, monkeypatch, "fixture: disconnect before prompt")
    answer = read(relay, query, params)
    assert not answer["ok"] and answer["error_code"] == "timeout"
    assert "probe" not in answer and not answer.get("untrusted_device_output")
    assert commands.read_text().splitlines() == [command]


def test_privilege_disconnect_preserves_probe_refusal(tmp_path, monkeypatch):
    query, params, command = case_arguments("ping_bad_source")
    relay, _, commands = device(tmp_path, monkeypatch, (FIXTURES / "ping_bad_source.out").read_text(),
                                 privilege="fixture: disconnect before prompt")
    answer = read(relay, query, params)
    assert not answer["ok"] and answer["status"] == "permission_denied"
    assert "probe" not in answer
    assert commands.read_text().splitlines() == [command, "show privilege"]


def test_reported_malformed_probe_address_has_no_summary(tmp_path, monkeypatch):
    query, params, _ = case_arguments("global4_ping")
    body = (FIXTURES / "ping.out").read_text().replace("198.51.100.1", "198.51.100.999")
    relay, _, _ = device(tmp_path, monkeypatch, body)
    answer = read(relay, query, params)
    assert not answer["complete"] and answer["status"] == "unparsed"
    assert answer["error_code"] == "incomplete_output"
    assert "probe" not in answer
