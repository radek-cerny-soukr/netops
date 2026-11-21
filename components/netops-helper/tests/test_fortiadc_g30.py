"""G30 via MCP and the production HTTPS parser with measured VM220 device payloads."""

from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from netops import worker
from netops.files import write_private
from netops_core import fortiadc_https, hostkey
from netops_core.audit import Recorder
from netops_helper import audit, engine, proxy, server
from test_fortinet_connection_count import replay

FIXTURES = Path(__file__).parent / "fixtures" / "fortiadc_g30"
DER = b"synthetic test leaf"
PIN = hashlib.sha256(DER).hexdigest()
TOKEN = "fixture-session-token"


class Response:
    def __init__(self, status, payload):
        self.status = status
        self.data = json.dumps(payload).encode()
        self.length = len(self.data)

    def getheaders(self):
        return [("Set-Cookie", "last_access_time=12345; Path=/; HttpOnly")]

    def read(self, maximum):
        data = self.data[:maximum]
        self.length -= len(data)
        return data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


class Wire:
    def __init__(self, fixture, scenario):
        self.fixture = fixture
        self.scenario = scenario
        self.commands = []
        self.sock = None

    def connect(self):
        self.sock = self

    def close(self):
        self.sock = None

    def getpeercert(self, binary_form):
        return b"incorrect peer" if self.scenario == "wrong_pin" else DER

    def request(self, method, path, body, headers):
        self.commands.append((method, path))
        if path == "/api/user/login":
            assert method == "POST" and json.loads(body)["username"] == "fixture-user"
            self.answer = Response(200, {"token": TOKEN})
        elif path == "/api/user/logout":
            self.answer = Response(200, {"payload": 0})
        else:
            assert method == "GET" and headers["Authorization"] == "Bearer " + TOKEN
            url = urlsplit(path)
            parameters = parse_qs(url.query)
            assert parameters["vdom"] == ["global"]
            selector = url.path.removeprefix("/api/")
            if "pkey" in parameters:
                selector += ":" + parameters["pkey"][0]
            if self.scenario == "denied" and selector == "load_balance_real_server_ssl_profile":
                self.answer = Response(403, {})
            else:
                self.answer = Response(200, self.fixture[selector])

    def getresponse(self):
        return self.answer


@pytest.mark.parametrize("scenario", ["ok", "empty", "derived_backend", "denied", "count_mismatch", "bad_acme", "identity_refused", "wrong_pin", "no_egress",
                                      "unverifiable_ssh_key", "invalid_https_identity"])
def test_inventory_mcp(tmp_path, monkeypatch, replay, scenario):
    import asyncio

    fixture = json.loads((FIXTURES / "rest.json").read_text())
    cli = (FIXTURES / "acme.out").read_text()
    if scenario == "empty":
        # Derived VM220 response: the live empty intermediate CA payload is used for each empty table.
        cli = ""
        empty = fixture["system_certificate_intermediate_ca"]
        fixture = {endpoint: empty if isinstance(data["payload"], list) else data
                   for endpoint, data in fixture.items()}
    if scenario == "bad_acme":
        cli = cli[:cli.index("== [ host01")]
    if scenario == "derived_backend":
        # Derived VM220 response: the lab has no cert configured for an active backend profile.
        fixture["load_balance_real_server_ssl_profile"]["payload"][2]["local_cert"] = "host01"
    if scenario == "count_mismatch":
        fixture["system_certificate_local_cert_group"]["payload"][0]["member_count"] += 1
    # Use the real SSH adapter with fake OpenSSH and a pinned response.
    install, verify = replay
    command = "get system certificate local"
    answers = {command: cli}
    if scenario == "identity_refused":
        # 1.0.12 summary 702 (550-rv/3): the account's SSH `get system status` is refused; HTTPS still answers.
        answers["get system status"] = "Command fail. Return code is -61 (Operation not permitted)\n"
    target = install("fortiadc", answers, prompt="LLLLLLLL-LLL $ ")
    if scenario == "invalid_https_identity":
        fixture["platform/info"]["payload"]["firmwareVersion"] = "fixture-invalid-firmware"
    if scenario == "unverifiable_ssh_key":
        def invalid_host_key(*_args):
            raise hostkey.HostKeyError("fixture private detail")

        monkeypatch.setattr(engine, "host_key_line", invalid_host_key)
    https = Wire(fixture, scenario)
    monkeypatch.setattr(fortiadc_https.http.client, "HTTPSConnection", lambda *args, **kw: https)
    helper = tmp_path / "helper"
    helper.mkdir(mode=0o700)
    device = {"name": "adc", "platform": "fortiadc", "address": "192.0.2.40", "port": 22,
              "role": "lab", "credential": "ro", "host_key_fingerprint": target.host_key_fingerprint,
              "host_key": target.host_key,
              "legacy_ssh": None, "auditor": None, "helper": {"account_role": "read-only", "ssh_platform": "fortiadc",
                                          "enabled_queries": ["certificate_inventory"], "read_inventory": {},
                                          "fortios_rest_certificate_sha256": PIN,
                                          "egress": {"addresses": ["192.0.2.40"],
                                                     "tcp_ports": [22] if scenario == "no_egress" else [22, 443],
                                                     "tcp_port_ranges": [], "udp_ports": [], "udp_port_ranges": [],
                                                     "allow_dns": False, "allow_icmp": False, "tls_server_names": []}}}
    write_private(helper / "inventory.json", json.dumps({"version": 2, "devices": [device]}).encode())
    write_private(helper / "vault.json", json.dumps({"version": 2, "credentials": {
        "ro": {"kind": "password", "login": "fixture-user", "value": "fixture-only"}}}).encode())
    monkeypatch.setattr(worker, "STATE", tmp_path)
    monkeypatch.setattr(proxy, "INVENTORY", helper / "inventory.json")
    monkeypatch.setattr(audit, "_RECORDER", Recorder(helper / "operations.jsonl", "helper"))
    monkeypatch.setattr(engine, "_paced_connection", lambda *args: nullcontext())
    engine._HOST_KEY_LINE_CACHE.clear()
    client = worker.HelperBridge()
    response = asyncio.run(client.call(server.mcp, "ssh_read", {
        "target": "adc", "platform": "fortiadc", "query": "certificate_inventory"}))
    assert TOKEN not in json.dumps(response)
    if scenario == "unverifiable_ssh_key":
        result = response["structuredContent"]
        assert not result["ok"] and result["error_code"] == "host_key_mismatch"
        assert https.commands == [] and "fixture private detail" not in str(response)
        return
    if scenario == "identity_refused":
        assert verify() == ["get system status"]
    elif scenario != "no_egress":
        assert verify() == ["get system status", command]
    if scenario in {"wrong_pin", "no_egress"}:
        assert https.commands == []
        assert "tls_pin_mismatch" in json.dumps(response) if scenario == "wrong_pin" else response["isError"]
        return
    assert "structuredContent" in response, response
    result = response["structuredContent"]
    if scenario == "invalid_https_identity":
        assert not result["ok"] and result["error_code"] == "product_identity"
        assert "fixture-invalid-firmware" not in str(response)
        assert https.commands[-1] == ("GET", "/api/user/logout") and https.sock is None
        return
    if scenario == "empty":
        assert result["ok"] and result["complete"] and result["status"] == "empty", result
        assert result["certificates"] == [] and result["observed_count"] == 0
        return
    assert result["ok"] and result["observed_count"] == 6, result
    assert result["complete"] is (scenario in {"ok", "derived_backend"}), result
    if scenario == "identity_refused":
        assert result["missing"], result
    custom = next(row for row in result["certificates"] if row["name"] == "host01")
    assert custom["san"] == "DNS:host03, IP Address:192.0.2.46"
    references = [{"kind": "client_ssl_profile", "name": "host04"},
                  {"kind": "local_cert_group", "name": "host02"}]
    if scenario == "derived_backend":
        references.append({"kind": "real_server_ssl_profile", "name": "LB_RS_SSL_PROF_MEDIUM"})
    assert custom["references"] == references
    assert custom["acme_status"] == (None if scenario in {"bad_acme", "identity_refused"} else "not_set")
    assert https.commands[-1] == ("GET", "/api/user/logout")
