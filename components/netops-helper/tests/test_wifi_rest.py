"""RO REST boundary and regression fixtures from the 80F 8.0.2 measurement."""
import dataclasses
import hashlib
import io
import sys
import json
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from conftest import _target
from netops_helper import engine, wifi_rest as r
from netops_helper.auth import EgressPolicy, TargetAuth

TOKEN = "synthetic-rest-token-canary-12345"
CERT = b"synthetic DER certificate"
PIN = hashlib.sha256(CERT).hexdigest()
FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name):
    return json.loads((FIXTURES / ("fortios_80f_802_wifi_rest_" + name + ".json")).read_text())


def auth(**changes):
    defaults = dict(fortios_rest_token=TOKEN, fortios_rest_certificate_sha256=PIN,
                    egress=EgressPolicy(addresses=("127.0.0.1",), tcp_ports=(443,)))
    defaults.update(changes)
    return dataclasses.replace(_target("fortinet", "system_status"), **defaults)


@pytest.fixture(autouse=True)
def audit(monkeypatch):
    events = []
    monkeypatch.setattr(engine, "record", lambda event, **fields: events.append((event, fields)))
    r._rates.clear()
    return events


@pytest.fixture
def transport(monkeypatch):
    peer = MagicMock()
    peer.getpeercert.return_value = CERT
    context = MagicMock()
    context.wrap_socket.return_value = peer
    monkeypatch.setattr(r.ssl, "SSLContext", lambda *a: context)
    monkeypatch.setattr(r.socket, "create_connection", lambda *a, **k: MagicMock())
    connection = MagicMock()
    response = connection.getresponse.return_value
    response.status = 200
    response.getheader.side_effect = lambda key, default=None: default
    response.read1.side_effect = [json.dumps(fixture("monitor_wifi_client")).encode(), b""]
    monkeypatch.setattr(r.http.client, "HTTPSConnection", lambda *a, **k: connection)
    return peer, connection, response


@pytest.mark.parametrize("method,path", [
    ("POST", r.MONITOR+"client"), ("PUT", r.MONITOR+"client"), ("DELETE", r.MONITOR+"client"),
    ("HEAD", r.MONITOR+"client"), ("GET", "/api/v2/cmdb/system/global"),
    ("GET", r.MONITOR+"client?filter=anything"), ("GET", r.MONITOR+"../system/status"),
    ("GET", "https://evil.invalid/api/v2/monitor/wifi/client"),
    ("GET", "/api/v2/log/memory/event/wireless?rows=200"),
    ("GET", "/api/v2/log/memory/event/wireless?rows=20"), ("GET", r.MONITOR+"station-capability"),
])
def test_allowlist_rejects_before_connect(monkeypatch, method, path):
    monkeypatch.setattr(r.socket, "create_connection", lambda *a, **k: pytest.fail("network used"))
    with pytest.raises(ValueError, match="policy_scope"):
        r.get(auth(), path, method=method, addresses=("127.0.0.1",))


def test_pin_required_before_connect(monkeypatch):
    monkeypatch.setattr(r.socket, "create_connection", lambda *a, **k: pytest.fail("network used"))
    with pytest.raises(ValueError, match="pin or CA"):
        r.get(dataclasses.replace(auth(), fortios_rest_certificate_sha256=None), r.MONITOR+"client")


def test_pin_is_checked_before_sending_token(transport):
    peer, connection, response = transport
    peer.getpeercert.return_value = b"wrong cert"
    with pytest.raises(ValueError, match="certificate_pin_mismatch") as error:
        r.get(auth(), r.MONITOR+"client", addresses=("127.0.0.1",))
    assert error.value.code == "tls_pin_mismatch"
    connection.request.assert_not_called()
    peer.close.assert_called()


def test_get_bearer_and_token_echo_redaction(transport):
    peer, connection, response = transport
    body = fixture("monitor_wifi_client")
    body["results"][0]["ssid"] = TOKEN
    body["results"][0]["unexpected"] = {"token": TOKEN}
    response.read1.side_effect = [json.dumps(body).encode(), b""]
    result = r.get(auth(), r.MONITOR+"client", addresses=("127.0.0.1",))
    assert TOKEN not in json.dumps(result)
    args, kwargs = connection.request.call_args
    assert args == ("GET", r.MONITOR+"client")
    assert kwargs["headers"]["Authorization"] == "Bearer " + TOKEN
    connection.close.assert_called()


def test_rest_token_is_redacted_from_ssh_schema_and_rest_output(transport):
    target = auth()
    assert TOKEN in target.redaction_secrets and TOKEN in target.secrets
    text = "interface note " + TOKEN + " end"
    assert TOKEN not in engine._redact_output(text, target)
    assert TOKEN not in engine._redact_schema_report({"untrusted_device_output": text, "list": [TOKEN]}, target)
    peer, connection, response = transport
    body = fixture("monitor_wifi_client")
    body["results"][0]["ssid"] = TOKEN
    response.read1.side_effect = [json.dumps(body).encode(), b""]
    assert TOKEN not in json.dumps(engine._wifi_rest_result(target, (("records", r.MONITOR + "client"),)))


@pytest.mark.parametrize("status", [301, 302, 401, 403, 429, 500])
def test_errors_never_follow_redirects_or_return_response_body(transport, status):
    _, connection, response = transport
    response.status = status
    with pytest.raises(r.RestError, match="fortios_rest_http") as error:
        r.get(auth(), r.MONITOR+"client", addresses=("127.0.0.1",))
    assert error.value.code == {401: "authentication_failed", 403: "authorization_failed", 429: "rate_limited", 500: "http_server_error"}.get(status, "http_status")
    assert error.value.http_status == status
    response.read1.assert_not_called()
    assert connection.request.call_count == 1


@pytest.mark.parametrize("declared", [True, False])
def test_size_limit_including_chunked_response(transport, declared):
    _, _, response = transport
    response.getheader.side_effect = lambda key, default=None: str(r.MAX_BYTES+1) if declared and key == "Content-Length" else default
    response.read1.side_effect = [b"x"*(r.MAX_BYTES+1)]
    with pytest.raises(ValueError, match="too_large"):
        r.get(auth(), r.MONITOR+"client", addresses=("127.0.0.1",))


def test_rate_limit_per_target(transport):
    target = auth(fortios_rest_rate_limit={"requests": 1, "window_seconds": 60})
    r.get(target, r.MONITOR+"client", addresses=("127.0.0.1",))
    with pytest.raises(ValueError, match="rate_limit") as error:
        r.get(target, r.MONITOR+"client", addresses=("127.0.0.1",))
    assert error.value.code == "rate_limited"
    assert error.value.http_status is None


def test_egress_outside_allowlist_is_a_structured_subcode(monkeypatch):
    monkeypatch.setattr(r.socket, "create_connection", lambda *a, **k: pytest.fail("network used"))
    with pytest.raises(r.RestError) as error:
        r.get(auth(), r.MONITOR+"client", addresses=("203.0.113.9",))
    assert error.value.code == "egress_denied"


def test_egress_checked_even_with_token(transport):
    with pytest.raises(ValueError, match="egress_scope"):
        r.get(auth(), r.MONITOR+"client", addresses=("192.0.2.100",))
    transport[1].request.assert_not_called()


@pytest.mark.parametrize("name,path", [
    ("monitor_wifi_client", r.MONITOR+"client"),
    ("monitor_wifi_managed_ap", r.MONITOR+"managed_ap"),
    ("monitor_wifi_ap_status", r.MONITOR+"ap_status"),
    ("monitor_wifi_rogue_ap", r.MONITOR+"rogue_ap"),
    ("monitor_wifi_interfering_ap", r.MONITOR+"interfering_ap"),
])
def test_measured_parsers(name, path):
    result = r.parse(path, fixture(name))
    assert result
    if name == "monitor_wifi_client":
        assert result[0]["mac"] == "00:00:5e:00:53:81"
        assert (result[0]["rssi_dbm"], result[0]["snr_db"], result[0]["link_rx_mbps"]) == (-40, 55, 573.5)
        assert result[0]["connected_seconds"] >= 0
    if name == "monitor_wifi_ap_status":
        assert result["wtp_active"] == 2


@pytest.mark.parametrize("change", [{"status":"error"}, {"results":"bad"}, {"http_method":"POST"}, {"vdom":"other"}])
def test_malformed_or_wrong_scope_is_not_live_evidence(change):
    doc = fixture("monitor_wifi_client")
    doc.update(change)
    with pytest.raises(ValueError, match="unparsed"):
        r.parse(r.MONITOR+"client", doc)


def fake_get(monkeypatch, echo=False):
    def get(target, path, **kwargs):
        name = "device_query" if path == r.DEVICES else "wireless_log" if path == r.WIRELESS_LOG or r._log_mac(path) is not None else "monitor_wifi_"+path.rsplit("/", 1)[-1]
        doc = fixture(name)
        if r._log_mac(path) is not None:
            doc['results'] = [row for row in doc['results'] if row.get('stamac') == r._log_mac(path)]
            doc['total_lines'] = len(doc['results'])
        if echo and path.endswith("client"):
            doc["results"][0]["ssid"] = TOKEN
        return doc
    monkeypatch.setattr(r, "get", get)


def test_tools_filters_ap_join_and_audit_do_not_expose_token(monkeypatch, audit):
    fake_get(monkeypatch, echo=True)
    answer = engine.wifi_clients(auth(), mac="00:00:5e:00:53:81")
    assert answer["ok"] and len(answer["records"]) == 1
    assert TOKEN not in json.dumps(answer) and TOKEN not in json.dumps(audit)
    assert any(fields.get("request") == "GET " + r.MONITOR+"client" for _,fields in audit)
    assert answer["records"][0]["ap"] == "name-1"
    assert "ap_serial" not in answer["records"][0]
    assert engine.wifi_aps_live(auth())["summary"]["wtp_active"] == 2
    assert engine.wifi_rogue(auth(), full=True)["rogue"]
    assert engine.wifi_clients(auth(), ssid="absent")["records"] == []


def test_no_token_returns_unsupported_without_contact(monkeypatch):
    monkeypatch.setattr(r, "get", lambda *a, **k: pytest.fail("network used"))
    target = dataclasses.replace(auth(), fortios_rest_token=None)
    for tool in (engine.wifi_clients, engine.wifi_aps_live, engine.wifi_rogue):
        answer = tool(target)
        assert answer["error_code"] == "unsupported" and "fortios_rest_credential" in answer["error"]


def test_triage_with_and_without_token_and_failed_rest(monkeypatch):
    from test_triage_wifi import outputs, NOW, CLIENT, AP2
    texts = outputs()
    def read(target, platform, query, parameters=None):
        text = texts[query]
        return {"ok": True, "text": text, "content_sha256": hashlib.sha256(text.encode()).hexdigest()}
    monkeypatch.setattr(engine, "triage_wifi_read", read)
    fake_get(monkeypatch)
    original = r.get
    def get(target, path, **kwargs):
        doc = original(target, path, **kwargs)
        if path.endswith("client"):
            doc["results"][0].update(mac=CLIENT, wtp_id=AP2, wtp_name="current AP", wtp_radio=2)
        if path.endswith("managed_ap"):
            doc["results"][0].update(serial=AP2, wtp_id=AP2)
        return doc
    monkeypatch.setattr(r, "get", get)
    live = engine.triage_wifi(auth(), CLIENT)
    assert live["chain"]["live_client"]["rssi_dbm"] == -40
    assert live["chain"]["access_point"]["serial"] == AP2
    # the SSH wtp-status carries no name; the controller's name comes with the REST station
    assert live["chain"]["access_point"]["name"] == live["chain"]["live_client"]["ap_name"] is not None
    assert not any(item["step"] == "client_rssi" for item in live["missing"])
    brief = engine.triage_wifi(auth(), CLIENT, summary=True)
    assert brief["view"] == "summary" and brief["verdict"] == live["verdict"] and brief["missing"] == live["missing"]
    assert [item["id"] for item in brief["findings"]] == [item["id"] for item in live["findings"]]
    assert all({"id", "severity", "object", "fact", "text"} <= set(item) for item in brief["findings"])
    assert brief["chain"]["live_client"]["rssi_dbm"] == -40 and brief["chain"]["access_point"]["name"] == live["chain"]["access_point"]["name"]
    assert "sources" not in brief and "vantage" not in brief
    assert len(json.dumps(brief)) < len(json.dumps(live)) / 2
    assert "view" not in engine.triage_wifi(auth(), CLIENT, summary=False)
    assert live["verdict"] == "no_rf_fault_found"
    offline = engine.triage_wifi(dataclasses.replace(auth(), fortios_rest_token=None), CLIENT)
    assert any(item["step"] == "client_rssi" for item in offline["missing"])
    monkeypatch.setattr(r, "get", lambda *a, **kw: (_ for _ in ()).throw(ValueError(TOKEN)))
    failed = engine.triage_wifi(auth(), CLIENT)
    assert TOKEN not in json.dumps(failed)
    assert any(item["reason"] == "rest_unavailable" for item in failed["missing"])


def test_inventory_enrollment_requires_api_token_trust_and_egress():
    from test_proxy_contracts import _device, _section
    from netops_helper import inventory as i
    # Use the inventory's own public parser rather than constructing an unchecked section.
    from netops_core import inventory as core
    section = _section()
    section.update(fortios_rest_credential="api-ro", fortios_rest_certificate_sha256=PIN)
    section["egress"]["tcp_ports"].append(443)
    device = core._device(0, _device(section))
    kinds = {"api-ro":"api-token", "device-a-account":"password", "device-a-community":"snmpv3-authpriv"}
    assert i.section(device, kinds).fortios_rest_credential == "api-ro"
    for patch in ({"fortios_rest_certificate_sha256":None}, {"fortios_rest_certificate_sha256":"bad"}):
        bad = dict(section, **patch)
        device = core._device(0, _device(bad))
        with pytest.raises(i.InventoryError):
            i.section(device, kinds)
    device = core._device(0, _device(section))
    with pytest.raises(i.InventoryError, match="api-token"):
        i.section(device, dict(kinds, **{"api-ro":"password"}))


@pytest.mark.parametrize("rest_port", [None, 443, 8443])
def test_proxy_injects_only_for_wifi_tools_and_redacts_server_echo(tmp_path, rest_port):
    from test_proxy_contracts import _load_proxy, _configure, _section, _inventory, _device, _write, _request
    from base64 import urlsafe_b64decode
    module = _load_proxy()
    inventory, vault, _, _ = _configure(module, tmp_path)
    section = _section()
    section.update(fortios_rest_credential="api-ro", fortios_rest_certificate_sha256=PIN)
    section["enabled_queries"].append("wifi_events")
    if rest_port is not None:
        section["fortios_rest_port"] = rest_port
    section["egress"]["tcp_ports"].append(rest_port or 443)
    _write(inventory, _inventory(_device(section)))
    doc = json.loads(vault.read_text())
    doc["credentials"]["api-ro"] = {"kind":"api-token", "login":None, "value":TOKEN}
    _write(vault, doc, 0o600)
    proxy = module.Proxy()
    proxy._emit = lambda *args: None
    assert proxy._target_scope_payload("device-a")["fortios_wifi_rest_enrolled"] is True
    assert proxy._target_scope_payload("device-a")["fortios_rest_port"] == (rest_port or 443)
    for number, tool in enumerate(("wifi_clients", "wifi_aps_live", "wifi_rogue", "wifi_triage", "ssh_read")):
        args = {"target":"device-a"}
        if tool == "wifi_triage":
            args["mac"] = "00:00:5e:00:53:81"
        if tool == "ssh_read":
            args.update(platform="fortinet", query="system_status")
        forward = proxy.request(_request(number, tool, args))
        assert forward is not None
        context = json.loads(forward)["params"]["arguments"]["auth_context"]
        decoded = TargetAuth.decode("device-a", context)
        if tool == "ssh_read":
            assert decoded.fortios_rest_token is None
        else:
            assert decoded.fortios_rest_port == (rest_port or 443)
            assert decoded.fortios_rest_token == TOKEN
            assert TOKEN not in repr(decoded)
            raw = json.dumps({"jsonrpc":"2.0", "id":number, "result":{
                "content":[{"type":"text", "text":json.dumps({"ssid":TOKEN})}],
                "structuredContent":{"ssid":TOKEN}}}).encode()
            assert TOKEN.encode() not in proxy.response(raw)
    assert len(proxy.rate_history["device-a"]) == 25  # 3+2+4+15+1
    assert len(proxy.triage_history["device-a"]) == 15


def test_ca_trust_uses_validated_file_and_hostname_check(transport, monkeypatch):
    from netops_helper import inventory
    monkeypatch.setattr(inventory, "_checked_tls_ca", lambda where, path: path)
    calls = []
    context = MagicMock()
    context.wrap_socket.return_value = transport[0]
    monkeypatch.setattr(r.ssl, "create_default_context", lambda **kwargs: calls.append(kwargs) or context)
    target = dataclasses.replace(auth(), fortios_rest_certificate_sha256=None,
                                 tls_ca_certificate="/etc/netops-helper/certs/private.pem")
    r.get(target, r.MONITOR+"client", addresses=("127.0.0.1",))
    assert calls == [{"cafile":target.tls_ca_certificate}]
    assert context.wrap_socket.call_args.kwargs["server_hostname"] == target.host


def test_non_numeric_signal_remains_unknown():
    doc = fixture("monitor_wifi_client")
    doc["results"][0].update(signal="unexpected", snr=True)
    row = r.parse(r.MONITOR+"client", doc)[0]
    assert row["rssi_dbm"] is None and row["snr_db"] is None


def test_real_audit_schema_accepts_rest_and_never_records_token(monkeypatch, tmp_path):
    from netops_core.audit import Recorder
    path = tmp_path / "rest-audit.jsonl"
    recorder = Recorder(path, "helper")
    monkeypatch.setattr(engine, "record", recorder.record)
    fake_get(monkeypatch, echo=True)
    result = engine.wifi_clients(auth())
    audit = path.read_text()
    assert result["ok"] and TOKEN not in audit and TOKEN not in json.dumps(result)
    rows = [json.loads(line) for line in audit.splitlines()]
    assert any(row.get("request") == "GET "+r.MONITOR+"client" for row in rows)
    assert len(rows) == 8  # public tool plus three independently audited GETs


@pytest.mark.parametrize("filters", [{"mac":"bad"}, {"ssid":""}, {"ap":"AP\ncommand"}, {"ssid":False}])
def test_proxy_refuses_unsafe_filters(filters):
    from netops_helper import proxy
    with pytest.raises(proxy.ToolArgumentsError):
        proxy.Proxy._validate_tool_arguments("wifi_clients", {"target":"device-a", **filters})


def test_failed_audit_prevents_rest_contact(monkeypatch, tmp_path):
    from netops_core.audit import Recorder
    blocked = tmp_path / "audit.jsonl"
    blocked.mkdir()
    recorder = Recorder(blocked, "helper")
    monkeypatch.setattr(engine, "record", recorder.record)
    monkeypatch.setattr(r, "get", lambda *a, **k: pytest.fail("device contacted without audit"))
    from netops_helper.audit import AuditPreflightError
    with pytest.raises(AuditPreflightError):
        engine.wifi_clients(auth())


def test_deadline_covers_slow_http_headers(transport, monkeypatch):
    _, _, response = transport
    timer = MagicMock()
    scheduled = []
    def schedule(seconds, expire):
        scheduled.append((seconds, expire))
        return timer
    monkeypatch.setattr(r.threading, "Timer", schedule)
    r.get(auth(), r.MONITOR+"client", addresses=("127.0.0.1",))
    assert 0 < scheduled[0][0] <= r.TIMEOUT
    timer.start.assert_called_once()
    timer.cancel.assert_called_once()
    scheduled[0][1]()
    transport[0].shutdown.assert_called_once()


def test_malformed_band_does_not_break_parse():
    doc = fixture("monitor_wifi_client")
    doc["results"][0]["health"] = {"band": "5ghz"}
    assert r.parse(r.MONITOR+"client", doc)[0]["band"] is None


def test_bad_mac_rows_are_skipped_and_counted(monkeypatch):
    doc = fixture("monitor_wifi_client")
    good = doc["results"][0]
    doc["results"] = [dict(good, mac=good["mac"].upper()), dict(good, mac="not-a-mac"), dict(good, mac=None)]
    rows, unparsed = r.parse_counted(r.MONITOR+"client", doc)
    assert [row["mac"] for row in rows] == [good["mac"]] and unparsed == 2
    monkeypatch.setattr(r, "get", lambda target, path, **kw: doc if path.endswith("client") else fixture("monitor_wifi_managed_ap"))
    answer = engine.wifi_clients(auth())
    assert answer["ok"] and answer["unparsed_rows"] == 2 and len(answer["records"]) == 1


@pytest.mark.parametrize("error", [OSError("dns"), TypeError("x"), AttributeError("x")])
def test_unexpected_failures_become_rest_unavailable(monkeypatch, error):
    def get(*a, **k):
        raise error
    monkeypatch.setattr(r, "get", get)
    for tool in (engine.wifi_clients, engine.wifi_aps_live, engine.wifi_rogue):
        assert tool(auth())["error_code"] == "transport_error"


def test_triage_survives_rest_failure_with_broken_station(monkeypatch):
    monkeypatch.setattr(engine, "fortios_wifi_get", lambda *a: (_ for _ in ()).throw(AttributeError("x")))
    assert engine._wifi_rest_result(auth(), (("records", r.MONITOR+"client"),))["error_code"] == "transport_error"


def test_bad_rest_rate_limit_envelope_is_wrapped():
    from test_engine_contracts import _context
    from netops_helper.auth import AuthenticationContextError
    context = _context(ssh_platform="fortinet", fortios_rest_rate_limit={"requests": 0, "window_seconds": 60})
    with pytest.raises(AuthenticationContextError):
        TargetAuth.decode("device-a", context)


def test_unenrolled_rest_tools_cost_one_slot():
    from netops_helper.proxy import Proxy
    for tool in ("wifi_clients", "wifi_aps_live", "wifi_rogue"):
        assert Proxy._rate_cost(tool, None) == 1
        assert Proxy._rate_cost(tool, TOKEN) == {"wifi_clients": 3, "wifi_aps_live": 2, "wifi_rogue": 4}[tool]
    assert Proxy._rate_cost("wifi_triage", TOKEN) == Proxy._rate_cost("wifi_triage", None) + 8


@pytest.mark.parametrize("code,status", [("tls_pin_mismatch", None), ("http_status", 403),
    ("timeout", None), ("rate_limited", 429), ("egress_denied", None)])
def test_structured_rest_subcodes(monkeypatch, code, status):
    def failed(*a, **k):
        raise r.RestError(code, TOKEN, http_status=status)
    monkeypatch.setattr(engine, "fortios_wifi_get", failed)
    result = engine.wifi_clients(auth())
    assert result["error_code"] == code
    assert result["error_subcode"] == code
    assert result["failed_step"] == r.MONITOR + "client"
    assert result.get("http_status") == status
    assert TOKEN not in str(result)


def test_transport_timeout_retains_code(transport):
    peer, _, _ = transport
    peer.do_handshake.side_effect = TimeoutError(TOKEN)
    with pytest.raises(r.RestError) as error:
        r.get(auth(), r.MONITOR + "client", addresses=("127.0.0.1",))
    assert error.value.code == "timeout"
    assert TOKEN not in str(error.value)


def test_ap_units_summary_and_all_rest_times_have_offsets():
    from datetime import datetime
    summary = r.parse(r.MONITOR + "ap_status", fixture("monitor_wifi_ap_status"))
    assert "client_count_max" not in summary
    ap = r.parse(r.MONITOR + "managed_ap", fixture("monitor_wifi_managed_ap"))[0]
    assert ap["mem_total_kib"] == 1937524
    assert "mem_total" not in ap
    assert ap["join_time"] == "2026-11-08T18:00:45+00:00"
    assert datetime.fromisoformat(ap["last_reboot_time"]).utcoffset() is not None
    for radio in ap["radio"]:
        if radio.get("channel_utilization_timestamp"):
            assert datetime.fromisoformat(radio["channel_utilization_timestamp"]).utcoffset() is not None
    client = r.parse(r.MONITOR + "client", fixture("monitor_wifi_client"))[0]
    assert datetime.fromisoformat(client["association_time"]).utcoffset() is not None


def test_ipv6_unspecified_and_invalid_are_removed():
    doc = fixture("monitor_wifi_client")
    doc["results"][0]["ip6"] = ["::", "0:0:0:0:0:0:0:0", "2001:db8::1", "invalid"]
    assert r.parse(r.MONITOR + "client", doc)[0]["ipv6"] == ["2001:db8::1"]


def test_rogue_bands_times_and_internal_endpoints():
    from datetime import datetime, timedelta
    rows = r.parse(r.MONITOR + "rogue_ap", fixture("monitor_wifi_rogue_ap"))
    assert rows[0]["band"] == "5ghz"
    assert rows[0]["phy_mode"] == "11ACVHT80"
    assert rows[1]["band"] == "24ghz"
    assert "wtp_ip" not in json.dumps(rows) and "wtp_port" not in json.dumps(rows)
    for row in rows:
        for key in ("first_seen", "last_seen"):
            assert datetime.fromisoformat(row[key]).utcoffset() is not None
        for observer in row["detected_by_wtp"]:
            assert datetime.fromisoformat(observer["last_seen"]).utcoffset() == timedelta(0)
    # the device wall clock (UTC+1) is converted, not relabelled
    assert [o["last_seen"] for o in rows[0]["detected_by_wtp"]] == ["2026-11-08T21:00:55+00:00", "2026-11-08T21:06:17+00:00"]
    assert rows[0]["last_seen"] == rows[0]["detected_by_wtp"][1]["last_seen"]


def test_missing_epoch_does_not_invent_timezone():
    doc = fixture("monitor_wifi_managed_ap")
    del doc["results"][0]["join_time_raw"]
    assert r.parse(r.MONITOR + "managed_ap", doc)[0]["join_time"] is None


def test_aps_live_summary_keeps_identity_state_and_radio_numbers(monkeypatch):
    import datetime as dt
    moment = dt.datetime(2026, 11, 9, 20, 0, tzinfo=dt.timezone.utc)
    class FixedDateTime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return moment.astimezone(tz) if tz is not None else moment.replace(tzinfo=None)
    # Compare identical snapshots, including retrieval times and metric ages;
    # crossing a wall-clock second must not make this shape test flaky.
    monkeypatch.setattr(dt, "datetime", FixedDateTime)
    monkeypatch.setattr(engine, "_triage_now", lambda: moment.isoformat())
    monkeypatch.setattr(r, "get", lambda target, path, **kw: fixture("monitor_wifi_" + path.rsplit("/", 1)[-1]))
    full = engine.wifi_aps_live(auth())
    brief = engine.wifi_aps_live(auth(), summary=True)
    assert "view" not in full and brief["view"] == "summary" and brief["summary"] == full["summary"]
    assert len(brief["records"]) == len(full["records"]) and [x["content_sha256"] for x in brief["sources"]] == [x["content_sha256"] for x in full["sources"]]
    row, source = brief["records"][0], full["records"][0]
    assert {key: row[key] for key in ("name", "state", "connection_state", "clients")} == {
        key: source[key] for key in ("name", "state", "connection_state", "clients")}
    assert len(row["radios"]) == len([x for x in source["radio"] if r.real_radio(x)]) and "radio" not in row
    assert set(row["radios"][0]) <= set(r._RADIO_OVERVIEW) and "oper_chan" in row["radios"][0]
    assert len(json.dumps(brief)) < len(json.dumps(full)) / 3
    assert engine.wifi_aps_live(auth(), summary=False)["records"] == full["records"]


def test_rogue_counts_filters_and_limits(monkeypatch):
    monkeypatch.setattr(r, "get", lambda target, path, **kw: fixture("monitor_wifi_" + path.rsplit("/", 1)[-1]))
    result = engine.wifi_rogue(auth(), full=True, limit=1, min_signal=-85)
    for name in ("rogue", "interfering"):
        assert result["counts"][name]["total"] == 2
        assert result["counts"][name]["matched"] == 2
        expected = 1 if name == "rogue" else 0
        assert result["counts"][name]["returned"] == expected
        assert len(result[name]) == expected
    assert result["has_more"] and result["next"]["offset"] == 1
    assert result["filters"] == {"limit": 1, "min_signal": -85, "mac": None, "ap": None, "full": True}
    # strongest first, then by MAC
    ordered = engine.wifi_rogue(auth(), full=True, limit=5)
    assert [row["mac"] for row in ordered["rogue"]] == ["00:00:5e:00:53:81", "00:00:5e:00:53:83"]
    assert [row["mac"] for row in ordered["interfering"]] == ["00:00:5e:00:53:81", "00:00:5e:00:53:82"]
    # a row below min_signal (-83 rogue, -85 interfering) is dropped from matched, not just from returned
    narrowed = engine.wifi_rogue(auth(), full=True, limit=5, min_signal=-82)
    for name in ("rogue", "interfering"):
        assert narrowed["counts"][name] == {"total": 2, "matched": 1, "unique_bssid": 1, "returned": 1}
        assert [row["mac"] for row in narrowed[name]] == ["00:00:5e:00:53:81"]
    empty = engine.wifi_rogue(auth(), full=True, min_signal=-10)
    assert empty["rogue"] == [] and empty["counts"]["rogue"]["matched"] == 0


@pytest.mark.parametrize("args", [{"limit": 0}, {"limit": True}, {"limit": 501},
                                  {"min_signal": 1}, {"min_signal": -151}, {"min_signal": "-80"}])
def test_bad_rogue_filters_rejected_before_network(monkeypatch, args):
    from netops_helper.proxy import Proxy, ToolArgumentsError
    monkeypatch.setattr(r, "get", lambda *a, **k: pytest.fail("network used"))
    with pytest.raises(ValueError):
        engine.wifi_rogue(auth(), **args)
    with pytest.raises(ToolArgumentsError) as failure:
        Proxy._validate_tool_arguments("wifi_rogue", {"target": "device-a", **args})
    assert failure.value.code == -32602
    assert failure.value.data["field"] == ("min_signal" if "min_signal" in args else "limit")


@pytest.mark.parametrize("mode,band", [
    ("11B", "24ghz"), ("11G", "24ghz"), ("11NG", "24ghz"), ("11NGHT20", "24ghz"), ("11AXG", "24ghz"),
    ("11A", "5ghz"), ("11NA", "5ghz"), ("11ACVHT80", "5ghz"), ("11AXA", "5ghz"), ("11AX6G", "6ghz"),
    ("11BE", None), ("11BE5G", None), ("11BE2G", None), ("11BEXYZ", None), ("11GX", None), ("11AXX", None),
])
def test_phy_mode_band_uses_an_anchored_table(mode, band):
    row = r._normalise({"band": mode})
    assert row["phy_mode"] == mode
    assert row["band"] == band


@pytest.mark.parametrize("error,detail", [
    (r.RestError("tls_pin_mismatch", TOKEN), "REST read failed: tls_pin_mismatch"),
    (r.RestError("http_status", TOKEN, http_status=403), "REST read failed: http_status (HTTP 403)"),
    (r.RestError("timeout", TOKEN), "REST read failed: timeout"),
    (r.RestError("authentication_failed", TOKEN, http_status=401), "REST read failed: authentication_failed (HTTP 401)"),
    (r.RestError("authorization_failed", TOKEN, http_status=403), "REST read failed: authorization_failed (HTTP 403)"),
    (r.RestError("invalid_json", TOKEN), "REST read failed: invalid_json"),
    (r.RestError("invalid_response", TOKEN), "REST read failed: invalid_response"),
    (r.RestError("configuration", TOKEN), "REST read failed: configuration"),
    (ValueError(TOKEN), "REST read failed: transport_error"),
])
def test_wifi_triage_names_the_rest_failure_cause(monkeypatch, error, detail):
    from test_triage_wifi import outputs
    texts = outputs()
    monkeypatch.setattr(engine, "triage_wifi_read", lambda target, platform, query, parameters=None: {
        "ok": True, "text": texts[query], "content_sha256": hashlib.sha256(texts[query].encode()).hexdigest()})
    monkeypatch.setattr(r, "get", lambda *a, **kw: (_ for _ in ()).throw(error))
    from test_triage_wifi import CLIENT
    result = engine.triage_wifi(auth(), CLIENT)
    items = [m for m in result["missing"] if m["step"] == "client_rssi"]
    assert len(items) == 3 and {m["sample"] for m in items} == {1, 2, 3}
    expected = {"step": "client_rssi", "reason": "rest_unavailable", "detail": detail,
                "error_code": error.code if isinstance(error, r.RestError) else "transport_error"}
    if isinstance(error, r.RestError) and error.http_status is not None:
        expected["http_status"] = error.http_status
    assert all(item == {**expected, "sample": number} for number, item in enumerate(items, 1))
    history_error, = [m for m in result['missing'] if m['step'] == 'wifi_events_rest']
    assert history_error == {**expected, 'step': 'wifi_events_rest'}
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize("public", [False, True])
def test_dns_deadline_kills_and_reaps_stalled_resolver(monkeypatch, public):
    import time
    import subprocess
    processes = []
    original = subprocess.Popen
    def popen(args, **kwargs):
        # A real child process models an indefinitely blocked libc resolver.
        args = args[:-1] + ["import time; time.sleep(60)"]
        process = original(args, **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(r.subprocess, "Popen", popen)
    monkeypatch.setattr(r, "TIMEOUT", 0.08)
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda *a: pytest.fail("unbounded engine DNS"))
    monkeypatch.setattr(r.socket, "create_connection", lambda *a, **k: pytest.fail("network after timeout"))
    target = auth(host="resolver.example.invalid", egress=EgressPolicy(
        addresses=("127.0.0.1",), tcp_ports=(443,), allow_dns=True))
    started = time.monotonic()
    if public:
        result = engine.wifi_clients(target)
        assert result["error_subcode"] == "timeout"
    else:
        with pytest.raises(r.RestError) as error:
            r.get(target, r.MONITOR + "client")
        assert error.value.code == "timeout"
    assert time.monotonic() - started < 1
    assert len(processes) == 1 and processes[0].poll() is not None


def test_dns_time_is_subtracted_from_connect_budget(transport, monkeypatch):
    import time
    monkeypatch.setattr(r, "TIMEOUT", 1)
    def resolve(auth, remaining):
        time.sleep(0.06)
        return ("127.0.0.1",)
    monkeypatch.setattr(r, "_resolve_addresses", resolve)
    timeouts = []
    monkeypatch.setattr(r.socket, "create_connection", lambda *a, **k: timeouts.append(k["timeout"]) or MagicMock())
    r.get(auth(), r.MONITOR + "client")
    assert 0 < timeouts[0] < 0.96


def test_dns_worker_success_checks_all_resolved_addresses(monkeypatch):
    from types import SimpleNamespace
    target = auth(host="resolver.example.invalid", egress=EgressPolicy(
        addresses=("127.0.0.1",), tcp_ports=(443,), allow_dns=True))
    process = MagicMock()
    process.communicate.return_value = (b'["127.0.0.1", "192.0.2.20"]', None)
    process.returncode = 0
    monkeypatch.setattr(r.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(r.socket, "create_connection", lambda *a, **k: pytest.fail("egress bypass"))
    with pytest.raises(r.RestError) as error:
        r.get(target, r.MONITOR + "client")
    assert error.value.code == "egress_denied"
    process.wait.assert_called_once()


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity", "1e999", "-1e999"])
def test_rest_nonfinite_json_is_fixed_diagnostic_without_body(transport, value):
    response = transport[2]
    response.read1.side_effect = [("{\"noise\":" + value + ",\"private_body\":\"" + TOKEN + "\"}").encode(), b""]
    result = engine.wifi_clients(auth())
    assert result["ok"] is False and result["error_subcode"] == "invalid_response"
    assert TOKEN not in json.dumps(result) and "private_body" not in json.dumps(result)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_parser_rejects_nonfinite_numbers_even_in_nested_unpublished_fields(value):
    document = fixture("monitor_wifi_client")
    document["results"][0]["noise"] = value
    with pytest.raises(r.RestError, match="invalid_json_number"):
        r.parse(r.MONITOR + "client", document)
    document["results"][0]["noise"] = -90
    document["extra"] = [{"nested": value}]
    with pytest.raises(r.RestError):
        r.parse(r.MONITOR + "client", document)


@pytest.mark.parametrize("value", [True, "-90", {}, []])
def test_client_numeric_fields_reject_wrong_types(value):
    document = fixture("monitor_wifi_client")
    document["results"][0].update(noise=value, data_rxrate_bps=value, data_txrate_bps=value, data_rate_bps=value)
    row = r.parse(r.MONITOR + "client", document)[0]
    assert all(row[k] is None for k in ("noise_dbm", "link_rx_mbps", "link_tx_mbps"))
    json.dumps(row, allow_nan=False)


@pytest.mark.parametrize("tool", ["wifi_clients", "wifi_aps_live", "wifi_rogue", "wifi_triage"])
def test_invalid_saved_token_returns_auth_material_without_contact(tmp_path, tool):
    from test_proxy_contracts import _load_proxy, _configure, _section, _inventory, _device, _write, _request
    module = _load_proxy()
    inventory, vault, _, _ = _configure(module, tmp_path)
    section = _section()
    section.update(fortios_rest_credential="api-ro", fortios_rest_certificate_sha256=PIN)
    section["enabled_queries"].append("wifi_events")
    section["egress"]["tcp_ports"].append(443)
    _write(inventory, _inventory(_device(section)))
    document = json.loads(vault.read_text())
    invalid = "synthetic invalid token canary"
    document["credentials"]["api-ro"] = {"kind": "api-token", "login": None, "value": invalid}
    _write(vault, document, 0o600)
    proxy = module.Proxy()
    errors = []
    proxy._emit = errors.append
    args = {"target": "device-a"}
    if tool == "wifi_triage":
        args["mac"] = "00:00:5e:00:53:01"
    assert proxy.request(_request(7, tool, args)) is None
    assert errors[0]["error"]["code"] == -32006
    assert errors[0]["error"]["data"]["category"] == "auth_material"
    assert "api-token" in errors[0]["error"]["data"]["hint"]
    assert invalid not in json.dumps(errors)
    assert not proxy.pending and not proxy.rate_history


@pytest.mark.parametrize("value", [pytest.param(10**1000, id="oversized-integer"),
                                  pytest.param(-(10**1000), id="negative-integer"),
                                  pytest.param(253402300800, id="outside-datetime-range")])
def test_invalid_association_time_cannot_overflow_elapsed_time(value):
    document = fixture("monitor_wifi_client")
    document["results"][0]["association_time"] = value
    row = r.parse(r.MONITOR + "client", document)[0]
    assert row["association_time"] is None
    assert row["connected_seconds"] is None
    json.dumps(row, allow_nan=False)


@pytest.mark.parametrize("status,code", [(401, "authentication_failed"), (403, "authorization_failed"),
                                         (500, "http_server_error"), (503, "http_server_error")])
def test_http_failures_have_distinct_tool_error_codes(transport, status, code):
    _, _, response = transport
    response.status = status
    result = engine.wifi_clients(auth())
    assert not result["ok"] and result["error_code"] == code and result["http_status"] == status


@pytest.mark.parametrize("body", [b"not JSON", b"{", b'{"a":1,"a":2}', b"\xff"])
def test_invalid_json_is_distinct_from_network_errors(transport, body):
    _, _, response = transport
    response.read1.side_effect = [body, b""]
    result = engine.wifi_clients(auth())
    assert result["error_code"] == "invalid_json" and result["failed_step"].endswith("client")


def test_invalid_envelope_has_its_own_tool_error_code(monkeypatch):
    monkeypatch.setattr(r, "get", lambda *a: {"status": "success", "http_method": "GET", "vdom": "other"})
    assert engine.wifi_clients(auth())["error_code"] == "unparsed_envelope"


@pytest.mark.parametrize("tool,endpoint,field", [(engine.wifi_clients, "client", "records"),
    (engine.wifi_aps_live, "managed_ap", "records"), (engine.wifi_rogue, "rogue_ap", "rogue")])
def test_large_rest_lists_are_paged_after_parsing(monkeypatch, tool, endpoint, field):
    def get(target, path, **kw):
        doc = fixture("monitor_wifi_" + path.rsplit("/", 1)[-1])
        if path.endswith(endpoint):
            import copy
            doc["results"] = [copy.deepcopy(row) for _ in range(1000) for row in doc["results"]]
            if endpoint == "rogue_ap":
                for n, row in enumerate(doc["results"]):
                    row["mac"] = "00:00:5e:00:%02x:%02x" % (n // 256, n % 256)
        return doc
    monkeypatch.setattr(r, "get", get)
    result = tool(auth(), **({"full": True} if endpoint == "rogue_ap" else {}))
    assert result["ok"] and result["has_more"] and result["next"]["offset"] > 0
    assert 0 < len(result[field]) <= 100 and len(json.dumps(result).encode()) <= 16000
    next_page = tool(auth(), **result["next"])
    assert next_page["page"]["offset"] == result["next"]["offset"]


def test_client_filter_runs_before_the_page_limit(monkeypatch):
    def get(target, path, **kw):
        doc = fixture("monitor_wifi_" + path.rsplit("/", 1)[-1])
        if path.endswith("client"):
            first = doc["results"][0]
            doc["results"] = [dict(first, ssid="other")] * 1000 + [dict(first, ssid="wanted")]
        return doc
    monkeypatch.setattr(r, "get", get)
    result = engine.wifi_clients(auth(), ssid="wanted", limit=1)
    assert result["ok"] and result["records"][0]["ssid"] == "wanted" and result["next"] is None


@pytest.mark.parametrize('kind,code', [('pin', 'tls_pin_mismatch'), ('tls', 'tls_error'),
    ('ca', 'tls_verification_failed'), ('timeout', 'timeout'), ('size', 'response_too_large'),
    ('encoding', 'unsupported_encoding'), ('configuration', 'configuration')])
def test_transport_and_configuration_have_precise_tool_codes(transport, kind, code):
    import ssl
    peer, _, response = transport
    target = auth()
    if kind == 'pin':
        peer.getpeercert.return_value = b'wrong certificate'
    elif kind == 'tls':
        peer.do_handshake.side_effect = ssl.SSLError('synthetic TLS error')
    elif kind == 'ca':
        peer.do_handshake.side_effect = ssl.SSLCertVerificationError('synthetic verification error')
    elif kind == 'timeout':
        peer.do_handshake.side_effect = TimeoutError('synthetic timeout')
    elif kind == 'size':
        response.getheader.side_effect = lambda key, default=None: str(r.MAX_BYTES + 1) if key == 'Content-Length' else default
    elif kind == 'encoding':
        response.getheader.side_effect = lambda key, default=None: 'gzip' if key == 'Content-Encoding' else default
    else:
        target = dataclasses.replace(target, fortios_rest_certificate_sha256=None)
    result = engine.wifi_clients(target)
    assert result['ok'] is False and result['error_code'] == code
    assert result['failed_step'] == r.MONITOR + 'client'
    assert TOKEN not in json.dumps(result)


def test_failed_second_rogue_read_also_bounds_partial_first_list(monkeypatch):
    def get(target, path, **kw):
        if path.endswith('interfering_ap'):
            raise r.RestError('timeout', 'synthetic timeout')
        document = fixture('monitor_wifi_rogue_ap')
        document['results'] *= 1000
        return document
    monkeypatch.setattr(r, 'get', get)
    result = engine.wifi_rogue(auth())
    assert result['ok'] is False and result['error_code'] == 'timeout'
    assert result['has_more'] and result['next']['offset'] > 0
    assert len(json.dumps(result).encode()) <= 16000


@pytest.mark.parametrize('selector', [
    {'mac': '00:00:5e:00:53:81'}, {'ssid': 'example'}, {'ap': 'Example AP'}, {'name': 'TabletExample'}, {},
])
def test_client_read_discards_partial_records_before_paging(monkeypatch, selector):
    def get(target, path):
        if path == r.MONITOR + 'managed_ap':
            raise r.RestError('http_server_error', TOKEN, http_status=503)
        return fixture('monitor_wifi_client')
    monkeypatch.setattr(r, 'get', get)
    result = engine.wifi_clients(auth(), **selector)
    assert result['ok'] is False and result['error_code'] == 'http_server_error'
    assert result['records'] == [] and result['filters'] == selector
    assert 'access_points' not in result and TOKEN not in json.dumps(result)


@pytest.mark.parametrize('code', sorted(__import__('netops_helper.triage_wifi', fromlist=['_REST_CODES'])._REST_CODES))
def test_triage_preserves_fixed_precise_rest_codes(code):
    from netops_helper import triage_wifi as triage
    answer = {'error_code': code, 'error_subcode': 'transport_or_response_error', 'error': TOKEN}
    fields = triage._rest_failure_fields(answer)
    assert fields == {'error_code': code, 'detail': 'REST read failed: ' + code}
    assert TOKEN not in json.dumps(fields)


def test_triage_rejects_untrusted_rest_diagnostic_text():
    from netops_helper import triage_wifi as triage
    assert triage._rest_failure_fields({'error_code': TOKEN, 'error_subcode': TOKEN, 'http_status': TOKEN}) == {
        'detail': 'REST read failed (unknown cause)'}
    assert triage._rest_failure_fields({'error_subcode': 'invalid_response'}) == {
        'detail': 'REST read failed: invalid_response'}


@pytest.mark.parametrize('suffix', ['', '&filter=anything', '&rows=400', '%0A', '%253A'])
def test_client_history_path_rejects_noncanonical_filters(monkeypatch, suffix):
    monkeypatch.setattr(r.socket, 'create_connection', lambda *a, **k: pytest.fail('network used'))
    path = r.wireless_log_path('00:00:5e:00:53:81') + suffix
    if not suffix:
        path = path.replace('%3A', ':')
    with pytest.raises(ValueError, match='policy_scope'):
        r.get(auth(), path)


def test_targeted_history_ignoring_server_filter_is_rejected():
    mac = '00:00:5e:00:53:81'
    doc = fixture('wireless_log')
    with pytest.raises(r.RestError) as error:
        r.parse(r.wireless_log_path(mac), doc)
    assert error.value.code == 'invalid_response'


@pytest.mark.parametrize('change', [{'total_lines': 518}, {'ready': False}, {'percent_logs_processed': 75}, {'total_lines': True}])
def test_history_window_does_not_claim_unproven_coverage(change):
    doc = fixture('wireless_log')
    doc.update(total_lines=len(doc['results']), ready=True, percent_logs_processed=100)
    doc.update(change)
    assert r.parse(r.WIRELESS_LOG, doc)['complete'] is False


@pytest.mark.parametrize("port", [443, 8443, 1, 65535])
def test_rest_port_reaches_dns_egress_socket_and_https(transport, monkeypatch, port):
    target = auth(host="resolver.example.invalid", fortios_rest_port=port,
                  egress=EgressPolicy(addresses=("127.0.0.1",), tcp_ports=(port,), allow_dns=True))
    process = MagicMock()
    process.communicate.return_value = (b'["127.0.0.1"]', None)
    process.returncode = 0
    popen = Mock(return_value=process)
    monkeypatch.setattr(r.subprocess, "Popen", popen)
    # Exercise the real isolated resolver program with a fake socket module.
    dns_input = io.BytesIO(json.dumps([target.host, port]).encode())
    dns_socket = MagicMock()
    dns_socket.getaddrinfo.return_value = [(None, None, None, None, ("127.0.0.1", port))]
    with patch.dict(sys.modules, socket=dns_socket):
        with patch("sys.stdin", buffer=dns_input):
            exec(r._DNS_PROGRAM, {})
    dns_socket.getaddrinfo.assert_called_once_with(target.host, port, dns_socket.AF_INET, dns_socket.SOCK_STREAM)
    connect = Mock(return_value=MagicMock())
    https = Mock(return_value=transport[1])
    monkeypatch.setattr(r.socket, "create_connection", connect)
    monkeypatch.setattr(r.http.client, "HTTPSConnection", https)
    r.get(target, r.MONITOR + "client")
    assert json.loads(process.communicate.call_args.args[0]) == [target.host, port]
    assert connect.call_args.args[0] == ("127.0.0.1", port)
    assert https.call_args.args[:2] == (target.host, port)
    transport[1].request.assert_called_once()


@pytest.mark.parametrize("port", [443, 8443])
def test_rest_port_outside_egress_is_refused_before_dns_or_socket(monkeypatch, port):
    target = auth(fortios_rest_port=port, egress=EgressPolicy(addresses=("127.0.0.1",), tcp_ports=(22,)))
    monkeypatch.setattr(r, "_resolve_addresses", lambda *a: pytest.fail("DNS used"))
    monkeypatch.setattr(r.socket, "create_connection", lambda *a, **k: pytest.fail("socket used"))
    with pytest.raises(ValueError, match="egress"):
        r.get(target, r.MONITOR + "client")


@pytest.mark.parametrize("port,ports,ranges,accepted", [
    (None, [443], [], True), (443, [443], [], True), (8443, [8443], [], True),
    (8443, [], [[8400, 8500]], True), (1, [1], [], True), (65535, [65535], [], True),
    (8443, [443], [], False), (None, [8443], [], False),
    (0, [443], [], False), (65536, [443], [], False), (True, [443], [], False),
    ("8443", [443], [], False), (8443.0, [443], [], False),
])
def test_inventory_rest_port_validation(port, ports, ranges, accepted):
    from test_proxy_contracts import _device, _section
    from netops_helper import inventory as i
    from netops_core import inventory as core
    section = _section()
    section.update(fortios_rest_credential="api-ro", fortios_rest_certificate_sha256=PIN)
    section["egress"].update(tcp_ports=ports, tcp_port_ranges=ranges)
    if port is not None:
        section["fortios_rest_port"] = port
    device = core._device(0, _device(section))
    kinds = {"api-ro": "api-token", "device-a-account": "password", "device-a-community": "snmpv3-authpriv"}
    if accepted:
        assert i.section(device, kinds).fortios_rest_port == (443 if port is None else port)
    else:
        with pytest.raises(i.InventoryError):
            i.section(device, kinds)


@pytest.mark.parametrize("port", [None, False, 0, 65536, "8443", 8443.5])
def test_auth_envelope_rejects_invalid_rest_port(port):
    from test_engine_contracts import _context
    with pytest.raises(ValueError):
        TargetAuth.decode("device-a", _context(fortios_rest_port=port))


def test_inventory_rejects_explicit_null_rest_port():
    from test_proxy_contracts import _device, _section
    from netops_core import inventory as core
    from netops_helper import inventory as i
    section = _section()
    section["fortios_rest_port"] = None
    with pytest.raises(i.InventoryError):
        i.section(core._device(0, _device(section)))


@pytest.mark.parametrize("args", [{"mac": "00:00:5E:00:53:01"}, {"ap": "unsafe\nname"}])
def test_bad_rogue_selectors_rejected_before_network(monkeypatch, args):
    from netops_helper.proxy import Proxy, ToolArgumentsError
    monkeypatch.setattr(r, "get", lambda *a, **kw: pytest.fail("network used"))
    with pytest.raises(ValueError):
        engine.wifi_rogue(auth(), **args)
    with pytest.raises(ToolArgumentsError) as failure:
        Proxy._validate_tool_arguments("wifi_rogue", {"target": "device-a", **args})
    assert failure.value.code == -32602


def test_client_history_audits_the_fixed_endpoint_in_both_operation_records(monkeypatch, audit):
    fake_get(monkeypatch)
    mac = '00:00:5e:00:53:81'
    answer = engine._wifi_rest_result(auth(), (('events', r.wireless_log_path(mac)),))
    assert answer['ok']
    rows = [fields for _, fields in audit if fields.get('request') == 'GET ' + r.WIRELESS_LOG]
    assert len(rows) == 2
    assert all(fields['channel'] == 'https' for fields in rows)
    assert mac not in json.dumps(rows) and TOKEN not in json.dumps(rows)


@pytest.mark.parametrize('endpoint', [
    r.WIRELESS_LOG + '&filter=stamac%3D%3Dinvalid',
    r.wireless_log_path('00:00:5e:00:53:81') + '&extra=value',
    'https://example.invalid/api/v2/monitor/wifi/client',
])
def test_audit_does_not_describe_an_untyped_rest_endpoint(endpoint):
    fields = engine._audit_fields({'endpoint': endpoint}, {})
    assert 'request' not in fields and 'channel' not in fields
