"""G2c Wi-Fi review items, driven through the engine entry points.

Transport is the only fake: SSH reads return the measured CLI captures and
`wifi_rest.get` returns the measured REST fixtures (edited as device INPUT);
parsers, triage rules, paging and the engine wrappers are production code.
"""
import copy
import dataclasses
import hashlib
import json
import re
from pathlib import Path

import pytest

from netops_helper import engine, triage_wifi as t, wifi_rest as r
from netops_helper.auth import EgressPolicy
from test_triage_wifi import AP2, CLIENT, outputs
from test_wifi_rest import auth, fixture

ROOT = Path(__file__).resolve().parents[3]
TOOLS = (ROOT / "components/netops-helper/docs/tools.md").read_text()
ASSOCIATED_AT = 1794161678  # association_time of the measured station row


@pytest.fixture(autouse=True)
def device(monkeypatch):
    monkeypatch.setattr(engine, "record", lambda *a, **kw: None)
    monkeypatch.setitem(t.run.__kwdefaults__, "pause", lambda seconds: None)  # three samples, no real 3 s waits
    r._rates.clear()
    texts = outputs()

    def read(target, platform, query, parameters=None):
        return {"ok": True, "text": texts[query], "content_sha256": hashlib.sha256(texts[query].encode()).hexdigest()}

    monkeypatch.setattr(engine, "triage_wifi_read", read)


def rest(monkeypatch, client=None, rogue=None, log=None, sample=None):
    """Replace only the HTTP GET; `sample(n)` may raise for the n-th station read."""
    reads = {"client": 0}

    def get(target, path, **kwargs):
        name = ("device_query" if path == r.DEVICES else
                "wireless_log" if path == r.WIRELESS_LOG or r._log_mac(path) is not None else
                "monitor_wifi_" + path.rsplit("/", 1)[-1])
        document = fixture(name)
        if path.endswith("/client"):
            reads["client"] += 1
            if sample:
                sample(reads["client"])
            document["results"][0].update(mac=CLIENT, wtp_id=AP2, wtp_name="current AP", wtp_radio=2)
            if client:
                document["results"][0].update(client)
        if path.endswith("/managed_ap"):
            document["results"][0].update(serial=AP2, wtp_id=AP2)
        if path.endswith("/rogue_ap") and rogue:
            document = rogue(document)
        if r._log_mac(path) is not None:
            document["results"] = [row for row in document["results"] if row.get("stamac") == r._log_mac(path)]
            if log:
                document["results"] = log(document["results"])
            document["total_lines"] = len(document["results"])
        return document

    monkeypatch.setattr(r, "get", get)


def test_direct_engine_calls_check_the_rest_port_without_the_proxy(monkeypatch):
    monkeypatch.setattr(r.socket, "create_connection", lambda *a, **k: pytest.fail("network used"))
    target = dataclasses.replace(auth(), fortios_rest_port=8443,
                                 egress=EgressPolicy(addresses=("127.0.0.1",), tcp_ports=(443,)))
    assert engine.wifi_clients(target)["error_code"] == "egress_denied"
    result = engine.triage_wifi(target, CLIENT)
    steps = {(m["step"], m.get("error_code")) for m in result["missing"]}
    assert {("client_rssi", "egress_denied"), ("wifi_events_rest", "egress_denied"),
            ("wifi_neighbors_rest", "egress_denied")} <= steps
    assert result["chain"]["signal_samples"]["rssi_dbm"] == {"min": None, "max": None, "last": None}


def test_full_triage_through_the_engine_is_bounded_and_every_event_is_reachable(monkeypatch):
    def many(rows):
        base = copy.deepcopy(rows[0])
        out = []
        for index in range(200):
            row = copy.deepcopy(base)
            row.update(logdesc="Wireless client disassociated " + "Ž" * 80, reason="idle timeout %03d" % index,
                       eventtime=str(1794166133206815079 + index * 10**9))
            out.append(row)
        return out

    rest(monkeypatch, log=many)
    arguments, reasons = {"history_limit": 500, "history_offset": 0}, []
    while arguments:
        page = engine.triage_wifi(auth(), CLIENT, **arguments)
        assert page["ok"] and len(json.dumps(page).encode()) <= 48_000
        rows = page["chain"]["events"]["timeline"]
        assert rows and page["page"]["returned"] == len(rows)
        reasons += [row["reason"] for row in rows]
        arguments = page["next"]
    assert sorted(reasons) == ["idle timeout %03d" % i for i in range(200)]


def _neighbor(monkeypatch, observer):
    def rogue(document):
        document["results"] = [document["results"][0]]
        row = document["results"][0]
        row.update(channel=124, band="11ACVHT40", bw="40", signal_strength=-40)  # the client's AP radio 2 operates on 124/40
        row["detected_by_wtp"][0].update(serial=observer, name="Example AP", signal_strength=-40)
        return document

    rest(monkeypatch, rogue=rogue)
    result = engine.triage_wifi(auth(), CLIENT)
    return result, [f["id"] for f in result["findings"]]


def test_strong_cochannel_neighbor_fires_through_the_engine_with_rest(monkeypatch):
    result, ids = _neighbor(monkeypatch, AP2)
    assert "F-WIFI-STRONG-COCHANNEL-NEIGHBOR" in ids
    assert result["chain"]["neighbors"]["strongest_relevant_dbm"] == -40


def test_neighbor_heard_by_another_access_point_is_context_only(monkeypatch):
    result, ids = _neighbor(monkeypatch, "FAPOTHER0000009")
    assert "F-WIFI-STRONG-COCHANNEL-NEIGHBOR" not in ids
    assert result["chain"]["neighbors"]["strongest_relevant_dbm"] is None


def _stale_error(rows):
    row = next(row for row in rows if "no server response" in row["logdesc"])
    stamp = ASSOCIATED_AT - 600
    row.update(date="2026-11-08", time="18:04:38", tz="+0000", eventtime=str(stamp * 10**9))
    return [row]


def _fail_from(first):
    def sample(number):
        if number >= first:
            raise r.RestError("timeout", "FortiOS REST deadline exceeded")
    return sample


def test_failed_last_sample_keeps_earlier_samples_and_does_not_revive_the_old_error(monkeypatch):
    rest(monkeypatch, client={"signal": -80}, log=_stale_error, sample=_fail_from(3))
    result = engine.triage_wifi(auth(), CLIENT)
    samples = result["chain"]["signal_samples"]
    assert [s["status"] for s in samples["samples"]] == ["associated", "associated", "unavailable"]
    assert samples["samples"][2]["error_code"] == "timeout"
    assert samples["rssi_dbm"] == {"min": -80, "max": -80, "last": None}
    assert {"step": "client_rssi", "reason": "rest_unavailable"}.items() <= next(
        m for m in result["missing"] if m["step"] == "client_rssi" and m.get("sample") == 3).items()
    weak = next(f for f in result["findings"] if f["id"] == "F-WIFI-WEAK-SIGNAL")
    assert weak["severity"] == "warning" and "last snapshot unavailable or client absent" in weak["fact"]
    error = next(f for f in result["findings"] if f["id"] == "F-WIFI-CLIENT-ERROR")
    assert error["historical"] and error["severity"] == "notice"
    chain = result["chain"]
    assert chain["association"]["status"] == "unknown" and chain["association"]["last_observed_status"] == "associated"
    assert chain["client"]["association_status"] == "unknown" and chain["client_state"]["rssi_dbm"] is None
    assert result["verdict"] == "incomplete"


def test_absent_last_sample_reports_not_associated_and_keeps_the_old_error_historical(monkeypatch):
    rest(monkeypatch, log=_stale_error)
    inner = r.get

    def get(target, path, **kwargs):
        document = inner(target, path, **kwargs)
        if path.endswith("/client"):
            get.reads += 1
            if get.reads == 3:
                document["results"] = []
        return document

    get.reads = 0
    monkeypatch.setattr(r, "get", get)
    result = engine.triage_wifi(auth(), CLIENT)
    assert [s["status"] for s in result["chain"]["signal_samples"]["samples"]] == ["associated", "associated", "not_associated"]
    assert result["verdict"] == "client_not_associated"
    assert next(f for f in result["findings"] if f["id"] == "F-WIFI-CLIENT-ERROR")["historical"]
    assert any(m["step"] == "client_rssi" and m["reason"] == "not_listed" for m in result["missing"])


def test_documentation_states_the_failed_sample_and_rate_limit_behaviour():
    row = next(line for line in TOOLS.splitlines() if line.startswith("| F-WIFI-CLIENT-ERROR |"))
    assert "current successful association" not in row
    assert "last successful station observation" in row and "a later sample failed" in row
    for phrase in ("never erases the earlier ones", "`status: unavailable`", "`not_associated`", "`rssi_dbm.last`",
                   "`client_rssi` with `rest_unavailable`", "`chain.association.last_observed_status` stays `associated`",
                   "`last snapshot unavailable or client absent`", "30 reads per 60 seconds", "reserves 15 reads",
                   "`error_code: rate_limited`", "`retry_after_seconds`"):
        assert phrase in TOOLS, phrase
    # the Wi-Fi section itself, not only the generic rate-limit section, carries the budget
    section = TOOLS.split("`wifi_triage(target, mac)`", 1)[1].split("| Chain part | Query |", 1)[0]
    assert "30 reads per 60 seconds" in section and "reserves 15 reads" in section
