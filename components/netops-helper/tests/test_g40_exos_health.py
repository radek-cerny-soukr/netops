"""Public EXOS health and log reads using real CLI responses at the SSH boundary."""

import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from netops import worker
from netops_helper import engine, proxy, server
from test_proxy_contracts import _device, _egress, _inventory, _write


FIXTURES = Path(__file__).parent / "fixtures/real/exos/g40"
X435 = FIXTURES.parent / "x435-8p-4s_33.7.1.6"
PROFILE = "extreme_exos"
HEALTH = {
    "version": "show version", "switch": "show switch", "memory": "show memory",
    "cpu_monitoring": "show cpu-monitoring", "temperature": "show temperature",
    "fans": "show fans", "power": "show power", "stacking": "show stacking",
    "mlag_peer": "show mlag peer", "ntp": "show ntp",
}
LOG = "show log messages {} severity {} starting date 11/20/2026 time 07:36:00 ending date 11/20/2026 time 08:45:00"
LEGACY_LOGS = {
    "log_messages": "show log messages memory-buffer",
    "log_warnings": "show log messages memory-buffer severity warning",
}
MEMORY = LEGACY_LOGS["log_messages"]
NVRAM = "show log messages nvram"


def captured(name):
    return (FIXTURES / (name + ".out")).read_text()


@pytest.fixture
def public(tmp_path, monkeypatch):
    answers = {command: captured("vm-" + query) for query, command in HEALTH.items()}
    answers["show stacking"] = 250, answers["show stacking"]
    answers["show switch"] = captured("vm-switch").replace("08:42:56", "08:45:00")
    answers[MEMORY] = captured("log-port").replace("07:36:57.71", "07:35:57.71")
    answers[NVRAM] = captured("log-nvram").replace("08:42:08.51", "07:35:08.51")
    answers[LOG.format("memory-buffer", "info")] = captured("log-port")
    answers[LOG.format("nvram", "warning")] = captured("log-nvram")
    calls = []
    private = tmp_path / "helper"
    private.mkdir()
    _write(private / "vault.json", {"version": 2, "credentials": {
        "device-a-account": {"kind": "password", "login": "reader", "value": "fixture-password"},
    }}, 0o600)
    path = tmp_path / "inventory.json"
    monkeypatch.setattr(worker, "STATE", tmp_path)
    monkeypatch.setattr(proxy, "INVENTORY", path)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    def transport(auth, platform, command, **kwargs):
        assert platform == PROFILE
        calls.append(command)
        result = answers[command]
        if isinstance(result, Exception):
            raise result
        return result if isinstance(result, tuple) else (0, result)

    monkeypatch.setattr(engine, "_exec_read", transport)
    bridge = worker.HelperBridge()

    def ask(tool, *, enabled=None, **arguments):
        section = {
            "account_role": "read-only", "ssh_platform": "exos", "device_types": ["switch"],
            "enabled_queries": [*HEALTH, *LEGACY_LOGS, "log_history"] if enabled is None else enabled,
            "read_inventory": {"interfaces": ["1", "11"]},
            "egress": {**_egress(), "tcp_ports": [22]},
            "rate_limit": {"requests": 60, "window_seconds": 60},
        }
        _write(path, _inventory(_device(section, "exos")))
        result = asyncio.run(bridge.call(server.mcp, tool, {"target": "device-a", **arguments}))
        if "structuredContent" in result:
            return result["structuredContent"]
        return result

    return ask, answers, calls


def log_read(public, *, source="memory-buffer", severity="info", params=None, **options):
    return public[0]("ssh_read", platform=PROFILE, query="log_history", parameters={
        "source": source, "severity": severity, "begin_date": "2026-11-20", "begin_time": "07:36:00",
        "end_date": "2026-11-20", "end_time": "08:45:00", **(params or {}),
    }, **options)


def test_vm_health_has_facts_despite_unsupported_stack(public):
    result = public[0]("triage_health", enabled=list(HEALTH))
    assert result.get("ok"), result
    assert result["ok"] and result["verdict"] == "incomplete"
    assert result["identity"]["model"] == "EXOS-VM"
    assert result["identity"]["os_version"] == "33.6.1.14"
    assert result["switch"] == {"state": "OPERATIONAL"}
    assert result["memory"]["free_kb"] == 528276
    assert result["cpu_monitoring"]["five_minutes_percent"] == 0.1
    assert result["temperature"][0]["celsius"] == 20.10
    assert [item["state"] for item in result["power"]] == ["Powered On", "Powered On"]
    assert result["fans"][0]["state"] == "Empty"
    peer, = result["mlag_peer"]["peers"]
    assert peer["checkpoint_status"] == "Up" and peer["local_address"] == "192.0.2.1"
    assert result["ntp"]["enabled"] is False
    assert result["missing"] == [{"step": "stacking", "reason": "unsupported"}]
    assert public[2] == list(HEALTH.values())


def test_x440_partial_read_and_untested_release(public):
    for query, command in HEALTH.items():
        public[1][command] = captured("x440-" + query)
    public[1]["show version"] = public[1]["show version"].replace("33.7.1.6", "99.7." + "1.6")
    public[1]["show memory"] = captured("x440-memory").split(" Free ")[0] + "--More--"
    result = public[0]("triage_health")
    assert result.get("ok"), result
    assert result["ok"] and result["verdict"] == "incomplete"
    assert result["firmware_support"]["status"] == "untested"
    assert result["stacking"] == {"configured": "Disabled", "enabled": False}
    assert [item["state"] for item in result["power"]] == ["Powered On", "Empty"]
    assert result["temperature"][0]["state"] == "Normal"
    assert {item["step"]: item["reason"] for item in result["missing"]} == {
        "memory": "truncated", "mlag_peer": "unparsed",
    }


def test_health_enrollment_requires_identity_and_skips_unenrolled_reads(public):
    refused = public[0]("triage_health", enabled=["switch"])
    assert refused.get("isError") or "error" in refused
    assert public[2] == []
    allowed = public[0]("triage_health", enabled=["version", "switch"])
    assert allowed["ok"] and allowed["verdict"] == "incomplete"
    assert public[2] == ["show version", "show switch"]


def test_memory_filters_port_exactly_and_pages_same_snapshot(public):
    rows = captured("log-port").splitlines()[:4]
    public[1][LOG.format("memory-buffer", "info")] = (
        ("\n".join(rows) + "\n") * 4 + "\nA total of 16 log messages were displayed.\n"
    )
    first = log_read(public, params={"interface": "11"}, max_bytes=1000)
    assert first.get("ok"), first
    coverage = first["log_history"]
    assert first["ok"] and first["status"] == "ok"
    assert coverage["complete"] and coverage["selected_messages"] == coverage["device_messages"] == 16
    assert coverage["by_severity"]["info"] == 16
    second = log_read(public, params={"interface": "11"}, offset=first["next_offset"],
                      content_sha256=first["content_sha256"], max_bytes=1000)
    assert second["pagination_source"] == "cached" and second["log_history"] == coverage
    assert public[2] == ["show version", "show switch", LOG.format("memory-buffer", "info"), MEMORY]
    text = first["untrusted_device_output"] + second["untrusted_device_output"]
    assert hashlib.sha256(text.encode()).hexdigest() == first["content_sha256"]
    assert text.count("Port 11") == 16
    empty = log_read(public, params={"interface": "1"})
    assert empty["ok"] and empty["complete"] and empty["status"] == "empty"
    assert empty["log_history"]["selected_messages"] == 0


def test_nvram_origin_and_warning_count(public):
    public[1]["show version"] = captured("x440-version").replace("patch1-11", "patch1-12")
    result = log_read(public, source="nvram", severity="warning")
    assert result.get("ok"), result
    assert result["ok"] and result["status"] == "ok"
    assert result["log_history"]["source"] == "nvram"
    assert result["firmware_support"]["status"] == "untested"
    assert result["firmware_support"]["device_version"] == "33.7.1.6-patch1-12"
    assert result["log_history"]["by_severity"]["warning"] == 2
    assert result["log_history"]["archive_correlation"] == "external_archive_unavailable"
    assert public[2] == ["show version", "show switch", LOG.format("nvram", "warning"), NVRAM]


@pytest.mark.parametrize("sample", ["", "log-empty"])
def test_empty_log_is_success(public, sample):
    public[1][LOG.format("memory-buffer", "info")] = captured(sample) if sample else ""
    result = log_read(public)
    assert result.get("ok"), result
    assert result["ok"] and result["complete"] and result["status"] == "empty"
    assert result["normalized"]["records"] == []


@pytest.mark.parametrize("cut", ["pager", "missing-footer", "short-count", "unknown", "line-cap"])
def test_incomplete_capture_is_reported(public, cut):
    text = captured("log-port")
    rows = text.splitlines()
    if cut == "pager":
        text = rows[0] + "\n--More--"
    elif cut == "missing-footer":
        text = rows[0] + "\n"
    elif cut == "short-count":
        text = text.replace("total of 4", "total of 5")
    elif cut == "unknown":
        text = text.replace(rows[0], "Undecodable log entry")
    else:
        text = ("\n".join(rows[:4]) + "\n") * 51 + "\nA total of 204 log messages were displayed.\n"
    public[1][LOG.format("memory-buffer", "info")] = text
    result = log_read(public)
    assert result.get("ok"), result
    assert result["ok"] and not result["complete"] and result["status"] == "incomplete"
    assert not result["log_history"]["complete"]


def test_device_rejection_never_becomes_empty(public):
    public[1][LOG.format("memory-buffer", "info")] = (250, "This user does not have permissions for this command.\n")
    result = log_read(public)
    assert not result["ok"] and not result["complete"] and result["status"] == "permission_denied"


def test_transport_output_cap_is_incomplete(public):
    public[1][LOG.format("memory-buffer", "info")] = engine.core_ssh.OutputLimitError()
    result = log_read(public)
    assert not result["ok"] and not result["complete"] and result["status"] == "incomplete"


def test_audit_command_secret_removed_before_response_hash(public):
    public[1][LOG.format("memory-buffer", "info")] = captured("log-audit")
    result = log_read(public)
    assert result.get("ok"), result
    assert result["ok"] and result["complete"]
    assert "readonly xy" not in json.dumps(result)
    text = result["untrusted_device_output"]
    assert "<Info:AAA.LogSsh> <REDACTED>" in text
    assert hashlib.sha256(text.encode()).hexdigest() == result["content_sha256"]


@pytest.mark.parametrize("query", [*LEGACY_LOGS, "log_history"])
@pytest.mark.parametrize("shape", ["unknown-event", "unknown-body", "continuation"])
def test_review_unknown_audit_is_withheld_from_every_page_and_hash(public, query, shape):
    command = LEGACY_LOGS.get(query, LOG.format("memory-buffer", "info"))
    prefix = captured("log-audit").split("CLI command:")[0]
    operational = captured("log-port").splitlines()[:4] * 4
    if shape == "unknown-event":
        audit = prefix.replace("AAA.LogSsh", "AuthStore.Update") + "server profile radius [{value}]"
    elif shape == "unknown-body":
        audit = prefix + "account service (credential slot {value})"
    else:
        audit = prefix + "CLI command: configure snmpv3 user service\n    auth {value}"

    def read(**options):
        if query == "log_history":
            return log_read(public, max_bytes=1000, **options)
        return public[0]("ssh_read", platform=PROFILE, query=query, max_bytes=1000, **options)

    hashes = []
    for synthetic in ("~q", "~z"):
        rows = [*operational[:10], audit.format(value=synthetic), *operational[10:]]
        public[1][command] = "\n".join(rows) + "\n\nA total of 17 log messages were displayed.\n"
        first = page = read()
        assert first.get("ok") is True and first.get("next_offset") is not None
        pages = []
        complete = []
        while True:
            assert synthetic not in json.dumps(page)
            pages.append(page["untrusted_device_output"])
            complete.append(page["complete"])
            if page["next_offset"] is None:
                break
            page = read(offset=page["next_offset"], content_sha256=first["content_sha256"])
            assert page["pagination_source"] == "cached"
        digest = hashlib.sha256("".join(pages).encode()).hexdigest()
        assert digest == first["content_sha256"]
        hashes.append(digest)
        assert not any(complete)
    assert len(set(hashes)) == 1


@pytest.mark.parametrize("kind", ["future", "overwritten", "equal_start", "missing_clock", "partial_buffer",
                                  "missing_buffer"])
def test_review_empty_window_needs_coverage_evidence(public, kind):
    source = "nvram" if kind == "overwritten" else "memory-buffer"
    public[1][LOG.format(source, "warning")] = captured("log-empty")
    public[1]["show switch"] = captured("vm-switch").replace("08:42:56", "09:42:56")
    retained = captured("log-port").replace("07:36:57.71", "07:35:57.71")
    if kind == "future":
        public[1]["show switch"] = captured("vm-switch")
    elif kind == "overwritten":
        # Preserve the real overwrite event and footer, placing the buffer after this window's start.
        retained = (X435 / "log_warnings.txt").read_text()
        retained = "\n".join("11/20/2026 08:00:" + line[17:] if line[:2].isdigit() else line
                             for line in retained.splitlines()) + "\n"
    elif kind == "missing_clock":
        public[1]["show switch"] = TimeoutError()
    elif kind == "partial_buffer":
        retained = retained.replace("total of 4", "total of 5")
    elif kind == "missing_buffer":
        retained = TimeoutError()
    elif kind == "equal_start":
        retained = retained.replace("07:35:57.71", "07:36:00.00")
    public[1][f"show log messages {source}"] = retained
    result = log_read(public, source=source, severity="warning")
    assert result.get("ok") is True
    assert result["complete"] is False and result["status"] == "incomplete"
    coverage = result["log_history"]
    assert coverage["selected_messages"] == 0
    assert coverage["incomplete_reasons"] == [{
        "future": "window_end_after_device_clock", "overwritten": "window_start_not_retained",
        "missing_clock": "device_clock_unavailable", "partial_buffer": "buffer_bounds_unavailable",
        "equal_start": "window_start_not_retained", "missing_buffer": "buffer_bounds_unavailable",
    }[kind]]


def test_review_legacy_ssh_login_keeps_diagnostics(public):
    rows = (X435 / "log_messages.txt").read_text().splitlines()[:3]
    public[1][LEGACY_LOGS["log_messages"]] = "\n".join(rows) + "\n"
    result = public[0]("ssh_read", platform=PROFILE, query="log_messages")
    assert result.get("ok") is True
    assert result["untrusted_device_output"].splitlines() == rows


def test_review_legacy_ssh_login_masks_only_trailing_credential(public):
    row = (X435 / "log_messages.txt").read_text().splitlines()[1]
    public[1][MEMORY] = row + " password: ~q\n"
    result = public[0]("ssh_read", platform=PROFILE, query="log_messages")
    assert result.get("ok") is True
    assert result["untrusted_device_output"] == row + " password <REDACTED>\n"


@pytest.mark.parametrize("params", [
    {"source": "nvram match all"}, {"severity": "warning only"}, {"begin_date": "2026-02-30"},
    {"end_date": "2026-11-19"}, {"interface": "12"}, {"interface": "11,12"},
])
def test_bad_log_parameters_do_not_reach_device(public, params):
    refused = log_read(public, params=params)
    assert refused.get("isError") or "error" in refused
    assert public[2] == []
