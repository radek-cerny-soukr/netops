import dataclasses

import pytest

from conftest import EXEC_CLIENT, FORTIADC_STATUS, _plain_query, _target, _write_client
import netops_helper.engine as engine
from netops_helper import triage_slb
from netops_helper.read_policy import READ_QUERIES


ADC_PROMPT = b"FortiADC-VM # "
SLB = "diagnose server-load-balance slb_load"
INVENTORY = {"interfaces": ("port1",), "adc_virtual_servers": ("VS_APP_HTTP",)}
LEGAL_EMPTY = {
    ("fortiadc", "interface_state"): {"interface": "port1"},
    ("fortiadc", "dos_access_limit"): {"virtual_server": "VS_APP_HTTP"},
    ("fortiadc", "dos_conn_limit"): {"virtual_server": "VS_APP_HTTP"},
    ("fortiadc", "dos_req_limit"): {"virtual_server": "VS_APP_HTTP"},
    ("fortiadc", "traffic_group_status"): {},
}
TRAFFIC_GROUP = "get system traffic-group-status brief"


def _fake_read(monkeypatch, output, rc=0):
    calls = []

    def fake(auth, platform, command, prompt=False):
        calls.append((platform, command, prompt))
        return rc, output

    monkeypatch.setattr(engine, "_verified_read", fake)
    return calls


def _read(platform, query, parameters=None):
    auth = dataclasses.replace(_target(platform, query), read_inventory=INVENTORY)
    return engine.ssh_read(auth, platform, query, parameters or {}, 0, 48_000)


def _cases():
    fortinet_query, _ = _plain_query("fortinet")
    prompt_only = engine._pty_body(SLB.encode() + b"\r\n" + ADC_PROMPT, SLB, ADC_PROMPT)
    return [
        ("fortiadc", "slb_load", "\n", "newline"),
        ("fortiadc", "slb_load", "", "empty"),
        ("fortiadc", "slb_load", " \r\n\r\n", "blank-lines"),
        ("fortiadc", "slb_load", prompt_only, "pty-echo-and-prompt-only"),
        ("fortinet", fortinet_query, "\n", "newline"),
        ("fortinet", fortinet_query, "", "empty"),
    ]


def test_prompt_only_pty_answer_reduces_to_empty_body():
    assert engine._pty_body(SLB.encode() + b"\r\n" + ADC_PROMPT, SLB, ADC_PROMPT) == ""


@pytest.mark.parametrize("platform,query,output,label", _cases(), ids=lambda v: v if isinstance(v, str) else None)
def test_whitespace_only_output_is_an_empty_failure(wire, monkeypatch, platform, query, output, label):
    calls = _fake_read(monkeypatch, output, rc=0)
    answer = _read(platform, query)
    assert calls, "fake transport was not used"
    assert answer["ok"] is False and answer["error_code"] == "empty", answer
    assert answer["rc"] == 0 and answer["query"] == query and answer["platform"] == platform
    assert "complete" not in answer and "untrusted_device_output" not in answer
    assert engine._SSH_PAGE_CACHE == {}


def test_empty_code_is_a_triage_missing_reason():
    assert "empty" in triage_slb.MISSING_REASONS


def test_only_catalogue_documented_queries_allow_empty_output():
    allowed = {(platform, name) for platform, queries in READ_QUERIES.items()
               for name, query in queries.items() if query.empty_allowed}
    assert allowed == set(LEGAL_EMPTY)
    for platform, name in allowed:
        assert "empty output means" in READ_QUERIES[platform][name].description


@pytest.mark.parametrize("platform,query", sorted(LEGAL_EMPTY))
@pytest.mark.parametrize("output", ["", "\n"])
def test_catalogue_legal_empty_output_stays_success(wire, monkeypatch, platform, query, output):
    _fake_read(monkeypatch, output)
    answer = _read(platform, query, LEGAL_EMPTY[(platform, query)])
    assert answer["ok"] is True and answer["complete"] is True, answer
    assert answer["untrusted_device_output"] == output and "error_code" not in answer


@pytest.mark.parametrize("platform", ["fortiadc", "fortinet"])
def test_control_non_empty_output_stays_success(wire, monkeypatch, platform):
    query = "slb_load" if platform == "fortiadc" else _plain_query("fortinet")[0]
    _fake_read(monkeypatch, "VS_APP_HTTP status 1\n")
    answer = _read(platform, query)
    assert answer["ok"] is True and answer["complete"] is True


@pytest.mark.parametrize("prompt", [b"(P) fortiadc-767-b # ", b"(S) FortiADC-KVM # "])
def test_an_ha_pair_without_traffic_groups_reads_as_an_empty_success(wire, monkeypatch, prompt):
    _write_client(wire["binaries"], "ssh", EXEC_CLIENT.format(log=str(wire["log"]), output=FORTIADC_STATUS, code=0))
    sent = []

    class Terminal:
        def __init__(self, *args, **options):
            self.answers = iter([b"banner\r\n" + prompt, TRAFFIC_GROUP.encode() + b"\r\r\n\r\n" + prompt])

        def expect(self, patterns, timeout):
            return 0, next(self.answers)

        def discard(self, seen):
            pass

        def send(self, text):
            sent.append(text)

        def close(self):
            pass

    monkeypatch.setattr(engine.core_session, "Session", Terminal)
    answer = _read("fortiadc", "traffic_group_status")
    assert sent == [TRAFFIC_GROUP]
    assert answer["ok"] is True and answer["complete"] is True and answer["transport"] == "pty", answer
    assert answer["untrusted_device_output"] == "" and "error_code" not in answer
    meaning = READ_QUERIES["fortiadc"]["traffic_group_status"].description
    for part in ("Administration Guide (p. 246) describes traffic groups for the HA mode active-active-VRRP",
                 "empty output means the device reports no traffic group",
                 "measured in active-passive mode (both roles) and in standalone mode",
                 "each time with an empty config system traffic-group section",
                 "names a predefined traffic group default",
                 "In active-active-VRRP empty output was not measured",
                 "check it against ha_status and the traffic group configuration"):
        assert part in meaning
    for claim in ("used only in", "is not expected", "which is expected"):
        assert claim not in meaning
    assert "error" not in meaning.lower() and "ha_status" in READ_QUERIES["fortiadc"]
