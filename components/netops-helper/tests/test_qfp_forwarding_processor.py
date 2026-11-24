"""Hardware IOS XE QFP observations through MCP, proxy and fake SSH transport."""

from pathlib import Path

import pytest

from netops_helper.query_catalog.cisco import QFP_QUERIES
from test_xe_health_ios_xe_health import public, read  # noqa: F401 - established IOS XE transport fixture

FIXTURES = Path(__file__).parent / "fixtures/real/cisco_xe/forwarding_processor_qfp"


def capture(name):
    return (FIXTURES / f"{name}.out").read_text()


def read_qfp(public, query, text=None, *, rc=0, **args):
    replies, _, _, _ = public
    replies["show version"] = capture("version")
    replies[QFP_QUERIES[query].command] = rc, text if text is not None else capture(query.removeprefix("qfp_"))
    return read(public, query, enabled=["version", *QFP_QUERIES], **args)


def test_documented_qfp_drop_counts(public):
    result = read_qfp(public, "qfp_drops")
    assert result["ok"] and result["status"] == "ok" and result["complete"]
    assert result["normalized"]["summary"]["last_clearing"] == "never"
    rows = {row["reason"]: row for row in result["normalized"]["records"]}
    assert rows["TailDrop"] == {"reason": "TailDrop", "packets": 193769387, "octets": 157113756882}
    assert result["firmware_support"]["status"] == "untested"


@pytest.mark.parametrize(("fixture", "processing", "tx"), [("utilization", 46, None), ("utilization_crypto", 0, 2)])
def test_documented_qfp_utilization_windows(public, fixture, processing, tx):
    result = read_qfp(public, "qfp_utilization", capture(fixture))
    assert result["ok"] and result["complete"]
    cpp, = result["normalized"]["records"]
    assert cpp["cpp"] == 0
    assert cpp["load_percent"]["processing"]["1_minute"] == processing
    assert cpp["load_percent"].get("tx", {}).get("1_minute") == tx
    assert set(cpp["input"]["total"]["pps"]) == {"5_seconds", "1_minute", "5_minutes", "60_minutes"}


@pytest.mark.parametrize("mutation", ["unknown", "pager", "cut", "blank"])
def test_unproved_utilization_is_incomplete(public, mutation):
    raw = capture("utilization")
    text = {
        "unknown": raw + "unrecognized table\n",
        "pager": raw + "--More--",
        "cut": "\n".join(raw.splitlines()[:-1]),
        "blank": "",
    }[mutation]
    result = read_qfp(public, "qfp_utilization", text)
    assert result["status"] == "incomplete" and not result["complete"]


def test_ios_cli_refusal_and_proxy_parameter_refusal(public):
    _, calls, _, _ = public
    refused = read(public, "qfp_drops", {"clear": "yes"}, enabled=["version", *QFP_QUERIES])
    assert not refused.get("ok") and not calls
    result = read_qfp(public, "qfp_drops", "% Invalid input detected at '^' marker.\n")
    assert not result["ok"] and result["status"] == "permission_denied"
