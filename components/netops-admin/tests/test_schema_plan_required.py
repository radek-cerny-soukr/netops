"""A schema Transaction apply needs the approved plan_sha256 of its preview like every other Admin apply.

Real path: execute.preview -> execute.apply (and the MCP tools admin_schema_preview -> admin_schema_apply) over the
schema bench of test_schema_execute (pinned library, measured rollback grants, fake FortiOS transport)."""
import pytest

from netops_admin import execute
from netops_admin.errors import Rejected
from test_schema_execute import runtime as schema_bench
from test_schema_plan import op
from test_schema_runtime import request


def test_a_transaction_without_the_preview_hash_is_refused_before_the_device_is_read(tmp_path, monkeypatch):
    value, fake = schema_bench(tmp_path, monkeypatch)
    opened = []
    factory = value.access_factory
    value.access_factory = lambda device: opened.append(device.name) or factory(device)
    with pytest.raises(Rejected) as caught:
        execute.apply(value, "lab", request([op(changes={"comment": "unapproved"})]))
    assert caught.value.reason_codes == ["plan_changed"]
    assert opened == [] and fake.applied_blocks == [] and list(value.store.records()) == []
    assert fake.addresses["source"]["comment"] == "source text"


def test_the_preview_hash_of_the_same_transaction_approves_it(tmp_path, monkeypatch):
    value, fake = schema_bench(tmp_path, monkeypatch)
    req = request([op(changes={"comment": "first"}), op(changes={"comment": "final"})])
    preview = execute.preview(value, "lab", req)
    assert preview["result"] == "ready" and fake.applied_blocks == []
    result = execute.apply(value, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed" and result["budget_changes"] == 2
    assert value.store.operation(result["change_id"])["plan"]["plan_sha256"] == preview["plan_sha256"]
    assert fake.addresses["source"]["comment"] == "final"


def test_a_transaction_whose_object_changed_after_the_preview_is_plan_changed(tmp_path, monkeypatch):
    value, fake = schema_bench(tmp_path, monkeypatch)
    req = request([op(changes={"comment": "approved"})])
    preview = execute.preview(value, "lab", req)
    assert preview["result"] == "ready"
    fake.addresses["source"]["comment"] = "changed meanwhile"
    with pytest.raises(Rejected) as caught:
        execute.apply(value, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert caught.value.reason_codes == ["plan_changed"]
    assert caught.value.reason_details[0]["expected"] == preview["plan_sha256"]
    assert fake.applied_blocks == [] and list(value.store.records()) == []
    assert fake.addresses["source"]["comment"] == "changed meanwhile"


@pytest.mark.parametrize("value", ["A" * 64, "a" * 10, "z" * 64])
def test_a_malformed_transaction_hash_is_refused(tmp_path, monkeypatch, value):
    bench, fake = schema_bench(tmp_path, monkeypatch)
    with pytest.raises(Rejected) as caught:
        execute.apply(bench, "lab", request([op()]), expected_plan_sha256=value)
    assert "64 lowercase hexadecimal" in caught.value.reasons[0]
    assert fake.applied_blocks == []


def test_mcp_schema_apply_requires_the_schema_preview_hash(tmp_path, monkeypatch):
    pytest.importorskip("fastmcp")
    from netops_admin import mcp_server
    from test_mcp_server import call, schema_arguments

    value, fake = schema_bench(tmp_path, monkeypatch)
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", value.config)
    monkeypatch.setattr(mcp_server, "build_runtime", lambda config: value)
    arguments = schema_arguments([op(changes={"comment": "mcp"})])
    missing = call("admin_schema_apply", arguments)
    assert missing["result"] == "rejected" and missing["reason_codes"] == ["plan_changed"]
    assert fake.applied_blocks == [] and list(value.store.records()) == []
    preview = call("admin_schema_preview", arguments)
    assert preview["result"] == "ready"
    answer = call("admin_schema_apply", dict(arguments, expected_plan_sha256=preview["plan_sha256"]))
    assert answer["result"] == "confirmed", answer
    assert fake.addresses["source"]["comment"] == "mcp"
