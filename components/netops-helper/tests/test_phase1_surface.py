import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
VENDOR_MARKERS = ("co" + "dex", "open" + "ai", "chat" + "gpt", "clau" + "de", "anthro" + "pic")
WRITE_MARKERS = (
    "prepare_", "apply_", "cancel_change", "sftp_upload",
    "send_command_timing", "posix_rename", "save_config", "config_mode",
)


def test_distribution_is_agent_vendor_neutral() -> None:
    assert not (ROOT / "plugin").exists()
    public_paths = "\n".join(path.relative_to(ROOT).as_posix().lower() for path in ROOT.rglob("*"))
    for marker in VENDOR_MARKERS:
        assert marker not in public_paths


def test_phase1_source_has_no_write_implementation() -> None:
    source_root = ROOT / "src" / "netops_helper"
    assert not (source_root / "changes.py").exists()
    assert not (source_root / "policy.py").exists()
    source = "\n".join(path.read_text().lower() for path in source_root.glob("*.py"))
    for marker in WRITE_MARKERS:
        assert marker not in source


def test_server_declares_read_only_untrusted_boundary() -> None:
    server = (ROOT / "src/netops_helper/server.py").read_text().lower()
    for required in ("read-only", "untrusted", "write_tools"):
        assert required in server


def test_route_trace_is_absent_from_phase1_surface() -> None:
    engine = (ROOT / "src/netops_helper/engine.py").read_text()
    server = (ROOT / "src/netops_helper/server.py").read_text()
    assert "def route_trace(" not in engine
    assert "def route_trace(" not in server
    assert "engine_route_trace" not in server


def test_read_query_catalog_exposes_legacy_and_rich_metadata() -> None:
    from netops_helper.query_catalog import READ_QUERIES
    from netops_helper.read_policy import (
        public_query_catalog,
        public_query_metadata,
    )
    from netops_helper.server import _query_catalog_payload

    payload = _query_catalog_payload()
    assert set(payload) == {"ok", "queries", "query_metadata"}
    assert payload["ok"] is True
    assert payload["queries"] == public_query_catalog()
    assert payload["query_metadata"] == public_query_metadata()
    for profile, queries in payload["query_metadata"].items():
        for query_name, metadata in queries.items():
            assert set(metadata) == {
                "command_template",
                "description",
                "high_volume",
                "parameters",
            }
            assert (
                metadata["command_template"]
                == READ_QUERIES[profile][query_name].command
            )
            assert isinstance(metadata["description"], str)
            assert isinstance(metadata["high_volume"], bool)
            for parameter in metadata["parameters"].values():
                assert set(parameter) == {"inventory", "kind"}
    server_tree = ast.parse(
        (ROOT / "src/netops_helper/server.py").read_text(encoding="utf-8")
    )
    ssh_read = next(
        node
        for node in server_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "ssh_read"
    )
    parameter_names = [argument.arg for argument in ssh_read.args.args]
    assert parameter_names == [
        "target",
        "platform",
        "query",
        "parameters",
        "offset",
        "max_bytes",
        "content_sha256",
        "auth_context",
    ]
    assert "command_template" not in parameter_names


def test_docs_require_isolated_read_only_session() -> None:
    docs = (ROOT / "docs/security-model.md").read_text().lower()
    for required in ("untrusted", "dedicated", "read-only", "never instructions"):
        assert required in docs
