from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("export_status", ROOT / "scripts" / "export_status.py")
export_status = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export_status)


def runner(stdout):
    def run(argv, **kwargs):
        assert argv[1:3] == ["query", "get"]
        return SimpleNamespace(stdout=stdout)
    return run


def test_queue_is_read_for_the_named_destination_only():
    answer = "dst.syslog.d_netops_audit#0.tcp,192.0.2.10:601.queued=3\ndst.syslog.d_other#0.tcp,192.0.2.10:601.queued=90\n"
    assert export_status.queued("d_netops_audit", "ctl", run=runner(answer)) == 3


def test_missing_destination_is_an_error():
    with pytest.raises(RuntimeError):
        export_status.queued("d_netops_audit", "ctl", run=runner("dst.syslog.d_other#0.x.queued=1\n"))


def test_failed_query_leaves_the_status_untouched(tmp_path):
    def failing(argv, **kwargs):
        raise subprocess.CalledProcessError(1, argv)
    with pytest.raises(subprocess.CalledProcessError):
        export_status.queued("d_netops_audit", "ctl", run=failing)


def test_pending_age_starts_when_the_queue_fills_and_resets_when_it_empties(tmp_path):
    output = tmp_path / "export-status.json"
    assert export_status.write_status(output, 0, 1000.0)["oldest_pending_age_seconds"] == 0
    export_status.write_status(output, 2, 1000.0)
    status = export_status.write_status(output, 5, 1060.0)
    assert status == {"updated_at": 1060.0, "pending": 5, "oldest_pending_age_seconds": 60.0}
    assert json.loads(output.read_text()) == status
    assert export_status.write_status(output, 0, 1100.0)["oldest_pending_age_seconds"] == 0
    assert export_status.write_status(output, 1, 1200.0)["oldest_pending_age_seconds"] == 0


def test_status_names_the_audit_file_only_when_given(tmp_path):
    ctl = tmp_path / "syslog-ng-ctl"
    ctl.write_text("#!/bin/sh\necho 'dst.syslog.d_netops_audit#0.tcp,192.0.2.10:601.queued=0'\n")
    ctl.chmod(0o755)
    output = tmp_path / "export-status.json"
    base = ["--destination", "d_netops_audit", "--output", str(output), "--ctl", str(ctl)]
    assert export_status.main(base + ["--audit-file", "/var/lib/netops-admin-audit/audit.jsonl"]) == 0
    assert json.loads(output.read_text())["audit_file"] == "/var/lib/netops-admin-audit/audit.jsonl"
    assert export_status.main(base) == 0
    assert "audit_file" not in json.loads(output.read_text())
    assert export_status.main(base + ["--audit-file", "audit.jsonl"]) == 2
    assert "audit_file" not in json.loads(output.read_text())
