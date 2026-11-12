"""EXOS ends some complete show commands with exit status 250; see docs/read-only-accounts.md."""
from pathlib import Path

import pytest

import netops_helper.engine as engine
from netops_helper import normalization
from conftest import _target

REAL = Path(__file__).parent / "fixtures/real/exos"
DIRS = sorted(path for path in REAL.iterdir() if path.is_dir())
NAMES = ("vlan_details", "interface_details", "ipv6_route_summary")


def _read_with(monkeypatch, platform, query, rc, body):
    monkeypatch.setattr(engine, "record", lambda *a, **kw: None)
    monkeypatch.setattr(engine, "_verified_read", lambda *a, **kw: (rc, body))
    return engine.ssh_read(_target(platform, query), platform, query, {}, 0, 48000)


@pytest.mark.parametrize("directory", DIRS, ids=lambda path: path.name)
@pytest.mark.parametrize("name", NAMES)
def test_real_output_with_status_250_is_ok_with_a_warning(directory, name):
    text = (directory / f"{name}.txt").read_text()
    assert text.strip()
    assert normalization.exos_exit_250("extreme_exos", 250, text)
    assert normalization.output_status(text, rc=250, profile="extreme_exos") == "ok"


@pytest.mark.parametrize("directory", DIRS, ids=lambda path: path.name)
def test_ssh_read_accepts_complete_real_output_with_status_250(monkeypatch, directory):
    text = (directory / "ipv6_route_summary.txt").read_text()
    answer = _read_with(monkeypatch, "extreme_exos", "ipv6_route_summary", 250, text)
    assert answer["ok"] is True
    assert answer["rc"] == 250
    # Raw catalogue output has no adapter yet, so a plain rc 0 read is "unparsed" too.
    assert answer["status"] == _read_with(monkeypatch, "extreme_exos", "ipv6_route_summary", 0, text)["status"] != "transport_error"
    assert answer["normalized"]["warnings"] == ["exit_status_250"]


@pytest.mark.parametrize("body", [
    "%% Invalid input detected at '^' marker.\n",
    "Vlan: x\nError: something failed\n",
    "Invalid input\n",
    "Incomplete command\n",
])
def test_status_250_with_an_error_mark_is_a_cli_error(monkeypatch, body):
    assert not normalization.exos_exit_250("extreme_exos", 250, body)
    answer = _read_with(monkeypatch, "extreme_exos", "ipv6_route_summary", 250, body)
    assert answer["ok"] is False
    assert answer["error_code"] == "device_cli_error"
    assert "exit_status_250" not in answer["normalized"]["warnings"]


def test_empty_output_with_status_250_fails(monkeypatch):
    assert not normalization.exos_exit_250("extreme_exos", 250, " \n")
    answer = _read_with(monkeypatch, "extreme_exos", "ipv6_route_summary", 250, "\n")
    assert answer["ok"] is False
    assert answer["error_code"] == "empty"


def test_other_profiles_do_not_normalize_status_250(monkeypatch):
    text = (DIRS[0] / "ipv6_route_summary.txt").read_text()
    for profile in ("cisco_ios", "linux", "fortinet", None):
        assert not normalization.exos_exit_250(profile, 250, text)
        assert normalization.output_status(text, rc=250, profile=profile) == "transport_error"
    answer = _read_with(monkeypatch, "linux", "hostname", 250, "host\n")
    assert "exit_status_250" not in str(answer.get("normalized", {}).get("warnings"))
