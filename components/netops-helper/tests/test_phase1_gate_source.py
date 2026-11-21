from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "check_public_release_phase1_source",
        ROOT / "tests" / "support" / "check_public_release.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_phase1_surface_gate_passes_on_real_helper_source() -> None:
    """Run the real phase-1 gate over the real component root (as ref/phase1_diag.py does)."""
    errors = _load_gate()._phase1_surface_errors(ROOT)
    assert errors == [], "phase-1 gate findings:\n" + "\n".join(errors)


SESSION_COMMAND = "show configuration session summary"
SESSION_SOURCES = ("read_policy.py", "query_catalog/cisco.py")


def _session_source(tmp_path, relative):
    source = tmp_path / "src/netops_helper"
    source.mkdir(parents=True)
    (source / "server.py").write_text("")
    target = source / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    original = (ROOT / "src/netops_helper" / relative).read_text()
    target.write_text(original)
    return target, original


@pytest.mark.parametrize("relative, name, command, pattern", [
    ("config_arista_eos_adapter.py", "STARTUP_COMMAND", "show startup-config", "show startup-config"),
    ("config_arista_eos_adapter.py", "DIFF_COMMAND", "show running-config diffs", "show running-config"),
    ("config_cisco_xe_adapter.py", "STARTUP_COMMAND", "show startup-config", "show startup-config"),
    ("config_cisco_xe_adapter.py", "DIFF_COMMAND",
     "show archive config differences nvram:startup-config system:running-config", "show archive config differences"),
])
def test_startup_diff_gate_requires_exact_literals_and_locations(tmp_path, relative, name, command, pattern):
    gate = _load_gate()
    target, original = _session_source(tmp_path, relative)
    assert gate._phase1_surface_errors(tmp_path) == []
    declaration = f"{name} = {command!r}"
    assert declaration in original
    finding = f"src/netops_helper/{relative}: {pattern}"
    for changed in (original.replace(declaration, f"{name} = {command + ' | json'!r}"),
                    original.replace(declaration, f"OTHER = {command!r}"),
                    original + f"\nEXTRA = {command!r}\n"):
        target.write_text(changed)
        assert any(finding in error for error in gate._phase1_surface_errors(tmp_path))


@pytest.mark.parametrize("relative", SESSION_SOURCES)
@pytest.mark.parametrize("command", [
    "show configuration",
    "show configuration session",
    "show configuration session details",
    "show configuration session summary details",
    "show configuration session summary extra",
    "show conf",
    "show conf session summary",
    "show config session summary",
    "show configuration session summary; show configuration",
])
def test_session_summary_gate_rejects_variants(tmp_path, relative, command):
    gate = _load_gate()
    target, original = _session_source(tmp_path, relative)
    assert gate._phase1_surface_errors(tmp_path) == []
    assert original.count(SESSION_COMMAND) == 1
    target.write_text(original.replace(SESSION_COMMAND, command))
    errors = gate._phase1_surface_errors(tmp_path)
    assert any(f"src/netops_helper/{relative}: show configuration" in error for error in errors)


@pytest.mark.parametrize("relative", SESSION_SOURCES)
@pytest.mark.parametrize("platform", ["cisco_ios", "cisco_xe"])
def test_session_summary_gate_exception_is_only_for_nxos(tmp_path, relative, platform):
    gate = _load_gate()
    target, original = _session_source(tmp_path, relative)
    if relative == "read_policy.py":
        original = original.replace(
            f'platform == "cisco_nxos" and inspected == "{SESSION_COMMAND}"',
            f'platform == "{platform}" and inspected == "{SESSION_COMMAND}"',
        )
    else:
        # Move the exact reviewed entry into a foreign profile dictionary.
        start = original.index("NXOS_QUERIES: dict")
        original = original[start:].replace("NXOS_QUERIES", {
            "cisco_ios": "IOS_QUERIES", "cisco_xe": "XE_QUERIES",
        }[platform], 1)
    target.write_text(original)
    assert gate._phase1_surface_errors(tmp_path)


@pytest.mark.parametrize("relative", SESSION_SOURCES)
def test_session_summary_gate_has_no_extra_or_renamed_source_allowance(tmp_path, relative):
    gate = _load_gate()
    target, original = _session_source(tmp_path, relative)
    target.write_text(original + f'\nEXTRA = "{SESSION_COMMAND}"\n')
    assert gate._phase1_surface_errors(tmp_path)
    target.unlink()
    (tmp_path / "src/netops_helper/other.py").write_text(original)
    assert gate._phase1_surface_errors(tmp_path)


@pytest.mark.parametrize("platform", ["cisco_ios", "cisco_xe", "cisco_nxos"])
@pytest.mark.parametrize("command", [
    "show configuration", "show configuration session",
    "show configuration session details", "show configuration session summary details",
    "show conf session summary",
])
def test_session_summary_policy_still_rejects_variants(platform, command):
    from netops_helper.read_policy import _validate_query_command

    with pytest.raises(RuntimeError):
        _validate_query_command(platform, command)


def test_session_summary_policy_accepts_only_nxos():
    from netops_helper.read_policy import _validate_query_command

    _validate_query_command("cisco_nxos", SESSION_COMMAND)
    for platform in ("cisco_ios", "cisco_xe"):
        with pytest.raises(RuntimeError):
            _validate_query_command(platform, SESSION_COMMAND)


FILTER_COMMAND = "show configuration interfaces {interface} family inet filter | no-more"
FILTER_SOURCE = "query_catalog/junos.py"


@pytest.mark.parametrize("command", [
    "show configuration | no-more",
    "show configuration interfaces {interface} family inet | no-more",
    "show configuration interfaces {interface} family inet6 filter | no-more",
    "show configuration interfaces {interface} family inet filter | display set | no-more",
])
def test_junos_filter_leaf_gate_and_policy_refuse_broader_variants(tmp_path, command):
    from netops_helper.read_policy import _validate_query_command

    gate = _load_gate()
    target, original = _session_source(tmp_path, FILTER_SOURCE)
    assert gate._phase1_surface_errors(tmp_path) == []
    target.write_text(original.replace(FILTER_COMMAND, command))
    assert any(f"{FILTER_SOURCE}: show configuration" in error for error in gate._phase1_surface_errors(tmp_path))
    with pytest.raises(RuntimeError):
        _validate_query_command("juniper_junos", command)


def test_junos_filter_leaf_gate_allows_only_the_reviewed_assignment(tmp_path):
    gate = _load_gate()
    target, original = _session_source(tmp_path, FILTER_SOURCE)
    target.write_text(original + f'\nEXTRA = "{FILTER_COMMAND}"\n')
    assert any(f"{FILTER_SOURCE}: show configuration" in error for error in gate._phase1_surface_errors(tmp_path))


@pytest.mark.parametrize("replacement", [
    "show configuration system | display xml | no-more",
    "show configuration system radius-server | display set | no-more",
    "show configuration system login | display xml | no-more",
])
def test_junos_management_gate_accepts_only_reviewed_leaves(tmp_path, replacement):
    from netops_helper.read_policy import _validate_query_command

    gate = _load_gate()
    target, original = _session_source(tmp_path, FILTER_SOURCE)
    reviewed = "show configuration system radius-server | display xml | no-more"
    assert gate._phase1_surface_errors(tmp_path) == []
    _validate_query_command("juniper_junos", reviewed)
    target.write_text(original.replace(reviewed, replacement))
    assert any(f"{FILTER_SOURCE}: show configuration" in error for error in gate._phase1_surface_errors(tmp_path))
    with pytest.raises(RuntimeError):
        _validate_query_command("juniper_junos", replacement)
