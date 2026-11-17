"""Keep the retained SSH and privacy checks live after exporter removal."""

from pathlib import Path
import shutil

import pytest

from support.check_public_release import (
    TEXT_SUFFIXES,
    _privacy_errors,
    _secret_and_network_marker_errors,
    _ssh_wire_errors,
)

ROOT = Path(__file__).resolve().parents[1]


def _source_files():
    # Inspect the actual package; the standalone release exporter no longer exists.
    files = sorted(
        path for path in (ROOT / "src").rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    )
    assert files, "Helper package sources are missing"
    return files


def test_ssh_wire_check_passes_on_real_helper():
    errors = _ssh_wire_errors(ROOT)
    assert errors == [], "SSH wire findings:\n" + "\n".join(errors)


def test_privacy_check_passes_on_real_helper_package():
    errors = _privacy_errors(ROOT, _source_files())
    assert errors == [], "privacy findings:\n" + "\n".join(errors)


def test_secret_and_network_check_passes_on_real_helper_package():
    errors = []
    for path in _source_files():
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        errors.extend(_secret_and_network_marker_errors(
            path.relative_to(ROOT).as_posix(),
            path.read_text(encoding="utf-8"),
        ))
    assert errors == [], "secret/network findings:\n" + "\n".join(errors)


def test_ssh_wire_check_rejects_retired_transport(tmp_path):
    for relative in ("src/netops_helper/engine.py", "tests/test_ssh_wire_safety.py"):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    assert _ssh_wire_errors(tmp_path) == []
    engine = tmp_path / "src/netops_helper/engine.py"
    with engine.open("a", encoding="utf-8") as stream:
        stream.write("\nimport paramiko\n")
    assert _ssh_wire_errors(tmp_path) == ["the read transport still imports paramiko"]


def test_privacy_check_rejects_private_configuration(tmp_path):
    path = tmp_path / "vault.json"
    path.write_text("{}\n", encoding="utf-8")
    assert _privacy_errors(tmp_path, [path]) == [
        "private configuration included: vault.json",
    ]


@pytest.mark.parametrize("text", ["openai-model", "anthropic-version"])
def test_privacy_check_allows_hyphenated_field_names(tmp_path, text):
    path = tmp_path / "sample.txt"
    path.write_text(text, encoding="utf-8")
    assert _privacy_errors(tmp_path, [path]) == []


@pytest.mark.parametrize("text", ["OpenAI", "Claude"])
def test_privacy_check_rejects_standalone_agent_vendor(tmp_path, text):
    path = tmp_path / "sample.txt"
    path.write_text(text, encoding="utf-8")
    assert _privacy_errors(tmp_path, [path]) == ["private marker in sample.txt"]


@pytest.mark.parametrize(("text", "message"), [
    ("gh" + "p_" + "A" * 36, "credential-shaped material"),
    ("gateway." + "internal", "private network marker"),
])
def test_secret_and_network_check_rejects_marker(tmp_path, text, message):
    path = tmp_path / "sample.txt"
    path.write_text(text, encoding="utf-8")
    relative = path.relative_to(tmp_path).as_posix()
    assert _secret_and_network_marker_errors(
        relative, path.read_text(encoding="utf-8"),
    ) == [f"{message} in sample.txt"]
