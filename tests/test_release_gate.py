from __future__ import annotations

import importlib.util
import ipaddress
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
RFC1918_TEST_ADDRESS = str(ipaddress.ip_address(0xC0A80A14))
IPV6_GUA_SAMPLE = str(ipaddress.ip_address((0x2A01 << 112) + (0x0430 << 96) + 0x20))
PUBLIC_IPV4_SAMPLE = str(ipaddress.ip_address(0x55A02C07))

MDNS_SAMPLE = "nas." + "local"


def _load_gate():
    path = ROOT / "scripts/check_release.py"
    specification = importlib.util.spec_from_file_location("_netops_repository_gate", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _fixture(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir(parents=True)
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / "README.md").write_text("# netops\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("# Security policy\n", encoding="utf-8")
    (root / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
    (root / ".dockerignore").write_text("**\n", encoding="utf-8")
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs/README.md").write_text("# Documentation map\n", encoding="utf-8")
    (root / "docs/verified-support.md").write_text("# Verified platform support\n", encoding="utf-8")
    (root / "docs/lab-measurements-2026-09-25.md").write_text("# Live lab measurements\n", encoding="utf-8")
    (root / "scripts").mkdir()
    shutil.copy2(ROOT / "scripts/check_release.py", root / "scripts/check_release.py")
    (root / "tests").mkdir()
    (root / "tests/test_release_gate.py").write_text("", encoding="utf-8")
    workflows = root / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n"
        "  repository:\n"
        "    steps:\n"
        "      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
        "      - run: |\n"
        "          python tests/test_release_gate.py\n"
        "          python scripts/check_release.py\n"
        "  demo:\n"
        "    if: ${{ !startsWith(github.ref, 'refs/tags/') || startsWith(github.ref, 'refs/tags/demo/') }}\n"
        "    defaults:\n"
        "      run:\n"
        "        working-directory: components/demo\n"
        "    steps:\n"
        "      - run: |\n"
        "          NETOPS_REQUIRE_RUNTIME_TESTS=1 python -m pytest -q\n"
        "          python scripts/check_demo.py\n",
        encoding="utf-8",
    )
    (workflows / "publish-pypi.yml").write_text(
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
        "  publish-pypi:\n"
        "    steps:\n"
        "      - uses: pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33\n",
        encoding="utf-8",
    )
    component = root / "components/demo"
    (component / "scripts").mkdir(parents=True)
    (component / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (component / "src").mkdir()
    (component / "src/module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (component / "scripts/create_release_artifacts.py").write_text(
        "from pathlib import Path\n"
        "\n"
        "ROOT = Path(__file__).resolve().parents[1]\n"
        "\n"
        "\n"
        "def selected_files(root: Path = ROOT) -> list[Path]:\n"
        "    return [root / 'LICENSE', root / 'src/module.py',\n"
        "            root / 'scripts/create_release_artifacts.py', root / 'scripts/check_demo.py']\n",
        encoding="utf-8",
    )
    (component / "scripts/check_demo.py").write_text(
        "print('demo_gate=passed')\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    return root


def _gate_for(root: Path):
    gate = _load_gate()
    gate.COMPONENT_GATES = {"demo": ("scripts/check_demo.py",)}
    return gate


def test_repository_fixture_passes() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        assert _gate_for(root).check(root) == []


def test_gate_rejects_tracked_file_outside_every_component_release() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        (root / "components/demo/notes.txt").write_text("stray\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        assert _gate_for(root).check(root) == [
            "tracked or unignored file outside every component release: "
            "components/demo/notes.txt"
        ]


def test_gate_rejects_unignored_untracked_secret_file() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        (root / "vault.json").write_text("{}\n", encoding="utf-8")
        assert _gate_for(root).check(root) == [
            "tracked or unignored file outside every component release: vault.json"
        ]
        (root / ".gitignore").write_text("dist/\nvault.json\n", encoding="utf-8")
        assert _gate_for(root).check(root) == []


def test_gate_rejects_selection_that_reaches_outside_the_component() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        selector = root / "components/demo/scripts/create_release_artifacts.py"
        selector.write_text(
            selector.read_text(encoding="utf-8").replace(
                "root / 'scripts/check_demo.py']",
                "root / 'scripts/check_demo.py', root / '../../README.md']",
            ),
            encoding="utf-8",
        )
        errors = _gate_for(root).check(root)
        assert any("reaches outside its tree" in error for error in errors), errors


def test_gate_rejects_component_license_drift() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        (root / "components/demo/LICENSE").write_text("MIT with a twist\n", encoding="utf-8")
        errors = _gate_for(root).check(root)
        assert "component LICENSE differs from the repository LICENSE: demo" in errors


def test_gate_rejects_component_without_a_registered_gate() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        gate = _load_gate()
        gate.COMPONENT_GATES = {}
        errors = gate.check(root)
        assert "component has no registered gate: demo" in errors


def test_gate_reports_a_failing_component_gate() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        (root / "components/demo/scripts/check_demo.py").write_text(
            "print('demo_gate=failed detail=deliberate')\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        errors = _gate_for(root).check(root)
        assert "component gate failed: demo/scripts/check_demo.py" in errors


def test_gate_rejects_ci_that_skips_a_component_or_a_required_step() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        workflow = root / ".github/workflows/ci.yml"
        text = workflow.read_text(encoding="utf-8")
        workflow.write_text(
            text.replace("        working-directory: components/demo\n", ""),
            encoding="utf-8",
        )
        errors = _gate_for(root).check(root)
        assert "CI does not run the checks of a component: demo" in errors

        workflow.write_text(
            text.replace("          python scripts/check_demo.py\n", ""),
            encoding="utf-8",
        )
        errors = _gate_for(root).check(root)
        assert "CI does not run a component gate: demo/scripts/check_demo.py" in errors

        workflow.write_text(
            text.replace(
                "          NETOPS_REQUIRE_RUNTIME_TESTS=1 python -m pytest -q\n", ""
            ),
            encoding="utf-8",
        )
        errors = _gate_for(root).check(root)
        assert (
            "CI does not run a required step: NETOPS_REQUIRE_RUNTIME_TESTS=1 python -m pytest -q"
            in errors
        )

        workflow.write_text(
            text.replace(
                "    if: ${{ !startsWith(github.ref, 'refs/tags/') || startsWith(github.ref, 'refs/tags/demo/') }}\n",
                "",
            ),
            encoding="utf-8",
        )
        errors = _gate_for(root).check(root)
        assert "CI does not scope the tag run of a component to its own tag: demo" in errors


def test_gate_rejects_actions_that_are_not_sha_pinned() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        workflow = root / ".github/workflows/ci.yml"
        pinned = workflow.read_text(encoding="utf-8")
        for form in (
            "      - uses: actions/checkout@v7\n",
            "      - name: Check out source\n        uses: actions/checkout@v7\n",
        ):
            workflow.write_text(
                pinned.replace(
                    "      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n",
                    form,
                ),
                encoding="utf-8",
            )
            errors = _gate_for(root).check(root)
            assert (
                "GitHub Action is not SHA-pinned in ci.yml: actions/checkout@v7" in errors
            ), (form, errors)


def test_gate_rejects_an_unpinned_action_in_the_publish_workflow() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        workflow = root / ".github/workflows/publish-pypi.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
                "pypa/gh-action-pypi-publish@release/v1",
            ),
            encoding="utf-8",
        )
        errors = _gate_for(root).check(root)
        assert (
            "GitHub Action is not SHA-pinned in publish-pypi.yml: pypa/gh-action-pypi-publish@release/v1"
            in errors
        ), errors


def test_gate_requires_the_publish_workflow() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        subprocess.run(
            ["git", "-C", str(root), "rm", "-q", "-f", ".github/workflows/publish-pypi.yml"], check=True
        )
        errors = _gate_for(root).check(root)
        assert "reviewed repository file is missing: .github/workflows/publish-pypi.yml" in errors, errors


def test_gate_rejects_private_and_credential_markers() -> None:
    flagged = {
        f"the runner is {RFC1918_TEST_ADDRESS}": (
            f"components/demo/src/module.py:2 holds an address outside the RFC 5737"
            f" documentation ranges: {RFC1918_TEST_ADDRESS}"
        ),
        f"public relay {PUBLIC_IPV4_SAMPLE}": (
            f"components/demo/src/module.py:2 holds an address outside the RFC 5737"
            f" documentation ranges: {PUBLIC_IPV4_SAMPLE}"
        ),
        f"prefix {IPV6_GUA_SAMPLE}": (
            f"components/demo/src/module.py:2 holds an IPv6 address outside"
            f" 2001:db8::/32: {IPV6_GUA_SAMPLE}"
        ),
        "path /" + "home/operator/keys": "private marker in components/demo/src/module.py",
        "token ghp_" + "a" * 36: "credential-shaped material in components/demo/src/module.py",
    }
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        module = root / "components/demo/src/module.py"
        for text, expected in flagged.items():
            module.write_text(f"VALUE = 1\n# {text}\n", encoding="utf-8")
            errors = _gate_for(root).check(root)
            assert expected in errors, (text, errors)
        module.write_text(
            "VALUE = 1\n# target 192.0.2.10, 2001:db8::1, example.invalid\n",
            encoding="utf-8",
        )
        assert _gate_for(root).check(root) == []


def test_gate_allows_documentation_addresses_and_reserved_domains() -> None:
    allowed = (
        "192.0.2.10",
        "198.51.100.7",
        "203.0.113.9",
        "127.0.0.11",
        "255.255.255.0",
        "2001:db8::1",
        "fe80::1",
        "example.invalid",
        "runner.example",
        "github.com",
    )
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        notes = root / "components/demo/notes.md"
        selector = root / "components/demo/scripts/create_release_artifacts.py"
        selector.write_text(
            selector.read_text(encoding="utf-8").replace(
                "root / 'scripts/check_demo.py']",
                "root / 'scripts/check_demo.py', root / 'notes.md']",
            ),
            encoding="utf-8",
        )
        for sample in allowed:
            notes.write_text(f"# poznamka\n\nhodnota {sample}\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            assert _gate_for(root).check(root) == [], sample


def test_gate_rejects_a_domain_outside_the_allowlist() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        notes = root / "components/demo/notes.md"
        selector = root / "components/demo/scripts/create_release_artifacts.py"
        selector.write_text(
            selector.read_text(encoding="utf-8").replace(
                "root / 'scripts/check_demo.py']",
                "root / 'scripts/check_demo.py', root / 'notes.md']",
            ),
            encoding="utf-8",
        )
        notes.write_text("# poznamka\n\nposta na mail." + "operator-domain.cz\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        errors = _gate_for(root).check(root)
        assert any("holds a domain outside" in error for error in errors), errors


def test_gate_rejects_an_address_that_ends_a_sentence() -> None:
    for payload, marker in (
        ("The management address is 10.0" + ".0.1.\n", "holds an address"),
        ("The peer is fd12:3456" + ":789a::1.\n", "holds an IPv6 address"),
        ("The mirror is operator-domain" + ".cz.\n", "holds a domain outside"),
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = _fixture(Path(directory))
            notes = root / "components/demo/notes.md"
            selector = root / "components/demo/scripts/create_release_artifacts.py"
            selector.write_text(
                selector.read_text(encoding="utf-8").replace(
                    "root / 'scripts/check_demo.py']",
                    "root / 'scripts/check_demo.py', root / 'notes.md']",
                ),
                encoding="utf-8",
            )
            notes.write_text("# poznamka\n\n" + payload, encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            errors = _gate_for(root).check(root)
            assert any(marker in error for error in errors), (payload, errors)


def test_gate_still_reads_a_version_as_a_version() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        notes = root / "components/demo/notes.md"
        selector = root / "components/demo/scripts/create_release_artifacts.py"
        selector.write_text(
            selector.read_text(encoding="utf-8").replace(
                "root / 'scripts/check_demo.py']",
                "root / 'scripts/check_demo.py', root / 'notes.md']",
            ),
            encoding="utf-8",
        )
        notes.write_text("# poznamka\n\nBuild 1.2.3.4.5 and 33.7.1.6.\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        assert _gate_for(root).check(root) == []


def test_gate_rejects_key_material_under_every_pem_header() -> None:
    payload = "MII" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef" * 2
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        module = root / "components/demo/src/module.py"
        for header in (
            "OPENSSH PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "PRIVATE KEY",
        ):
            module.write_text(
                "VALUE = 1\n# -----BEGIN {0}-----\n# {1}\n# -----END {0}-----\n".format(
                    header, payload
                ),
                encoding="utf-8",
            )
            errors = _gate_for(root).check(root)
            assert "private key material in components/demo/src/module.py" in errors, (
                header,
                errors,
            )
        module.write_text(
            "VALUE = 1\n# -----BEGIN PRIVATE KEY----- (jen znacka, bez materialu)\n",
            encoding="utf-8",
        )
        assert _gate_for(root).check(root) == []


def test_gate_rejects_a_symbolic_link_in_place_of_a_reviewed_file() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        target = root / "docs/README.md"
        target.unlink()
        target.symlink_to("/" + "home/operator/.ssh/identity")
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        errors = _gate_for(root).check(root)
        assert "tracked entry is a symbolic link: docs/README.md" in errors, errors


def test_gate_rejects_a_text_file_that_is_not_utf8() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        module = root / "components/demo/src/module.py"
        module.write_bytes(
            "VALUE = 1  # {0}\n".format(RFC1918_TEST_ADDRESS).encode("utf-16-le")
        )
        errors = _gate_for(root).check(root)
        assert (
            "tracked text file holds a NUL byte: components/demo/src/module.py" in errors
        ), errors


def test_gate_accepts_relative_markdown_links_to_a_file_and_a_directory() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        (root / "docs/README.md").write_text(
            "# Documentation map\n\n"
            "See [security policy](../SECURITY.md) and [demo component](../components/demo/).\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        assert _gate_for(root).check(root) == []


def test_gate_rejects_a_broken_relative_markdown_link() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        (root / "SECURITY.md").write_text(
            "# Security policy\n\nSee [egress control](docs/egress-control.md).\n",
            encoding="utf-8",
        )
        errors = _gate_for(root).check(root)
        assert (
            "relative link target is missing: SECURITY.md -> docs/egress-control.md" in errors
        ), errors


def test_gate_ignores_link_like_text_in_code_spans_and_fenced_code_blocks() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        (root / "docs/README.md").write_text(
            "# Documentation map\n\n"
            "A label is `[a-z0-9-]([a-z0-9-]{0,61}[a-z0-9])`, not a link.\n\n"
            "```\n"
            "[missing](docs/does-not-exist.md)\n"
            "```\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        assert _gate_for(root).check(root) == []


def test_gate_ignores_scheme_links_and_pure_anchors() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        (root / "docs/README.md").write_text(
            "# Documentation map\n\n"
            "See [upstream](https://example.invalid/docs) and"
            " [a section below](#missing-heading).\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        assert _gate_for(root).check(root) == []


def test_gate_reads_ci_without_its_comments() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        workflow = root / ".github/workflows/ci.yml"
        text = workflow.read_text(encoding="utf-8")
        workflow.write_text(
            text[: text.index("  demo:")]
            + "# smazany job, jen komentar:\n"
            + "#   working-directory: components/demo\n"
            + "#   python scripts/check_demo.py\n"
            + "#   NETOPS_REQUIRE_RUNTIME_TESTS=1 python -m pytest -q\n",
            encoding="utf-8",
        )
        errors = _gate_for(root).check(root)
        assert "CI does not run the checks of a component: demo" in errors, errors
        assert "CI does not run a component gate: demo/scripts/check_demo.py" in errors, errors


def test_component_selector_cannot_disarm_the_gate() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        selector = root / "components/demo/scripts/create_release_artifacts.py"
        selector.write_text(
            selector.read_text(encoding="utf-8")
            + "\nimport sys as _sys\n"
            + "_gate = _sys.modules.get('__main__')\n"
            + "if _gate is not None and hasattr(_gate, 'PRIVATE_MARKERS'):\n"
            + "    _gate.PRIVATE_MARKERS = ()\n"
            + "    _gate.TEST_TOLERATED_MARKERS = ()\n",
            encoding="utf-8",
        )
        module = root / "components/demo/src/module.py"
        module.write_text(
            "VALUE = 1\n# runner {0}\n".format(RFC1918_TEST_ADDRESS), encoding="utf-8"
        )
        errors = _gate_for(root).check(root)
        assert any(
            "holds an address outside" in error for error in errors
        ), errors


def test_gate_reads_what_git_would_commit_not_only_the_working_tree() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = _fixture(Path(directory))
        module = root / "components/demo/src/module.py"
        module.write_text(
            f"VALUE = 1\n# the runner is {RFC1918_TEST_ADDRESS}\n", encoding="utf-8"
        )
        subprocess.run(
            ["git", "-C", str(root), "add", "components/demo/src/module.py"], check=True
        )
        module.write_text("VALUE = 1\n# target 192.0.2.10\n", encoding="utf-8")
        errors = _gate_for(root).check(root)
        assert any("staged components/demo/src/module.py" in error for error in errors), errors
        assert any(RFC1918_TEST_ADDRESS in error for error in errors), errors
        subprocess.run(
            ["git", "-C", str(root), "add", "components/demo/src/module.py"], check=True
        )
        assert _gate_for(root).check(root) == []


def test_repository_gate_covers_the_real_tree() -> None:
    gate = _load_gate()
    tracked, errors = gate.tracked_files(ROOT)
    assert errors == []
    assert gate.component_names(ROOT) == ["netops-admin", "netops-auditor", "netops-core", "netops-helper"]
    assert gate._coverage_errors(ROOT, tracked, gate.component_names(ROOT)) == []
    assert gate._license_errors(ROOT, gate.component_names(ROOT)) == []
    assert gate._workflow_errors(ROOT, gate.component_names(ROOT)) == []


def main() -> int:
    for name, function in sorted(globals().items()):
        if name.startswith("test_") and callable(function):
            function()
    print("repository_gate_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
