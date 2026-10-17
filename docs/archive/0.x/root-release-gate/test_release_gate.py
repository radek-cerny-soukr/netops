from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
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
    (root / "docs/compatibility-boundaries.md").write_text("# Compatibility boundaries\n", encoding="utf-8")
    (root / "scripts").mkdir()
    shutil.copy2(ROOT / "scripts/check_release.py", root / "scripts/check_release.py")
    (root / "scripts/except_branch_coverage.py").write_text("", encoding="utf-8")
    (root / "scripts/except_branch_coverage.json").write_text("{}\n", encoding="utf-8")
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



def test_gate_accepts_a_repository_beneath_a_parent_alias() -> None:
    with tempfile.TemporaryDirectory() as directory:
        parent = Path(directory).resolve()
        root = _fixture(parent)
        alias = parent / "repository-parent-alias"
        alias.symlink_to(parent, target_is_directory=True)
        assert _gate_for(root).check(alias / root.name) == []


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



def _markdown_heading_anchors(text: str) -> set[str]:
    from html import unescape
    anchors: set[str] = set()
    counts: dict[str, int] = {}
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        heading = re.match(r"^ {0,3}#{1,6}\s+(.*?)\s*#*\s*$", line)
        if heading is None:
            continue
        label = re.sub(r"!?\[([^\]]+)\]\([^)]*\)", r"\1", heading.group(1))
        label = unescape(re.sub(r"<[^>]+>", "", label)).lower()
        slug = re.sub(r"[^\w\- ]", "", label.replace(chr(96), "")).replace(" ", "-")
        count = counts.get(slug, 0)
        candidate = slug if count == 0 else f"{slug}-{count}"
        while candidate in anchors:
            count += 1
            candidate = f"{slug}-{count}"
        counts[slug] = count + 1
        anchors.add(candidate)
    return anchors


def _assert_markdown_fragment(text: str, fragment: str, where) -> None:
    from urllib.parse import unquote
    if fragment:
        assert unquote(fragment) in _markdown_heading_anchors(text), (where, fragment)


def test_documentation_anchors_accept_headings_duplicates_and_encoded_fragments() -> None:
    text = "# Core `SSH` & TLS\n## Duplicate\n## Duplicate\n## Duplicate-1\n~~~text\n# Hidden\n~~~\n"
    assert _markdown_heading_anchors(text) == {"core-ssh--tls", "duplicate", "duplicate-1", "duplicate-1-1"}
    for fragment in ["core-ssh--tls", "duplicate", "duplicate-1", "duplicate-1-1", "%64uplicate"]:
        _assert_markdown_fragment(text, fragment, "positive fixture")
    for fragment in ["missing", "hidden", "duplicate-2"]:
        try:
            _assert_markdown_fragment(text, fragment, "negative fixture")
        except AssertionError:
            pass
        else:
            raise AssertionError("missing fragment was accepted: " + fragment)


def test_component_archives_have_resolvable_documentation_links() -> None:
    from urllib.parse import unquote, urlsplit
    import tomllib
    with tempfile.TemporaryDirectory() as directory:
        for component in sorted((ROOT / "components").iterdir()):
            script = component / "scripts/create_release_artifacts.py"
            if not script.is_file():
                continue
            output = Path(directory) / component.name
            output.mkdir()
            completed = subprocess.run([sys.executable, "-B", str(script), "--output", str(output)],
                                       capture_output=True, text=True)
            assert completed.returncode == 0, completed.stdout + completed.stderr
            [archive] = output.iterdir()
            metadata = tomllib.loads((component / "pyproject.toml").read_text())["project"]
            homepage = metadata["urls"]["Homepage"].rstrip("/")
            blob_prefix = homepage + "/blob/"
            outside_links = 0
            for document in archive.rglob("*.md"):
                fence = None
                for line in document.read_text().splitlines():
                    marker = re.match(r"^\s*(`{3,}|~{3,})", line)
                    if marker:
                        token = marker.group(1)
                        if fence is None:
                            fence = token
                        elif token[0] == fence[0] and len(token) >= len(fence):
                            fence = None
                        continue
                    if fence is not None:
                        continue
                    # Keep the brackets around a code-formatted label. Independent
                    # of the exporter's full-link tokenization.
                    text = re.sub(r"(`+).*?\1", lambda m: " " * len(m.group(0)), line)
                    for target in re.findall(r"\]\(([^)\s]+)\)", text):
                        url = urlsplit(target)
                        if target.startswith(blob_prefix):
                            rest = unquote(target[len(blob_prefix):].split("#", 1)[0].split("?", 1)[0])
                            matched = re.fullmatch(r"(netops-[a-z]+/v[0-9.]+|main|[0-9a-f]{7,40})/(.*)", rest)
                            assert matched, target
                            reference, repo_path = matched.groups()
                            assert (ROOT / repo_path).exists(), (document.relative_to(archive), target)
                            assert not repo_path.startswith("/") and ".." not in Path(repo_path).parts
                            has_tag = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--verify", "--quiet", reference],
                                                     capture_output=True).returncode == 0
                            if has_tag:
                                checked = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", reference + ":" + repo_path],
                                                         capture_output=True)
                                assert checked.returncode == 0, target
                            if url.fragment and repo_path.endswith(".md"):
                                body = subprocess.check_output(
                                    ["git", "-C", str(ROOT), "show", reference + ":" + repo_path],
                                    text=True,
                                ) if has_tag else (ROOT / repo_path).read_text()
                                _assert_markdown_fragment(body, url.fragment, (document.relative_to(archive), target))
                            outside_links += 1
                            continue
                        if not url.path and not url.scheme and not url.netloc:
                            _assert_markdown_fragment(document.read_text(), url.fragment, document.relative_to(archive))
                            continue
                        if url.scheme or url.netloc:
                            continue
                        resolved = (document.parent / unquote(url.path)).resolve()
                        assert resolved.is_relative_to(archive), (document.relative_to(archive), target)
                        assert resolved.exists(), (document.relative_to(archive), target)
                        if url.fragment and resolved.suffix == ".md":
                            _assert_markdown_fragment(resolved.read_text(), url.fragment, (document.relative_to(archive), target))
            if component.name != "netops-core":
                assert outside_links > 0, component.name
            original = component / "CHANGELOG.md"
            if "../../docs/" in original.read_text():
                expected = "/blob/" + metadata["name"] + "/v" + metadata["version"] + "/docs/"
                assert expected in (archive / "CHANGELOG.md").read_text()


def test_documentation_export_rewrites_code_labels_and_preserves_code_examples() -> None:
    import runpy
    import tomllib
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "example.md"
        content = (
            "[`Core SSH`](../../netops-core/docs/ssh.md?view=plain#host-pinning)\n"
            "`[example](../../missing.md)`\n"
            "``[example](../../missing.md)``\n"
            "~~~text\n[example](../../missing.md)\n~~~\n"
            "[local](configuration.md)\n"
            "[Read `Core` SSH](../../netops-core/docs/ssh.md?view=plain#host-pinning)\n"
            "[`Core` and `SSH`](../../netops-core/docs/ssh.md?view=plain#host-pinning)\n"
        )
        source.write_text(content)
        for component in sorted((ROOT / "components").iterdir()):
            script = component / "scripts/create_release_artifacts.py"
            if not script.is_file():
                continue
            namespace = runpy.run_path(str(script))
            result = namespace["_export_documentation_bytes"](source, Path("docs/example.md")).decode()
            metadata = tomllib.loads((component / "pyproject.toml").read_text())["project"]
            if component.name == "netops-core":
                assert result == content
            else:
                expected = metadata["urls"]["Homepage"].rstrip("/") + "/blob/" + metadata["name"] + "/v" + metadata["version"] + "/components/netops-core/docs/ssh.md?view=plain#host-pinning"
                assert result == content.replace("../../netops-core/docs/ssh.md?view=plain#host-pinning", expected)


def test_documented_installation_build_copies_exclude_stale_files() -> None:
    import shlex
    import os

    checked = 0
    for guide in sorted((ROOT / "components").glob("*/docs/installation.md")):
        fence = chr(96) * 3
        for block in re.findall(fence + r"(?:sh|bash)\n(.*?)\n\s*" + fence, guide.read_text(), re.DOTALL):
            lines = [line.strip() for line in block.splitlines()]
            copies = [i for i, line in enumerate(lines) if line.startswith("cp -r ")]
            if not copies:
                continue
            assert len(copies) == 1, guide
            end = copies[0]
            starts = [i for i, line in enumerate(lines[:end]) if line.startswith(("mkdir ", "build_dir="))]
            assert starts, guide
            preparation = "\n".join(lines[starts[0]:end + 1])
            install = lines[end + 1]
            install = re.sub(r'(\(umask 022; )(.+?)( -m pip install )', r'\1"$INSTALL_PROBE"\3', install, count=1)
            assert "$INSTALL_PROBE" in install, guide
            sources = shlex.split(lines[end].split("||", 1)[0])[2:-1]
            assert sources and all(re.fullmatch(r"netops-(?:core|auditor|admin|helper)-[0-9]+\.[0-9]+\.[0-9]+", source) for source in sources), guide
            assert preparation == (
                'build_dir=$(mktemp -d ./netops-build.XXXXXXXXXX) || exit 1\n'
                + 'cp -r ' + ' '.join(sources) + ' "$build_dir/" || exit 1'
            ), (guide, "unknown preparation command")
            options = "--no-index --no-deps --no-build-isolation" if "--no-index" in lines[end + 1] else "--no-deps"
            expected_install = '(umask 022; "$INSTALL_PROBE" -m pip install ' + options + ' ' + ' '.join('"$build_dir/' + source + '"' for source in sources) + ') || exit 1'
            assert install == expected_install, (guide, "unknown installation command")
            cleanup_lines = lines[end + 2:]
            allowed_cleanup = ['rm -rf -- "$build_dir" || exit 1']
            launcher_check = '"$HOME/.local/share/netops-helper/venv/bin/python" -c \'from os import access,stat,X_OK; from stat import S_ISREG; from sys import argv,exit; valid=all(S_ISREG(stat(p).st_mode) and access(p,X_OK) and not stat(p).st_mode & 0o022 for p in argv[1:]); exit(0 if valid else "Unsafe launcher permissions")\' "$HOME/.local/share/netops-helper/venv/bin/netops-askpass" "$HOME/.local/share/netops-helper/venv/bin/netops-helper-proxy" || exit 1'
            if guide.parent.parent.name == "netops-helper" and options == "--no-deps":
                allowed_cleanup.append(launcher_check)
            assert cleanup_lines == allowed_cleanup, (guide, "unknown cleanup command")
            cleanup = "\n".join(cleanup_lines)
            cleanup = cleanup.replace(
                '"$HOME/.local/share/netops-helper/venv/bin/python" -c ', '"$INSTALL_PROBE" -c ',
            )
            with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
                sandbox = Path(directory)
                root = sandbox / "work"
                root.mkdir()
                home = sandbox / "home"
                home.mkdir()
                temporary = sandbox / "tmp"
                temporary.mkdir()
                canary = home / ".local/share/netops-core/canary"
                canary.parent.mkdir(parents=True)
                canary.write_text("PRIVATE_TEST_HOME = True\n")
                outside = Path(outside_directory) / "protected-file"
                outside.write_text("OUTSIDE_WORK = True\n")
                for source in sources:
                    verified = root / source / "src"
                    verified.mkdir(parents=True)
                    (verified / "verified.py").write_text("VERIFIED = True\n")
                    for legacy in ("build", "build-proxy"):
                        stale = root / legacy / source / "src"
                        stale.mkdir(parents=True)
                        (stale / "zz_stale.py").write_text("STALE = True\n")
                        built = stale.parent / "build/lib"
                        built.mkdir(parents=True)
                        (built / "zz_stale_build.py").write_text("STALE = True\n")
                foreign = root / "netops-build.keep"
                foreign.mkdir()
                (foreign / "operator-file").write_text("KEEP = True\n")
                protected = {path: path.read_bytes() for path in sandbox.rglob("*") if path.is_file()}
                protected[outside] = outside.read_bytes()
                probe = root / "install-probe"
                probe.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$NETOPS_INSTALL_ARGUMENTS"\n')
                probe.chmod(0o700)
                arguments = root / "install-arguments"
                environment = {
                    "PATH": os.defpath, "LC_ALL": "C", "HOME": str(home), "TMPDIR": str(temporary),
                    "INSTALL_PROBE": str(probe), "NETOPS_INSTALL_ARGUMENTS": str(arguments),
                    "NETOPS_TEST_OUTSIDE": str(outside),
                }
                paths = []
                for _ in range(2):
                    result = subprocess.run(
                        ["sh", "-c", preparation + "\n" + install + '\nprintf "%s\\n" "${build_dir-}"'],
                        cwd=root, text=True, capture_output=True, env=environment,
                    )
                    assert result.returncode == 0, (guide, result.stderr)
                    path = result.stdout.strip()
                    assert path, (guide, "installation reuses an unverified build directory")
                    build = (root / path).resolve()
                    assert build.is_relative_to(root) and build != root
                    assert build not in paths, (guide, "installation reused a prior build")
                    paths.append(build)
                    argv = arguments.read_text().splitlines()
                    assert argv[:3] == ["-m", "pip", "install"], argv
                    installed_sources = [(root / value).resolve() for value in argv[3:] if not value.startswith("-")]
                    assert installed_sources == [build / source for source in sources], (guide, installed_sources, build)
                    for source in sources:
                        copied = build / source
                        assert sorted(str(f.relative_to(copied)) for f in copied.rglob("*") if f.is_file()) == ["src/verified.py"], guide
                        assert (copied / "src/verified.py").read_text() == "VERIFIED = True\n"
                        assert (root / source / "src/verified.py").read_text() == "VERIFIED = True\n"
                        for legacy in ("build", "build-proxy"):
                            assert (root / legacy / source / "src/zz_stale.py").is_file()
                    cleaned = subprocess.run(
                        ["sh", "-c", cleanup], cwd=root, text=True, capture_output=True,
                        env=dict(environment, build_dir=path),
                    )
                    assert cleaned.returncode == 0, (guide, cleaned.stderr)
                    assert not build.exists(), (guide, "successful build copy was not removed")
                    for protected_path, content in protected.items():
                        assert protected_path.is_file(), (guide, "cleanup removed a protected file", protected_path)
                        assert protected_path.read_bytes() == content, (guide, "cleanup changed a protected file", protected_path)
            checked += 1
    assert checked == 5, checked


def test_documented_offline_installation_python_guard() -> None:
    import shlex
    import sys

    guide = ROOT / "components/netops-helper/docs/installation.md"
    marker = "<!-- install-check: skip offline variant; needs build tools carried over from a connected host -->"
    fence = chr(96) * 3
    block = re.search(fence + r"sh\n(.*?)\n" + fence, guide.read_text().split(marker, 1)[1], re.DOTALL)
    assert block, guide
    tokens = shlex.split(block.group(1).splitlines()[0].strip())
    assert tokens[:2] == ["python3", "-c"], "offline installation must check Python before creating its environment"
    assert tokens[3:] == ["||", "exit", "1"], tokens
    for version, accepted in [((3, 12, 15), False), ((3, 13, 0), True), ((3, 14, 4), True)]:
        program = "import sys; sys.version_info = " + repr(version) + "; exec(sys.argv[1])"
        result = subprocess.run([sys.executable, "-c", program, tokens[2]], text=True, capture_output=True)
        assert (result.returncode == 0) == accepted, (version, result.stderr)
        if not accepted:
            assert "Python 3.13 or newer is required" in result.stderr


def _load_except_coverage():
    path = ROOT / "scripts/except_branch_coverage.py"
    specification = importlib.util.spec_from_file_location("_netops_except_coverage", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _except_coverage_tools() -> str | None:
    for name in ("coverage", "pytest"):
        if importlib.util.find_spec(name) is None:
            return name
    return None


def test_except_branch_coverage_baseline_follows_the_source() -> None:
    gate = _load_except_coverage()
    baseline = json.loads(gate.BASELINE.read_text(encoding="utf-8"))
    assert sorted(baseline["components"]) == sorted(gate.MODULES)
    for component, modules in gate.MODULES.items():
        recorded = baseline["components"][component]
        assert sorted(recorded["modules"]) == sorted(modules), component
        for module in modules:
            source = (ROOT / "components" / component / "src" / module).read_text(encoding="utf-8")
            found = len(gate.branches_of(source))
            assert recorded["modules"][module]["branches_in_source"] == found, (
                "%s/%s has %d except/else branches; measure them and record the floor with "
                "scripts/except_branch_coverage.py --write-baseline" % (component, module, found)
            )


def test_except_branch_coverage_gate_refuses_a_lower_coverage() -> None:
    missing = _except_coverage_tools()
    if missing is not None:
        print("except_branch_coverage=skipped: %s is not installed" % missing)
        return
    gate = _load_except_coverage()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        component = root / "components/demo"
        (component / "src/demo_pkg").mkdir(parents=True)
        (component / "tests").mkdir()
        (component / "src/demo_pkg/__init__.py").write_text("", encoding="utf-8")
        (component / "src/demo_pkg/state.py").write_text(
            "def load(text):\n"
            "    try:\n"
            "        value = int(text)\n"
            "    except ValueError:\n"
            "        return None\n"
            "    except TypeError:\n"
            "        return -1\n"
            "    else:\n"
            "        return value\n",
            encoding="utf-8",
        )
        (component / "tests/test_state.py").write_text(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))\n"
            "from demo_pkg.state import load\n"
            "def test_load():\n"
            "    assert load('1') == 1\n"
            "    assert load('x') is None\n",
            encoding="utf-8",
        )
        baseline = root / "baseline.json"
        gate.ROOT = root
        gate.MODULES = {"demo": ("demo_pkg/state.py",)}
        assert gate.main(["demo", "--baseline", str(baseline), "--write-baseline"]) == 0
        recorded = json.loads(baseline.read_text(encoding="utf-8"))["components"]["demo"]
        assert (recorded["branches"], recorded["covered"], recorded["min_percent"]) == (3, 2, 66)
        assert gate.main(["demo", "--baseline", str(baseline)]) == 0
        assert gate.main(["demo", "--baseline", str(baseline), "--min", "67"]) == 1
        recorded["modules"]["demo_pkg/state.py"]["min_percent"] = 67
        baseline.write_text(json.dumps({"components": {"demo": recorded}}), encoding="utf-8")
        assert gate.main(["demo", "--baseline", str(baseline)]) == 1
        assert gate.main(["demo", "--baseline", str(baseline), "--report-only"]) == 0


def test_except_branch_coverage_of_the_components_keeps_its_floor() -> None:
    missing = _except_coverage_tools()
    if missing is not None:
        print("except_branch_coverage=skipped: %s is not installed" % missing)
        return
    if os.environ.get("NETOPS_EXCEPT_COVERAGE") != "1":
        print("except_branch_coverage=skipped: set NETOPS_EXCEPT_COVERAGE=1 to measure the four test suites")
        return
    assert _load_except_coverage().main([]) == 0


def main() -> int:
    for name, function in sorted(globals().items()):
        if name.startswith("test_") and callable(function):
            function()
    print("repository_gate_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


def test_diagnostic_multicast_exception_requires_rejection_fixture():
    gate = _load_gate()
    relative = "components/netops-helper/tests/test_fortios_diagnostics.py"
    source = (ROOT / relative).read_text(encoding="utf-8")
    assert not gate._address_errors(relative, source, False)
    assert gate._address_errors("tests/other.py", source, False)
    for before, after in (
        ("def test_invalid_request(kwargs):", "def test_accepted_request(kwargs):"),
        ("values.update(kwargs)", "pass"),
        ("values.update(kwargs)", "values.update(kwargs)\n    values.clear()"),
        ("pytest.raises(ValueError)", "pytest.raises(AssertionError)"),
        ("d.validate(**values)", "d.authorize(**values)"),
    ):
        assert before in source
        assert gate._address_errors(relative, source.replace(before, after, 1), False)
    address = str(ipaddress.IPv4Address(0xE0000001))
    assert gate._address_errors(relative, source + "\nOTHER = " + repr(address) + "\n", False)
    private_source = source.replace(address, RFC1918_TEST_ADDRESS)
    assert gate._address_errors(relative, private_source, False)
