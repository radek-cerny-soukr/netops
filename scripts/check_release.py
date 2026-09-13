#!/usr/bin/env python3
"""Fail closed when the monorepo tree leaves a tracked file outside every component release."""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
COMPONENTS_DIRECTORY = "components"
COMPONENT_SELECTOR = "scripts/create_release_artifacts.py"
COMPONENT_GATES = {
    "netops-helper": ("scripts/check_public_release.py",),
    "netops-auditor": ("scripts/check_gates.py",),
}
CI_REQUIRED_FRAGMENTS = (
    "scripts/check_release.py",
    "tests/test_release_gate.py",
    "NETOPS_REQUIRE_RUNTIME_TESTS=1 python -m pytest -q",
)
ROOT_FILES = {
    ".github/workflows/ci.yml",
    ".gitignore",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "docs/README.md",
    "scripts/check_release.py",
    "tests/test_release_gate.py",
}
DOMAIN_SUFFIXES = {".cfg", ".conf", ".env", ".ini", ".json", ".md", ".txt", ".yaml", ".yml"}
TEXT_SUFFIXES = {
    "", ".cfg", ".conf", ".env", ".in", ".ini", ".json", ".lock", ".md", ".py", ".sh",
    ".toml", ".txt", ".yaml", ".yml",
}
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
DOCUMENTATION_IPV6 = (ipaddress.ip_network("2001:db8::/32"),)
RESERVED_TLDS = frozenset(("example", "invalid", "test", "localhost"))
ALLOWED_DOMAINS = (
    "arista.com",
    "cisco.com",
    "cyclonedx.org",
    "debian.org",
    "docker.com",
    "example.com",
    "example.net",
    "example.org",
    "extremenetworks.com",
    "fortinet.com",
    "github.com",
    "juniper.net",
    "opencontainers.org",
    "pypi.org",
    "python.org",
    "readthedocs.io",
    "sigstore.dev",
)
ALLOWED_LITERALS = frozenset(
    (
        "33.7.1.6",
        "1.3.6.1",
        "aa:bb:cc:dd:ee:ff",
    )
)
DOCUMENTATION_MAC_PREFIX = "00:00:5e:00:53:"
IPV4_PATTERN = re.compile(r"(?<![0-9A-Za-z.])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![0-9A-Za-z]|\.[0-9])")
IPV6_PATTERN = re.compile(r"(?<![0-9A-Za-z:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Za-z:]|\.[0-9])")
DOMAIN_PATTERN = re.compile(
    r"(?<![0-9A-Za-z._-])"
    r"([0-9A-Za-z](?:[0-9A-Za-z-]*[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:[0-9A-Za-z-]*[0-9A-Za-z])?)+)"
    r"(?![0-9A-Za-z_-]|\.[0-9A-Za-z])"
)
FILE_SUFFIXES = frozenset(
    (
        "cfg", "conf", "gz", "html", "in", "ini", "json", "jsonl", "lock", "log", "md",
        "pem", "py", "pyc", "sh", "sig", "tar", "toml", "txt", "yaml", "yml",
    )
)
KNOWN_TLDS = frozenset(
    (
        "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "pro",
        "io", "dev", "app", "ai", "co", "cz", "sk", "de", "eu", "uk", "us", "ru",
        "local", "lan", "internal", "intranet", "arpa", "xyz", "me", "tv", "cc",
        "home", "host", "box", "corp",
        "cloud", "systems", "tools", "network", "email", "site", "online",
    )
)
PRIVATE_MARKERS = (
    re.compile(r"/workspace(?:/|$)", re.IGNORECASE),
    re.compile(r"/(?:work|out)(?:/|$)", re.IGNORECASE),
    re.compile(r"/home/[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?(?:/|$)", re.IGNORECASE),
    re.compile(r"/Users/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?(?:/|$)"),
    re.compile(r"[A-Za-z]:\\Users\\", re.IGNORECASE),
    re.compile(r"/root/\.[a-z]", re.IGNORECASE),
    re.compile(r"~[a-z][a-z0-9._-]{1,31}/", re.IGNORECASE),
    re.compile(r"\brpi(?:[-_ ]?\d+)?[-_]?[a-z]{3,}\b", re.IGNORECASE),
    re.compile(r"\braspberry(?:\s+|[-_]+)pi\b", re.IGNORECASE),
    re.compile(r"\b(?:home|local|personal|private)[-_ ]+lab\b", re.IGNORECASE),
    re.compile(r"\bcodex\b", re.IGNORECASE),
    re.compile(r"\bopenai\b", re.IGNORECASE),
    re.compile(r"\bchatgpt\b", re.IGNORECASE),
    re.compile(r"\bclaude\b", re.IGNORECASE),
    re.compile(r"\banthropic\b", re.IGNORECASE),
)
MAC_PATTERN = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Za-z:])")
PEM_MARKER = re.compile(r"BEGIN[ A-Z0-9]*PRIVATE KEY")
PEM_PAYLOAD = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
PEM_WINDOW = 200
CREDENTIAL_MARKERS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bssh-(?:ed25519|rsa|dss) AAAA[0-9A-Za-z+/]{40,}"),
)


def _live_yaml(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def component_names(root: Path) -> list[str]:
    directory = root / COMPONENTS_DIRECTORY
    if not directory.is_dir():
        return []
    return sorted(
        entry.name for entry in directory.iterdir()
        if entry.is_dir() and not entry.is_symlink()
    )


SELECTOR_PROGRAM = """
import importlib.util
import sys
from pathlib import Path

specification = importlib.util.spec_from_file_location("_netops_component_selector", sys.argv[1])
module = importlib.util.module_from_spec(specification)
specification.loader.exec_module(module)
selected_files = getattr(module, "selected_files", None)
if not callable(selected_files):
    raise SystemExit("release selector has no file selector")
paths = selected_files(Path(sys.argv[2]))
sys.stdout.write("\\0".join(str(Path(item).resolve()) for item in paths))
"""


def _selected_paths(selector: Path, component_root: Path) -> list[str]:
    completed = subprocess.run(
        [sys.executable, "-B", "-c", SELECTOR_PROGRAM, str(selector), str(component_root)],
        capture_output=True,
        check=False,
        timeout=300,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        raise RuntimeError(detail[-1] if detail else "release selector failed")
    return [item for item in completed.stdout.decode("utf-8", "replace").split("\0") if item]


def component_selection(root: Path, name: str) -> tuple[set[str], list[str]]:
    component_root = root / COMPONENTS_DIRECTORY / name
    selector_path = component_root / COMPONENT_SELECTOR
    if not selector_path.is_file():
        return set(), [f"component has no release selector: {name}/{COMPONENT_SELECTOR}"]
    try:
        selected = _selected_paths(selector_path, component_root)
    except Exception as exc:
        return set(), [f"component release selection is unavailable or invalid: {name}: {exc}"]
    errors: list[str] = []
    relative_files: set[str] = set()
    for path in selected:
        try:
            relative = Path(path).resolve().relative_to(component_root)
        except ValueError:
            errors.append(f"component release selection reaches outside its tree: {name}: {path}")
            continue
        relative_files.add(f"{COMPONENTS_DIRECTORY}/{name}/{relative.as_posix()}")
    return relative_files, errors


def tracked_files(root: Path) -> tuple[set[str], list[str]]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, check=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return set(), ["git working tree could not be enumerated"]
    return {
        item.decode("utf-8", "replace") for item in completed.stdout.split(b"\0") if item
    }, []


def _coverage_errors(root: Path, tracked: set[str], names: list[str]) -> list[str]:
    errors: list[str] = []
    owner: dict[str, str] = {}
    for name in names:
        selection, selection_errors = component_selection(root, name)
        errors.extend(selection_errors)
        for relative in sorted(selection):
            if relative in owner:
                errors.append(
                    f"file is claimed by two components: {relative} ({owner[relative]}, {name})"
                )
                continue
            owner[relative] = name
    for relative in sorted(tracked - set(owner) - ROOT_FILES):
        errors.append(f"tracked or unignored file outside every component release: {relative}")
    for relative in sorted(set(owner) - tracked):
        errors.append(f"component release selects a file that is not in the tree: {relative}")
    for relative in sorted(ROOT_FILES - tracked):
        errors.append(f"reviewed repository file is missing: {relative}")
    return errors


def _license_errors(root: Path, names: list[str]) -> list[str]:
    errors: list[str] = []
    try:
        expected = (root / "LICENSE").read_bytes()
    except OSError:
        return ["repository LICENSE is unavailable"]
    for name in names:
        path = root / COMPONENTS_DIRECTORY / name / "LICENSE"
        try:
            actual = path.read_bytes()
        except OSError:
            errors.append(f"component carries no LICENSE copy: {name}")
            continue
        if actual != expected:
            errors.append(f"component LICENSE differs from the repository LICENSE: {name}")
    return errors


def _workflow_errors(root: Path, names: list[str]) -> list[str]:
    errors: list[str] = []
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    if not workflows:
        return ["repository carries no CI workflow"]
    for workflow in workflows:
        try:
            text = workflow.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append(f"CI workflow is unreadable: {workflow.name}")
            continue
        for value in re.findall(r"(?:^|[\s{,])uses:\s*([^\s,}]+)", _live_yaml(text)):
            if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", value):
                errors.append(f"GitHub Action is not SHA-pinned in {workflow.name}: {value}")
    try:
        ci_workflow = _live_yaml(
            (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError):
        return errors + ["CI workflow ci.yml is unavailable"]
    for name in names:
        if f"{COMPONENTS_DIRECTORY}/{name}" not in ci_workflow:
            errors.append(f"CI does not run the checks of a component: {name}")
        for relative in COMPONENT_GATES.get(name, ()):
            if relative not in ci_workflow:
                errors.append(f"CI does not run a component gate: {name}/{relative}")
    for fragment in CI_REQUIRED_FRAGMENTS:
        if fragment not in ci_workflow:
            errors.append(f"CI does not run a required step: {fragment}")
    return errors


def _gate_errors(root: Path, names: list[str]) -> list[str]:
    errors: list[str] = []
    for name in sorted(set(COMPONENT_GATES) - set(names)):
        errors.append(f"gate is registered for a component that does not exist: {name}")
    for name in names:
        gates = COMPONENT_GATES.get(name)
        if not gates:
            errors.append(f"component has no registered gate: {name}")
            continue
        component_root = root / COMPONENTS_DIRECTORY / name
        for relative in gates:
            path = component_root / relative
            if not path.is_file():
                errors.append(f"registered component gate is missing: {name}/{relative}")
                continue
            completed = subprocess.run(
                [sys.executable, "-B", str(path)],
                cwd=str(component_root),
                capture_output=True,
                check=False,
                timeout=900,
            )
            for line in completed.stdout.decode("utf-8", "replace").splitlines():
                print(f"{name}: {line}")
            if completed.returncode:
                errors.append(f"component gate failed: {name}/{relative}")
    return errors


def _pem_material_errors(relative: str, text: str) -> list[str]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if PEM_MARKER.search(line) is None:
            continue
        for candidate in lines[index + 1:index + 1 + PEM_WINDOW]:
            if PEM_PAYLOAD.search(candidate) is not None:
                return [f"private key material in {relative}"]
    return []


def _documented_ipv4(candidate: str) -> bool | None:
    try:
        address = ipaddress.IPv4Address(candidate)
    except ValueError:
        return None
    if any(address in network for network in DOCUMENTATION_NETWORKS):
        return True
    if address.is_loopback or address.is_unspecified:
        return True
    value = int(address)
    inverted = (~value) & 0xFFFFFFFF
    return (inverted & (inverted + 1)) == 0 or (value & (value + 1)) == 0


IPV6_IDENTIFYING_GROUPS = 3


def _documented_ipv6(candidate: str) -> bool | None:
    try:
        address = ipaddress.IPv6Address(candidate)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return True
    if any(address in network for network in DOCUMENTATION_IPV6):
        return True
    groups = [
        (int(address) >> shift) & 0xFFFF for shift in range(112, -1, -16)
    ]
    return sum(1 for group in groups if group) < IPV6_IDENTIFYING_GROUPS


def _documented_domain(candidate: str) -> bool:
    lowered = candidate.lower()
    labels = lowered.split(".")
    if len(labels) < 2:
        return True
    top = labels[-1]
    if not top.isascii() or not top.isalpha():
        return True
    if top in RESERVED_TLDS:
        return True
    if top in FILE_SUFFIXES or top not in KNOWN_TLDS:
        return True
    return any(
        lowered == allowed or lowered.endswith("." + allowed) for allowed in ALLOWED_DOMAINS
    )


def _address_errors(relative: str, text: str, domains: bool) -> list[str]:
    errors: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for match in IPV4_PATTERN.finditer(line):
            if match.group(1) in ALLOWED_LITERALS:
                continue
            if _documented_ipv4(match.group(1)) is False:
                errors.append(
                    f"{relative}:{number} holds an address outside the RFC 5737"
                    f" documentation ranges: {match.group(1)}"
                )
        for match in IPV6_PATTERN.finditer(line):
            if _documented_ipv6(match.group(1)) is False:
                errors.append(
                    f"{relative}:{number} holds an IPv6 address outside 2001:db8::/32:"
                    f" {match.group(1)}"
                )
        for match in MAC_PATTERN.finditer(line):
            value = match.group(0).lower()
            if value in ALLOWED_LITERALS or value.startswith(DOCUMENTATION_MAC_PREFIX):
                continue
            errors.append(
                f"{relative}:{number} holds a MAC address: {match.group(0)}"
            )
        for match in DOMAIN_PATTERN.finditer(line) if domains else ():
            if not _documented_domain(match.group(1)):
                errors.append(
                    f"{relative}:{number} holds a domain outside the allowed"
                    f" documentation domains: {match.group(1)}"
                )
    return errors


def _privacy_errors(root: Path, tracked: set[str]) -> list[str]:
    errors: list[str] = []
    for relative in sorted(tracked):
        path = root / relative
        if path.is_symlink():
            errors.append(f"tracked entry is a symbolic link: {relative}")
            continue
        if not path.is_file():
            errors.append(f"tracked entry is not a regular file: {relative}")
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            errors.append(f"tracked file could not be read: {relative}")
            continue
        if b"\x00" in raw:
            errors.append(f"tracked text file holds a NUL byte: {relative}")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"tracked text file is not valid UTF-8: {relative}")
            continue
        if any(marker.search(relative) for marker in PRIVATE_MARKERS):
            errors.append(f"private marker in tracked path: {relative}")
        if any(marker.search(text) for marker in PRIVATE_MARKERS):
            errors.append(f"private marker in {relative}")
        if any(marker.search(text) for marker in CREDENTIAL_MARKERS):
            errors.append(f"credential-shaped material in {relative}")
        errors.extend(_pem_material_errors(relative, text))
        errors.extend(
            _address_errors(relative, text, path.suffix.lower() in DOMAIN_SUFFIXES)
        )
    return errors


def check(root: Path = ROOT) -> list[str]:
    names = component_names(root)
    if not names:
        return ["repository holds no component"]
    tracked, errors = tracked_files(root)
    if errors:
        return errors
    errors.extend(_coverage_errors(root, tracked, names))
    errors.extend(_license_errors(root, names))
    errors.extend(_workflow_errors(root, names))
    errors.extend(_privacy_errors(root, tracked))
    errors.extend(_gate_errors(root, names))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    arguments = parser.parse_args()
    errors = check(arguments.root.resolve())
    if errors:
        for error in errors:
            print(f"release_check=failed detail={error}")
        return 1
    print("release_check=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
