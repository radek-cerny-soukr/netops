#!/usr/bin/env python3
"""Fail closed when netops-admin gains an unreviewed way to reach a device, loses its version pin, or ships an invalid profile."""

from __future__ import annotations

import argparse
import ast
import ipaddress
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "netops_admin"
PLANNING_MODULES = frozenset((
    "__future__", "argparse", "dataclasses", "hashlib", "ipaddress", "json", "pathlib", "re", "sys",
))
PLANNING_FROM = {"netops_auditor": frozenset(("l1_fortios", "l1_exos")), "importlib": frozenset(("resources",))}
EXECUTION_MODULES = PLANNING_MODULES | frozenset(("datetime", "fcntl", "os", "secrets", "time"))
FILE_RULES = {
    "access.py": (
        EXECUTION_MODULES,
        {
            "netops_core": frozenset(("hostkey", "prompt", "session", "ssh", "vault")),
            "netops_auditor": frozenset(("collect",)),
        },
    ),
    "notify.py": (EXECUTION_MODULES | frozenset(("ssl", "urllib.error", "urllib.request")), {}),
    "execute.py": (EXECUTION_MODULES, {}),
    "enrollment.py": (EXECUTION_MODULES, {}),
    "exec_fortios.py": (EXECUTION_MODULES, {}),
    "exec_exos.py": (EXECUTION_MODULES, {}),
    "membership.py": (PLANNING_MODULES, {"netops_auditor.management": frozenset(("exos_model", "ports"))}),
    "audit_gate.py": (PLANNING_MODULES, {"netops_auditor": frozenset(("checks_exos", "checks_fortios", "management")),
                                         "netops_auditor.engine": frozenset(("load_catalog", "run"))}),
    "mcp_server.py": (EXECUTION_MODULES | frozenset(("threading", "typing")), {"fastmcp": frozenset(("FastMCP",))}),
    "state.py": (EXECUTION_MODULES, {}),
    "audit.py": (EXECUTION_MODULES | {"math"}, {}),
    "config.py": (EXECUTION_MODULES, {"netops_auditor.management": frozenset(("load_policy",))}),
    "cli.py": (EXECUTION_MODULES, {}),
}
FORBIDDEN_NAMES = frozenset(("eval", "exec", "compile", "__import__", "breakpoint"))
FORBIDDEN_ATTRIBUTES = frozenset(("system", "popen", "spawnv", "spawnve", "execv", "execve", "fork"))
DEPENDENCIES = ["netops-auditor==0.2.7", "netops-core==0.2.4"]
COMPONENT = "netops-admin"
PLATFORMS = frozenset(("fortios", "exos"))
RELEASE_SELECTOR = ("scripts", "create_release_artifacts.py")
RELEASE_MANIFEST = "release-manifest.json"
RELEASE_METADATA = frozenset((RELEASE_MANIFEST, "SHA256SUMS"))


DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
DOCUMENTATION_IPV6 = (ipaddress.ip_network("2001:db8::/32"),)
IPV6_IDENTIFYING_GROUPS = 3
ALLOWED_DOMAINS = ("example.invalid", "example.com", "example.net", "example.org")
RELEASE_ALLOWED_DOMAINS = ALLOWED_DOMAINS + (
    "arista.com",
    "cisco.com",
    "cyclonedx.org",
    "debian.org",
    "docker.com",
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
RESERVED_TLDS = frozenset(("example", "invalid", "test", "localhost"))
ALLOWED_LITERALS = frozenset(("33.7.1.6", "1.3.6.1", "aa:bb:cc:dd:ee:ff"))
DOCUMENTATION_MAC_PREFIX = "00:00:5e:00:53:"

IPV4_PATTERN = re.compile(
    r"(?<![0-9A-Za-z.])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![0-9A-Za-z]|\.[0-9])"
)
IPV6_PATTERN = re.compile(
    r"(?<![0-9A-Za-z:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Za-z:]|\.[0-9])"
)
MAC_PATTERN = re.compile(
    r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Za-z:])"
)
DOMAIN_PATTERN = re.compile(
    r"(?<![0-9A-Za-z._-])"
    r"([0-9A-Za-z](?:[0-9A-Za-z-]*[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:[0-9A-Za-z-]*[0-9A-Za-z])?)+)"
    r"(?![0-9A-Za-z_-]|\.[0-9A-Za-z])"
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
CREDENTIAL_MARKERS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bssh-(?:ed25519|rsa|dss) AAAA[0-9A-Za-z+/]{40,}"),
)
RELEASE_TEXT_SUFFIXES = frozenset(
    (
        "", ".cfg", ".conf", ".env", ".in", ".ini", ".json", ".lock", ".md", ".py",
        ".sh", ".toml", ".txt", ".yaml", ".yml",
    )
)
RELEASE_DOMAIN_SUFFIXES = frozenset(
    (".cfg", ".conf", ".env", ".ini", ".json", ".md", ".txt", ".yaml", ".yml")
)
PEM_MARKER_PATTERN = re.compile(r"BEGIN[ A-Z0-9]*PRIVATE KEY")
PEM_END_PATTERN = re.compile(r"END[ A-Z0-9]*PRIVATE KEY")
PEM_PAYLOAD_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
PEM_WINDOW = 200

KNOWN_TLDS = frozenset(
    (
        "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "pro",
        "mobi", "asia", "tel", "travel", "jobs", "coop", "aero", "museum", "cat",
        "io", "ai", "dev", "app", "cloud", "online", "site", "store", "shop", "tech",
        "systems", "network", "email", "digital", "solutions", "services", "software",
        "agency", "company", "group", "center", "expert", "works", "team", "zone",
        "link", "click", "space", "website", "host", "domains", "media", "news",
        "xyz", "top", "live", "life", "world", "today", "blog", "wiki", "page",
        "eu", "cz", "sk", "de", "at", "pl", "hu", "si", "hr", "ro", "bg", "ua",
        "uk", "ie", "fr", "it", "es", "pt", "nl", "be", "lu", "ch", "li",
        "se", "no", "dk", "fi", "is", "ee", "lv", "lt", "ru", "by", "kz",
        "us", "ca", "mx", "br", "ar", "cl", "co", "pe",
        "au", "nz", "jp", "cn", "hk", "tw", "kr", "sg", "my", "th", "vn", "id", "in",
        "il", "tr", "ae", "sa", "za", "eg", "ng", "ke",
        "tv", "me", "cc", "ws", "fm", "gg", "je", "im", "sh", "st", "to", "nu",
        "local", "lan", "intranet", "internal", "home", "corp", "arpa", "onion",
    )
)
FILE_SUFFIXES = frozenset(
    (
        "conf", "config", "cfg", "ini", "toml", "yaml", "yml", "json", "jsonl", "xml",
        "py", "pyc", "pyi", "sh", "bash", "ps1", "bat", "js", "ts", "css", "html", "htm",
        "md", "rst", "txt", "log", "csv", "tsv", "sql", "db", "sqlite", "lock", "sum",
        "tar", "gz", "bz2", "xz", "zip", "tgz", "bak", "tmp", "swp", "out", "err",
        "pem", "crt", "cer", "der", "key", "pub", "csr", "sig", "asc",
        "png", "jpg", "jpeg", "gif", "svg", "pdf", "bin", "img", "iso", "diff", "patch",
        "orig", "rej", "in", "env", "example", "sample", "tmpl", "tpl", "j2", "lst",
    )
)

VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+(?:[.+-][0-9A-Za-z.+-]+)?$")
REQUIREMENT_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9,._-]+\])?==[0-9A-Za-z][0-9A-Za-z.*+!-]*$"
)


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _ipv4_verdict(candidate: str):
    try:
        address = ipaddress.IPv4Address(candidate)
    except ValueError:
        return None
    for network in DOCUMENTATION_NETWORKS:
        if address in network:
            return True
    value = int(address)
    inverted = (~value) & 0xFFFFFFFF
    if (inverted & (inverted + 1)) == 0:
        return True
    if (value & (value + 1)) == 0:
        return True
    return False


def _suspect_domain(candidate: str, allowed_domains=ALLOWED_DOMAINS) -> bool:
    lowered = candidate.lower()
    labels = lowered.split(".")
    if len(labels) < 2:
        return False
    top = labels[-1]
    if not top.isascii() or not top.isalpha():
        return False
    if top in RESERVED_TLDS:
        return False
    if top in FILE_SUFFIXES:
        return False
    if top not in KNOWN_TLDS and not 2 <= len(top) <= 6:
        return False
    for allowed in allowed_domains:
        if lowered == allowed or lowered.endswith("." + allowed):
            return False
    return True


def _pem_material(lines, index: int) -> bool:
    for offset in range(index, min(len(lines), index + PEM_WINDOW)):
        if PEM_PAYLOAD_PATTERN.search(lines[offset]):
            return True
        if offset > index and PEM_END_PATTERN.search(lines[offset]):
            return False
    return False


def _own(module: str) -> bool:
    return module == PACKAGE or module.startswith(PACKAGE + ".")


def _rules(name: str):
    modules, extra = FILE_RULES.get(name, (PLANNING_MODULES, {}))
    allowed_from = {key: set(value) for key, value in PLANNING_FROM.items()}
    for key, value in extra.items():
        allowed_from.setdefault(key, set()).update(value)
    return modules, allowed_from


def import_errors(root: Path = ROOT) -> list:
    errors = []
    for path in sorted((root / "src" / PACKAGE).rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        modules, allowed_from = _rules(path.name)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name not in modules and not _own(alias.name):
                        errors.append("%s:%d imports %s" % (relative, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level or _own(module) or module in modules:
                    continue
                allowed = allowed_from.get(module, set())
                for alias in node.names:
                    if alias.name not in allowed:
                        errors.append("%s:%d imports %s from %s" % (relative, node.lineno, alias.name, module))
            elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
                errors.append("%s:%d uses %s" % (relative, node.lineno, node.id))
            elif isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRIBUTES:
                errors.append("%s:%d calls %s" % (relative, node.lineno, node.attr))
    return errors


def metadata_errors(root: Path = ROOT) -> list:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    errors = []
    if project.get("name") != "netops-admin":
        errors.append("pyproject names another project")
    tree = ast.parse((root / "src" / PACKAGE / "__init__.py").read_text(encoding="utf-8"))
    versions = [
        ast.literal_eval(node.value) for node in tree.body
        if isinstance(node, ast.Assign) and any(getattr(target, "id", None) == "__version__" for target in node.targets)
    ]
    if versions != [project.get("version")]:
        errors.append("package __version__ differs from pyproject version")
    if project.get("dependencies") != DEPENDENCIES:
        errors.append("dependencies must be exactly %r" % DEPENDENCIES)
    return errors


def profile_errors(root: Path = ROOT) -> list:
    sys.path.insert(0, str(root / "src"))
    try:
        from netops_admin import profiles
        loaded = profiles.load_profiles()
    except Exception as exc:
        return ["profiles do not load: %s" % exc]
    errors = []
    if not loaded:
        errors.append("no profile is shipped")
    for platform, table in loaded:
        if platform not in PLATFORMS:
            errors.append("profile %s %s has no adapter" % (platform, table))
    return errors


def _project_metadata(root: Path, errors: list):
    path = root / "pyproject.toml"
    relative = _relative(root, path)
    if not path.is_file():
        errors.append("%s is missing" % relative)
        return None
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        project = document["project"]
        name = project["name"]
        version = project["version"]
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        errors.append("%s holds no usable project metadata: %s" % (relative, error))
        return None
    if name != COMPONENT:
        errors.append("%s declares a foreign component name: %r" % (relative, name))
    if not isinstance(version, str) or not VERSION_PATTERN.match(version):
        errors.append("%s declares an unusable version: %r" % (relative, version))
        return None
    return version


def gate_version_metadata(root: Path) -> list:
    errors = []
    project_version = _project_metadata(root, errors)
    path = root / "src" / PACKAGE / "__init__.py"
    relative = _relative(root, path)
    if not path.is_file():
        errors.append("%s is missing" % relative)
    else:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError) as error:
            errors.append("%s is unreadable or not valid Python: %s" % (relative, error))
        else:
            version = None
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, ast.AnnAssign):
                    targets = [node.target]
                else:
                    continue
                if not any(
                    isinstance(target, ast.Name) and target.id == "__version__"
                    for target in targets
                ):
                    continue
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    version = node.value.value
            if version is None:
                errors.append("%s declares no __version__ string" % relative)
            elif not VERSION_PATTERN.match(version):
                errors.append("%s declares an unusable __version__: %r" % (relative, version))
            elif project_version is not None and version != project_version:
                errors.append(
                    "%s declares %r while pyproject.toml declares %r"
                    % (relative, version, project_version)
                )

    document = root / "sbom.cdx.json"
    relative = _relative(root, document)
    if not document.is_file():
        errors.append("%s is missing" % relative)
    else:
        try:
            component = json.loads(document.read_text(encoding="utf-8"))["metadata"]["component"]
        except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
            errors.append("%s does not carry a root component: %s" % (relative, error))
        else:
            named = component.get("version")
            if project_version is not None and named != project_version:
                errors.append(
                    "%s names version %r while pyproject.toml declares %r;"
                    " regenerate it with scripts/generate_sbom.py"
                    % (relative, named, project_version)
                )

    requirements = root / "requirements-mcp.txt"
    relative = _relative(root, requirements)
    if not requirements.is_file():
        errors.append("%s is missing" % relative)
        return errors
    try:
        text = requirements.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        errors.append("%s is unreadable: %s" % (relative, error))
        return errors
    pinned = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if not REQUIREMENT_PATTERN.match(line):
            errors.append(
                "%s:%d does not pin an exact version with ==: %s" % (relative, number, line)
            )
            continue
        pinned += 1
    if not pinned:
        errors.append("%s pins no requirement" % relative)
    return errors


SELECTOR_PROGRAM = """
import importlib.util
import sys
from pathlib import Path

specification = importlib.util.spec_from_file_location("_netops_release_selector", sys.argv[1])
module = importlib.util.module_from_spec(specification)
specification.loader.exec_module(module)
selected_files = getattr(module, "selected_files", None)
if not callable(selected_files):
    raise SystemExit("release selector has no file selector")
paths = selected_files(Path(sys.argv[2]))
sys.stdout.write("\\0".join(str(Path(item).resolve()) for item in paths))
"""


def _release_files(root: Path) -> list:
    selector = root.joinpath(*RELEASE_SELECTOR)
    if not selector.is_file() or selector.is_symlink():
        raise RuntimeError("release selector is missing: %s" % "/".join(RELEASE_SELECTOR))
    completed = subprocess.run(
        [sys.executable, "-B", "-c", SELECTOR_PROGRAM, str(selector), str(root)],
        capture_output=True,
        check=False,
        timeout=300,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        raise RuntimeError(detail[-1] if detail else "release selector failed")
    chosen = []
    for item in completed.stdout.decode("utf-8", "replace").split("\0"):
        if not item:
            continue
        path = Path(item)
        try:
            path.relative_to(root)
        except ValueError:
            raise RuntimeError("release selection reaches outside the component: %s" % item)
        chosen.append(path)
    return chosen


def _repository(root: Path) -> bool:
    for candidate in (root, *root.parents):
        if (candidate / ".git").exists():
            return True
    return False


def _tree_files(root: Path) -> tuple:
    files, errors, walk_errors = set(), [], []
    for directory, directory_names, file_names in os.walk(
        root, topdown=True, onerror=walk_errors.append, followlinks=False
    ):
        base = Path(directory)
        for name in sorted(directory_names):
            child = base / name
            if child.is_symlink():
                errors.append(
                    "released tree holds a symlink: %s" % _relative(root, child)
                )
        for name in sorted(file_names):
            path = base / name
            relative = _relative(root, path)
            if path.is_symlink():
                errors.append("released tree holds a symlink: %s" % relative)
            elif not path.is_file():
                errors.append(
                    "released tree holds an entry that is not a regular file: %s" % relative
                )
            else:
                files.add(relative)
    if walk_errors:
        errors.append("released tree could not be traversed")
    return files, errors


def _manifest_files(root: Path) -> tuple:
    path = root / RELEASE_MANIFEST
    if path.is_symlink():
        return None, ["%s must not be a symlink" % RELEASE_MANIFEST]
    if not path.is_file():
        return None, []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        return None, ["%s is unreadable or not valid JSON: %s" % (RELEASE_MANIFEST, error)]
    entries = document.get("files") if isinstance(document, dict) else None
    if not isinstance(entries, dict) or not entries:
        return None, ["%s holds no file list" % RELEASE_MANIFEST]
    return set(entries), []


def _completeness_errors(root: Path, selected: set) -> list:
    present, errors = _tree_files(root)
    if errors:
        return errors
    content = present - RELEASE_METADATA
    for relative in sorted(content - selected):
        errors.append("released tree holds a file outside the release selection: %s" % relative)
    for relative in sorted(selected - content):
        errors.append("release selection names a file the released tree lacks: %s" % relative)
    manifest, manifest_errors = _manifest_files(root)
    errors.extend(manifest_errors)
    if manifest is None:
        return errors
    for relative in sorted(manifest - content):
        errors.append("%s names a file the released tree lacks: %s" % (RELEASE_MANIFEST, relative))
    for relative in sorted(content - manifest):
        errors.append("released tree holds a file outside %s: %s" % (RELEASE_MANIFEST, relative))
    return errors


def _documented_ipv6(candidate: str):
    try:
        address = ipaddress.IPv6Address(candidate)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return True
    for network in DOCUMENTATION_IPV6:
        if address in network:
            return True
    if address.is_private:
        return False
    groups = [(int(address) >> shift) & 0xFFFF for shift in range(112, -1, -16)]
    return sum(1 for group in groups if group) < IPV6_IDENTIFYING_GROUPS


def _documented_ipv4(candidate: str):
    try:
        address = ipaddress.IPv4Address(candidate)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return True
    return _ipv4_verdict(candidate)


def _release_text_errors(relative: str, text: str, domains: bool) -> list:
    errors = []
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        for match in IPV4_PATTERN.finditer(line):
            candidate = match.group(1)
            if candidate in ALLOWED_LITERALS:
                continue
            if _documented_ipv4(candidate) is False:
                errors.append(
                    "%s:%d holds an address outside the RFC 5737 documentation ranges: %s"
                    % (relative, number, candidate)
                )
        for match in IPV6_PATTERN.finditer(line):
            candidate = match.group(1)
            if _documented_ipv6(candidate) is False:
                errors.append(
                    "%s:%d holds an IPv6 address outside 2001:db8::/32: %s"
                    % (relative, number, candidate)
                )
        for match in MAC_PATTERN.finditer(line):
            value = match.group(0).lower()
            if value in ALLOWED_LITERALS or value.startswith(DOCUMENTATION_MAC_PREFIX):
                continue
            errors.append("%s:%d holds a MAC address: %s" % (relative, number, match.group(0)))
        if domains:
            for match in DOMAIN_PATTERN.finditer(line):
                candidate = match.group(1)
                if _suspect_domain(candidate, RELEASE_ALLOWED_DOMAINS):
                    errors.append(
                        "%s:%d holds a domain name outside the allowed documentation domains: %s"
                        % (relative, number, candidate)
                    )
        for marker in PRIVATE_MARKERS:
            if marker.search(line):
                errors.append("%s:%d holds a private marker" % (relative, number))
                break
        for marker in CREDENTIAL_MARKERS:
            if marker.search(line):
                errors.append("%s:%d holds credential-shaped material" % (relative, number))
                break
        if PEM_MARKER_PATTERN.search(line) and _pem_material(lines, number - 1):
            errors.append(
                "%s:%d holds a private key block carrying base64 key material"
                % (relative, number)
            )
    return errors


def gate_release_content(root: Path) -> list:
    base = root.resolve()
    try:
        files = _release_files(base)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        return ["release selection is unavailable or invalid: %s" % error]
    if not files:
        return ["release selection holds no file"]
    errors = []
    for path in files:
        relative = _relative(base, path)
        for marker in PRIVATE_MARKERS:
            if marker.search(relative):
                errors.append("%s is a released path holding a private marker" % relative)
                break
        suffix = path.suffix.lower()
        if suffix not in RELEASE_TEXT_SUFFIXES:
            continue
        try:
            raw = path.read_bytes()
        except OSError as error:
            errors.append("%s is unreadable: %s" % (relative, error))
            continue
        if b"\x00" in raw:
            errors.append("%s holds a NUL byte" % relative)
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append("%s is not valid UTF-8" % relative)
            continue
        errors.extend(
            _release_text_errors(relative, text, suffix in RELEASE_DOMAIN_SUFFIXES)
        )
    if not _repository(base):
        errors.extend(
            _completeness_errors(base, {_relative(base, path) for path in files})
        )
    return errors


GATE_ORDER = ("imports", "project_metadata", "version_metadata", "profiles", "release_content")
GATES = {
    "imports": import_errors,
    "project_metadata": metadata_errors,
    "version_metadata": gate_version_metadata,
    "profiles": profile_errors,
    "release_content": gate_release_content,
}


def check(root: Path) -> dict:
    return {name: GATES[name](root) for name in GATE_ORDER}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if not root.is_dir():
        print("gate_root=failed detail=root is not a directory: %s" % root)
        print("admin_gates=failed")
        return 2
    results = check(root)
    failed = False
    for name in GATE_ORDER:
        errors = results[name]
        if not errors:
            print("gate_%s=passed" % name)
            continue
        failed = True
        for error in errors:
            print("gate_%s=failed detail=%s" % (name, error))
    print("admin_gates=%s" % ("failed" if failed else "passed"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
