#!/usr/bin/env python3
"""Fail closed when netops-admin gains an unreviewed way to reach a device or ships an invalid profile."""

from __future__ import annotations

import argparse
import ast
import ipaddress
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "netops_admin"
PLANNING_MODULES = frozenset((
    "__future__", "argparse", "dataclasses", "hashlib", "ipaddress", "json", "pathlib", "re", "sys",
))
PLANNING_FROM = {"netops_auditor": frozenset(("l1_fortios", "l1_exos")), "importlib": frozenset(("resources",))}
EXECUTION_MODULES = PLANNING_MODULES | frozenset(("datetime", "fcntl", "os", "secrets", "stat", "time"))
INPUTS = {"netops_core.inputs": frozenset(("InputError", "read_regular"))}
FILE_RULES = {
    "__init__.py": (PLANNING_MODULES, {"netops": frozenset(("__version__",))}),
    "access.py": (
        EXECUTION_MODULES,
        {
            "netops_core": frozenset(("hostkey", "platforms", "prompt", "session", "ssh", "vault", "schema", "fortios")),
            "netops_auditor": frozenset(("collect",)),
        },
    ),
    "notify.py": (EXECUTION_MODULES | frozenset(("ssl", "urllib.error", "urllib.request", "subprocess")), INPUTS),
    "execute.py": (EXECUTION_MODULES, {"contextlib": frozenset(("contextmanager",)),
                                    "netops_core.target_lock": frozenset(("target_lock", "TargetBusy", "TargetLockError"))}),
    "enrollment.py": (EXECUTION_MODULES, {}),
    "exec_fortios.py": (EXECUTION_MODULES, {}),
    "exec_exos.py": (EXECUTION_MODULES, {}),
    "exec_eos.py": (EXECUTION_MODULES, {}),
    "exec_ios.py": (EXECUTION_MODULES, {}),
    "exec_junos.py": (EXECUTION_MODULES, {}),
    "exec_fortiadc.py": (EXECUTION_MODULES, {}),
    "exec_nxos.py": (EXECUTION_MODULES, {}),
    "fortiadc_plan.py": (PLANNING_MODULES, {}),
    "membership.py": (PLANNING_MODULES, {"netops_auditor.management": frozenset(("exos_model", "port_inventory", "ports"))}),
    "audit_gate.py": (PLANNING_MODULES, {"netops_auditor": frozenset(("checks_exos", "checks_fortios", "management")),
                                         "netops_auditor.engine": frozenset(("EVALUATED", "NOT_EVALUATED", "SECTION_MISSING", "evaluate", "load_catalog")),
                                         "netops_auditor.state": frozenset(("evaluation_complete",))}),
    "mcp_server.py": (EXECUTION_MODULES | frozenset(("functools", "threading", "typing")),
                      {"fastmcp": frozenset(("FastMCP",)), "fastmcp.exceptions": frozenset(("ToolError",))}),
    "state.py": (EXECUTION_MODULES | {"math", "subprocess"}, dict(INPUTS, **{"contextlib": frozenset(("contextmanager",))})),
    "audit.py": (EXECUTION_MODULES | {"math"}, INPUTS),
    "config.py": (EXECUTION_MODULES, dict(INPUTS, **{"netops_auditor.management": frozenset(("load_policy",))})),
    "cli.py": (EXECUTION_MODULES, dict(INPUTS, **{"netops_core": frozenset(("schema",))})),
    "schema_request.py": (PLANNING_MODULES | {"copy"}, {}),
    "exec_schema_fortios.py": (EXECUTION_MODULES, {"netops_core": frozenset(("fortios",))}),
    "schema_runtime.py": (PLANNING_MODULES | {"copy"}, {
        "netops_core": frozenset(("fortios", "schema")),
        "netops_auditor": frozenset(("schema_checks", "scoped_fortios", "checks_fortios")),
        "netops_auditor.engine": frozenset(("EVALUATED",)),
        "netops_auditor.state": frozenset(("evaluation_complete",)),
    }),
    "schema_policy.py": (PLANNING_MODULES | {"copy"},
                         dict(INPUTS, **{"netops_core": frozenset(("fortios",)),
                                         "netops_auditor.schema_checks": frozenset(("SECRET_ATTRIBUTE",))})),
    "schema_plan.py": (PLANNING_MODULES | {"copy"}, {
        "netops_core": frozenset(("fortios", "schema")),
        "netops_auditor": frozenset(("schema_checks",)),
    }),
}
FORBIDDEN_NAMES = frozenset(("eval", "exec", "compile", "__import__", "breakpoint"))
FORBIDDEN_ATTRIBUTES = frozenset(("system", "popen", "spawnv", "spawnve", "execv", "execve", "fork"))
PLATFORMS = frozenset(("fortios", "exos", "eos", "ios", "iosxe", "fortiadc", "nxos", "junos"))


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
ALLOWED_LITERALS = frozenset((
    # firmware, BootROM and diagnostics version strings of the golden EXOS captures look like addresses
    "33.7.1.6", "33.6.1.14", "1.3.6.1", "aa:bb:cc:dd:ee:ff", "1.0.1.9", "2.0.0.6", "255.255.255.255", "31.7.3.37", "32.6.2.68",
))
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


GATE_ORDER = ("imports", "profiles")
GATES = {
    "imports": import_errors,
    "profiles": profile_errors,
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
