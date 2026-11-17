#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ast
import importlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "netops_auditor"
CORE_PACKAGE = "netops_core"
MCP_MODULE = "mcp_server.py"
MCP_DEPENDENCY = "fastmcp"

GATE_ORDER = (
    "fixtures_per_rule",
    "fixtures_synthetic",
    "catalog",
    "core_stdlib",
)

CLASSES = ("fakt", "usudek")
SEVERITIES = ("high", "medium", "low", "info")
JUDGEMENT_CLASS = "usudek"
FORBIDDEN_JUDGEMENT_SEVERITY = "high"
RULE_FIELDS = (
    "id",
    "version",
    "check",
    "sections",
    "default_sections",
    "class",
    "severity",
    "scope_gate",
    "evidence_fields",
    "title",
    "remediation",
    "refs",
    "known_false_positives",
)
REQUIRED_RULE_FIELDS = (
    "id",
    "version",
    "check",
    "sections",
    "class",
    "severity",
    "evidence_fields",
    "title",
    "remediation",
)

FIXTURE_NAMES = ("positive.conf", "negative.conf")
FIXTURE_ROOT = ("tests", "fixtures")
RULE_FIXTURE_ROOT = ("tests", "fixtures", "rules")

DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
ALLOWED_DOMAINS = ("example.invalid", "example.com", "example.net", "example.org")
RESERVED_TLDS = frozenset(("example", "invalid", "test", "localhost"))

IPV4_PATTERN = re.compile(
    r"(?<![0-9A-Za-z.])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![0-9A-Za-z]|\.[0-9])"
)
DOMAIN_PATTERN = re.compile(
    r"(?<![0-9A-Za-z._-])"
    r"([0-9A-Za-z](?:[0-9A-Za-z-]*[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:[0-9A-Za-z-]*[0-9A-Za-z])?)+)"
    r"(?![0-9A-Za-z_-]|\.[0-9A-Za-z])"
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
        "tar", "gz", "bz2", "xz", "zip", "tgz", "bak", "tmp", "swp", "out", "err", "sarif",
        "pem", "crt", "cer", "der", "key", "pub", "csr", "sig", "asc",
        "png", "jpg", "jpeg", "gif", "svg", "pdf", "bin", "img", "iso", "diff", "patch",
        "orig", "rej", "in", "env", "example", "sample", "tmpl", "tpl", "j2", "lst",
    )
)


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _catalog_directory(root: Path) -> Path:
    return root / "src" / PACKAGE / "catalog"


def _catalog_paths(root: Path):
    directory = _catalog_directory(root)
    if not directory.is_dir():
        return None
    return sorted(directory.glob("*.json"))


def _catalog_documents(root: Path):
    paths = _catalog_paths(root)
    if paths is None:
        return [], ["catalog directory is missing: src/%s/catalog" % PACKAGE]
    if not paths:
        return [], ["catalog directory holds no platform file: src/%s/catalog" % PACKAGE]
    documents, errors = [], []
    for path in paths:
        relative = _relative(root, path)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as error:
            errors.append("%s is unreadable or not valid JSON: %s" % (relative, error))
            continue
        if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
            errors.append("%s holds no rules list" % relative)
            continue
        documents.append((relative, path.stem, document))
    return documents, errors


def _rule_identifiers(root: Path):
    documents, errors = _catalog_documents(root)
    identifiers = []
    for relative, _platform, document in documents:
        for index, item in enumerate(document["rules"]):
            if not isinstance(item, dict):
                errors.append("%s rule %d is not an object" % (relative, index))
                continue
            identifier = item.get("id")
            if not isinstance(identifier, str) or not identifier.strip():
                errors.append("%s rule %d has no usable id" % (relative, index))
                continue
            identifiers.append(identifier)
    return identifiers, errors


def gate_fixtures_per_rule(root: Path) -> list:
    identifiers, errors = _rule_identifiers(root)
    directory = root.joinpath(*RULE_FIXTURE_ROOT)
    for identifier in sorted(set(identifiers)):
        for name in FIXTURE_NAMES:
            path = directory / identifier / name
            relative = "%s/%s/%s" % ("/".join(RULE_FIXTURE_ROOT), identifier, name)
            if not path.is_file():
                errors.append("rule_id=%s has no fixture %s" % (identifier, relative))
            elif path.stat().st_size == 0:
                errors.append("rule_id=%s has an empty fixture %s" % (identifier, relative))
    if directory.is_dir():
        known = set(identifiers)
        for child in sorted(directory.iterdir()):
            if child.name not in known:
                errors.append(
                    "fixture entry %s/%s belongs to no rule of the catalog"
                    % ("/".join(RULE_FIXTURE_ROOT), child.name)
                )
    return errors


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


def _text_errors(relative: str, text: str) -> list:
    errors = []
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        for match in IPV4_PATTERN.finditer(line):
            candidate = match.group(1)
            if _ipv4_verdict(candidate) is False:
                errors.append(
                    "%s:%d holds an address outside the RFC 5737 documentation ranges: %s"
                    % (relative, number, candidate)
                )
        for match in DOMAIN_PATTERN.finditer(line):
            candidate = match.group(1)
            if _suspect_domain(candidate):
                errors.append(
                    "%s:%d holds a domain name outside the allowed documentation domains: %s"
                    % (relative, number, candidate)
                )
        if PEM_MARKER_PATTERN.search(line) and _pem_material(lines, number - 1):
            errors.append(
                "%s:%d holds a private key block carrying base64 key material"
                % (relative, number)
            )
    return errors


def gate_fixtures_synthetic(root: Path) -> list:
    directory = root.joinpath(*FIXTURE_ROOT)
    if not directory.is_dir():
        return ["fixture directory is missing: %s" % "/".join(FIXTURE_ROOT)]
    errors = []
    for parent, directory_names, file_names in os.walk(directory, followlinks=False):
        base = Path(parent)
        for name in sorted(directory_names):
            child = base / name
            if child.is_symlink():
                errors.append(
                    "%s is a symlink and may point at real data" % _relative(root, child)
                )
        for name in sorted(file_names):
            path = base / name
            relative = _relative(root, path)
            if path.is_symlink():
                errors.append("%s is a symlink and may point at real data" % relative)
                continue
            if not path.is_file():
                errors.append("%s is not a regular file" % relative)
                continue
            try:
                text = path.read_bytes().decode("utf-8", "replace")
            except OSError as error:
                errors.append("%s is unreadable: %s" % (relative, error))
                continue
            errors.extend(_text_errors(relative, text))
    return errors


def _loaded_package(root: Path):
    source = str(root / "src")
    while source in sys.path:
        sys.path.remove(source)
    sys.path.insert(0, source)
    engine = importlib.import_module("%s.engine" % PACKAGE)
    findings = importlib.import_module("%s.findings" % PACKAGE)
    for path in sorted((root / "src" / PACKAGE).glob("checks_*.py")):
        importlib.import_module("%s.%s" % (PACKAGE, path.stem))
    return engine, findings


def _rule_errors(relative: str, index: int, item) -> list:
    errors = []
    where = "%s rule %d" % (relative, index)
    if not isinstance(item, dict):
        return ["%s is not an object" % where]
    identifier = item.get("id")
    if isinstance(identifier, str) and identifier.strip():
        where = "rule_id=%s in %s" % (identifier, relative)
    else:
        errors.append("%s has no usable id" % where)
    missing = [name for name in REQUIRED_RULE_FIELDS if name not in item]
    if missing:
        errors.append("%s misses fields: %s" % (where, ", ".join(missing)))
    unknown = sorted(set(item) - set(RULE_FIELDS))
    if unknown:
        errors.append("%s carries unknown fields: %s" % (where, ", ".join(unknown)))
    for name in ("title", "remediation", "check"):
        value = item.get(name)
        if not isinstance(value, str) or not value.strip():
            errors.append("%s has an empty or non-string %s" % (where, name))
    version = item.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        errors.append("%s has a version that is not a positive integer: %r" % (where, version))
    rule_class = item.get("class")
    if rule_class not in CLASSES:
        errors.append(
            "%s has a class outside %s: %r" % (where, ", ".join(CLASSES), rule_class)
        )
    severity = item.get("severity")
    if severity not in SEVERITIES:
        errors.append(
            "%s has a severity outside %s: %r" % (where, ", ".join(SEVERITIES), severity)
        )
    if rule_class == JUDGEMENT_CLASS and severity == FORBIDDEN_JUDGEMENT_SEVERITY:
        errors.append(
            "%s is class %s and must not carry severity %s"
            % (where, JUDGEMENT_CLASS, FORBIDDEN_JUDGEMENT_SEVERITY)
        )
    evidence = item.get("evidence_fields")
    if not isinstance(evidence, list) or not evidence:
        errors.append("%s has empty evidence_fields" % where)
    else:
        for position, field in enumerate(evidence):
            if not isinstance(field, str) or not field.strip():
                errors.append(
                    "%s has an empty or non-string evidence_fields[%d]" % (where, position)
                )
    return errors


def gate_catalog(root: Path) -> list:
    documents, errors = _catalog_documents(root)
    if not documents:
        return errors
    try:
        engine, findings = _loaded_package(root)
    except Exception as error:
        errors.append(
            "%s is not importable from src: %s: %s" % (PACKAGE, type(error).__name__, error)
        )
        return errors
    if tuple(getattr(findings, "CLASSES", ())) != CLASSES:
        errors.append(
            "findings.CLASSES is %r, the gate expects %r"
            % (tuple(getattr(findings, "CLASSES", ())), CLASSES)
        )
    if tuple(getattr(findings, "SEVERITIES", ())) != SEVERITIES:
        errors.append(
            "findings.SEVERITIES is %r, the gate expects %r"
            % (tuple(getattr(findings, "SEVERITIES", ())), SEVERITIES)
        )
    for relative, platform, document in documents:
        seen = set()
        for index, item in enumerate(document["rules"]):
            errors.extend(_rule_errors(relative, index, item))
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                if item["id"] in seen:
                    errors.append("rule_id=%s in %s is declared twice" % (item["id"], relative))
                seen.add(item["id"])
        if not document["rules"]:
            errors.append("%s holds no rule" % relative)
        try:
            rules = engine.load_catalog(platform)
        except Exception as error:
            errors.append(
                "%s does not load through engine.load_catalog(%r): %s: %s"
                % (relative, platform, type(error).__name__, error)
            )
            continue
        if len(rules) != len(document["rules"]):
            errors.append(
                "%s declares %d rules but engine.load_catalog(%r) returned %d"
                % (relative, len(document["rules"]), platform, len(rules))
            )
    return errors


def gate_core_stdlib(root: Path) -> list:
    directory = root / "src" / PACKAGE
    if not directory.is_dir():
        return ["package directory is missing: src/%s" % PACKAGE]
    allowed = set(sys.stdlib_module_names) | {PACKAGE, CORE_PACKAGE}
    errors = []
    modules = sorted(directory.glob("*.py"))
    if not modules:
        return ["package directory holds no module: src/%s" % PACKAGE]
    for path in modules:
        relative = _relative(root, path)
        extra = {MCP_DEPENDENCY} if path.name == MCP_MODULE else set()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError) as error:
            errors.append("%s is unreadable or not valid Python: %s" % (relative, error))
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue
                if node.module == "netops" and all(alias.name == "__version__" for alias in node.names):
                    continue
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            for name in names:
                if not name or name in allowed or name in extra:
                    continue
                errors.append(
                    "%s:%d imports a module outside the standard library: %s"
                    % (relative, node.lineno, name)
                )
    return errors


GATES = {
    "fixtures_per_rule": gate_fixtures_per_rule,
    "fixtures_synthetic": gate_fixtures_synthetic,
    "catalog": gate_catalog,
    "core_stdlib": gate_core_stdlib,
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
        print("auditor_gates=failed")
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
    print("auditor_gates=%s" % ("failed" if failed else "passed"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
