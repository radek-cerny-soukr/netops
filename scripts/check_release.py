"""Source privacy rules that release/check_source.py and release/report_gate.py load as a library."""

from __future__ import annotations

import ast
import ipaddress
import re


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
    "openssh.org",
    "readthedocs.io",
    "sigstore.dev",
)
ALLOWED_LITERALS = frozenset(
    ("33.7.1.6",
        "33.6.1.14",
        "1.3.6.1",
        "aa:bb:cc:dd:ee:ff", "1.0.1.9", "2.0.0.6", "255.255.255.255", "31.7.3.37", "32.6.2.68",
        "5.2.1.1", "169.254.0.0", "00:00:00:00:00:00",)
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
    re.compile(r"\bIT[- ]kufr", re.IGNORECASE),
    re.compile(r"\bwork/(?:claude|codex)-", re.IGNORECASE),
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


def _negative_diagnostic_literals(relative: str, text: str) -> set[tuple[int, int, int]]:
    if relative != "components/netops-helper/tests/test_fortios_diagnostics.py":
        return set()
    try:
        module = ast.parse(text)
    except SyntaxError:
        return set()
    accepted = set()
    multicast = str(ipaddress.IPv4Address(0xE0000001))
    for function in module.body:
        if not isinstance(function, ast.FunctionDef) or function.name != "test_invalid_request":
            continue
        if [argument.arg for argument in function.args.args] != ["kwargs"]:
            continue
        statements = [ast.unparse(statement) for statement in function.body]
        if len(statements) != 3 or statements[1] != "values.update(kwargs)":
            continue
        initial = function.body[0]
        if not isinstance(initial, ast.Assign) or len(initial.targets) != 1 or ast.unparse(initial.targets[0]) != "values":
            continue
        if not isinstance(initial.value, ast.Call) or ast.unparse(initial.value.func) != "dict" or initial.value.args:
            continue
        if statements[2] != "with pytest.raises(ValueError):\n    d.validate(**values)":
            continue
        for decorator in function.decorator_list:
            if not isinstance(decorator, ast.Call) or ast.unparse(decorator.func) != "pytest.mark.parametrize":
                continue
            if len(decorator.args) != 2 or not isinstance(decorator.args[0], ast.Constant) or decorator.args[0].value != "kwargs":
                continue
            cases = decorator.args[1]
            if not isinstance(cases, ast.List):
                continue
            for case in cases.elts:
                if not isinstance(case, ast.Dict) or len(case.keys) != 1:
                    continue
                key, value = case.keys[0], case.values[0]
                if isinstance(key, ast.Constant) and key.value == "address" and isinstance(value, ast.Constant) and value.value == multicast:
                    accepted.add((value.lineno, value.col_offset + 1, value.end_col_offset - 1))
    return accepted


def _address_errors(relative: str, text: str, domains: bool) -> list[str]:
    errors: list[str] = []
    negative_literals = _negative_diagnostic_literals(relative, text)
    for number, line in enumerate(text.splitlines(), start=1):
        for match in IPV4_PATTERN.finditer(line):
            if (number, match.start(1), match.end(1)) in negative_literals:
                continue
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
