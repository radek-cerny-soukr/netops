import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

def legacy(root):
    spec = importlib.util.spec_from_file_location("source_privacy_rules", root / "scripts/check_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ALLOWED_DOMAINS += ("chatgpt.com", "claude.com", "ghcr.io", "cisecurity.org")
    # the two public Discord hosts that `netops check-intent --notify` accepts for its webhook (notify.DISCORD_WEBHOOK)
    module.ALLOWED_DOMAINS += ("discord.com", "discordapp.com")
    # protocol constants that real device output prints: the Ethernet broadcast address (FortiOS interface and
    # STP listings) and OSPF AllDRouters, the IANA group next to the already accepted AllSPFRouters (IOS XE)
    module.ALLOWED_LITERALS = module.ALLOWED_LITERALS | {"ff:ff:ff:ff:ff:ff", "224.0.0.6"}
    return module

VENDORED_SCHEMA_PINS = {
    "release/schema/cyclonedx-1.7/PROVENANCE.json": "1582c046da37af18f27008d49761e5a94efff65e0ebdde56cacd73672c99b778",
    "release/schema/cyclonedx-1.7/bom-1.7.schema.json": "df472ef4aaf593904c479293723a1a5c191d6672715c93b3c0b5c318f3914221",
    "release/schema/cyclonedx-1.7/spdx.schema.json": "54a6288292bc6c90b0d3952f5f939f17436fa76704ffe68a46e5b78539c7cc1b",
    "release/schema/cyclonedx-1.7/jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
    "release/schema/cyclonedx-1.7/cryptography-defs.schema.json": "018ea7f78b5208ec647cfd10f669cc9c26aba6aceb79c4da7f9c0ef4c99b60de",
}

def pinned_vendored_schema(relative, text):
    expected = VENDORED_SCHEMA_PINS.get(relative)
    return expected is not None and hashlib.sha256(text.encode("utf-8")).hexdigest() == expected

ESCAPE_SEQUENCE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8}))")

# Administrator decision of 2026-11-22: keep lab identifiers out of public documentation.
# General shapes stay readable rules; each is reported only by its type, never by pattern or line content.
LAB_IDENTIFIER_PATTERNS = (
    ("vm number", re.compile(r"\bVM[ _-]?[0-9]{3}\b", re.IGNORECASE)),
    # a host name such as rpi<N>-<role>; the model abbreviation RPi5 on its own stays allowed
    ("host name", re.compile(r"\brpi[0-9]+-[a-z]", re.IGNORECASE)),
    ("internal address", re.compile(r"(?<![\d.])192\.168\.")),
    ("internal address", re.compile(r"(?<![\d.])10\.255\.")),
    ("serial number", re.compile(r"\bFGT[0-9A-Z]{10,}\b", re.IGNORECASE)),
    ("task reference", re.compile(r"netops-20[0-9]{6}-")),
    ("task reference", re.compile(r"\bnetops-t[0-9]+\b", re.IGNORECASE)),
    ("task reference", re.compile(r"\btask[ _-]?#?[0-9]{2,}\b", re.IGNORECASE)),
    ("evidence path", re.compile(r"task-evidence/", re.IGNORECASE)),
)

# Names of the maintainer's lab (hosts, devices, domain, test kit, temporary accounts and profiles) are kept
# only as SHA-256 fingerprints of the lowercase token, so this public gate does not publish them itself.
LAB_IDENTIFIER_FINGERPRINTS = {
    "3a321923989772675264c7b12ac8dd102af59e2829f019c73f3d5d98a7c1fbf3": "host name",
    "13015d079f0842c20f910818ba42801d6c22f60fd06491cda807174d179d2e48": "host name",
    "df96faf3f0903da7e99986a2b13813b289d79f9a07b982a2ec846d943751bdd1": "host name",
    "378a4a3f2c2380c72ab7c90671c43d018955185c2acc1a6cc0844c943672c936": "host name",
    "172421c1c87292bc98a8a17ea4e4ad631e6df65c5e2a7c7da3f306a714bf0d29": "host name",
    "a4ee1eef94d828af0d1beb34de5a3731e5b057596d04a9ee106fed3a025c2507": "lab name",
    "ee641363d4dc946df7a620f6b4ee237b8c81e6b699a74dd7dd1c8de5edc2f470": "lab name",
    "b2e2af04179af933c71f903ec20acab578474a0d7b9dc6d3ac9dfecfb5a21f25": "domain name",
    "a3053e5e355c09213744b410db1fe0173f0dea2fa1d94d8486e5c396514771a8": "device name",
    "9ff1baad71a3b50caff4ca0b9cf8ab6db94144a3b9f65e76bcc51d3b1adc98bb": "device name",
    "3d819eaa0398212d59d5ac1f429571c50c6ad2c22d3480efa474319cf942db37": "device name",
    "9a45c68e83e05380986c2a4a53ff3039e80e7f8c04bee61437aaa9387191975c": "device name",
    "ba13f1eddf678ecb447e471d30cddf1ddb34c293bcd6b38f3410049e59221bd6": "device name",
    "b6aae1020fee3b322ddedc901e402e160af33fc327d588e58a6d600710124392": "device name",
    "7a7398ea50e105e78d264eb35e934e72743ad791b48f8e1e043bf4bc0801c16e": "device name",
    "f112f6027d1604855e8a16300b7b90eae9feb8f8f0e17258249d89669cb9b226": "device name",
    "06c99cb7954912952fa6153383dffedd6090b3a39a49370d9fb669ac153bedf5": "account name",
    "79390ec03b017d01508f21ba70022b3b54c6a7a06a8858ba070c13e8268bf744": "account name",
    "d0dd14c00677d357b3827220be2041f39dd5cdad44252bb89b01b7368393184d": "account name",
    "28041b42f958646fcf60b0164a42953fd5bf7d740d202c20bf0c12af1ec60806": "account name",
}

LAB_TOKEN = re.compile(r"[\w.-]+")
LAB_TOKEN_SEPARATOR = re.compile(r"([.-])")

def lab_token_candidates(line):
    """Lowercase words of a line (letters, digits, `_`, `-`, `.`) and every run of their `-`/`.` separated parts."""
    for token in LAB_TOKEN.findall(line.lower()):
        pieces = LAB_TOKEN_SEPARATOR.split(token)
        for first in range(0, len(pieces), 2):
            for last in range(first, len(pieces), 2):
                candidate = "".join(pieces[first:last + 1])
                if candidate:
                    yield candidate

def lab_identifier_types(line):
    types = [kind for kind, pattern in LAB_IDENTIFIER_PATTERNS if pattern.search(line)]
    types += [LAB_IDENTIFIER_FINGERPRINTS.get(hashlib.sha256(candidate.encode("utf-8")).hexdigest())
              for candidate in lab_token_candidates(line)]
    return [kind for kind in dict.fromkeys(types) if kind]

def lab_identifier_errors(relative, text):
    if relative in {"TASK.md", "RESULT.md"} or relative.startswith("ref/"):
        return []
    path = Path(relative)
    directories = path.parts[:-1]
    component_dirs = directories[2:] if directories[:1] == ("components",) else ()
    if (directories[:1] == ("tests",) or directories[:2] == ("release", "tests")
            or component_dirs[:1] == ("tests",)):
        return []
    suffix = path.suffix.lower()
    is_docs = directories[:1] == ("docs",) or component_dirs[:1] == ("docs",)
    if suffix != ".md" and (suffix != ".json" or not is_docs):
        return []
    errors = []
    for number, line in enumerate(text.splitlines(), 1):
        variants = [line]
        try:
            variants.append(decode_text_escapes(line))
        except ValueError:
            pass  # privacy_text already reports the unusable escape for this file
        types = dict.fromkeys(kind for variant in variants for kind in lab_identifier_types(variant))
        errors += [f"{relative}:{number}: lab identifier ({kind})" for kind in types]
    return errors

def decode_text_escapes(text):
    for _ in range(8):
        decoded = ESCAPE_SEQUENCE.sub(
            lambda match: chr(int(next(value for value in match.groups() if value), 16)), text)
        if decoded == text:
            return decoded
        text = decoded
    if ESCAPE_SEQUENCE.search(text):
        raise ValueError("Escape nesting exceeds the privacy scan limit")
    return text

def decoded_json_strings(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from decoded_json_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from decoded_json_strings(item)
    elif isinstance(value, str):
        yield value

def privacy_text_once(rules, relative, text, domains=True):
    checked = re.sub(r"(?i)\braspberry\s+pi\s+os(?:\s+64)?\b", "Supported ARM operating system", text)
    checked = re.sub(r"(?i)\braspberry\s+pi\s+[0-9]+\b", "Supported ARM board model", checked)
    errors = []
    if any(marker.search(relative) for marker in rules.PRIVATE_MARKERS):
        errors.append("private marker in path: " + relative)
    if any(marker.search(checked) for marker in rules.PRIVATE_MARKERS):
        errors.append("private marker in " + relative)
    if any(marker.search(text) for marker in rules.CREDENTIAL_MARKERS):
        errors.append("credential-shaped material in " + relative)
    errors.extend(rules._pem_material_errors(relative, text))
    if rules._address_errors(relative, text, domains and Path(relative).suffix.lower() in rules.DOMAIN_SUFFIXES):
        errors.append("network or domain material in " + relative)
    return errors

def privacy_text(rules, relative, text):
    domains = not pinned_vendored_schema(relative, text)
    variants = [text]
    if Path(relative).suffix.lower() == ".json":
        try:
            decoded = json.loads(text)
        except ValueError:
            pass
        else:
            variants.append(chr(10).join(decoded_json_strings(decoded)))
    errors = []
    for original in tuple(variants):
        try:
            variants.append(decode_text_escapes(original))
        except ValueError:
            errors.append("unusable text escape in " + relative)
    for variant in dict.fromkeys(variants):
        errors.extend(privacy_text_once(rules, relative, variant, domains))
    return list(dict.fromkeys(errors))

RELEASE_FILE_VERSION = re.compile(r"(?:netops-|releases/download/v)(\d+\.\d+\.\d+)[-/]")

def readme_version_errors(text, version):
    errors = ["README does not state release " + version + ": " + marker
              for marker in ("This README describes NetOps " + version + ",", "**Acceptance of " + version + ":**")
              if marker not in text]
    errors += ["README names release files of " + found + ", not " + version
               for found in sorted(set(RELEASE_FILE_VERSION.findall(text))) if found != version]
    return errors
def section(text, heading):
    start = text.find(heading + "\n")
    if start < 0:
        return ""
    end = re.compile(r"^#{1,%d} " % len(heading.split(" ")[0]), re.M).search(text, start + len(heading))
    return text[start:end.start() if end else len(text)]

LIVE_FIRMWARE = re.compile(r"\b(Forti[A-Za-z]+|[A-Z][A-Za-z]+)(?:-[A-Za-z0-9]+)? (\d+(?:\.\d+)+ build\d+)\b")
LIVE_LINE = re.compile(r"^Live verification of NetOps (\S+) on \d{4}-\d{2}-\d{2}: .*$", re.M)

TABLE_CELL_SPLIT = re.compile(r"(?<!\\)\|")

def table_cells(line):
    line = line.strip()
    if len(line) < 2 or not (line.startswith("|") and line.endswith("|")):
        return None
    return [cell.strip() for cell in TABLE_CELL_SPLIT.split(line[1:-1])]

def tested_client_results(clients, version):
    """Result cells of the table under "**Tested for NetOps <version> (<date>)**", or None without that heading."""
    heading = re.search(r"^\*\*Tested for NetOps " + re.escape(version) + r" \(\d{4}-\d{2}-\d{2}\)\*\*[^\n]*$", clients, re.M)
    if not heading:
        return None
    lines = clients[heading.end():].split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    header = table_cells(lines[0]) if lines else None
    separator = table_cells(lines[1]) if len(lines) > 1 else None
    if (not header or "Result" not in header or not separator or len(separator) != len(header)
            or not all(re.fullmatch(r":?-+:?", cell) for cell in separator)):
        return []
    column = header.index("Result")
    results = []
    for line in lines[2:]:
        cells = table_cells(line)
        if cells is None:
            break
        results.append(cells[column] if column < len(cells) else "")
    return results

def client_acceptance_errors(clients, version, notes_exist):
    results = tested_client_results(clients, version)
    tested = results is not None
    deferred = ("**NetOps " + version + ":** the client acceptance (Codex CLI and Claude Code) runs once on the signed release candidate image; "
                "its results are in the [release notes](release/notes-" + version + ".md#acceptance).")
    pending = deferred in clients.splitlines()
    if tested and pending:
        return ["README claims and defers client results of " + version + ": Tested MCP clients has both a result table and the pending-acceptance line"]
    if pending:
        return [] if notes_exist else ["README defers client results of " + version + " to release/notes-" + version + ".md, which does not exist"]
    if tested:
        if any(re.match(r"(PASS|FAIL)\b", result) for result in results):
            return []
        return ["README Tested MCP clients for " + version + " has no client result"]
    return ["README Tested MCP clients has neither a result table for NetOps " + version + " nor the exact pending-acceptance line of NetOps " + version]

def support_errors(readme, verified, version, notes_exist=False):
    supported = section(readme, "## Supported devices and firmware")
    lines = [line for line in LIVE_LINE.finditer(supported) if line.group(1) == version]
    errors = [] if lines else ["README Supported devices has no live verification of NetOps " + version]
    rows = {row.split("|")[1].strip(): row for row in supported.splitlines() if row.startswith("| ")}
    for line in lines:
        pairs = LIVE_FIRMWARE.findall(line.group(0))
        if len(pairs) != len(re.findall(r"\bbuild\d+\b", line.group(0))):
            errors.append("README live verification names a build without its platform and firmware version")
        errors += ["README live verification names " + platform + " " + firmware + " outside the Supported devices table"
                   for platform, firmware in pairs if not re.search(r"(?<![\w.])" + re.escape(firmware) + r"\b", rows.get(platform, ""))]
    if "NetOps " + version not in verified:
        errors.append("docs/verified-support.md does not name NetOps " + version)
    errors += client_acceptance_errors(section(readme, "#### Tested MCP clients"), version, notes_exist)
    return errors
CANDIDATE_BRANCH = re.compile(r"release/[^\s\"']*-candidate")

def workflow_branch_errors(texts, version):
    expected = "release/" + version + "-candidate"
    push = re.search(r"^on:\n  push:\n(.*?)(?=^ {0,2}\w|\Z)", texts["ci.yml"], re.MULTILINE | re.DOTALL)
    errors = []
    if push is None or push[1] != '    branches:\n      - "**"\n    tags:\n      - "**"\n':
        errors.append("ci.yml must run on pushes to all branches and tags")
    for name in ("candidate.yml", "codeql.yml"):
        for found in sorted(set(CANDIDATE_BRANCH.findall(texts[name])) or {"(none)"}):
            if found != expected:
                errors.append(name + " names candidate branch " + found + ", not " + expected)
    return errors

def check(root, release=False):
    rules = legacy(root)
    proc = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True)
    names = proc.stdout.decode().rstrip(chr(0)).split(chr(0))
    errors = []
    for relative in names:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            errors.append("tracked path is not a single regular file: " + relative)
            continue
        if path.suffix.lower() not in rules.TEXT_SUFFIXES | {".ps1", ".psm1", ".example"}:
            continue
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
            if chr(0) in text:
                errors.append("NUL in text: " + relative)
            errors.extend(privacy_text(rules, relative, text))
            errors.extend(lab_identifier_errors(relative, text))
        except (OSError, UnicodeError):
            errors.append("unreadable tracked text: " + relative)
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    version = project["version"]
    if not re.fullmatch(r"1\.0\.[0-9]+", version):
        errors.append("product version must be 1.0.x")
    product_tree = ast.parse((root / "src/netops/__init__.py").read_text())
    product_versions = [node.value.value for node in product_tree.body if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)]
    if product_versions != [version]:
        errors.append("installed product version differs from project metadata")
    readme_text = (root / "README.md").read_text(encoding="utf-8")
    errors.extend(readme_version_errors(readme_text, version))
    if release:
        errors.extend(support_errors(readme_text, (root / "docs/verified-support.md").read_text(encoding="utf-8"), version,
                                       (root / "release" / ("notes-" + version + ".md")).is_file()))
    errors.extend(workflow_branch_errors({name: (root / ".github/workflows" / name).read_text(encoding="utf-8")
                                          for name in ("ci.yml", "candidate.yml", "codeql.yml")}, version))
    for role in ("core", "helper", "auditor", "admin"):
        component = root / "components" / ("netops-" + role)
        metadata = tomllib.loads((component / "pyproject.toml").read_text())
        engine = metadata.get("tool", {}).get("netops-engine", {})
        if "project" in metadata or "build-system" in metadata or engine != {"name": "netops-" + role, "distribution": "netops", "release": "shared-root-version"}:
            errors.append("component must declare only its shared engine identity: " + role)
        module = ast.parse((component / "src" / ("netops_" + role) / "__init__.py").read_text())
        if not any(isinstance(node, ast.ImportFrom) and node.module == "netops" and any(alias.name == "__version__" for alias in node.names) for node in module.body):
            errors.append("component does not import product version: " + role)
    for path in (root / "components/netops-core/src/netops_core").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom) and node.level:
                continue
            imports = [name.name for name in node.names] if isinstance(node, ast.Import) else [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            for name in imports:
                if name.split(".")[0] == "netops":
                    if not isinstance(node, ast.ImportFrom) or node.module != "netops" or any(alias.name != "__version__" for alias in node.names):
                        errors.append("Core may import only the shared product version")
                elif name.split(".")[0] not in sys.stdlib_module_names | {"netops_core"}:
                    errors.append("unexpected Core dependency in " + str(path.relative_to(root)))
    return errors

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    errors = check(Path(args.root), args.release)
    for error in errors:
        print(error)
    print("source_gate=" + ("FAIL" if errors else "PASS"))
    return 1 if errors else 0

if __name__ == "__main__":
    sys.exit(main())
