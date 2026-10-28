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
CANDIDATE_BRANCH = re.compile(r"release/[^\s\"']*-candidate")

def workflow_branch_errors(texts, version):
    expected = "release/" + version + "-candidate"
    return [name + " names candidate branch " + found + ", not " + expected
            for name, text in sorted(texts.items())
            for found in sorted(set(CANDIDATE_BRANCH.findall(text)) or {"(none)"}) if found != expected]

def check(root):
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
        except (OSError, UnicodeError):
            errors.append("unreadable tracked text: " + relative)
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    version = project["version"]
    product_tree = ast.parse((root / "src/netops/__init__.py").read_text())
    product_versions = [node.value.value for node in product_tree.body if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)]
    if product_versions != [version]:
        errors.append("installed product version differs from project metadata")
    errors.extend(readme_version_errors((root / "README.md").read_text(encoding="utf-8"), version))
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
    args = parser.parse_args()
    errors = check(Path(args.root))
    for error in errors:
        print(error)
    print("source_gate=" + ("FAIL" if errors else "PASS"))
    return 1 if errors else 0

if __name__ == "__main__":
    sys.exit(main())
