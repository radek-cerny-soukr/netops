#!/usr/bin/env python3
import argparse
import base64
import binascii
import collections
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import stat
import urllib.parse
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALLOWED_HOSTS = {"ghcr.io", "github.com"}
ASSET_NAME = re.compile(r"(?:compose\.yaml|env\.example|acceptance-[a-z0-9]+(?:-[a-z0-9]+)*\.json|netops-\d+\.\d+\.\d+-(?:SHA256SUMS(?:\.sigstore\.json)?|manifest\.json|acceptance-manifest\.json|vulnerability-assessments\.json|linux-(?:amd64|arm64)(?:\.cdx\.json|-grype\.json|-gate\.json)))")
ALLOWED_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128"))
VENDOR_SCHEMA = json.load(open(os.path.join(HERE, "vendor-schema.json"), encoding="utf-8"))
LAB_WORDS = re.compile(r"(?i)\b(?:esxi|vmware|vsphere|proxmox|kvm|qemu|(?<!/)lima|virtualbox|hyper-v|parallels|utm|vm|vms|vmid|virtual machine|hypervisor|home\s?lab|tunnel(?:ed|s)?|ssh relay|port forward(?:ing)?|clean snapshot|vm snapshot|guest)\b")
PATHS = re.compile(r"(?:/home/|/srv/|/Users/|/mnt/|/volume\d|/root/|(?i:[a-z]:\\{1,2}users\\))")
DOTTED = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z][A-Za-z0-9-]{1,62}(?![\w-])")
URL = re.compile(r"[a-z][a-z0-9+.-]*://[^\s\x00-\x1f]*")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}")
IDENTIFIER = re.compile(r"[^\s\x00-\x1f]+")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MAC = re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f:])")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%\w+)?(?![0-9A-Fa-f:])")


def privacy_rules():
    spec = importlib.util.spec_from_file_location("source_privacy_rules", os.path.join(HERE, "..", "scripts", "check_release.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return tuple(module.PRIVATE_MARKERS) + tuple(module.CREDENTIAL_MARKERS)


def strings(value, skip=()):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in skip:
                continue
            yield str(key)
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, str):
        yield value


def values(document, path=""):
    if isinstance(document, dict):
        for key, item in document.items():
            yield from values(item, path + "." + key)
    elif isinstance(document, list):
        for item in document:
            yield from values(item, path + "[]")
    elif isinstance(document, str):
        yield path, document


def key_paths(document, path="", found=None):
    found = set() if found is None else found
    if isinstance(document, dict):
        for key, item in document.items():
            found.add(path + "." + key)
            key_paths(item, path + "." + key, found)
    elif isinstance(document, list):
        for item in document:
            key_paths(item, path + "[]", found)
    return found


def public_text_findings(text, asset_names, hosts=True):
    found = collections.Counter()
    found["laboratory wording"] += len(LAB_WORDS.findall(text))
    for match in DOTTED.finditer(text if hosts else ""):
        token = match.group(0).lower()
        if token in ALLOWED_HOSTS or token in asset_names:
            continue
        found["host name"] += 1
    found["hardware address"] += len(MAC.findall(text))
    for pattern in (IPV4, IPV6):
        for match in pattern.finditer(text):
            try:
                address = ipaddress.ip_address(match.group(0).split("%")[0])
            except ValueError:
                continue
            if not any(address in network for network in ALLOWED_NETWORKS):
                found["network address"] += 1
    return found


def vendor_kind(name, document):
    if name.endswith(".cdx.json") and isinstance(document, dict) and document.get("bomFormat") == "CycloneDX":
        return "cdx"
    if name.endswith("-grype.json") and isinstance(document, dict) and isinstance(document.get("matches"), list) and (document.get("descriptor") or {}).get("name") == "grype":
        return "grype"
    return None


VENDOR_HOST_DIGESTS = set(VENDOR_SCHEMA["vendor_host_sha256"])


def vendor_host(name):
    return name in ALLOWED_HOSTS or hashlib.sha256(name.encode()).hexdigest() in VENDOR_HOST_DIGESTS
IDENTIFIER_SUFFIXES = set(VENDOR_SCHEMA["identifier_suffixes"])


ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|U([0-9a-fA-F]{8}))")
DECODE_LIMIT = 8
BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{8,}={0,2}(?![A-Za-z0-9+/_=-])")
BASE64_CANDIDATE_LIMIT = 64 * 1024
DECODE_BYTES_LIMIT = 128 * 1024
OPAQUE_TEXT_RUN = re.compile(rb"[\x20-\x7e]{8,}")


def unescaped(text):
    def character(match):
        code = int(match.group(1) or match.group(2) or match.group(3), 16)
        return chr(code) if code < 0x110000 else ""
    return urllib.parse.unquote(ESCAPE.sub(character, text))


def base64_text(token):
    if len(token) % 4 == 1 or ("=" in token and len(token) % 4):
        return None
    normalized = token.replace("-", "+").replace("_", "/")
    try:
        raw = base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True)
        if base64.b64encode(raw).decode("ascii").rstrip("=") != normalized.rstrip("="):
            return None
    except (binascii.Error, ValueError):
        return None
    raw = raw.replace(b"\x00", b"")
    try:
        return raw.decode("utf-8"), True
    except UnicodeDecodeError:
        runs = OPAQUE_TEXT_RUN.findall(raw)
        return (b"\n".join(runs).decode("ascii"), False) if runs else None


def variants(text, decode_base64=True):
    found = [text]
    seen = {text}
    pending = [(text, 0)]
    decoded_bytes = 0
    index = 0
    while index < len(pending):
        current, depth = pending[index]
        index += 1
        def next_variants():
            decoded = unescaped(current)
            if decoded != current:
                yield decoded, "unusable text escape", False
            if not decode_base64:
                return
            for match in BASE64_CANDIDATE.finditer(current):
                token = match.group(0)
                if len(token) > BASE64_CANDIDATE_LIMIT:
                    yield None, "unusable text encoding", True
                    return
                decoded = base64_text(token)
                if decoded is None:
                    continue
                decoded, textual = decoded
                if not textual:
                    yield decoded, None, None
                elif decoded != current:
                    yield decoded, "unusable text encoding", True

        for decoded, failure, is_base64 in next_variants():
            if decoded is None:
                return found, failure
            if decoded in seen:
                continue
            if is_base64 is None:
                seen.add(decoded)
                found.append(decoded)
                continue
            if depth >= DECODE_LIMIT:
                return found, failure
            if is_base64:
                decoded_bytes += len(decoded.encode("utf-8"))
                if decoded_bytes > DECODE_BYTES_LIMIT:
                    return found, "unusable text encoding"
            seen.add(decoded)
            found.append(decoded)
            pending.append((decoded, depth + 1))
    return found, None


def all_variants(texts, found, decode_base64=True):
    result = []
    for text in texts:
        decoded, exceeded = variants(text, decode_base64=decode_base64)
        if exceeded:
            found[exceeded] += 1
        result.extend(decoded)
    return list(dict.fromkeys(result))


def vendor_field_findings(kind, text, asset_names):
    found = collections.Counter()
    if kind == "url":
        host = (urllib.parse.urlsplit(text).hostname or "") if URL.fullmatch(text) else None
        if host is None:
            found["vendor value not a URL"] += 1
        elif host and not vendor_host(host.lower()):
            found["host name"] += 1
        return found + public_text_findings(text, asset_names, hosts=False)
    if kind == "email":
        for match in EMAIL.finditer(text):
            if not vendor_host(match.group(0).split("@", 1)[1].lower()):
                found["host name"] += 1
        return found + public_text_findings(EMAIL.sub(" ", text), asset_names)
    if kind == "identifier" and IDENTIFIER.fullmatch(text) is not None:
        for match in DOTTED.finditer(text):
            token = match.group(0).lower()
            if token.rsplit(".", 1)[-1] not in IDENTIFIER_SUFFIXES and not vendor_host(token):
                found["host name"] += 1
        return found + public_text_findings(text, asset_names, hosts=False)
    documented = set(VENDOR_SCHEMA["documented_tokens"])
    for match in DOTTED.finditer(text):
        if match.group(0).lower() not in documented and match.group(0).lower() not in ALLOWED_HOSTS:
            found["host name"] += 1
    return found + public_text_findings(text, asset_names, hosts=False)


def check_file(path, markers, asset_names):
    with open(path, "rb") as stream:
        raw = stream.read()
    text = raw.decode("utf-8")
    found = collections.Counter()
    pieces = [text]
    if name_is_json(path):
        pieces.extend(strings(json.loads(text)))
    decoded = "\n".join(all_variants(pieces, found))
    found["private marker"] += sum(1 for marker in markers if marker.search(decoded))
    found["private path"] += len(PATHS.findall(decoded))
    name = os.path.basename(path)
    if name.endswith(".json"):
        document = json.loads(text)
        kind = vendor_kind(name, document)
        if kind is None:
            found.update(public_text_findings("\n".join(all_variants(strings(document), found, decode_base64=False)), asset_names))
        else:
            schema = VENDOR_SCHEMA[kind]
            found["unexpected vendor field"] += len(key_paths(document) - set(schema["key_paths"]))
            fields = schema["fields"]
            strict = []
            for value_path, value in values(document):
                if value_path in fields:
                    for variant in all_variants([value], found, decode_base64=False):
                        found.update(vendor_field_findings(fields[value_path], variant, asset_names))
                else:
                    strict.append(value)
            found.update(public_text_findings("\n".join(all_variants(strict, found, decode_base64=False)), asset_names))
    else:
        found.update(public_text_findings("\n".join(all_variants([text], collections.Counter(), decode_base64=False)), asset_names))
    return {kind: count for kind, count in found.items() if count}


def name_is_json(path):
    return path.endswith(".json")


def main():
    parser = argparse.ArgumentParser(description="Refuse private or laboratory details in public release assets; findings name only the file and the kind")
    parser.add_argument("directory")
    args = parser.parse_args()
    markers = privacy_rules()
    asset_names = {name.lower() for name in os.listdir(args.directory) if ASSET_NAME.fullmatch(name)}
    failed = 0
    for name in sorted(os.listdir(args.directory)):
        path = os.path.join(args.directory, name)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            failed += 1
            print("FAIL %s: not a regular file" % name)
            continue
        if not ASSET_NAME.fullmatch(name):
            failed += 1
            print("FAIL unexpected file name (not a release asset name)")
            continue
        if name.endswith(".sigstore.json"):
            continue
        try:
            findings = check_file(path, markers, asset_names)
        except UnicodeDecodeError:
            findings = {"invalid UTF-8": 1}
        except ValueError:
            findings = {"invalid JSON": 1}
        if findings:
            failed += 1
            print("FAIL %s: %s" % (name, ", ".join("%s x%d" % item for item in sorted(findings.items()))))
    print("report_gate=%s" % ("FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
