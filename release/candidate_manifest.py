#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import shutil
import sys

from sbom_gate import SBOMError, validate_sbom

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
ARCHES = ("amd64", "arm64")
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
ORDER = {"pass": 0, "needs-assessment": 1, "fail": 2, "unknown": 3}


class ManifestError(Exception):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def check_index(raw, digests):
    if raw.get("mediaType") not in INDEX_TYPES:
        raise ManifestError("index media type %r is not an image index" % raw.get("mediaType"))
    found = {}
    for entry in raw.get("manifests", []):
        platform = entry.get("platform", {})
        if platform.get("os") == "unknown":
            raise ManifestError("index carries an attestation manifest; build without provenance/sbom attestations")
        if platform.get("os") != "linux" or platform.get("architecture") not in ARCHES:
            raise ManifestError("unexpected platform %r" % platform)
        if platform["architecture"] in found:
            raise ManifestError("duplicate architecture " + platform["architecture"])
        found[platform["architecture"]] = entry.get("digest")
    if found != digests:
        raise ManifestError("index platforms %r do not match built digests %r" % (found, digests))


def pinned_env(source, image, index_digest):
    lines, pinned = [], 0
    with open(source, encoding="utf-8") as stream:
        for line in stream.read().splitlines():
            if line.startswith("NETOPS_IMAGE="):
                line = "NETOPS_IMAGE=%s@%s" % (image, index_digest)
                pinned += 1
            lines.append(line)
    if pinned != 1:
        raise ManifestError("env example must contain exactly one NETOPS_IMAGE line, found %d" % pinned)
    return "\n".join(lines) + "\n"


def build(args):
    if not COMMIT.fullmatch(args.commit):
        raise ManifestError("commit must be 40 hex characters")
    if not DIGEST.fullmatch(args.index_digest):
        raise ManifestError("index digest malformed")
    if not VERSION.fullmatch(args.version):
        raise ManifestError("version must be X.Y.Z")
    digests = {}
    for arch in ARCHES:
        with open(os.path.join(args.dir, "digest-%s.txt" % arch), encoding="utf-8") as stream:
            value = stream.read().strip()
        if not DIGEST.fullmatch(value):
            raise ManifestError("digest for %s malformed" % arch)
        digests[arch] = value
    if len(set(digests.values())) != len(ARCHES):
        raise ManifestError("architectures share one digest")
    with open(args.index_raw, encoding="utf-8") as stream:
        check_index(json.load(stream), digests)
    for arch in ARCHES:
        validate_sbom(os.path.join(args.dir, "sbom-%s.cdx.json" % arch), args.image, digests[arch])
    prefix = "netops-%s" % args.version
    os.makedirs(args.release_dir, exist_ok=True)
    if os.listdir(args.release_dir):
        raise ManifestError("release directory is not empty")
    shutil.copyfile(args.compose, os.path.join(args.release_dir, "compose.yaml"))
    with open(os.path.join(args.release_dir, "env.example"), "w", encoding="utf-8") as stream:
        stream.write(pinned_env(args.env, args.image, args.index_digest))
    images, worst = {}, "pass"
    for arch in ARCHES:
        files = {}
        for kind, source, target in (("sbom", "sbom-%s.cdx.json", "%s-linux-%s.cdx.json"),
                                     ("scan", "grype-%s.json", "%s-linux-%s-grype.json"),
                                     ("gate", "gate-%s.json", "%s-linux-%s-gate.json")):
            name = target % (prefix, arch)
            shutil.copyfile(os.path.join(args.dir, source % arch), os.path.join(args.release_dir, name))
            files[kind] = {"file": name, "sha256": sha256_file(os.path.join(args.release_dir, name))}
        with open(os.path.join(args.dir, "gate-%s.json" % arch), encoding="utf-8") as stream:
            status = json.load(stream).get("status", "unknown")
        if status not in ORDER:
            status = "unknown"
        worst = max(worst, status, key=ORDER.get)
        images[arch] = {"platform": "linux/" + arch, "digest": digests[arch], "files": files, "vulnerability_gate": status}
    if args.assessments:
        with open(args.assessments, encoding="utf-8") as stream:
            entries = json.load(stream)
        if not isinstance(entries, list) or any(not (e.get("id") and e.get("package") and e.get("reasoning") and "exploitable" in e) for e in entries):
            raise ManifestError("vulnerability assessments must be a list of id, package, exploitable and reasoning")
        shutil.copyfile(args.assessments, os.path.join(args.release_dir, prefix + "-vulnerability-assessments.json"))
    release_files = {name: sha256_file(os.path.join(args.release_dir, name)) for name in ("compose.yaml", "env.example")}
    manifest = {"schema": "netops-release-candidate/1", "product": "netops", "version": args.version,
                "source": {"repository": args.repository, "commit": args.commit},
                "build": {"workflow_run_id": args.run_id, "workflow_run_attempt": args.run_attempt},
                "image": {"name": args.image, "index_digest": args.index_digest, "platforms": images},
                "release_files": release_files, "vulnerability_gate": worst}
    manifest_name = prefix + "-manifest.json"
    with open(os.path.join(args.release_dir, manifest_name), "w", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=1, sort_keys=True)
        stream.write("\n")
    names = sorted(n for n in os.listdir(args.release_dir))
    with open(os.path.join(args.release_dir, prefix + "-SHA256SUMS"), "w", encoding="utf-8") as stream:
        for name in names:
            stream.write("%s  %s\n" % (sha256_file(os.path.join(args.release_dir, name)), name))
    return manifest, manifest_name


def main():
    parser = argparse.ArgumentParser()
    for name in ("version", "repository", "commit", "image", "index-digest", "index-raw", "run-id", "run-attempt", "dir",
                 "compose", "env", "release-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--assessments")
    args = parser.parse_args()
    try:
        manifest, name = build(args)
    except (ManifestError, SBOMError, OSError, ValueError) as error:
        print("candidate_manifest=failed: %s" % error, file=sys.stderr)
        return 1
    print("candidate_manifest=written %s vulnerability_gate=%s index=%s" % (name, manifest["vulnerability_gate"], args.index_digest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
