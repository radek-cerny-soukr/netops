# Release process

Release tags follow the component scheme `<project.name>/v<version>`, where `project.name` is the `[project]` `name` from the component's `pyproject.toml`: this component tags `netops-helper/v0.3.6`, and any further component released from this repository uses the same scheme under its own name. The release title is `<project.name> <version>`, for example `netops-helper 0.3.6`. Publishing a newer version leaves the release page and the tag of earlier versions in place. The repository was renamed from `netops-helper` to `netops` on 2026-09-11; the old URLs redirect, and the canonical origin is `https://github.com/radek-cerny-soukr/netops`.

This component lives in the `netops` monorepo under `components/netops-helper/`. Every command below runs in that directory; the repository as a whole has its own gate, `scripts/check_release.py` at the repository root, which verifies that no tracked file falls outside a component release and then runs the gate of every component. Run it before freezing a release, from the repository root.

Official releases are built on an isolated, trusted Linux ARM64 builder from a clean, signed commit. Hosted CI performs portable source checks only; it is not the release builder.

The guarded builder, source updater, checksum signer and publisher are separately provisioned maintainer tooling; they are not shipped in this repository or its source archives. References to `verify-host.sh` or publisher steps below require that reviewed environment. Source checks and export scripts shown here are repository tools.

Never publish surrounding private project context, environment-specific certificates, generated firewall bundles, live reports, credentials, host keys, deployment policy, or deployment scripts. The release export is a positive allowlist.

The current published release is linked from the [repository release table](https://github.com/radek-cerny-soukr/netops/blob/main/README.md#components). The procedure below describes a **new** release: `<version>` means the newly reviewed version from this component's `pyproject.toml`, not an instruction to recreate the current tag. Confirm that its tag and release do not already exist. Published tags and assets must not be moved or overwritten.

1. Review every source change and freeze the release metadata, including the actual release date. Ensure the new version agrees in `pyproject.toml`, `src/netops_helper/__init__.py`, release tooling, Compose image label, SBOM metadata, and changelog. Any later source, release-date, test, ignore-rule, or release-tool change requires a new commit and a complete repeat of the remaining procedure.
2. Decide whether dependency inputs changed. For an application-code/version-only release, keep both hash lockfiles byte-identical. If `requirements.txt`, `requirements-release.in`, a dependency, index policy, Python baseline, or lock generator changes, first pin and record the exact reviewed generator environment, then regenerate both locks and review the complete dependency/license diff. The current Helper lock headers record `pip-tools==7.6.1` and Python 3.14.7. The complete reviewed generator environment is recorded below.
3. Run the portable dependency-free contracts, regenerate the committed CycloneDX dependency SBOM, require a byte-clean SBOM result, run the public release gate, and inspect an allowlisted source export:

   ```bash
   (cd ../.. && python scripts/check_release.py)
   PYTHONPATH=src:../netops-core/src python tests/run_tests.py
   python scripts/generate_sbom.py
   git diff --exit-code -- sbom.cdx.json
   python scripts/check_public_release.py
   python scripts/create_release_artifacts.py --output path/to/new-output
   ```

   The export destination must not already exist. Review the complete diff and exported tree before signing.
4. Create the final trusted signed commit on clean `main`. Verify its signature against the release trust root, its exact object ID, the canonical origin, the absence of replace refs, and a clean tracked and untracked status. Do not create a tag or perform any public write as part of the commit operation.
5. After a separate explicit authorization for this local Git mutation, create the signed annotated tag `netops-helper/v<version>` on that exact commit. Verify that the ref resolves to a tag object, its trusted signature is valid, and it peels to the signed `main` commit. This authorization does not authorize a bundle transfer, build, transparency-log upload, branch push, tag push, or release operation.
6. Create one bounded Git bundle whose advertised refs are exactly `refs/heads/main` and the release tag `refs/tags/netops-helper/v<version>`; do not use `--all`. Other components have their own tags; they are outside this component bundle and must remain untouched in the canonical repository.

   ```bash
   release_version="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
   git bundle create "netops-helper-${release_version}.bundle" \
     refs/heads/main "refs/tags/netops-helper/v${release_version}"
   git bundle verify "netops-helper-${release_version}.bundle"
   ```

   Create it at a new path and never overwrite an existing bundle. Before transfer, require that its advertised ref set matches exactly, reject replace refs, verify the trusted signature of the selected `main` commit and every annotated tag, verify each tag's reviewed peel target, and require `netops-helper/v<version>` to match the canonical project version and peel to `main`.
7. Transfer the verified bundle only through the guarded source updater. Before replacing any builder repository, it must inspect the bundle and independently verify the exact advertised refs, object types, trusted commit and tag signatures, peel targets, project version, clean `main`, canonical origin, and absence of replace refs. It must clone only into a new staging repository, then repeat those checks after the clone and before an atomic repository exchange. The staged and resulting builder repositories must retain exactly `netops-helper/v<version>` as the required release tag; in particular, `netops-helper/v<version>` must remain a trusted annotated tag peeled to builder `HEAD`. A branch-only clone, a clone that drops any required tag, or any failed pre-exchange or post-clone check must fail before the ARM64 build.
8. In the isolated builder, install `requirements-release.lock` with `--require-hashes`, run the portable contracts, full pytest, and the mandatory runtime suite, and reproduce the committed dependency SBOM byte-for-byte:

   ```bash
   PYTHONPATH=src:../netops-core/src python tests/run_tests.py
   PYTHONPATH=src:../netops-core/src python tests/test_engine_contracts.py
   python tests/test_proxy_contracts.py
   python tests/test_egress_scripts.py
   python tests/test_apply_egress_rules.py
   NETOPS_REQUIRE_RUNTIME_TESTS=1 python -m pytest -q
   python scripts/generate_sbom.py
   git diff --exit-code -- sbom.cdx.json
   python scripts/check_public_release.py
   ```

   The environment flag makes a missing runtime dependency fail collection instead of silently skipping the FortiOS wire-level test.
9. Create the allowlisted source tree with `scripts/create_release_artifacts.py`. The export carries `src/netops_core` next to `src/netops_helper`, so the image is built from the export directory with the default build arguments of the `Dockerfile` (`COMPONENT_DIR=.`, `CORE_PACKAGE_DIR=src/netops_core`); building from the repository root instead needs the two arguments `compose.yaml` passes. Docker Buildx runs only on this export; the release toolbox must not mount the host Docker socket. Build and test the Linux ARM64 image from the exact commit already bound to `netops-helper/v<version>`.
10. Record the ARM64 OCI image digest, generate an image SBOM, and scan it with a current Grype vulnerability database. Run the release gate against the actual report:

    ```bash
    python scripts/check_public_release.py --grype-report path/to/grype-report.json
    ```

    The gate requires both `matches` and `ignoredMatches`, reports active and ignored counts for every severity, fails on active Critical findings, and requires rule attribution for ignored Critical findings. Counts from an earlier scan are context, not a threshold for the current build. Review every active High/Medium finding and every ignored item; the command is not a substitute for risk analysis.
11. Recreate the source export with the image digest, produce a deterministic source archive, and generate one SHA-256 manifest covering every published artifact. If the build or review fails, stop without pushing or silently moving, deleting, or recreating `netops-helper/v<version>`; any recovery from an unpublished tag requires a separately reviewed local procedure and a complete rebuild of the selected final commit.
12. Only after the ARM64 build, runtime tests, SBOMs, vulnerability review, and release artifacts pass, request separate explicit approval for the public transparency-log write. Then run the guarded checksum-signing step with exact certificate identity and OIDC issuer values. It must refuse an existing signature bundle, fingerprint the release set before and after signing, verify the result offline, promote without overwrite, and preserve a failed private attempt for diagnosis. Approval for this transparency-log entry authorizes no public Git repository or release mutation.
13. Treat branch push, tag push, draft creation, and draft publication as four independent public mutations. Immediately before each one, repeat its applicable preflight and obtain a separate explicit approval naming the exact operation. Push only the clean signed commit and the already verified tag; create the draft with the source archive, ARM64 OCI archive, image SBOM, complete Grype JSON, image digest, checksums, and signature bundle.
14. Independently verify hosted checks for both pushed refs, the draft metadata, every artifact byte and digest, the signature, source allowlist, runtime wire test, and vulnerability counts before separately authorizing draft publication.

The release target is Linux ARM64. Cross-building amd64 is intentionally excluded because it would require privileged host-level binfmt/QEMU setup. Other architectures can build reviewed source, but those builds are outside the official verification claim.

Changing an image digest, lock, snapshot date, ignore rule, release test, or release tool is a reviewed source change. Pinning improves repeatability; it does not prove safety. The section below says exactly which pin buys which guarantee, and names the one layer that deliberately has none.

## Reproducibility of the image

Two builds of the same signed commit are not guaranteed to be byte-identical, and that is a reviewed, deliberate property of this image, not an oversight.

What IS reproducible from one build of a given commit to the next:

- the base image, pinned by its full `sha256` digest on the Dockerfile's first line;
- the Python dependencies, installed with `--require-hashes` from `requirements.lock` (runtime) or `requirements-release.lock` (release tooling), so every wheel is fixed by content hash, not by version number alone;
- the exported source tree: `scripts/create_release_artifacts.py` selects an exact allowlisted file set and writes `release-manifest.json` and `SHA256SUMS` with a SHA-256 for every file in it, so the source that reaches the builder is byte-for-byte the reviewed commit.

What is NOT reproducible: the one distribution package the Dockerfile installs on top of that pinned base, `apt-get install --yes --no-install-recommends openssh-client`. That command resolves against Debian's live archive for the base image's suite (trixie) at whatever moment the build runs. The suite keeps receiving point releases and security updates, so a build today and a build of the exact same commit next month can install two different `openssh-client` versions, and transitively different versions of the libraries it pulls in, even though neither the Dockerfile line nor the base image digest changed.

What that means in practice: the exact `openssh-client` version a given build carries is not written down anywhere in the Dockerfile or the source tree. It is only recorded after the build, in that release's CycloneDX image SBOM and in the Grype report scanned against that same image. Two builds of one commit can therefore carry different `openssh-client` versions and a different vulnerability count for it; that is expected, not a sign of a broken pin. Treat the SBOM and Grype report of the image you actually built as authoritative, never a previous release's numbers - see [Known vulnerability findings](known-vulnerabilities.md).

This was considered and rejected as a defect to fix. Freezing the distribution layer against a dated snapshot (for example, an archive mirror pinned to one day) would make a rebuild byte-for-byte reproducible, at the cost of also freezing whichever package version that day's snapshot happened to carry. `openssh-client` is exactly the package this release ships with a known unfixed Critical CVE in (see [Known vulnerability findings](known-vulnerabilities.md)); pinning it to a snapshot would freeze that exposure in place and remove the one way this project currently sheds it without a source change - a later Debian point release carrying a fixed `openssh-client` reaching a plain rebuild on its own. Digest-pinning the base image already buys determinism for the interpreter and the base OS layer. Leaving this one package unpinned, so that a rebuild picks up its security updates automatically, is a trade-off made in favor of receiving those updates, at the cost of that one layer's build being reproducible.

## After publication

After the new release is published and independently verified, update the current-version links in the repository documentation and check every release, tag and download URL against the public release and tag lists. The previous release page, its assets and its tag stay. Removing one is a separate decision that needs explicit authorization for that exact deletion and a local archive of its assets first; other components' releases and tags are never touched.

## Lock generator environment

The 2026-09-20 dependency update used Python 3.13.15 and the following hash-pinned generator wheels. Install these exact wheels with `pip install --require-hashes` before invoking the command recorded in each lock header. Package indexes can change; the committed application lockfiles are the authoritative dependency selection.

```text
build==1.6.1 --hash=sha256:ecd351a4be9d35a9eaaba244a7687143c9c7d4aea6ac964e7e7ddab20cbcf4e7
click==8.5.0 --hash=sha256:255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360
packaging==26.3 --hash=sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c
pip==26.2.1 --hash=sha256:71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e
pip-tools==7.6.1 --hash=sha256:6111c8b4b07fd14b7223ca921485b0e96cf66e20bf94da95eeed9845f510cb8f
pyproject_hooks==1.3.3 --hash=sha256:5fc53fdac9f7bd63fbcdc868fb5f90b4784d78a53a3d3388cd738b807441a20b
setuptools==84.0.0 --hash=sha256:51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670
wheel==0.48.0 --hash=sha256:3217dcc807155e45db462d7ef2431f5ddda0d7273b700d05a67b271ceb1287ab
```

The image build refreshes Debian package indexes and upgrades installed distribution packages before installing `openssh-client`. The base image digest and Python patch release remain pinned; the resulting OS package versions are captured by the image SBOM and scan. This preserves the documented limit that the OS layer is not bit-for-bit reproducible across repository updates.

## Runtime update on 2026-09-21

The Helper image and its CI job use Python 3.14.7. Both Helper lockfiles were regenerated with the same hash-pinned generator wheels listed above under Python 3.14.7, without upgrading package versions. Core and Auditor retain their Python 3.13 minimum. The runtime TAR regression must fail on the vulnerable 3.13.15 image and pass on the shipped image; it also checks valid file and hard-link extraction. Run `python tests/test_runtime_tar_safety.py` with the image interpreter.

### Portable proxy error regression

The deeply nested array fixture is valid JSON but not a supported JSON-RPC object. Depending on the interpreter build, decoding can fail at its nesting limit or succeed and reach the proxy object check. Test refusal in both cases (`-32700` and `-32600`, respectively), while retaining strict parse-error checks for malformed JSON, invalid encoding and oversized input. Also verify that a subsequent valid request still works; do not depend on one platform's parser recursion limit.
