# Release process

Release tags follow the component scheme `<name>/v<version>`, where `<name>` is the project name
declared in this component's `pyproject.toml`: this component tags
`netops-auditor/v0.2.2`, and the release title is `netops-auditor 0.2.2`. Tags of another component
are never touched by this procedure. A tag is deleted together with its release page when a newer
version of the same component is published. The canonical origin is
`https://github.com/radek-cerny-soukr/netops`.

**This repository keeps exactly one release page and one tag per component.** Publishing a version
removes the release page, the four downloadable assets and the tag of the version it replaces. Every
release stays in the history as one signed commit on `main` whose message names the component and the
version, so a reader who wants an earlier version works from that commit and this procedure, never
from a page, a tag or an asset link that no longer exists.

This component lives in the `netops` monorepo under `components/netops-auditor/`. Every command below
runs in that directory unless stated otherwise. The repository as a whole has its own gate,
`scripts/check_release.py` at the repository root, which verifies that no tracked file falls outside a
component release and then runs the gate of every component; run it before freezing a release.

Official releases are built on an isolated, trusted Linux ARM64 builder from a clean, signed commit.
Hosted CI performs portable source checks only; it is not the release builder.

The guarded builder, source updater, checksum signer and publisher are separately provisioned maintainer tooling; they are not shipped in this repository or its source archives. References to `verify-host.sh` or publisher steps below require that reviewed environment. Source checks and export scripts shown here are repository tools.

Never publish surrounding private project context, environment-specific certificates, live reports,
credentials, host keys, or inventory and vault files. The release export is a positive allowlist, and
the component gate also reads the content of every released file and, outside a
repository, holds the exported tree to exactly the released selection.

## What 0.2.2 releases

This component releases **from source; it ships no container image**. The release carries four assets:

| asset | what it is |
|---|---|
| `netops-auditor-<version>-source.tar.gz` | the allowlisted source export, deterministic |
| `netops-auditor-<version>-source.cdx.json` | the CycloneDX dependency SBOM |
| `netops-auditor-<version>-release-SHA256SUMS` | checksums of the two payloads |
| `netops-auditor-<version>-release-SHA256SUMS.sigstore.json` | the Sigstore bundle over those checksums |

An image, and the three assets that come with one, are planned for a later version. Until then the
component runs from the unpacked archive on any Python 3.13 host.

### It needs `netops-core` beside it

The auditor reads the inventory, the credential store, the host key trust and the SSH
transport from `netops-core`, and `pyproject.toml` pins it as `netops-core==0.2.1`. There is no index
to resolve that pin against: **the operator installs the `netops-core` source archive of exactly that
version next to the auditor**. Download it from the current
[`netops-core/v0.2.1`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-core%2Fv0.2.1)
release, unpack `netops-core-0.2.1-source.tar.gz`, verify its checksums, and
either install the unpacked directory into the same environment or put its `src` on `PYTHONPATH`. In
this repository the archive is the tree, so the tests and the CI job take the component from
`../netops-core/src`: `pyproject.toml` carries it in `[tool.pytest.ini_options] pythonpath` and
`tests/conftest.py` inserts it. Nothing else is required: `netops-core` is standard library only, and
`fastmcp` is needed solely for the MCP surface.

## Procedure

The current published release is linked from the [repository release table](https://github.com/radek-cerny-soukr/netops/blob/main/README.md#releases). The procedure below describes a **new** release: `<version>` means the newly reviewed version from this component's `pyproject.toml`, not an instruction to recreate the current tag. Confirm that its tag and release do not already exist. Published tags and assets must not be moved or overwritten.

1. Review every source change and freeze the release metadata, including the release date. The new
   version must agree in `pyproject.toml`, `src/netops_auditor/__init__.py`, and the root of
   `sbom.cdx.json`; the gate `version_metadata` compares those three. The pinned version of
   `netops-core` must agree with the version of the component that is released beside it; the SBOM
   carries the pin as the one required dependency of the root component. The changelog heading is not
   gated, but the publisher reads the release notes from the section it names, so it has to match too. Any later change to source, tests, release
   tooling, or the release date requires a new commit and a complete repeat of the remaining steps.
2. Run the portable checks, regenerate the committed SBOM, require it byte-identical, run the
   component gate, and inspect an allowlisted export:

   ```bash
   (cd ../.. && python3 scripts/check_release.py)
   (cd ../.. && python3 tests/test_release_gate.py)
   python3 -m pytest -q
   python3 scripts/generate_sbom.py
   git diff --exit-code -- sbom.cdx.json
   python3 scripts/check_gates.py
   python3 scripts/create_release_artifacts.py --output path/to/new-output
   ```

   The test suite reads `netops-core` from `../netops-core/src`; away from this tree, put the
   unpacked source archive of the pinned version there or on `PYTHONPATH`.

   The export destination must not already exist. Run the gate once more **inside** the export; away
   from a repository it also proves the exported tree matches the release selection and the manifest:

   ```bash
   (cd path/to/new-output/netops-auditor-<version> && python3 -B scripts/check_gates.py)
   ```
3. Create the final trusted signed commit on clean `main`, then, under a separate explicit
   authorization, the signed annotated tag `netops-auditor/v<version>` on that exact commit. Verify the
   tag resolves to a tag object, carries a trusted signature, and peels to the signed commit. Neither
   step authorizes a push, a build, or a transparency-log upload.
4. On the builder, place a clone of the repository at the released commit in `repos/netops-auditor`
   and run the source-only profile:

   ```bash
   RELEASE_COMPONENT=netops-auditor bash verify-host.sh
   ```

   The profile decides that this component has no image: the container build, the OCI archive, the
   digest comparison, and the runtime self-test are skipped, the component is checked with its own
   gates in addition to its test suite, which the builder installs from `requirements-release.lock`
   with `--require-hashes`, and the artifact names follow `netops-auditor-<version>-*`. The SBOM is
   not generated during the release: the committed one is regenerated, compared byte for byte, and
   then published as the asset.
   The run ends with `release_verification=passed ... component=netops-auditor platform=source-only`.
   An unknown component name is refused before the first container call.
5. Sign the checksum file. This writes to a public transparency log and is a separate authorized
   action; the signing identity must be the GitHub account, never another provider.
6. Run the applicable preflight immediately before each public write. Branch push, tag push,
   draft creation with asset upload, and draft publication are separately authorized operations.
   Verify hosted checks, draft metadata, artifact bytes, checksums and the signature before
   publishing the draft. Then download every published asset and compare it with the local
   `SHA256SUMS`. The tag contains a slash, so in a download URL it is
   encoded as `netops-auditor%2Fv<version>`.

## Determinism

The source archive is byte-reproducible: entries are owned by `0/0`, carry a fixed modification time,
and the archive is created with an explicit mode normalization, so the umask of the builder does not
change the bytes. The SBOM is regenerated and compared byte for byte during step 2; a release whose
SBOM does not reproduce is not released.

## Replacing the previous public release

After the new release is published and independently verified, remove only this component's previous release page, its assets and its tag under explicit authorization for those exact deletions. Preserve any required rollback artifacts locally first. Other components' releases and tags remain untouched. Recheck the public release and tag lists, update the current-version links in the repository documentation, and check every release, tag and download URL against those lists. Do not link to a superseded tag: use a commit permalink for historical source.
