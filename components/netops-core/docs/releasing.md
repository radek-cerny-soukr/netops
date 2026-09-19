# Release process

Release tags follow the component scheme `<name>/v<version>`, where `<name>` is the project name
declared in this component's `pyproject.toml`: this component tags `netops-core/v0.1.0`, and the
release title is `netops-core 0.1.0`. Tags of another component are never touched by this procedure,
and the unprefixed tags `v0.1.0`, `v0.2.0`, `v0.2.1` are the history of `netops-helper`; they are
never moved, deleted, or recreated. The canonical origin is
`https://github.com/radek-cerny-soukr/netops`.

This component lives in the `netops` monorepo under `components/netops-core/`. Every command below
runs in that directory unless stated otherwise. The repository as a whole has its own gate,
`scripts/check_release.py` at the repository root, which verifies that no tracked file falls outside a
component release and then runs the gate of every component; run it before freezing a release.

Official releases are built on an isolated, trusted Linux ARM64 builder from a clean, signed commit.
Hosted CI performs portable source checks only; it is not the release builder.

Never publish surrounding private project context, environment-specific certificates, live reports,
credentials, host keys, or inventory and vault files. The release export is a positive allowlist, and
the component gate also reads the content of every released file and, outside a repository, holds the
exported tree to exactly the released selection.

## What 0.1.0 releases

This component releases **from source; it ships no container image**, because it is a library and
nothing in it runs on its own. The release carries four assets:

| asset | what it is |
|---|---|
| `netops-core-<version>-source.tar.gz` | the allowlisted source export, deterministic |
| `netops-core-<version>-source.cdx.json` | the CycloneDX dependency SBOM |
| `netops-core-<version>-release-SHA256SUMS` | checksums of the two payloads |
| `netops-core-<version>-release-SHA256SUMS.sigstore.json` | the Sigstore bundle over those checksums |

An image is not planned for a later version either: a component that runs brings its own image and
takes this library from the tree at build time. The library runs on any Python 3.13 host with nothing
installed beside the standard library.

## Procedure

1. Review every source change and freeze the release metadata, including the release date. Version
   `0.1.0` must agree in `pyproject.toml`, `src/netops_core/__init__.py`, and the root of
   `sbom.cdx.json`; the gate `version_metadata` compares those three. The changelog heading is not
   gated, but the publisher reads the release notes from the section it names, so it has to match too,
   and `## 0.1.0 - unreleased` becomes the release date in the same commit. Any later change to
   source, tests, release tooling, or the release date requires a new commit and a complete repeat of
   the remaining steps.
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

   The export destination must not already exist. Run the gate once more **inside** the export; away
   from a repository it also proves the exported tree matches the release selection and the manifest:

   ```bash
   (cd path/to/new-output/netops-core-<version> && python3 -B scripts/check_gates.py)
   ```
3. Create the final trusted signed commit on clean `main`, then, under a separate explicit
   authorization, the signed annotated tag `netops-core/v0.1.0` on that exact commit. Verify the tag
   resolves to a tag object, carries a trusted signature, and peels to the signed commit. Neither step
   authorizes a push, a build, or a transparency-log upload.
4. On the builder, place a clone of the repository at the released commit in `repos/netops-core` and
   run the source-only profile:

   ```bash
   RELEASE_COMPONENT=netops-core bash verify-host.sh
   ```

   The profile decides that this component has no image: the container build, the OCI archive, the
   digest comparison, and the runtime self-test are skipped, the component is checked with its own
   gate in addition to its test suite, which the builder installs from `requirements-release.lock`
   with `--require-hashes`, and the artifact names follow `netops-core-<version>-*`. The SBOM is not
   generated during the release: the committed one is regenerated, compared byte for byte, and then
   published as the asset. The run ends with
   `release_verification=passed ... component=netops-core platform=source-only`. An unknown component
   name is refused before the first container call.
5. Sign the checksum file. This writes to a public transparency log and is a separate authorized
   action; the signing identity must be the GitHub account, never another provider.
6. Publish in three separately authorized steps - `preflight`, `create-draft`, `publish-draft` - and
   then verify the published release independently: download every asset from the release page and
   check it against the local `SHA256SUMS`. The tag contains a slash, so in a download URL it is
   encoded as `netops-core%2Fv0.1.0`.

## Determinism

The source archive is byte-reproducible: entries are owned by `0/0`, carry a fixed modification time,
and the archive is created with an explicit mode normalization, so the umask of the builder does not
change the bytes. The SBOM is regenerated and compared byte for byte during step 2; a release whose
SBOM does not reproduce is not released.

## The dependency lock

`requirements-release.in` names only what the release toolbox needs: `cyclonedx-bom` to generate the
SBOM and `pytest` to run the suite. `requirements-release.lock` is compiled from it with
`--generate-hashes`, and the builder installs it with `--require-hashes`, so a package that does not
match its recorded hash stops the release. Nothing in that lock is a dependency of the library: the
component itself declares none.
