# Installation

These instructions install netops-auditor 0.2.12 from its matching versioned source assets. Verify the release checksums and provenance before installation.

`netops-auditor` runs on Python 3.13 or newer. It needs `netops-core` of exactly the pinned version beside it, and `fastmcp` only for the MCP surface. This guide installs both components from their release archives into a private environment of the user. It needs the `venv` module of Python, `curl` and `cosign`; [Tools on the installing host](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#tools-on-the-installing-host) shows how to get them.

## From the release archives

Download the source archive of each component with the release `SHA256SUMS` and its Sigstore bundle from its release page, `netops-core` 0.2.9 and `netops-auditor` 0.2.12. Verify the bundle with `cosign` and the archive against `SHA256SUMS`, stop if either check fails, and unpack both archives in the same directory:

```sh
for release in netops-core:0.2.9 netops-auditor:0.2.12; do
  component=${release%%:*}
  version=${release#*:}
  base="https://github.com/radek-cerny-soukr/netops/releases/download/${component}%2Fv${version}"
  for name in source.tar.gz release-SHA256SUMS release-SHA256SUMS.sigstore.json; do
    curl -fsSLO "${base}/${component}-${version}-${name}" || exit 1
  done
  cosign verify-blob \
    --bundle "${component}-${version}-release-SHA256SUMS.sigstore.json" \
    --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
    --certificate-oidc-issuer https://github.com/login/oauth \
    "${component}-${version}-release-SHA256SUMS" || exit 1
  sha256sum --check --ignore-missing "${component}-${version}-release-SHA256SUMS" || exit 1
done
tar -xzf netops-core-0.2.9-source.tar.gz || exit 1
(cd netops-core-0.2.9 && sha256sum -c SHA256SUMS) || exit 1
tar -xzf netops-auditor-0.2.12-source.tar.gz || exit 1
(cd netops-auditor-0.2.12 && sha256sum -c SHA256SUMS) || exit 1
```

`cosign` must report `Verified OK` and `sha256sum` `OK` for every file; [Verifying a release](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#verifying-a-release) describes the check. The first command below stops when `python3` is older than 3.13. The lock pins `fastmcp` and its dependencies, which only the MCP surface uses, and the test and SBOM tools. `pip` writes build metadata into the directory it installs from, so install from copies and keep the unpacked archives unchanged; the local `umask 022` keeps the generated launchers from being group-writable. The paths start with `./`: a bare directory name would make `pip` look the name up on the package index.

```sh
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else "Python 3.13 or newer is required")' || exit 1
(umask 022; python3 -m venv "$HOME/.local/share/netops-auditor/venv") || exit 1
(umask 022; "$HOME/.local/share/netops-auditor/venv/bin/python" -m pip install --require-hashes -r netops-auditor-0.2.12/requirements-release.lock) || exit 1
build_dir=$(mktemp -d ./netops-build.XXXXXXXXXX) || exit 1
cp -r netops-core-0.2.9 netops-auditor-0.2.12 "$build_dir/" || exit 1
(umask 022; "$HOME/.local/share/netops-auditor/venv/bin/python" -m pip install --no-deps "$build_dir/netops-core-0.2.9" "$build_dir/netops-auditor-0.2.12") || exit 1
rm -rf -- "$build_dir" || exit 1
```

If installation stops, restore the missing prerequisite or network access and repeat the installation block. Each attempt creates a fresh build directory, so files left by an earlier build cannot enter the installed package. After a successful installation the block removes only that attempt's source copies; an interrupted attempt may leave its disposable directory behind. Keep the verified source archive unchanged.

Check the installed version, the command, the test suite and then the gate of the unpacked archive. `-B` and `-p no:cacheprovider` keep `__pycache__` and `.pytest_cache` out of the archive, whose gate refuses any file outside its release selection; `PYTHONDONTWRITEBYTECODE=1` does the same for the interpreters the tests start, which `-B` does not reach. The gate after the suite therefore also shows that the tests left no file behind. The tests take `netops-core` from the sibling `../netops-core-0.2.9`:

```sh
"$HOME/.local/share/netops-auditor/venv/bin/python" -c 'from importlib.metadata import version; print(version("netops-auditor"))' || exit 1
"$HOME/.local/share/netops-auditor/venv/bin/netops-auditor" --help > /dev/null || exit 1
(cd netops-auditor-0.2.12 && PYTHONDONTWRITEBYTECODE=1 "$HOME/.local/share/netops-auditor/venv/bin/python" -B -m pytest -q -p no:cacheprovider) || exit 1
(cd netops-auditor-0.2.12 && "$HOME/.local/share/netops-auditor/venv/bin/python" -B scripts/check_gates.py) || exit 1
(cd netops-auditor-0.2.12 && sha256sum -c --quiet SHA256SUMS) || exit 1
```

The first command prints `0.2.12`, the suite ends with no failure, the gate with `auditor_gates=passed`, and the last command shows that every file of the archive is unchanged. Launch the installed command by its absolute path above, or add that environment's `bin` directory to `PATH`; [Running it](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/README.md#running-it) and [configuration](configuration.md) continue from there.

PyPI is a delayed, separate publication channel. Check exact-version availability and the component's dependency pins before installing from the index. The release pages remain authoritative; PyPI files are not covered by the GitHub release assets' Sigstore bundles. See [the distribution boundary](releasing.md#pypi-a-delayed-channel).

## MCP environment

Before launching `python -B -m netops_auditor.mcp_server`, set all three required variables:

| Variable | Value |
|---|---|
| `NETOPS_AUDITOR_STORE` | Existing readable SQLite audit store at the current schema version; opened read-only |
| `NETOPS_AUDITOR_TENANT` | Tenant whose finished audit results the server may read |
| `NETOPS_AUDITOR_CATALOG` | Catalogue name `fortios` or `exos`, not a filename |
| `NETOPS_AUDITOR_SUPPRESSIONS` | Optional version-2 suppression file bound to that tenant; unset means no suppressions |
| `NETOPS_AUDITOR_SCHEMA_REPORTS` | Optional operator manifest for pinned finished schema reports; required only for `schema_report` |

For example, after the CLI has written the store:

```sh
NETOPS_AUDITOR_STORE=/path/to/audit.sqlite3 \
NETOPS_AUDITOR_TENANT=demo \
NETOPS_AUDITOR_CATALOG=fortios \
python -B -m netops_auditor.mcp_server
```

The server refuses startup if a required variable is empty, the store cannot be opened read-only at the current schema version, the catalogue is unknown or the supplied suppression file is invalid. It requires the pinned FastMCP runtime. Its seven tools are `audit_status`, `list_rules`, `rule_detail`, `list_findings`, `finding_detail`, `compare` and `schema_report`; none collects a configuration or reaches a device.
