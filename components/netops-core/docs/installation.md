# Installation

These instructions install netops-core 0.2.9 from its matching versioned source assets. Verify the release checksums and provenance before installation.

`netops-core` is a library: the components that use it install it beside themselves, as their own installation guides describe. This guide installs it on its own, into a private environment of the user, for a program of your own or to check a release. It needs Python 3.13 or newer with its `venv` module, `curl` and `cosign`; [Tools on the installing host](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#tools-on-the-installing-host) shows how to get them.

## From the release archive

Download the source archive with the release `SHA256SUMS` and its Sigstore bundle, verify the bundle with `cosign` and the archive against `SHA256SUMS`, and stop if either check fails:

```sh
for release in netops-core:0.2.9; do
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
```

`cosign` must report `Verified OK` and `sha256sum` `OK` for every file; [Verifying a release](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#verifying-a-release) describes the check. The first command below stops when `python3` is older than 3.13. The lock carries only the test and SBOM tools, since the library itself has no dependency. `pip` writes build metadata into the directory it installs from, so install from a copy and keep the unpacked archive unchanged; the local `umask 022` keeps the generated `netops-askpass` launcher from being group-writable:

```sh
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else "Python 3.13 or newer is required")' || exit 1
(umask 022; python3 -m venv "$HOME/.local/share/netops-core/venv") || exit 1
(umask 022; "$HOME/.local/share/netops-core/venv/bin/python" -m pip install --require-hashes -r netops-core-0.2.9/requirements-release.lock) || exit 1
build_dir=$(mktemp -d ./netops-build.XXXXXXXXXX) || exit 1
cp -r netops-core-0.2.9 "$build_dir/" || exit 1
(umask 022; "$HOME/.local/share/netops-core/venv/bin/python" -m pip install --no-deps "$build_dir/netops-core-0.2.9") || exit 1
rm -rf -- "$build_dir" || exit 1
```

If installation stops, restore the missing prerequisite or network access and repeat the installation block. Each attempt creates a fresh build directory, so files left by an earlier build cannot enter the installed package. After a successful installation the block removes only that attempt's source copies; an interrupted attempt may leave its disposable directory behind. Keep the verified source archive unchanged.

Check the installed version, the test suite and then the gate of the unpacked archive. `-B` and `-p no:cacheprovider` keep `__pycache__` and `.pytest_cache` out of the archive, whose gate refuses any file outside its release selection, so the gate after the suite also shows that the tests left no file behind:

```sh
"$HOME/.local/share/netops-core/venv/bin/python" -c 'from importlib.metadata import version; print(version("netops-core"))' || exit 1
(cd netops-core-0.2.9 && PATH="$HOME/.local/share/netops-core/venv/bin:$PATH" NETOPS_REQUIRE_INSTALLED_PACKAGE_TESTS=1 python3 -B -m pytest -q -p no:cacheprovider) || exit 1
(cd netops-core-0.2.9 && "$HOME/.local/share/netops-core/venv/bin/python" -B scripts/check_gates.py) || exit 1
(cd netops-core-0.2.9 && sha256sum -c --quiet SHA256SUMS) || exit 1
```

The first command prints `0.2.9`, the suite ends with no failure, the gate with `core_gates=passed`, and the last command shows that every file of the archive is unchanged. `NETOPS_REQUIRE_INSTALLED_PACKAGE_TESTS=1` turns a missing `netops-askpass` on `PATH` into a failure instead of a skipped test.

PyPI is a delayed, separate publication channel. Check exact-version availability and the component's dependency pins before installing from the index. The release pages remain authoritative; PyPI files are not covered by the GitHub release assets' Sigstore bundles. See [the distribution boundary](releasing.md#pypi-a-delayed-channel).
