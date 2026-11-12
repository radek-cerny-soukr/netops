# Qualification of the single NetOps image

Build production once. The separate tester starts FROM that exact image digest, adds hash-locked test tools in its own environment and verifies active engine bytes against the installed wheel. Application files and production dependencies are not rebuilt or replaced.

Use the source commit recorded in the verified release manifest. Set `NETOPS_IMAGE` to its complete ghcr image reference with `@sha256:...` and `CANDIDATE_COMMIT` to its source commit. Run the commands from that source checkout. The Dockerfile-specific ignore file admits test sources without changing the production build context.

Reports must be written to persistent bind mounts: a tmpfs disappears when the container exits, so it cannot be recovered with docker cp afterwards. The qualification parent is private; only the individual mounted report directories permit the tester UID to write.

```sh
: "${NETOPS_IMAGE:?Set the verified complete image digest reference}"
: "${CANDIDATE_COMMIT:?Set the verified source commit}"
umask 077
mkdir -p qualification
chmod 0700 qualification
docker build --build-arg NETOPS_TEST_IMAGE="$NETOPS_IMAGE" -f release/engine-regression.Dockerfile -t netops-engine-tests .
failed=0
for role in core helper auditor admin; do
    mkdir -p "qualification/$role"
    chmod 0777 "qualification/$role"
    status=0
    docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 2g --cpus 2 --tmpfs /tmp:rw,nosuid,nodev,exec,size=512m,mode=1777 --tmpfs /pytmp:rw,nosuid,nodev,exec,size=512m,mode=1777 --mount "type=bind,source=$PWD/qualification/$role,target=/reports" netops-engine-tests --role "$role" --candidate-commit "$CANDIDATE_COMMIT" --candidate-image "${NETOPS_IMAGE#*@}" --output /reports/engine-report.json > "qualification/$role.log" 2>&1 || status=$?
    printf '%s\n' "$status" > "qualification/$role.exit"
    if [ "$status" -ne 0 ]; then failed=1; fi
done
test "$failed" -eq 0
```

Preserve logs, exit codes and reports on every outcome. Run on both supported architectures. A report from another candidate, rebuild or architecture is not replacement evidence.

The engine regression runs only `components/<role>/tests`. The product contract tests in `tests/v1` (for example the FortiADC F1 contract `test_fortiadc_f1_contract.py`) are copied into the production image as `/opt/netops/tests` and form the installed-image unit test layer. It runs from the same production image, in `ci.yml` (on every push and pull request, amd64 runner `ubuntu-24.04` only) and in the candidate workflow `candidate.yml` from the pushed digest on both architectures, amd64 and arm64; qualification from a source checkout runs it with the same command and requires exit status 0:

```sh
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m --cap-drop ALL --security-opt no-new-privileges --user 51000:51000 --entrypoint python "$NETOPS_IMAGE" -B -m unittest discover -s /opt/netops/tests -v > qualification/unit.log 2>&1
```

Both layers are required; a regression caught only by a `tests/v1` contract test is not visible in the engine reports.

Historical standalone distribution/export/SBOM test functions are archived with original bytes and individual retirement reasons in `docs/archive/0.x/standalone-layout/INDEX.json`. Current root source gates verify the shared product metadata and Core dependency boundary; installed-image tests verify executable/runtime behavior. Run the root source gates in the git source checkout (they read the tracked file list): `python3 -B release/check_source.py` prints `source_gate=PASS` and exits 0, or names each violation, prints `source_gate=FAIL` and exits nonzero. There is no test-disposition exclusion mechanism. Any skipped or deselected test rejects the engine report, even if pytest exits successfully. Failures, errors and empty collections also reject it. A missing prerequisite must be supplied and the test executed. Test support fixtures are not installed or deployed. Fake SSH fixtures need executable test tmpfs; production tmpfs stays noexec.

Release acceptance follows the test layers listed under Verification and release in the [README](../README.md#verification-and-release). CI suites run once per architecture in GitHub Actions and are not repeated by hand on each operating system. The platform layer installs the release by the quickstart on every supported host family, with Docker as root and rootless, and checks health, three MCP calls of each role recorded in the audit, a refused call without the token, restart and backup; the corrective release 1.0.2 replaced it with the blind runs listed in its [release notes](../release/notes-1.0.2.md#acceptance), and 1.0.3 with the blind runs listed in its [release notes](../release/notes-1.0.3.md#acceptance). `release/acceptance/nonroot_operator.sh` and, on Fedora Server, `release/acceptance/selinux_negative.sh` are targeted checks, not separate signing rows. Public reports contain sanitized result summaries only; private raw evidence remains outside release assets.


The tester provides a synthetic root-owned 0600 file so the nonroot Helper permission-refusal test always has a real foreign-owner target. Test processes remain UID 51000. The filesystem askpass and memory-observation failure cases exercise their explicit platform branches with module-local platform dependencies; they do not change the interpreter-wide platform or claim native macOS execution. POSIX sockets, processes and refusal/cleanup behavior are real.

The five deliberately failing sandbox cases are fixture inputs under each engine's tests/support/sandbox_violations.py. The driver explicitly runs every case in a child pytest and checks its JUnit report for the exact case names and expected safety refusals. They are executed negative inputs, not skipped normal tests. A missing case, unexpected failure, skip, setup error or missing refusal rejects the driver. The child JUnit report is written below the test temporary directory `/pytmp`, so the tmpfs of the command above discards it. When retained child reports are needed, use the following variant for that role instead of its original run command. It uses a private host directory in place of the test tmpfs; no second run is required:

```sh
role=core
umask 077
mkdir -p qualification
chmod 0700 qualification
mkdir -p "qualification/$role" "qualification/$role-pytmp"
chmod 0777 "qualification/$role" "qualification/$role-pytmp"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 2g --cpus 2 --tmpfs /tmp:rw,nosuid,nodev,exec,size=512m,mode=1777 --mount "type=bind,source=$PWD/qualification/$role-pytmp,target=/pytmp" --mount "type=bind,source=$PWD/qualification/$role,target=/reports" netops-engine-tests --role "$role" --candidate-commit "$CANDIDATE_COMMIT" --candidate-image "${NETOPS_IMAGE#*@}" --output /reports/engine-report.json > "qualification/$role-detail.log" 2>&1
docker run --rm --network none --read-only --user 51000:51000 --entrypoint sh -v "$PWD/qualification/$role-pytmp:/pytmp:ro" netops-engine-tests -c 'find /pytmp -name "*.xml"'
```

The retained files are owned by UID 51000. The example reads them through a container running as that UID with a read-only mount; use that UID when reading or copying the reports rather than changing their ownership.


Source privacy checks hexadecimal and Unicode escapes in every supported text format, including malformed JSON. Excessive nesting fails closed. No path, directory or test file is exempt. The archived 0.x Helper supply-chain module, which encodes synthetic private-shaped markers as escapes, is therefore not part of the tree; its index entry keeps the original hash and names the public commit holding the same bytes.

## Configuration failure boundaries

Configuration diagnostics classify a failure at its known source. An unclassified exception is an operational failure; it does not prove that the supplied JSON schema is wrong. Diagnostics never print an unknown exception message, JSON document, document key, credential reference or file path supplied in the input.

| Source reached by configure | Classification and public diagnostic |
|---|---|
| Declared container user, instance lock, state version and product version | Existing fixed operator-access or state-compatibility message. |
| Private-file type/link, owner, mode, size, concurrent change or length check in files.check_regular/read_private | A fixed operational marker on the same ValueError, preserving its existing type and text. |
| Parent audit-preflight refusal or unsupported internal workflow metadata | A fixed operational marker on the same ValueError. The audit refusal is identical for configure, offline Admin workflows and Auditor import-snapshot/import-policy. Other Auditor commands do not use this import preflight. |
| Reading stdin; bootstrap capabilities, UID/groups/environment; opening or closing state; temporary directory creation, publish, fsync, cleanup or output | If no narrower known marker is available, a fixed operational message instructs inspection of private state and audit. PermissionError has a fixed access/ownership message. No diagnostic claims that a failed write left the state unchanged. |
| JSON syntax | Fixed text with integer line and column only; no JSONDecodeError.msg or doc. |
| JSON decoding, duplicate keys, nonfinite constants, number or nesting limit | Fixed input reason, selected only within the input parser. Existing supported JSON encodings and accepted input values are preserved. |
| Size/envelope, notification input, syslog host/port and supplied public CA validation | Fixed typed input message. Invalid public CA bytes, missing BasicConstraints and invalid types identify ca_pem without echoing it. |
| Core vault/inventory, Helper/Auditor section and Admin configuration validation | Existing allowlisted field/reason metadata or the fixed Helper-section guidance. Device list positions are integers; aliases and credential names are not displayed. Only an explicit exception cause carries metadata through a wrapper. |
| Mixed loader codes read, regular, owner, private-mode, single-link and policy | Neutral prefix: Role configuration could not be loaded. These existing codes can represent input limits, invalid policy or storage faults; diagnostics do not invent a more specific cause. Library exception types, messages, validation and I/O remain unchanged. |
| Installed Auditor catalogue, structural runtime errors and other unclassified configure exceptions | Fixed operational fallback; no claim that the user's document is invalid. |
| Auditor policy import validation versus storage | Invalid policy content has a fixed input refusal. OSError from reading the staged policy follows the existing fixed private-storage refusal, preserving cleanup and create-only publication. Import refusals use the same no-automatic-retry suffix. |
| Saved Admin notification file absent | Fixed prerequisite: supply notification_topic for setup or restore the private notification file. Absence alone does not prove first setup. |
| Saved Admin notification file unreadable, unsafe or malformed | Fixed private-state diagnostic. It does not request a first setup or echo the stored contents. |

Tests exercise CLI output and unchanged role files, real private-file refusals, parser positives and negatives, neutral loader codes and untrusted markers. The CLI suite checks equal operational and audit diagnostics for configure, Admin workflows and Auditor imports. Maintainer QA also runs an image-level check with the actual default container UID and actual demoted gateway UID: denying audit storage must refuse all three role configurations, Admin doctor and an Auditor import before stdin or staging. A unit identity fixture or failed harness is not evidence for actual isolation.

Admin configure measures its existing serialized config bytes against the engine's CONFIG_MAX_BYTES before writing the same bytes. Exactly the existing byte limit remains accepted; one extra byte has a fixed config size diagnostic. Admin file reads keep a neutral loader reason and its parser uses the fixed config JSON reason.

The startup output check scans the exact token bytes in private initialization, startup and container-log captures. It rejects unreadable captures, invalid token files and empty captures. A container log may be empty only after successful log capture and an explicit allowance for that file; it is still scanned. The report records the number of allowed empty captures. This check does not detect tokens transformed by encoding or split across lines. Tokens are never passed as command arguments to the checker.

The platform runner records each suite and cleanup command exit status and validates every required report before returning success. Missing or extra reports, candidate binding mismatches, failed checks, inconsistent summaries and failed restart or cleanup commands make the run fail. The signing checklist requires the evidence of the release's test layers, not a fixed number of acceptance rows.

The release documentation is completed in this order: the candidate workflow builds the candidate while the description of its acceptance (placeholder `acceptance-X.Y.Z`) and the release date in the heading of its changelog section (placeholder `release-date`) are still open, and refuses every other placeholder (`release/placeholder_gate.py --candidate`). After the acceptance of the candidate digests, the acceptance as it was run and the release date are written into the documentation without a rebuild, in a later commit that changes only documentation; the release manifest, the acceptance reports and the signed checksum list keep the source commit and image digests of the candidate. The signing tool then checks the Markdown of that source checkout (`-SourceDir`) like `release/placeholder_gate.py` without `--candidate` and refuses to sign while any placeholder is open.

The red-team startup-stop check exercises the operator path on the same container and nonempty local audit: normal stop, start, restart followed immediately by stop, and restoration. It requires clean exit codes, preserved audit prefixes through restoration, instance_stop as the last stopped-state record and the same container, image, CA and token. This ordinary timing test complements separate controlled startup-barrier checks; it does not deterministically select the instant before the signal handler is installed.

The audit test of a maximum-cardinality record proves that the event loop keeps running while the record is redacted: redaction waits for a loop heartbeat and the test requires that it arrived. It does not require a minimum number of heartbeat samples. The number of samples within one record depends on the speed and load of the test host; a minimum of five samples at a 0.01 s interval failed in 14 of 32 runs on one host while the loop was not blocked. With redaction moved back onto the event loop the test fails in every run.

The Helper proxy contract test requires mode 0755 or 0775 of `netops_helper/proxy.py` in the tested tree and, in a git checkout, index mode 100755. The engine regression image copies the checkout without `.git`, so it prints `index_mode_check=skipped reason=not a git repository` and checks the file mode, which git set from the index at checkout. No 1.0 deliverable depends on this mode: the production image sets every application file to 0644 and loads the proxy as a module.

## Retained source and branch-coverage checks

The shared-product source gate checks tracked files from the sealed clean candidate checkout. It is not a scanner for untracked workstation files or a comparison of staged blobs with a dirty working tree. All public source and release assets still require their privacy checks.

The mixed historical repository gate is preserved byte for byte, with an individual disposition for every original test, in [the root-gate archive](archive/0.x/root-release-gate/INDEX.json). Its live privacy edge cases run in the current source-gate test module. Its three independent except/else coverage controls remain in tests/test_release_gate.py. They require the hash-locked pytest and coverage tools in the separate QA environment, NETOPS_REQUIRE_RUNTIME_TESTS=1 and NETOPS_EXCEPT_COVERAGE=1. Missing prerequisites are errors. Before a release, run those controls and measure all four engines against the recorded module and component floors. Keep the raw component logs and JSON using scripts/except_branch_coverage.py --log-dir and --json; do not lower floors or use report-only to accept a release. These controls are maintainer QA outside the release test layers; they are not a signing requirement.

The component measurement runs each engine suite under coverage with subprocess measurement. The data files of all test processes and the pytest temporary directories are written below `/tmp` and combined there, so the 512 MiB `/tmp` of the engine regression command is not enough: the measurement then fails with `sqlite3.OperationalError: database or disk is full`. Run the three controls from the engine regression image with an exec tmpfs of 8 GiB as `/tmp`. Pages written to a tmpfs count against the memory limit of the container, so the limit must exceed the tmpfs size:

```sh
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 10g --tmpfs /tmp:rw,nosuid,nodev,exec,size=8g,mode=1777 -e NETOPS_EXCEPT_COVERAGE=1 -w /repo --entrypoint /testenv/bin/python netops-engine-tests -B -m pytest -p no:cacheprovider tests/test_release_gate.py
```

Without a CPU limit the three controls take about 11 minutes on an amd64 workstation; limited to two CPUs (`--cpus 2`) they did not finish within 15 minutes.

One product packages the root MIT LICENSE. The component source copies are checked during release review; no automated duplicate-copy mutation gate is claimed. Current workflow action references are reviewed for immutable SHA pins. Automated future-unpin mutations, a source Markdown link resolver and the historical parent-alias case remain follow-up QA work. The current source privacy gate does not resolve Markdown links or anchors. Release review checks the actual installation instructions and changed relative links and anchors; this is not a claim that every historical documentation resolver test is active.

## Source checkout problems

### Build behind TLS inspection

If a proxy or firewall decrypts TLS, the package downloads in `docker build` fail. The production `Dockerfile` stops in its first step with `TLS: server certificate not trusted` from `apk`, followed by `ERROR: Not continuing due to stale/unavailable repositories.`; a pip step prints `ERROR: Could not find a version that satisfies the requirement <package>==<version> (from versions: none)`. Both Dockerfiles accept a CA bundle that contains the inspection CA as the optional BuildKit secret `extra_ca`. On a Debian or Ubuntu host that trusts the inspection CA, pass the system bundle:

```sh
docker build --secret id=extra_ca,src=/etc/ssl/certs/ca-certificates.crt --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" .
docker build --secret id=extra_ca,src=/etc/ssl/certs/ca-certificates.crt --build-arg NETOPS_TEST_IMAGE="$NETOPS_IMAGE" -f release/engine-regression.Dockerfile -t netops-engine-tests .
```

The bundle is appended to the image's own bundle in a temporary directory only while a download step runs; no image layer contains it. Without the secret both builds run the same commands as before. The wheel built with the secret is byte-identical to the wheel built without it from the same commit. Do not run two builds of the same Dockerfile at the same time, one with and one without the secret: BuildKit runs identical concurrent steps once and does not distinguish them by the secret, so one of the builds can fail with the download error above.

### Seal refused in a checkout made under umask 0002

The seal of the private collector captures, `release/acceptance/process_profile_seal.py --directory … --age-dir …`, reads the recipient list `release/acceptance/process_profile_recipients.txt` and refuses it when the file is writable by group or others; it then prints `{"schema": "netops-process-profile-seal-status/1", "sealed": false, "reason": "seal-refused"}` and exits 1. git and tar create files according to the umask, so a checkout or an extracted source archive made under `umask 0002`, the default for user accounts on Ubuntu, has this file with mode 664. The release itself seals in the candidate workflow on the GitHub runner; a run of the seal from your own checkout needs the group and other write bits removed:

```sh
stat -c %a release/acceptance/process_profile_recipients.txt
chmod go-w release/acceptance/process_profile_recipients.txt
stat -c %a release/acceptance/process_profile_recipients.txt
```

The first `stat` prints `664` in such a checkout, the second `644`. Alternatively make the checkout under `umask 022`. The source tests of the seal copy the file into a private test directory, so they pass under either umask.

### Release tooling tests outside GitHub Actions

The candidate workflow runs `release/tests` and `release/acceptance/tests` on the `ubuntu-24.04` runner with Python 3.14.10 and the locked SBOM validation tooling from `release/requirements-sbom.lock`. `release/tests/test_workflow_calls.py` executes the run block of the workflow step "Test the release and acceptance tooling" in `candidate.yml` unchanged, so it needs what the runner provides to that block: Bash, `xargs -P`, `nproc` and GNU sed, whose `-u` option passes every prefixed output line on as it arrives. The workflow itself only runs on that runner and is not changed for other hosts. BusyBox sed, the default `sed` on Alpine, has no `-u`; there the pipeline subtests fail with the usage message of sed. On Alpine install GNU sed first (`apk add sed`). `release/tests/test_compose_config.py` needs the Docker Compose CLI plugin (`docker compose version`), not a Docker daemon. Test shims that wrap a system command, such as the `mktemp` shim of `release/acceptance/tests/test_nonroot_operator.py`, call the command found on `PATH` and do not assume its location.
