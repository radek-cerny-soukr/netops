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

Historical standalone distribution/export/SBOM test functions are archived with original bytes and individual retirement reasons in `docs/archive/0.x/standalone-layout/INDEX.json`. Current root source gates verify the shared product metadata and Core dependency boundary; installed-image tests verify executable/runtime behavior. Run the root source gates in the git source checkout (they read the tracked file list): `python3 -B release/check_source.py` prints `source_gate=PASS` and exits 0, or names each violation, prints `source_gate=FAIL` and exits nonzero. There is no test-disposition exclusion mechanism. Any skipped or deselected test rejects the engine report, even if pytest exits successfully. Failures, errors and empty collections also reject it. A missing prerequisite must be supplied and the test executed. Test support fixtures are not installed or deployed. Fake SSH fixtures need executable test tmpfs; production tmpfs stays noexec.

Release acceptance follows the test layers listed under Verification and release in the [README](../README.md#verification-and-release). CI suites run once per architecture in GitHub Actions and are not repeated by hand on each operating system. The platform layer installs the release by the quickstart on every supported host family, with Docker as root and rootless, and checks health, three MCP calls of each role recorded in the audit, a refused call without the token, restart and backup; the corrective release 1.0.2 replaces it with the blind runs that the README lists. `release/acceptance/nonroot_operator.sh` and, on Fedora Server, `release/acceptance/selinux_negative.sh` are targeted checks, not separate signing rows. Public reports contain sanitized result summaries only; private raw evidence remains outside release assets.


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

The red-team startup-stop check exercises the operator path on the same container and nonempty local audit: normal stop, start, restart followed immediately by stop, and restoration. It requires clean exit codes, preserved audit prefixes through restoration, instance_stop as the last stopped-state record and the same container, image, CA and token. This ordinary timing test complements separate controlled startup-barrier checks; it does not deterministically select the instant before the signal handler is installed.

## Retained source and branch-coverage checks

The shared-product source gate checks tracked files from the sealed clean candidate checkout. It is not a scanner for untracked workstation files or a comparison of staged blobs with a dirty working tree. All public source and release assets still require their privacy checks.

The mixed historical repository gate is preserved byte for byte, with an individual disposition for every original test, in [the root-gate archive](archive/0.x/root-release-gate/INDEX.json). Its live privacy edge cases run in the current source-gate test module. Its three independent except/else coverage controls remain in tests/test_release_gate.py. They require the hash-locked pytest and coverage tools in the separate QA environment, NETOPS_REQUIRE_RUNTIME_TESTS=1 and NETOPS_EXCEPT_COVERAGE=1. Missing prerequisites are errors. Before a release, run those controls and measure all four engines against the recorded module and component floors. Keep the raw component logs and JSON using scripts/except_branch_coverage.py --log-dir and --json; do not lower floors or use report-only to accept a release. These controls are maintainer QA outside the release test layers; they are not a signing requirement.

One product packages the root MIT LICENSE. The component source copies are checked during release review; no automated duplicate-copy mutation gate is claimed. Current workflow action references are reviewed for immutable SHA pins. Automated future-unpin mutations, a source Markdown link resolver and the historical parent-alias case remain follow-up QA work. The current source privacy gate does not resolve Markdown links or anchors. Release review checks the actual installation instructions and changed relative links and anchors; this is not a claim that every historical documentation resolver test is active.
