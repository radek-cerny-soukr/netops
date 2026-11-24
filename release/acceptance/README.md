# Acceptance tooling

The process profile sealer requires `curl` when installing age from GitHub. Downloads retry up to five times with a 10-second delay, a 300-second retry window, a 20-second connection timeout and a 120-second transfer timeout; the curl process has a 330-second overall timeout. The archive and binary SHA-256 pins are checked before age runs. A prolonged outage still fails the installation; rerun the candidate after service recovers.


## Previous-release upgrade check

`release.env` selects the published 1.0.12 image by digest and a local 1.0.13 candidate. Populate `from/` from the 1.0.12 release as the comments describe, then run `bash upgrade-check.sh release.env`. Use a private scratch `WORKDIR`, an unused port and a unique `NONCE` per run. The script creates only its own Compose projects/volumes and removes them and its private work data unless `KEEP=1` is set.

For the upgrade from 1.0.12 to 1.0.13, run `admin enroll` again for each Admin device before making changes. The enrollment format is still `netops-enrollment/1`. The binding includes hashes of all packaged Admin profiles, which changed in 1.0.13, so Admin returns `enrollment_required` for the restored enrollment. The upgrade check uses synthetic Admin state and verifies that the backup is restored.

The source instance contains an enrolled Helper target, a synthetic Auditor run with a finding and rule status, and a synthetic completed Admin journal plus request identity. These are local fixtures in the scratch state; no device command is sent and no real change is applied. The check compares role file manifests, MCP responses, version migration audit, second-start behavior, original-volume preservation and rollback. `age_hours` is elapsed time and is normalized like the other time values. The declaration `api-changes-1.0.12-1.0.13.json` specifies the expected API differences. The check fails on undeclared differences and stale declarations.

To draft API declarations from retained captures, use the same pointer comparison and canonical fingerprint functions as `verify_state.py`:

```sh
python3 -B generate_api_changes.py "$WORK/from-mcp.json" "$WORK/to-mcp.json" \
  --from-version 1.0.12 --to-version 1.0.13 --reasons api-changes-1.0.12-1.0.13.json --out api-changes-1.0.12-1.0.13.json
```

The compared API is the tools (`tools/list`), the prompts (`prompts/list`, objects `prompt:<name>`) and the server capabilities of the `initialize` result (object `mcp:capabilities`), plus the role responses. The generator holds no release-specific text: `--reasons` names the reviewed reasons, either an earlier declaration (its reason is reused per object and kind) or a JSON object `{"<object> <kind>": "<reason>"}`. A change without a reviewed reason is an error; `--draft` writes a placeholder reason instead, and `verify_state.py` refuses a declaration that still contains one. Review every tool, prompt, capability and response change and its reason, then repeat the full upgrade check with the committed declaration and a fresh nonce. The generator is a review aid; it does not run during verification or automatically accept changes. Missing captures, removed tools, undeclared changes, stale declarations or mismatched value hashes fail. Catalogue responses are collected across every page. Keep raw captures and backups private; exported reports are checked for the synthetic token and password.
