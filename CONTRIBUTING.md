# Contributing

This repository holds one component per directory under `components/`, each with its own version, gate, tests, and release. Work in the directory of the component you are changing; run its own checks there, and the repository gate `python3 scripts/check_release.py` from the root before proposing a change. A new component needs a release selector, a gate of its own, a `LICENSE` copy, and a CI job - the repository gate refuses a component that is missing any of them.

Contributions are welcome when they preserve the fail-closed model.

1. Open an issue describing the use case and threat impact before adding a new mutation profile.
2. Keep credentials, addresses, host keys, certificates, device output, and local policies out of
   commits, fixtures, issues, and CI logs.
3. Add exact positive and negative tests for every command/path capability.
4. Run the complete offline suite and public-release checker.
5. Keep both hash lockfiles byte-identical when dependencies did not change. If a dependency or
   lock generator changes, pin and record the exact Python 3.13 generator environment, regenerate
   both locks, and explain the complete dependency diff. Always regenerate and byte-compare the
   CycloneDX SBOM with the reviewed release environment.
6. Update tool, limitation, security, and changelog documentation with behavior changes.

Do not add raw command input, a generic-shell escape hatch, automatic host-key acceptance, write tools, or broad credentials to phase 1. New queries require named templates, typed inventory-bound slots, positive and negative tests, explicit pagination, and review of prompt-injection exposure. Device-side read-only authorization is mandatory; redaction and skill instructions are not authorization boundaries.

By submitting a contribution, you agree that it is licensed under the MIT License.
