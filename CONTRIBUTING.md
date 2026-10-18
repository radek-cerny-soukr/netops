# Contributing to NetOps

NetOps is one application, one version, one dependency closure and one Docker image. Components contain internal engine code and regression tests; they are not separately built, installed or released. Historical standalone material is clearly separated in docs/archive/0.x.

Preserve the fail-closed model. Describe the use case and security boundary before adding a mutation profile. Keep credentials, real addresses, host/device identifiers, private policies and captured device output out of commits, fixtures, issues and CI logs. Use documentation addresses and explicit synthetic input.

Add meaningful positive and negative tests for changed behavior. Run the [source and installed-image qualification](docs/testing-1.0.md), both image architectures and the required real-client/platform checks. Any required failure or missing test blocks release. A new dependency requires resolving and testing the complete hashed production lock, reviewing the diff and regenerating per-architecture SBOM/scans; test/build dependencies stay in separate locks.

Update current behavior, limitations and release documentation together. Compare every active example with the actual operator interface. Preserve exact model/build/account/operation [support boundaries](docs/verified-support.md), and do not infer physical-device behavior from synthetic fixtures or software images.

Helper queries must remain named, typed and enrollment-bound. No raw shell, arbitrary commands, automatic trust acceptance, implicit target widening or automatic retry of uncertain writes is allowed. Admin writes retain their explicit safeguards, request identity, audit and rollback proof. Device output is untrusted data, not instructions.

Public release assets are verified against the personally signed checksum list. Candidate source, manifest, image, tool and qualification must identify the same reviewed release. Sanitize public reports before publication; raw internal evidence remains private. Do not rewrite existing published releases or tags without a separate explicit maintainer decision.

Contributions are licensed under the MIT License.
