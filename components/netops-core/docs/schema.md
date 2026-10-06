# Schema and configuration primitives

## Scope

Core 0.2.6 supplies the standard-library-only `netops_core.fortios` parser and `netops_core.schema` runtime. Auditor keeps its existing `l1_fortios` import interface through the shared parser. Helper and Admin use the same schema identities and configuration instance traversal.

Operators provide measured libraries separately and pin their bytes. This archive does not contain a complete vendor schema catalogue or the lab measurement/calibration tools.

## Library contract

`load(path, expected_sha256=...)` reads a bounded regular UTF-8 JSON file, rejects duplicate fields, nonfinite values and invalid metadata, checks the supplied SHA-256, and returns a `Library`. Format 1 requires `platform: "fortios"`, `hardware`, `os_version`, `build` and a `config` mapping of measured paths.

A node is a `table` or `section`, with `scope`, `available` and `attrs`. Scope and availability may be unknown. Attributes may carry measured types, options, bounds, byte lengths, multiplicity and reference metadata. Unresolved or missing built-in reference measurements remain explicit. Metadata validates the library's representation; it does not prove a vendor measurement was performed correctly.

The `identity` property of `Library` is the exact `(hardware, os_version, build)` tuple. `require_identity(...)` refuses another tuple. `paths`, `node(...)`, `availability(...)` and `scope(...)` expose bounded library information. Parent scope and availability constrain descendants. `validate(path, changes)` validates 1–64 attributes using measured validators; unknown availability, scope, types or values cannot authorize a write.

## Configuration traversal

The parser handles FortiOS escaping, quoted backslashes, multiline values and the empty single-quoted export token. It raises a classified parse/truncation error instead of treating a cut snapshot as complete.

`config_instances(library, tree, include_unknown=False)` retains each instance's VDOM and parent table keys, including measured inline configuration keys. Equal object names in different VDOMs are distinct. It does not infer defaults or prove that a saved snapshot is complete.

## Consumer responsibilities and limits

- Helper verifies fresh live model/version/build and the SSH host key against its server registry before returning one enrolled path. It reads a full snapshot in memory, redacts known credential attributes and returns selected attributes only.
- Auditor's `schema-check` uses operator-declared identity and an explicit complete-snapshot assertion; it does not contact the device to validate that declaration. Unknown reference coverage cannot produce a clean integrity claim.
- Admin additionally requires pinned rollback calibration, grants, independent checks and an on-device safeguard. A new library digest inherits no old write grant.
- Model/licence-specific availability, conditional visibility, reference targets and generated identities require actual measurement. VM evidence is not a grant for physical hardware. Library data and device responses remain untrusted inputs.

See the component READMEs for schema reads, scoped audit and calibrated transaction setup, and [verified support](https://github.com/radek-cerny-soukr/netops/blob/main/docs/verified-support.md#candidate-validation-3-4-october-2026) for the measured scope.
