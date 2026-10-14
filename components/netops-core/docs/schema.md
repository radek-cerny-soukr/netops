# Schema and configuration primitives

## Scope

Core 0.2.8 supplies the standard-library-only `netops_core.fortios` parser and `netops_core.schema` runtime. Auditor keeps its existing `l1_fortios` import interface through the shared parser. Helper and Admin use the same schema identities and configuration instance traversal.

Operators supply version-bound schema libraries separately and pin their bytes. This archive contains neither a complete vendor schema catalogue nor schema-generation/calibration utilities.

## Library contract

`load(path, expected_sha256=...)` reads a bounded regular UTF-8 JSON file, rejects duplicate fields, nonfinite values (the literals `NaN`, `Infinity` and `-Infinity`, and a number such as `1e999` that overflows to infinity) and invalid metadata, checks the supplied SHA-256, and returns a `Library`. Format 1 requires `platform: "fortios"`, `hardware`, `os_version`, `build` and a `config` mapping of measured paths.

A node is a `table` or `section`, with `scope`, `available` and `attrs`. Scope and availability may be unknown. Attributes may carry measured types, options, bounds, byte lengths, multiplicity and reference metadata. Unresolved or missing built-in reference measurements remain explicit. Metadata validates the library's representation; it does not prove a vendor measurement was performed correctly.

The `identity` property of `Library` is the exact `(hardware, os_version, build)` tuple. `require_identity(...)` refuses another tuple. `paths`, `node(...)`, `availability(...)` and `scope(...)` expose bounded library information. Parent scope and availability constrain descendants. `validate(path, changes)` validates 1–64 attributes using measured validators; unknown availability, scope, types or values cannot authorize a write.

## Visibility conditions

An attribute may carry measured visibility `conditions`. Core validates their shape when it loads a library and does not evaluate them. A library with an unknown field, a repeated clause, a dependency cycle or a shape beyond the limits is refused.

- `any_of` holds 1–64 alternative clauses. Optional `measured_on` is an evidence label; `measured_contexts` lists the scoped contexts (`global` or `vdom:<name>`) for the condition, and `evidence_sha256` binds the supporting evidence bytes.
- A local clause tests another attribute of the same object, `{"when": "type", "equals": "dynamic"}`, optionally with the recorded `baseline` and `hidden_by` values.
- `{"all_of": [...]}` requires all of its 1–16 clauses. Clauses nest at most 8 levels deep and one condition holds at most 256 clauses.
- A reference clause tests an attribute of the object that a reference attribute of the same object names:

```json
{"reference": {"attribute": "sdn", "table": "system sdn-connector",
               "target_attribute": "type", "equals": "kubernetes",
               "contexts": [{"source": "vdom:root", "target": "global"}],
               "evidence_sha256": "<SHA-256 of the measurement evidence>"}}
```

All six fields are required. `attribute` is a single-valued attribute of the same object whose `ref` lists `table` among its `tables`. `table` is another top-level table. `target_attribute` is an option attribute of that table other than its key, and `equals` is one of its measured options. `contexts` holds 1–64 measured pairs, at most one per source: the context of the object whose attribute is conditioned and the context in which the referenced object was resolved. A target attribute cannot carry a reference clause itself, and the reference attribute cannot depend on the attribute it conditions.

A consumer that evaluates conditions distinguishes three results: satisfied, not satisfied and unknown. Only a satisfied condition can allow a write. An empty reference, or an absent one whose measured default is absent or empty, is not satisfied. An attribute of the referenced object that the snapshot omits, as `show` omits default values, takes its measured default only when that default is not model-dependent and the attribute carries no conditions. An absent or ambiguous referenced object, an omitted attribute without such a default, an absent reference with a non-empty or model-dependent default, a value outside the measured options, an unmeasured context and invalid metadata are unknown. A reference clause applies only to its measured target value, context and library.

## Configuration traversal

The parser handles FortiOS escaping, quoted backslashes, multiline values and the empty single-quoted export token. It raises a classified parse/truncation error instead of treating a cut snapshot as complete.

`config_instances(library, tree, include_unknown=False)` retains each instance's VDOM and parent table keys, including measured inline configuration keys. Equal object names in different VDOMs are distinct. It does not infer defaults or prove that a saved snapshot is complete.

## Consumer responsibilities and limits

- Helper verifies fresh live model/version/build and the SSH host key against its server registry before returning one enrolled path. It reads a full snapshot in memory, redacts known credential attributes and returns selected attributes only. It does not evaluate visibility conditions; a library whose condition metadata Core refuses cannot be bound.
- Auditor's `schema-check` uses operator-declared identity and an explicit complete-snapshot assertion; it does not contact the device to validate that declaration. Unknown reference coverage cannot produce a clean integrity claim. Its upgrade comparison reports a configured attribute whose target visibility depends on a referenced object as not evaluated.
- Admin additionally requires pinned rollback calibration, grants, independent checks and an on-device safeguard. A new library digest inherits no old write grant. Admin evaluates local and reference conditions against the same pinned snapshot in the exact measured context; an unknown result refuses the change and a satisfied condition grants nothing.
- Model/licence-specific availability, conditional visibility, reference targets and generated identities require actual measurement. VM evidence is not a grant for physical hardware. Library data and device responses remain untrusted inputs.

See the component READMEs for schema reads, scoped audit and calibrated transaction setup, and [verified support](https://github.com/radek-cerny-soukr/netops/blob/main/docs/verified-support.md#fortios-bounds) for the model/build and permission boundaries.
