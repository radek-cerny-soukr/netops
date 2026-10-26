# Release SBOM validation

Before creating the candidate output directory, `candidate_manifest.py` validates both architecture SBOMs with `sbom_gate.py`. Each must satisfy the complete vendored CycloneDX 1.7 Draft 7 schema, contain at least one component, and identify a root container whose name equals the image name and whose version equals that architecture's full `sha256:` digest. Image references with digest prefixes or suffixes do not match.

The four schemas and Apache 2.0 license are unmodified official files from CycloneDX/specification commit `4b3f59453366e27c8073fd24e98bf21ef8892c8e` (tag `1.7`). `schema/cyclonedx-1.7/PROVENANCE.json` records source URLs and byte hashes. The validator checks hardcoded hashes and schema identities, checks reference closure, and uses a registry whose retrieval callback rejects every unknown resource. An input document's `$schema` string is inert data; it never selects or downloads a validator.

Install the CI-only dependencies with:

```sh
python3 -m pip install --only-binary=:all: --require-hashes -r release/requirements-sbom.lock
```

This lock reuses existing runtime package versions and hashes but does not change runtime dependencies or the product image. Additional format helpers use non-GPL packages. The exact required schema formats are `date`, `date-time`, `idn-email`, `iri-reference`, and `uri`. Missing checkers and unknown schema formats fail closed. Date/calendar and RFC 3339 date-time checks, RFC 3986 URI checks, and RFC 3987 IRI-reference syntax checks use jsonschema's pinned implementations and helpers. Its `idn-email` checker only requires an at sign; this is not complete email syntax, IDNA or deliverability validation. Schema validation also does not establish SBOM completeness, authenticity, vulnerability status, or image contents.

A direct offline check is:

```sh
python3 -B release/sbom_gate.py SBOM.cdx.json --image IMAGE --digest sha256:DIGEST
```

The CLI exits nonzero on invalid input or missing/corrupt schemas. Pipeline integration validates both architectures before copying or writing candidate artifacts.
