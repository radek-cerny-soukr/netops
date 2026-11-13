# Vulnerability assessments

`vulnerability-assessments.json` supplies the written assessments shipped with a release. Each record identifies a finding by `id`, `package`, `version` and `type`; coverage requires `exploitable: false` and nonempty `reasoning` and `evidence` strings. These are application applicability assessments, not claims that a vulnerable upstream package was repaired.

A High/Critical finding whose Grype fix state is `fixed` normally blocks release. The following fields document the limited exception when the scanner names an upstream fix that has not yet been released:

| Field | Required value |
|---|---|
| `fixed_version_not_released` | Boolean `true`; asserts that the reported fix is not available yet. |
| `fix_unavailable_versions` | Nonempty list of version strings, exactly matching Grype's `vulnerability.fix.versions` list, including order. A different fix version is not covered. |
| `fix_unavailable_evidence` | HTTPS URL with a host, pointing to evidence that those fix versions have not been released. |
| `fix_unavailable_checked` | Calendar date in `YYYY-MM-DD` form when availability was checked; between 0 and 14 days before the scan/signing day, inclusive. Future dates and timestamps are invalid. |

The exception also requires the exact `id`/`package`/`version`/`type` identity, `exploitable: false`, and nonempty `reasoning` and `evidence`. A genuinely available fix is not eligible: rebuild with the fix instead of renewing the exception. A missing, malformed, expired or mismatched exception still blocks the release.

Daily scans merge the released assessment asset with current repository records; repository records take precedence for the same CVE and package. After the 14-day validity window, the daily scan deliberately fails. Check upstream availability again: update the dated evidence only if the fix remains unreleased, otherwise update the image and rescan. The signing gate independently checks the exception against the signing day.
