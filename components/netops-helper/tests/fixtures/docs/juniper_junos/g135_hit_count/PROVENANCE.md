# G135 J03 `show security policies hit-count` documentation samples

Source: Juniper CLI reference "show security policies hit-count" (query source J-C7B534872022),
https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-policies-hit-count.html
(redirects to the same path on the HPE Networking documentation site),
fetched 2026-11-18 by task netops-20261118-492-r2, HTTP 200.

Each file is one "Sample Output" block of that page in page order, byte for byte after HTML entity decoding,
without the first line (the `user@host>` prompt with the command). Trailing spaces, tabs and the missing or
present final newline are kept as published. Nothing was anonymised: the samples contain no site data.
The Helper query itself only sends `show security policies hit-count | no-more`; the option samples
document the table layouts the same parser must recognise (classic table with `Number of policy` footer,
Junos 21.2+ table with `Logical system`, `Action`, `Redirect`/`Redirects` and the `detail` sub-tables).

| File | Command in the sample | SHA-256 of the file |
|---|---|---|
| `default.out` | `show security policies hit-count` | `24770064afc312d66d5222a621078cd0cf96c5bbb835a89083383fdf68d4ea26` |
| `ascending.out` | `show security policies hit-count ascending` | `0eacb113fd47c53387ed3fe945cd35e31e0cb11f5a993c5c6c1a57fa655d21e8` |
| `descending_range.out` | `show security policies hit-count descending greater-than 70 less-than 100` | `817faa312499ebeffdfe68f417cac87691b080efc7125c4448491b1caba1fc2c` |
| `zone_pair.out` | `show security policies hit-count from-zone untrust to-zone trust` | `e99a4282784d7df4bc59109becf157e16189d440548e4a5a67e25f3e8011436e` |
| `logical_system.out` | `show security policies hit-count` | `cb07412b64977d31f69f53c6b8fc1d1dface673c8e875e03fe06e5bbdcef4132` |
| `detail_redirect.out` | `show security policies hit-count detail` | `4fb569a303047f960e25224ffed89f7850fa489cc4ad8f7e0f52eec79d3a1b97` |
| `detail_url_categories.out` | `show security policies hit-count policy-name policy1 detail url-categories` | `66d1f38da2c84c83eff57421e1c27861a4c4ec68b6ee539895a56a67a9a37bf7` |
| `detail_dynamic_applications.out` | `show security policies hit-count policy-name policy1 detail dynamic-applications` | `7eeab27173ad8de93b0dd299fcb8d7d76e086866293e807231012f7106e65d89` |

`../g135/security_policy_hits.out` (G135, task 492) is the first sample with trailing blanks removed.
