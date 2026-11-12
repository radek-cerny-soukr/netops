# FortiOS Wi-Fi: live clients with a read-only REST token

NetOps 1.0.7 adds an optional REST path for FortiOS Wi-Fi observations. This is an explicit exception to the SSH-only diagnostic design: the read-only SSH account cannot run `diagnose wireless-controller`, including the live station table, and a REST session login with that account did not succeed. A separate FortiOS REST API user with a read-only access profile supplies the missing live association, RSSI and SNR. It does not replace the SSH account or grant write operations to the Helper.

## Measurement and limits

A laboratory measurement on 2026-11-08 used a FortiGate-80F active-passive HA pair with FortiOS 8.0.2 build0251. A REST API user whose access profile had all ten permission groups set to `read`, with explicit trusthosts and a pinned HTTPS certificate, received HTTP 200 from both test hosts for the five Wi-Fi monitor endpoints in the table below (device identity and wireless log GETs were additionally measured on 2026-11-09 and are now used). Separate lab negative tests returned HTTP 403 for PUT `/api/v2/cmdb/system/global`, POST `/api/v2/cmdb/firewall/address`, and DELETE of a nonexistent firewall address. Those negative tests are measurement evidence, not functionality exposed by NetOps. NetOps never sends those methods.

The live capture contained two managed APs, two clients and 32 rogue APs. Anonymized excerpts are regression fixtures in `components/netops-helper/tests/fixtures/fortios_80f_802_wifi_rest_*.json`. A read-only recheck on 2026-11-09 received HTTP 200 from all seven GETs, confirmed the all-read `netops-api-ro` profile and matched the selected GUI certificate fingerprint to the HTTPS DER hash; it did not test narrower permissions, writes or HA failover. A later permission-isolation measurement on 2026-11-09 verified the minimum
`wifi read` + `loggrp read` profile below, with the other groups `none`, all seven
GETs 200 and write-method attempts 403. Other FortiOS versions/models are not qualified by that measurement; missing/changed fields remain unknown and unsuccessful or non-root envelopes are refused. `wifi_triage` retains its exact 80F 8.0.2 build0251 SSH parser qualification and never returns a healthy verdict.

## What is read

All URLs use HTTPS on the enrolled target address and `helper.fortios_rest_port`
(default 443), root VDOM only. The selected port must be allowed by TCP egress. Callers cannot supply URLs, HTTP methods, headers, VDOMs, bodies or query parameters.

| Fixed GET endpoint | Use and returned fields |
| --- | --- |
| `/api/v2/monitor/user/device/query` | Optional identity enrichment by unique exact MAC: hostname, OS, hardware vendor/type. Failure leaves unknown fields and an explicit identity gap; live observations continue. |
| `/api/v2/log/memory/event/wireless?rows=200&filter=subtype%3D%3Dwireless` | Preferred triage history. The subtype filter is necessary on the measured firmware; the unfiltered URL also returns system events. At most 200 rows. Triage adds the typed station filter described below; no caller query string. |
| `/api/v2/monitor/wifi/client` | `wifi_clients`: MAC, IPv4/IPv6, SSID, AP ID/name, radio/band/`phy_mode`/channel, signal (RSSI dBm), SNR dB, noise dBm, `link_rx_mbps`/`link_tx_mbps`, traffic `bandwidth_rx`/`bandwidth_tx`, client retry/discard, association time (ISO 8601 UTC), elapsed seconds, authentication and security. Presence means associated; authentication is reported separately. |
| `/api/v2/monitor/wifi/managed_ap` | `wifi_clients` joins AP ID to unique AP serial/name. `wifi_aps_live` returns AP serial/name, state/connection, client count, version/profile, local address, join time, CPU/memory, radios, SSIDs and LLDP. Ambiguous joins leave serial unknown. |
| `/api/v2/monitor/wifi/ap_status` | `wifi_aps_live`: AP session/active/down/rebooted counts and the current client count. |
| `/api/v2/monitor/wifi/rogue_ap` | `wifi_rogue` and `wifi_triage`: observed SSID/MAC, channel/band, signal/noise, security/encryption, vendor, first/last seen, detecting APs and managed flag. Observation does not establish malicious activity. |
| `/api/v2/monitor/wifi/interfering_ap` | `wifi_rogue` and `wifi_triage`: MAC and detecting AP/radio/signal observations. No containment operation. |

For client history the Helper builds exactly the fixed log path above followed by
`&filter=stamac%3D%3D<percent-encoded-canonical-MAC>`. The two repeated `filter=`
parameters were verified on FortiOS 8.0.2: the device selects the client before
applying `rows=200`. A single combined filter expression is ignored by this
firmware. Every returned row must have the requested `stamac` and wireless
subtype; otherwise `invalid_response` is reported. No free-form filter is accepted.

`wifi_clients(target, ssid=None, ap=None, mac=None, limit=100, offset=0, max_bytes=16000, name=None)` applies exact local filters after redaction. Hostname `name` uses exact case-insensitive comparison; combined filters use AND; AP matches ID, resolved name or serial. MAC must be canonical lower-case `aa:bb:cc:dd:ee:ff`, SSID/AP bounded printable text. A missing client means not listed in that snapshot, not a diagnosed fault. If the client or AP GET fails, no partial station records are returned; the failure and requested filters remain explicit. Association duration is computed from the device epoch and Helper clock, clamped at zero; clock differences affect it.

`wifi_aps_live(target, summary=false, limit=100, offset=0, max_bytes=16000)` reads managed APs and summary; `summary=true` shortens each AP to identity, state, client count and a few numbers per radio (channel, clients, channel utilisation, TX retries, noise floor, interfering and rogue counts) and marks the result `view: "summary"`. `wifi_rogue(target)` reads rogue and interfering APs. With a token, client reads cost three target requests, AP reads two, and relevant neighbor reads four. A client row whose MAC is missing or invalid is skipped and counted in `unparsed_rows`; the other rows are returned. Without a token all three return `ok: false`, `error_code: unsupported` and enrollment guidance without contacting the device and consume only the ordinary one-slot proxy budget.

`wifi_triage(target, mac=...)` or `wifi_triage(target, ip=...)` (add `summary=true` for the short form: verdict, findings, `missing`, `checked` and the deciding facts only) adds three live client snapshots about three seconds apart when the target has a token. It uses current AP/radio/SSID for the controller chain, reads rogue and interfering neighbors, and keeps historical events separate. A unique live IP match can resolve a MAC missing from ARP. `chain.live_client` carries live RSSI/SNR; `chain.live_sources` names endpoint, capture time and content hash. Every failed or missing signal snapshot remains explicit in `missing`, even when a later snapshot recovers. A failed REST read, absent client or absent signal fields keeps an explicit missing item; SSH diagnostics still run. The switch port remains unavailable.

## Security boundary

- GET only and an exact allowlist of the seven fixed paths in the table above; only the wireless log request has its fixed row count, subtype and optional typed MAC filter; no redirects, ambient HTTP proxies, arbitrary destinations or configurable HTTP headers.
- Bearer token lives in the existing private role vault as kind `api-token`. Inventory holds its record name, never the token. Only the trusted proxy injects it into the ephemeral internal authentication envelope for the three tools and `wifi_triage`. Clients cannot supply that envelope.
- Mandatory exact SHA-256 pin of the DER certificate, or a configured CA with hostname/SAN verification. A pin is checked on the same TLS connection **before** sending Authorization. With both CA and pin configured, both must pass. TLS 1.2 minimum. There is no insecure enrollment mode.
- Target address and the selected `fortios_rest_port` must satisfy the existing egress policy; DNS is resolved once to permitted IPv4 addresses and the connection uses that address. NetOps 1.0 does not install a host firewall: restrict egress on the host as needed.
- Each GET has a ten-second connection/read deadline and a 2 MiB response cap, including unknown-length/chunked responses; compressed responses are refused. Calls use the enrolled target rate budget (default 30 requests/60 seconds). Triage reserves seven SSH reads plus eight REST reads when enabled (one client/AP/identity read, two station-only snapshots, one log GET and rogue/interfering GETs). `wifi_clients` reserves three reads, `wifi_aps_live` two, and `wifi_rogue` four (two observations plus client/AP context). The REST transport also limits actual GETs per target, but that counter lives in the memory of one Helper worker process; it is not shared between workers or sessions served by different workers. The proxy budget above is the cross-session limit.
- Audit preflight is mandatory before device access. Each REST read records the fixed GET endpoint, status, operation correlation and sanitized result hash; neither body, Authorization header nor token is audited. Errors expose no response body or exception text from the device. Explicit secret redaction and sensitive-key redaction protect returned data, with proxy redaction as another boundary. Device data remains untrusted input.
- A read-only API profile and narrow trusthosts are device-side defenses in addition to the client allowlist. Never use a super_admin token for this feature.

## Create access on FortiGate

This is the administrator's checklist for optional **Helper Wi-Fi REST** access.
The setup blocks below change FortiGate or NetOps configuration; execute them only
as an authorized administrator. Readback and MCP verification use only reads.
Separate measurements have separate provenance. The earlier authorized laboratory
provisioning and permission-isolation task on 2026-11-09 created profile
`netops-t53-min` and exercised token generation and seven GETs; its supplied
measurement record identifies task netops-20261109-53, but does not identify the
provisioning login, token creator or cleanup of its temporary API user. Those
lifecycle details remain unverified; this guide does not claim the test account
was removed. A later readback on 2026-11-09 found `netops-t53-min` absent;
that verifies profile removal, not the unspecified temporary API-user/token
lifecycle. The retained all-read runtime account is a separate identity.
The documentation readback on 2026-11-09, including the later explicit
`netops-test-ro` visibility check, made no device changes, generated no keys and
triggered no HA failover. The password prompt observation comes from earlier
provisioning, not that readback.

Example values are placeholders: `192.0.2.1` is the enrolled FortiGate/cluster
address, `192.0.2.10` is the NetOps source **as seen by FortiGate after NAT**, and
`MGMT_INTERFACE` is the receiving management interface name. Replace these
addresses/names before copying. The profile and API user are both named
`netops-api-ro`; the NetOps vault reference is `fortigate-wifi-api-ro`, and the
example enrolled target alias is `fg-wifi`. Keep these names consistent if renamed.
Never substitute a secret into a command shown here.

### Prerequisites

- [ ] **Version and context.** Record the model/build and current VDOM. The
  qualified device is FortiGate-80F, FortiOS 8.0.2 build0251. Other versions and
  models need their own read verification. Use a separate administrator for
  provisioning; on the measured 8.0.2 build API-user creation requires
  `super_admin`. The runtime token must use the read profile below.

  ```text
  get system status
  get system ha status
  ```

- [ ] **HTTPS on the receiving interface.** Inspect the actual interface that
  receives traffic from the NetOps host, including traffic arriving through a
  VPN. Its `allowaccess` must contain `https`. In the 2026-11-09 readback the
  receiving interface was `wan1`, with HTTPS enabled. Do not copy its other
  management services into a new installation.

  ```text
  show system interface "MGMT_INTERFACE"
  ```

  If HTTPS is missing, the authorized setup is below. `append` preserves the
  existing allowaccess services; do not replace them with an example list.

  ```text
  config system interface
      edit "MGMT_INTERFACE"
          append allowaccess https
      next
  end
  ```

- [ ] **HTTPS listener and port.** Read the effective settings (including defaults):

  ```text
  get system global | grep admin-sport
  get system global | grep admin-https-redirect
  get system global | grep admin-server-cert
  ```

  Measured values: `admin-sport: 443`, `admin-https-redirect: enable`,
  `admin-server-cert: Fortinet_GUI_Server`. `admin-sport` is the management HTTPS
  port used by REST. Set `helper.fortios_rest_port` to that value when it is
  not 443 (for example 8443), and allow the same port in `helper.egress.tcp_ports`
  or a nonoverlapping TCP range. Port 443 may serve SSL VPN instead of management.
  The resolver, egress check, socket and HTTPS connection all use the selected
  REST port; inventory `port` changes SSH only. There is no need to move the
  FortiGate listener. Port forwarding/proxy workarounds were not qualified.
  `admin-https-redirect` controls HTTP-to-HTTPS redirection; it neither enables
  HTTPS on an interface nor changes NetOps' destination. NetOps starts with HTTPS,
  never uses port 80 and refuses redirects, so enabling this setting is **not** a
  REST prerequisite. See Fortinet's [management port settings](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/616955/configuring-ports).

- [ ] **Trusthosts, route and local-in policy.** Determine the stable egress
  source IP after container/host/VPN/NAT processing. Authorize that IP as one /32
  per NetOps host, rather than a whole LAN; the container's private address is
  not necessarily the address FortiGate sees. Check return routing and any
  intermediate firewall/NAT rule for the selected management HTTPS port. Traffic terminating on FortiGate
  is governed by interface management access and local-in policy, rather than
  an ordinary forwarding firewall policy on that same FortiGate. Review the
  relevant local-in rules and referenced addresses/services in order:

  ```text
  show firewall local-in-policy
  ```

  Also check the aggregate local-administrator trusted-host restrictions: an
  API-user trusthost alone may not make the HTTPS listener reachable if the
  source is excluded by every local administrator. Add only the intended source
  under an approved management policy; do not open a broad subnet to diagnose
  access. The measured RO account returned no visible local-in entries, which
  is not proof that none exist. See Fortinet's [local-in policy](https://docs.fortinet.com/document/fortigate/7.2.4/administration-guide/363127/local-in-policy)
  and [administrator trusted hosts](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/14906/administrator-account-options).

- [ ] **VDOM.** This NetOps REST path accepts successful **root VDOM only**
  responses and provides no caller-selectable VDOM/query string. The measured
  cluster had VDOMs disabled and current VDOM `root`. On multi-VDOM devices the
  API user needs `set vdom "root"` only in that mode; omit `set vdom` entirely
  in single-VDOM mode (the measured firmware rejects it there); do not change it to another
  VDOM expecting NetOps to follow. Non-root Wi-Fi is unsupported, and root Wi-Fi
  on a multi-VDOM system remains unqualified. An administrator may need the
  global CLI context to provision the user/profile, but NetOps never switches
  VDOM context for these GETs.

- [ ] **HA.** Enroll the cluster address that follows the primary. The measured
  active-passive pair reported both members `in-sync` via `get system ha status`.
  FGCP normally replicates configuration; this is the basis for expecting the
  API user and its stored key to follow the primary, **not a measured proof of
  token replication or failover**. The explicit 2026-11-09 check as `netops-test-ro` did not expose the
  protected API-user entry; the secondary's entry/key was not inspected, and no failover was forced.
  An administrator with an authorized session to the secondary through the
  primary should compare the selected API user's profile, VDOM and trusthosts
  without exposing `api-key`/ENC values. Do not generate a new key on each member.
  During a separately scheduled failover, verify the same token, cluster address
  and certificate using the MCP calls below; interrupted requests may fail and
  require a new call. Reserved per-member management interfaces are a separate,
  unqualified path. Certificate differences can cause `tls_pin_mismatch` after
  failover even when authentication is replicated. Fortinet describes
  [FGCP and its synchronization exceptions](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/062403/fgcp)
  and [local-certificate replication](https://community.fortinet.com/fortigate-3/technical-tip-how-local-certificates-are-handled-in-a-fortigate-ha-cluster-180965).

- [ ] **Time and history.** Check `get system status` and `get system ntp`, and
  the NetOps host's `date -u`. Use correct NTP/time on both: CA validity and
  token expiry depend on clocks; client duration and event chronology also use
  device epochs and the Helper clock. The device had `ntpsync: enable`, type
  `fortiguard`, interval 60; actual NTP synchronization was not established by
  those configuration reads. An HTTP 200 log response can still be empty when
  wireless events are not retained in memory. Read the relevant log settings
  without changing logging just to enable enrollment:

  ```text
  get system ntp
  show log memory setting
  show log eventfilter
  ```

### Create the access profile, API user and token

- [ ] **Use the verified minimum profile (recommended).** On FortiGate-80F
  8.0.2 build0251 the 2026-11-09 permission-isolation measurement established
  that `wifi read` plus `loggrp read` suffices: all seven GETs returned 200,
  while PUT/POST/DELETE returned 403. All other groups, including `authgrp`,
  were `none`; device identity `/monitor/user/device/query` needs no additional
  group on this measured build. All five `cli-*` privileges were disabled.
  This qualification does not establish permissions on other models/builds.

  The earlier **all-read alternative** also passed all seven GETs: set
  `secfabgrp`, `ftviewgrp`, `authgrp`, `sysgrp`, `netgrp`, `fwgrp`, `vpngrp`
  and `utmgrp` to `read` in the profile below, keeping `wifi` and `loggrp`
  at `read` and `cli-*` disabled. Prefer the verified minimum and recheck every
  endpoint, identity enrichment and history after enrollment.

- [ ] **Create a new dedicated profile and API user** (do not reuse or overwrite
  an existing identity without reviewing its consumers). Keep the separate SSH
  read-only account. On the measured firmware these are the complete setup blocks:

  ```text
  config system accprofile
      edit "netops-api-ro"
          set secfabgrp none
          set ftviewgrp none
          set authgrp none
          set sysgrp none
          set netgrp none
          set loggrp read
          set fwgrp none
          set vpngrp none
          set utmgrp none
          set wifi read
          set cli-diagnose disable
          set cli-get disable
          set cli-show disable
          set cli-exec disable
          set cli-config disable
      next
  end
  config system api-user
      edit "netops-api-ro"
          set accprofile "netops-api-ro"
          config trusthost
              edit 1
                  set ipv4-trusthost 192.0.2.10 255.255.255.255
              next
          end
      next
  end
  ```

  The block is for single-VDOM mode: do **not** issue `set vdom` there;
  FortiOS rejects it. Only in multi-VDOM mode add `set vdom "root"` inside the
  API-user entry. This provisioning syntax does not qualify multi-VDOM runtime
  reads; non-root Wi-Fi remains unsupported.

  Leave the API profile's `cli-*` privileges disabled. Do not set any group to
  `read-write`. CORS is unnecessary for this server-to-server client. Leave PKI
  peer authentication unset: NetOps does not enroll a client TLS certificate;
  requiring one would reject an otherwise valid bearer token. Do not enable
  URL-query API keys: NetOps sends `Authorization: Bearer` only. Fortinet's
  [Using APIs](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/940602/using-apis)
  explains bearer tokens, trusted hosts, PKI and optional token expiry.

- [ ] **Verify safe readback as the provisioning administrator.** These commands
  select the intended entry and suppress its encrypted key. On 2026-11-09,
  `netops-test-ro` reading `show system api-user netops-test-api-ro` returned no
  API-user entry or profile binding (SSH completed successfully). Earlier
  readbacks made through the device's provisioning login are not evidence of
  RO visibility. Visibility depends on the login/profile; an empty RO readback
  does not establish deletion or an invalid token.

  ```text
  show system accprofile "netops-api-ro"
  show system api-user "netops-api-ro" | grep -v api-key
  ```

- [ ] **Generate the token privately as an administrator with API-user rights**,
  with terminal recording disabled. An account without permission to manage
  `system api-user` cannot generate the key; the measured build requires the
  provisioning administrator (`super_admin`), not the runtime read-only account:

  ```text
  execute api-user generate-key netops-api-ro
  ```

  On measured 8.0.2 this requested the current administrator password even with
  SSH key authentication. Enter it only in that private prompt. Capture the
  generated key directly into the secret manager: never into chat, a terminal
  transcript, shell argument, URL, repository or RESULT file. The token is shown
  once; generation replaces the previous key. If an expiry is configured, record
  its deadline and rotate before it expires. No regular SSH password/session
  login substitutes for this separate API token.

### Certificate and SHA-256 pin

- [ ] Read `admin-server-cert` above, then inspect **that selected local
  certificate**, through a separately trusted administrative channel. In this
  example `Fortinet_GUI_Server` is the certificate-name placeholder; replace it
  when the setting selects another name:

  ```text
  get vpn certificate local details "Fortinet_GUI_Server"
  ```

  On measured 8.0.2 the `Fingerprint` field is 32 colon-separated SHA-256 bytes
  and matched the HTTPS DER hash. Remove colons and lowercase it to obtain
  NetOps' 64-hex-digit pin. Older versions may display another digest length;
  do not pad a SHA-1/MD5 fingerprint into a pin. If the CLI cannot supply SHA-256,
  securely export only the public certificate through the trusted administrator
  GUI and hash its DER form. Never export its private key.

- [ ] Compare the certificate actually presented **from the NetOps host/network
  path**. For the example enrolled IP address, run in Bash:

  ```sh
  set -o pipefail
  # Replace 443 with admin-sport when different.
  openssl s_client -connect 192.0.2.1:443 </dev/null |
    openssl x509 -outform DER |
    sha256sum
  ```

  For an enrolled DNS name, use this complete variant (`fg.example.net` is the
  enrolled DNS-name placeholder; use the same name for connection and SNI):

  ```sh
  set -o pipefail
  # Replace 443 with admin-sport when different.
  openssl s_client -connect fg.example.net:443 -servername fg.example.net </dev/null |
    openssl x509 -outform DER |
    sha256sum
  ```

  This must match
  the trusted administrative SHA-256; `s_client` alone does not establish identity.
  Hash the leaf **DER certificate**, not PEM text, the public key or the SSH key.
  Nonzero pipeline status means the fingerprint acquisition failed.

- [ ] Record certificate name, pin, validity dates and renewal owner. Renewal,
  replacement, selecting another `admin-server-cert`, or firmware regeneration
  of the GUI certificate changes the DER pin even if its key/name remains the
  same. A firmware upgrade does not necessarily replace the certificate; check
  it after upgrade and HA changes. A changed certificate causes
  `tls_pin_mismatch` before NetOps sends any bearer token. Verify a new pin
  independently and reconfigure NetOps; do not automatically trust the peer or
  disable verification. Alternatively use a validated CA and a matching enrolled
  hostname/SAN, with the public CA mounted read-only below
  `/etc/netops-helper/certs`; see [Helper configuration](helper-configuration.md#optional-helper-fields).
  If both CA and pin are enrolled, **both must pass**. CA verification also checks
  certificate validity dates; a pin alone is exact certificate identity, not a
  CA-chain/date validation policy.

## Store the token in NetOps

- [ ] Prepare the **complete** private `configure helper` input, preserving the
  existing SSH inventory and all credentials; see the
  [Helper configuration schema/example](helper-configuration.md).
  Add this entry to `vault.credentials`. The token and hash markers below are
  deliberately invalid schema illustrations, not values to copy unchanged;
  fill them through your private secret-input workflow. They are never shell
  command placeholders.

  ```json
  "fortigate-wifi-api-ro": {
    "kind": "api-token",
    "login": null,
    "value": "REPLACE_PRIVATELY_WITH_GENERATED_KEY"
  }
  ```

  On the selected device's `helper` section add:

  ```json
  "fortios_rest_port": 443,
  "fortios_rest_credential": "fortigate-wifi-api-ro",
  "fortios_rest_certificate_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_SHA256_DIGITS"
  ```

  Alternatively omit the pin and set `tls_ca_certificate` to the validated CA
  path. Keep `ssh_platform: "fortios"`, the target address and the existing SSH
  port. `fortios_rest_port` is optional (default 443), a whole number 1–65535;
  set it to `admin-sport` for a different management listener. Add that same port
  to `helper.egress.tcp_ports` (or its nonoverlapping range), keeping SSH allowed.
  The port must be reachable from the actual Helper container: host egress,
  intermediate firewall and return routing apply. There is no raw token in
  inventory. The credential reference must resolve to an `api-token` record on
  a FortiOS target with certificate trust and the selected TCP port allowed.
  `configure helper` refuses a port outside egress; `target_scope` reports the
  effective `fortios_rest_port`.

  For triage retain `system_status` and the desired RO Wi-Fi queries in
  `enabled_queries`. `wifi_events` is optional for REST history: triage first uses
  the fixed wireless log GET. SSH history fallback needs `wifi_events` enrollment;
  unavailable history remains explicit.

- [ ] Protect the full private input with mode 0600 **outside the repository**.
  From the deployed instance's Compose directory, apply it through stdin:

  ```sh
  docker compose stop
  docker compose run -T --rm netops configure helper < helper-private.json
  docker compose up -d --wait
  ```

  `helper-private.json` is a private input filename placeholder. `configure helper`
  validates before replacing role files; it is not a partial merge. The token has
  the existing vault ownership, file protection and role isolation. Securely
  remove the private transfer input according to the normal secret procedure.
  Existing targets require no migration.

## Verify access

- [ ] In an already authenticated MCP session, send these concrete `tools/call`
  requests, one at a time. `fg-wifi` is the enrolled target-name placeholder;
  replace it with the exact inventory alias. These are complete JSON-RPC request
  bodies, not unauthenticated HTTP requests:

  ```json
  {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"target_scope","arguments":{"target":"fg-wifi"}}}
  ```

  Expect `ok: true` and `fortios_wifi_rest_enrolled: true` in the structured
  result, and verify `fortios_rest_port` equals the effective `admin-sport`
  (default 443). This flag verifies enrollment only; it makes no device request and
  does not prove HTTPS/token validity. The token value is never returned.

  ```json
  {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wifi_clients","arguments":{"target":"fg-wifi"}}}
  {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wifi_aps_live","arguments":{"target":"fg-wifi","summary":true}}}
  {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"wifi_rogue","arguments":{"target":"fg-wifi","full":true}}}
  ```

  Expect `ok: true` and successful root-VDOM GETs in audit. Empty lists can be
  valid observations; match a known associated client and its AP/radio/RSSI to
  the controller. Audit identifies the fixed endpoints, never the bearer.
  A real device/permission problem must remain an explicit error or gap.

- [ ] With a known associated station, run triage. `00:00:5e:00:53:21` is a
  documentation MAC; replace it with the station being checked:

  ```json
  {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"wifi_triage","arguments":{"target":"fg-wifi","mac":"00:00:5e:00:53:21","summary":true}}}
  ```

  Expect live signal evidence and no `missing` item with `step: "client_rssi"` when the device
  supplies RSSI/SNR. Inspect identity and history gaps too: the device-query GET
  is optional enrichment, so a successful live client list alone does not prove
  it works. No token means the three REST tools return `unsupported` without a
  device request, and triage reports `rest_token_not_enrolled` for live signal.
  An absent station/history or missing data does not prove a healthy connection.

- [ ] Verify the profile and /32 trusthosts through the provisioning administrator.
  Existing measurement demonstrates PUT/POST/DELETE 403, but those are historical
  lab checks, **not enrollment verification commands**. No write probes are
  required or exposed by NetOps. Failover and wrong-pin tests belong to a
  separately authorized lab/change, not this routine read checklist.

## Troubleshooting

Public REST failures include `error_code`, the fixed endpoint in `failed_step`
and numeric `http_status` when available. Read the precise code; triage's legacy
`error_subcode` can be coarser. Do not regenerate tokens, widen trusthosts or
change management ports automatically.

| Error or symptom | Likely cause | What to check |
| --- | --- | --- |
| `tls_pin_mismatch` | Presented leaf DER differs from enrolled pin | Read `admin-server-cert` and its selected certificate again; compare the SHA-256 DER hash from the NetOps host. Check renewal/replacement, upgrade, HA member and TLS interception. Verify identity before replacing the pin; bearer was not sent. |
| `tls_verification_failed` | CA chain, SAN/name, expiry or clock failure | Correct CA mount/path, enrolled DNS/IP SAN, certificate validity and time on the Helper host; when a pin is also set it must match too. |
| `tls_error` | TLS handshake/record problem | HTTPS listener, TLS 1.2+ support, service collision or interception, certificate and any required client-certificate/PKI setting. |
| `authentication_failed`, HTTP 401 | Wrong/expired/revoked token, replaced key, or rejected source trusthost | Check the API user is the intended one, vault reference, rotation/expiry and source IP **after NAT**. A working SSH password is not an API token. |
| `authorization_failed`, HTTP 403 | Access profile/VDOM is insufficient; source or local access restrictions can also block access | Check the selected API user's profile/VDOM and exact failing endpoint. Recheck trusthosts and management restrictions. The verified minimum on 80F 8.0.2 build0251 is `wifi read` + `loggrp read`; all-read is an alternative. For identity `/monitor/user/device/query` on other builds check whether `authgrp read` is required; do not grant write permissions to fix a GET. |
| `timeout` | Ten-second DNS/connect/TLS/read deadline; filtered path or failover | Host/container route and return route, host egress, intermediate firewall/NAT, interface `allowaccess https`, ordered local-in rules and cluster state. |
| `helper.fortios_rest_port is invalid` during configuration | Selected REST port is outside TCP egress or not an integer 1–65535 | Match `admin-sport`, `helper.fortios_rest_port` and `helper.egress.tcp_ports`/ranges; this diagnostic concerns the port, not the credential. |
| `transport_error` / connection refused | Wrong port/address, absent HTTPS listener, DNS or TCP failure | Match `helper.fortios_rest_port` (default 443) to `get system global` `admin-sport` and TCP egress; inventory SSH `port` is independent. |
| HTTP redirect / `http_status` | Reached another service, redirect or non-200 response | HTTPS on the exact enrolled address and `fortios_rest_port`; NetOps never follows redirects. `admin-https-redirect` cannot repair a missing HTTPS listener. |
| Source works on one host only | API /32 trusthost or local admin aggregate restrictions, different NAT path | Use the source visible to FortiGate, not the container IP; compare routing and the selected API user's safe trusthost readback. |
| `unparsed_envelope` | Wrong/non-root VDOM, failed envelope or unsupported response layout | `get system status`, API-user root scope (`set vdom "root"` only in multi-VDOM), build and endpoint. Non-root is unsupported; do not change the parser or scope as a workaround. |
| `configuration` / `egress_denied` | Local enrollment or address/port allowlist failure | Existing `api-token` reference, 64 lowercase hex pin or CA, FortiOS platform, target address and allowed TCP `fortios_rest_port` (default 443). |
| Empty history or identity gap | No retained wireless events/device record, optional endpoint refused | Wireless memory-log retention and `loggrp`/`authgrp`, failing GET and HTTP status, device/host clocks. No automatic logging change. |

Other bounded transport/response errors retain the following codes:

| Code | Meaning |
|---|---|
| `http_server_error` | HTTP 500–599 |
| `invalid_json` | Malformed JSON, duplicate keys, invalid encoding or excessive nesting |
| `invalid_response` | Nonfinite numeric value or a rejected normalized response |
| `response_too_large` / `unsupported_encoding` | Response exceeds 2 MiB or is compressed |
| `rate_limited` | Local rate budget or HTTP 429; respect the target window |

For existing triage clients `error_subcode` keeps the coarse codes: TLS
pin/verification, timeout, rate, egress and `invalid_response` retain their names;
401/403/5xx map to `http_status`; other new diagnoses map to
`transport_or_response_error`. Use `error_code` for precise diagnosis. These
responses contain no device response body, token or raw transport exception.

## Rotate and revoke

- [ ] **Rotate the token** privately using the same complete command:

  ```text
  execute api-user generate-key netops-api-ro
  ```

  Replace `fortigate-wifi-api-ro` in the private vault input, apply the stopped
  instance configuration flow above and repeat the MCP GET verification.
  Generation invalidates the old token: arrange a short diagnostic outage. For
  staged handover provision a second separately scoped RO API user, enroll and
  verify it, then delete the old user. Do not regenerate keys separately on HA
  peers; verify replication and the active address through the administrator.

- [ ] **Rotate certificate trust independently.** After a legitimate certificate
  change, compare trusted administrative and presented DER hashes again before
  updating `fortios_rest_certificate_sha256` through `configure helper`. With a
  CA-only enrollment a valid renewal with the same trusted CA/SAN normally needs
  no pin update; with both CA and pin it still does. Never bypass a mismatch.

- [ ] **Revoke** by deleting the API user, then removing its
  `fortios_rest_credential`, unused `fortios_rest_certificate_sha256` and unused
  vault record from the complete private NetOps input and applying it again.
  Confirm `target_scope` now reports `fortios_wifi_rest_enrolled: false`; the
  three REST tools return `unsupported`. Preserve any CA/egress settings still
  used by other functions. Delete the profile only after confirming no other
  identity uses it:

  ```text
  config system api-user
      delete "netops-api-ro"
  end
  ```

  ```text
  config system accprofile
      delete "netops-api-ro"
  end
  ```

  In HA have the administrator verify deletion is replicated; `in-sync` alone
  was not a token-validity test in this measurement. To disable only NetOps REST,
  remove its enrollment/vault record and return to SSH diagnostics; device-side
  revocation is still required when the token itself must become unusable.


## Normalized Wi-Fi data

All REST absolute times are ISO 8601 in UTC (`+00:00`). `association_time`, AP
`join_time`/`last_reboot_time`, radio `channel_utilization_timestamp` and rogue
`first_seen`/`last_seen` use device epochs. Observer wall clocks (`detected_by_wtp`)
are converted to UTC with the offset computed from the parent device local/UTC pair. When neither an epoch nor
a device offset is available, the time is null; the Helper host timezone is never
assumed. Durations such as `connected_seconds` remain numbers.

AP `mem_free_kib` and `mem_total_kib` are KiB (1024 bytes). The misleading
`client_count_max` is omitted. `wtp_rebooted` is the device's AP reboot summary;
the firmware supplies no explicit interval, so it must not be read as a lifetime
or since-probe counter. `ipv6` omits the unspecified address `::` and invalid
addresses. `band` contains only `24ghz`, `5ghz`, `6ghz` or null; `phy_mode` holds
the PHY mode. Unknown PHY modes do not produce a guessed band.

`wifi_rogue(target, limit=100, min_signal=null, offset=0, max_bytes=16000, mac=None, ap=None, full=false)` defaults to
neighbors relevant to the selected client/AP; without a selector it uses active
clients' radios. Default minimum signal is −75 dBm. It filters locally by AP
observer where available, band and possible spectral overlap of channel widths,
then groups by BSSID with `deduplicated_bssid` and `observation_count`. Missing
context returns `relevance.status=missing_context`, not proof of a clear channel.
Unknown neighbor width uses only its primary frequency and is marked in the
relevance explanation. Unknown own-radio width sets `relevance.status` and `overlap` to `width_unknown`: an exact primary-channel match remains relevant in the same band, while other spectral overlap is unknown. A context GET failure returns `context_read_failed` with fixed `error_code`, `failed_step` and available HTTP status; this differs from no active clients. For 2.4 GHz,
unknown secondary direction gives only possible overlap. No age cutoff is invented;
last-seen timestamps are retained for the operator. `full=true` requests the full
list (no default signal threshold) and retains all observations per BSSID. Total
counts describe source rows, `matched` describes relevant rows, `unique_bssid`
describes grouped rows and `returned` the page. Rogue is not a fault or attack by itself.



All three REST tools accept `limit=100` (1–500 records), `offset=0`
(0–8,000,000 records) and `max_bytes=16000` (1,000–48,000 bytes), with published
schema bounds. Filters, AP joins and summary conversion precede paging.
`has_more` and `next` explicitly identify additional data; `page` gives full
counts and the returned count. Rogue rows precede interfering rows in the
shared offset. Reissue the same tool and filters with `next`'s arguments to
read further. Each page is a fresh read charged normally; compare
source hashes and restart if the table changes. One indivisible row or metadata
that exceeds the byte budget returns `result_too_large`; increase the budget
or narrow the filter. [Full paging contract](../components/netops-helper/docs/tools.md#bounded-table-and-rest-results).


## Diagnostic interpretation in 1.0.7

Client identity fields `hostname`, `os`, `device_type` and `vendor` contain
`unknown` when neither source supplies them. `identity_sources` names the GET
for each known field; joins require a unique exact MAC, including private MACs.

`link_rx_mbps` and `link_tx_mbps` are separate reported PHY link rates, **not
throughput** and must not be summed into a download speed. The earlier candidate
1.0.7-only `data_rate_bps` and duplicate `rx_rate_bps`/`tx_rate_bps` have been removed; use the Mbps link fields.
Traffic `bandwidth_rx/tx` is kept with its source names: its unit and averaging
interval are unspecified by the measured envelope. Retry/discard percentages and
`idle_seconds` give context, but zero retry with no traffic does not prove quality.

Both triage views include `chain.observation`: one AP name, radio, band, primary
channel, source channel width, RSSI/SNR, utilisation/retry, capture and radio
measurement time/age, traffic state and source DFS state if present (otherwise
null). AP summaries hide nonexistent radios, distinguish nonoperating radios and
never present zero noise as a measurement. PHY mode alone does not prove client
Wi-Fi generation or DFS state. Full detail retains AP serial/ID and LLDP.

`rf_verdict` is `incomplete` when deciding RF values are missing: client RSSI/SNR,
AP/radio/band/channel/width, utilisation, retry, noise, interference count and radio
sample time. Station and AP channels must agree. A missing background RF scan row
or neighbor scan alone does not make these operating-radio measurements incomplete.
When the RF table omits the operating channel, `chain.rf` uses the selected
`managed_ap` radio counters and names their source; the optional scan gap remains
explicit with `required_for_rf_verdict: false`. No other AP's channel row is used.
`no_rf_fault_found` requires these deciding values with no triggered RF rule; `rf_concern_found` means a heuristic triggered. Top-level `verdict`
uses these unless a fault or fault-level finding gives `fault_found`. This is
never a verdict about working Internet, DNS or application throughput. The
separate `missing.locate_endpoint` includes AP LLDP uplink context, not proof
that the cable, switch or gateway works.

Inventory `helper.wifi_thresholds` accepts integer overrides with these defaults:

```json
{"weak_signal_dbm": -70, "very_weak_signal_dbm": -75, "low_snr_db": 20,
 "busy_percent": 70, "retry_percent": 20, "interfering_aps": 5,
 "strong_neighbor_dbm": -60}
```

RSSI minimum below −70 gives `F-WIFI-WEAK-SIGNAL` warning. It has higher `fault` severity and `fault_level=true` only if both minimum and final snapshot are below −75. A transient dip followed by recovery, an unavailable final snapshot or final absence remains warning with an explicit note. Low SNR below 20 gives `F-WIFI-LOW-SNR` warning. Other radio
thresholds retain their notice semantics. dBm bounds are −150..0, SNR/percentage
bounds 0..100, interfering AP count 1..1000; the very weak threshold must be below
the weak threshold. These are operational heuristics, not manufacturer limits.
Each finding includes `text` with a measured fact, threshold when applicable,
time, interval limitation and first action; IDs remain for automation.

History contains an ascending client `timeline` (connect/auth/roam/disconnect/DHCP,
AP/radio and reason/status), and a window with from/to, scanned/client counts and
human-readable coverage. Summary selects significant events: failures and disconnects with reasons,
AP transitions (old → new, band where supplied and time), last successful
connection and only the last DHCP, together with full window counts; full detail retains the bounded timeline. REST triage window times cover the selected client's returned records
(`scope: client_records`); `device_found` is the count matching the server filters,
not the global event count. `device_returned`, `scanned_records`, skipped/undated
counts, `filter_mac` and `complete` distinguish a full retained client history from
a bounded or incomplete window. Completeness requires all matching records,
100 percent processing, readiness and no skipped records. SSH window times cover
the locally filtered client records of its bounded global batch and say so. Missing records are not proof that an event did not happen.
Authentication reason/status is evaluated independently of disconnect class, including handshake timeout and previous authentication no longer valid. Unmeasured text and numeric reason interpretations are heuristics: no bad-password live fixture has qualified them. `timeline_type` follows the final class computed from description/reason/status/action; `authentication_failure` is a separate flag.
An error older than the last successfully observed association becomes notice:
“historical error, client connected at last observed association”, even if a later
snapshot fails or the client is absent; errors after that association retain
fault severity. Device/Helper clock skew limits this time comparison.


Calls on one target are serialized. A triage taking about 25–30 seconds blocks
other reads of that target until completion; transport delays and signal sampling
can extend it. Do not expect concurrent polling of the same target during triage.
With REST and a resolved MAC, the reservation is 15 reads: seven possible CLI
reads, one client/AP/identity read, two station-only snapshots, one history GET and rogue/interfering GETs. Snapshot starts are
about three seconds apart; slower reads extend the interval. `chain.signal_samples`
contains actual fetch times, per-snapshot AP/radio and RSSI/SNR min/max/last. A
missing or failed final sample has last=null, never a copied earlier value. Weak
signal uses all successful samples, even when the last fails or the client disappears, and explains whether the last value remains weak or has recovered; low SNR uses the minimum too. These snapshots can miss shorter changes.

A MAC absent from the final successful station snapshot returns `ok=true` and
`verdict=client_not_associated`, with `chain.association` and retained history
(last AP, disconnect/reason, authentication failures). A logged cause is evidence,
not proof of continued absence; missing evidence gives cause `unknown`. A failed
REST read gives association status `unknown`, not a diagnosed absence; `last_observed_status` and `last_observed_at` retain the last successful association separately. Top-level `client_not_associated` takes precedence, while `rf_verdict` and `findings_max_severity` remain visible in full and summary (including a fault on the last AP).

Both views separate `chain.client_state` (signal/link) from `chain.radio_context`
(utilization/retries). Radio findings explicitly say "radio-wide, shared by N
clients, not specific to this client". They name the source and known averaging
interval; the SSH utilization interval is retained, while the measured REST
source supplies no averaging interval and retries have no sample time/interval.
`fetched_at` and the compatible `captured_at` are retrieval times, not measurement
times. `measurement_age_seconds` and `radio_measurement_age_seconds` remain null
with a note for unknown measurement time. A utilization timestamp applies only
to `channel_utilization_age_seconds`, not retries or RSSI/SNR.

`chain.events.summary` in full detail and `chain.events` in summary include
significant `timeline` (at most 20 groups), `last_connection`, `last_disconnect`, `last_ap`, `last_dhcp`, `authentication_failures` (bounded event-index references) and `authentication_note`. Consecutive repetitions carry `repetitions` and `first_time`; `timeline_total`, `timeline_omitted` and `timeline_aggregated` account for the selected history. Authentication failures have total and omitted counts. Full `timeline` pages every parsed station event from the bounded window using
`history_limit` (default 100, 1–500) and `history_offset` (default 0, 0–8 000 000).
Full events use the same compact diagnostic fields as summary plus
`source_sha256`, the redacted log source hash. The **entire structured full
result is at most 48 000 bytes**, including findings, significant-history summary
and paging metadata. The text MCP copy adds transport overhead. `truncated`,
`page` and `next` report continuation; pass `next.history_limit` and
`next.history_offset` to the next call with the same selector. Each page rereads
sources and consumes 15 reads and about 30 seconds; the default rate limit of 30 reads per 60 seconds permits two pages per window. Prefer `summary=true` when full history is unnecessary; compare hashes and window bounds
to detect changing history. Summary remains bounded to 20 significant groups
and does not apply these full-history page selectors. Oversized metadata or one
indivisible event returns `result_too_large`, with no nonadvancing continuation.
Full detail has source hashes, while summary omits them. The full live client omits the complete managed AP record and events have no duplicate `recent` list. The note says
"no authentication failure in retained history of this MAC" when none is found,
with an incomplete-window qualification where needed. Log level `warning` on a
successful handshake does not turn it into a failure. AP changes inferred from
consecutive logged connections are labeled observations, not proof of a forced
roaming cause. Unknown bands remain null.

Client logs may omit `radioband`. An unambiguous primary channel supplies the
band with `band_source=unambiguous_primary_channel`; channel numbers that overlap
bands remain null. A raw disconnect reason such as `Reserved 0` is retained in
history but gives association cause `unknown`, not an invented explanation.


Hostname selection (`name`) requires read-only REST enrollment and identity access
(`/monitor/user/device/query` when the station endpoint has no hostname). On
the verified 80F 8.0.2 build0251 minimum profile this needs no separate User & Device
(`authgrp`) permission; other builds require their own read verification. A failed identity read is propagated in `missing` with fixed
failure fields; it is not proof that the named client is absent. Both name-selected
tools return `identity_trust: "client_supplied"`. DHCP/device hostnames are claims
by the client, not authenticated identities: an offline device's name can be
impersonated without a collision. Use a verified MAC for identification and
recheck private-MAC changes. Unicode Cc/Cf controls are refused in selectors and
make identity text unknown. Public client rows use one AP label and a distinct
serial (or unresolved ID), without duplicate AP name/ID fields.

History advice suggests SSH `wifi_events` only when REST history is unavailable
and that query is enrolled. Otherwise it points to REST enrollment via
`target_scope`; successful REST history needs no SSH advice. SSH scans a bounded
global batch; REST filters by station before the row bound. A controller-wide
SSH scan lacks observer and band/width evidence, so its primary-channel matches
are context only. A triage neighbor finding requires `wifi_relevance` to establish
the client's AP observer, band and possible spectral overlap.
