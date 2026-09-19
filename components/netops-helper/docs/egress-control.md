# Egress control

## What the contract does

The public Compose network is a stable Docker bridge named `netops-helper` with host interface `nh-egress0` and `internal: false`. Outbound diagnostics require this external connectivity.

`scripts/generate_egress_rules.py` reads `inventory.json` and `egress-policy.json` - never the vault - and produces a deterministic, secret-free bundle for the reviewed iptables backend. Its inputs are the common `address` and `port` of every device whose `helper` section is an object, the ports and flags of `helper.egress`, and the eight fields of the egress policy; a device without a helper section is ignored. `scripts/apply_egress_rules.py` applies an exact managed-chain transaction, and `scripts/check_egress_rules.py` compares observed Docker/iptables state with the bundle. These are privileged operator tools and are never exposed through MCP.

The generated DOCKER-USER jump matches traffic forwarded from `nh-egress0`. It permits only the profile's derived IPv4 destinations, protocols, and ports, then drops other forwarded traffic from that bridge.

`manifest_sha256` is the SHA-256 of the bundle's canonical normalized `manifest` object. It binds the rendered rule marker and lets apply/check detect manifest/ruleset substitution. It is not a digest of the policy file, the source revision, or the original input bytes. The manifest does carry `inventory_sha256`, the SHA-256 of the inventory file the bundle was generated from, so one bundle names the enrollment it came from. The normalized manifest intentionally omits device names and can deduplicate identical effective scopes, so the operator must review its actual network scope and separately record the transferred bundle digest.

Bundle schema 3 contains only the IPv4 ruleset that the apply helper actually installs. It does not generate or claim an ip6tables chain. The IPv6 boundary is the Compose network setting `enable_ipv6: false`, represented in the manifest as `network_ipv6_enabled: false` and `ipv6_boundary: docker-network-disabled`. Apply verifies Docker's exact `EnableIPv6: false` state before inspecting or changing IPv4 firewall state; missing, ambiguous, or enabled state fails closed. This is a network-scoped boundary, not a host-wide IPv6 firewall claim.

The stable bridge name is the rule anchor. A fixed container subnet is intentionally unnecessary for interface-based matching and could collide with existing runner addressing.

## Profiles

`strict-target` preserves per-target destination and port associations. Use it whenever Docker/iptables behavior on the runner supports the generated rules.

`lan-constrained` requires a non-empty, unique list of canonical IPv4 CIDRs. Every CIDR must be wholly contained within one of the three RFC1918 blocks; public ranges, IPv6, non-canonical host-bit forms, and supernets spanning beyond RFC1918 are rejected. Every enrolled target destination must fall inside at least one declared CIDR.

For this profile, the generator forms the union of every enrolled target's TCP ports/ranges, UDP ports/ranges, and ICMP permission, then grants that entire union to every address in every declared LAN CIDR. DNS remains separately limited to the explicit resolver list. Consequently, an enrolled port for one target becomes reachable on all hosts in all declared LAN CIDRs. This deliberately catches internet exfiltration while accepting substantially broader lateral reach than `strict-target`; it is not per-target isolation.

`strict-target` is bounded by each target's canonical addresses and its own effective port/range/ICMP scope. Both profiles use explicit resolver addresses and the device `port`, derived only when that device has an `ssh_platform` with enabled queries or at least one SFTP root; TLS probes require explicit TCP scope, and FTP requires an explicit control port and passive TCP range. No HTTPS port is derived.

## DNS

A device named by a host name requires all three:

- `allow_dns: true`;
- non-empty canonical `egress.addresses`;
- explicit `dns_resolvers` in the egress policy.

The server resolves the host name and rejects any canonical IPv4 result outside that address list. The firewall bundle exposes only aggregate DNS permission and resolver addresses, not hostnames or TLS names.

Docker commonly presents `127.0.0.11` to the container as embedded DNS and performs forwarding/NAT internally. The exact path is engine- and host-dependent. A generated upstream-resolver rule is not proof that embedded DNS is constrained or even functional.

Once UDP/TCP 53 is permitted to a resolver, a compromised process can use DNS queries as an exfiltration channel; the firewall does not validate requested names. The strictest profile therefore uses literal IP targets, `allow_dns: false`, and no resolvers. Hostname targets accept this DNS tradeoff. Even with `allow_dns: false` the chain only drops resolver traffic that leaves the bridge as forwarded packets; queries the container sends to Docker's embedded `127.0.0.11` are answered or forwarded by the Docker daemon from the host's own network stack, which DOCKER-USER never sees. Closing that path is a host INPUT/OUTPUT decision, not something this bundle can enforce. Application-level resolution checks also have re-resolution/TOCTOU limits, so the verified host firewall remains the authoritative network boundary.

## Residual host-access boundary

DOCKER-USER controls forwarded traffic. It does not claim complete containment.

Traffic from `nh-egress0` to a service on the runner host itself may traverse INPUT rather than FORWARD and can therefore fall outside the managed chain. This release does not install a generic INPUT drop. Doing so before observing Docker embedded DNS/NAT behavior could break DNS or other host networking.

Before relying on the control, an ARM64 live test must verify:

- allowed and denied target address/port combinations;
- the Docker network remains IPv6-disabled and IPv6 is unavailable to its containers;
- DNS success and denial behavior through `127.0.0.11`;
- attempts to reach runner-local listening services through bridge and host addresses;
- survival and ordering of the DOCKER-USER jump across Docker restart;
- checker detection of rule drift.

The checker and the apply helper require the DOCKER-USER jump to be the first rule of FORWARD, the position Docker itself installs; an earlier `ACCEPT` would bypass the managed chain, so any other ordering fails closed as `docker_user_unreachable`.

## Persistence across reboot

The apply helper writes live kernel state only. Nothing in this project persists the rules: after a reboot the chain is gone while `restart: unless-stopped` brings the container back with unrestricted egress. Re-apply the reviewed bundle from the host before the container is reachable, for example with a oneshot unit ordered after Docker:

```
[Unit]
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/netops-helper/scripts/apply_egress_rules.py --bundle /etc/netops-helper/egress-bundle.json --apply

[Install]
WantedBy=multi-user.target
```

The helper is idempotent and fails closed, so a repeated run is safe; the checker should still run after every Docker restart or network recreation.

The helper reads and writes rules through whichever `iptables-save`/`iptables-restore` binaries are on `PATH`. If those are the legacy backend while Docker installed its chains through iptables-nft (or vice versa), the DOCKER-USER chain does not appear in the observed state and the run fails closed as `docker_user_missing` rather than installing rules into a table Docker never consults.

If runner-host access must be denied, design a host-specific INPUT policy after these observations, preserve required DNS/NAT behavior, and retest. Do not describe the generated rules as a sandbox or full compromise containment.

## Apply-helper limits

The apply helper requires root, an explicit `--apply`, a mode-600 bundle, and working `docker`, `nft`, and `iptables-save`/`iptables-restore`. It uses `nft` even for the reviewed iptables backend to detect unsupported native Docker nftables state. An indeterminate backend, a missing/unreachable IPv4 DOCKER-USER hook, or any Docker network IPv6 state other than the exact boolean `false` fails closed before an IPv4 restore.

The single IPv4 `iptables-restore` COMMIT is atomic. If later verification fails, rollback of the tool-owned marked jump and private chain is best effort; operator recovery may still be required. The helper never edits unrelated chains and never invokes ip6tables.

The checker validates the supplied bundle internally and compares it with observed Docker network and IPv4 ruleset state. It does not reread the inventory or the egress policy, prove that enrollment has not changed, execute live traffic tests, or cover runner-host INPUT. A passing checker is therefore necessary but not sufficient and must be rerun with a freshly generated bundle after every relevant enrollment or Docker-network change.

## Operator workflow

1. Stop if the Compose network name, bridge name, backend, or policy schema differs from the reviewed contract.
2. Generate a bundle using file paths, never inline credential JSON.
3. Recompute the transferred bundle digest, verify `manifest_sha256` against its canonical manifest, and review the profile, normalized destinations, ports/ranges, DNS rules, declared Docker IPv6-disabled boundary, rendered ruleset, and final IPv4 default drop. Do not interpret `manifest_sha256` as a source-file digest.
4. Keep an out-of-band recovery path.
5. Apply the exact bundle with the dedicated helper under the minimum required privilege.
6. Run the checker against live observed state.
7. Perform the ARM64 traffic tests above.
8. Regenerate, reapply, and recheck after any device entry, helper section, metadata/listing root, port, Docker network, or resolver change.

Generated bundles reveal network scope even though they contain no credentials. Store them as environment-sensitive operational data and never publish them as release artifacts.
