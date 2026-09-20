# Installation

NetOps Helper phase 1 uses three trust zones:

- a dedicated read-only MCP agent/session;
- a local proxy host holding the inventory, the credentials, the host key pins, and the runner file;
- an execution host running the isolated container and reaching enrolled targets.

The proxy and execution host may share one machine in a deployment. Device-side authorization, the egress contract, and the dedicated client session remain separate mandatory boundaries.

## 1. Prepare target accounts

Create a dedicated identity on every target and enforce read-only permissions on that platform. Do not reuse administrator, Docker-enabled, sudo-capable, or future write-service credentials. Test both the intended named diagnostics and denial of configuration display/export, configuration mode, file writes, maintenance, privilege escalation, and shell escape over the same SSH/AAA path that NetOps Helper will use.

For FortiOS, an administrator must configure and verify persistent console `output standard` before enrollment. The runtime never changes paging mode. See [Read-only accounts](read-only-accounts.md).

If SNMP is required, create a separate read-only community that is not the SSH password. SNMPv2c sends it in plaintext, so restrict source and destination ACLs and the enrolled UDP egress scope.

The same device credential is used for SSH, SFTP, FTPS, and plain FTP. Plain FTP sends those credentials without encryption. Prefer FTPS; if legacy FTP is unavoidable, use a separate remote FTP identity and target alias, and enforce rejection of SSH/SFTP for that identity on the target. Policy `sftp_roots` also authorizes `sftp_stat`, so policy alone is not an FTP-only protocol boundary. Review [credentials and protocol use](configuration.md#credentials-and-protocol-use) before creating accounts.

## 2. Install the shared access layer on the proxy host

The proxy and the egress generator import `netops_core` and `netops_helper`. Both come from the tree of this repository, not from an index: install `components/netops-core` and `components/netops-helper` into the environment that runs the proxy, or put `components/netops-core/src` and `components/netops-helper/src` on `PYTHONPATH`. The scripts add both directories themselves when they are started from a checkout, so a checkout needs no further setup.

From a release export the same two ways apply to the unpacked archives: `python -m pip install <netops-core directory> <netops-helper directory>` into the environment that runs the proxy, or their `src` directories on `PYTHONPATH`. **Both archives are needed for that path**, and in that order: the helper archive carries a copy of `netops_core` for the image build, but its metadata still pins `netops-core==0.2.2`, which no index serves, so `pip install <netops-helper directory>` on its own ends in `No matching distribution found for netops-core`. That is the pin doing its job, not a damaged archive.

Installing has two practical advantages over `PYTHONPATH` on a proxy host. It puts the proxy on the path as the command **`netops-helper-proxy`**, which is what a client is then configured to launch instead of an absolute path into an unpacked archive. And it puts the askpass program on the path as **`netops-askpass`**, which `NETOPS_ASKPASS_PROGRAM` may name on a host whose temporary directory is mounted `noexec`; without it, such a host cannot hand a password to the client at all, because the program written beside the secret cannot be executed there.

## 3. Prepare configuration and trust on the proxy host

Use `$XDG_CONFIG_HOME/netops-helper` or set the documented `NETOPS_*` variables. All four files are described in [Configuration](configuration.md#the-four-operator-files).

1. Create `vault.json` with mode `600` or `400`; it is one JSON object of credential records, not JSONL. Follow [credentials and protocol use](configuration.md#credentials-and-protocol-use).
2. Copy `config/inventory.example.json` to `inventory.json` and replace every documentation address, name, and pin.
3. Declare exact platform, query, inventory, metadata/listing-root, and egress scope and a suitable rate limit in the `helper` section of every device.
4. Obtain the host key fingerprint of the runner and of every device through an independently trusted channel, exactly as `ssh-keygen -lf` prints it, and write it into `runner.json` and into each device's `host_key_fingerprint`.
5. Copy `config/egress-policy.example.json` to `egress-policy.json` and `config/runner.example.json` to `runner.json`; the runner has no inventory entry and can never be addressed as a target.
6. Delete any `target-policy.json` and unset `NETOPS_TARGET_POLICY_PATH`, `NETOPS_KNOWN_HOSTS_PATH` and `NETOPS_MASTER_ALIAS`: the proxy refuses to start while one of them is present.

The device `address` is either a canonical IPv4 literal or a canonical lowercase host name. A host name additionally needs explicit enrolled canonical IPv4 results, DNS permission, and configured resolvers. IPv6 devices are not supported in this release.

For private TLS or FTPS trust, complete [the private CA, SAN, and FTPS pin procedure](configuration.md#private-tls-and-ftps-ca-san-and-pins) before building the runner image. The stock image works with certificates chaining to its public system trust. It does not normally trust a private device CA or self-signed device certificate.

## 4. Build and create stopped Docker resources

Install Docker Engine with Compose v2 and obtain a verified release on the execution host. The image needs both `src/netops_helper` and `src/netops_core`. In the repository `compose.yaml` builds from the repository root and passes the two build arguments `COMPONENT_DIR=components/netops-helper` and `CORE_PACKAGE_DIR=components/netops-core/src/netops_core`; in a release export (`scripts/create_release_artifacts.py`), which carries `src/netops_core` inside the component tree, the exported `compose.yaml` builds from the archive root (`context: .`) with the Dockerfile's own defaults (`COMPONENT_DIR=.`, `CORE_PACKAGE_DIR=src/netops_core`), so `docker compose build --pull=false` in the unpacked archive is the documented path. The Compose network contract is:

- network name `netops-helper`;
- bridge interface `nh-egress0`;
- `internal: false` so targets remain reachable;
- `enable_ipv6: false` as the network-scoped IPv6 boundary.

Do not change `internal` to true as an egress-hardening shortcut; it removes required external connectivity. Do not force a fixed bridge subnet unless it was independently designed for that host. Interface-based matching does not need a fixed subnet, and a fixed allocation can collide with existing networks.

The image also installs `netops_core/askpass.py` as `/usr/local/bin/netops-askpass` and sets `NETOPS_ASKPASS_PROGRAM` to it. A device credential of kind `password` is handed to the client by an askpass program the client executes, and this Compose file mounts `/tmp` and `/run` `noexec`, so the default program written beside the secret could not run there. Keep both: the `noexec` mounts and the installed program. Do not remove `noexec` to make password authentication work, and do not point the variable at a path under `/tmp`, `/run`, or any directory the service can write.

The image installs one distribution package on top of the digest-pinned base: `openssh-client`, which provides the `ssh` and `ssh-keyscan` binaries every `ssh_read` and every host key verification runs, and the `sftp` binary `sftp_stat` runs. It is installed with `--no-install-recommends` and the package lists are removed in the same layer; the exact `openssh-client` version a given build carries is not pinned in the Dockerfile, only recorded after the fact in that release's SBOM and Grype report - see [Reproducibility of the image](releasing.md#reproducibility-of-the-image). The health check refuses to report healthy when any of the three binaries is missing.

The health check also refuses to report healthy when `NETOPS_ASKPASS_PROGRAM` is set and the path it names is not a regular file this process can execute or is writable by group or other, reusing the same rule `netops_core.ssh` applies before it hands a password to the client. A broken or missing askpass program is otherwise silent until a password-authenticated call fails at the device with what looks like a wrong password. On a host that leaves the variable unset, this part of the check does not run.

**Known and unfixed:** the `openssh-client` that Debian trixie ships carries CVE-2026-60002, a Critical client-side use-after-free triggered by a server that changes its host key during a key re-exchange; the upstream fix is OpenSSH 10.4 and trixie stays on 10.0. This release ships with that vulnerability as a reviewed exception, not with a fix. Read [known vulnerability findings](known-vulnerabilities.md) before deploying; if the exposure is not acceptable, rebuild the image on a base that ships OpenSSH 10.4 or newer.

Build the digest-pinned image, then create the network and container without starting the service:

```bash
docker compose build --pull=false
docker compose up --no-start --no-build
docker compose ps --all
docker network inspect netops-helper
```

The official Docker Compose CLI defines `up --no-start` as creating services without starting them. The explicit network declaration causes Compose to create the named network as part of that operation. See the official [`docker compose up` reference](https://docs.docker.com/reference/cli/docker/compose/up/) and [Compose network reference](https://docs.docker.com/reference/compose-file/networks/).

Verify that the container is not running and that the inspected network is the bridge `nh-egress0` with `EnableIPv6: false`. Stop here if any value differs. Do not use `docker compose up -d` at this stage: that would start the helper before egress enforcement is verified.

The runner SSH identity later used by the proxy needs narrowly constrained permission to invoke the fixed remote command `docker exec -i netops-helper python -m netops_helper.server`. The stock proxy invokes OpenSSH with `ssh -T`, so it allocates no terminal, and explicitly disables agent, X11, TCP, tunnel, proxy-command, jump-host, local-command, environment, and multiplexing paths. Docker group membership is effectively privileged host access; use a dedicated runner account constrained to that command or another independently reviewed restriction.

The runner credential is a vault record of kind `password` or `ssh-key`. A password is handed to OpenSSH's askpass helper once over a private abstract socket, with one prompt allowed and `PubkeyAuthentication=no`. A key is written to a mode-`600` identity file in the proxy's private temporary directory and used with `IdentitiesOnly=yes`, `PubkeyAuthentication=yes`, `PasswordAuthentication=no` and `BatchMode=yes`; the directory is removed when the proxy exits. Certificate-based authentication is not implemented.

## 5. Generate the egress bundle on the proxy host

Run the generator from the same verified source revision that is deployed on the runner. It reads the inventory and the egress policy, never the vault, and atomically writes a mode-`600` bundle. The bundle contains no credentials, logins, device names, host names, TLS names, or host-key material, but it does reveal destination addresses, ports, LAN scopes, and resolver scope.

```bash
python3 scripts/generate_egress_rules.py \
  --inventory /path/to/inventory.json \
  --policy /path/to/egress-policy.json \
  --output /restricted/path/netops-helper-egress.json
```

Generation must finish with exit status zero. Do not pass JSON inline, and do not place the output in the public repository.

If the proxy and runner are different hosts:

1. compute the bundle's SHA-256 digest locally;
2. transfer it over an approved encrypted channel whose runner identity is verified independently;
3. store it in a runner-local restricted directory with mode `600`;
4. recompute and compare the digest on the runner through a separate trusted observation.

A successful transfer proves only byte equality. It does not replace review of the bundle's intended network scope. `manifest_sha256` later verifies only the normalized manifest inside that bundle; it is not a digest of the policy file, the source revision, or the original input bytes. The manifest does record `inventory_sha256`, the digest of the inventory file the bundle was generated from, so a bundle can be tied back to one reviewed enrollment.

## 6. Review, explicitly apply, and check egress

Read [Egress control](egress-control.md) before changing the host firewall. Retain an out-of-band recovery path.

Review the schema-3 bundle on the runner before applying it. Confirm at minimum:

- `manifest_sha256` matches a fresh digest of the canonical normalized manifest, the ruleset was rendered from that manifest, and the effective network scope is intended;
- profile is the intended `strict-target` or explicitly accepted `lan-constrained` profile; for `lan-constrained`, every CIDR is a canonical subnet wholly inside RFC1918 space and every target destination lies within the declared LAN union;
- network and bridge are exactly `netops-helper` and `nh-egress0`;
- `network_ipv6_enabled` is `false` and `ipv6_boundary` is `docker-network-disabled`;
- every IPv4 destination, TCP/UDP port or range, resolver, and LAN CIDR is expected; remember that `lan-constrained` applies the union of all enrolled ports/ranges and ICMP permission to every declared LAN CIDR;
- the final IPv4 managed-chain action is drop;
- the bundle exposes no unintended environment data.

Then invoke the privileged apply helper with the explicit consent flag and immediately run the read-only checker:

```bash
sudo python3 scripts/apply_egress_rules.py \
  --bundle /restricted/path/netops-helper-egress.json --apply
sudo python3 scripts/check_egress_rules.py \
  --expected /restricted/path/netops-helper-egress.json
```

Continue only after `egress_apply=ok` and `egress_check=ok`. The helper requires root, a mode-`600` bundle, Docker inspection, `nft`, and `iptables-save`/`iptables-restore`. It rejects native Docker nftables, an indeterminate backend, an unreachable IPv4 DOCKER-USER path, a network mismatch, or any Docker IPv6 state other than exact boolean false.

Bundle schema 3 contains one IPv4 ruleset and apply uses one IPv4 `iptables-restore` COMMIT. It never invokes ip6tables and does not claim an IPv6 firewall transaction. IPv6 is instead disabled on this Docker network by Compose. DOCKER-USER filters forwarded bridge traffic; it does not protect services reached through the runner's INPUT path. The checker validates its defined network and forwarding contract, not complete host containment.

## 7. Start the service only after the check

Start the already-created stopped container and confirm its state:

```bash
docker compose start
docker compose ps
```

If start causes an unexpected recreate or network change, stop the service, rerun the checker, and investigate before reconnecting a client. Do not replace this guarded first start with `docker compose up -d`.

## 8. Connect an MCP client

Configure any compatible client to launch `python3` with the absolute path to `scripts/remote_mcp_proxy.py` as a stdio MCP server. Keep client-specific settings outside the repository.

Use a dedicated read-only agent/session with no generic shell, write-capable filesystem, deployment, configuration, or mutating tools. Restart the client after changing its MCP configuration.

## 9. Validate the deployment

Run portable source checks in a suitable development environment, from this component's directory (`components/netops-helper/` in the `netops` repository):

```bash
PYTHONPATH=src:../netops-core/src python tests/run_tests.py
PYTHONPATH=src:../netops-core/src python tests/test_engine_contracts.py
python tests/test_proxy_contracts.py
python tests/test_egress_scripts.py
python tests/test_apply_egress_rules.py
python scripts/check_public_release.py
```

On the maintained ARM64 release builder, install the locked runtime and run the complete suite with mandatory runtime tests:

```bash
NETOPS_REQUIRE_RUNTIME_TESTS=1 python -m pytest -q
```

Then start a fresh dedicated client session:

1. Call `helper_status`; confirm `write_tools` is empty and review `invalid_target_count` and per-target rate state.
2. Choose only an alias returned in `target_aliases`.
3. Call `target_scope`; review query, inventory, metadata/listing root, egress, `host_key_pinned`, `snmp_enrolled`, and rate state. Remember that egress addresses and other returned scope are topology-sensitive.
4. Compare enabled names and typed slots with `read_query_catalog`.
5. Execute one harmless enrolled query against a controlled test target.
6. Confirm target-side authentication/authorization logging and the expected two-phase audit pair.
7. Confirm a forbidden query or malformed parameter is rejected without a target connection.

The ARM64 live network test must also verify:

- allowed and denied target address/port combinations;
- IPv6 remains unavailable to containers on this network;
- expected DNS behavior through Docker embedded DNS at `127.0.0.11`;
- attempts to reach runner-local listening services through bridge and host addresses;
- survival and ordering of the DOCKER-USER jump across Docker restart;
- checker detection of rule drift.

DOCKER-USER alone does not cover INPUT. If runner-host services require protection, design a host-specific INPUT policy only after observing actual Docker DNS/NAT behavior, then retest it.

## Change procedure

Any change to a device entry or its connection port, a helper section, metadata/listing roots, resolver scope, Compose network, or Docker networking requires the guarded sequence again:

1. stop the service;
2. regenerate and securely transfer a fresh bundle;
3. review it and retain recovery access;
4. explicitly apply it;
5. run the checker and live negative tests;
6. start the service only after all checks pass.

Do not assume that a previously installed rule follows enrollment changes automatically. Run the checker after Docker restart or network recreation even when the policy did not change.

## Removal

Disconnect the MCP client and stop the container. Remove or replace the tool-owned host-firewall chain through a reviewed operator procedure before removing the Compose network. Preserve or securely dispose of the audit volume according to retention policy. Removing the MCP connection does not remove the vault, the inventory, the runner file, the transferred bundle, or host firewall state.
