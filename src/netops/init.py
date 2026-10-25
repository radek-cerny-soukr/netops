import fcntl
import ipaddress
import json
import os
import secrets
import stat
import subprocess
import sys
from . import __version__
from .bootstrap import demote, prepare
from .certificates import create_ca, names, server_name, renew
from .files import STATE, UIDS, check_regular, read_private, write_private

WARNING = "Local audit is discouraged but permitted. It stores inputs and outputs; disk usage can grow quickly with NetOps use."
NONINTERACTIVE = "init needs an interactive terminal (docker compose run --rm netops init), or choose the audit explicitly: --audit local --accept-local-audit, or --audit syslog --syslog-host HOST [--syslog-port PORT]"
PLACEHOLDER_NAME = "replace-me-with-certificate-dns-name"
PLACEHOLDER = "NETOPS_SERVER_NAME is still the env.example placeholder; set it in .env to the exact DNS name your MCP clients will use"

def changed_identity(settings):
    name = os.environ.get("NETOPS_SERVER_NAME", "")
    if name and name.encode("idna").decode("ascii").lower() != settings["server_name"].encode("idna").decode("ascii").lower():
        return ("NETOPS_SERVER_NAME is " + name + " but the instance CA and certificate are bound to " + settings["server_name"]
                + "; restore the previous value: the server name is fixed at init and a different name needs a new instance")
    return None

def check_start(settings, directory):
    from .audit import RECOVER_HINT, audit_limits, incomplete_tail, rejection_snapshot
    from .certificates import verify_pairs
    audit_limits(settings["audit"])
    audit_directory = directory / "gateway" / "audit"
    try:
        info = audit_directory.lstat()
    except FileNotFoundError:
        info = None
    if info is not None and (not stat.S_ISDIR(info.st_mode) or info.st_uid != UIDS["gateway"] or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("Unsafe audit directory ownership or permissions")
    rejection_snapshot(audit_directory, UIDS["gateway"])
    if settings["audit"]["mode"] == "local" and any(incomplete_tail(path, owner=UIDS["gateway"]) for path in audit_directory.glob("*.jsonl")):
        raise ValueError("Incomplete final audit record; " + RECOVER_HINT)
    problem = changed_identity(settings)
    if problem:
        raise ValueError(problem)
    verify_pairs()

def connection(settings):
    name = settings["server_name"]
    if ":" in name:
        name = "[" + name + "]"
    port = os.environ.get("NETOPS_PORT", "") or str(settings["external_port"])
    url = "https://" + name + ":" + port + "/mcp"
    print("MCP URL: " + url)
    print("Authorization: Bearer ${NETOPS_TOKEN}")
    print("Export the public CA: docker compose run --rm netops ca > netops-ca.pem (add -p <instance> before run for an additional instance)")
    print("Claude Code: NODE_EXTRA_CA_CERTS=/absolute/path/netops-ca.pem")
    print("Codex: CODEX_CA_CERTIFICATE=/absolute/path/netops-ca.pem")
    print("Other MCP clients: configure HTTPS Streamable HTTP, the CA certificate and Authorization from NETOPS_TOKEN.")
    print("No token value is included in this output.")
    from .certificates import ca_notice
    print(ca_notice()[0])

def choose_audit(args):
    audit_mode = args.audit
    warned = False
    try:
        if audit_mode is None:
            host = input("TLS syslog receiver (recommended; leave blank to choose local audit): ").strip()
            if host:
                audit_mode = "syslog"
                try:
                    syslog_port = int(input("TLS syslog port [6514]: ").strip() or "6514")
                except ValueError:
                    raise ValueError("Syslog port must be a decimal port number") from None
                audit = {"mode": "syslog", "host": host, "port": syslog_port}
            else:
                print(WARNING)
                warned = True
                if input("Type LOCAL to accept local audit: ").strip() != "LOCAL":
                    raise ValueError("Local audit was not explicitly accepted")
                audit_mode = "local"
    except EOFError:
        raise ValueError(NONINTERACTIVE) from None
    if audit_mode == "local":
        if args.audit == "local" and not args.accept_local_audit:
            raise ValueError("Noninteractive local audit requires --accept-local-audit")
        if not warned:
            print(WARNING)
        audit = {"mode": "local"}
    elif args.audit == "syslog":
        if not args.syslog_host:
            raise ValueError("--syslog-host is required")
        audit = {"mode": "syslog", "host": args.syslog_host, "port": args.syslog_port}
    if audit["mode"] == "syslog":
        names(audit["host"])
        if not 1 <= int(audit["port"]) <= 65535:
            raise ValueError("Syslog port must be between 1 and 65535")
    audit.update({"budget_bytes": args.audit_budget, "segment_bytes": 16777216, "retention_seconds": 604800})
    if audit["mode"] == "local":
        print("Audit budget: " + str(args.audit_budget) + " bytes; local segments 16777216 bytes; local maximum age 604800 seconds. Measure workload before choosing capacity.")
    else:
        print("Audit queue budget: " + str(args.audit_budget) + " bytes for records not yet delivered to the syslog receiver; when it is full, new operations are refused. Measure workload before choosing capacity.")
    return audit


def initialize(args):
    bind = os.environ.get("NETOPS_BIND_IP", "")
    name = os.environ.get("NETOPS_SERVER_NAME", "")
    if not bind or not name:
        raise ValueError("NETOPS_BIND_IP and NETOPS_SERVER_NAME are required; NetOps never chooses a host bind address implicitly")
    try:
        ipaddress.ip_address(bind)
    except ValueError:
        raise ValueError("NETOPS_BIND_IP must be a valid explicit IP address") from None
    server_name(name)
    if name.encode("idna").decode("ascii").lower() == PLACEHOLDER_NAME:
        raise ValueError(PLACEHOLDER)
    try:
        port = int(os.environ.get("NETOPS_PORT", "8443"))
    except ValueError:
        raise ValueError("NETOPS_PORT must be a decimal port number") from None
    if not 1 <= port <= 65535:
        raise ValueError("NETOPS_PORT must be between 1 and 65535")
    if args.audit_budget < 16777216:
        raise ValueError("Audit budget must be at least 16 MiB")
    if not 1 <= args.syslog_port <= 65535:
        raise ValueError("Syslog port must be between 1 and 65535")
    if os.geteuid() != 0:
        raise ValueError("Initialization and the short start bootstrap require the declared container user and capabilities")
    config = STATE / "gateway" / "config.json"
    if config.exists() or config.is_symlink():
        from .state import read_state_settings
        settings = read_state_settings(STATE)
        problem = changed_identity(settings)
        if problem:
            raise ValueError(problem)
        connection(settings)
        print("Already initialized; CA, token and data preserved.")
        return 0
    prepare()
    if any((STATE / "gateway" / item).exists() for item in ("ca.key", "ca.pem", "token")):
        raise ValueError("Partial initialization found; inspect it explicitly rather than silently replacing identities")
    audit = choose_audit(args)
    settings = {"version": 1, "product_version": __version__, "server_name": name, "external_port": port, "admin_enabled": not args.disable_admin, "audit": audit}
    create_ca(name)
    renew(name, force=True)
    write_private(STATE / "gateway" / "token", (secrets.token_urlsafe(48) + "\n").encode(), UIDS["gateway"])
    write_private(STATE / "helper" / "inventory.json", b'{"version":2,"devices":[]}\n', UIDS["helper"])
    write_private(STATE / "helper" / "vault.json", b'{"version":2,"credentials":{}}\n', UIDS["helper"])
    write_private(STATE / "admin" / "vault.json", b'{"version":2,"credentials":{}}\n', UIDS["admin"])
    write_private(STATE / "auditor" / "config.json", b'{"tenant":"default","catalog":"fortios"}\n', UIDS["auditor"])
    admin = {"version": 1, "state_dir": str(STATE / "admin" / "changes"), "audit_file": str(STATE / "admin" / "operations.jsonl"), "devices": {}}
    write_private(STATE / "admin" / "config.json", json.dumps(admin).encode(), UIDS["admin"])
    subprocess.run([sys.executable, "-c", "from netops_auditor.store import Store; import sys; Store(sys.argv[1]).close()", str(STATE / "auditor" / "store.sqlite")], preexec_fn=lambda: demote(UIDS["auditor"]), check=True)
    write_private(config, json.dumps(settings).encode(), UIDS["gateway"])
    connection(settings)
    print("No network device is enrolled. Configure role inventory and credentials explicitly before device operations.")
    return 0
