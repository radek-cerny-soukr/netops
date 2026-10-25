import argparse
import asyncio
import importlib
import json
import os
import secrets
import sys
from . import __version__
from .files import STATE, UIDS, read_private, write_private
from .state import StateCompatibilityError, OperatorAccessError, require_initialized
from .diagnostics import RoleConfigurationError, SyslogConfigurationError, operation_message, OPERATION_FAILURE, OPERATION_PERMISSION, OPERATION_SUFFIX, GENERAL_OPERATION_FAILURE, GENERAL_OPERATION_PERMISSION

async def selftest():
    roles = {}
    for role, module in (("helper", "netops_helper.server"), ("auditor", "netops_auditor.mcp_server"), ("admin", "netops_admin.mcp_server")):
        server = importlib.import_module(module).mcp
        names = [tool.name for tool in await server.list_tools()]
        if role == "helper":
            from netops_helper.proxy import Proxy
            names.append(Proxy._target_scope_tool()["name"])
        roles[role] = {"tools": len(names), "names": names}
    print(json.dumps({"version": __version__, "roles": roles}, sort_keys=True))
    return 0

def admin_outcome(payload):
    result = payload.get("result") if isinstance(payload, dict) else None
    structured = result.get("structuredContent") if isinstance(result, dict) else None
    if isinstance(structured, dict):
        value = structured.get("result")
        if isinstance(value, dict):
            value = value.get("result")
        return value if isinstance(value, str) else None
    return None

def note_pending(chains, item):
    chain = chains.setdefault(item["correlation"], {"request": None, "interrupted": None, "admin": None, "response": False, "withheld": False, "left": False})
    direction = item["direction"]
    payload = item.get("payload")
    if direction == "request":
        payload = payload if isinstance(payload, dict) else {}
        params = payload.get("params")
        params = params if isinstance(params, dict) else {}
        chain["request"] = {"time": item["time"], "correlation": item["correlation"], "method": payload.get("method"), "request_id": payload.get("id"), "tool": params.get("name")}
    elif direction == "client_disconnect":
        if isinstance(payload, dict) and payload.get("phase") == "before_dispatch" and payload.get("complete_body") is True and payload.get("operation_executed") is False:
            chain["left"] = True
    elif direction == "interrupted":
        may = not (isinstance(payload, dict) and payload.get("operation_may_have_completed") is False)
        chain["interrupted"] = chain["interrupted"] is True or may
    elif direction == "response_withheld":
        chain["withheld"] = True
    elif direction == "response":
        outcome = admin_outcome(payload)
        if outcome in ("unknown", "revert-failed"):
            chain["admin"] = chain["admin"] or outcome
        else:
            chain["response"] = True

def pending_entries(chains):
    for chain in chains.values():
        if chain["request"] is None:
            continue
        if chain["admin"]:
            outcome = "Admin result " + chain["admin"] + "; inspect admin_status and the actual device; never retry automatically"
        elif chain["interrupted"] is False:
            outcome = "interrupted before dispatch; the operation was not executed"
        elif chain["interrupted"] and chain["response"]:
            outcome = "interrupted; a response is recorded; the client may not have received it; inspect audit export, status and the actual device before any repeat; do not retry writes automatically"
        elif chain["interrupted"]:
            outcome = "interrupted before a result was recorded; the operation may have completed; inspect the device before any repeat"
        elif chain["withheld"]:
            outcome = "response withheld because the token changed; the operation may have completed; inspect status and the device"
        elif chain["response"]:
            continue
        elif chain["left"]:
            outcome = "client left before dispatch; the operation was not executed"
        else:
            outcome = "no response recorded; the operation may have completed; do not retry writes automatically"
        yield {**chain["request"], "outcome": outcome}

def main():
    parser = argparse.ArgumentParser(prog="netops")
    commands = parser.add_subparsers(dest="command", required=True, metavar="{version,selftest,serve,connection,health,init,configure,admin,auditor,ca,token,audit}")
    for name in ("version", "selftest", "serve", "connection", "health"):
        commands.add_parser(name)
    worker = commands.add_parser("worker")
    worker.add_argument("role", choices=("helper", "auditor", "admin"))
    init = commands.add_parser("init")
    init.add_argument("--audit", choices=("local", "syslog"))
    init.add_argument("--accept-local-audit", action="store_true")
    init.add_argument("--syslog-host")
    init.add_argument("--syslog-port", type=int, default=6514)
    init.add_argument("--audit-budget", type=int, default=268435456)
    init.add_argument("--disable-admin", action="store_true")
    configure = commands.add_parser("configure")
    configure.add_argument("role", choices=("helper", "admin", "auditor", "syslog"))
    for role in ("admin", "auditor"):
        tool = commands.add_parser(role, add_help=False)
        tool.add_argument("--help", action="store_true", dest="role_help")
        tool.add_argument("--version", action="store_true", dest="role_version")
        tool.add_argument("arguments", nargs=argparse.REMAINDER)
    ca = commands.add_parser("ca")
    ca.add_argument("action", choices=("export", "rotate"), default="export", nargs="?")
    token = commands.add_parser("token")
    token.add_argument("action", choices=("show", "rotate"))
    audit = commands.add_parser("audit")
    audit.add_argument("action", choices=("show", "tail", "export", "pending", "stats", "recover", "reassemble"), default="show", nargs="?")
    audit.add_argument("--lines", type=int, default=100)
    audit.add_argument("--record-id")
    args = parser.parse_args()
    if args.command == "audit":
        if args.action == "reassemble" and args.record_id is None:
            parser.error("audit reassemble requires --record-id")
        if args.action != "reassemble" and args.record_id is not None:
            parser.error("--record-id is only valid for audit reassemble")
    try:
        if args.command == "version":
            print(__version__)
            return 0
        if args.command == "selftest":
            return asyncio.run(selftest())
        if args.command == "worker":
            from .worker import run
            return asyncio.run(run(args.role))
        if args.command == "health":
            from .health import check
            return check()
        if args.command == "serve":
            from .bootstrap import serve
            serve()
            return 0
        if args.command == "init":
            from .init import initialize
            return initialize(args)
        if args.command == "configure":
            from .operator import configure
            return configure(args.role)
        if args.command in ("admin", "auditor"):
            if args.role_version:
                print("NetOps " + __version__ + " (" + args.command + ")")
                return 0
            from .operator import role_cli
            arguments = ["--help"] if args.role_help else args.arguments
            return role_cli(args.command, arguments)
        if args.command == "ca":
            if args.action == "rotate":
                from .operator import rotate_instance_ca
                return rotate_instance_ca()
            require_initialized(STATE)
            sys.stdout.write(read_private(STATE / "gateway" / "ca.pem", owner=UIDS["gateway"]).decode())
            return 0
        if args.command == "connection":
            require_initialized(STATE)
            from .init import connection
            connection(json.loads(read_private(STATE / "gateway" / "config.json", owner=UIDS["gateway"])))
            return 0
        if args.command == "token":
            if os.geteuid() != 0:
                raise OperatorAccessError("Use the image default container user for token display or rotation; remove any --user override")
            require_initialized(STATE)
            if args.action == "show":
                sys.stdout.write(read_private(STATE / "gateway" / "token", owner=UIDS["gateway"]).decode())
            else:
                from .state import read_state_settings
                read_state_settings(STATE)
                write_private(STATE / "gateway" / "token", (secrets.token_urlsafe(48) + "\n").encode(), UIDS["gateway"], replace=True)
                print("Token rotated; existing authorization is invalid.")
            return 0
        if args.command == "audit" and args.action == "reassemble":
            from .syslog_parts import ID, MAX_MESSAGE_BYTES, ReassemblyError, decode_messages
            if ID.fullmatch(args.record_id) is None:
                sys.stderr.write("netops: reassembly_argument_error line_0\n")
                return 2
            consumed = 0
            read_failed = False
            warned = False
            def messages():
                nonlocal consumed, read_failed
                try:
                    limit = MAX_MESSAGE_BYTES + 2
                    while line := sys.stdin.buffer.readline(limit):
                        consumed += 1
                        if len(line) == limit and not line.endswith(b"\n"):
                            while (rest := sys.stdin.buffer.readline(limit)) and not rest.endswith(b"\n"):
                                pass
                            yield b""
                        else:
                            yield line.removesuffix(b"\n")
                except Exception:
                    read_failed = True
                    raise
            def warning(item):
                nonlocal warned
                warned = True
                sys.stderr.write(json.dumps({"schema": "netops-syslog-reassembly-warning/1",
                                             "code": item.code, "line_number": item.line_number},
                                            separators=(",", ":"), ensure_ascii=True) + "\n")
            try:
                original = decode_messages(messages(), args.record_id, on_warning=warning)
            except Exception as error:
                if read_failed:
                    sys.stderr.write("netops: reassembly_read_error after_line_" + str(consumed) + "\n")
                elif isinstance(error, ReassemblyError):
                    location = "after_line_" if error.end else "line_"
                    sys.stderr.write("netops: reassembly_validation_error " + location + str(error.line_number) + "\n")
                else:
                    raise
                return 2
            sys.stdout.buffer.write(original)
            sys.stdout.buffer.flush()
            return 3 if warned else 0
        if args.command == "audit" and args.action == "recover":
            from .operator import recover_audit
            return recover_audit()
        if args.command == "audit":
            require_initialized(STATE)
            from .audit import RECOVER_HINT, file_order, split_records
            from .redaction import terminal_safe
            from collections import Counter, deque
            entries = deque(maxlen=max(0, min(args.lines, 10000)))
            chains = {}
            counts = Counter()
            total_bytes = 0
            total_records = 0
            directory = STATE / "gateway" / "audit"
            problems = []
            for path in sorted(list(directory.glob("*.jsonl")) + list(directory.glob("*.queue")), key=file_order):
                raw = read_private(path, 33554432, UIDS["gateway"])
                lines, fragment = split_records(raw)
                if fragment:
                    problems.append(path.name + " ends with an incomplete record that was not shown; " + RECOVER_HINT)
                for line in lines:
                    try:
                        item = json.loads(line)
                    except ValueError:
                        problems.append(path.name + " holds a complete record that is not valid JSON and was not shown; keep the segment and inspect it, `audit recover` does not change complete records")
                        continue
                    total_bytes += len(line) + 1
                    total_records += 1
                    counts[item["direction"]] += 1
                    if args.action == "tail":
                        entries.append(item)
                    elif args.action == "pending":
                        note_pending(chains, item)
                    elif args.action != "stats":
                        print(terminal_safe(item))
            if args.action == "tail":
                for item in entries:
                    print(terminal_safe(item))
            elif args.action == "pending":
                for item in pending_entries(chains):
                    print(terminal_safe(item))
            elif args.action == "stats":
                rejections_path = STATE / "gateway" / "audit" / "rejections.json"
                rejections = json.loads(read_private(rejections_path, 4096, UIDS["gateway"])) if rejections_path.exists() else None
                print(terminal_safe({"records": total_records, "bytes": total_bytes, "mean_record_bytes": total_bytes / total_records if total_records else 0, "directions": dict(counts), "unauthenticated_rejections": rejections}))
            for problem in problems:
                sys.stderr.write("netops: audit " + problem + "\n")
            return 1 if problems else 0
    except Exception as error:
        detail = operation_message(error)
        if detail is None:
            if isinstance(error, (StateCompatibilityError, OperatorAccessError)):
                detail = str(error)
            elif isinstance(error, PermissionError):
                detail = OPERATION_PERMISSION if args.command == "configure" else GENERAL_OPERATION_PERMISSION
            elif isinstance(error, OSError):
                detail = OPERATION_FAILURE if args.command == "configure" else GENERAL_OPERATION_FAILURE
            elif args.command == "configure":
                trusted = SyslogConfigurationError if args.role == "syslog" else RoleConfigurationError
                detail = str(error) if isinstance(error, trusted) else OPERATION_FAILURE
            else:
                detail = str(error) if args.command in ("init", "serve", "connection", "ca", "audit", "health") and isinstance(error, ValueError) else type(error).__name__
        sys.stderr.write("netops: " + detail + OPERATION_SUFFIX)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
