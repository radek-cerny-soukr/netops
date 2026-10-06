from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from netops_admin import __version__
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected, shown
from netops_admin.jsontext import loads
from netops_admin.membership import ports as port_list
from netops_core.inputs import InputError, read_regular
from netops_admin.request import parse_request

MAX_FILE_BYTES = 16 * 1024 * 1024 + 1
POLICY_FIELDS = frozenset(("protected",))
EXIT_MISMATCH = 1
EXIT_REJECTED = 3


def _read(path: Path) -> bytes:
    try:
        return read_regular(path, MAX_FILE_BYTES)
    except OSError as exc:
        raise Rejected(["%s cannot be read: %s" % (shown(path.name), exc.strerror or type(exc).__name__)]) from None
    except InputError as exc:
        raise Rejected(["%s cannot be read: %s" % (shown(path.name), exc)]) from None


def _json(path: Path, label: str):
    return loads(_read(path), label)


def _policy(path):
    if path is None:
        return {}
    data = _json(path, "policy")
    if not isinstance(data, dict) or set(data) - POLICY_FIELDS:
        raise Rejected(["policy may hold only: %s" % ", ".join(sorted(POLICY_FIELDS))])
    protected = data.get("protected", {})
    if not isinstance(protected, dict) or not all(
        isinstance(table, str) and isinstance(names, list) and all(isinstance(name, str) for name in names)
        for table, names in protected.items()
    ):
        raise Rejected(["policy protected must map a table to a list of names"])
    return protected


def _ports(value):
    if value is None:
        return None
    try:
        return port_list(value)
    except ValueError:
        raise Rejected(["--ports is not a port list"]) from None


def _emit(document) -> None:
    sys.stdout.write(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n")


EXIT_NOT_CONFIRMED = 4
EXIT_NOT_READY = 5
EXIT_CONFIRMED_BLOCKED = 6


def build_runtime(config):
    from netops_admin import execute

    def factory(device):
        from netops_admin.access import DeviceAccess

        return DeviceAccess(device)

    notifier = None
    if config.notify is not None:
        from netops_admin.notify import NtfyNotifier

        notifier = NtfyNotifier(config.notify.server, config.notify.topic_file, config.notify.timeout_seconds,
                                config.notify.x509_strict)
    return execute.Runtime(config, factory, notifier=notifier)


def _operate(args) -> int:
    from netops_admin import execute
    from netops_admin.config import load_config

    config = load_config(args.config)
    if args.command == "status":
        store = execute.Store(config.state_dir)
        change_id = args.change_id
        if change_id is None and args.request_id:
            known = store.request(args.request_id)
            change_id = None if known is None else known["change_id"]
        record = None if change_id is None else store.operation(change_id)
        if record is None:
            raise Rejected(["no operation matches"])
        _emit(execute.refresh_delivery(execute.Runtime(config, None), record))
        return 0

    runtime = build_runtime(config)
    if args.command == "doctor":
        from netops_admin import readiness
        report = readiness.doctor(runtime, args.device)
        _emit(report)
        return 0 if report["ready"] else EXIT_NOT_READY
    if args.command == "preview":
        result = execute.preview(runtime, args.device, parse_request(_read(args.request)))
        _emit(result)
        return 0 if result["result"] == "ready" else EXIT_REJECTED
    if args.command == "enroll":
        from netops_admin import enrollment
        record = enrollment.run(runtime, args.device, args.probe)
        _emit(record)
        return 0 if record.get("enrollment") == "valid" else EXIT_NOT_CONFIRMED
    if args.command == "unblock":
        _emit({"device": args.device, "unblocked": execute.unblock(runtime, args.device, args.reason)})
        return 0
    if args.command == "notify-retry":
        _emit(execute.notify_retry(runtime, args.change_id))
        return 0
    if args.command == "recover":
        settled = execute.recover(runtime, args.device)
        _emit({"device": args.device, "settled": settled})
        return EXIT_CONFIRMED_BLOCKED if any(execute.blocks(r.get("result"), r.get("reason")) for r in settled) else 0
    if args.command == "undo":
        record = execute.undo(runtime, args.change_id, args.reason)
    else:
        record = execute.apply(runtime, args.device, parse_request(_read(args.request)))
    _emit(record)
    if record.get("result") != "confirmed":
        return EXIT_NOT_CONFIRMED
    return EXIT_CONFIRMED_BLOCKED if record.get("reason") in execute.BLOCKING_REASONS else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="netops-admin",
        description="Plan a bounded device change, execute it behind a rollback safeguard, "
                    "and compare predictions with device snapshots.",
    )
    parser.add_argument("--version", action="version", version="netops-admin %s" % __version__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="validate a request against a snapshot and print the plan")
    plan.add_argument("--platform", required=True, choices=("fortios", "exos"))
    plan.add_argument("--snapshot", required=True, type=Path)
    plan.add_argument("--request", required=True, type=Path)
    plan.add_argument("--firmware")
    plan.add_argument("--policy", type=Path)
    plan.add_argument("--ports", help="ExtremeXOS: the ports the switch lists in show ports no-refresh, e.g. 1-12")
    schema_plan = commands.add_parser("schema-plan", help="plan a bounded transaction against a pinned schema and rollback calibration")
    schema_plan.add_argument("--library", required=True, type=Path)
    schema_plan.add_argument("--schema-sha256", required=True)
    schema_plan.add_argument("--calibration", required=True, type=Path)
    schema_plan.add_argument("--calibration-sha256", required=True)
    schema_plan.add_argument("--snapshot", required=True, type=Path)
    schema_plan.add_argument("--operations", required=True, type=Path)
    schema_plan.add_argument("--policy", type=Path)
    schema_verify = commands.add_parser("schema-verify", help="compare a snapshot with a schema transaction prediction")
    schema_verify.add_argument("--library", required=True, type=Path)
    schema_verify.add_argument("--schema-sha256", required=True)
    schema_verify.add_argument("--plan", required=True, type=Path)
    schema_verify.add_argument("--snapshot", required=True, type=Path)
    schema_verify.add_argument("--expect", choices=("after", "before"), default="after")
    check = commands.add_parser("verify", help="compare a snapshot with the prediction of a plan")
    check.add_argument("--plan", required=True, type=Path)
    check.add_argument("--snapshot", required=True, type=Path)
    check.add_argument("--expect", choices=("after", "before"), default="after")
    run = commands.add_parser("apply", help="execute one request on a configured device with a rollback safeguard")
    run.add_argument("--config", required=True, type=Path)
    run.add_argument("--device", required=True)
    run.add_argument("--request", required=True, type=Path)
    look_ahead = commands.add_parser("preview", help="run every check of apply against the device and print the plan, without any change")
    look_ahead.add_argument("--config", required=True, type=Path)
    look_ahead.add_argument("--device", required=True)
    look_ahead.add_argument("--request", required=True, type=Path)
    ready = commands.add_parser("doctor", help="report whether a configured device is ready for changes, without any change")
    ready.add_argument("--config", required=True, type=Path)
    ready.add_argument("--device", required=True)
    enroll = commands.add_parser("enroll", help="operator: test actual on-device rollback before enabling writes")
    enroll.add_argument("--config", required=True, type=Path)
    enroll.add_argument("--device", required=True)
    enroll.add_argument("--probe", required=True, help="unused IPv4 subnet for FortiOS, unused VLAN tag for EXOS")
    look = commands.add_parser("status", help="show the journal record of an operation")
    look.add_argument("--config", required=True, type=Path)
    look.add_argument("--change-id")
    look.add_argument("--request-id")
    heal = commands.add_parser("recover", help="settle operations left running by an interruption")
    heal.add_argument("--config", required=True, type=Path)
    heal.add_argument("--device", required=True)
    resend = commands.add_parser("notify-retry", help="deliver the notification of a finished operation again")
    resend.add_argument("--config", required=True, type=Path)
    resend.add_argument("--change-id", required=True)
    free = commands.add_parser("unblock", help="administrator: lift the block of a device after investigation")
    free.add_argument("--config", required=True, type=Path)
    free.add_argument("--device", required=True)
    free.add_argument("--reason", required=True)
    back = commands.add_parser("undo", help="person: return a confirmed operation as a new operation behind a safeguard")
    back.add_argument("--config", required=True, type=Path)
    back.add_argument("--change-id", required=True)
    back.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in ("apply", "status", "recover", "unblock", "notify-retry", "undo", "enroll",
                            "preview", "doctor"):
            return _operate(args)
        if args.command in ("schema-plan", "schema-verify"):
            from netops_core import schema
            from netops_admin import schema_plan, schema_policy
            try:
                library = schema.load(args.library, args.schema_sha256)
                text = _read(args.snapshot).decode("utf-8")
            except (ValueError, UnicodeError):
                raise Rejected(["the pinned schema or UTF-8 snapshot cannot be read"]) from None
            if args.command == "schema-plan":
                calibration = schema_policy.load(library, args.calibration, args.calibration_sha256)
                document = schema_plan.build(library, calibration, text, _json(args.operations, "schema operations"),
                                             _policy(args.policy))
                _emit(document)
                return 0
            result = schema_plan.verify(library, _json(args.plan, "schema plan"), text, args.expect)
            _emit(result)
            return 0 if result["result"] == "match" else EXIT_MISMATCH
        if args.command == "plan":
            request = parse_request(_read(args.request))
            document = build_plan(args.platform, _read(args.snapshot), request,
                                  firmware=args.firmware, protected=_policy(args.policy), ports=_ports(args.ports))
            _emit(document)
            return 0
        result = verify(_json(args.plan, "plan"), _read(args.snapshot), expect=args.expect)
        _emit(result)
        return 0 if result["result"] == "match" else EXIT_MISMATCH
    except Rejected as exc:
        _emit({"result": "rejected", "reasons": exc.reasons})
        return EXIT_REJECTED
