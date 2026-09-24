from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from netops_admin import __version__
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

MAX_FILE_BYTES = 16 * 1024 * 1024 + 1
POLICY_FIELDS = frozenset(("protected",))
EXIT_MISMATCH = 1
EXIT_REJECTED = 3


def _read(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(MAX_FILE_BYTES)
    except OSError as exc:
        raise Rejected(["%s cannot be read: %s" % (path.name, exc.strerror)]) from None


def _json(path: Path, label: str):
    try:
        return json.loads(_read(path).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Rejected(["%s is not UTF-8 JSON" % label]) from None


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


def _emit(document) -> None:
    sys.stdout.write(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n")


EXIT_NOT_CONFIRMED = 4


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
        _emit({"device": args.device, "settled": execute.recover(runtime, args.device)})
        return 0
    if args.command == "undo":
        record = execute.undo(runtime, args.change_id, args.reason)
    else:
        record = execute.apply(runtime, args.device, parse_request(_read(args.request)))
    _emit(record)
    return 0 if record.get("result") == "confirmed" else EXIT_NOT_CONFIRMED


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
    check = commands.add_parser("verify", help="compare a snapshot with the prediction of a plan")
    check.add_argument("--plan", required=True, type=Path)
    check.add_argument("--snapshot", required=True, type=Path)
    check.add_argument("--expect", choices=("after", "before"), default="after")
    run = commands.add_parser("apply", help="execute one request on a configured device with a rollback safeguard")
    run.add_argument("--config", required=True, type=Path)
    run.add_argument("--device", required=True)
    run.add_argument("--request", required=True, type=Path)
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
        if args.command in ("apply", "status", "recover", "unblock", "notify-retry", "undo", "enroll"):
            return _operate(args)
        if args.command == "plan":
            request = parse_request(_read(args.request))
            document = build_plan(args.platform, _read(args.snapshot), request,
                                  firmware=args.firmware, protected=_policy(args.policy))
            _emit(document)
            return 0
        result = verify(_json(args.plan, "plan"), _read(args.snapshot), expect=args.expect)
        _emit(result)
        return 0 if result["result"] == "match" else EXIT_MISMATCH
    except Rejected as exc:
        _emit({"result": "rejected", "reasons": exc.reasons})
        return EXIT_REJECTED
