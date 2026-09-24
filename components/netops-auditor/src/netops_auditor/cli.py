from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from netops_core import vault

from . import management
from . import checks_exos
from . import checks_fortios
from . import collect
from . import inventory
from . import l1_exos
from . import l1_fortios
from . import sarif
from .engine import CATALOG_DIR, CatalogError, CheckError, load_catalog, run
from .findings import Finding
from .state import STATE_GONE, STATE_NEW, STATE_OPEN_KNOWN, STATE_SUPPRESSED, classify
from .state import STATE_NOT_EVALUATED, evaluation_complete, last_evaluated
from .store import Store, StoreError
from .store import migrate as migrate_store
from .suppressions import MOMENT_FORMAT, SuppressionError, load_for_tenant
from .suppressions import migrate_file as migrate_suppressions

PLATFORMS = {
    "exos": (checks_exos, l1_exos),
    "fortios": (checks_fortios, l1_fortios),
}

PARSE_ERRORS = (l1_exos.ParseError, l1_fortios.ParseError)

SEVERITY_ORDER = ("high", "medium", "low", "info")

STATE_ORDER = (STATE_NEW, STATE_OPEN_KNOWN, STATE_SUPPRESSED, STATE_GONE)

PRESENT_STATES = (STATE_NEW, STATE_OPEN_KNOWN, STATE_SUPPRESSED)

SUPPRESSION_SECTIONS = ("orphaned", "expired")

FINDING_KEYS = (
    "rule_id",
    "severity",
    "class",
    "object_key",
    "section",
    "line",
    "fingerprint",
    "evidence",
    "state",
)

GONE_KEYS = ("rule_id", "severity", "object_key", "fingerprint")

SUPPRESSION_KEYS = ("rule_id", "object_key", "fingerprint", "author", "expires", "reason")

STATUS_FRESH = "fresh"
STATUS_STALE = "stale"
STATUS_NEVER = "never"

DEFAULT_STALE_AFTER_HOURS = 26.0

EXIT_OK = 0
EXIT_STALE = 1
EXIT_ERROR = 2

COLLECTION_KEY = "collection"

COLLECTION_KEYS = (
    "channel",
    "source",
    "profile",
    "credential-kind",
    "snapshot_sha256",
    "legacy_ssh",
)

CHANNEL_KINDS = {
    inventory.CHANNEL_REST: ("api-token",),
    inventory.CHANNEL_SSH: ("password", "ssh-key"),
}

LEGACY_NONE = "none"

CREDENTIAL_NONE = "none"

COMPLETENESS_RULE = "%s.snapshot.incomplete"

COMPLETENESS_RULE_VERSION = 1

COMPLETENESS_SEVERITY = "high"

COMPLETENESS_CLASS = "fakt"

DEFAULT_PROFILE = "unknown"


class Failure(Exception):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netops-auditor")
    commands = parser.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("run")
    audit.add_argument("--platform", required=True, choices=sorted(PLATFORMS))
    audit.add_argument("--tenant", required=True)
    audit.add_argument("--device", required=True)
    audit.add_argument("--config", required=True)
    audit.add_argument("--policy")
    audit.add_argument("--store")
    audit.add_argument("--suppressions")
    audit.add_argument("--baseline-accept", action="store_true", dest="baseline_accept")
    audit.add_argument("--accepted-by", dest="accepted_by")
    audit.add_argument("--note")
    audit.add_argument("--json", action="store_true", dest="as_json")
    audit.add_argument("--sarif", action="store_true")
    audit.set_defaults(handler=_command_run)
    gather = commands.add_parser("collect")
    gather.add_argument("--inventory", required=True)
    gather.add_argument("--device", required=True)
    gather.add_argument("--tenant", required=True)
    gather.add_argument("--vault")
    gather.add_argument(
        "--max-response-bytes",
        dest="max_response_bytes",
        type=int,
        default=collect.REST_MAX_BODY_BYTES,
    )
    gather.add_argument("--policy")
    gather.add_argument("--store")
    gather.add_argument("--suppressions")
    gather.add_argument("--baseline-accept", action="store_true", dest="baseline_accept")
    gather.add_argument("--accepted-by", dest="accepted_by")
    gather.add_argument("--note")
    gather.add_argument("--json", action="store_true", dest="as_json")
    gather.set_defaults(handler=_command_collect)
    freshness = commands.add_parser("status")
    freshness.add_argument("--tenant", required=True)
    freshness.add_argument("--device", required=True)
    freshness.add_argument("--store", required=True)
    freshness.add_argument(
        "--stale-after-hours",
        dest="stale_after_hours",
        type=float,
        default=DEFAULT_STALE_AFTER_HOURS,
    )
    freshness.add_argument("--json", action="store_true", dest="as_json")
    freshness.set_defaults(handler=_command_status)
    waivers = commands.add_parser("migrate-suppressions")
    waivers.add_argument("--input", required=True, dest="source")
    waivers.add_argument("--output", required=True, dest="destination")
    waivers.add_argument("--tenant", required=True)
    waivers.set_defaults(handler=_command_migrate_suppressions)
    database = commands.add_parser("migrate-store")
    database.add_argument("--store", required=True)
    database.set_defaults(handler=_command_migrate_store)
    combined = commands.add_parser("merge-sarif")
    combined.add_argument("--output", required=True)
    combined.add_argument("inputs", nargs="+")
    combined.set_defaults(handler=_command_merge_sarif)
    return parser


def _read_config(path: Path) -> tuple:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise Failure("cannot read configuration: %s" % error)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Failure("configuration is not valid UTF-8: %s" % path)
    return text, hashlib.sha256(data).hexdigest()


def _load_rules(platform: str) -> tuple:
    try:
        return load_catalog(platform)
    except CatalogError as error:
        raise Failure("catalog %s: %s" % (platform, error))
    except OSError as error:
        raise Failure("cannot read catalog: %s" % error)
    except ValueError as error:
        raise Failure("catalog %s is not readable JSON: %s" % (platform, error))


def _rules_version(platform: str, rules) -> str:
    path = CATALOG_DIR / ("%s.json" % platform)
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise Failure("cannot read catalog: %s" % error)
    return "%s:%d:%s" % (platform, len(rules), digest)


def _audit(platform: str, text: str, tenant: str, device: str, rules, policy=None) -> tuple:
    try:
        tree = PLATFORMS[platform][1].parse(text)
    except PARSE_ERRORS as error:
        raise Failure("cannot parse configuration: %s" % error)
    try:
        return run(tree, tenant, device, rules, policy)
    except CheckError as error:
        raise Failure("catalog does not match the checks: %s" % error)


def _checked_options(args):
    if args.baseline_accept:
        if not args.store:
            raise Failure("--baseline-accept needs --store")
        if not args.accepted_by or not args.note:
            raise Failure("--baseline-accept needs --accepted-by and --note")
    elif args.accepted_by or args.note:
        raise Failure("--accepted-by and --note need --baseline-accept")


def _checked_budget(value) -> None:
    if value <= 0:
        raise Failure("--max-response-bytes must be positive, got %r" % (value,))


def _load_suppressions(path, tenant):
    if path is None:
        return ()
    try:
        return load_for_tenant(path, tenant)[1]
    except SuppressionError as error:
        raise Failure("suppressions: %s" % error)


def _store_path(value, must_exist: bool) -> Path:
    path = Path(value)
    if path.is_dir():
        raise Failure("store path is a directory: %s" % path)
    if must_exist:
        if not path.is_file():
            raise Failure("store does not exist: %s" % path)
    elif not path.parent.is_dir():
        raise Failure("store directory does not exist: %s" % path.parent)
    return path


def _previous(store, tenant: str, device: str) -> tuple:
    return last_evaluated(store, tenant, store.runs_for_device(tenant, device))[1]



def _checked_policy_scope(store, tenant, device, rules_version):
    runs = store.runs_for_device(tenant, device)
    if not runs:
        return
    previous = str(runs[0]["rules_version"]).split(":")[3:]
    current = str(rules_version).split(":")[3:]
    if previous != current:
        raise Failure("operator policy differs from this device history; use a separate store for the new policy")


def _record(args, digest: str, rules_version: str, findings) -> tuple:
    path = _store_path(args.store, False)
    try:
        with Store(path) as store:
            _checked_policy_scope(store, args.tenant, args.device, rules_version)
            baseline = store.baseline_fingerprints(args.tenant, args.device)
            previous = _previous(store, args.tenant, args.device)
            run_id = store.record_run(
                args.tenant,
                args.device,
                digest,
                args.config,
                rules_version,
                findings,
            )
            accepted = None
            if args.baseline_accept:
                accepted = store.accept_baseline(
                    args.tenant,
                    args.device,
                    run_id,
                    args.accepted_by,
                    args.note,
                )
    except StoreError as error:
        raise Failure("store: %s" % error)
    return previous, baseline, accepted


def _finding_entry(finding, states) -> dict:
    item = finding.as_dict()
    item["state"] = states[item["fingerprint"]]
    return {key: item[key] for key in FINDING_KEYS}


def _gone_entry(item) -> dict:
    return {
        "rule_id": item.rule_id,
        "severity": item.severity,
        "object_key": item.object_key,
        "fingerprint": item.fingerprint,
    }


def _suppression_entry(item) -> dict:
    return {
        "rule_id": item.rule_id,
        "object_key": item.object_key,
        "fingerprint": item.fingerprint,
        "author": item.author,
        "expires": item.expires.strftime(MOMENT_FORMAT),
        "reason": item.reason,
    }


def _summary(findings) -> dict:
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    counts["total"] = len(findings)
    return counts


def _report(tenant, device, platform, digest: str, rules_version: str, findings, result) -> dict:
    states = dict(result.states)
    report = {
        "tool": "netops-auditor",
        "platform": platform,
        "tenant": tenant,
        "device": device,
        "snapshot_sha256": digest,
        "rules_version": rules_version,
        "summary": _summary(findings),
        "states": {name: result.counts[name] for name in STATE_ORDER},
        "findings": [_finding_entry(finding, states) for finding in findings],
        "gone": [_gone_entry(item) for item in result.gone],
        "suppressions": {
            "orphaned": [_suppression_entry(item) for item in result.orphaned_suppressions],
            "expired": [_suppression_entry(item) for item in result.expired_suppressions],
        },
    }
    if not evaluation_complete(findings):
        report["evaluation"] = STATE_NOT_EVALUATED
        report["not_evaluated"] = [
            {**_gone_entry(item), "state": STATE_NOT_EVALUATED}
            for item in result.not_evaluated
        ]
    return report


def _scalar(value) -> str:
    return json.dumps(value, ensure_ascii=False)


def _finding_lines(item) -> list:
    evidence = item["evidence"]
    lines = [
        "",
        "[%s] %s (%s)" % (item["severity"], item["rule_id"], item["class"]),
        "  object: %s" % item["object_key"],
        "  section: %s" % item["section"],
        "  line: %d" % item["line"],
        "  fingerprint: %s" % item["fingerprint"],
    ]
    if evidence:
        rendered = " ".join("%s=%s" % (key, _scalar(evidence[key])) for key in sorted(evidence))
        lines.append("  evidence: %s" % rendered)
    return lines


def _gone_lines(item) -> list:
    return [
        "",
        "[%s] %s (%s)" % (item["severity"], item["rule_id"], STATE_GONE),
        "  object: %s" % item["object_key"],
        "  fingerprint: %s" % item["fingerprint"],
    ]


def _suppression_lines(section: str, item) -> list:
    return [
        "",
        "[%s] %s" % (section, item["rule_id"]),
        "  object: %s" % item["object_key"],
        "  fingerprint: %s" % item["fingerprint"],
        "  author: %s" % item["author"],
        "  expires: %s" % item["expires"],
        "  reason: %s" % item["reason"],
    ]


def _text_report(report: dict) -> str:
    summary = report["summary"]
    states = report["states"]
    waivers = report["suppressions"]
    counted = ", ".join("%s %d" % (name, summary[name]) for name in SEVERITY_ORDER)
    lines = [
        "netops-auditor %s" % report["platform"],
        "tenant: %s" % report["tenant"],
        "device: %s" % report["device"],
        "snapshot-sha256: %s" % report["snapshot_sha256"],
        "rules-version: %s" % report["rules_version"],
    ]
    if COLLECTION_KEY in report:
        gathered = report[COLLECTION_KEY]
        lines.extend("collection-%s: %s" % (name, gathered[name]) for name in COLLECTION_KEYS)
    lines.extend(
        [
            "findings: %d (%s)" % (summary["total"], counted),
            "states: %s" % ", ".join("%s %d" % (name, states[name]) for name in STATE_ORDER),
            "suppressions: %s"
            % ", ".join("%s %d" % (name, len(waivers[name])) for name in SUPPRESSION_SECTIONS),
        ]
    )
    for name in PRESENT_STATES:
        group = [item for item in report["findings"] if item["state"] == name]
        lines.append("")
        lines.append("state %s: %d" % (name, len(group)))
        for item in group:
            lines.extend(_finding_lines(item))
    lines.append("")
    lines.append("state %s: %d" % (STATE_GONE, len(report["gone"])))
    for item in report["gone"]:
        lines.extend(_gone_lines(item))
    for name in SUPPRESSION_SECTIONS:
        lines.append("")
        lines.append("%s suppressions: %d" % (name, len(waivers[name])))
        for item in waivers[name]:
            lines.extend(_suppression_lines(name, item))
    if "rule_coverage" in report:
        lines.extend("rule %s: %s" % item for item in sorted(report["rule_coverage"].items()))
    if "evaluation" in report:
        lines.append("evaluation: not-evaluated")
        lines.append("state not-evaluated: %d" % len(report["not_evaluated"]))
        for item in report["not_evaluated"]:
            lines.extend(_gone_lines(item))
    return "\n".join(lines) + "\n"


def _text_status(report: dict) -> str:
    age = report["age_hours"]
    lines = [
        "netops-auditor status",
        "tenant: %s" % report["tenant"],
        "device: %s" % report["device"],
        "state: %s" % report["state"],
        "last-audit: %s" % (STATUS_NEVER if report["last_audit"] is None else report["last_audit"]),
        "age-hours: %s" % ("unknown" if age is None else "%.2f" % age),
        "stale-after-hours: %.2f" % report["stale_after_hours"],
    ]
    return "\n".join(lines) + "\n"


def _render(report: dict, as_json: bool, renderer) -> str:
    if as_json:
        return json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    return renderer(report)


def _command_run(args) -> int:
    _checked_options(args)
    if args.as_json and args.sarif:
        raise Failure("--json and --sarif exclude each other")
    text, digest = _read_config(Path(args.config))
    rules = _load_rules(args.platform)
    rules_version = _rules_version(args.platform, rules)
    suppression_items = _load_suppressions(args.suppressions, args.tenant)
    policy, coverage = _policy(args, args.platform, text)
    if policy:
        rules_version += ":" + management.policy_digest(policy)
    findings = _audit(args.platform, text, args.tenant, args.device, rules, policy)
    previous, baseline, accepted = (), frozenset(), None
    if args.store:
        previous, baseline, accepted = _record(args, digest, rules_version, findings)
    result = classify(findings, baseline, suppression_items, previous, datetime.now(timezone.utc))
    report = _report(
        args.tenant, args.device, args.platform, digest, rules_version, findings, result
    )
    report["rule_coverage"] = coverage
    if args.sarif:
        sys.stdout.write(sarif.render(sarif.document(report, rules, args.config)))
    else:
        sys.stdout.write(_render(report, args.as_json, _text_report))
    if accepted is not None:
        sys.stderr.write("baseline: accepted %d of %d findings\n" % (accepted, len(findings)))
    return EXIT_OK


def _moment(value) -> datetime:
    try:
        return datetime.strptime(value, MOMENT_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise Failure("store holds an unreadable timestamp: %r" % (value,))


def _status_report(args, last, now: datetime) -> dict:
    report = {
        "tool": "netops-auditor",
        "tenant": args.tenant,
        "device": args.device,
        "stale_after_hours": args.stale_after_hours,
        "last_audit": None,
        "age_hours": None,
        "state": STATUS_NEVER,
    }
    if last is None:
        return report
    age = (now - _moment(last["started_at"])).total_seconds() / 3600.0
    report["last_audit"] = last["started_at"]
    report["age_hours"] = round(age, 2)
    report["state"] = STATUS_STALE if age > args.stale_after_hours else STATUS_FRESH
    return report


def _command_status(args) -> int:
    if not args.stale_after_hours > 0:
        raise Failure("--stale-after-hours must be positive, got %r" % (args.stale_after_hours,))
    path = _store_path(args.store, True)
    try:
        with Store(path) as store:
            last = store.last_run(args.tenant, args.device)
            evaluated = last is None or evaluation_complete(store.findings_for_run(args.tenant, last["id"]))
    except StoreError as error:
        raise Failure("store: %s" % error)
    report = _status_report(args, last, datetime.now(timezone.utc))
    if not evaluated:
        report["state"] = "incomplete"
    sys.stdout.write(_render(report, args.as_json, _text_status))
    return EXIT_OK if report["state"] == STATUS_FRESH else EXIT_STALE


def _inventory_record(path, name) -> tuple:
    try:
        record = inventory.device(inventory.load(path), name)
        if record.auditor is None:
            raise inventory.InventoryError(
                "device %s carries no auditor section, the auditor reads only the devices whose"
                " entry names it" % record.name
            )
        return record, inventory.section(record)
    except inventory.InventoryError as error:
        raise Failure("inventory: %s" % error)


def _catalog_platform(record) -> str:
    if record.platform not in PLATFORMS:
        raise Failure(
            "device %s runs platform %s, the auditor holds no rule catalog for it"
            % (record.name, record.platform)
        )
    return record.platform


def _credential(record, section, path):
    if record.credential is None:
        if path is not None:
            raise Failure(
                "device %s reads channel %s and takes no credential, drop --vault"
                % (record.name, section.channel)
            )
        return None
    if path is None:
        raise Failure(
            "device %s reads channel %s under credential %s, name the store with --vault"
            % (record.name, section.channel, record.credential)
        )
    try:
        credential = vault.load(path).credential(record.credential)
    except vault.VaultError as error:
        raise Failure("vault: %s" % error)
    kinds = CHANNEL_KINDS[section.channel]
    if credential.kind not in kinds:
        raise Failure(
            "device %s reads channel %s under credential %s of kind %s, channel %s takes a"
            " credential of kind %s"
            % (
                record.name,
                section.channel,
                record.credential,
                credential.kind,
                section.channel,
                " or ".join(kinds),
            )
        )
    return credential


def _gathered(record, section, credential, max_response_bytes) -> tuple:
    if section.channel == inventory.CHANNEL_FILE:
        snapshot, event = collect.collect_file(
            record.name, record.platform, section.source, DEFAULT_PROFILE
        )
        return snapshot, (event,)
    if section.channel == inventory.CHANNEL_REST:
        snapshot, event = collect.collect_fortios_rest(
            record.name,
            section.source,
            credential,
            DEFAULT_PROFILE,
            tls_fingerprint=section.tls_fingerprint,
            max_response_bytes=max_response_bytes,
        )
        return snapshot, (event,)
    snapshot, events = collect.collect_ssh(
        record.name,
        record.platform,
        record.address,
        record.port,
        credential,
        record.host_key_fingerprint,
        legacy_ssh=record.legacy_ssh,
    )
    return snapshot, tuple(events)


def _traced(args, record, events) -> str:
    if not args.store or not events:
        return ""
    try:
        with Store(_store_path(args.store, False)) as store:
            store.record_channel_events(args.tenant, record.name, events, run_id=None)
    except (Failure, StoreError) as error:
        return "; the channel events stayed unrecorded: %s" % error
    return ""


def _collected(args, record, section, credential) -> tuple:
    try:
        return _gathered(record, section, credential, args.max_response_bytes)
    except collect.CollectError as error:
        events = () if error.event is None else (error.event,)
        raise Failure("channel %s: %s%s" % (section.channel, error, _traced(args, record, events)))


def _completeness(tenant, record, section, snapshot):
    try:
        missing = collect.missing_sections(
            snapshot.text, section.required_sections, snapshot.platform
        )
        item = collect.completeness_finding(record.name, missing)
    except collect.CollectError as error:
        raise Failure("completeness: %s" % error)
    if item is None:
        return None
    return Finding(
        rule_id=COMPLETENESS_RULE % record.platform,
        rule_version=COMPLETENESS_RULE_VERSION,
        tenant=tenant,
        device=record.name,
        object_key=item["object_key"],
        severity=COMPLETENESS_SEVERITY,
        rule_class=COMPLETENESS_CLASS,
        section=item["section"],
        line=item["line"],
        evidence=tuple(sorted(item["evidence"].items())),
    )


def _recorded(args, record, snapshot, rules_version, findings, events) -> tuple:
    path = _store_path(args.store, False)
    try:
        with Store(path) as store:
            _checked_policy_scope(store, args.tenant, record.name, rules_version)
            baseline = store.baseline_fingerprints(args.tenant, record.name)
            previous = _previous(store, args.tenant, record.name)
            run_id = store.record_run(
                args.tenant,
                record.name,
                snapshot.sha256,
                snapshot.source,
                rules_version,
                findings,
            )
            store.record_channel_events(args.tenant, record.name, events, run_id=run_id)
            accepted = None
            if args.baseline_accept:
                accepted = store.accept_baseline(
                    args.tenant, record.name, run_id, args.accepted_by, args.note
                )
    except StoreError as error:
        raise Failure("store: %s" % error)
    return previous, baseline, accepted


def _collection(snapshot, record, credential) -> dict:
    return {
        "channel": snapshot.channel,
        "source": snapshot.source,
        "profile": snapshot.profile,
        "credential-kind": CREDENTIAL_NONE if credential is None else credential.kind,
        "snapshot_sha256": snapshot.sha256,
        "legacy_ssh": record.legacy_ssh if record.legacy_ssh else LEGACY_NONE,
    }


def _command_collect(args) -> int:
    _checked_options(args)
    _checked_budget(args.max_response_bytes)
    record, section = _inventory_record(args.inventory, args.device)
    platform = _catalog_platform(record)
    rules = _load_rules(platform)
    rules_version = _rules_version(platform, rules)
    suppression_items = _load_suppressions(args.suppressions, args.tenant)
    credential = _credential(record, section, args.vault)
    snapshot, events = _collected(args, record, section, credential)
    policy, coverage = _policy(args, platform, snapshot.text)
    if policy:
        rules_version += ":" + management.policy_digest(policy)
    gate = _completeness(args.tenant, record, section, snapshot)
    findings = (
        (gate,)
        if gate is not None
        else _audit(platform, snapshot.text, args.tenant, record.name, rules, policy)
    )
    previous, baseline, accepted = (), frozenset(), None
    if args.store:
        previous, baseline, accepted = _recorded(
            args, record, snapshot, rules_version, findings, events
        )
    result = classify(findings, baseline, suppression_items, previous, datetime.now(timezone.utc))
    report = _report(
        args.tenant, record.name, platform, snapshot.sha256, rules_version, findings, result
    )
    report[COLLECTION_KEY] = _collection(snapshot, record, credential)
    report["rule_coverage"] = coverage
    sys.stdout.write(_render(report, args.as_json, _text_report))
    if accepted is not None:
        sys.stderr.write("baseline: accepted %d of %d findings\n" % (accepted, len(findings)))
    return EXIT_OK


def _command_migrate_suppressions(args) -> int:
    try:
        count = migrate_suppressions(args.source, args.destination, args.tenant)
    except SuppressionError as error:
        raise Failure("suppressions: %s" % error)
    sys.stdout.write(
        "migrated %d suppressions of tenant %s into %s\n"
        % (count, args.tenant, args.destination)
    )
    return EXIT_OK


def _command_merge_sarif(args) -> int:
    documents = []
    for source in args.inputs:
        try:
            documents.append((source, json.loads(Path(source).read_text(encoding="utf-8"))))
        except (OSError, UnicodeError, ValueError) as error:
            raise Failure("cannot read SARIF %s: %s" % (source, error))
    try:
        merged = sarif.merge(documents)
    except sarif.SarifError as error:
        raise Failure("merge-sarif: %s" % error)
    try:
        Path(args.output).write_text(sarif.render(merged), encoding="utf-8")
    except OSError as error:
        raise Failure("cannot write SARIF: %s" % error)
    results = len(merged["runs"][0]["results"])
    sys.stdout.write("merged %d results from %d files into %s\n" % (results, len(documents), args.output))
    return EXIT_OK


def _command_migrate_store(args) -> int:
    path = _store_path(args.store, True)
    try:
        counts = migrate_store(path)
    except StoreError as error:
        raise Failure("store: %s" % error)
    sys.stdout.write(
        "migrated %d findings and %d baseline entries in %s\n"
        % (counts["findings"], counts["baseline"], path)
    )
    return EXIT_OK


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        return args.handler(args)
    except Failure as error:
        sys.stderr.write("error: %s\n" % error)
        return EXIT_ERROR



def _policy(args, platform, text):
    try:
        policy = management.load_policy(args.policy, platform) if getattr(args, "policy", None) else None
        tree = PLATFORMS[platform][1].parse(text)
        coverage = management.coverage(platform, tree, policy)
        missing = [name for name in (policy or {}).get("required_rules", []) if coverage[name] != "evaluated"]
        if missing:
            raise Failure("mandatory policy rules not evaluated: " + ", ".join(missing))
        return policy, coverage
    except (OSError, ValueError, UnicodeError, l1_fortios.ParseError, l1_exos.ParseError) as exc:
        raise Failure("policy cannot be evaluated (%s)" % type(exc).__name__) from None

if __name__ == "__main__":
    sys.exit(main())
