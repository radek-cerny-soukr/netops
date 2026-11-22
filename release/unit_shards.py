"""Deterministic split of the installed product unit tests into CI shards.

The image copies tests/v1 to /opt/netops/tests and CI used to run all of it
with ``python -m unittest discover``.  This tool lists the same test modules
(top-level ``test*.py``, the default discovery pattern) and assigns each
module to exactly one shard: modules are placed longest first on the least
loaded process slot of all shards (PARALLEL slots per shard; ties: lower
slot, then lower shard) using the measured WEIGHTS, so the same tree always
gives the same shards.

  --list                 print every test module, sorted (CI runs it on the
                         source and, from stdin, inside the product image and
                         compares both lists)
  --shards N --shard K   print the modules of shard K, one per line, longest
                         first (the order the runner starts them in)
  --shards N --check     prove the shards are disjoint, non-empty and together
                         contain every test module (nothing can drop out)

Standard library only; it never imports the product or the tests.
"""

import argparse
from pathlib import Path
import sys

# run from a file on the host, or from stdin inside the product image (with --tests)
ROOT = Path(globals().get("__file__", "unit_shards.py")).resolve().parents[1]
TESTS = ROOT / "tests" / "v1"

# Seconds per module, measured one module per container with four modules in
# parallel on four pinned cores (AMD; GitHub runners were 1.3-2x slower).
# Only the ratios matter.  A module without a weight gets DEFAULT_WEIGHT;
# --check refuses weights of modules that no longer exist.
WEIGHTS = {
    "test_abandoned_large": 7.4,
    "test_admin_text_limits": 10.2,
    "test_admission_negatives": 7.6,
    "test_admission_uvicorn": 3.8,
    "test_argument_items_contract": 2.2,
    "test_argument_items_independent": 76.1,
    "test_audit_admission_owner_parent": 1.0,
    "test_audit_cancellation": 3.1,
    "test_audit_contract_negatives": 2.3,
    "test_audit_file_order": 11.2,
    "test_audit_pending_truth": 3.8,
    "test_audit_shutdown": 12.1,
    "test_auditor_ctrl_c_message": 2.1,
    "test_auditor_inputs": 2.3,
    "test_auditor_running_collect": 11.8,
    "test_auditor_text_limits": 4.2,
    "test_body_receive_deadline": 4.3,
    "test_bootstrap_directories": 0.7,
    "test_ca_and_audit_recovery": 5.3,
    "test_catalog_paging_block": 4.7,
    "test_cli_operation_scope": 2.4,
    "test_collect_inventory_guidance": 2.6,
    "test_config_block": 7.2,
    "test_config_embedded_cli": 1.2,
    "test_config_embedded_operational": 1.6,
    "test_config_embedded_operational_actual802": 1.5,
    "test_config_embedded_operational_families": 1.6,
    "test_config_embedded_operational_get_aliases": 1.3,
    "test_config_embedded_operational_shell": 1.7,
    "test_config_export_integrity": 97.7,
    "test_config_filter_block": 3.4,
    "test_config_fortiadc": 2.8,
    "test_config_fortios_visibility": 14.9,
    "test_config_framed_stream_block": 1.4,
    "test_config_full_engine": 42.5,
    "test_config_full_exceptions": 1.1,
    "test_config_full_filter": 8.5,
    "test_config_full_fortios": 1.4,
    "test_config_full_redaction": 1.2,
    "test_config_minimal_real_fortios": 5.1,
    "test_config_semantic_redaction": 2.1,
    "test_config_sibling_headers": 19.9,
    "test_config_unsupported_firmware": 4.9,
    "test_configuration_diagnostics": 3.3,
    "test_configure_exception_boundary": 2.5,
    "test_configure_failure_origin": 3.0,
    "test_configure_guidance_boundary": 3.6,
    "test_diagnostic_block": 7.0,
    "test_diagnostic_precision": 3.3,
    "test_f3_unreachable_ssh": 18.6,
    "test_fortiadc_f1_contract": 2.2,
    "test_fortiadc_live_export": 2.1,
    "test_fortiadc_profile_coverage": 1.7,
    "test_gateway_operator_inputs": 11.4,
    "test_health_live_tail": 1.0,
    "test_health_queue_bytes": 1.0,
    "test_healthz": 4.4,
    "test_helper_assigned_secrets": 15.7,
    "test_helper_pagination_null": 25.4,
    "test_helper_prompts": 3.1,
    "test_helper_redaction_contract": 12.8,
    "test_helper_redaction_formats": 3.3,
    "test_helper_status_version": 1.2,
    "test_helper_text_limits": 13.9,
    "test_import_read_only": 4.7,
    "test_init_audit_choice": 1.6,
    "test_init_server_name_placeholder": 1.1,
    "test_initialization_guidance": 2.4,
    "test_linear_time_parsers": 2.4,
    "test_mcp_argument_guidance": 5.9,
    "test_operator_failure_consistency": 3.3,
    "test_operator_faults": 2.5,
    "test_parser_watchdog": 1.1,
    "test_partial_body_ownership": 2.6,
    "test_pending_truth_contract": 1.3,
    "test_port_ranges": 2.8,
    "test_probe_vantage": 1.6,
    "test_progress_bridge": 1.2,
    "test_progress_delivery_failures": 3.1,
    "test_progress_stream": 7.1,
    "test_proxy_banner_classification": 1.2,
    "test_proxy_negotiation_diagnostics": 1.3,
    "test_psk_occurrence_labels": 2.6,
    "test_read_admission_permissions": 1.1,
    "test_redaction_1_0_6_floor": 757.2,
    "test_redaction_adversarial": 6.0,
    "test_redaction_candidate_contract": 1.2,
    "test_redaction_candidate_scan": 5.2,
    "test_redaction_capability": 1.0,
    "test_redaction_fastpath_contract": 0.9,
    "test_redaction_private_keys": 0.9,
    "test_redaction_short_string_contract": 1.3,
    "test_redaction_spans_serialization": 0.7,
    "test_redaction_window_boundaries": 97.4,
    "test_response_send_deadline": 4.5,
    "test_response_snmp_context": 1.1,
    "test_results": 3.3,
    "test_runtime": 22.0,
    "test_scope_field_names": 1.3,
    "test_selftest_manifest_contract": 3.8,
    "test_selftest_tools": 3.9,
    "test_snmp_config_credentials": 2.0,
    "test_snmpv3_auth": 1.0,
    "test_snmpv3_engine": 1.6,
    "test_start_role_config_admission": 2.3,
    "test_start_semantic_admission": 2.4,
    "test_startup_rpc": 2.1,
    "test_state_version": 2.3,
    "test_switch_managed_bridge": 3.2,
    "test_switch_read_audit_g2a": 1.6,
    "test_syslog_completed_bytes_preserved": 8.9,
    "test_syslog_parts": 47.1,
    "test_syslog_reassemble_cli": 20.4,
    "test_syslog_tls": 8.4,
    "test_tls_ca_guidance": 2.2,
    "test_triage_unreachable_bridge": 3.1,
    "test_upgrade_previous_release": 2.9,
    "test_webhook_safeguard_redaction": 1.1,
    "test_worker_configuration_guidance": 2.8,
    "test_worker_owned_transform": 1.0,
    "test_worker_snmp_get": 1.3,
}
DEFAULT_WEIGHT = 10.0
# Test processes per shard: a GitHub ubuntu-24.04 runner has 4 vCPUs and the job runs xargs -P "$(nproc)".
PARALLEL = 4


class ShardError(Exception):
    pass


def modules(tests=TESTS):
    tests = Path(tests)
    if not tests.is_dir():
        raise ShardError("test directory is missing: %s" % tests)
    packages = sorted(str(path.parent.relative_to(tests)) for path in tests.rglob("__init__.py"))
    if packages:
        # unittest discovery would descend into these packages; this tool only shards top-level modules
        raise ShardError("test packages are not supported by the shard split: " + ", ".join(packages))
    found = sorted(path.stem for path in tests.glob("test*.py") if path.is_file())
    if not found:
        raise ShardError("no test modules in %s" % tests)
    return found


def assign(names, shards, weights=None, parallel=None):
    """Longest module first onto the least loaded of the shards x parallel process slots.

    Returns the modules of every shard, longest first (the order the runner starts
    them in), and the estimated duration of every shard (its busiest slot).
    """
    weights = WEIGHTS if weights is None else weights
    parallel = PARALLEL if parallel is None else parallel
    if shards < 1 or parallel < 1:
        raise ShardError("the number of shards and of parallel processes must be at least 1")
    if shards > len(names):
        raise ShardError("more shards (%d) than test modules (%d)" % (shards, len(names)))
    weight = lambda name: weights.get(name, DEFAULT_WEIGHT)
    plan = [[] for _ in range(shards)]
    slots = [[0.0] * parallel for _ in range(shards)]
    for name in sorted(names, key=lambda item: (-weight(item), item)):
        shard, slot = min(((shard, slot) for shard in range(shards) for slot in range(parallel)),
                          key=lambda place: (slots[place[0]][place[1]], place[1], place[0]))
        plan[shard].append(name)
        slots[shard][slot] += weight(name)
    return plan, [max(loads) for loads in slots]


def check(names, shards, weights=None):
    weights = WEIGHTS if weights is None else weights
    errors = []
    stale = sorted(set(weights) - set(names))
    if stale:
        errors.append("weights name missing test modules: " + ", ".join(stale))
    plan, loads = assign(names, shards, weights)
    seen = {}
    for number, members in enumerate(plan, 1):
        if not members:
            errors.append("shard %d is empty" % number)
        for name in members:
            if name in seen:
                errors.append("%s is in shards %d and %d" % (name, seen[name], number))
            seen[name] = number
    missing = sorted(set(names) - set(seen))
    if missing:
        errors.append("modules in no shard: " + ", ".join(missing))
    extra = sorted(set(seen) - set(names))
    if extra:
        errors.append("shards name unknown modules: " + ", ".join(extra))
    return errors, plan, loads


def main(argv=None):
    parser = argparse.ArgumentParser(description="Split the installed product unit tests into CI shards.")
    parser.add_argument("--shards", type=int, help="number of shards")
    parser.add_argument("--shard", type=int, help="shard to print (1..N)")
    parser.add_argument("--check", action="store_true", help="verify that the shards cover every test module once")
    parser.add_argument("--list", action="store_true", help="print every test module")
    parser.add_argument("--tests", default=str(TESTS), help="test directory (default: tests/v1)")
    args = parser.parse_args(argv)
    try:
        names = modules(args.tests)
        if args.list:
            print("\n".join(names))
            return 0
        if args.shards is None:
            parser.error("--shards is required with --shard or --check")
        if args.check:
            errors, plan, loads = check(names, args.shards)
            for number, (members, load) in enumerate(zip(plan, loads), 1):
                print("shard %d/%d: %d modules, estimated %.0f s at the measured speed with %d processes"
                      % (number, args.shards, len(members), load, PARALLEL))
            print("%d test modules in %d shards" % (sum(len(members) for members in plan), args.shards))
            for error in errors:
                print("error: " + error, file=sys.stderr)
            return 1 if errors else 0
        if args.shard is None or not 1 <= args.shard <= args.shards:
            parser.error("--shard must be between 1 and --shards")
        plan, _ = assign(names, args.shards)
        print("\n".join(plan[args.shard - 1]))
        return 0
    except ShardError as error:
        print("error: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
