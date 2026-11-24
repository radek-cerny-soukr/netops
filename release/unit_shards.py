"""Deterministic split of the installed product unit tests into CI shards.

The image copies tests/v1 to /opt/netops/tests and CI used to run all of it
with ``python -m unittest discover``.  This tool lists the same test modules
(top-level ``test*.py``, the default discovery pattern) and assigns each
module to exactly one shard: modules are placed longest first on the least
loaded process slot of all shards (PARALLEL slots per shard; ties: lower
slot, then lower shard) using the measured WEIGHTS, so the same tree always
gives the same shards.

Time-sensitive modules (SERIAL_MODULES: a test with a wall-clock budget that
fails when other test containers compete for the CPU) stay in the shard the
split gives them, but the runner starts them only after the parallel part of
the shard has finished, one at a time, with no other test container running.

  --list                 print every test module, sorted (CI runs it on the
                         source and, from stdin, inside the product image and
                         compares both lists)
  --shards N --shard K   print the modules of shard K, one per line: the
                         parallel part longest first (the order the runner
                         starts them in), then the serial part
  --part parallel|serial with --shard: print only the modules the runner starts
                         in parallel, or only the SERIAL_MODULES of the shard
                         (run alone, one after another, after the parallel
                         part; may be empty)
  --check [--shards N]   prove the shards are disjoint, non-empty and together
                         contain every test module (default: three shards);
                         estimates include the redaction corpus. With
                         GITHUB_EVENT_NAME=workflow_dispatch, run the whole
                         corpus as one module; otherwise, use partitions when
                         supported by the tested tree.
  --tests DIR            split the test modules of another tree (a manual CI
                         run tests a released tag with the tools of the
                         workflow revision)
  --ignore-stale-weights with --check: weights and serial modules that the tested
                         tree does not have are not an error (they cannot change
                         the split); coverage, disjointness and non-empty
                         shards are still proven

Standard library only; it never imports the product or the tests.
"""

import argparse
import os
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
    "test_auditor_admin_gate_compatibility": 1.0,
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
    "test_network_overview_bridge": 4.3,
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
REDACTION_FLOOR = "test_redaction_1_0_6_floor"
# Modules with a wall-clock budget inside the test: under four concurrent test
# containers test_admin_text_limits exceeded its 10 s parser budget on GitHub
# (runs 45022462276 and 45022466018) although it passes alone.  Each runs in its
# shard after the parallel part, alone; the budget itself is never changed and a
# failure is not retried.  The single list of such modules: --check proves that
# each of them is a test module and in the serial part of exactly one shard.
SERIAL_MODULES = (
    "test_admin_text_limits",
)
# Test processes per shard: a GitHub ubuntu-24.04 runner has 4 vCPUs and the job runs xargs -P "$(nproc)".
PARALLEL = 4
DEFAULT_SHARDS = 3


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


def assign(names, shards, weights=None, parallel=None, serial=None):
    """Longest module first onto the least loaded of the shards x parallel process slots.

    Returns the modules of every shard and the estimated duration of every shard.
    The members of a shard are its parallel part longest first (the order the
    runner starts them in), then its serial modules longest first.  Serial
    modules are placed like the others (the split does not depend on the serial
    list), but the estimate of a shard is its busiest slot without them plus
    their sum (they run one at a time after the parallel part).
    """
    weights = WEIGHTS if weights is None else weights
    parallel = PARALLEL if parallel is None else parallel
    serial = set(SERIAL_MODULES if serial is None else serial)
    if shards < 1 or parallel < 1:
        raise ShardError("the number of shards and of parallel processes must be at least 1")
    if shards > len(names):
        raise ShardError("more shards (%d) than test modules (%d)" % (shards, len(names)))
    weight = lambda name: weights.get(name, DEFAULT_WEIGHT)
    plan = [[] for _ in range(shards)]
    slots = [[0.0] * parallel for _ in range(shards)]
    running = [[0.0] * parallel for _ in range(shards)]
    alone = [[] for _ in range(shards)]
    for name in sorted(names, key=lambda item: (-weight(item), item)):
        shard, slot = min(((shard, slot) for shard in range(shards) for slot in range(parallel)),
                          key=lambda place: (slots[place[0]][place[1]], place[1], place[0]))
        slots[shard][slot] += weight(name)
        if name in serial:
            alone[shard].append(name)
        else:
            plan[shard].append(name)
            running[shard][slot] += weight(name)
    loads = [max(loads) + sum(weight(name) for name in tail) for loads, tail in zip(running, alone)]
    return [members + tail for members, tail in zip(plan, alone)], loads


def parts(members, serial=None):
    """Split the members of a shard into the part run in parallel and the part run alone afterwards."""
    serial = set(SERIAL_MODULES if serial is None else serial)
    return [name for name in members if name not in serial], [name for name in members if name in serial]


def check(names, shards, weights=None, ignore_stale=False, serial=None, parallel=None):
    weights = WEIGHTS if weights is None else weights
    serial = SERIAL_MODULES if serial is None else tuple(serial)
    errors = []
    stale = sorted(set(weights) - set(names))
    if stale and not ignore_stale:
        errors.append("weights name missing test modules: " + ", ".join(stale))
    repeated = sorted(name for name in set(serial) if serial.count(name) > 1)
    if repeated:
        errors.append("serial modules listed more than once: " + ", ".join(repeated))
    absent = sorted(set(serial) - set(names))
    if absent and not ignore_stale:
        errors.append("serial modules name missing test modules: " + ", ".join(absent))
    plan, loads = assign(names, shards, weights, parallel=parallel, serial=serial)
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
    for name in sorted(set(serial) & set(names)):
        alone = [number for number, members in enumerate(plan, 1) if name in parts(members, serial)[1]]
        together = [number for number, members in enumerate(plan, 1) if name in parts(members, serial)[0]]
        if len(alone) != 1 or together:
            errors.append("serial module %s is in the serial part of %d shards and in the parallel part of %d"
                          % (name, len(alone), len(together)))
    return errors, plan, loads


def main(argv=None):
    parser = argparse.ArgumentParser(description="Split the installed product unit tests into CI shards.")
    parser.add_argument("--shards", type=int, help="number of shards")
    parser.add_argument("--shard", type=int, help="shard to print (1..N)")
    parser.add_argument("--part", choices=("parallel", "serial"),
                        help="with --shard: only the modules run in parallel, or only those run alone afterwards")
    parser.add_argument("--check", action="store_true", help="verify that the shards cover every test module once")
    parser.add_argument("--list", action="store_true", help="print every test module")
    parser.add_argument("--tests", default=str(TESTS), help="test directory (default: tests/v1)")
    parser.add_argument("--ignore-stale-weights", action="store_true",
                        help="with --check: do not refuse weights or serial modules missing from the test directory")
    args = parser.parse_args(argv)
    try:
        names = modules(args.tests)
        if args.list:
            print("\n".join(names))
            return 0
        if args.shards is None:
            if not args.check:
                parser.error("--shards is required with --shard")
            args.shards = DEFAULT_SHARDS
        if args.part and (args.check or args.shard is None):
            parser.error("--part needs --shard and cannot be combined with --check")
        weights = WEIGHTS
        parallel = PARALLEL
        partitioned = False
        if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch" and REDACTION_FLOOR in names:
            floor_source = Path(args.tests, REDACTION_FLOOR + ".py").read_text(encoding="utf-8")
            partitioned = "NETOPS_REDACTION_FUZZ_PART" in floor_source
            if partitioned:
                # Branch CI starts one partition in each runner's first slot.
                # Balance the other modules across the remaining slots.
                weights = {**WEIGHTS, REDACTION_FLOOR: 0}
                parallel = PARALLEL - 1
        if args.check:
            errors, plan, loads = check(names, args.shards, weights,
                                       ignore_stale=args.ignore_stale_weights, parallel=parallel)
            if partitioned:
                print("branch CI: redaction corpus split into %d partitions" % args.shards)
            unweighted = sorted(set(names) - set(WEIGHTS))
            if unweighted:
                print("modules without a measured weight (%.0f s assumed): %s" % (DEFAULT_WEIGHT, ", ".join(unweighted)))
            for number, (members, load) in enumerate(zip(plan, loads), 1):
                alone = parts(members)[1]
                if partitioned:
                    floor_seconds = WEIGHTS[REDACTION_FLOOR] / args.shards
                    load = max(load, floor_seconds + sum(weights.get(name, DEFAULT_WEIGHT) for name in alone))
                print("shard %d/%d: %d modules (%d run alone afterwards%s), estimated %.0f s at the measured speed with %d processes"
                      % (number, args.shards, len(members), len(alone), (": " + ", ".join(alone)) if alone else "",
                         load, PARALLEL))
            print("%d test modules in %d shards" % (sum(len(members) for members in plan), args.shards))
            for error in errors:
                print("error: " + error, file=sys.stderr)
            return 1 if errors else 0
        if args.shard is None or not 1 <= args.shard <= args.shards:
            parser.error("--shard must be between 1 and --shards")
        plan, _ = assign(names, args.shards, weights, parallel=parallel)
        members = plan[args.shard - 1]
        if args.part:
            members = parts(members)[0 if args.part == "parallel" else 1]
        if members:
            print("\n".join(members))
        return 0
    except ShardError as error:
        print("error: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
