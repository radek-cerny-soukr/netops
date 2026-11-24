#!/usr/bin/env python3
"""Source, SSH wire and privacy checks for the reviewed Helper contract."""

from __future__ import annotations

import ast
import io
import json
import os
from pathlib import Path
import re
import stat
import tokenize
from typing import Any


TEXT_SUFFIXES = {
    "", ".cfg", ".env", ".in", ".ini", ".json", ".lock", ".md", ".py", ".sh", ".toml", ".txt",
    ".yaml", ".yml",
}
SECRET_MATERIAL_MARKERS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bssh-(?:ed25519|rsa|dss) AAAA[0-9A-Za-z+/]{40,}"),
)
PRIVATE_NETWORK_MARKERS = (
    re.compile(r"(?<![0-9])100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9])"),
    re.compile(r"(?<![0-9])169\.254\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9])"),
    re.compile(r"(?<![0-9a-f:])f[cd][0-9a-f]{2}:[0-9a-f:]+", re.IGNORECASE),
    re.compile(r"(?<![0-9a-f:])fe80:[0-9a-f:]+", re.IGNORECASE),
    re.compile(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:local|lan|home\.arpa|internal|intranet)\b", re.IGNORECASE),
)


def _mcp_tool(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(decorator, ast.Attribute) and decorator.attr == "tool"
        or isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr == "tool"
        for decorator in function.decorator_list
    )


def _schema_snapshot_allowed(tree: ast.AST) -> bool:
    functions=[n for n in getattr(tree,"body",()) if isinstance(n,ast.FunctionDef) and n.name=="schema_read"]
    if len(functions)!=1:
        return False
    function=functions[0]
    if not any(isinstance(n,ast.Name) and n.id=="_audit_device_call" for n in function.decorator_list):
        return False
    imports=[n for n in ast.walk(function) if isinstance(n,ast.ImportFrom) and n.level==1 and n.module is None]
    if not any(any(a.name=="schema_read" and a.asname=="reader" for a in n.names) for n in imports):
        return False
    calls=[n for n in ast.walk(function) if isinstance(n,ast.Call)]
    controls={}
    for call in calls:
        if isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name) and call.func.value.id=="reader":
            controls.setdefault(call.func.attr,[]).append(call)
    if any(len(controls.get(name,()))!=1 for name in ("binding","selectors","verify_status","snapshot")):
        return False
    reads=[n for n in calls if isinstance(n.func,ast.Name) and n.func.id=="read_from_device"]
    if len(reads)!=2 or any(len(n.args)!=3 for n in reads):
        return False
    status=[n for n in reads if isinstance(n.args[2],ast.Constant) and n.args[2].value=="get system status"]
    snapshots=[n for n in reads if isinstance(n.args[2],ast.Constant) and n.args[2].value=="show full-configuration"]
    if len(status)!=1 or len(snapshots)!=1:
        return False
    ordered=[controls["binding"][0],controls["selectors"][0],status[0],controls["verify_status"][0],snapshots[0],controls["snapshot"][0]]
    if [n.lineno for n in ordered]!=sorted(n.lineno for n in ordered):
        return False
    if any(not isinstance(n.args[0],ast.Name) or n.args[0].id!="auth" or
           not isinstance(n.args[1],ast.Constant) or n.args[1].value!="fortinet" for n in reads):
        return False
    parents={child:parent for parent in ast.walk(function) for child in ast.iter_child_nodes(parent)}
    expected={"binding":["auth"],"selectors":["auth","library","path","view","vdom","keys"],
              "verify_status":["library","status"]}
    for name,arguments in expected.items():
        if [getattr(arg,"id",None) for arg in controls[name][0].args]!=arguments:
            return False
    identity_assignment=parents.get(controls["verify_status"][0])
    if not isinstance(identity_assignment,ast.Assign) or len(identity_assignment.targets)!=1 or not isinstance(identity_assignment.targets[0],ast.Name):
        return False
    context_name=identity_assignment.targets[0].id
    stores=[n for n in ast.walk(function) if isinstance(n,ast.Name) and n.id==context_name and isinstance(n.ctx,ast.Store)]
    if len(stores)!=1:
        return False
    context_keywords=[n for n in controls["snapshot"][0].keywords if n.arg=="current_vdom"]
    if len(context_keywords)!=1 or not isinstance(context_keywords[0].value,ast.Name) or context_keywords[0].value.id!=context_name:
        return False
    snapshot_assignment=parents.get(snapshots[0])
    if not isinstance(snapshot_assignment,ast.Assign) or len(snapshot_assignment.targets)!=1:
        return False
    target=snapshot_assignment.targets[0]
    if not isinstance(target,ast.Tuple) or [getattr(n,"id",None) for n in target.elts]!=["rc","raw"]:
        return False
    for node in ast.walk(function):
        if isinstance(node,ast.Name) and node.id=="raw" and isinstance(node.ctx,ast.Load):
            parent=parents[node]
            refusal=isinstance(parent,ast.Call) and isinstance(parent.func,ast.Name) and parent.func.id=="_cli_refused" and len(parent.args)==2 and parent.args[1] is node
            selection=parent is controls["snapshot"][0] and len(parent.args)>=2 and parent.args[1] is node
            if not (refusal or selection):
                return False
    return True


def _diagnostic_vdom_allowed(tree: ast.AST) -> bool:
    functions = {n.name: n for n in getattr(tree, "body", ()) if isinstance(n, ast.FunctionDef)}
    run, identity = functions.get("run"), functions.get("status_identity")
    if run is None or identity is None:
        return False
    def raising_guard(function, expression):
        expected = ast.dump(ast.parse(expression, mode="eval").body)
        return [n for n in ast.walk(function) if isinstance(n, ast.If)
                and ast.dump(n.test) == expected
                and any(isinstance(child, ast.Raise) for child in n.body)]
    for expression in ('len(domains) != 1 or not VDOM_NAME.fullmatch(domains[0])',
                       'len(markers) != 1 or markers[0] not in VDOM_MODES',
                       'mode == "disable" and domains != ["root"]'):
        if len(raising_guard(identity, expression)) != 1:
            return False
    unscoped = raising_guard(run, 'vdom is None and mode != "disable"')
    vdom_foreign = raising_guard(run, "vdom is not None and vdom != domain")
    read = ast.dump(ast.parse('owner = interfaces.entries[interface].value("vdom")').body[0])
    reported = [n for n in ast.walk(run) if isinstance(n, ast.If)
                and ast.dump(n.test) == ast.dump(ast.parse('interfaces is not None and set(interfaces.entries)=={interface}', mode="eval").body)
                and [ast.dump(child) for child in n.body] == [read]]
    unknown = raising_guard(run, "owner is None")
    foreign = raising_guard(run, "owner!=domain")
    calls = [n for n in ast.walk(run) if isinstance(n, ast.Call)]
    expected = ast.dump(ast.parse('status_identity(shell.command("get system status"))', mode="eval").body)
    status = [n for n in calls if ast.dump(n) == expected]
    if any(isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
           and n.func.value.id == "shell" and n.func.attr == "navigate" for n in calls):
        return False
    # 1.0.9 item 11 (measured on the 60F 7.6.8): only the sessions recipe of a multi-VDOM session enters the
    # context of the verified session VDOM, after the VDOM guards and before the interface owner is read, and
    # enter_vdom answers only for a `current vf=<vdom>:<index>` marker checked by context_index.
    context_assign = ast.dump(ast.parse(
        'context = enter_vdom(shell, domain) if mode == "multiple" and recipe == "sessions" else None').body[0])
    contexts = [n for n in ast.walk(run) if isinstance(n, ast.Assign) and ast.dump(n) == context_assign]
    entered = [n for n in calls if isinstance(n.func, ast.Name) and n.func.id == "enter_vdom"
               and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id == "shell"]
    enter = functions.get("enter_vdom")
    marker = enter is not None and any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                                       and n.func.id == "context_index" for n in ast.walk(enter))
    # STARTUP (2026-11-17): the tested identities are not a gate any more (firmware_support reports them), so the
    # status read is followed directly by the VDOM guards.
    return (len(unscoped) == len(vdom_foreign) == len(reported) == len(unknown) == len(foreign) == len(status) == 1
            and len(contexts) == len(entered) == 1 and marker
            and status[0].lineno < unscoped[0].lineno < vdom_foreign[0].lineno
            < contexts[0].lineno < reported[0].lineno < unknown[0].lineno < foreign[0].lineno)


def _diagnostic_wrapper_allowed(tree: ast.AST) -> bool:
    functions=[n for n in getattr(tree,"body",()) if isinstance(n,ast.FunctionDef) and n.name=="fortios_diagnostics"]
    adc=[n for n in getattr(tree,"body",()) if isinstance(n,ast.FunctionDef) and n.name=="_fortiadc_diagnostics"]
    if len(functions)!=1 or len(adc)!=1:
        return False
    function=functions[0]
    if not any(isinstance(n,ast.Name) and n.id=="_audit_device_call" for n in function.decorator_list):
        return False
    return _diagnostic_calls_ordered(function,{
        "diagnostics.validate": ["recipe","address","interface","count","timeout","max_bytes","vdom"],
        "diagnostics.authorize": ["auth","recipe","address","interface","vdom"],
        "diagnostics.run": ["shell","recipe","address","interface","count","timeout","vdom"]}) and _diagnostic_calls_ordered(adc[0],{
        "diagnostics.adc_validate": ["recipe","address","interface","count","timeout","max_bytes","vdom","health_check"],
        "diagnostics.adc_authorize": ["auth","recipe","address","health_check"],
        "diagnostics.adc_run": ["shell","recipe","address","timeout","count","health_check"]})


def _diagnostic_calls_ordered(function: ast.FunctionDef, expected: dict) -> bool:
    found={}
    for call in (n for n in ast.walk(function) if isinstance(n,ast.Call)):
        if isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name):
            name=call.func.value.id+"."+call.func.attr
            if name in expected:
                if name in found or [getattr(arg,"id",None) for arg in call.args]!=expected[name]:
                    return False
                found[name]=call.lineno
    return set(found)==set(expected) and list(found[name] for name in expected)==sorted(found.values())


def _catalog_code_text(source: str, tree: ast.Module) -> str:
    """Preserve code spelling and positions while masking comments and docstrings."""
    lines = source.splitlines(keepends=True)

    def position(line: int, byte_column: int) -> tuple[int, int]:
        return line, len(lines[line - 1].encode("utf-8")[:byte_column].decode("utf-8"))

    docstrings = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                value = node.body[0].value
                docstrings.append((position(value.lineno, value.col_offset),
                                   position(value.end_lineno, value.end_col_offset)))
    tokens = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT or any(
            start <= token.start and token.end <= end for start, end in docstrings
        ):
            token = token._replace(string=re.sub(r"[^\r\n]", " ", token.string))
        tokens.append(token)
    return tokenize.untokenize(tokens).lower()


def _nxos_session_summary_nodes(tree: ast.Module, relative: str) -> list[ast.Constant]:
    """Exact NX-M008 literals in the NX-OS catalogue and its platform guard only."""
    command = "show configuration session summary"
    if relative == "src/netops_helper/query_catalog/cisco.py":
        for assignment in tree.body:
            if (isinstance(assignment, ast.AnnAssign)
                    and isinstance(assignment.target, ast.Name)
                    and assignment.target.id == "NXOS_QUERIES"
                    and isinstance(assignment.value, ast.Dict)):
                return [value.args[0]
                        for key, value in zip(assignment.value.keys, assignment.value.values)
                        if isinstance(key, ast.Constant) and key.value == "configuration_sessions"
                        and isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                        and value.func.id == "Query" and value.args
                        and isinstance(value.args[0], ast.Constant) and value.args[0].value == command]
    if relative == "src/netops_helper/read_policy.py":
        expected = ast.parse(
            'platform == "cisco_nxos" and inspected == "show configuration session summary"',
            mode="eval",
        ).body
        return [node.test.values[1].comparators[0]
                for function in tree.body
                if isinstance(function, ast.FunctionDef) and function.name == "_validate_query_command"
                for node in function.body
                if isinstance(node, ast.If) and ast.dump(node.test) == ast.dump(expected)
                and len(node.body) == 1 and isinstance(node.body[0], ast.Return)
                and node.body[0].value is None and not node.orelse]
    return []


def _junos_filter_binding_nodes(tree: ast.Module, relative: str) -> list[ast.Constant]:
    """Recognize the sole reviewed Junos configuration leaf template."""
    if relative != "src/netops_helper/query_catalog/junos.py":
        return []
    command = "show configuration interfaces {interface} family inet filter | no-more"
    return [node.value for node in tree.body
            if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "FILTER_BINDING_COMMAND"
            and isinstance(node.value, ast.Constant) and node.value.value == command]


def _junos_management_nodes(tree: ast.Module, relative: str) -> list[ast.Constant]:
    """Recognize the five reviewed management leaves in the fixed Junos map."""
    if relative != "src/netops_helper/query_catalog/junos.py":
        return []
    assignments = [node for node in tree.body if isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == "CONFIG_COMMANDS" for target in node.targets
    )]
    if len(assignments) != 1 or len(assignments[0].targets) != 1:
        return []
    mapping = assignments[0].value
    paths = {"dns_resolvers": "name-server", "syslog_status": "syslog", "authentication_order": "authentication-order",
             "radius_servers": "radius-server", "tacacs_servers": "tacplus-server"}
    if not isinstance(mapping, ast.Dict) or len(mapping.keys) != len(paths):
        return []
    if any(not isinstance(key, ast.Constant) or not isinstance(key.value, str)
           or not isinstance(value, ast.Constant) or not isinstance(value.value, str)
           for key, value in zip(mapping.keys, mapping.values)):
        return []
    commands = {key.value: value.value for key, value in zip(mapping.keys, mapping.values)}
    expected = {name: f"show configuration system {path} | display xml | no-more" for name, path in paths.items()}
    return list(mapping.values) if commands == expected else []


def _startup_diff_nodes(tree: ast.Module, relative: str) -> list[ast.Constant]:
    diffs = {
        "src/netops_helper/config_arista_eos_adapter.py": "show running-config diffs",
        "src/netops_helper/config_cisco_nxos_adapter.py": "show running-config diff",
        "src/netops_helper/config_cisco_ios_adapter.py":
            "show archive config differences nvram:startup-config system:running-config",
        "src/netops_helper/config_cisco_xe_adapter.py":
            "show archive config differences nvram:startup-config system:running-config",
    }
    if relative not in diffs:
        return []
    commands = {
        "STARTUP_COMMAND": "show startup-config",
        "DIFF_COMMAND": diffs[relative],
    }
    nodes = {}
    for statement in tree.body:
        if (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name) and statement.targets[0].id in commands):
            name = statement.targets[0].id
            if name in nodes or not isinstance(statement.value, ast.Constant) or statement.value.value != commands[name]:
                return []
            nodes[name] = statement.value
    return list(nodes.values()) if nodes.keys() == commands.keys() else []


def _phase1_surface_errors(root: Path) -> list[str]:
    errors: list[str] = []
    source_root = root / "src/netops_helper"
    server_path = source_root / "server.py"
    walk_errors: list[OSError] = []
    source_paths: list[Path] = []
    contains_symlink = False
    try:
        if source_root.is_symlink() or not source_root.is_dir():
            raise OSError("phase-1 source root is not a regular directory")
        for directory, directory_names, file_names in os.walk(
            source_root, topdown=True, onerror=walk_errors.append, followlinks=False,
        ):
            directory_path = Path(directory)
            retained_directories = []
            for name in sorted(directory_names):
                candidate = directory_path / name
                mode = candidate.lstat().st_mode
                if stat.S_ISLNK(mode):
                    contains_symlink = True
                    continue
                if not stat.S_ISDIR(mode):
                    raise OSError("phase-1 source child is not a directory")
                retained_directories.append(name)
            directory_names[:] = retained_directories
            for name in sorted(file_names):
                if not name.endswith(".py"):
                    continue
                candidate = directory_path / name
                mode = candidate.lstat().st_mode
                if stat.S_ISLNK(mode):
                    contains_symlink = True
                    continue
                if not stat.S_ISREG(mode):
                    raise OSError("phase-1 Python source is not a regular file")
                source_paths.append(candidate)
    except OSError:
        return ["phase-1 surface sources are unavailable or invalid"]
    if walk_errors or server_path not in source_paths:
        return ["phase-1 surface sources are unavailable or invalid"]
    if contains_symlink:
        errors.append("phase-1 source tree contains a symlink")

    source_texts: dict[Path, str] = {}
    source_trees: dict[Path, ast.Module] = {}
    catalog_texts: dict[Path, str] = {}
    try:
        for source_path in source_paths:
            source_text = source_path.read_text(encoding="utf-8")
            source_texts[source_path] = source_text.lower()
            source_trees[source_path] = ast.parse(source_text)
            catalog_texts[source_path] = _catalog_code_text(source_text, source_trees[source_path])
    except (OSError, UnicodeError, SyntaxError):
        return ["phase-1 surface sources are unavailable or invalid"]

    forbidden_tool_names = {
        "route_trace",
        "traceroute",
        "running_config",
        "startup_config",
        "full_configuration",
        "configuration_backup",
        "configuration_export",
        "https_get",
        "sftp_read_text",
    }
    for node in source_trees[server_path].body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _mcp_tool(node):
            normalized = node.name.lower()
            if normalized in forbidden_tool_names or any(
                marker in normalized
                for marker in ("config_export", "backup_config", "raw_command")
            ):
                errors.append(f"phase-1 server registers forbidden tool: {node.name}")

    diagnostic_tools=[n for n in source_trees[server_path].body if isinstance(n,ast.FunctionDef) and n.name=="fortios_diagnostics" and _mcp_tool(n)]
    if diagnostic_tools:
        engine=source_trees.get(source_root/"engine.py")
        recipes=source_trees.get(source_root/"fortios_diagnostics.py")
        if engine is None or recipes is None or not _diagnostic_wrapper_allowed(engine) or not _diagnostic_vdom_allowed(recipes):
            errors.append("bounded diagnostic audit, grants, identity or single-VDOM controls are incomplete")

    removed_body_read_identifiers = {
        "https_get",
        "sftp_read_text",
        "engine_https_get",
        "engine_sftp_read_text",
        "https_endpoints",
        "require_https_endpoint",
    }
    production_trees = dict(source_trees)
    for relative in (
        "scripts/remote_mcp_proxy.py",
        "scripts/generate_egress_rules.py",
    ):
        path = root / relative
        if not path.exists():
            continue
        try:
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode):
                raise OSError("body-read surface is not a regular file")
            production_trees[path] = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError):
            errors.append(f"phase-1 body-read surface is unavailable or invalid: {relative}")
    for source_path, source_tree in production_trees.items():
        found: set[str] = set()
        for node in ast.walk(source_tree):
            candidates: tuple[str | None, ...] = ()
            if isinstance(node, ast.Name):
                candidates = (node.id,)
            elif isinstance(node, ast.Attribute):
                candidates = (node.attr,)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                candidates = (node.name,)
            elif isinstance(node, ast.alias):
                candidates = (node.name.rsplit(".", 1)[-1], node.asname)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                candidates = (node.value,)
            found.update(
                candidate for candidate in candidates
                if candidate in removed_body_read_identifiers
            )
        if found:
            relative = source_path.relative_to(root).as_posix()
            errors.append(
                "phase-1 removed body-read surface remains in "
                + relative + ": " + ", ".join(sorted(found))
            )

    example_policy = root / "config/inventory.example.json"
    if example_policy.exists():
        try:
            mode = example_policy.lstat().st_mode
            if not stat.S_ISREG(mode):
                raise OSError("example policy is not a regular file")
            example_document = json.loads(example_policy.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append("phase-1 example policy is unavailable or invalid")
        else:
            pending: list[Any] = [example_document]
            legacy_field_found = False
            while pending:
                value = pending.pop()
                if isinstance(value, dict):
                    if "https_endpoints" in value:
                        legacy_field_found = True
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)
            if legacy_field_found:
                errors.append("phase-1 example policy contains removed https_endpoints")

    forbidden_catalog_patterns = (
        "show running-config",
        "show startup-config",
        "show archive config differences",
        "show full-configuration",
        "show configuration",
        "backup configuration",
        "execute backup",
        "running_config",
        "startup_config",
        "full_configuration",
        "configuration_backup",
    )
    forbidden_implementation_patterns = (
        "prepare" + "_",
        "apply" + "_",
        "cancel" + "_change",
        "sftp" + "_upload",
        "send" + "_command_timing",
        "posix" + "_rename",
        "save" + "_config",
        "config" + "_mode",
    )
    config_read_allowances = {
        ("src/netops_helper/config_arista_eos_adapter.py", "show running-config"): 1,
        ("src/netops_helper/config_cisco_nxos_adapter.py", "show running-config"): 1,
        ("src/netops_helper/config_cisco_xe_adapter.py", "show running-config"): 1,
        ("src/netops_helper/config_indented.py", "show running-config"): 1,
        ("src/netops_helper/config_cisco_ios_adapter.py", "show running-config"): 1,
        ("src/netops_helper/config_exos_adapter.py", "show configuration"): 1,
        # JUNOS-CONFIG: Junos display-set capture, the ACCESS-DENIED visibility probe and compare rollback <n>
        ("src/netops_helper/config_junos_adapter.py", "show configuration"): 3,
        ("src/netops_helper/config_fortiadc.py", "show full-configuration"): 2,
        ("src/netops_helper/config_fortios.py", "show full-configuration"): 1,
        # WIRELESS-NETWORK-SERVICES (RP08): the one Unleashed `show config` template and its exact read-policy admission; the engine
        # passes only the allowlisted sections with secrets redacted (tests/test_wireless_network_services_ruckus.py).
        ("src/netops_helper/query_catalog/ruckus.py", "show configuration"): 1,
        ("src/netops_helper/read_policy.py", "show configuration"): 1,
    }
    for source_path in source_paths:
        relative = source_path.relative_to(root).as_posix()
        source_text = source_texts[source_path]
        catalog_text = catalog_texts[source_path]
        if relative == "src/netops_helper/engine.py" and _schema_snapshot_allowed(source_trees[source_path]):
            function=next(n for n in source_trees[source_path].body if isinstance(n,ast.FunctionDef) and n.name=="schema_read")
            lines=catalog_text.splitlines(keepends=True)
            bounded="".join(lines[function.lineno-1:function.end_lineno])
            if bounded.count("show full-configuration")==1 and catalog_text.count("show full-configuration")==1:
                catalog_text=catalog_text.replace("show full-configuration","[bounded schema snapshot]",1)
        if relative == "src/netops_helper/fortios_diagnostics.py" and _diagnostic_vdom_allowed(source_trees[source_path]):
            interface_token='show full-configuration system interface "'
            if catalog_text.count("show full-configuration")==1:
                catalog_text=catalog_text.replace(interface_token,"[verified interface owner]"+chr(34),1)
        # Like the bounded snapshot exceptions above, mask only the reviewed
        # literal at its verified AST location, never a prefix or a source-wide count.
        tree = source_trees[source_path]
        legacy_nodes = _nxos_session_summary_nodes(tree, relative) + _junos_filter_binding_nodes(tree, relative)
        bounded_nodes = ((legacy_nodes if len(legacy_nodes) == 1 else []) + _junos_management_nodes(tree, relative)
                         + _startup_diff_nodes(tree, relative))
        lines = catalog_text.splitlines(keepends=True)
        for node in sorted(bounded_nodes, key=lambda item: (item.lineno, item.col_offset), reverse=True):
            if node.lineno != node.end_lineno:
                continue
            line = lines[node.lineno - 1]
            start = len(line.encode("utf-8")[:node.col_offset].decode("utf-8"))
            end = len(line.encode("utf-8")[:node.end_col_offset].decode("utf-8"))
            lines[node.lineno - 1] = line[:start] + " " * (end - start) + line[end:]
        catalog_text = "".join(lines)
        if relative == "src/netops_helper/adc_monitoring.py":
            # ADC-HA: one fixed NTP section read; no general configuration export.
            exports = [node.value for node in ast.walk(source_trees[source_path])
                       if isinstance(node, ast.Constant) and isinstance(node.value, str)
                       and "show full-configuration" in node.value.lower()]
            if exports == ["show full-configuration system time ntp"]:
                catalog_text = catalog_text.replace("show full-configuration system time ntp",
                                                    "[bounded NTP configuration]", 1)
        for pattern in forbidden_catalog_patterns:
            count = catalog_text.count(pattern)
            if pattern == "show configuration":
                # Abbreviated configuration display is excluded as in read_policy.
                count += sum(match.group() != pattern for match in
                             re.finditer(r"\bshow conf[a-z]*\b", catalog_text))
            if count and count != config_read_allowances.get((relative, pattern)):
                errors.append(
                    "phase-1 source contains configuration export pattern: "
                    f"{relative}: {pattern}"
                )
        for pattern in forbidden_implementation_patterns:
            if pattern in source_text:
                errors.append(
                    "phase-1 source contains a write implementation: "
                    f"{relative}: {pattern}"
                )
    return errors


def _ssh_wire_errors(root: Path) -> list[str]:
    errors: list[str] = []
    engine_path = root / "src/netops_helper/engine.py"
    wire_path = root / "tests/test_ssh_wire_safety.py"
    try:
        engine_text = engine_path.read_text(encoding="utf-8")
        engine_tree = ast.parse(engine_text)
        wire_text = wire_path.read_text(encoding="utf-8")
        wire_tree = ast.parse(wire_text)
    except (OSError, UnicodeError, SyntaxError):
        return ["SSH transport or wire-safety test is unavailable or invalid"]

    imported: set[str] = set()
    for node in ast.walk(engine_tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for retired in ("netmiko", "paramiko"):
        if retired in imported:
            errors.append(f"the read transport still imports {retired}")

    functions = {
        node.name
        for node in ast.walk(engine_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for required in ("host_key_line", "read_from_device", "_exec_read", "_pty_read"):
        if required not in functions:
            errors.append(f"the read transport has no {required}")
    if "netmiko_connection" in functions or "ReadOnlyFortinetSSH" in {
        node.name for node in ast.walk(engine_tree) if isinstance(node, ast.ClassDef)
    }:
        errors.append("a retired Netmiko connection factory is still present")

    for token, message in (
        ("core_hostkey.scan(", "the host key pin is not verified with the shared keyscan"),
        ("core_ssh.run_command(", "the exec transport does not call the shared SSH client"),
        ("core_session.Session(", "the terminal transport does not use the shared session"),
        ("session.discard(", "the terminal transport does not discard its login phase"),
        ("_SSH_TRANSPORTS", "the transport per platform is not a table in the code"),
        ("_PLATFORM_PREAMBLE", "the platform preamble is not a table in the code"),
    ):
        if token not in engine_text:
            errors.append(message)
    transport_bodies = [
        node
        for node in ast.walk(engine_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"read_from_device", "_exec_read", "_pty_read", "_pty_body"}
    ]
    literals = {
        inner.value
        for node in transport_bodies
        for inner in ast.walk(node)
        if isinstance(inner, ast.Constant) and isinstance(inner.value, str)
    }
    if literals & {"exit", "quit", "config", "configure", "end", "save"}:
        errors.append("the read transport carries a literal that leaves the read boundary")

    wire_tests = {
        node.name
        for node in ast.walk(wire_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }
    required_tests = {
        "test_every_exec_platform_sends_its_preamble_and_the_catalog_command",
        "test_the_password_reaches_the_client_only_through_the_askpass_file",
        "test_a_key_reaches_the_client_only_as_a_private_file",
        "test_the_legacy_options_appear_only_with_the_enrolled_profile",
        "test_the_exec_client_is_given_no_configuration_file_of_the_host",
        "test_the_access_point_is_driven_on_a_terminal_and_the_login_never_leaks",
        "test_the_login_phase_of_the_access_point_stays_out_of_error_and_audit",
    }
    missing_tests = sorted(required_tests - wire_tests)
    if missing_tests:
        errors.append("wire-safety test is missing: " + ", ".join(missing_tests))
    required_tokens = (
        "engine.ssh_read",
        "engine._SSH_TRANSPORTS",
        "\"-F\"",
        "/dev/null",
        "StrictHostKeyChecking=yes",
        "SSH_ASKPASS",
        "LEGACY_OPTIONS",
        "transcript",
        "FORBIDDEN_ON_THE_WIRE",
    )
    if any(token not in wire_text for token in required_tokens):
        errors.append("SSH wire-safety test does not inspect the real client call")
    return errors


def _privacy_errors(root: Path, files: list[Path]) -> list[str]:
    errors: list[str] = []
    forbidden_names = {
        "vault.json", "inventory.json", "egress-policy.json", "runner.json",
        "known_hosts", ".env",
    }
    private_markers = (
        re.compile(r"begin\s+private\s+key", re.IGNORECASE),
        re.compile(r"/workspace(?:/|$)", re.IGNORECASE),
        re.compile(r"/home/[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?(?:/|$)", re.IGNORECASE),
    )
    topology_markers = (
        re.compile(r"\brpi(?:[-_ ]?\d+)?[-_][a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\b", re.IGNORECASE),
        re.compile(r"\braspberry(?:\s+|[-_]+)pi\b", re.IGNORECASE),
        re.compile(r"\b(?:home|local|personal|private)[-_ ]+lab\b", re.IGNORECASE),
        re.compile(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?-(?:mcp|readonly)\b", re.IGNORECASE),
    )
    agent_vendor_path_markers = (
        re.compile(r"\bcodex\b", re.IGNORECASE),
        re.compile(r"\bopenai\b", re.IGNORECASE),
        re.compile(r"\bchatgpt\b", re.IGNORECASE),
        re.compile(r"\bclaude\b", re.IGNORECASE),
        re.compile(r"\banthropic\b", re.IGNORECASE),
    )
    agent_vendor_markers = (
        re.compile(r"(?<![-\w])codex(?![-\w])", re.IGNORECASE),
        re.compile(r"(?<![-\w])openai(?![-\w])", re.IGNORECASE),
        re.compile(r"(?<![-\w])chatgpt(?![-\w])", re.IGNORECASE),
        re.compile(r"(?<![-\w])claude(?![-\w])", re.IGNORECASE),
        re.compile(r"(?<![-\w])anthropic(?![-\w])", re.IGNORECASE),
    )
    private_ipv4 = re.compile(
        r"(?<![0-9])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})(?![0-9])"
    )
    hardcoded_trust_file = re.compile(
        r"/(?:usr/local/share/ca-certificates|etc/netops-helper/certs)/[^\s\"'`]+\.(?:crt|cer|pem)"
    )
    for path in files:
        relative = path.relative_to(root)
        if any(marker.search(relative.as_posix()) for marker in agent_vendor_path_markers):
            errors.append(f"agent-vendor-specific path in {relative}")
        if any(
            marker.search(relative.as_posix())
            for marker in (*private_markers, *topology_markers)
        ):
            errors.append(f"private marker in release path: {relative}")
        if path.name in forbidden_names:
            errors.append(f"private configuration included: {relative}")
        if path.suffix.lower() in {".crt", ".cer", ".key", ".p12", ".pfx", ".pem"}:
            errors.append(f"environment-specific key/certificate included: {relative}")
        if path.suffix.lower() in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8", errors="replace")
            for marker in (*private_markers, *topology_markers, *agent_vendor_markers):
                if marker.search(text):
                    errors.append(f"private marker in {relative}")
            if private_ipv4.search(text):
                errors.append(f"private IPv4 address in {relative}")
            errors.extend(_secret_and_network_marker_errors(relative.as_posix(), text))
            if hardcoded_trust_file.search(text):
                errors.append(f"hard-coded environment trust file in {relative}")

    for trust_directory in (root / "config/container/ca", root / "config/container/certs"):
        if trust_directory.exists():
            for trust_path in trust_directory.iterdir():
                if trust_path.is_file() and trust_path.name != ".gitkeep":
                    errors.append(
                        "environment-specific trust material present: "
                        f"{trust_path.relative_to(root)}"
                    )

    return errors


def _secret_and_network_marker_errors(relative: str, text: str) -> list[str]:
    errors: list[str] = []
    if any(marker.search(text) for marker in SECRET_MATERIAL_MARKERS):
        errors.append(f"credential-shaped material in {relative}")
    if not relative.startswith("tests/") and any(
        marker.search(text) for marker in PRIVATE_NETWORK_MARKERS
    ):
        errors.append(f"private network marker in {relative}")
    return errors
