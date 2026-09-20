#!/usr/bin/env python3
"""Explicit host-side installer for the generated iptables egress contract.

The reviewed Docker network has IPv6 explicitly disabled, so this installer
manages only the IPv4 DOCKER-USER path and rejects any missing, ambiguous, or
enabled Docker IPv6 state before changing the firewall. The single IPv4
iptables-restore COMMIT is atomic; later failures use a best-effort rollback of
only this tool's marked jump and private chain. The contract does not claim to
filter container-to-host traffic traversing INPUT.
"""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_egress_rules as checker
import generate_egress_rules as generator


LOCK_PATH = Path("/run/netops-helper-egress.lock")
MARKER_PREFIX = "netops-helper-egress:"
MARKER = re.compile(rf"{re.escape(MARKER_PREFIX)}[0-9a-f]{{64}}")
RunCallable = Callable[..., Any]


class EgressApplyError(RuntimeError):
    """Fail-closed apply error carrying only a non-sensitive public code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _run(
    runner: RunCallable,
    command: list[str],
    *,
    input_text: str | None = None,
    allow_failure: bool = False,
) -> tuple[int, str]:
    kwargs: dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "check": False,
        "timeout": 15,
        "text": True,
        "env": {"PATH": os.environ.get("PATH", "")},
    }
    if input_text is None:
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["input"] = input_text
    try:
        completed = runner(command, **kwargs)
    except (OSError, subprocess.SubprocessError) as exc:
        if allow_failure:
            return 127, ""
        raise EgressApplyError("host_command_failed") from exc
    returncode = getattr(completed, "returncode", None)
    stdout = getattr(completed, "stdout", "")
    if not isinstance(returncode, int) or not isinstance(stdout, str):
        raise EgressApplyError("host_command_failed")
    if returncode != 0 and not allow_failure:
        raise EgressApplyError("host_command_failed")
    return returncode, stdout


def load_bundle(path: Path) -> dict[str, Any]:
    try:
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise EgressApplyError("bundle_permissions")
        raw = path.read_text(encoding="utf-8")
        bundle = json.loads(raw)
    except EgressApplyError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EgressApplyError("bundle_invalid") from exc
    if not isinstance(bundle, dict):
        raise EgressApplyError("bundle_invalid")
    try:
        checker.validate_bundle(bundle)
    except checker.EgressCheckError as exc:
        raise EgressApplyError("bundle_invalid") from exc
    return bundle


def _inspect_host(bundle: dict[str, Any], runner: RunCallable) -> dict[str, Any]:
    manifest = bundle["manifest"]
    _, raw_network = _run(
        runner, ["docker", "network", "inspect", manifest["network_name"]],
    )
    try:
        networks = json.loads(raw_network)
        network = networks[0]
        driver = network["Driver"]
        bridge = (network.get("Options") or {}).get(
            "com.docker.network.bridge.name"
        )
        network_ipv6_enabled = network["EnableIPv6"]
        if not isinstance(network_ipv6_enabled, bool):
            raise TypeError("Docker EnableIPv6 must be boolean")
    except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
        raise EgressApplyError("network_invalid") from exc
    if (
        driver != "bridge"
        or bridge != manifest["bridge_name"]
        or manifest["network_name"] != generator.NETWORK_NAME
        or manifest["backend"] != generator.BACKEND
        or network_ipv6_enabled != manifest["network_ipv6_enabled"]
    ):
        raise EgressApplyError("network_invalid")
    _run(runner, ["ip", "link", "show", "dev", manifest["bridge_name"]])
    nft_status, nft_tables = _run(
        runner, ["nft", "list", "tables"], allow_failure=True,
    )
    if nft_status != 0:
        raise EgressApplyError("backend_indeterminate")
    if "docker-bridges" in nft_tables:
        raise EgressApplyError("native_nftables_unsupported")
    _, ipv4_save = _run(runner, ["iptables-save"])
    return {
        "backend": "iptables",
        "network_name": manifest["network_name"],
        "network_driver": driver,
        "network_bridge": bridge,
        "network_ipv6_enabled": network_ipv6_enabled,
        "bridge_names": [bridge],
        "ipv4_save": ipv4_save,
    }


def _chain_exists(save: str) -> bool:
    prefix = f":{generator.CHAIN_NAME} "
    return any(line.startswith(prefix) for line in save.splitlines())


def _rules(save: str, chain: str) -> list[str]:
    prefix = f"-A {chain} "
    return [line.strip() for line in save.splitlines() if line.strip().startswith(prefix)]


def _references(save: str) -> list[str]:
    pattern = re.compile(rf"(?:^| )-j {re.escape(generator.CHAIN_NAME)}(?: |$)")
    return [
        line.strip() for line in save.splitlines()
        if line.strip().startswith("-A ") and pattern.search(line.strip())
    ]


def _valid_owned_chain_rule(line: str) -> bool:
    drop = f"-A {generator.CHAIN_NAME} -j DROP"
    if line == drop:
        return True
    prefix = f"-A {generator.CHAIN_NAME} -d "
    if not line.startswith(prefix):
        return False
    parts = line.split()
    try:
        destination = parts[3]
        network = ipaddress.ip_network(destination, strict=False)
    except (IndexError, ValueError):
        return False
    if network.version != 4 or str(network) != destination:
        return False
    tcp_or_udp = re.fullmatch(
        rf'-A {re.escape(generator.CHAIN_NAME)} -d \S+ -p (tcp|udp) '
        rf'-m \1 --dport ([1-9][0-9]{{0,4}}|[1-9][0-9]{{0,4}}:[1-9][0-9]{{0,4}}) -j ACCEPT',
        line,
    )
    icmp = re.fullmatch(
        rf'-A {re.escape(generator.CHAIN_NAME)} -d \S+ -p icmp -m icmp '
        rf'--icmp-type 8 -j ACCEPT',
        line,
    )
    return tcp_or_udp is not None or icmp is not None


def _is_owned_jump(line: str) -> bool:
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        return False
    return (
        len(tokens) == 10
        and tokens[:4] == ["-A", "DOCKER-USER", "-i", generator.BRIDGE_NAME]
        and tokens[4:7] == ["-m", "comment", "--comment"]
        and MARKER.fullmatch(tokens[7]) is not None
        and tokens[8:] == ["-j", generator.CHAIN_NAME]
    )


def _has_exact_jump(line: str, source_chain: str, target_chain: str) -> bool:
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        return False
    jumps = [index for index, token in enumerate(tokens) if token == "-j"]
    return (
        len(tokens) >= 4
        and tokens[:2] == ["-A", source_chain]
        and len(jumps) == 1
        and tokens[-2:] == ["-j", target_chain]
    )


def snapshot_owned(save: str) -> dict[str, Any]:
    marker_lines = [
        line.strip() for line in save.splitlines() if MARKER_PREFIX in line
    ]
    if any(not _is_owned_jump(line) for line in marker_lines):
        raise EgressApplyError("foreign_marker_collision")
    docker_user = _rules(save, "DOCKER-USER")
    if not checker._has_forward_jump(save):
        raise EgressApplyError("docker_user_unreachable")
    if not any(line.startswith(":DOCKER-USER ") for line in save.splitlines()):
        raise EgressApplyError("docker_user_missing")
    exists = _chain_exists(save)
    chain_rules = _rules(save, generator.CHAIN_NAME)
    references = _references(save)
    if not exists:
        if chain_rules or references:
            raise EgressApplyError("foreign_chain_collision")
        return {"exists": False, "jump": None, "chain_rules": []}
    if (
        len(references) != 1
        or not _is_owned_jump(references[0])
        or not docker_user
        or docker_user[0] != references[0]
        or not chain_rules
        or chain_rules[-1] != f"-A {generator.CHAIN_NAME} -j DROP"
        or any(not _valid_owned_chain_rule(line) for line in chain_rules)
    ):
        raise EgressApplyError("foreign_chain_collision")
    return {"exists": True, "jump": references[0], "chain_rules": chain_rules}


def _delete_rule(rule: str) -> str:
    if not rule.startswith("-A "):
        raise EgressApplyError("ruleset_invalid")
    return "-D " + rule[3:]


def _insert_jump(rule: str) -> str:
    prefix = "-A DOCKER-USER "
    if not rule.startswith(prefix):
        raise EgressApplyError("ruleset_invalid")
    return "-I DOCKER-USER 1 " + rule[len(prefix):]


def build_apply_payload(
    snapshot: dict[str, Any], expected: dict[str, Any],
) -> str:
    commands = ["*filter"]
    if snapshot["exists"]:
        commands.append(_delete_rule(snapshot["jump"]))
    else:
        commands.append(f"-N {generator.CHAIN_NAME}")
    commands.append(f"-F {generator.CHAIN_NAME}")
    commands.append(_insert_jump(expected["jump_rule"]))
    commands.extend(expected["chain_rules"])
    commands.extend(["COMMIT", ""])
    return "\n".join(commands)


def build_rollback_payload(
    snapshot: dict[str, Any], expected: dict[str, Any],
) -> str:
    commands = [
        "*filter",
        _delete_rule(expected["jump_rule"]),
        f"-F {generator.CHAIN_NAME}",
    ]
    if snapshot["exists"]:
        commands.append(_insert_jump(snapshot["jump"]))
        commands.extend(snapshot["chain_rules"])
    else:
        commands.append(f"-X {generator.CHAIN_NAME}")
    commands.extend(["COMMIT", ""])
    return "\n".join(commands)


def _restore(
    runner: RunCallable, payload: str, *, allow_failure: bool = False,
) -> bool:
    command = ["iptables-restore", "--noflush", "--wait", "10"]
    status, _ = _run(
        runner, command, input_text=payload, allow_failure=allow_failure,
    )
    return status == 0


def _rollback(
    runner: RunCallable,
    committed: bool,
    snapshot: dict[str, Any],
    expected: dict[str, Any],
) -> bool:
    if not committed:
        return True
    payload = build_rollback_payload(snapshot, expected)
    return _restore(runner, payload, allow_failure=True)


def apply_bundle(bundle: dict[str, Any], runner: RunCallable = subprocess.run) -> None:
    try:
        checker.validate_bundle(bundle)
    except checker.EgressCheckError as exc:
        raise EgressApplyError("bundle_invalid") from exc
    observed = _inspect_host(bundle, runner)
    ruleset = bundle["ruleset"]
    snapshot = snapshot_owned(observed["ipv4_save"])
    committed = False
    try:
        payload = build_apply_payload(snapshot, ruleset["ipv4"])
        _restore(runner, payload)
        committed = True
        after = _inspect_host(bundle, runner)
        errors = checker.check(bundle, after)
        if errors:
            raise EgressApplyError("post_check_failed")
    except EgressApplyError as exc:
        rollback_ok = _rollback(
            runner, committed, snapshot, ruleset["ipv4"],
        )
        if not rollback_ok:
            raise EgressApplyError("rollback_failed") from exc
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Explicitly install a reviewed NetOps Helper egress bundle.",
    )
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    arguments = parser.parse_args()
    if not arguments.apply:
        print("egress_apply=failed code=explicit_apply_required", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("egress_apply=failed code=root_required", file=sys.stderr)
        return 2
    try:
        lock_fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise EgressApplyError("apply_locked") from exc
        bundle = load_bundle(arguments.bundle.resolve(strict=True))
        apply_bundle(bundle)
    except (EgressApplyError, OSError) as exc:
        code = exc.code if isinstance(exc, EgressApplyError) else "host_command_failed"
        print(f"egress_apply=failed code={code}", file=sys.stderr)
        return 1
    finally:
        if "lock_fd" in locals():
            os.close(lock_fd)
    print("egress_apply=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
