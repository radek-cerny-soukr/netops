#!/usr/bin/env python3
"""Broken-input matrix over every parser and every input of the helper.

The proxy's four operator files (inventory, vault, egress policy, runner), the JSON-RPC lines of
the client and of the server, the ephemeral authentication context, the FTPS pin file, the
operator preflight, the egress generator, checker and installer, and the parameters of every MCP
tool receive the same family of broken shapes: an empty file, binary bytes, invalid UTF-8, a byte
order mark, CRLF, CR, U+2028 and NUL line breaks, an extremely long line, deep nesting, duplicate
keys, wrong types, Unicode digits, missing and extra fields, a truncated document and, where the
input is a path, a symbolic link, a FIFO or a directory in place of a file. Each input is accepted
or refused with the documented error of its layer - a JSON-RPC error that is not `internal_error`,
the script's own error and exit code, the parser's own error class, a tool error raised from a
refusal - and it never ends in another exception and never hangs. The file runs under pytest and
as a dependency-free script; the MCP tool checks need FastMCP and are skipped without it.
"""

from __future__ import annotations

from base64 import urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor
import asyncio
import contextlib
import importlib.util
import json
import logging
import os
from pathlib import Path
import resource
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
for _source in (ROOT / "src", ROOT.parent / "netops-core" / "src"):
    if str(_source) not in sys.path:
        sys.path.insert(0, str(_source))

from netops_core.hostkey import fingerprint_of  # noqa: E402
from netops_helper import inventory as helper_inventory  # noqa: E402
from netops_helper.auth import AuthenticationContextError, TargetAuth  # noqa: E402

SOURCES = os.pathsep.join((str(ROOT / "src"), str(ROOT.parent / "netops-core" / "src")))
SECONDS = 60
DEPTH = 100000
LONG = 4 * 1024 * 1024
MEMORY = 2 * 1024 * 1024 * 1024
MAX_MESSAGE = 2000
DEVICE_PIN = "SHA256:" + "A" * 43
RUNNER_PIN = "SHA256:" + "B" * 43
SUPERSCRIPT = str.maketrans("0123456789", "\u2070\u00b9\u00b2\u00b3\u2074\u2075\u2076\u2077\u2078\u2079")
ARABIC_INDIC = str.maketrans("0123456789", "".join(chr(0x0660 + digit) for digit in range(10)))
FULLWIDTH = str.maketrans("0123456789", "".join(chr(0xFF10 + digit) for digit in range(10)))
WRONG = {
    "null": None,
    "true": True,
    "zero": 0,
    "negative": -1,
    "huge": 10 ** 30,
    "fraction": 1.5,
    "nan": float("nan"),
    "infinity": float("inf"),
    "empty-text": "",
    "blank-text": " \t",
    "text": "x",
    "superscript-digit": "\u00b2",
    "arabic-digit": "\u0663",
    "line-separator": "a\u2028b",
    "nul": "a\x00b",
    "lone-surrogate": "\ud800",
    "long-text": "x" * 100000,
    "long-digits": "9" * 5000,
    "list": [],
    "list-of-null": [None],
    "object": {},
    "object-of-null": {"x": None},
}


class Hang(BaseException):
    pass


def clean(failures):
    assert not failures, "\n".join("%s: %s" % item for item in sorted(failures.items()))


def bounded(call, seconds=SECONDS):
    def expire(signum, frame):
        raise Hang()

    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    with open("/proc/self/statm") as stream:
        used = int(stream.read().split()[0]) * resource.getpagesize()
    ceiling = used + MEMORY if hard == resource.RLIM_INFINITY else min(hard, used + MEMORY)
    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    resource.setrlimit(resource.RLIMIT_AS, (ceiling, hard))
    try:
        return call()
    finally:
        resource.setrlimit(resource.RLIMIT_AS, (soft, hard))
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def library(call, refusals):
    try:
        bounded(call)
    except refusals:
        return None
    except Hang:
        return "no answer within %d s" % SECONDS
    except Exception as error:
        return "%s: %s" % (type(error).__name__, str(error)[:300])
    return None


def byte_shapes(valid):
    data = valid.encode("utf-8")
    return {
        "empty": b"",
        "whitespace": b" \t\r\n\x0b\x0c",
        "binary": bytes(range(256)) * 64,
        "invalid-utf8": b"\xc3\x28" + data,
        "surrogate": b"\xed\xa0\x80" + data,
        "utf16": valid.encode("utf-16"),
        "bom": b"\xef\xbb\xbf" + data,
        "crlf": valid.replace("\n", "\r\n").encode("utf-8"),
        "cr": valid.replace("\n", "\r").encode("utf-8"),
        "line-separator": valid.replace("\n", "\u2028").encode("utf-8"),
        "paragraph-separator": valid.replace("\n", "\u2029\n").encode("utf-8"),
        "next-line": valid.replace("\n", "\x85\n").encode("utf-8"),
        "nul": valid.replace("\n", "\x00\n").encode("utf-8"),
        "long-line": b"x" * LONG + b"\n" + data,
        "long-tail": data + b"y" * LONG,
        "truncated": data[: len(data) // 2],
        "truncated-character": data + "\u017e".encode("utf-8")[:1],
        "superscript-digits": valid.translate(SUPERSCRIPT).encode("utf-8"),
        "arabic-digits": valid.translate(ARABIC_INDIC).encode("utf-8"),
        "fullwidth-digits": valid.translate(FULLWIDTH).encode("utf-8"),
        "deep-list": b"[" * DEPTH + b"]" * DEPTH,
        "deep-object": b'{"a":' * DEPTH + b"1" + b"}" * DEPTH,
        "repeated": data * 50,
    }


_DELETE = object()
LONG_NUMBER = "long-number-placeholder"


def _paths(value, prefix=()):
    yield prefix, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _paths(item, prefix + (key,))
    elif isinstance(value, list) and value:
        yield from _paths(value[0], prefix + (0,))


def _replaced(document, path, change):
    copy = json.loads(json.dumps(document))
    if not path:
        return change(copy)
    parent = copy
    for step in path[:-1]:
        parent = parent[step]
    result = change(parent[path[-1]])
    if result is _DELETE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = result
    return copy


def _duplicated(value, target, path=()):
    if isinstance(value, dict):
        pairs = ["%s:%s" % (json.dumps(key), _duplicated(item, target, path + (key,))) for key, item in value.items()]
        if path == target and pairs:
            pairs.insert(0, pairs[0])
        return "{%s}" % ",".join(pairs)
    if isinstance(value, list):
        items = [_duplicated(item, target, path + (index,)) if index == 0 else json.dumps(item)
                 for index, item in enumerate(value)]
        return "[%s]" % ",".join(items)
    return json.dumps(value)


def json_shapes(document):
    shapes = {"root=%s" % name: json.dumps(value) for name, value in WRONG.items()}
    shapes["root=list-of-document"] = json.dumps([document])
    for path, value in _paths(document):
        where = "/".join(str(step) for step in path) or "root"
        if path:
            for name, wrong in WRONG.items():
                shapes["%s=%s" % (where, name)] = json.dumps(_replaced(document, path, lambda _, wrong=wrong: wrong))
            shapes["%s=long-number" % where] = json.dumps(
                _replaced(document, path, lambda _: LONG_NUMBER)).replace(json.dumps(LONG_NUMBER), "9" * 5000)
            if isinstance(path[-1], str):
                shapes["%s:missing" % where] = json.dumps(_replaced(document, path, lambda _: _DELETE))
        if isinstance(value, dict):
            shapes["%s:extra-field" % where] = json.dumps(
                _replaced(document, path, lambda item: dict(item, unexpected_field=1)) if path
                else dict(document, unexpected_field=1))
            if value:
                shapes["%s:duplicate-key" % where] = _duplicated(document, path)
        if isinstance(value, list):
            shapes["%s:empty-list" % where] = json.dumps(_replaced(document, path, lambda _: []) if path else [])
            shapes["%s:many-items" % where] = json.dumps(
                _replaced(document, path, lambda item: item * 2000) if path else document)
    return shapes


def all_shapes(document):
    shapes = {name: text.encode("utf-8") for name, text in json_shapes(document).items()}
    shapes.update(byte_shapes(json.dumps(document, indent=1)))
    return shapes


def path_shapes(directory, valid, mode=0o644):
    root = Path(tempfile.mkdtemp(prefix="paths-", dir=str(directory)))
    target = root / "valid"
    target.write_bytes(valid)
    target.chmod(mode)
    folder = root / "directory"
    folder.mkdir()
    fifo = root / "fifo"
    os.mkfifo(fifo, mode)
    links = {
        "symlink": target,
        "symlink-dangling": root / "nowhere",
        "symlink-fifo": fifo,
        "symlink-directory": folder,
    }
    for name, destination in links.items():
        (root / name).symlink_to(destination)
    (root / "symlink-loop").symlink_to(root / "symlink-loop")
    shapes = {name: root / name for name in links}
    shapes.update({
        "missing": root / "missing",
        "directory": folder,
        "fifo": fifo,
        "symlink-loop": root / "symlink-loop",
        "below-a-file": target / "child",
        "device-null": Path(os.devnull),
        "device-zero": Path("/dev/zero"),
        "name-too-long": root / ("x" * 5000),
    })
    return {name: str(path) for name, path in shapes.items()}


def _write(path: Path, data, mode: int | None = None) -> Path:
    if path.is_symlink() or path.exists():
        if path.is_dir() and not path.is_symlink():
            path.rmdir()
        else:
            path.unlink()
    path.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode("utf-8"))
    if mode is not None:
        path.chmod(mode)
    return path


def _egress() -> dict:
    return {
        "addresses": ["192.0.2.10"],
        "tcp_ports": [21, 444],
        "udp_ports": [161],
        "tcp_port_ranges": [[8000, 8010]],
        "udp_port_ranges": [[5000, 5010]],
        "allow_icmp": False,
        "allow_dns": False,
        "tls_server_names": ["alternate.example"],
    }


def _section() -> dict:
    return {
        "account_role": "read-only",
        "ssh_platform": "fortios",
        "enabled_queries": ["system_status"],
        "read_inventory": {"interfaces": [], "services": [], "addresses": ["192.0.2.20"], "switches": ["sw1"]},
        "sftp_roots": ["/safe"],
        "fortios_output_standard_verified": True,
        "snmp_credential": "device-a-community",
        "rate_limit": {"requests": 30, "window_seconds": 60},
        "egress": _egress(),
    }


def inventory_document() -> dict:
    return {"version": 2, "devices": [{
        "name": "device-a",
        "platform": "fortios",
        "address": "192.0.2.10",
        "port": 22,
        "role": "interni",
        "credential": "device-a-account",
        "host_key_fingerprint": DEVICE_PIN,
        "legacy_ssh": None,
        "auditor": None,
        "helper": _section(),
    }]}


def egress_policy_document() -> dict:
    return {
        "schema_version": 1,
        "profile": "strict-target",
        "backend": "iptables",
        "bridge_name": "nh-egress0",
        "network_name": "netops-helper",
        "ipv6_mode": "deny",
        "dns_resolvers": ["192.0.2.53"],
        "lan_cidrs": [],
    }


def runner_document() -> dict:
    return {
        "version": 1,
        "host": "runner.example.invalid",
        "port": 22,
        "credential": "runner-account",
        "host_key_fingerprint": RUNNER_PIN,
    }


def vault_document() -> dict:
    return {"version": 2, "credentials": {
        "runner-account": {"kind": "password", "login": "runner-user", "value": "runner-password"},
        "device-a-account": {"kind": "password", "login": "reader", "value": "ssh-password"},
        "device-a-community": {"kind": "snmp-community", "value": "snmp-community-value"},
    }}


GLOBALS = {"inventory": "INVENTORY", "vault": "VAULT", "egress-policy": "EGRESS_POLICY", "runner": "RUNNER"}
DOCUMENTS = {
    "inventory": (inventory_document, None),
    "vault": (vault_document, 0o600),
    "egress-policy": (egress_policy_document, None),
    "runner": (runner_document, None),
}


def _configured(directory: Path) -> dict:
    files = {}
    for name, (document, mode) in DOCUMENTS.items():
        files[name] = _write(directory / ("%s.json" % name), document(), mode)
    return files


def _load(path: Path, name: str):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    assert specification.loader is not None
    specification.loader.exec_module(module)
    return module


def _proxy_module(files: dict):
    module = _load(ROOT / "src" / "netops_helper" / "proxy.py", "netops_helper.proxy")
    module.INVENTORY = files["inventory"]
    module.VAULT = files["vault"]
    module.EGRESS_POLICY = files["egress-policy"]
    module.RUNNER = files["runner"]
    return module


def _call(identifier, tool: str, arguments) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0", "id": identifier, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }).encode("utf-8")


REQUESTS = (
    ("ssh_read", {"target": "device-a", "platform": "fortinet", "query": "system_status"}),
    ("tcp_probe", {"target": "device-a", "port": 444}),
    ("snmp_get", {"target": "device-a", "oids": ["1.3.6.1.2.1.1.1.0"]}),
    ("sftp_stat", {"target": "device-a", "remote_path": "/safe/file"}),
    ("helper_status", {}),
)


def _proxy_outcome(proxy, raw: bytes):
    emitted = []
    proxy._emit = emitted.append
    found = library(lambda: proxy.request(raw), ())
    if found:
        return found
    for message in emitted:
        if not isinstance(message, dict):
            return "emitted %r" % type(message).__name__
        category = ((message.get("error") or {}).get("data") or {}).get("category")
        if category == "internal_error":
            return "internal_error: an unexpected exception was swallowed"
        try:
            json.dumps(message, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError) as error:
            return "the emitted message cannot be written: %s" % error
    return None


def test_proxy_refuses_every_broken_operator_file() -> None:
    failures = {}
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        files = _configured(directory)
        module = _proxy_module(files)
        for name, (document, mode) in DOCUMENTS.items():
            shapes = {key: ("bytes", data) for key, data in all_shapes(document()).items()}
            valid = json.dumps(document()).encode("utf-8")
            shapes.update({"path " + key: ("path", path) for key, path in
                           path_shapes(directory, valid, mode or 0o644).items()})
            for label, (kind, value) in shapes.items():
                if kind == "bytes":
                    _write(files[name], value, mode)
                    setattr(module, GLOBALS[name], files[name])
                else:
                    setattr(module, GLOBALS[name], Path(value))
                if name == "runner":
                    found = library(lambda: module.Proxy()._load_runner(), module.RunnerFileError)
                else:
                    found = None
                    for tool, arguments in REQUESTS:
                        found = found or _proxy_outcome(module.Proxy(), _call(1, tool, arguments))
                    found = found or library(lambda: module.Proxy()._helper_status_payload(), module.ProxyError)
                if found:
                    failures["%s %s" % (name, label)] = found
            _write(files[name], document(), mode)
            setattr(module, GLOBALS[name], files[name])
    clean(failures)


def _launch(argv, environment, cwd=ROOT):
    def limited():
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY, MEMORY))

    try:
        done = subprocess.run(
            [sys.executable, "-B", *argv], stdin=subprocess.DEVNULL, capture_output=True,
            timeout=SECONDS, env=environment, cwd=str(cwd), preexec_fn=limited,
        )
    except subprocess.TimeoutExpired:
        return None, "", ""
    return done.returncode, done.stdout.decode("utf-8", "replace"), done.stderr.decode("utf-8", "replace")


def _verdict(result, codes):
    code, out, err = result
    if code is None:
        return "no answer within %d s" % SECONDS
    if "Traceback" in out or "Traceback" in err:
        return "traceback: %s" % (err.strip().splitlines() or ["?"])[-1][:300]
    if code not in codes:
        return "exit code %r outside %s" % (code, sorted(codes))
    if code and not err.strip():
        return "refused without a message"
    return None


def _matrix(cases, codes):
    with ThreadPoolExecutor(max_workers=max(2, os.cpu_count() or 2)) as pool:
        results = list(pool.map(lambda item: _launch(*item), cases.values()))
    return {name: found for name, result in zip(cases, results) if (found := _verdict(result, codes))}


def _environment(home: Path, **variables) -> dict:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "config"), "PYTHONPATH": SOURCES,
    }
    environment.update(variables)
    return environment


def test_proxy_start_refuses_a_broken_runner_file_without_a_traceback() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        files = _configured(directory)
        cases = {}
        shapes = byte_shapes(json.dumps(runner_document(), indent=1))
        for index, (name, data) in enumerate(shapes.items()):
            runner = _write(directory / ("runner-%d.json" % index), data)
            cases[name] = (["-m", "netops_helper.proxy"], _environment(
                directory, NETOPS_INVENTORY_PATH=str(files["inventory"]),
                NETOPS_VAULT_PATH=str(directory / "missing-vault.json"),
                NETOPS_EGRESS_POLICY_PATH=str(files["egress-policy"]), NETOPS_RUNNER_PATH=str(runner)))
        for name, path in path_shapes(directory, json.dumps(runner_document()).encode("utf-8")).items():
            cases["path " + name] = (["-m", "netops_helper.proxy"], _environment(
                directory, NETOPS_INVENTORY_PATH=str(files["inventory"]),
                NETOPS_VAULT_PATH=str(directory / "missing-vault.json"),
                NETOPS_EGRESS_POLICY_PATH=str(files["egress-policy"]), NETOPS_RUNNER_PATH=path))
        clean(_matrix(cases, {2}))


def test_proxy_answers_every_broken_client_line() -> None:
    failures = {}
    with tempfile.TemporaryDirectory() as temporary:
        module = _proxy_module(_configured(Path(temporary)))
        for tool, arguments in REQUESTS:
            document = json.loads(_call(7, tool, arguments))
            shapes = all_shapes(document)
            shapes.update({
                "batch": json.dumps([document, document]).encode("utf-8"),
                "empty-batch": b"[]",
                "notification": json.dumps({key: value for key, value in document.items() if key != "id"}).encode(),
            })
            for name, raw in shapes.items():
                found = _proxy_outcome(module.Proxy(), raw)
                if found:
                    failures["%s %s" % (tool, name)] = found
        for method in ("initialize", "tools/list", "ping", "resources/list", "notifications/initialized"):
            document = {"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}
            for name, raw in all_shapes(document).items():
                found = _proxy_outcome(module.Proxy(), raw)
                if found:
                    failures["%s %s" % (method, name)] = found
    clean(failures)


def test_proxy_answers_every_broken_server_line() -> None:
    failures = {}
    with tempfile.TemporaryDirectory() as temporary:
        module = _proxy_module(_configured(Path(temporary)))
        tool, arguments = REQUESTS[0]
        answer = {"jsonrpc": "2.0", "id": 7, "result": {
            "content": [{"type": "text", "text": json.dumps({"ok": True, "untrusted_device_output": "x"})}],
            "structuredContent": {"ok": True, "untrusted_device_output": "x"}, "isError": False}}
        shapes = all_shapes(answer)
        shapes.update({
            "error": json.dumps({"jsonrpc": "2.0", "id": 7, "error": {"code": -1, "message": "x"}}).encode(),
            "batch": json.dumps([answer, answer]).encode(),
            "server-request": json.dumps({"jsonrpc": "2.0", "id": 9, "method": "sampling/createMessage"}).encode(),
        })
        for name, raw in shapes.items():
            proxy = module.Proxy()
            proxy._emit = lambda message: None
            if library(lambda: proxy.request(_call(7, tool, arguments)), ()) is not None:
                failures["setup"] = "the valid request was not forwarded"
                break
            found = library(lambda: proxy.response(raw), ())
            if found:
                failures[name] = found
    clean(failures)


def _context(document) -> str:
    return urlsafe_b64encode(json.dumps(document).encode("utf-8")).decode("ascii").rstrip("=")


def context_document() -> dict:
    return {
        "alias": "device-a",
        "host": "192.0.2.10",
        "port": 22,
        "login": "operator",
        "credential_kind": "password",
        "secret": "ssh-secret-value",
        "host_key_fingerprint": fingerprint_of(urlsafe_b64encode(b"host-key").decode("ascii")),
        "account_role": "read-only",
        "read_inventory": {"interfaces": ["port3"]},
        "ssh_platform": "fortios",
        "enabled_queries": ["interface_details"],
        "sftp_roots": ["/safe"],
        "snmp_community": "community-value",
        "egress": {
            "addresses": ["192.0.2.10"], "tcp_ports": [], "udp_ports": [], "tcp_port_ranges": [],
            "udp_port_ranges": [], "allow_icmp": False, "allow_dns": False, "tls_server_names": [],
        },
    }


def test_authentication_context_refuses_every_broken_envelope() -> None:
    TargetAuth.decode("device-a", _context(context_document()))
    failures = {}
    contexts = {name: urlsafe_b64encode(data).decode("ascii") for name, data in all_shapes(context_document()).items()}
    contexts.update({"raw " + name: value for name, value in WRONG.items() if isinstance(value, str)})
    contexts.update({"not-base64": "!!!", "padding-only": "====", "non-ascii": "\u00e9" * 8})
    for name, context in contexts.items():
        found = library(lambda: TargetAuth.decode("device-a", context), AuthenticationContextError)
        if found:
            failures[name] = found
    for name, value in WRONG.items():
        found = library(lambda: TargetAuth.decode(value, _context(context_document())), AuthenticationContextError)
        if found:
            failures["alias " + name] = found
        found = library(lambda: TargetAuth.decode("device-a", value), AuthenticationContextError)
        if found:
            failures["context object " + name] = found
    clean(failures)


def test_helper_inventory_and_egress_policy_raise_only_inventory_errors() -> None:
    failures = {}
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        for name, data in all_shapes(inventory_document()).items():
            path = _write(directory / "inventory.json", data)
            found = library(lambda: [helper_inventory.section(entry) for entry in
                                     helper_inventory.devices(helper_inventory.load(path))],
                            helper_inventory.InventoryError)
            if found:
                failures["inventory " + name] = found
        for name, text in json_shapes(egress_policy_document()).items():
            try:
                document = json.loads(text)
            except ValueError:
                continue
            found = library(lambda: helper_inventory.egress_policy(document), helper_inventory.InventoryError)
            if found:
                failures["egress policy " + name] = found
    clean(failures)


def _script(name: str):
    return _load(ROOT / "scripts" / ("%s.py" % name), "_malformed_%s" % name)


def test_operator_preflight_refuses_every_broken_file() -> None:
    preflight = _script("check_operator_config")
    failures = {}
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        files = _configured(directory)
        paths = {"%s.json" % name: path for name, path in files.items()}
        assert preflight.check(paths)["devices"] == 1
        cases = {}
        for name, (document, mode) in DOCUMENTS.items():
            for label, data in all_shapes(document()).items():
                _write(files[name], data, mode)
                found = library(lambda: preflight.check(paths), preflight.PreflightError)
                if found:
                    failures["%s %s" % (name, label)] = found
            _write(files[name], document(), mode)
            valid = json.dumps(document()).encode("utf-8")
            for label, path in path_shapes(directory, valid, mode or 0o644).items():
                argv = [str(ROOT / "scripts" / "check_operator_config.py")]
                for other, location in files.items():
                    argv.extend(["--%s" % other, path if other == name else str(location)])
                cases["%s path %s" % (name, label)] = (argv, _environment(directory))
        failures.update(_matrix(cases, {0, 1}))
    clean(failures)


def test_egress_generator_checker_and_installer_refuse_every_broken_input() -> None:
    generator = _script("generate_egress_rules")
    checker = _script("check_egress_rules")
    installer = _script("apply_egress_rules")
    failures = {}
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        files = _configured(directory)
        output = directory / "bundle.json"
        generator.generate(files["inventory"], files["egress-policy"], output)
        bundle = json.loads(output.read_text(encoding="utf-8"))
        checker.validate_bundle(bundle)
        refusals = (generator.EgressContractError, OSError)
        for name, (document, label) in {"egress-policy": (egress_policy_document, "policy"),
                                       "inventory": (inventory_document, "inventory")}.items():
            for shape, data in all_shapes(document()).items():
                _write(files[name], data)
                found = library(lambda: generator.generate(files["inventory"], files["egress-policy"],
                                                           directory / "out.json"), refusals)
                if found:
                    failures["generate %s %s" % (label, shape)] = found
            _write(files[name], document())
        for shape, data in all_shapes(bundle).items():
            path = _write(directory / "candidate.json", data, 0o600)
            found = library(lambda: checker.validate_bundle(checker._read_json(path, require_mode_600=True)),
                            checker.EgressCheckError)
            if found:
                failures["check " + shape] = found
            found = library(lambda: installer.load_bundle(path), installer.EgressApplyError)
            if found:
                failures["apply " + shape] = found
        cases = {}
        script = str(ROOT / "scripts" / "generate_egress_rules.py")
        for label, path in path_shapes(directory, files["egress-policy"].read_bytes()).items():
            cases["generate policy " + label] = ([script, "--inventory", str(files["inventory"]), "--policy", path,
                                                  "--output", str(directory / "cli-out.json")], _environment(directory))
            cases["generate output " + label] = ([script, "--inventory", str(files["inventory"]), "--policy",
                                                  str(files["egress-policy"]), "--output", path],
                                                 _environment(directory))
        failures.update(_matrix(cases, {0, 2}))
        for label, path in path_shapes(directory, output.read_bytes(), 0o600).items():
            target = Path(path)
            found = library(lambda: checker.validate_bundle(checker._read_json(target, require_mode_600=True)),
                            checker.EgressCheckError)
            if found:
                failures["check path " + label] = found
            found = library(lambda: installer.load_bundle(target), installer.EgressApplyError)
            if found:
                failures["apply path " + label] = found
    clean(failures)


def _duplicates(document) -> dict:
    return {"/".join(str(step) for step in path) or "root": _duplicated(document, path).encode("utf-8")
            for path, value in _paths(document) if isinstance(value, dict) and value}


def test_every_operator_input_refuses_a_repeated_key() -> None:
    failures = {}

    def refused(label, call, refusals):
        try:
            call()
        except refusals:
            return
        except Exception as error:
            failures[label] = "%s: %s" % (type(error).__name__, str(error)[:200])
            return
        failures[label] = "a key repeated within one JSON object was accepted"

    TargetAuth.decode("device-a", _context(context_document()))
    for where, data in _duplicates(context_document()).items():
        context = urlsafe_b64encode(data).decode("ascii")
        refused("envelope " + where, lambda: TargetAuth.decode("device-a", context), AuthenticationContextError)
    preflight = _script("check_operator_config")
    generator = _script("generate_egress_rules")
    checker = _script("check_egress_rules")
    installer = _script("apply_egress_rules")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        files = _configured(directory)
        paths = {"%s.json" % name: path for name, path in files.items()}
        proxy = _proxy_module(files)
        output = directory / "bundle.json"
        generator.generate(files["inventory"], files["egress-policy"], output)
        bundle = json.loads(output.read_text(encoding="utf-8"))
        assert preflight.check(paths)["devices"] == 1
        proxy.Proxy()._load_runner()
        proxy.Proxy()._load_egress_policy()
        for name, (document, mode) in DOCUMENTS.items():
            for where, data in _duplicates(document()).items():
                _write(files[name], data, mode)
                refused("preflight %s %s" % (name, where), lambda: preflight.check(paths), preflight.PreflightError)
                if name == "runner":
                    refused("proxy runner " + where, lambda: proxy.Proxy()._load_runner(), proxy.RunnerFileError)
                if name == "egress-policy":
                    refused("proxy egress policy " + where, lambda: proxy.Proxy()._load_egress_policy(),
                            proxy.PolicySchemaError)
                    refused("generator egress policy " + where,
                            lambda: generator.generate(files["inventory"], files["egress-policy"],
                                                       directory / "out.json"),
                            generator.EgressContractError)
            _write(files[name], document(), mode)
        candidate = _write(directory / "candidate.json", output.read_bytes(), 0o600)
        installer.load_bundle(candidate)
        for where, data in _duplicates(bundle).items():
            candidate = _write(directory / "candidate.json", data, 0o600)
            refused("checker bundle " + where, lambda: checker._read_json(candidate, require_mode_600=True),
                    checker.EgressCheckError)
            refused("installer bundle " + where, lambda: installer.load_bundle(candidate), installer.EgressApplyError)
    if _runtime_available():
        from netops_helper import engine

        original = engine.TLS_PINS_PATH
        try:
            with tempfile.TemporaryDirectory() as temporary:
                document = {"other-device": {"sha256": "0" * 64, "certificate": "/nonexistent.crt"}}
                engine.TLS_PINS_PATH = _write(Path(temporary) / "pins.json", document)
                engine._ftps_context("device-a")
                for where, data in _duplicates(document).items():
                    engine.TLS_PINS_PATH = _write(Path(temporary) / "pins.json", data)
                    refused("tls pins " + where, lambda: engine._ftps_context("device-a"), engine.FtpsPinError)
        finally:
            engine.TLS_PINS_PATH = original
    clean(failures)


def _runtime_available() -> bool:
    return all(importlib.util.find_spec(name) is not None for name in ("fastmcp", "icmplib"))


def test_ftps_pin_file_refuses_every_broken_shape() -> None:
    if not _runtime_available():
        return
    from netops_helper import engine

    failures = {}
    original = engine.TLS_PINS_PATH
    try:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            document = {"device-a": {"sha256": "0" * 64, "certificate": str(engine.TLS_CERT_DIR / "pinned.crt")}}
            shapes = {name: ("bytes", data) for name, data in all_shapes(document).items()}
            shapes.update({"path " + name: ("path", path) for name, path in
                           path_shapes(directory, json.dumps(document).encode("utf-8")).items()})
            for name, (kind, value) in shapes.items():
                engine.TLS_PINS_PATH = _write(directory / "pins.json", value) if kind == "bytes" else Path(value)
                found = library(lambda: engine._ftps_context("device-a"), engine.FtpsPinError)
                if found:
                    failures[name] = found
    finally:
        engine.TLS_PINS_PATH = original
    clean(failures)


class _Traced(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[str] = []

    def emit(self, record) -> None:
        if record.exc_info:
            self.records.append(record.getMessage()[:200])


TOOL_CALLS = {
    "helper_status": {},
    "read_query_catalog": {},
    "dns_probe": {"target": "device-a"},
    "tcp_probe": {"target": "device-a", "port": 444, "timeout": 1.0},
    "icmp_probe": {"target": "device-a", "count": 1},
    "tls_probe": {"target": "device-a", "port": 444, "server_name": "alternate.example"},
    "ssh_read": {"target": "device-a", "platform": "fortinet", "query": "interface_details",
                 "parameters": {"interface": "port3"}, "offset": 0, "max_bytes": 16000},
    "snmp_get": {"target": "device-a", "oids": ["1.3.6.1.2.1.1.1.0"], "port": 161},
    "sftp_stat": {"target": "device-a", "remote_path": "/safe/file"},
    "ftp_list": {"target": "device-a", "remote_path": "/safe", "use_tls": True, "port": 21},
}


def _refusal(error) -> bool:
    return isinstance(error, ValueError)


def _tool_outcome(server, tool, arguments, traced):
    from fastmcp.exceptions import ToolError, ValidationError

    del traced.records[:]
    try:
        bounded(lambda: asyncio.run(server.mcp.call_tool(tool, arguments)))
    except ValidationError:
        return None
    except ToolError as error:
        cause = error.__cause__
        if cause is not None and not _refusal(cause):
            return "unexpected %s: %s" % (type(cause).__name__, str(cause)[:300])
        if len(str(error)) > MAX_MESSAGE:
            return "a refusal of %d characters repeats the input" % len(str(error))
        if cause is not None and str(error) != str(cause):
            return "the refusal %r is not the message of the server, %r" % (str(error)[:120], str(cause)[:120])
        if traced.records:
            return "the server logged a traceback: %s" % traced.records[0]
        return None
    except Hang:
        return "no answer within %d s" % SECONDS
    except Exception as error:
        return "%s: %s" % (type(error).__name__, str(error)[:300])
    return None


@contextlib.contextmanager
def _offline():
    from netops_helper import engine

    def refusing(error):
        def refused(*args, **keywords):
            raise error("the test never reaches a device")
        return refused

    replaced = (
        (socket, "create_connection", refusing(ConnectionRefusedError)),
        (engine, "ping", refusing(ConnectionRefusedError)),
        (engine.core_ssh, "run_command", refusing(engine.core_ssh.SshError)),
        (engine.core_sftp, "stat", refusing(engine.core_sftp.SftpError)),
        (engine.core_hostkey, "scan", refusing(engine.core_hostkey.HostKeyError)),
        (engine.core_session, "Session", refusing(engine.core_session.SessionError)),
        (engine, "TLS_PINS_PATH", Path(tempfile.gettempdir()) / "netops-helper-test-absent-pins.json"),
    )
    saved = [(owner, name, getattr(owner, name)) for owner, name, _ in replaced]
    for owner, name, value in replaced:
        setattr(owner, name, value)
    try:
        yield
    finally:
        for owner, name, value in saved:
            setattr(owner, name, value)


def test_every_mcp_tool_answers_broken_parameters_with_a_tool_error() -> None:
    if not _runtime_available():
        return
    from netops_helper import engine, server

    handler = _Traced()
    logger = logging.getLogger("fastmcp")
    levels = [(item, item.level) for item in logger.handlers]
    for item, _ in levels:
        item.setLevel(logging.CRITICAL + 1)
    logger.addHandler(handler)
    recorded = engine.record
    engine.record = lambda *args, **keywords: None
    failures = {}
    try:
        with _offline():
            context = _context(context_document())
            for tool, base in TOOL_CALLS.items():
                arguments = dict(base, auth_context=context) if base else {}
                variants = {"base": arguments, "extra argument": dict(arguments, unexpected_argument=1)}
                for name in arguments:
                    for label, value in WRONG.items():
                        variants["%s=%s" % (name, label)] = dict(arguments, **{name: value})
                    variants["%s missing" % name] = {key: item for key, item in arguments.items() if key != name}
                for label, variant in variants.items():
                    found = _tool_outcome(server, tool, variant, handler)
                    if found:
                        failures["%s %s" % (tool, label)] = found
    finally:
        engine.record = recorded
        logger.removeHandler(handler)
        for item, level in levels:
            item.setLevel(level)
    clean(failures)


REFUSED_CALLS = {
    2: ("tcp_probe", {"target": "device-a", "port": 444, "auth_context": "x"},
        "invalid ephemeral authentication context"),
    3: ("ssh_read", {"target": "device-b", "platform": "fortinet", "query": "interface_details",
                     "auth_context": None}, "target alias does not match authentication context"),
    4: ("dns_probe", {"target": "device-a", "auth_context": "{\"alias\":"}, "invalid ephemeral authentication context"),
}


def test_the_server_process_answers_a_refusal_without_a_traceback_in_its_log() -> None:
    if not _runtime_available():
        return
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join([SOURCES] + [item for item in sys.path if item])
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "malformed-inputs", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    for identifier, (tool, arguments, _message) in sorted(REFUSED_CALLS.items()):
        if arguments.get("auth_context") is None:
            arguments = dict(arguments, auth_context=_context(context_document()))
        messages.append({"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                         "params": {"name": tool, "arguments": arguments}})
    process = subprocess.Popen(
        [sys.executable, "-B", "-m", "netops_helper.server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=environment, cwd=str(ROOT),
    )
    answers = {}
    try:
        process.stdin.write(b"".join(json.dumps(message).encode("utf-8") + b"\n" for message in messages))
        process.stdin.flush()
        deadline = time.monotonic() + SECONDS
        while set(REFUSED_CALLS) - set(answers) and time.monotonic() < deadline:
            line = process.stdout.readline()
            if not line:
                break
            answer = json.loads(line)
            if answer.get("id") in REFUSED_CALLS:
                answers[answer["id"]] = answer
    finally:
        process.stdin.close()
        try:
            _out, log = process.communicate(timeout=SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            _out, log = process.communicate()
    failures = {}
    text = log.decode("utf-8", "replace")
    if "Traceback" in text:
        failures["server log"] = "the log of the server holds a traceback: %s" % text.strip()[-600:]
    for identifier, (tool, _arguments, message) in REFUSED_CALLS.items():
        answer = answers.get(identifier)
        if answer is None:
            failures[tool] = "no answer"
            continue
        result = answer.get("result") or {}
        content = [item.get("text") for item in result.get("content") or []]
        if result.get("isError") is not True or content != [message]:
            failures[tool] = "answered %r" % (answer,)
    clean(failures)


def main() -> int:
    for name, function in sorted(globals().items()):
        if name.startswith("test_") and callable(function):
            function()
    print("malformed_input_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
