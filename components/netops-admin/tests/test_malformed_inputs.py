"""Broken-input matrix over every input of the admin.

Each input receives the same family of broken shapes: an empty file, binary bytes, invalid UTF-8, an
encoded surrogate, a byte order mark, CRLF, CR, U+2028 and NUL line breaks, extremely long lines and
numbers, deep nesting, duplicate keys, wrong types, Unicode digits, missing and extra fields, a
truncated document and, where the input is a path, a symbolic link, a FIFO, /dev/zero, a directory or
a NUL character in place of a file. The inputs are the configuration and the files it names, the port
policy, the request, the plan, the FortiOS and ExtremeXOS snapshots, the files of the state directory,
the answers of a device to the write and the check account, every command line argument, every MCP
tool argument and the inputs of scripts/export_status.py. The input is either accepted or refused with
a controlled error - a documented exit code with its reasons on the command line, a result with
bounded reasons or a ToolError on the MCP surface without a traceback in the server log - and it never
ends in a traceback and never hangs. A key repeated within one JSON object is refused in every JSON
input of the admin.
"""

import asyncio
import copy
import dataclasses
import importlib.util
import itertools
import json
import logging
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import FIXTURES, request_bytes
from enrollment_helpers import certify
from fake_exos import FIRMWARE, FakeExos
from fake_fortios import FakeFortiOS

from netops_admin import audit, cli, engine, execute, notify
from netops_admin import config as configuration
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

COMPONENT = Path(__file__).resolve().parents[1]
SOURCES = os.pathsep.join(str(path) for path in (
    COMPONENT / "src", COMPONENT.parent / "netops-auditor" / "src", COMPONENT.parent / "netops-core" / "src"))
SECONDS = 60
IN_PROCESS_SECONDS = 15
PLAN_CODES = frozenset((0, 2, 3))
VERIFY_CODES = frozenset((0, 1, 2, 3))
APPLY_CODES = frozenset((0, 2, 3, 4, 6))
PREVIEW_CODES = frozenset((0, 2, 3))
DOCTOR_CODES = frozenset((0, 2, 3, 5))
ENROLL_CODES = frozenset((0, 2, 3, 4))
RECOVER_CODES = frozenset((0, 2, 3, 6))
COMMAND_CODES = frozenset((0, 2, 3))
EXPORT_CODES = frozenset((0, 1, 2))
DEPTH = 100000
SHALLOW = 4000
LONG = 4 * 1024 * 1024
ANSWER_LONG = 256 * 1024
MEMORY = 2 * 1024 * 1024 * 1024
MAX_MESSAGE = 2000
PIN = "SHA256:" + "A" * 43
TOPIC = "NTFY_TOPIC=netops-test-topic\n"
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
STATE_WRONG = ("null", "true", "negative", "huge", "nan", "text", "lone-surrogate", "long-digits", "list", "object")
ODD_VALUES = (
    "", " ", "\u00b2", "\u0663", "-1", "0", "nan", "inf", "-inf", "1e309", "0x10", "1_000",
    "x" * 100000, "9" * 5000, "a\u2028b", "a\nb", "-", "--", "\ufeffx", "relative/../odd", "a\x00b",
)
ANSWER_SHAPES = ("empty", "binary", "invalid-utf8", "bom", "crlf", "cr", "line-separator", "nul", "long-line",
                 "truncated", "arabic-digits", "deep-list")


class Hang(BaseException):
    pass


def fortios_sample():
    return (FIXTURES / "fortios_8_0_0.conf").read_text(encoding="utf-8")


def exos_sample():
    return (FIXTURES / "exos_33_7_1.conf").read_text(encoding="utf-8")


SAMPLES = {"fortios": fortios_sample, "exos": exos_sample}


def byte_shapes(valid, long=LONG):
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
        "long-line": b"x" * long + b"\n" + data,
        "long-tail": data + b"y" * long,
        "long-number": b"9" * 5000,
        "truncated": data[: len(data) // 2],
        "truncated-character": data + "\u017e".encode("utf-8")[:1],
        "superscript-digits": valid.translate(SUPERSCRIPT).encode("utf-8"),
        "arabic-digits": valid.translate(ARABIC_INDIC).encode("utf-8"),
        "fullwidth-digits": valid.translate(FULLWIDTH).encode("utf-8"),
        "deep-list": b"[" * DEPTH + b"]" * DEPTH,
        "deep-object": b'{"a":' * DEPTH + b"1" + b"}" * DEPTH,
        "shallow-deep-list": b"[" * SHALLOW + b"]" * SHALLOW,
        "shallow-deep-object": b'{"a":' * SHALLOW + b"1" + b"}" * SHALLOW,
        "repeated": data * 50,
    }


def fortios_shapes(valid):
    return {
        "deep-blocks": "config a\n" * DEPTH + "end\n" * DEPTH,
        "deep-entries": "config firewall address\n" + "edit x\n" * DEPTH + "next\n" * DEPTH + "end\n",
        "end-outside": "end\n" + valid,
        "next-outside": "next\n" + valid,
        "unterminated-block": valid + "config firewall address\n    edit \"x\"\n",
        "unterminated-quote": valid + 'config system global\n    set hostname "fw\n',
        "lone-backslash": valid + 'config system global\n    set hostname "fw\\\nend\n',
        "set-without-name": valid + "config system global\n    set\nend\n",
        "edit-without-key": valid + "config firewall address\n    edit\n    next\nend\n",
        "config-without-name": valid + "config\nend\n",
        "repeated-entry": valid + 'config firewall address\n    edit "spare-host"\n        set comment "twice"\n    next\nend\n',
        "header-version-long": valid.replace("FW-build0167", "FW-build" + "9" * 5000, 1),
        "header-version-superscript": valid.replace("8.0.0", "\u00b8.0.0", 1),
        "header-missing": "\n".join(line for line in valid.splitlines() if not line.startswith("#")) + "\n",
        "many-values": valid + "config firewall address\n    edit \"spare-host\"\n        set comment " + "a " * 500000 + "\n    next\nend\n",
        "many-addresses": valid + "config firewall address\n" + "".join(
            '    edit "a%d"\n        set subnet 192.0.2.%d 255.255.255.255\n    next\n' % (n, n % 250)
            for n in range(20000)) + "end\n",
    }


def exos_shapes(valid):
    return {
        "port-superscript": valid + "configure vlan DATA add ports \u00b2 untagged\n",
        "port-arabic": valid + "configure vlan DATA add ports \u0661:\u0662 tagged\n",
        "port-range-reversed": valid + "configure vlan DATA add ports 9-1 tagged\n",
        "port-range-huge": valid + "configure vlan DATA add ports 1-" + "9" * 5000 + " tagged\n",
        "tag-huge": valid + "create vlan v2\nconfigure vlan v2 tag " + "9" * 5000 + "\n",
        "unterminated-quote": valid + 'configure snmp sysName "fw\n',
        "repeated-vlan": valid + 'create vlan "spare"\nconfigure vlan spare tag 3991\n',
        "module-header-long": "# Module " + "a" * LONG + " configuration.\n" + valid,
        "many-vlans": "".join("create vlan v%d\nconfigure vlan v%d tag %d\n" % (n, n, n % 4094 + 1) for n in range(20000)),
        "many-values": valid + "configure vlan DATA add ports " + "1," * 500000 + "1 tagged\n",
    }


PLATFORM_SHAPES = {"fortios": fortios_shapes, "exos": exos_shapes}


def text_shapes(platform):
    valid = SAMPLES[platform]()
    shapes = byte_shapes(valid)
    shapes.update({name: text.encode("utf-8") for name, text in PLATFORM_SHAPES[platform](valid).items()})
    return shapes


def _paths(value, prefix=()):
    yield prefix, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _paths(item, prefix + (key,))
    elif isinstance(value, list) and value:
        yield from _paths(value[0], prefix + (0,))


_DELETE = object()
LONG_NUMBER = "long-number-placeholder"


def _replaced(document, path, change):
    copied = json.loads(json.dumps(document))
    if not path:
        return change(copied)
    parent = copied
    for step in path[:-1]:
        parent = parent[step]
    result = change(parent[path[-1]])
    if result is _DELETE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = result
    return copied


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


def json_shapes(document, wrong=tuple(WRONG)):
    shapes = {"root=%s" % name: json.dumps(WRONG[name]) for name in wrong}
    shapes["root=list-of-document"] = json.dumps([document])
    for path, value in _paths(document):
        where = "/".join(str(step) for step in path) or "root"
        if path:
            for name in wrong:
                shapes["%s=%s" % (where, name)] = json.dumps(
                    _replaced(document, path, lambda _, item=WRONG[name]: item))
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


LINKS = ("symlink", "symlink-dangling", "symlink-fifo", "symlink-directory", "symlink-zero")


def path_shapes(directory, valid):
    root = Path(tempfile.mkdtemp(prefix="paths-", dir=str(directory)))
    target = root / "valid"
    target.write_bytes(valid)
    folder = root / "directory"
    folder.mkdir()
    fifo = root / "fifo"
    os.mkfifo(fifo)
    links = dict(zip(LINKS, (target, root / "nowhere", fifo, folder, Path("/dev/zero"))))
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
    })
    return {name: str(path) for name, path in shapes.items()}


def nul_path(directory):
    return str(directory) + "/valid\x00child"


def placed(path, shape, valid):
    path = Path(path)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    aside = path.with_name(path.name + ".aside")
    if aside.is_dir() and not aside.is_symlink():
        shutil.rmtree(aside)
    elif aside.exists() or aside.is_symlink():
        aside.unlink()
    if shape == "directory":
        path.mkdir()
    elif shape == "fifo":
        os.mkfifo(path)
    elif shape == "symlink":
        aside.write_bytes(valid)
        path.symlink_to(aside)
    elif shape == "symlink-dangling":
        path.symlink_to(aside)
    elif shape == "symlink-loop":
        path.symlink_to(path)
    elif shape == "symlink-fifo":
        os.mkfifo(aside)
        path.symlink_to(aside)
    elif shape == "symlink-directory":
        aside.mkdir()
        path.symlink_to(aside)
    elif shape == "symlink-zero":
        path.symlink_to("/dev/zero")
    elif shape == "symlink-null":
        path.symlink_to(os.devnull)
    elif shape != "missing":
        raise AssertionError(shape)


PLACED = ("directory", "fifo", "symlink", "symlink-dangling", "symlink-loop", "symlink-fifo", "symlink-directory",
          "symlink-zero", "symlink-null", "missing")


def _environment():
    environment = dict(os.environ)
    environment["PYTHONPATH"] = SOURCES
    return environment


def _limited():
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY, MEMORY))


def launch(argv, module="netops_admin", environment=None, script=None):
    command = [sys.executable, "-B", script] if script else [sys.executable, "-B", "-m", module]
    try:
        done = subprocess.run(
            [*command, *argv],
            stdin=subprocess.DEVNULL,
            preexec_fn=_limited,
            capture_output=True,
            timeout=SECONDS,
            env=_environment() if environment is None else environment,
            cwd=str(COMPONENT),
        )
    except subprocess.TimeoutExpired:
        return None, "", ""
    return done.returncode, done.stdout.decode("utf-8", "replace"), done.stderr.decode("utf-8", "replace")


def _refusal(out):
    try:
        document = json.loads(out)
    except ValueError:
        return "the refusal is not one JSON document"
    reasons = document.get("reasons") if isinstance(document, dict) else None
    if not isinstance(reasons, list) or not reasons or not all(isinstance(reason, str) for reason in reasons):
        return "refused without reasons"
    return None


def verdict(code, out, err, codes):
    if code is None:
        return "no answer within %d s" % SECONDS
    if "Traceback" in out or "Traceback" in err:
        return "traceback: %s" % (err.strip().splitlines() or ["?"])[-1][:300]
    if code not in codes:
        return "exit code %r outside %s" % (code, sorted(codes))
    if code == 2 and not err.strip():
        return "refused without a message"
    if code == 3 and out.strip():
        return _refusal(out)
    return None


def matrix(cases, codes, module="netops_admin", environment=None, script=None):
    with ThreadPoolExecutor(max_workers=max(2, os.cpu_count() or 2)) as pool:
        results = list(pool.map(lambda argv: launch(argv, module, environment, script), cases.values()))
    failures = {}
    for name, result in zip(cases, results):
        found = verdict(*result, codes)
        if found:
            failures[name] = found
    return failures


def clean(failures):
    assert not failures, "%d failures:\n%s" % (len(failures), "\n".join("%s: %s" % item for item in sorted(failures.items())))


def bounded(call, seconds=IN_PROCESS_SECONDS):
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


def outcome(capsys, call, codes):
    try:
        code = bounded(call)
    except SystemExit as stop:
        code = stop.code
    except Hang:
        capsys.readouterr()
        return "no answer within %d s" % IN_PROCESS_SECONDS
    except Exception as error:
        capsys.readouterr()
        return "traceback: %s: %s" % (type(error).__name__, str(error)[:300])
    out, err = capsys.readouterr()
    return verdict(code, out, err, codes)


def in_process(capsys, argv, codes):
    return outcome(capsys, lambda: cli.main(argv), codes)


def library(call, refusals):
    try:
        bounded(call)
    except refusals:
        return None
    except Hang:
        return "no answer within %d s" % IN_PROCESS_SECONDS
    except Exception as error:
        return "%s: %s" % (type(error).__name__, str(error)[:300])
    return None


def written(directory, name, data):
    path = Path(directory) / name
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return str(path)


def config_document(root):
    root = Path(root)
    device = {"port": 22, "host_key_fingerprint": PIN, "vault": str(root / "vault.json"), "credential": "rw",
              "check_credential": "ro", "safeguard_seconds": 180, "confirm_margin_seconds": 45}
    return {
        "version": 1,
        "state_dir": str(root / "state"),
        "audit_file": str(root / "audit" / "audit.jsonl"),
        "export_status_file": str(root / "export-status.json"),
        "notify": {"server": "https://ntfy.example.invalid", "topic_file": str(root / "topic.env"),
                   "timeout_seconds": 5, "x509_strict": True},
        "limits": {"export_status_max_age_seconds": 1000000, "changes_per_device_per_hour": 100000,
                   "changes_per_day": 100000, "rejections_per_hour": 1000000},
        "devices": {
            "lab": dict(device, platform="fortios", address="192.0.2.1", check_address="192.0.2.3",
                        protected={"firewall address": ["srv-web"]}, accounts=["netops-rw"]),
            "sw": dict(device, platform="exos", address="192.0.2.2", firmware=FIRMWARE, legacy_ssh="rsa-sha1",
                       accounts=["admin", "netops-rw"], protected={"vlan": ["DATA"]}),
        },
    }


def export_document(root):
    return {"updated_at": time.time(), "pending": 0, "oldest_pending_age_seconds": 0.0,
            "audit_file": str(Path(root) / "audit" / "audit.jsonl")}


def fortios_policy():
    return {"version": 1, "platform": "fortios", "required_rules": ["address-unused"],
            "address_networks": ["192.0.2.0/24"], "protected_groups": ["grp-a"]}


class _Delivered:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _delivered(request, timeout=None, context=None):
    return _Delivered()


REQUESTS = {
    "create": dict(device="lab"),
    "update": dict(op="update", key="spare-host", changes={"comment": "reserved"}, request_id="req-0002-example"),
    "refused": dict(op="delete", key="srv-web", changes={}, request_id="req-0003-example"),
    "vlan": dict(table="vlan", key="guest", changes={"tag": 3999, "description": "guest wifi"},
                 request_id="req-0004-example"),
}


class Bench:
    """A configured admin whose devices are fakes and whose state directory is a fresh copy for every run."""

    def __init__(self, root, monkeypatch):
        self.root = Path(root)
        self.document = config_document(self.root)
        written(self.root, "topic.env", TOPIC)
        written(self.root, "export-status.json", json.dumps(export_document(self.root)))
        self.config = written(self.root, "admin.json", json.dumps(self.document))
        self.requests = {name: written(self.root, "request-%s.json" % name, request_bytes(**fields))
                         for name, fields in REQUESTS.items()}
        self.state = None
        self.certified = True
        self.real_access = False
        self.addresses = None
        self.fakes = {}
        self.wrap = {}
        self.runs = itertools.count()
        self._load = configuration.load_config
        monkeypatch.setattr(configuration, "load_config", self.load)
        monkeypatch.setattr(cli, "build_runtime", self.runtime)
        monkeypatch.setattr(notify.urllib.request, "urlopen", _delivered)

    def load(self, path):
        loaded = self._load(path)
        return loaded if self.state is None else dataclasses.replace(loaded, state_dir=str(self.state))

    def _lab(self):
        device = FakeFortiOS()
        if self.addresses is not None:
            device.addresses = copy.deepcopy(self.addresses)
        return device

    def runtime(self, config):
        fakes = self.fakes
        notifier = None
        if config.notify is not None:
            notifier = notify.NtfyNotifier(config.notify.server, config.notify.topic_file,
                                           config.notify.timeout_seconds, config.notify.x509_strict)
        factory = lambda device: fakes[device.name]  # noqa: E731
        if self.real_access:
            from netops_admin.access import DeviceAccess as factory
        built = execute.Runtime(config, factory, notifier=notifier,
                                sleep=lambda seconds: [fake.advance(seconds) for fake in fakes.values()])
        if self.certified:
            for name in config.devices:
                try:
                    certify(built, getattr(fakes[name], "device", fakes[name]), name)
                except Exception:
                    pass
        return built

    def fresh(self, template=None):
        if self.state is not None and self.state.parent == self.root / "runs":
            shutil.rmtree(self.state, ignore_errors=True)
        target = self.root / "runs" / str(next(self.runs))
        if template is None:
            target.mkdir(parents=True)
        else:
            shutil.copytree(template, target, symlinks=True)
        self.state = target
        self.fakes = {"lab": self._lab(), "sw": FakeExos()}
        for name, wrapper in self.wrap.items():
            self.fakes[name] = wrapper(self.fakes[name])
        return target

    def prepare(self, capsys):
        self.fresh()
        code = cli.main(["apply", "--config", self.config, "--device", "lab", "--request", self.requests["create"]])
        out = capsys.readouterr().out
        assert code == 0, out
        self.record = json.loads(out)
        self.change_id, self.request_id = self.record["change_id"], self.record["request_id"]
        assert cli.main(["preview", "--config", self.config, "--device", "lab",
                         "--request", self.requests["refused"]]) == cli.EXIT_REJECTED
        capsys.readouterr()
        self.addresses = copy.deepcopy(self.fakes["lab"].addresses)
        self.template = self.root / "template"
        shutil.copytree(self.state, self.template)
        self.running = self.root / "template-running"
        shutil.copytree(self.state, self.running)
        path = self.running / "operations" / ("%s.json" % self.change_id)
        record = json.loads(path.read_text(encoding="utf-8"))
        names = [step["step"] for step in record["steps"]]
        record["steps"] = record["steps"][:names.index("change_applied") + 1]
        record.update(status="running", result=None)
        for name in ("reason", "differences", "finished_at_epoch", "audit_delivery", "notification"):
            record.pop(name, None)
        path.write_text(json.dumps(record), encoding="utf-8")
        self.blocked = self.root / "template-blocked"
        shutil.copytree(self.state, self.blocked)
        (self.blocked / "blocked" / "lab.json").write_text(json.dumps(
            {"device": "lab", "change_id": self.change_id, "reason": "foreign change"}), encoding="utf-8")
        self.certified = False
        return self

    def run(self, capsys, argv, codes, template=None):
        self.fresh(template)
        return in_process(capsys, argv, codes)


@pytest.fixture
def bench(tmp_path, monkeypatch):
    root = tmp_path / "bench"
    root.mkdir()
    return Bench(root, monkeypatch)


def plan_argv(platform, snapshot, request, *extra):
    argv = ["plan", "--platform", platform, "--snapshot", snapshot, "--request", request]
    if platform == "exos":
        argv += ["--firmware", FIRMWARE]
    return argv + list(extra)


PLAN_REQUESTS = {"fortios": REQUESTS["update"], "exos": REQUESTS["vlan"]}


def _planned(tmp_path, capsys, platform):
    snapshot = written(tmp_path, "valid-%s.conf" % platform, SAMPLES[platform]())
    request = written(tmp_path, "request-%s.json" % platform, request_bytes(**PLAN_REQUESTS[platform]))
    code = cli.main(plan_argv(platform, snapshot, request))
    out = capsys.readouterr().out
    assert code == 0, out
    return snapshot, request, written(tmp_path, "plan-%s.json" % platform, out), json.loads(out)


@pytest.mark.parametrize("platform", sorted(SAMPLES))
def test_plan_and_verify_survive_every_broken_snapshot(tmp_path, capsys, platform):
    _, request, plan, _ = _planned(tmp_path, capsys, platform)
    cases, codes = {}, {}
    for name, data in text_shapes(platform).items():
        snapshot = written(tmp_path, name + ".conf", data)
        cases["plan " + name] = plan_argv(platform, snapshot, request)
        cases["verify " + name] = ["verify", "--plan", plan, "--snapshot", snapshot]
        cases["verify before " + name] = ["verify", "--plan", plan, "--snapshot", snapshot, "--expect", "before"]
        if platform == "exos":
            cases["plan ports " + name] = plan_argv(platform, snapshot, request, "--ports", "1-12")
    failures = matrix({name: argv for name, argv in cases.items() if name.startswith("plan")}, PLAN_CODES)
    failures.update(matrix({name: argv for name, argv in cases.items() if name.startswith("verify")}, VERIFY_CODES))
    clean(failures)


@pytest.mark.parametrize("platform", sorted(SAMPLES))
def test_snapshot_paths_that_are_not_a_regular_file(tmp_path, capsys, platform):
    _, request, plan, _ = _planned(tmp_path, capsys, platform)
    shapes = path_shapes(tmp_path, SAMPLES[platform]().encode("utf-8"))
    oversized = tmp_path / "oversized.conf"
    with open(oversized, "wb") as stream:
        stream.truncate(engine.MAX_SNAPSHOT_BYTES + 2)
    shapes["oversized"] = str(oversized)
    failures = matrix({name: plan_argv(platform, path, request) for name, path in shapes.items()}, PLAN_CODES)
    failures.update(matrix({"verify " + name: ["verify", "--plan", plan, "--snapshot", path]
                            for name, path in shapes.items()}, VERIFY_CODES))
    for label, argv, codes in (("plan", plan_argv(platform, nul_path(tmp_path), request), PLAN_CODES),
                               ("verify", ["verify", "--plan", plan, "--snapshot", nul_path(tmp_path)], VERIFY_CODES)):
        found = in_process(capsys, argv, codes)
        if found:
            failures[label + " nul-in-path"] = found
    clean(failures)


def _document_matrix(tmp_path, capsys, document, argv_for, codes, parse=None, refusals=()):
    failures = {}
    shapes = {name: text.encode("utf-8", "surrogatepass") for name, text in json_shapes(document).items()}
    shapes.update(byte_shapes(json.dumps(document, indent=1)))
    for index, (name, data) in enumerate(shapes.items()):
        path = written(tmp_path, "document-%d.json" % index, data)
        found = in_process(capsys, argv_for(path), codes)
        if found:
            failures[name] = found
        if parse is not None:
            found = library(lambda: parse(data), refusals)
            if found:
                failures[name + " (library)"] = found
    paths = path_shapes(tmp_path, json.dumps(document).encode("utf-8"))
    failures.update({"path " + name: found for name, found in
                     matrix({name: argv_for(path) for name, path in paths.items()}, codes).items()})
    found = in_process(capsys, argv_for(nul_path(tmp_path)), codes)
    if found:
        failures["path nul-in-path"] = found
    return failures


def test_plan_survives_every_broken_request(tmp_path, capsys):
    snapshot, _, _, _ = _planned(tmp_path, capsys, "fortios")
    document = json.loads(request_bytes(**REQUESTS["update"]))
    clean(_document_matrix(tmp_path, capsys, document, lambda path: plan_argv("fortios", snapshot, path), PLAN_CODES,
                           parse_request, Rejected))


def test_plan_survives_every_broken_policy(tmp_path, capsys):
    snapshot, request, _, _ = _planned(tmp_path, capsys, "fortios")
    document = {"protected": {"firewall address": ["srv-web", "spare-host"], "vlan": ["DATA"]}}
    clean(_document_matrix(tmp_path, capsys, document,
                           lambda path: plan_argv("fortios", snapshot, request, "--policy", path), PLAN_CODES))


@pytest.mark.parametrize("platform", sorted(SAMPLES))
def test_verify_survives_every_broken_plan(tmp_path, capsys, platform):
    snapshot, _, _, document = _planned(tmp_path, capsys, platform)
    clean(_document_matrix(tmp_path, capsys, document,
                           lambda path: ["verify", "--plan", path, "--snapshot", snapshot], VERIFY_CODES))


PORT_VALUES = ODD_VALUES + (
    "1-12", "1-4096", "1-4097", "0-1", "12-1", "1:1-1:4096", "1:1-2:4096", "1:1-9999:4096", "1," * 100000 + "1",
    "all", "1-" + "9" * 5000, "\u0661-\u0662", "1:\u00b2", ",", "1,,2", "1-", "-1", ":", "1:", "1:1-",
)


def test_plan_survives_every_port_list(tmp_path, capsys):
    snapshot, request, _, _ = _planned(tmp_path, capsys, "exos")
    failures = {}
    for value in PORT_VALUES:
        found = in_process(capsys, plan_argv("exos", snapshot, request, "--ports", value), PLAN_CODES)
        if found:
            failures[repr(value[:24])] = found
    clean(failures)


def _status(path):
    return ["status", "--config", path, "--change-id", "0" * 32]


def test_every_broken_configuration_is_refused(tmp_path, capsys):
    document = config_document(tmp_path)
    document["devices"]["lab"]["audit_policy"] = written(tmp_path, "policy.json", json.dumps(fortios_policy()))
    clean(_document_matrix(tmp_path, capsys, document, _status, COMMAND_CODES,
                           lambda data: configuration.load_config(written(tmp_path, "library.json", data)), Rejected))


CONFIG_FILES = {
    "state_dir": ("state_dir",),
    "audit_file": ("audit_file",),
    "export_status_file": ("export_status_file",),
    "topic_file": ("notify", "topic_file"),
    "audit_policy": ("devices", "lab", "audit_policy"),
    "vault": ("devices", "lab", "vault"),
}


def test_every_file_the_configuration_names_may_be_broken(tmp_path, capsys, bench):
    bench.prepare(capsys)
    contents = {"state_dir": b"", "audit_file": b"", "export_status_file": json.dumps(export_document(bench.root)),
                "topic_file": TOPIC, "audit_policy": json.dumps(fortios_policy()), "vault": b"{}"}
    failures = {}
    for field, path in CONFIG_FILES.items():
        data = contents[field]
        shapes = path_shapes(tmp_path, data if isinstance(data, bytes) else data.encode("utf-8"))
        shapes["nul-in-path"] = nul_path(tmp_path)
        for name, location in shapes.items():
            document = copy.deepcopy(bench.document)
            parent = document
            for step in path[:-1]:
                parent = parent[step]
            parent[path[-1]] = location
            config = written(tmp_path, "config-%s-%s.json" % (field, name), json.dumps(document))
            bench.state = None
            for label, argv, codes in (
                ("doctor", ["doctor", "--config", config, "--device", "lab"], DOCTOR_CODES),
                ("apply", ["apply", "--config", config, "--device", "lab", "--request", bench.requests["update"]],
                 APPLY_CODES),
                ("unblock", ["unblock", "--config", config, "--device", "lab", "--reason", "checked"], COMMAND_CODES),
            ):
                bench.fakes = {"lab": bench._lab(), "sw": FakeExos()}
                bench.certified = True
                bench.real_access = field == "vault"
                found = in_process(capsys, argv, codes)
                if found:
                    failures["%s %s %s" % (field, name, label)] = found
    clean(failures)


def _state_commands(bench):
    config = bench.config
    return {
        "status": (["status", "--config", config, "--change-id", bench.change_id], COMMAND_CODES),
        "status by request": (["status", "--config", config, "--request-id", bench.request_id], COMMAND_CODES),
        "undo": (["undo", "--config", config, "--change-id", bench.change_id, "--reason", "back"], APPLY_CODES),
        "notify-retry": (["notify-retry", "--config", config, "--change-id", bench.change_id], COMMAND_CODES),
        "unblock": (["unblock", "--config", config, "--device", "lab", "--reason", "checked"], COMMAND_CODES),
        "preview": (["preview", "--config", config, "--device", "lab", "--request", bench.requests["update"]],
                    PREVIEW_CODES),
        "apply again": (["apply", "--config", config, "--device", "lab", "--request", bench.requests["create"]],
                        APPLY_CODES),
        "recover": (["recover", "--config", config, "--device", "lab"], RECOVER_CODES),
        "doctor": (["doctor", "--config", config, "--device", "lab"], DOCTOR_CODES),
    }


STATE_FILES = {
    "operation": ("template", "operations/{change}.json", ("status", "undo", "notify-retry", "preview")),
    "running operation": ("running", "operations/{change}.json", ("recover",)),
    "request": ("template", "requests/{request}.json", ("status by request", "apply again")),
    "baseline": ("template", "baselines/lab.json", ("preview", "doctor")),
    "enrollment": ("template", "enrollments/lab.json", ("preview", "doctor")),
    "blocked": ("blocked", "blocked/lab.json", ("unblock", "preview", "doctor")),
    "rejections": ("template", "rejections.json", ("preview", "doctor")),
}


@pytest.mark.parametrize("name", sorted(STATE_FILES))
def test_every_broken_state_file_is_refused(capsys, bench, name):
    bench.prepare(capsys)
    attribute, pattern, selected = STATE_FILES[name]
    template = getattr(bench, attribute)
    relative = pattern.format(change=bench.change_id, request=bench.request_id)
    valid = (template / relative).read_bytes()
    document = json.loads(valid)
    shapes = {label: text.encode("utf-8", "surrogatepass") for label, text in json_shapes(document, STATE_WRONG).items()}
    shapes.update(byte_shapes(valid.decode("utf-8"), ANSWER_LONG))
    commands = _state_commands(bench)
    failures = {}
    for label in list(shapes) + list(PLACED):
        for command in selected:
            argv, codes = commands[command]
            bench.fresh(template)
            if label in shapes:
                (bench.state / relative).write_bytes(shapes[label])
            else:
                placed(bench.state / relative, label, valid)
            found = in_process(capsys, argv, codes)
            if found:
                failures["%s %s" % (label, command)] = found
    clean(failures)


def _duplicates(document):
    return {"/".join(str(step) for step in path) or "root": _duplicated(document, path).encode("utf-8")
            for path, value in _paths(document) if isinstance(value, dict) and value}


def test_a_repeated_key_is_refused_in_every_json_input(tmp_path, capsys, bench):
    bench.prepare(capsys)
    failures = {}

    def refused(label, call, refusals):
        try:
            outcome = bounded(call)
        except refusals:
            return
        except Exception as error:
            failures[label] = "%s: %s" % (type(error).__name__, str(error)[:200])
            return
        failures[label] = "a key repeated within one JSON object was accepted: %r" % (outcome,)

    request = json.loads(request_bytes(**REQUESTS["update"]))
    for where, data in _duplicates(request).items():
        refused("request " + where, lambda: parse_request(data), Rejected)
    snapshot, request_path, _plan, plan = _planned(tmp_path, capsys, "fortios")
    for where, data in _duplicates(plan).items():
        path = written(tmp_path, "plan-repeated.json", data)
        found = in_process(capsys, ["verify", "--plan", path, "--snapshot", snapshot], {cli.EXIT_REJECTED})
        if found:
            failures["plan " + where] = found
    for where, data in _duplicates({"protected": {"firewall address": ["srv-web"]}}).items():
        path = written(tmp_path, "policy-repeated.json", data)
        found = in_process(capsys, plan_argv("fortios", snapshot, request_path, "--policy", path), {cli.EXIT_REJECTED})
        if found:
            failures["policy " + where] = found
    for where, data in _duplicates(bench.document).items():
        path = written(tmp_path, "admin-repeated.json", data)
        refused("configuration " + where, lambda: bench._load(path), Rejected)
    store_reads = {
        "operations/%s.json" % bench.change_id: lambda store: store.operation(bench.change_id),
        "requests/%s.json" % bench.request_id: lambda store: store.request(bench.request_id),
        "baselines/lab.json": lambda store: store.baseline("lab"),
        "enrollments/lab.json": lambda store: store.enrollment("lab"),
        "blocked/lab.json": lambda store: store.blocked("lab"),
    }
    for relative, read in store_reads.items():
        template = bench.blocked if relative.startswith("blocked") else bench.template
        for where, data in _duplicates(json.loads((template / relative).read_bytes())).items():
            bench.fresh(template)
            (bench.state / relative).write_bytes(data)
            refused("%s %s" % (relative, where), lambda: read(execute.Store(bench.state)), Rejected)
    status = Path(bench.document["export_status_file"])
    limits = dict(configuration.DEFAULT_LIMITS)
    for where, data in _duplicates(export_document(bench.root)).items():
        status.write_bytes(data)
        state, _why = audit.export_state(str(status), limits)
        if state != "blocked" or audit.export_updated_at(str(status)) is not None:
            failures["export status " + where] = "a key repeated within one JSON object was accepted"
    clean(failures)


STATE_PLACES = ("", "operations", "requests", "locks", "blocked", "baselines", "enrollments", "locks/lab.lock",
                ".rejections.lock")
PLACES_SHAPES = ("file", "fifo", "symlink-loop", "symlink-dangling", "symlink-zero", "symlink-null", "symlink-fifo",
                 "missing")


def test_every_broken_place_of_the_state_directory_is_refused(capsys, bench):
    bench.prepare(capsys)
    commands = _state_commands(bench)
    failures = {}
    for place in STATE_PLACES:
        for shape in PLACES_SHAPES:
            for command in ("status", "preview", "apply again", "unblock", "recover", "doctor"):
                argv, codes = commands[command]
                bench.fresh(bench.template)
                target = bench.state / place
                if shape == "file":
                    if target.is_dir():
                        shutil.rmtree(target)
                    target.write_bytes(b"{}")
                else:
                    placed(target, shape, b"{}")
                found = in_process(capsys, argv, codes)
                if found:
                    failures["%s=%s %s" % (place or "state_dir", shape, command)] = found
    clean(failures)


def test_every_broken_export_status_is_refused(tmp_path, capsys, bench):
    bench.prepare(capsys)
    document = export_document(bench.root)
    status = Path(bench.document["export_status_file"])
    shapes = {label: text.encode("utf-8", "surrogatepass") for label, text in json_shapes(document).items()}
    shapes.update(byte_shapes(json.dumps(document)))
    commands = _state_commands(bench)
    failures = {}
    limits = dict(configuration.DEFAULT_LIMITS)
    for label in list(shapes) + list(PLACED):
        if label in shapes:
            status.write_bytes(shapes[label])
        else:
            placed(status, label, json.dumps(document).encode("utf-8"))
        found = library(lambda: (audit.export_state(str(status), limits), audit.export_updated_at(str(status))), ())
        if found:
            failures[label + " (library)"] = found
        for command in ("preview", "doctor", "status"):
            argv, codes = commands[command]
            found = bench.run(capsys, argv, codes, bench.template)
            if found:
                failures["%s %s" % (label, command)] = found
    clean(failures)


def _kind(command):
    return re.sub(r"[0-9a-f]{12,}", "<id>", command)


class Recorder:
    def __init__(self, device):
        self.device = device
        self.answers = {}

    def __getattr__(self, name):
        return getattr(self.device, name)

    def _seen(self, method, command, answer):
        self.answers.setdefault((method, _kind(command)), answer)
        return answer

    def snapshot(self):
        return self._seen("snapshot", "", self.device.snapshot())

    def query(self, command):
        return self._seen("query", command, self.device.query(command))

    def check_query(self, command):
        return self._seen("check_query", command, self.device.check_query(command))


class Broken(Recorder):
    def __init__(self, device, target, answer, later):
        super().__init__(device)
        self.target, self.answer, self.later, self.calls = target, answer, later, 0

    def _seen(self, method, command, answer):
        if (method, _kind(command)) != self.target:
            return answer
        self.calls += 1
        return self.answer if not self.later or self.calls > 1 else answer


@pytest.mark.parametrize("device", ("lab", "sw"))
def test_every_broken_answer_of_a_device_is_refused(capsys, bench, device):
    request = bench.requests["create" if device == "lab" else "vlan"]
    commands = {
        "apply": (["apply", "--config", bench.config, "--device", device, "--request", request], APPLY_CODES),
        "doctor": (["doctor", "--config", bench.config, "--device", device], DOCTOR_CODES),
    }
    recorders = []
    bench.wrap = {device: lambda fake: recorders.append(Recorder(fake)) or recorders[-1]}
    for command, (argv, codes) in commands.items():
        assert bench.run(capsys, argv, codes) is None, command
    answers = {}
    for recorder in recorders:
        for key, answer in recorder.answers.items():
            answers.setdefault(key, answer)
    assert len(answers) >= 5, sorted(answers)
    failures = {}
    for target, valid in sorted(answers.items()):
        shapes = byte_shapes(valid, ANSWER_LONG)
        for shape in ANSWER_SHAPES:
            answer = shapes[shape].decode("utf-8", "replace")
            for command, later in (("apply", False), ("apply", True), ("doctor", False)):
                argv, codes = commands[command]
                bench.wrap = {device: lambda fake: Broken(fake, target, answer, later)}
                found = bench.run(capsys, argv, codes)
                if found:
                    failures["%s %s %s%s" % (" ".join(target).strip(), shape, command, " later" if later else "")] = found
    argv, _codes = commands["apply"]
    bench.wrap = {device: lambda fake: Broken(fake, ("snapshot", ""), "", False)}
    found = bench.run(capsys, argv, frozenset((cli.EXIT_REJECTED,)))
    if found:
        failures["an empty snapshot is not refused, the broken answers do not reach the admin"] = found
    clean(failures)


def _variants(base):
    yield "base", base
    options = [index for index, item in enumerate(base) if item.startswith("--") and index + 1 < len(base)
               and not base[index + 1].startswith("--")]
    for index in options:
        for value in ODD_VALUES:
            argv = list(base)
            argv[index + 1] = value
            yield "%s=%r" % (base[index], value[:12]), argv
        yield "%s missing" % base[index], base[:index] + base[index + 2:]
        yield "%s twice" % base[index], base + [base[index], base[index + 1]]
    yield "unknown option", base + ["--unknown-option"]
    yield "stray argument", base + ["stray"]


def test_every_command_line_argument_is_refused_or_accepted_without_a_traceback(tmp_path, capsys, bench, monkeypatch):
    bench.prepare(capsys)
    place = tmp_path / "cwd"
    place.mkdir()
    monkeypatch.chdir(place)
    snapshot, request, plan, _ = _planned(tmp_path, capsys, "fortios")
    exos_snapshot, exos_request, _, _ = _planned(tmp_path, capsys, "exos")
    policy = written(tmp_path, "policy.json", json.dumps({"protected": {"firewall address": ["srv-web"]}}))
    config = bench.config
    commands = {
        "plan": (plan_argv("fortios", snapshot, request, "--policy", policy), PLAN_CODES),
        "plan exos": (plan_argv("exos", exos_snapshot, exos_request, "--ports", "1-12"), PLAN_CODES),
        "verify": (["verify", "--plan", plan, "--snapshot", snapshot, "--expect", "before"], VERIFY_CODES),
        "apply": (["apply", "--config", config, "--device", "lab", "--request", bench.requests["update"]], APPLY_CODES),
        "preview": (["preview", "--config", config, "--device", "lab", "--request", bench.requests["update"]],
                    PREVIEW_CODES),
        "doctor": (["doctor", "--config", config, "--device", "lab"], DOCTOR_CODES),
        "enroll": (["enroll", "--config", config, "--device", "lab", "--probe", "198.51.100.0/24"], ENROLL_CODES),
        "enroll exos": (["enroll", "--config", config, "--device", "sw", "--probe", "3998"], ENROLL_CODES),
        "status": (["status", "--config", config, "--change-id", bench.change_id, "--request-id", bench.request_id],
                   COMMAND_CODES),
        "recover": (["recover", "--config", config, "--device", "lab"], RECOVER_CODES),
        "notify-retry": (["notify-retry", "--config", config, "--change-id", bench.change_id], COMMAND_CODES),
        "unblock": (["unblock", "--config", config, "--device", "lab", "--reason", "checked"], COMMAND_CODES),
        "undo": (["undo", "--config", config, "--change-id", bench.change_id, "--reason", "back"], APPLY_CODES),
        "none": ([], COMMAND_CODES),
        "unknown": (["unknown-command"], COMMAND_CODES),
        "version": (["--version"], COMMAND_CODES),
    }
    failures = {}
    for command, (base, codes) in commands.items():
        for name, argv in _variants(base):
            found = bench.run(capsys, argv, codes, bench.template)
            if found:
                failures["%s %s" % (command, name)] = found
    clean(failures)


def test_the_installed_entry_point_answers_broken_input_without_a_traceback(tmp_path):
    snapshot = written(tmp_path, "valid.conf", fortios_sample())
    request = written(tmp_path, "request.json", request_bytes(**REQUESTS["update"]))
    shapes = path_shapes(tmp_path, b"")
    cases = {
        "binary snapshot": plan_argv("fortios", written(tmp_path, "binary.conf", bytes(range(256))), request),
        "deep request": plan_argv("fortios", snapshot, written(tmp_path, "deep.json", b"[" * SHALLOW + b"]" * SHALLOW)),
        "fifo request": plan_argv("fortios", snapshot, shapes["fifo"]),
        "fifo config": ["status", "--config", shapes["fifo"], "--change-id", "0" * 32],
        "zero config": ["status", "--config", shapes["device-zero"], "--change-id", "0" * 32],
        "no arguments": [],
    }
    for label in ("request", "snapshot"):
        argv = plan_argv("fortios", snapshot, request)
        position = argv.index("--" + label) + 1
        argv[position] = (argv[position] + "-\udcff").encode("utf-8", "surrogateescape")
        cases["undecodable " + label] = argv
    argv = plan_argv("fortios", snapshot, request)
    argv[argv.index("--platform") + 1] = b"forti\xff"
    cases["undecodable platform"] = argv
    strict = dict(_environment(), PYTHONIOENCODING="utf-8:strict")
    undecodable = {name: argv for name, argv in cases.items() if name.startswith("undecodable")}
    failures = {name + " (strict output)": found
                for name, found in matrix(undecodable, PLAN_CODES, environment=strict).items()}
    failures.update(matrix({name: argv for name, argv in cases.items() if "config" not in name}, PLAN_CODES))
    failures.update(matrix({name: argv for name, argv in cases.items() if "config" in name}, COMMAND_CODES))
    clean(failures)


mcp_server = importlib.import_module("netops_admin.mcp_server") if importlib.util.find_spec("fastmcp") else None


@pytest.fixture
def fresh_server(monkeypatch):
    if mcp_server is None:
        pytest.skip("fastmcp is not installed")
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", None)
    return mcp_server


def test_mcp_configuration_refuses_every_broken_environment(tmp_path, fresh_server):
    document = config_document(tmp_path)
    failures = {}
    environments = {"%s=%r" % (fresh_server.CONFIG_VARIABLE, value[:12]): {fresh_server.CONFIG_VARIABLE: value}
                    for value in ODD_VALUES}
    shapes = {name: text.encode("utf-8", "surrogatepass") for name, text in json_shapes(document).items()}
    shapes.update(byte_shapes(json.dumps(document)))
    for index, (name, data) in enumerate(shapes.items()):
        environments["configuration " + name] = {fresh_server.CONFIG_VARIABLE: written(tmp_path, "mcp-%d.json" % index, data)}
    for name, path in path_shapes(tmp_path, json.dumps(document).encode("utf-8")).items():
        environments["configuration path " + name] = {fresh_server.CONFIG_VARIABLE: path}
    for name, environment in environments.items():
        found = library(lambda: fresh_server.configure(environment), fresh_server.ConfigurationError)
        if found:
            failures[name] = found
        fresh_server._CONFIGURATION = None
    process = dict(_environment(), **{fresh_server.CONFIG_VARIABLE: str(tmp_path / "missing.json")})
    code, out, err = launch([], "netops_admin.mcp_server", process)
    found = verdict(code, out, err, COMMAND_CODES)
    if found or code != 2:
        failures["process with a missing configuration"] = found or "exit code %r" % code
    clean(failures)


class Traced(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        if record.exc_info:
            self.records.append(record.getMessage()[:200])


@pytest.fixture
def traced():
    handler = Traced()
    logger = logging.getLogger("fastmcp")
    levels = [(item, item.level) for item in logger.handlers]
    for item, _ in levels:
        item.setLevel(logging.CRITICAL + 1)
    logger.addHandler(handler)
    yield handler
    logger.removeHandler(handler)
    for item, level in levels:
        item.setLevel(level)


def tool_outcome(server, tool, arguments, traced):
    from fastmcp.exceptions import ToolError, ValidationError

    del traced.records[:]
    result = None
    try:
        result = bounded(lambda: asyncio.run(server.mcp.call_tool(tool, arguments)))
    except ValidationError:
        pass
    except ToolError as error:
        if str(error).startswith("Error calling tool"):
            return "unexpected exception wrapped by FastMCP: %s" % str(error)[:300]
        if len(str(error)) > MAX_MESSAGE:
            return "a refusal of %d characters repeats the input" % len(str(error))
    except Hang:
        return "no answer within %d s" % IN_PROCESS_SECONDS
    except Exception as error:
        return "%s: %s" % (type(error).__name__, str(error)[:300])
    if traced.records:
        return "traceback logged: %s" % traced.records[0]
    content = getattr(result, "structured_content", None) or {}
    reasons = content.get("reasons") or []
    if any(len(str(reason)) > MAX_MESSAGE for reason in reasons):
        return "a reason of %d characters repeats the input" % max(len(str(reason)) for reason in reasons)
    return None


def _tool_calls(bench):
    request = dict(device="lab", table="firewall address", op="update", key="spare-host",
                   changes={"comment": "reserved"}, reason="operator asked", user_request="please update",
                   request_id="req-mcp-0001-example")
    return {
        "admin_apply": request,
        "admin_preview": dict(request, request_id="req-mcp-0002-example"),
        "admin_status": {"change_id": bench.change_id, "request_id": bench.request_id},
        "admin_doctor": {"device": "lab"},
    }


def _tool_variants(arguments):
    yield "base", arguments
    for name in arguments:
        for label, value in WRONG.items():
            yield "%s=%s" % (name, label), dict(arguments, **{name: value})
        yield "%s missing" % name, {key: value for key, value in arguments.items() if key != name}
    if "changes" in arguments:
        for label, value in WRONG.items():
            yield "changes/comment=%s" % label, dict(arguments, changes={"comment": value})
            yield "changes key=%s" % label, dict(arguments, changes={str(value)[:64] or "x": "reserved"})
    yield "extra argument", dict(arguments, unexpected_argument=1)


def _serve(bench, monkeypatch, server, template):
    monkeypatch.setattr(server, "build_runtime", bench.runtime)
    bench.fresh(template)
    server._CONFIGURATION = bench.load(bench.config)


def test_every_mcp_tool_answers_broken_arguments_without_a_traceback(capsys, monkeypatch, bench, traced, fresh_server):
    bench.prepare(capsys)
    failures = {}
    for tool, arguments in _tool_calls(bench).items():
        for name, variant in _tool_variants(arguments):
            _serve(bench, monkeypatch, fresh_server, bench.template)
            found = tool_outcome(fresh_server, tool, variant, traced)
            if found:
                failures["%s %s" % (tool, name)] = found
    clean(failures)


def test_every_mcp_tool_answers_a_broken_state_or_configuration_without_a_traceback(capsys, monkeypatch, bench, traced,
                                                                                    fresh_server):
    bench.prepare(capsys)
    calls = _tool_calls(bench)
    damages = {
        "operations is a file": ("operations", "file"),
        "operation is a directory": ("operations/%s.json" % bench.change_id, "directory"),
        "operation is a fifo": ("operations/%s.json" % bench.change_id, "fifo"),
        "operation is null": ("operations/%s.json" % bench.change_id, b"null"),
        "operation has a list as plan": ("operations/%s.json" % bench.change_id, None),
        "request is binary": ("requests/%s.json" % bench.request_id, bytes(range(256))),
        "request is nested deeply": ("requests/%s.json" % bench.request_id, b"[" * SHALLOW + b"]" * SHALLOW),
        "state is a file": ("", "file"),
        "lock is a fifo": ("locks/lab.lock", "fifo"),
        "rejections are text": ("rejections.json", b"x"),
    }
    failures = {}
    for label, (relative, damage) in damages.items():
        for tool, arguments in calls.items():
            _serve(bench, monkeypatch, fresh_server, bench.template)
            target = bench.state / relative
            if damage is None:
                record = json.loads(target.read_text(encoding="utf-8"))
                record["plan"] = []
                target.write_text(json.dumps(record), encoding="utf-8")
            elif isinstance(damage, bytes):
                target.write_bytes(damage)
            elif damage == "file":
                shutil.rmtree(target)
                target.write_bytes(b"{}")
            else:
                placed(target, damage, b"{}")
            found = tool_outcome(fresh_server, tool, arguments, traced)
            if found:
                failures["%s %s" % (label, tool)] = found
    fresh_server._CONFIGURATION = None
    for tool, arguments in calls.items():
        found = tool_outcome(fresh_server, tool, arguments, traced)
        if found:
            failures["unconfigured %s" % tool] = found
    clean(failures)


EXPORT_SPEC = importlib.util.spec_from_file_location("export_status_script", COMPONENT / "scripts" / "export_status.py")
export_status = importlib.util.module_from_spec(EXPORT_SPEC)
EXPORT_SPEC.loader.exec_module(export_status)
DESTINATION = "d_netops_audit"
QUEUE = "dst.syslog.d_netops_audit#0.tcp,192.0.2.10:601.queued=%s\n"


def _ctl(directory, answer, code=0):
    folder = Path(tempfile.mkdtemp(prefix="ctl-", dir=str(directory)))
    (folder / "answer.bin").write_bytes(answer if isinstance(answer, bytes) else answer.encode("utf-8"))
    script = folder / "syslog-ng-ctl"
    script.write_text("#!%s\nimport os, sys\nhere = os.path.dirname(os.path.abspath(__file__))\n"
                      "sys.stdout.buffer.write(open(os.path.join(here, 'answer.bin'), 'rb').read())\n"
                      "sys.exit(%d)\n" % (sys.executable, code), encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def _strict(text):
    def refuse(constant):
        raise ValueError("non-standard constant %s" % constant)

    return json.loads(text, parse_constant=refuse)


def export_outcome(capsys, argv, output=None):
    found = outcome(capsys, lambda: export_status.main(argv), EXPORT_CODES)
    if found is None and output is not None and Path(output).is_file():
        try:
            document = _strict(Path(output).read_text(encoding="utf-8"))
        except ValueError as error:
            return "the written status is not strict JSON: %s" % error
        state, _why = audit.export_state(output, dict(configuration.DEFAULT_LIMITS), clock=lambda: time.time())
        if state == "blocked" and document.get("pending") == 0:
            return "the written status blocks the admin: %s" % _why
    return found


def test_export_status_survives_every_broken_answer_of_syslog_ng(tmp_path, capsys):
    valid = QUEUE % 3
    answers = dict(byte_shapes(valid, ANSWER_LONG))
    answers.update({
        "count-huge": (QUEUE % ("9" * 5000)).encode("utf-8"),
        "count-arabic": (QUEUE % "\u0663").encode("utf-8"),
        "count-superscript": (QUEUE % "\u00b2").encode("utf-8"),
        "count-negative": (QUEUE % "-3").encode("utf-8"),
        "count-empty": (QUEUE % "").encode("utf-8"),
        "many-lines": (QUEUE % 1).encode("utf-8") * 100000,
        "other-destination": b"dst.syslog.d_other#0.tcp,192.0.2.10:601.queued=3\n",
        "trailing-newline-name": b"dst.syslog.d_netops_audit\n#0.tcp.queued=3\n",
    })
    failures = {}
    for name, answer in answers.items():
        for code in (0, 1):
            output = str(tmp_path / ("status-%s-%d.json" % (name, code)))
            found = export_outcome(capsys, ["--destination", DESTINATION, "--output", output,
                                            "--ctl", _ctl(tmp_path, answer, code)], output)
            if found:
                failures["%s rc=%d" % (name, code)] = found
    for name in ("count-huge", "count-arabic", "count-superscript", "count-negative", "count-empty"):
        output = tmp_path / ("not-a-count-%s.json" % name)
        argv = ["--destination", DESTINATION, "--output", str(output), "--ctl", _ctl(tmp_path, answers[name])]
        found = outcome(capsys, lambda: export_status.main(argv), frozenset((1,)))
        if found or output.exists():
            failures[name + " read as a queue length"] = found or "a status was written"
    clean(failures)


def test_export_status_survives_a_broken_pending_since_file(tmp_path, capsys):
    ctl = _ctl(tmp_path, QUEUE % 3)
    valid = "%.3f" % time.time()
    shapes = dict(byte_shapes(valid))
    shapes.update({name: value.encode("utf-8") for name, value in {
        "nan": "nan", "inf": "inf", "minus-inf": "-inf", "overflow": "1e309", "minus-overflow": "-1e309",
        "future": "%.3f" % (time.time() + 10 ** 9), "negative": "-1", "underscore": "1_000", "hex": "0x10",
    }.items()})
    failures = {}
    for index, name in enumerate(list(shapes) + list(PLACED)):
        output = tmp_path / ("status-%d.json" % index)
        since = output.with_name(output.name + ".pending-since")
        if name in shapes:
            since.write_bytes(shapes[name])
        else:
            placed(since, name, valid.encode("utf-8"))
        found = export_outcome(capsys, ["--destination", DESTINATION, "--output", str(output), "--ctl", ctl],
                               str(output))
        if found:
            failures[name] = found
    clean(failures)


def test_export_status_survives_every_broken_output_path(tmp_path, capsys):
    ctl = _ctl(tmp_path, QUEUE % 0)
    shapes = {name: path for name, path in path_shapes(tmp_path, b"{}").items() if not name.startswith("device")
              and name not in ("symlink-zero",)}
    shapes["nul-in-path"] = nul_path(tmp_path)
    shapes["long-name"] = str(tmp_path / ("x" * 300))
    failures = {}
    for name, path in shapes.items():
        found = export_outcome(capsys, ["--destination", DESTINATION, "--output", path, "--ctl", ctl])
        if found:
            failures[name] = found
    clean(failures)


def test_export_status_arguments_are_refused_or_accepted_without_a_traceback(tmp_path, capsys, monkeypatch):
    place = tmp_path / "cwd"
    place.mkdir()
    monkeypatch.chdir(place)
    base = ["--destination", DESTINATION, "--output", str(tmp_path / "status.json"), "--ctl",
            _ctl(tmp_path, QUEUE % 0), "--audit-file", "/var/log/netops-admin/audit.jsonl"]
    failures = {}
    for name, argv in itertools.chain(_variants(base), (("none", []),)):
        found = export_outcome(capsys, argv)
        if found:
            failures[name] = found
    clean(failures)
