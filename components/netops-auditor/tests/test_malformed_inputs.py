"""Broken-input matrix over every parser and every CLI and MCP input of the auditor.

Each input receives the same family of broken shapes: an empty file, binary bytes, invalid UTF-8,
a byte order mark, CRLF, CR, U+2028 and NUL line breaks, an extremely long line, deep nesting,
duplicate keys, wrong types, Unicode digits, missing and extra fields, a truncated document and,
where the input is a path, a symbolic link, a FIFO or a directory in place of a file. The input is
either accepted or refused with a controlled error - one message and a documented exit code on the
CLI, a ToolError on the MCP surface, the parser's own error class in the library - and it never
ends in a traceback and never hangs.
"""

import asyncio
import json
import logging
import os
import resource
import signal
import sqlite3
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from netops_auditor import cli, collect, l1_exos, l1_fortios, sarif

COMPONENT = Path(__file__).resolve().parents[1]
FIXTURES = COMPONENT / "tests" / "fixtures"
SOURCES = os.pathsep.join((str(COMPONENT / "src"), str(COMPONENT.parent / "netops-core" / "src")))
TENANT = "tenant-a"
DEVICE = "fw-a.example.invalid"
SECONDS = 60
RUN_CODES = frozenset((0, 2, 3))
STATUS_CODES = frozenset((0, 1, 2))
COMMAND_CODES = frozenset((0, 2))
DEPTH = 100000
LONG = 4 * 1024 * 1024
MEMORY = 2 * 1024 * 1024 * 1024
MAX_MESSAGE = 2000
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
FORTIOS_ESCAPES = (
    '"folder\\\\"',
    '"say \\"hi\\""',
    '"a\\\\\\"b"',
    '"trail\\\\" "next"',
    '"\\\\\\\\"',
    '"two\nlines\\\\"',
    '""',
)


class Hang(BaseException):
    pass


def fortios_sample():
    text = (FIXTURES / "fortios_clean.conf").read_text(encoding="utf-8")
    anchor = "    set ssl-static-key-ciphers disable\n"
    assert text.count(anchor) == 1
    return text.replace(anchor, anchor + "    set admintimeout 5\n    set admin-sport 8443\n")


def exos_sample():
    return (FIXTURES / "exos_clean.conf").read_text(encoding="utf-8")


SAMPLES = {"fortios": fortios_sample, "exos": exos_sample}


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


def fortios_shapes(valid):
    group = 'config firewall addrgrp\n    edit "g"\n        set member "g"\n    next\nend\n'
    return {
        "admintimeout-superscript": valid.replace("set admintimeout 5", "set admintimeout \u00b2"),
        "admintimeout-arabic": valid.replace("set admintimeout 5", "set admintimeout \u0663"),
        "admintimeout-huge": valid.replace("set admintimeout 5", "set admintimeout " + "9" * 5000),
        "admintimeout-negative": valid.replace("set admintimeout 5", "set admintimeout -5"),
        "port-superscript": valid.replace("set admin-sport 8443", "set admin-sport 8\u00b2"),
        "deep-blocks": "config a\n" * DEPTH + "end\n" * DEPTH,
        "deep-entries": "config firewall address\n" + "edit x\n" * DEPTH + "next\n" * DEPTH + "end\n",
        "end-outside": "end\n" + valid,
        "next-outside": "next\n" + valid,
        "unterminated-block": "config system global\n    set hostname \"fw\"\n",
        "unterminated-quote": valid + 'config system global\n    set hostname "fw\n',
        "lone-backslash": 'config system global\n    set hostname "fw\\\nend\n',
        "set-without-name": "config system global\n    set\nend\n",
        "unset-without-name": "config system global\n    unset\nend\n",
        "edit-without-key": "config firewall address\n    edit\n    next\nend\n",
        "config-without-name": "config\nend\n",
        "many-values": "config system global\n    set x " + "a " * 500000 + "\nend\n",
        "self-group": valid + group,
        "many-addresses": "config firewall address\n"
        + "".join('    edit "a%d"\n        set subnet 192.0.2.%d 255.255.255.255\n    next\n' % (n, n % 250) for n in range(20000))
        + "end\n",
    }


def exos_shapes(valid):
    return {
        "port-superscript": valid + "configure vlan v1 add ports \u00b2 untagged\n",
        "port-arabic": valid + "configure vlan v1 add ports \u0661:\u0662 tagged\n",
        "port-range-reversed": valid + "configure vlan v1 add ports 9-1 tagged\n",
        "tag-huge": valid + "create vlan v2\nconfigure vlan v2 tag " + "9" * 5000 + "\n",
        "unterminated-quote": valid + 'configure snmp sysName "fw\n',
        "unterminated-upm": valid + "create upm profile p\nconfigure vlan v1 add ports 1 untagged\n",
        "module-header-long": "# Module " + "a" * LONG + " configuration.\n" + valid,
        "many-vlans": "".join("create vlan v%d\nconfigure vlan v%d tag %d\n" % (n, n, n % 4094 + 1) for n in range(20000)),
        "many-values": "configure vlan v1 add ports " + "1," * 500000 + "1 tagged\n",
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


_DELETE = object()
LONG_NUMBER = "long-number-placeholder"


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


def path_shapes(directory, valid):
    root = Path(tempfile.mkdtemp(prefix="paths-", dir=str(directory)))
    target = root / "valid"
    target.write_bytes(valid)
    folder = root / "directory"
    folder.mkdir()
    fifo = root / "fifo"
    os.mkfifo(fifo)
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
    })
    return {name: str(path) for name, path in shapes.items()}


def _environment():
    environment = dict(os.environ)
    environment["PYTHONPATH"] = SOURCES
    return environment


def _limited():
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY, MEMORY))


def launch(argv, module="netops_auditor", environment=None):
    try:
        done = subprocess.run(
            [sys.executable, "-B", "-m", module, *argv],
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


def verdict(code, out, err, codes):
    if code is None:
        return "no answer within %d s" % SECONDS
    if "Traceback" in out or "Traceback" in err:
        return "traceback: %s" % (err.strip().splitlines() or ["?"])[-1][:300]
    if code not in codes:
        return "exit code %r outside %s" % (code, sorted(codes))
    if code == 2 and not err.strip():
        return "refused without a message"
    return None


def matrix(cases, codes, module="netops_auditor", environment=None):
    with ThreadPoolExecutor(max_workers=max(2, os.cpu_count() or 2)) as pool:
        results = list(pool.map(lambda argv: launch(argv, module, environment), cases.values()))
    failures = {}
    for name, result in zip(cases, results):
        found = verdict(*result, codes)
        if found:
            failures[name] = found
    return failures


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


def in_process(capsys, argv, codes):
    try:
        code = bounded(lambda: cli.main(argv))
    except SystemExit as stop:
        code = stop.code
    except Hang:
        capsys.readouterr()
        return "no answer within %d s" % SECONDS
    except Exception as error:
        capsys.readouterr()
        return "traceback: %s: %s" % (type(error).__name__, str(error)[:300])
    out, err = capsys.readouterr()
    return verdict(code, out, err, codes)


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


def written(directory, name, data):
    path = directory / name
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return str(path)


def run_argv(platform, config, *extra):
    return ["run", "--platform", platform, "--tenant", TENANT, "--device", DEVICE, "--config", config, *extra]


def report_of(capsys, platform, config, *extra):
    code = cli.main(run_argv(platform, config, *extra))
    out, err = capsys.readouterr()
    assert code in (0, 3), err
    return out


@pytest.fixture
def offline(monkeypatch):
    def refused(*args, **keywords):
        raise collect.CollectError("the test never reaches a device")

    monkeypatch.setattr(collect, "collect_ssh", refused)
    monkeypatch.setattr(collect, "collect_fortios_rest", refused)


@pytest.mark.parametrize("platform", sorted(SAMPLES))
def test_run_survives_every_broken_configuration(tmp_path, platform):
    cases = {}
    for name, data in text_shapes(platform).items():
        config = written(tmp_path, name + ".conf", data)
        cases[name] = run_argv(platform, config)
        cases[name + " --json"] = run_argv(platform, config, "--json")
        cases[name + " --sarif"] = run_argv(platform, config, "--sarif")
    clean(matrix(cases, RUN_CODES))


@pytest.mark.parametrize("platform", sorted(SAMPLES))
def test_run_refuses_a_configuration_path_that_is_not_a_regular_file(tmp_path, platform):
    shapes = path_shapes(tmp_path, SAMPLES[platform]().encode("utf-8"))
    cases = {name: run_argv(platform, path) for name, path in shapes.items()}
    oversized = tmp_path / "oversized.conf"
    with open(oversized, "wb") as stream:
        stream.truncate(collect.MAX_SNAPSHOT_BYTES + 1)
    cases["oversized"] = run_argv(platform, str(oversized))
    clean(matrix(cases, RUN_CODES))


@pytest.mark.parametrize("platform", sorted(SAMPLES))
def test_every_configuration_parser_raises_only_its_own_error(platform):
    parser = {"fortios": l1_fortios, "exos": l1_exos}[platform]
    failures = {}
    for name, data in text_shapes(platform).items():
        text = data.decode("utf-8", "surrogateescape")
        found = library(lambda: parser.parse(text), parser.ParseError)
        if found:
            failures[name] = found
    clean(failures)


def test_fortios_escaped_quotes_parse_the_way_the_tokenizer_reads_them(tmp_path, capsys):
    failures = {}
    for index, quoted in enumerate(FORTIOS_ESCAPES):
        text = "config system global\n    set comments %s\nend\n" % quoted
        expected = tuple(l1_fortios.tokenize("set comments %s" % quoted)[2:])
        try:
            values = l1_fortios.parse(text).section("system global").values("comments")
        except l1_fortios.ParseError as error:
            failures[quoted] = "parse refused what tokenize reads: %s" % error
            continue
        if values != expected:
            failures[quoted] = "parse read %r, tokenize %r" % (values, expected)
        config = written(tmp_path, "escape-%d.conf" % index, text)
        code = cli.main(run_argv("fortios", config, "--json"))
        _, err = capsys.readouterr()
        if code not in (0, 3):
            failures[quoted + " (cli)"] = "exit code %r: %s" % (code, err.strip())
    clean(failures)


def fortios_policy():
    return {
        "version": 1,
        "platform": "fortios",
        "required_rules": ["address-unused"],
        "address_networks": ["192.0.2.0/24"],
        "dhcp_networks": {"1": ["198.51.100.0/24"]},
        "protected_groups": ["grp-a"],
    }


def exos_policy():
    return {
        "version": 1,
        "platform": "exos",
        "vlan_tags": [[1, 100]],
        "port_vlans": {"1": {"tagged": ["v10"], "untagged": ["Default"]}},
        "protected_ports": ["1"],
        "management_vlans": ["Mgmt"],
        "description_glob": "uplink*",
    }


POLICIES = {"fortios": fortios_policy, "exos": exos_policy}


@pytest.mark.parametrize("platform", sorted(SAMPLES))
def test_run_survives_every_broken_policy(tmp_path, capsys, platform):
    config = written(tmp_path, "device.conf", SAMPLES[platform]())
    document = POLICIES[platform]()
    report_of(capsys, platform, config, "--policy", written(tmp_path, "valid.json", json.dumps(document)))
    failures = {}
    for index, (name, text) in enumerate(json_shapes(document).items()):
        policy = written(tmp_path, "policy-%d.json" % index, text)
        found = in_process(capsys, run_argv(platform, config, "--policy", policy), RUN_CODES)
        if found:
            failures[name] = found
    cases = {}
    for name, data in byte_shapes(json.dumps(document, indent=1)).items():
        cases[name] = run_argv(platform, config, "--policy", written(tmp_path, name + ".policy", data))
    for name, path in path_shapes(tmp_path, json.dumps(document).encode("utf-8")).items():
        cases[name] = run_argv(platform, config, "--policy", path)
    failures.update(matrix(cases, RUN_CODES))
    clean(failures)


def _suppressions(capsys, tmp_path, version):
    from netops_auditor.findings import fingerprint_of

    text = SAMPLES["fortios"]().replace("set allowaccess ping\n", "set allowaccess ping https ssh\n", 1)
    config = written(tmp_path, "dirty.conf", text)
    finding = json.loads(report_of(capsys, "fortios", config, "--json"))["findings"][0]
    rule_version = 1
    item = {
        "fingerprint": finding["fingerprint"] if version == 2 else fingerprint_of(
            finding["rule_id"], rule_version, TENANT, DEVICE, finding["object_key"]),
        "rule_id": finding["rule_id"],
        "rule_version": rule_version,
        "device": DEVICE,
        "object_key": finding["object_key"],
        "reason": "ticket NET-1",
        "author": "radek",
        "created": "2026-01-01T00:00:00Z",
        "expires": "2036-01-01T00:00:00Z",
    }
    document = {"version": version, "suppressions": [item]}
    if version == 2:
        document["tenant"] = TENANT
    return config, document


def test_run_survives_every_broken_suppression_file(tmp_path, capsys):
    config, document = _suppressions(capsys, tmp_path, 2)
    report_of(capsys, "fortios", config, "--suppressions", written(tmp_path, "valid.json", json.dumps(document)))
    failures = {}
    for index, (name, text) in enumerate(json_shapes(document).items()):
        path = written(tmp_path, "suppressions-%d.json" % index, text)
        found = in_process(capsys, run_argv("fortios", config, "--suppressions", path), RUN_CODES)
        if found:
            failures[name] = found
    cases = {}
    for name, data in byte_shapes(json.dumps(document, indent=1)).items():
        cases[name] = run_argv("fortios", config, "--suppressions", written(tmp_path, name + ".waivers", data))
    for name, path in path_shapes(tmp_path, json.dumps(document).encode("utf-8")).items():
        cases[name] = run_argv("fortios", config, "--suppressions", path)
    failures.update(matrix(cases, RUN_CODES))
    clean(failures)


def test_migrate_suppressions_survives_every_broken_input_and_output(tmp_path, capsys):
    _, document = _suppressions(capsys, tmp_path, 1)
    failures = {}
    for index, (name, text) in enumerate(json_shapes(document).items()):
        source = written(tmp_path, "old-%d.json" % index, text)
        argv = ["migrate-suppressions", "--input", source, "--output", str(tmp_path / ("new-%d.json" % index)),
                "--tenant", TENANT]
        found = in_process(capsys, argv, COMMAND_CODES)
        if found:
            failures[name] = found
    cases = {}
    for name, data in byte_shapes(json.dumps(document, indent=1)).items():
        source = written(tmp_path, name + ".old", data)
        cases[name] = ["migrate-suppressions", "--input", source, "--output", str(tmp_path / (name + ".new")),
                       "--tenant", TENANT]
    valid = written(tmp_path, "valid-old.json", json.dumps(document))
    for name, path in path_shapes(tmp_path, json.dumps(document).encode("utf-8")).items():
        cases["input " + name] = ["migrate-suppressions", "--input", path, "--output",
                                  str(tmp_path / ("input-%s.new" % name)), "--tenant", TENANT]
        cases["output " + name] = ["migrate-suppressions", "--input", valid, "--output", path, "--tenant", TENANT]
    failures.update(matrix(cases, COMMAND_CODES))
    clean(failures)


def _sarif(capsys, tmp_path):
    text = SAMPLES["fortios"]().replace("set allowaccess ping\n", "set allowaccess ping https ssh\n", 1)
    config = written(tmp_path, "sarif.conf", text)
    return json.loads(report_of(capsys, "fortios", config, "--sarif"))


def _trimmed_sarif(document):
    run = document["runs"][0]
    run["tool"]["driver"]["rules"] = run["tool"]["driver"]["rules"][:1]
    run["results"] = [item for item in run["results"] if item["ruleId"] == run["tool"]["driver"]["rules"][0]["id"]][:1]
    if not run["results"]:
        run["results"] = [{"ruleId": run["tool"]["driver"]["rules"][0]["id"], "ruleIndex": 0}]
    return document


def test_merge_sarif_survives_every_broken_document(tmp_path, capsys):
    document = _trimmed_sarif(_sarif(capsys, tmp_path))
    valid = written(tmp_path, "valid.sarif", json.dumps(document))
    assert cli.main(["merge-sarif", "--output", str(tmp_path / "valid-out.sarif"), valid]) == 0, capsys.readouterr()
    capsys.readouterr()
    failures = {}
    for index, (name, text) in enumerate(json_shapes(document).items()):
        path = written(tmp_path, "broken-%d.sarif" % index, text)
        argv = ["merge-sarif", "--output", str(tmp_path / ("out-%d.sarif" % index)), valid, path]
        found = in_process(capsys, argv, COMMAND_CODES)
        if found:
            failures[name] = found
        try:
            broken = json.loads(text)
        except ValueError:
            continue
        found = library(lambda: sarif.merge([("valid", document), ("broken", broken)]), sarif.SarifError)
        if found:
            failures[name + " (merge)"] = found
    cases = {}
    for name, data in byte_shapes(json.dumps(document, indent=1)).items():
        cases[name] = ["merge-sarif", "--output", str(tmp_path / (name + ".out")), written(tmp_path, name + ".in", data)]
    for name, path in path_shapes(tmp_path, json.dumps(document).encode("utf-8")).items():
        cases["input " + name] = ["merge-sarif", "--output", str(tmp_path / ("input-%s.out" % name)), path]
        cases["output " + name] = ["merge-sarif", "--output", path, valid]
    failures.update(matrix(cases, COMMAND_CODES))
    clean(failures)


def _store(capsys, tmp_path):
    config = written(tmp_path, "store.conf", SAMPLES["fortios"]())
    database = tmp_path / "audit.sqlite"
    report_of(capsys, "fortios", config, "--store", str(database))
    return config, database


def store_shapes(tmp_path, database):
    data = database.read_bytes()
    shapes = {name: written(tmp_path, "store-" + name, value) for name, value in {
        "empty": b"",
        "binary": bytes(range(256)) * 64,
        "text": b"not a database\n",
        "truncated": data[: len(data) // 2],
        "header-only": data[:100],
    }.items()}
    foreign = tmp_path / "foreign.sqlite"
    with sqlite3.connect(str(foreign)) as connection:
        connection.execute("CREATE TABLE runs (x)")
    shapes["foreign-schema"] = str(foreign)
    future = tmp_path / "future.sqlite"
    future.write_bytes(data)
    with sqlite3.connect(str(future)) as connection:
        connection.execute("PRAGMA user_version = 99")
    shapes["future-version"] = str(future)
    for name, path in path_shapes(tmp_path, data).items():
        shapes["path " + name] = path
    return shapes


def test_every_store_command_survives_a_broken_store(tmp_path, capsys):
    config, database = _store(capsys, tmp_path)
    cases = {}
    for name, path in store_shapes(tmp_path, database).items():
        cases["run " + name] = (run_argv("fortios", config, "--store", path), RUN_CODES)
        cases["status " + name] = (["status", "--tenant", TENANT, "--device", DEVICE, "--store", path], STATUS_CODES)
        cases["migrate " + name] = (["migrate-store", "--store", path], COMMAND_CODES)
    failures = {}
    for codes in (RUN_CODES, STATUS_CODES, COMMAND_CODES):
        selected = {name: argv for name, (argv, wanted) in cases.items() if wanted is codes}
        failures.update(matrix(selected, codes))
    clean(failures)


def inventory_document(config):
    return {
        "version": 2,
        "devices": [
            {
                "name": DEVICE,
                "platform": "fortios",
                "address": None,
                "port": None,
                "role": "perimetr",
                "credential": None,
                "host_key_fingerprint": None,
                "legacy_ssh": None,
                "auditor": {
                    "channel": "file",
                    "source": config,
                    "required_sections": ["system global"],
                    "tls_fingerprint": None,
                },
                "helper": None,
            },
            {
                "name": "fw-b.example.invalid",
                "platform": "fortios",
                "address": "192.0.2.10",
                "port": 443,
                "role": "perimetr",
                "credential": "fw-b-api",
                "host_key_fingerprint": None,
                "legacy_ssh": None,
                "auditor": {
                    "channel": "fortios-rest",
                    "source": "https://192.0.2.10",
                    "required_sections": ["system global"],
                    "tls_fingerprint": "0123456789abcdef" * 4,
                },
                "helper": None,
            },
        ],
    }


def collect_argv(inventory, device=DEVICE, *extra):
    return ["collect", "--inventory", inventory, "--device", device, "--tenant", TENANT, *extra]


def test_collect_survives_every_broken_inventory(tmp_path, capsys, offline):
    config = written(tmp_path, "device.conf", SAMPLES["fortios"]())
    document = inventory_document(config)
    valid = written(tmp_path, "valid.json", json.dumps(document))
    assert cli.main(collect_argv(valid)) in (0, 3), capsys.readouterr()
    capsys.readouterr()
    failures = {}
    for index, (name, text) in enumerate(json_shapes(document).items()):
        path = written(tmp_path, "inventory-%d.json" % index, text)
        found = in_process(capsys, collect_argv(path), RUN_CODES)
        if found:
            failures[name] = found
    for name, data in byte_shapes(json.dumps(document, indent=1)).items():
        found = in_process(capsys, collect_argv(written(tmp_path, name + ".inventory", data)), RUN_CODES)
        if found:
            failures[name] = found
    cases = {name: collect_argv(path) for name, path in path_shapes(tmp_path, valid.encode("utf-8")).items()}
    failures.update(matrix(cases, RUN_CODES))
    clean(failures)


def test_collect_survives_every_broken_snapshot_of_the_file_channel(tmp_path):
    cases = {}
    for name, data in text_shapes("fortios").items():
        snapshot = written(tmp_path, name + ".conf", data)
        cases[name] = collect_argv(written(tmp_path, name + ".json", json.dumps(inventory_document(snapshot))), DEVICE, "--json")
    for name, path in path_shapes(tmp_path, SAMPLES["fortios"]().encode("utf-8")).items():
        cases["source " + name] = collect_argv(written(tmp_path, name + ".paths.json", json.dumps(inventory_document(path))))
    clean(matrix(cases, RUN_CODES))


def vault_document():
    return {"version": 2, "credentials": {"fw-b-api": {"kind": "api-token", "value": "replace-me"}}}


def test_collect_survives_every_broken_vault(tmp_path, capsys, offline):
    config = written(tmp_path, "device.conf", SAMPLES["fortios"]())
    inventory = written(tmp_path, "inventory.json", json.dumps(inventory_document(config)))
    failures = {}
    shapes = {name: text.encode("utf-8") for name, text in json_shapes(vault_document()).items()}
    shapes.update(byte_shapes(json.dumps(vault_document(), indent=1)))
    for index, (name, data) in enumerate(shapes.items()):
        path = Path(written(tmp_path, "vault-%d.json" % index, data))
        path.chmod(0o600)
        found = in_process(capsys, collect_argv(inventory, "fw-b.example.invalid", "--vault", str(path)), RUN_CODES)
        if found:
            failures[name] = found
    for name, path in path_shapes(tmp_path, json.dumps(vault_document()).encode("utf-8")).items():
        found = in_process(capsys, collect_argv(inventory, "fw-b.example.invalid", "--vault", path), RUN_CODES)
        if found:
            failures["path " + name] = found
    clean(failures)


ODD_VALUES = (
    "", " ", "\u00b2", "\u0663", "-1", "0", "nan", "inf", "-inf", "1e309", "0x10", "1_000",
    "x" * 100000, "9" * 5000, "a\u2028b", "a\nb", "-", "--", "\ufeffx", "relative/../odd",
)


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


def test_every_command_line_argument_is_refused_or_accepted_without_a_traceback(tmp_path, capsys, offline,
                                                                              monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    config, database = _store(capsys, tmp_path)
    sarif_path = written(tmp_path, "valid.sarif", json.dumps(_trimmed_sarif(_sarif(capsys, tmp_path))))
    inventory = written(tmp_path, "inventory.json", json.dumps(inventory_document(config)))
    old = written(tmp_path, "old.json", json.dumps(_suppressions(capsys, tmp_path, 1)[1]))
    commands = {
        "run": (run_argv("fortios", config, "--store", str(database), "--json"), RUN_CODES),
        "collect": (collect_argv(inventory, DEVICE, "--max-response-bytes", "1000", "--json"), RUN_CODES),
        "status": (["status", "--tenant", TENANT, "--device", DEVICE, "--store", str(database),
                    "--stale-after-hours", "26"], STATUS_CODES),
        "migrate-store": (["migrate-store", "--store", str(database)], COMMAND_CODES),
        "migrate-suppressions": (["migrate-suppressions", "--input", old, "--output", str(tmp_path / "new.json"),
                                  "--tenant", TENANT], COMMAND_CODES),
        "merge-sarif": (["merge-sarif", "--output", str(tmp_path / "merged.sarif"), sarif_path], COMMAND_CODES),
        "none": ([], COMMAND_CODES),
        "unknown": (["unknown-command"], COMMAND_CODES),
    }
    failures = {}
    for command, (base, codes) in commands.items():
        for name, argv in _variants(base):
            found = in_process(capsys, argv, codes)
            if found:
                failures["%s %s" % (command, name)] = found
            (tmp_path / "new.json").unlink(missing_ok=True)
    clean(failures)


def test_the_installed_entry_point_answers_broken_input_without_a_traceback(tmp_path):
    cases = {
        "superscript": run_argv("fortios", written(tmp_path, "superscript.conf",
                                                   "config system global\n    set admintimeout \u00b2\nend\n")),
        "binary": run_argv("exos", written(tmp_path, "binary.conf", bytes(range(256)))),
        "nested-sarif": ["merge-sarif", "--output", str(tmp_path / "out.sarif"),
                         written(tmp_path, "nested.sarif", '{"version":"2.1.0","runs":[null]}')],
        "fifo-config": run_argv("fortios", path_shapes(tmp_path, b"")["fifo"]),
        "no-arguments": [],
    }
    config = written(tmp_path, "clean.conf", SAMPLES["fortios"]())
    for label, extra in (("text", ()), ("json", ("--json",)), ("sarif", ("--sarif",))):
        argv = run_argv("fortios", config, *extra)
        argv[argv.index("--tenant") + 1] = b"tenant-\xff"
        cases["undecodable tenant " + label] = argv
        argv = run_argv("fortios", config, *extra)
        argv[argv.index("--device") + 1] = b"fw-\xff"
        cases["undecodable device " + label] = argv
        argv = ["merge-sarif", "--output", str(tmp_path / "out-\udcff.sarif"), config]
        cases["undecodable output " + label] = [item.encode("utf-8", "surrogateescape") for item in argv]
    strict = dict(_environment(), PYTHONIOENCODING="utf-8:strict")
    undecodable = {name: argv for name, argv in cases.items() if name.startswith("undecodable")}
    failures = {name + " (strict output)": found
                for name, found in matrix(undecodable, RUN_CODES, environment=strict).items()}
    failures.update(matrix(cases, RUN_CODES))
    clean(failures)


mcp_server = pytest.importorskip("netops_auditor.mcp_server") if __import__("importlib").util.find_spec("fastmcp") else None


def _configured(tmp_path, capsys):
    _, database = _store(capsys, tmp_path)
    return {
        mcp_server.STORE_VARIABLE: str(database),
        mcp_server.TENANT_VARIABLE: TENANT,
        mcp_server.CATALOG_VARIABLE: "fortios",
    }


@pytest.fixture
def fresh_server():
    if mcp_server is None:
        pytest.skip("fastmcp is not installed")
    mcp_server._CONFIGURATION = None
    yield mcp_server
    mcp_server._CONFIGURATION = None


def test_mcp_configuration_refuses_every_broken_environment(tmp_path, capsys, fresh_server):
    from netops_auditor.mcp_server import ConfigurationError

    good = _configured(tmp_path, capsys)
    database = Path(good[fresh_server.STORE_VARIABLE])
    _, suppressions = _suppressions(capsys, tmp_path, 2)
    failures = {}
    environments = {}
    for name, path in store_shapes(tmp_path, database).items():
        environments["store " + name] = dict(good, **{fresh_server.STORE_VARIABLE: path})
    for value in ODD_VALUES:
        for variable in (fresh_server.TENANT_VARIABLE, fresh_server.CATALOG_VARIABLE, fresh_server.STORE_VARIABLE):
            environments["%s=%r" % (variable, value[:12])] = dict(good, **{variable: value})
    waivers = {name: text.encode("utf-8") for name, text in json_shapes(suppressions).items()}
    waivers.update(byte_shapes(json.dumps(suppressions)))
    for index, (name, data) in enumerate(waivers.items()):
        environments["suppressions " + name] = dict(
            good, **{fresh_server.SUPPRESSIONS_VARIABLE: written(tmp_path, "mcp-waivers-%d.json" % index, data)})
    for name, path in path_shapes(tmp_path, json.dumps(suppressions).encode("utf-8")).items():
        environments["suppressions path " + name] = dict(good, **{fresh_server.SUPPRESSIONS_VARIABLE: path})
    for name, environment in environments.items():
        found = library(lambda: fresh_server.configure(environment), ConfigurationError)
        if found:
            failures[name] = found
        fresh_server._CONFIGURATION = None
    process = dict(_environment(), **{key: value for key, value in good.items()})
    process[fresh_server.STORE_VARIABLE] = str(tmp_path / "missing.sqlite")
    code, out, err = launch([], "netops_auditor.mcp_server", process)
    found = verdict(code, out, err, COMMAND_CODES)
    if found or code != 2:
        failures["process with a missing store"] = found or "exit code %r" % code
    clean(failures)


TOOL_CALLS = {
    "audit_status": {"device": DEVICE, "stale_after_hours": 26},
    "list_rules": {},
    "rule_detail": {"rule_id": "fortios.mgmt.idle-timeout"},
    "list_findings": {"device": DEVICE, "severity": "high", "state": "new", "since": "2026-01-01T00:00:00Z",
                      "group_by": "object"},
    "finding_detail": {"device": DEVICE, "fingerprint": "0" * 64},
    "compare": {"device": DEVICE, "first_run_id": 1, "second_run_id": 1},
}


def _tool_variants(arguments):
    yield "base", arguments
    for name in arguments:
        for label, value in WRONG.items():
            yield "%s=%s" % (name, label), dict(arguments, **{name: value})
        yield "%s missing" % name, {key: value for key, value in arguments.items() if key != name}
    yield "extra argument", dict(arguments, unexpected_argument=1)


class Traced(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        if record.exc_info:
            self.records.append(record.getMessage()[:200])


def tool_outcome(server, tool, arguments, traced):
    from fastmcp.exceptions import ToolError, ValidationError

    del traced.records[:]
    try:
        bounded(lambda: asyncio.run(server.mcp.call_tool(tool, arguments)))
    except ValidationError:
        pass
    except ToolError as error:
        if str(error).startswith("Error calling tool"):
            return "unexpected exception wrapped by FastMCP: %s" % str(error)[:300]
        if len(str(error)) > MAX_MESSAGE:
            return "a refusal of %d characters repeats the input" % len(str(error))
    except Hang:
        return "no answer within %d s" % SECONDS
    except Exception as error:
        return "%s: %s" % (type(error).__name__, str(error)[:300])
    if traced.records:
        return "traceback logged: %s" % traced.records[0]
    return None


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


def test_every_mcp_tool_answers_broken_arguments_with_a_tool_error(tmp_path, capsys, traced, fresh_server):
    fresh_server.configure(_configured(tmp_path, capsys))
    failures = {}
    for tool, arguments in TOOL_CALLS.items():
        for name, variant in _tool_variants(arguments):
            found = tool_outcome(fresh_server, tool, variant, traced)
            if found:
                failures["%s %s" % (tool, name)] = found
    clean(failures)
