"""Broken-input matrix over every parser and every input of netops-core.

The inventory, the vault, host key pins and scans, platform names, legacy SSH profiles, the SSH,
SFTP and session arguments, the SFTP listing, the prompt cleaner, the audit recorder and the
askpass program each receive the same family of broken shapes: an empty file, binary bytes,
invalid UTF-8, a byte order mark, CRLF, CR, U+2028 and NUL line breaks, an extremely long line,
deep nesting, duplicate keys, wrong types, Unicode digits, missing and extra fields, a truncated
document and, where the input is a path, a symbolic link, a FIFO or a directory in place of a
file. Every function either accepts the input or raises its own error class; it never raises
anything else and never hangs.
"""

import json
import os
import resource
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from netops_core import audit, hostkey, inventory, legacy_ssh, platforms, prompt, session, sftp, ssh, vault

COMPONENT = Path(__file__).resolve().parents[1]
SECONDS = 60
DEPTH = 100000
LONG = 4 * 1024 * 1024
MEMORY = 2 * 1024 * 1024 * 1024
PIN = "SHA256:" + "A" * 43
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
INVENTORY = {
    "version": 2,
    "devices": [
        {
            "name": "fw-a.example.invalid",
            "platform": "fortios",
            "address": "192.0.2.10",
            "port": 22,
            "role": "perimetr",
            "credential": "fw-a-ro",
            "host_key_fingerprint": PIN,
            "legacy_ssh": "rsa-sha1",
            "auditor": {"channel": "ssh", "required_sections": ["system global"]},
            "helper": {"account_role": "read-only"},
        },
    ],
}
VAULT = {
    "version": 2,
    "credentials": {
        "fw-a-ro": {"kind": "password", "login": "audit-ro", "value": "replace-me"},
        "fw-a-key": {
            "kind": "ssh-key",
            "login": "audit-ro",
            "value": "-----BEGIN OPENSSH PRIVATE KEY-----\nreplace-me\n-----END OPENSSH PRIVATE KEY-----\n",
        },
        "fw-a-api": {"kind": "api-token", "value": "replace-me"},
    },
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


def path_shapes(directory, valid, mode=0o644):
    root = Path(tempfile.mkdtemp(prefix="paths-", dir=str(directory)))
    target = root / "valid"
    target.write_bytes(valid)
    target.chmod(mode)
    folder = root / "directory"
    folder.mkdir()
    fifo = root / "fifo"
    os.mkfifo(fifo, 0o600)
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
    result = {name: str(path) for name, path in shapes.items()}
    result["nul-in-name"] = str(root / "a") + "\x00b"
    return result


def file_shapes(directory, document, mode=0o644):
    shapes = {name: text.encode("utf-8") for name, text in json_shapes(document).items()}
    shapes.update(byte_shapes(json.dumps(document, indent=1)))
    result = {}
    for index, (name, data) in enumerate(shapes.items()):
        path = directory / ("shape-%d.json" % index)
        path.write_bytes(data)
        path.chmod(mode)
        result[name] = str(path)
    return result


def test_inventory_load_raises_only_inventory_errors(tmp_path):
    valid = tmp_path / "valid.json"
    valid.write_text(json.dumps(INVENTORY), encoding="utf-8")
    assert len(inventory.load(valid)) == 1
    failures = {}
    shapes = file_shapes(tmp_path, INVENTORY)
    shapes.update({"path " + name: path for name, path in path_shapes(tmp_path, valid.read_bytes()).items()})
    for name, path in shapes.items():
        found = library(lambda: inventory.load(path), inventory.InventoryError)
        if found:
            failures[name] = found
    devices = inventory.load(valid)
    for name, value in WRONG.items():
        for call in (lambda: inventory.device(devices, value), lambda: inventory.for_consumer(devices, value)):
            found = library(call, inventory.InventoryError)
            if found:
                failures["lookup " + name] = found
    clean(failures)


def test_vault_load_raises_only_vault_errors(tmp_path):
    valid = tmp_path / "valid.json"
    valid.write_text(json.dumps(VAULT), encoding="utf-8")
    valid.chmod(0o600)
    assert vault.load(valid).credential("fw-a-ro").kind == "password"
    failures = {}
    shapes = file_shapes(tmp_path, VAULT, 0o600)
    shapes.update({"path " + name: path for name, path in path_shapes(tmp_path, valid.read_bytes(), 0o600).items()})
    for name, path in shapes.items():
        found = library(lambda: vault.load(path).credential("fw-a-ro").use(), vault.VaultError)
        if found:
            failures[name] = found
    for name, value in WRONG.items():
        for label, call in (
            ("names", lambda: vault.load(valid, names=value)),
            ("names-list", lambda: vault.load(valid, names=[value])),
            ("credential", lambda: vault.load(valid).credential(value)),
        ):
            found = library(call, vault.VaultError)
            if found:
                failures["%s %s" % (label, name)] = found
    clean(failures)


def _text_values():
    values = dict(WRONG)
    values.update({"pin-superscript": "SHA256:" + "\u00b2" * 43, "pin-short": "SHA256:" + "A" * 42,
                   "pin-long": PIN + "A", "pin-lowercase-prefix": "sha256:" + "A" * 43,
                   "pin-separator": PIN[:-1] + "\u2028", "pin-nul": PIN[:-1] + "\x00"})
    return values


def test_host_key_functions_raise_only_host_key_errors(tmp_path):
    failures = {}
    lines = ["198.51.100.1 ssh-ed25519 cmVwbGFjZS1tZQ==", "# comment", ""]
    for name, value in _text_values().items():
        calls = {
            "checked_pin": lambda: hostkey.checked_pin(value),
            "fingerprint_of": lambda: hostkey.fingerprint_of(value),
            "keyscan host": lambda: hostkey.keyscan_argv(value, 22, 5),
            "keyscan port": lambda: hostkey.keyscan_argv("192.0.2.1", value, 5),
            "keyscan timeout": lambda: hostkey.keyscan_argv("192.0.2.1", 22, value),
            "keyscan type": lambda: hostkey.keyscan_argv("192.0.2.1", 22, 5, value),
            "matching pin": lambda: hostkey.matching_line(lines, value),
            "matching lines": lambda: hostkey.matching_line(value, PIN),
            "matching line": lambda: hostkey.matching_line([value], PIN),
            "known_hosts line": lambda: hostkey.known_hosts_file(str(tmp_path), value),
        }
        for label, call in calls.items():
            found = library(call, hostkey.HostKeyError)
            if found:
                failures["%s %s" % (label, name)] = found
    for name, data in byte_shapes("\n".join(lines) + "\n").items():
        text = data.decode("utf-8", "replace")
        found = library(lambda: hostkey.matching_line(text.splitlines(), PIN), hostkey.HostKeyError)
        if found:
            failures["scan output " + name] = found
    clean(failures)


def test_platform_and_legacy_profile_names_raise_only_their_errors():
    failures = {}
    for name, value in _text_values().items():
        for label, call, refusal in (
            ("platform", lambda: platforms.normalize(value), platforms.PlatformError),
            ("legacy", lambda: legacy_ssh.checked(value), legacy_ssh.LegacySshError),
            ("legacy options", lambda: legacy_ssh.openssh_options(value), legacy_ssh.LegacySshError),
        ):
            found = library(call, refusal)
            if found:
                failures["%s %s" % (label, name)] = found
    clean(failures)


def test_client_arguments_raise_only_client_errors():
    good = {"host": "192.0.2.1", "port": 22, "login": "audit-ro", "known_hosts": "/nonexistent/known_hosts",
            "command": "get system status"}
    failures = {}
    for field in good:
        for name, value in WRONG.items():
            arguments = dict(good, **{field: value})
            calls = {
                "ssh": (lambda: ssh.argv(**arguments), ssh.SshError),
                "sftp": (lambda: sftp.argv(**{key: item for key, item in arguments.items() if key != "command"}),
                         sftp.SftpError),
                "session": (lambda: session.argv(**{key: item for key, item in arguments.items() if key != "command"}),
                            (session.SessionError, ssh.SshError)),
            }
            for label, (call, refusal) in calls.items():
                if label != "ssh" and field == "command":
                    continue
                found = library(call, refusal)
                if found:
                    failures["%s %s=%s" % (label, field, name)] = found
    for name, value in _text_values().items():
        for label, call, refusal in (
            ("remote path", lambda: sftp._checked_remote_path(value), sftp.SftpError),
            ("remote path below root", lambda: sftp._checked_remote_path("/" + str(value)), sftp.SftpError),
            ("session patterns", lambda: session._checked_patterns(value), session.SessionError),
            ("session pattern", lambda: session._checked_patterns([value]), session.SessionError),
        ):
            found = library(call, refusal)
            if found:
                failures["%s %s" % (label, name)] = found
    clean(failures)


def test_device_output_parsers_never_raise_on_broken_output():
    listing = "sftp> ls -ln /data\n-rw-r--r--    1 0 0 1024 Jan 1 00:00 /data/file\n"
    failures = {}
    for name, data in byte_shapes(listing).items():
        found = library(lambda: [sftp._listed(line) for line in sftp._listing(data)], sftp.SftpError)
        if found:
            failures["sftp listing " + name] = found
        text = data.decode("utf-8", "replace")
        for platform in ("fortios", "exos", "fortinet", None, 1, "unknown"):
            found = library(lambda: prompt.cleaned("fw-a # " + text + "\nfw-a # \n", platform), ())
            if found:
                failures["prompt %r %s" % (platform, name)] = found
    for name, value in _text_values().items():
        if isinstance(value, str):
            found = library(lambda: sftp._listed("-rw-r--r-- 1 0 0 %s Jan 1 00:00 /data/file" % value), ())
            if found:
                failures["sftp size " + name] = found
    clean(failures)


def test_sftp_listing_reads_only_ascii_digits_as_a_size():
    for size in ("\u0663", "\uff11", "1_000", "+1", "9" * 5000):
        assert sftp._listed("-rw-r--r-- 1 0 0 %s Jan 1 00:00 /data/file" % size) is None, size
    assert sftp._listed("-rw-r--r-- 1 0 0 1024 Jan 1 00:00 /data/file")[2] == 1024


def _deep(depth):
    value = []
    for _ in range(depth):
        value = [value]
    return value


def test_audit_recorder_raises_only_audit_errors(tmp_path):
    refusals = (audit.AuditFieldError, audit.AuditPersistenceError)
    failures = {}
    for name, path in path_shapes(tmp_path, b"").items():
        found = library(lambda: audit.Recorder(path, "helper").record("probe", status="ok"), refusals)
        if found:
            failures["path " + name] = found
    recorder = audit.Recorder(tmp_path / "audit.jsonl", "helper")
    values = dict(WRONG, unserializable=object(), surrogate="\ud800")
    for name, value in values.items():
        for label, call in (
            ("event", lambda: recorder.record(value)),
            ("status", lambda: recorder.record("probe", status=value)),
            ("operation_id", lambda: recorder.record("probe", operation_id=value)),
            ("detail", lambda: recorder.record("probe", detail=value)),
            ("component", lambda: audit.Recorder(tmp_path / "other.jsonl", value)),
            ("path", lambda: audit.Recorder(value, "helper")),
            ("segment_bytes", lambda: audit.Recorder(tmp_path / "other.jsonl", "helper", segment_bytes=value)),
        ):
            found = library(call, refusals)
            if found:
                failures["%s %s" % (label, name)] = found
    found = library(lambda: recorder.record("probe", detail=_deep(DEPTH)), refusals)
    if found:
        failures["detail deep"] = found
    clean(failures)


def _limited():
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY, MEMORY))


def _askpass(environment, codes=(0, 1)):
    try:
        done = subprocess.run(
            [sys.executable, "-B", str(COMPONENT / "src" / "netops_core" / "askpass.py")],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=SECONDS, env=environment,
            preexec_fn=_limited,
        )
    except subprocess.TimeoutExpired:
        return "no answer within %d s" % SECONDS
    text = (done.stdout + done.stderr).decode("utf-8", "replace")
    if "Traceback" in text:
        return "traceback: %s" % text.strip().splitlines()[-1][:300]
    if done.returncode not in codes:
        return "exit code %r outside %s" % (done.returncode, codes)
    if done.returncode == 1 and not done.stderr.strip():
        return "refused without a message"
    return None


def test_askpass_program_answers_a_broken_secret_file_without_a_traceback(tmp_path):
    base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    failures = {}
    found = _askpass(base)
    if found:
        failures["variable missing"] = found
    for name, path in path_shapes(tmp_path, b"replace-me\n", 0o600).items():
        if "\x00" in path:
            continue
        found = _askpass(dict(base, NETOPS_ASKPASS_FILE=path), (0,) if name == "symlink" else (1,))
        if found:
            failures[name] = found
    for name, value in (("empty", ""), ("relative", "secret"), ("separator", "a\u2028b")):
        found = _askpass(dict(base, NETOPS_ASKPASS_FILE=value), (1,))
        if found:
            failures[name] = found
    clean(failures)


def test_unpaired_surrogate_escapes_are_refused_by_the_inventory_and_the_vault(tmp_path):
    broken = json.dumps(INVENTORY).replace("fw-a.example.invalid", "fw-a\\ud800.example.invalid")
    path = tmp_path / "inventory.json"
    path.write_text(broken, encoding="utf-8")
    with pytest.raises(inventory.InventoryError, match="unpaired surrogate"):
        inventory.load(path)
    broken = json.dumps(VAULT).replace("audit-ro", "audit\\ud800-ro", 1)
    path = tmp_path / "vault.json"
    path.write_text(broken, encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(vault.VaultError, match="unpaired surrogate"):
        vault.load(path)
