"""Local encrypted NX-OS backup and private restore-file export."""

import fcntl
import hashlib
from hmac import compare_digest
import json
import os
from pathlib import Path
import re

from netops.files import read_private, write_private
from netops_core import hostkey, nxos_config, ssh, tested
from netops_core.vault import Credential, VaultError

from . import backup
from .errors import Rejected

MAGIC = b"NETOPS-NXOS-BACKUP\x00\x01"
COMMAND = "show running-config"
COUNT = COMMAND + " | count"
TESTED = ("Nexus9000 C9300v", "9.3(12)")
MAX_BYTES = ssh.CAPTURE_MAX_BYTES
_HEADER = b"!Command: " + COMMAND.encode("ascii")
_CONTROL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)")
_UNUSABLE = re.compile(rb"(?mi)--\s*More\s*--|^% |^Cmd exec error\.|<UNVERIFIED:|<removed>")
_REQUIRED = re.compile(rb"(?m)^(version|hostname|interface) [^\r\n]+")


def _plan(host, port, login, pin, directory, keep):
    try:
        hostkey.checked_pin(pin)
    except hostkey.HostKeyError:
        raise backup._reject("backup_request_invalid", "An OpenSSH SHA256 host-key fingerprint is required") from None
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", host) or not 1 <= port <= 65535
            or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", login) or not 1 <= keep <= 365):
        raise backup._reject("backup_request_invalid", "Invalid NX-OS backup target, login or retention")
    directory = backup._backup_destination(directory)
    plan = dict(platform="cisco_nxos", host=host, port=port, login=login, ssh_host_key=pin,
                directory=str(directory), keep=keep)
    return plan, hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()


def _read(host, port, login, credential, known_host, command, maximum):
    try:
        result = ssh.run_command(host, port, login, credential, known_host, command,
                                 timeout_seconds=30, capture_max_bytes=maximum)
    except ssh.OutputLimitError:
        raise backup._reject("backup_incomplete", "NX-OS backup response exceeded the capture limit") from None
    except ssh.SshError:
        raise backup._reject("backup_transport_failed", "NX-OS SSH connection or transfer failed") from None
    if result.rc != 0:
        raise backup._reject("backup_refused", "NX-OS refused a backup read")
    return result.stdout


def _validate(data):
    head, newline, body = data.lstrip(b"\r\n").partition(b"\n")
    if (not newline or head.rstrip(b"\r ") != _HEADER or len(data) > MAX_BYTES or not data.endswith(b"\n")
            or _CONTROL.search(data) or _UNUSABLE.search(data)
            or set(_REQUIRED.findall(body)) != {b"version", b"hostname", b"interface"}):
        raise backup._reject("backup_incomplete", "NX-OS configuration framing or required sections are incomplete")


def _export(host, port, login, pin):
    try:
        credential = Credential("nxos-backup", "password", os.environ.get("NETOPS_BACKUP_PASSWORD", ""), login=login)
    except VaultError:
        raise backup._reject("backup_credentials_unavailable", "Set NETOPS_BACKUP_PASSWORD for the NX-OS backup account") from None
    try:
        known_host = hostkey.scan(host, port, pin, 10)
    except hostkey.HostKeyUnavailable:
        raise backup._reject("backup_transport_failed", "Could not obtain the NX-OS SSH host key") from None
    except hostkey.HostKeyError:
        raise backup._reject("backup_identity_mismatch", "NX-OS SSH host key did not match the configured pin") from None
    version = _read(host, port, login, credential, known_host, "show version", nxos_config.IDENTITY_MAX_BYTES)
    try:
        firmware = nxos_config.version_identity(version.decode("utf-8"))
    except ValueError:
        raise backup._reject("backup_identity_mismatch", "NX-OS did not report a verifiable identity") from None
    data = _read(host, port, login, credential, known_host, COMMAND, MAX_BYTES)
    _validate(data)
    count = _read(host, port, login, credential, known_host, COUNT, 65536)
    if nxos_config.line_count(count.decode("ascii", "replace")) != data.count(b"\n"):
        raise backup._reject("backup_incomplete", "NX-OS configuration line count did not match")
    return data, firmware


def _prefix(host, port, pin):
    return "nxos-" + hashlib.sha256(f"{host.lower()}:{port}:{pin}".encode()).hexdigest()[:32]


def _status(directory, prefix, key, keep):
    pattern = re.compile(re.escape(prefix) + r"-([0-9]{8}T[0-9]{6}Z)-[a-f0-9]{32}\.netops-backup")
    count = 0
    invalid = 0
    latest = None
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            for path in directory.iterdir():
                if not (match := pattern.fullmatch(path.name)):
                    continue
                try:
                    modified = path.lstat().st_mtime_ns
                    data = backup._read_backup(path, key, magic=MAGIC, maximum=MAX_BYTES)
                    _validate(data)
                except (OSError, Rejected):
                    invalid += 1
                    continue
                count += 1
                if latest is None or modified > latest[0]:
                    latest = (modified, path.name, match[1])
        finally:
            os.close(fd)
    except OSError:
        raise backup._reject("backup_storage_failed", "Could not inspect the private NX-OS backup directory") from None
    return dict(result="available" if latest else "unverified" if invalid else "missing",
                artifact=latest[1] if latest else None, created_at=latest[2] if latest else None,
                retained=count, unverified=invalid, retention_ok=not invalid and count <= keep)


def run(host, port, login, pin, directory, keep, confirmation, *, status=False):
    plan, digest = _plan(host, port, login, pin, directory, keep)
    prefix = _prefix(host, port, pin)
    if status:
        return _status(Path(plan["directory"]), prefix, backup._key(), keep)
    if confirmation is None:
        return dict(result="ready", plan=plan, plan_sha256=digest)
    if not compare_digest(confirmation.encode(), digest.encode()):
        raise backup._reject("plan_changed", "The backup confirmation does not match the current plan")
    key = backup._key()
    data, (model, version) = _export(host, port, login, pin)
    destination = backup._backup_destination(directory)
    if destination != Path(plan["directory"]):
        raise backup._reject("backup_destination_unsafe", "The backup destination changed after confirmation")
    name, retention_ok, _, sealed = backup._save(destination, prefix, data, keep, key, magic=MAGIC, verify_readback=True)
    support = tested.support("Cisco NX-OS", version, [TESTED], model=model, function="configuration backup")
    created_at = name.removeprefix(prefix + "-").partition("-")[0]
    result = dict(result="confirmed", artifact=name, retention_ok=retention_ok, firmware_support=support,
                  created_at=created_at, **backup._metrics(sealed))
    if warning := tested.warning(support):
        result["warnings"] = [warning]
    return result


def unseal(source, output):
    directory = backup._backup_destination(output.parent)
    backup._backup_destination(source.parent)
    data = backup._read_backup(source, backup._key(), magic=MAGIC, maximum=MAX_BYTES)
    _validate(data)
    if backup._backup_destination(output.parent) != directory:
        raise backup._reject("backup_destination_unsafe", "The restore destination changed before writing")
    path = directory / output.name
    try:
        write_private(path, data)
        if read_private(path, MAX_BYTES, owner=os.getuid()) != data:
            raise backup._reject("backup_storage_failed", "Private NX-OS restore file readback did not match")
    except (OSError, RuntimeError):
        raise backup._reject("backup_storage_failed", "Could not create a private NX-OS restore file") from None
    return dict(result="confirmed", **backup._metrics(data))
