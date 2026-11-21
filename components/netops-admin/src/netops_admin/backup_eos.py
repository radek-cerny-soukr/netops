"""Local, encrypted Arista EOS configuration backup and private restore-file export."""

import datetime
import fcntl
import hashlib
from hmac import compare_digest
import json
import os
from pathlib import Path
import re
from uuid import uuid4

from netops.files import read_private, sync_directory, write_private
from netops_core import hostkey, ssh, tested
from netops_core.vault import Credential, VaultError

from . import backup, eos
from .errors import Rejected

MAGIC = b"NETOPS-EOS-BACKUP\x00\x01"
MAX_BYTES = ssh.CAPTURE_MAX_BYTES
MAX_METADATA = 4096
COMMAND = "show running-config"
MODEL = re.compile(r"Arista ([A-Za-z0-9][A-Za-z0-9_.+-]{0,63})")
IMAGE = re.compile(r"Software image version: (([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?[A-Z]{1,2})"
                   r"(?:-[A-Za-z0-9.]{1,64})?)(?: \([A-Za-z][A-Za-z ]{0,31}\))?")
CONTROL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
PAGER = re.compile(rb"--\s*More\s*--", re.I)
REQUIRED_CONFIG_LINE = re.compile(rb"^(hostname|interface)[ \t]+\S+[ \t]*\r?$", re.M)


def _plan(host, port, login, pin, directory, keep):
    try:
        hostkey.checked_pin(pin)
    except hostkey.HostKeyError:
        raise backup._reject("backup_request_invalid", "An OpenSSH SHA256 host-key fingerprint is required") from None
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", host) or not 1 <= port <= 65535
            or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", login) or not 1 <= keep <= 365):
        raise backup._reject("backup_request_invalid", "Invalid EOS backup target, login or retention")
    directory = backup._backup_destination(directory)
    plan = dict(platform="arista_eos", host=host, port=port, login=login, ssh_host_key=pin,
                directory=str(directory), keep=keep)
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
    return plan, digest


def _read(host, port, login, credential, known_host, command, maximum):
    try:
        result = ssh.run_command(host, port, login, credential, known_host, command,
                                 timeout_seconds=30, capture_max_bytes=maximum)
    except ssh.OutputLimitError:
        raise backup._reject("backup_incomplete", "EOS backup response exceeded the capture limit") from None
    except ssh.SshError:
        raise backup._reject("backup_transport_failed", "EOS SSH connection or transfer failed") from None
    if result.rc != 0:
        raise backup._reject("backup_refused", "EOS refused a backup read")
    return result.stdout


def _identity(data):
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        lines = []
    models = [match[1] for line in lines if (match := MODEL.fullmatch(line))]
    images = [match for line in lines if (match := IMAGE.fullmatch(line))]
    if len(models) != 1 or len(images) != 1:
        raise backup._reject("backup_identity_mismatch", "The target did not report a verifiable Arista EOS identity")
    return models[0], images[0][2], images[0][1]


def _configuration(data, model, version):
    """Check frame, device identity, size and terminator. Return bytes loadable as an EOS config file."""
    if (not data or len(data) > MAX_BYTES or CONTROL.search(data) or PAGER.search(data)
            or not data.endswith((b"\nend\n", b"\r\nend\r\n"))):
        raise backup._reject("backup_incomplete", "EOS returned an incomplete or oversized configuration")
    lines = data.splitlines(keepends=True)
    first = 0
    while first < len(lines) and not lines[first].strip():
        first += 1
    if first < len(lines) and lines[first].rstrip(b"\r\n") == b"> " + COMMAND.encode("ascii"):
        first += 1
    if first == len(lines) or not eos.COMMAND_HEADER.fullmatch(lines[first].rstrip(b"\r\n").decode("ascii", "replace")):
        raise backup._reject("backup_incomplete", "EOS configuration command header is missing")
    first += 1
    if first < len(lines) and lines[first].startswith(b"! Time: "):
        first += 1
    config = b"".join(lines[first:])
    _verify_config(config, model, version)
    return config


def _verify_config(config, model, version):
    device, delimiter, body = config.partition(b"\n")
    header = eos.DEVICE_LINE.fullmatch(device.rstrip(b"\r").decode("ascii", "replace"))
    if (len(config) > MAX_BYTES or not delimiter or header is None or header.group(2, 3) != (model, version)
            or not body.endswith((b"\nend\n", b"\r\nend\r\n"))
            or re.search(rb"(?m)^% ", body) or PAGER.search(body) or CONTROL.search(body)):
        raise backup._reject("backup_incomplete", "EOS configuration framing or device identity is incomplete")
    if {match[1] for match in REQUIRED_CONFIG_LINE.finditer(body)} != {b"hostname", b"interface"}:
        raise backup._reject("backup_incomplete", "EOS configuration is missing hostname or interface statements")


def _export(host, port, login, pin):
    password = os.environ.get("NETOPS_BACKUP_PASSWORD", "")
    try:
        credential = Credential("eos-backup", "password", password, login=login)
    except VaultError:
        raise backup._reject("backup_credentials_unavailable", "Set NETOPS_BACKUP_PASSWORD for the EOS backup account") from None
    try:
        known_host = hostkey.scan(host, port, pin, 10)
    except hostkey.HostKeyUnavailable:
        raise backup._reject("backup_transport_failed", "Could not obtain the EOS SSH host key") from None
    except hostkey.HostKeyError:
        raise backup._reject("backup_identity_mismatch", "EOS SSH host key did not match the configured pin") from None
    privilege = _read(host, port, login, credential, known_host, "show privilege", 65536)
    try:
        authorized = eos.privilege(privilege.decode("ascii", "replace")) == 15
    except Rejected:
        authorized = False
    if not authorized:
        raise backup._reject("backup_refused", "The EOS backup account must log in at privilege 15")
    model, version, build = _identity(_read(host, port, login, credential, known_host, "show version", 65536))
    config = _configuration(_read(host, port, login, credential, known_host, COMMAND, MAX_BYTES), model, version)
    return config, dict(model=model, version=version, build=build)


def _read_archive(path, key):
    data = backup._read_backup(path, key, magic=MAGIC, maximum=MAX_BYTES + MAX_METADATA)
    header, sep, config = data.partition(b"\n")
    try:
        if not sep or len(header) >= MAX_METADATA:
            raise ValueError()
        metadata = json.loads(header)
        if (set(metadata) != {"model", "version", "build", "created_at", "target_id", "bytes"} or
                type(metadata["bytes"]) is not int or metadata["bytes"] != len(config) or
                MODEL.fullmatch("Arista " + metadata["model"]) is None or
                (match := IMAGE.fullmatch("Software image version: " + metadata["build"])) is None or
                match[2] != metadata["version"] or re.fullmatch(r"[a-f0-9]{32}", metadata["target_id"]) is None or
                not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", metadata["created_at"])):
            raise ValueError()
        _verify_config(config, metadata["model"], metadata["version"])
    except (ValueError, TypeError, KeyError, Rejected):
        raise backup._reject("backup_invalid", "Could not validate the encrypted EOS backup") from None
    return metadata, config


def _publish(directory, key, config, metadata, keep, stamp):
    target = metadata["target_id"]
    prefix = f"eos-{target}-"
    pattern = re.compile(re.escape(prefix) + r"[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}\.netops-backup")
    path = directory / f"{prefix}{stamp}-{uuid4().hex}.netops-backup"
    data = json.dumps(metadata, sort_keys=True).encode() + b"\n" + config
    sealed = backup._seal(data, key, MAGIC)
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            write_private(path, sealed)
            if _read_archive(path, key) != (metadata, config):
                raise backup._reject("backup_storage_failed", "Encrypted EOS backup readback did not match")
            previous = []
            retention_ok = True
            for candidate in directory.iterdir():
                if candidate != path and pattern.fullmatch(candidate.name):
                    try:
                        modified = candidate.lstat().st_mtime_ns
                        old, _ = _read_archive(candidate, key)
                    except (OSError, Rejected):
                        retention_ok = False
                        continue
                    if old["target_id"] == target:
                        previous.append((modified, candidate))
                    else:
                        retention_ok = False
            try:
                for _, candidate in sorted(previous, reverse=True)[keep - 1:]:
                    candidate.unlink()
                sync_directory(directory)
            except OSError:
                retention_ok = False
        finally:
            os.close(fd)
    except (OSError, RuntimeError):
        raise backup._reject("backup_storage_failed", "Could not publish the encrypted EOS backup") from None
    return dict(result="confirmed", artifact=path.name, retention_ok=retention_ok, **backup._metrics(sealed))


def run(host, port, login, pin, directory, keep, confirmation):
    plan, digest = _plan(host, port, login, pin, directory, keep)
    if confirmation is None:
        return dict(result="ready", plan=plan, plan_sha256=digest)
    if not compare_digest(confirmation.encode(), digest.encode()):
        raise backup._reject("plan_changed", "The backup confirmation does not match the current plan")
    key = backup._key()
    config, metadata = _export(host, port, login, pin)
    target = hashlib.sha256(f"{host.lower()}:{port}".encode()).hexdigest()[:32]
    created = datetime.datetime.now(datetime.timezone.utc)
    metadata.update(target_id=target, created_at=created.strftime("%Y-%m-%dT%H:%M:%SZ"), bytes=len(config))
    destination = backup._backup_destination(directory)
    if destination != Path(plan["directory"]):
        raise backup._reject("backup_destination_unsafe", "The backup destination changed after confirmation")
    result = _publish(destination, key, config, metadata, keep, created.strftime("%Y%m%dT%H%M%SZ"))
    support = tested.support("Arista EOS", metadata["version"], [("cEOSLab", "4.36.1F")],
                             model=metadata["model"], function="configuration backup")
    result.update(created_at=metadata["created_at"], firmware_support=support)
    if warning := tested.warning(support):
        result["warnings"] = [warning]
    return result


def unseal(source, output):
    directory = backup._backup_destination(output.parent)
    backup._private_directory(source.parent)
    key = backup._key()
    metadata, config = _read_archive(source, key)
    if backup._backup_destination(output.parent) != directory:
        raise backup._reject("backup_destination_unsafe", "The restore destination changed before writing")
    path = directory / output.name
    try:
        write_private(path, config)
        if read_private(path, MAX_BYTES, owner=os.getuid()) != config:
            raise backup._reject("backup_storage_failed", "Private EOS restore file readback did not match")
    except (OSError, RuntimeError):
        raise backup._reject("backup_storage_failed", "Could not create a private EOS restore file") from None
    return dict(result="confirmed", metadata=metadata, **backup._metrics(config))
