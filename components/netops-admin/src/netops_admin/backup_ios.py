"""Local encrypted Cisco IOS running configuration backup."""

import fcntl
import hashlib
from hmac import compare_digest
import json
import os
from pathlib import Path
import re

from netops.files import write_private
from netops_core import hostkey, legacy_ssh, ssh, tested, vault

from . import backup, ios
from .errors import Rejected

LEGACY_MAGIC = b"NETOPS-IOS-BACKUP\x00\x01"
MAGIC = b"NETOPS-IOS-BACKUP\x00\x02"
MAX_BYTES = ssh.CAPTURE_MAX_BYTES
MAX_METADATA = 320
COMMAND = "show running-config"
ARCHIVE_IDENTITY = re.compile(rb"([a-z0-9][a-z0-9.:-]{0,252}:[1-9][0-9]{0,4}) (SHA256:[A-Za-z0-9+/]{43})")
HEADER = re.compile(rb"\ABuilding configuration\.\.\.[ \t]*\n[ \t\n]*"
                    rb"Current configuration[ ]*:[ ]*([1-9][0-9]{0,8}) bytes[ \t]*\n")
VERSION = re.compile(rb"(?m)^version ([0-9]+\.[0-9]+)(?:\.[0-9]+)*[ \t]*$")
HOSTNAME = re.compile(rb"(?m)^hostname [^ \t\n]+[ \t]*$")
UNUSABLE = re.compile(rb"--[ \t]*More[ \t]*--|^% |^Line has invalid autocommand|[\x00\x08\x1b]", re.M | re.I)
AUDIT_TIME = re.compile(r"[0-9]{8}T[0-9]{6}Z")


def _endpoint(host, port):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", host) or not 1 <= port <= 65535:
        raise backup._reject("backup_request_invalid", "Invalid Cisco IOS backup endpoint")
    return f"{host.lower()}:{port}"


def _endpoint_prefix(endpoint):
    return "ios-" + hashlib.sha256(endpoint.encode("ascii")).hexdigest()[:32]


def _archive_prefix(endpoint, pin):
    return _endpoint_prefix(endpoint) + "-" + hashlib.sha256(pin.encode("ascii")).hexdigest()[:32]


def _read_archive(source, key):
    data = backup._read_backup(source, key, magic=MAGIC, maximum=MAX_BYTES + MAX_METADATA)
    header, separator, config = data.partition(b"\n")
    identity = ARCHIVE_IDENTITY.fullmatch(header)
    if not separator or identity is None:
        raise backup._reject("backup_invalid", "Could not verify the encrypted Cisco IOS backup identity")
    return identity[1].decode("ascii"), identity[2].decode("ascii"), config


def _body(data):
    if (len(data) > MAX_BYTES or not data.startswith(b"!\n") or not data.endswith(b"\nend\n")
            or UNUSABLE.search(data) or not VERSION.search(data) or not HOSTNAME.search(data)):
        raise backup._reject("backup_incomplete", "Cisco IOS configuration body is incomplete or unrecognized")
    return data


def _configuration(data):
    normalized = data.replace(b"\r\r\n", b"\n").replace(b"\r\n", b"\n")
    normalized = normalized.lstrip(b" \t\n")
    if ios.refused(normalized[:256].decode("utf-8", "replace")):
        raise backup._reject("backup_refused", "Cisco IOS refused the running configuration read")
    header = HEADER.match(normalized)
    if header is None or len(data) > MAX_BYTES:
        raise backup._reject("backup_incomplete", "Cisco IOS running configuration size header is missing")
    body = _body(normalized[header.end():])
    # IOSv and IOSvL2 report the configuration-file count with small differences
    # from the exact CLI representation (respectively +5 and -4 bytes on the lab).
    if abs(len(body) - int(header[1])) > 8:
        raise backup._reject("backup_incomplete", "Cisco IOS configuration size differs from the reported size")
    return body


def _read(host, port, credential, pinned, command, legacy):
    try:
        result = ssh.run_command(host, port, credential.login, credential, pinned, command, legacy_ssh=legacy,
                                 timeout_seconds=30, capture_max_bytes=MAX_BYTES, suppress_login_banner=True)
    except ssh.OutputLimitError:
        raise backup._reject("backup_incomplete", "Cisco IOS output exceeded the capture limit") from None
    except ssh.SshError:
        raise backup._reject("backup_transport_failed", "Cisco IOS SSH connection or transfer failed") from None
    if result.rc != 0:
        raise backup._reject("backup_refused", "Cisco IOS rejected the backup read")
    return result.stdout


def run(host, port, login, pin, directory, keep, confirmation, *, legacy=None):
    endpoint = _endpoint(host, port)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", login) or not 1 <= keep <= 365:
        raise backup._reject("backup_request_invalid", "Invalid Cisco IOS backup login or retention")
    try:
        hostkey.checked_pin(pin)
        legacy_ssh.checked(legacy)
    except (hostkey.HostKeyError, legacy_ssh.LegacySshError):
        raise backup._reject("backup_request_invalid", "Invalid Cisco IOS SSH pin or legacy SSH profile") from None
    destination = backup._backup_destination(directory)
    plan = dict(platform="cisco_ios", host=host, port=port, login=login, ssh_sha256=pin,
                directory=str(destination), keep=keep, legacy_ssh=legacy)
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
    if confirmation is None:
        return {"result": "ready", "plan_sha256": digest, "plan": plan}
    if not compare_digest(confirmation.encode(), digest.encode()):
        raise backup._reject("plan_changed", "The Cisco IOS backup confirmation does not match the current plan")
    key = backup._key()
    try:
        credential = vault.Credential("ios-backup", "password", os.environ.get("NETOPS_BACKUP_PASSWORD", ""), login=login)
    except vault.VaultError:
        raise backup._reject("backup_credentials_unavailable", "Set NETOPS_BACKUP_PASSWORD for Cisco IOS") from None
    try:
        pinned = hostkey.scan(host, port, pin, 10, legacy=legacy)
    except hostkey.HostKeyError:
        raise backup._reject("backup_identity_mismatch", "Could not verify the Cisco IOS SSH host key") from None
    version = _read(host, port, credential, pinned, "show version", legacy).decode("utf-8", "replace")
    try:
        firmware = ios.version(version)
    except Rejected:
        raise backup._reject("backup_identity_mismatch", "The target did not report a Cisco IOS identity") from None
    if firmware["xe"] or not re.fullmatch(r"[A-Za-z0-9_.():-]{1,96}", firmware["version"]):
        raise backup._reject("backup_identity_mismatch", "The target did not report a classic Cisco IOS identity")
    data = _configuration(_read(host, port, credential, pinned, COMMAND, legacy))
    if backup._backup_destination(directory) != destination:
        raise backup._reject("backup_destination_unsafe", "The backup destination changed after confirmation")

    def read_previous(path):
        previous_endpoint, previous_pin, config = _read_archive(path, key)
        if (previous_endpoint, previous_pin) != (endpoint, pin):
            raise backup._reject("backup_invalid", "Could not verify the encrypted Cisco IOS backup identity")
        return _body(config)

    payload = f"{endpoint} {pin}\n".encode("ascii") + data
    name, retained, _, sealed = backup._save(destination, _archive_prefix(endpoint, pin), payload, keep, key,
                                            magic=MAGIC, read_previous=read_previous)
    support = tested.support("Cisco IOS", firmware["version"], ["15.9(3)M12", "15.2(20200924:215240)"],
                             function="running configuration backup")
    result = {"result": "confirmed", "artifact": name, "retention_ok": retained,
              "firmware_support": support, **backup._metrics(sealed)}
    if warning := tested.warning(support):
        result["warnings"] = [warning]
    return result


def status(host, port, directory):
    endpoint = _endpoint(host, port)
    prefix = _endpoint_prefix(endpoint)
    destination = backup._backup_destination(directory)
    pattern = re.compile(r"(?P<prefix>" + re.escape(prefix) + r"(?:-[a-f0-9]{32})?)-"
                         r"(?P<stamp>" + AUDIT_TIME.pattern + r")-[a-f0-9]{32}\.netops-backup")
    try:
        fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            newest = max((path for path in destination.iterdir() if pattern.fullmatch(path.name)),
                         key=lambda path: path.lstat().st_mtime_ns, default=None)
            if newest is None:
                return {"result": "missing", "last_backup": None}
            match = pattern.fullmatch(newest.name)
            key = backup._key()
            if match["prefix"] == prefix:
                data = backup._read_backup(newest, key, magic=LEGACY_MAGIC, maximum=MAX_BYTES)
            else:
                archived_endpoint, pin, data = _read_archive(newest, key)
                if archived_endpoint != endpoint or match["prefix"] != _archive_prefix(endpoint, pin):
                    raise backup._reject("backup_invalid", "Could not verify the encrypted Cisco IOS backup identity")
            _body(data)
        finally:
            os.close(fd)
    except OSError:
        raise backup._reject("backup_storage_failed", "Could not read the Cisco IOS backup directory") from None
    return {"result": "confirmed", "last_backup": match["stamp"], "artifact": newest.name}


def unseal(source, output):
    backup._backup_destination(source.parent)
    destination = backup._backup_destination(output.parent)
    key = backup._key()
    try:
        _, _, data = _read_archive(source, key)
    except Rejected:
        data = backup._read_backup(source, key, magic=LEGACY_MAGIC, maximum=MAX_BYTES)
    data = _body(data)
    if backup._backup_destination(output.parent) != destination:
        raise backup._reject("backup_destination_unsafe", "The restore destination changed before writing")
    try:
        write_private(Path(destination, output.name), data)
    except (OSError, RuntimeError):
        raise backup._reject("backup_storage_failed", "Could not create the private Cisco IOS restore file") from None
    return {"result": "confirmed", "bytes": len(data)}
