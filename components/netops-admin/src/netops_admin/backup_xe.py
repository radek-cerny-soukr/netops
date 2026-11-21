"""Local, encrypted backup of the Cisco IOS XE running configuration."""

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

MAGIC = b"NETOPS-IOS-XE-BACKUP\x00\x01"
MAX_BYTES = ssh.CAPTURE_MAX_BYTES
COMMAND = "show running-config"
HEADER = re.compile(rb"\ABuilding configuration\.\.\.[ \t]*\n[ \t\n]*"
                    rb"Current configuration : ([1-9][0-9]{0,11}) bytes[ \t]*\n")
VERSION = re.compile(rb"(?m)^version [0-9]+(?:\.[0-9]+)+[ \t]*$")
HOSTNAME = re.compile(rb"(?m)^hostname [A-Za-z0-9][A-Za-z0-9._-]{0,62}[ \t]*$")
UNUSABLE = re.compile(rb"--[ \t]*More[ \t]*--|^%|^Line has invalid autocommand|[\x00\x08\x1b\r]", re.M | re.I)
XE_VERSION = re.compile(r"(?m)^Cisco IOS XE Software, Version ([0-9]+\.[0-9]+\.[0-9]+[a-z]{0,2})[ \t]*$")
AUDIT_TIME = r"[0-9]{8}T[0-9]{6}Z"
TESTED = ("17.18.2 (X86_64BI_LINUX-ADVENTERPRISEK9-M)", "17.18.2 (X86_64BI_LINUX_L2-ADVENTERPRISEK9-M)")


def _endpoint(host, port):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", host) or not 1 <= port <= 65535:
        raise backup._reject("backup_request_invalid", "Invalid Cisco IOS XE backup endpoint")
    return "xe-" + hashlib.sha256(f"{host.lower()}:{port}".encode()).hexdigest()[:32]


def _body(data):
    if (len(data) > MAX_BYTES or not data.startswith(b"!\n") or not data.endswith(b"\nend\n")
            or UNUSABLE.search(data) or not VERSION.search(data) or not HOSTNAME.search(data)):
        raise backup._reject("backup_incomplete", "Cisco IOS XE configuration body is incomplete or unrecognized")
    return data


def _configuration(data):
    normalized = data.replace(b"\r\n", b"\n").lstrip(b" \t\n")
    if ios.refused(normalized[:256].decode("utf-8", "replace")):
        raise backup._reject("backup_refused", "Cisco IOS XE refused the running configuration read")
    header = HEADER.match(normalized)
    if header is None or len(data) > MAX_BYTES:
        raise backup._reject("backup_incomplete", "Cisco IOS XE running configuration size header is missing")
    body = _body(normalized[header.end():].lstrip(b" \t\n"))
    # Both measured IOL XE images report one extra final newline in the file length.
    if int(header[1]) not in (len(body), len(body) + 1):
        raise backup._reject("backup_incomplete", "Cisco IOS XE configuration size differs from the reported size")
    return body


def _read(host, port, credential, pinned, command, legacy, maximum):
    try:
        result = ssh.run_command(host, port, credential.login, credential, pinned, command, legacy_ssh=legacy,
                                 timeout_seconds=30, capture_max_bytes=maximum, suppress_login_banner=True)
    except ssh.OutputLimitError:
        raise backup._reject("backup_incomplete", "Cisco IOS XE exceeded the capture limit") from None
    except ssh.SshError:
        raise backup._reject("backup_transport_failed", "Cisco IOS XE SSH connection or transfer failed") from None
    if result.rc != 0:
        raise backup._reject("backup_refused", "Cisco IOS XE rejected the backup read")
    return result.stdout


def _firmware(raw):
    text = raw.decode("utf-8", "replace").replace("\r\n", "\n")
    try:
        firmware = ios.version(text)
    except Rejected:
        firmware = None
    if firmware and firmware["xe"] and re.fullmatch(r"[A-Za-z0-9_.():-]{1,96}", firmware["version"]):
        image = firmware["image"]
        if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", image):
            return f"{firmware['version']} ({image})"
    if match := XE_VERSION.search(text):
        return match[1]
    raise backup._reject("backup_identity_mismatch", "The target did not report a Cisco IOS XE identity")


def run(host, port, login, pin, directory, keep, confirmation, *, legacy=None):
    prefix = _endpoint(host, port)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", login) or not 1 <= keep <= 365:
        raise backup._reject("backup_request_invalid", "Invalid Cisco IOS XE backup login or retention")
    try:
        hostkey.checked_pin(pin)
        legacy_ssh.checked(legacy)
    except (hostkey.HostKeyError, legacy_ssh.LegacySshError):
        raise backup._reject("backup_request_invalid", "Invalid Cisco IOS XE SSH pin or legacy SSH profile") from None
    destination = backup._backup_destination(directory)
    plan = dict(platform="cisco_xe", host=host, port=port, login=login, ssh_sha256=pin,
                directory=str(destination), keep=keep, legacy_ssh=legacy)
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
    if confirmation is None:
        return {"result": "ready", "plan_sha256": digest, "plan": plan}
    if not compare_digest(confirmation.encode(), digest.encode()):
        raise backup._reject("plan_changed", "The Cisco IOS XE backup confirmation differs from the current plan")
    key = backup._key()
    try:
        credential = vault.Credential("xe-backup", "password", os.environ.get("NETOPS_BACKUP_PASSWORD", ""), login=login)
    except vault.VaultError:
        raise backup._reject("backup_credentials_unavailable", "Set NETOPS_BACKUP_PASSWORD for Cisco IOS XE") from None
    try:
        pinned = hostkey.scan(host, port, pin, 10, legacy=legacy)
    except hostkey.HostKeyUnavailable:
        raise backup._reject("backup_transport_failed", "Could not obtain the Cisco IOS XE SSH host key") from None
    except hostkey.HostKeyError:
        raise backup._reject("backup_identity_mismatch", "Cisco IOS XE SSH host key did not match the pin") from None
    version = _firmware(_read(host, port, credential, pinned, "show version", legacy, 65536))
    data = _configuration(_read(host, port, credential, pinned, COMMAND, legacy, MAX_BYTES))
    if backup._backup_destination(directory) != destination:
        raise backup._reject("backup_destination_unsafe", "The backup destination changed after confirmation")
    name, retained, _, sealed = backup._save(destination, prefix, data, keep, key, magic=MAGIC)
    support = tested.support("Cisco IOS XE", version, TESTED, function="running configuration backup")
    result = {"result": "confirmed", "artifact": name, "retention_ok": retained,
              "firmware_support": support, **backup._metrics(sealed)}
    if warning := tested.warning(support):
        result["warnings"] = [warning]
    return result


def status(host, port, directory):
    prefix = _endpoint(host, port)
    destination = backup._backup_destination(directory)
    pattern = re.compile(re.escape(prefix) + rf"-({AUDIT_TIME})-[a-f0-9]{{32}}\.netops-backup")
    try:
        fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            newest = max((path for path in destination.iterdir() if pattern.fullmatch(path.name)),
                         key=lambda path: path.lstat().st_mtime_ns, default=None)
            if newest is None:
                return {"result": "missing", "last_backup": None}
            _body(backup._read_backup(newest, backup._key(), magic=MAGIC, maximum=MAX_BYTES))
        finally:
            os.close(fd)
    except OSError:
        raise backup._reject("backup_storage_failed", "Could not read the Cisco IOS XE backup directory") from None
    return {"result": "confirmed", "last_backup": pattern.fullmatch(newest.name)[1], "artifact": newest.name}


def unseal(source, output):
    backup._backup_destination(source.parent)
    destination = backup._backup_destination(output.parent)
    data = _body(backup._read_backup(source, backup._key(), magic=MAGIC, maximum=MAX_BYTES))
    if backup._backup_destination(output.parent) != destination:
        raise backup._reject("backup_destination_unsafe", "The restore destination changed before writing")
    try:
        write_private(Path(destination, output.name), data)
    except (OSError, RuntimeError):
        raise backup._reject("backup_storage_failed", "Could not create the private Cisco IOS XE restore file") from None
    return {"result": "confirmed", "bytes": len(data)}
