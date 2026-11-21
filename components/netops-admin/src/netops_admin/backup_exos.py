"""Private, versioned exports of native saved ExtremeXOS configurations."""

import hashlib
from hmac import compare_digest
import json
import os
from pathlib import Path
import re
from xml.etree import ElementTree

from netops.files import read_private, write_private
from netops_admin.backup import _backup_destination, _key, _metrics, _read_backup, _reject, _save
from netops_core import hostkey, legacy_ssh, tested, vault
from netops_core.sftp import (DEFAULT_TIMEOUT_SECONDS, EXOS_CONFIG_FILE, EXOS_CONFIG_MAX_BYTES,
                             SftpError, read_exos_configuration)

MAGIC = b"NETOPS-EXOS-BACKUP\x00\x01"
REQUIRED_MODULES = {"xos-module-aaa", "xos-module-cfgmgr", "xos-module-devmgr", "xos-module-vlan"}


def _identity(data):
    if (not 256 <= len(data) <= EXOS_CONFIG_MAX_BYTES or not data.startswith(b"<?xml version=")
            or not data.rstrip().endswith(b"</xos-configuration>")
            or b"<!DOCTYPE" in data or b"<!ENTITY" in data):
        raise _reject("backup_incomplete", "ExtremeXOS returned an incomplete native configuration")
    try:
        root = ElementTree.fromstring(data)
    except (ElementTree.ParseError, LookupError, ValueError):
        raise _reject("backup_incomplete", "ExtremeXOS configuration XML is invalid") from None
    model, version = root.get("platform", ""), root.get("version", "")
    if (root.tag != "xos-configuration" or not REQUIRED_MODULES <= {child.tag for child in root}
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}", model)
            or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}(?:-patch[0-9]+-[0-9]+)?", version)
            or not re.fullmatch(r"[0-9A-Fa-f]{1,64}", root.get("checksum", ""))):
        raise _reject("backup_incomplete", "ExtremeXOS configuration header or required modules are missing")
    return model, version


def _credential(login, identity):
    try:
        if identity is None:
            return vault.Credential("backup", "password", os.environ.get("NETOPS_BACKUP_PASSWORD", ""), login=login)
        key = read_private(identity, 65536, owner=os.getuid()).decode("utf-8")
        return vault.Credential("backup", "ssh-key", key, login=login)
    except (OSError, RuntimeError, ValueError, vault.VaultError):
        raise _reject("backup_credentials_unavailable", "Supply a private SSH identity or NETOPS_BACKUP_PASSWORD") from None


def run(host, port, login, pin, filename, directory, keep, confirmation, *, identity=None, legacy=None):
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", host) or not 1 <= port <= 65535
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", login) or not 1 <= keep <= 365
            or not EXOS_CONFIG_FILE.fullmatch(filename)):
        raise _reject("backup_request_invalid", "Invalid ExtremeXOS backup target, saved filename or retention")
    try:
        hostkey.checked_pin(pin)
        legacy_ssh.checked(legacy)
    except (hostkey.HostKeyError, legacy_ssh.LegacySshError):
        raise _reject("backup_request_invalid", "Invalid ExtremeXOS SSH pin or legacy profile") from None
    destination = _backup_destination(directory)
    plan = dict(host=host, port=port, login=login, ssh_sha256=pin, file=filename, directory=str(destination),
                keep=keep, identity=str(identity.absolute()) if identity is not None else None, legacy_ssh=legacy)
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
    if confirmation is None:
        return {"result": "ready", "plan_sha256": digest, "plan": plan}
    if not compare_digest(confirmation.encode(), digest.encode()):
        raise _reject("plan_changed", "The backup confirmation does not match the current plan")
    key = _key()
    credential = _credential(login, identity)
    try:
        pinned = hostkey.scan(host, port, pin, DEFAULT_TIMEOUT_SECONDS, legacy=legacy)
    except hostkey.HostKeyError:
        raise _reject("backup_identity_mismatch", "Could not verify the ExtremeXOS SSH host key") from None
    try:
        data = read_exos_configuration(host, port, credential, pinned, filename, legacy_ssh=legacy)
    except (OSError, SftpError):
        raise _reject("backup_transport_failed", "ExtremeXOS SFTP configuration transfer failed") from None
    model, version = _identity(data)
    if _backup_destination(directory) != Path(plan["directory"]):
        raise _reject("backup_destination_unsafe", "The backup destination changed after confirmation")
    prefix = "exos-" + hashlib.sha256(f"{host.lower()}:{port}/{filename}".encode()).hexdigest()[:32]
    name, retention_ok, _, sealed = _save(destination, prefix, data, keep, key, magic=MAGIC)
    support = tested.support("ExtremeXOS", version,
                             [("EXOS-VM", "33.6.1.14"), ("X440G2-12p-10G4", "33.7.1.6-patch1-11")],
                             model=model, function="saved configuration backup")
    result = {"result": "confirmed", "artifact": name, "retention_ok": retention_ok,
              "firmware_support": support, **_metrics(sealed)}
    if warning := tested.warning(support):
        result["warnings"] = [warning]
    return result


def unseal(source, output):
    directory = _backup_destination(output.parent)
    _backup_destination(source.parent)
    data = _read_backup(source, _key(), magic=MAGIC)
    _identity(data)
    if not EXOS_CONFIG_FILE.fullmatch(output.name):
        raise _reject("backup_request_invalid", "The ExtremeXOS restore filename must end in .cfg")
    if _backup_destination(output.parent) != directory:
        raise _reject("backup_destination_unsafe", "The restore destination changed before writing")
    try:
        write_private(directory / output.name, data)
    except (OSError, RuntimeError):
        raise _reject("backup_storage_failed", "Could not create the private ExtremeXOS restore file") from None
    return {"result": "confirmed", **_metrics(data)}
