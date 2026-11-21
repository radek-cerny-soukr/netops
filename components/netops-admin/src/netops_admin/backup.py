"""FortiOS global backup for the local Admin operator."""
from contextlib import contextmanager
import fcntl
import hashlib
from hmac import compare_digest
from http.client import HTTPException, HTTPSConnection
from http.cookies import CookieError, SimpleCookie
import json
import os
from pathlib import Path
import re
from ssl import CERT_NONE, PROTOCOL_TLS_CLIENT, SSLContext
import stat
import time
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from netops.files import read_private, sync_directory, write_private
from netops_admin.errors import Rejected
from netops_core import tested

MAX_BYTES = 64 * 1024 * 1024
MAGIC = b"NETOPS-FORTIOS-BACKUP\x00\x01"
NONCE_BYTES = 12
AUTH = "/api/v2/authentication"
EXPORT = "/api/v2/monitor/system/config/backup?scope=global"
HEADER = re.compile(rb"#config-version=(F[A-Z0-9_-]+)-([0-9]+\.[0-9]+\.[0-9]+)-FW-build([0-9]+)-[0-9]+:[^\r\n]+")
QUOTING = re.compile(rb'\\.|"')
MASKED_VALUE = re.compile(rb'set [a-z0-9_-]+ (?:FortinetPasswordMask|"FortinetPasswordMask")')
GLOBAL_SECTIONS = frozenset((b'system global', b'system interface', b'system admin'))


def _reject(code, text):
    return Rejected([text], reason_codes=[code])


def _private_directory(directory):
    try:
        info = directory.lstat()
        if stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid():
            return directory.resolve(strict=True)
    except OSError:
        pass
    raise _reject("backup_destination_unsafe", "Use an existing private directory owned by the operator")


def _backup_destination(directory):
    resolved = _private_directory(directory)
    requested = directory.absolute()
    for ancestor in dict.fromkeys((requested, *requested.parents, resolved, *resolved.parents)):
        try:
            (ancestor / '.git').lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise _reject("backup_destination_unsafe", "Could not verify the backup destination") from None
        raise _reject("backup_destination_unsafe", "Store backups and restore files outside Git worktrees")
    return resolved


def _plan(host, port, login, pin, directory, keep):
    if (not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}", host) or
            not 1 <= port <= 65535 or not re.fullmatch(r"[a-f0-9]{64}", pin) or
            (login and not re.fullmatch(r"[a-zA-Z0-9_.@-]{1,128}", login)) or not 1 <= keep <= 365):
        raise _reject("backup_request_invalid", "Invalid FortiOS backup target, TLS pin or retention")
    directory = _backup_destination(directory)
    plan = dict(host=host, port=port, login=login, tls_sha256=pin, directory=str(directory), keep=keep)
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
    return plan, digest


def _key():
    value = os.environ.get("NETOPS_BACKUP_KEY", "")
    if not re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        raise _reject("backup_credentials_unavailable", "Set NETOPS_BACKUP_KEY to a 32-byte key in hexadecimal")
    return bytes.fromhex(value)


def _request(host, port, pin, method, path, *, headers=None, body=None, maximum=65536):
    # Verify the configured leaf certificate before any credentials can reach the connection.
    context = SSLContext(PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = CERT_NONE
    connection = HTTPSConnection(host, port, timeout=20, context=context)
    try:
        connection.connect()
        actual = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        if not compare_digest(actual, pin):
            raise _reject("backup_identity_mismatch", "FortiOS TLS certificate fingerprint did not match")
        connection.request(method, path, body=body, headers=headers or {})
        with connection.getresponse() as response:
            data = response.read(maximum + 1)
            length = response.getheader("Content-Length")
            if (len(data) > maximum or (length is not None and int(length) != len(data)) or
                    (path == EXPORT and response.status == 200 and length is None and not response.chunked)):
                raise _reject("backup_incomplete", "FortiOS returned an incomplete or oversized response")
            return response.status, response.getheaders(), data
    except (OSError, HTTPException, ValueError):
        raise _reject("backup_transport_failed", "FortiOS TLS connection or HTTP transfer failed") from None
    finally:
        connection.close()


@contextmanager
def _authorization(host, port, pin, login):
    secret = os.environ.get("NETOPS_BACKUP_PASSWORD" if login else "NETOPS_BACKUP_TOKEN", "")
    if not secret:
        raise _reject("backup_credentials_unavailable", "Set the FortiOS backup credential in the operator environment")
    if login is None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", secret):
            raise _reject("backup_credentials_unavailable", "Invalid FortiOS API token syntax")
        yield {"Authorization": "Bearer " + secret}
        return

    status, headers, data = _request(host, port, pin, "POST", AUTH,
                                     headers={"Content-Type": "application/json"},
                                     body=json.dumps({"username": login, "password": secret}))
    cookies = SimpleCookie()
    try:
        for name, value in headers:
            if name.lower() == "set-cookie":
                cookies.load(value)
        csrf = next(c.value for name, c in cookies.items() if name.startswith("ccsrf_token_"))
        session = next(c for name, c in cookies.items() if name.startswith("session_key_"))
        if status != 200 or json.loads(data)["status_message"] != "LOGIN_SUCCESS":
            raise ValueError()
    except (ValueError, TypeError, KeyError, StopIteration, CookieError):
        raise _reject("backup_refused", "FortiOS refused the backup login") from None

    headers = {"Cookie": f"{session.key}={session.coded_value}", "X-CSRFTOKEN": csrf}
    try:
        yield headers
    finally:
        try:
            _request(host, port, pin, "DELETE", AUTH, headers=headers)
        except Rejected:
            # FortiOS expires the session. Preserve the export result or its original failure.
            pass


def _sections(data):
    lines = iter(data.split(b"\n"))
    header = next(lines).rstrip(b"\r")
    if (not 256 <= len(data) <= MAX_BYTES or not data.endswith(b"\n") or
            not HEADER.fullmatch(header)):
        raise _reject("backup_incomplete", "FortiOS returned an incomplete backup")
    stack = []
    quoted = False
    top_level, global_sections, vdom_sections = set(), set(), set()
    last_section = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if not quoted:
            if line == b"#password_mask=1" or MASKED_VALUE.fullmatch(line):
                raise _reject("backup_incomplete", "FortiOS returned a password-masked backup")
            if line.startswith(b"#"):
                continue
            words = line.split(None, 1)
            word = words[0]
            if word == b"config" and len(words) == 2:
                stack.append((b"end", words[1]))
            elif word == b"edit" and len(words) == 2 and stack and stack[-1][0] == b"end":
                vdom = words[1].removeprefix(b'"').removesuffix(b'"') if stack == [(b"end", b"vdom")] else None
                stack.append((b"next", vdom))
            elif stack and stack[-1][0] == line:
                _, section = stack.pop()
                if line == b"end":
                    if not stack:
                        top_level.add(section)
                        last_section = section
                    elif stack == [(b"end", b"global")]:
                        global_sections.add(section)
                    elif len(stack) == 2 and stack[0] == (b"end", b"vdom") and stack[1][0] == b"next":
                        vdom_sections.add((stack[1][1], section))
            elif not stack or word in (b"config", b"edit", b"end", b"next"):
                raise _reject("backup_incomplete", "FortiOS backup framing is incomplete")
        quoted ^= sum(match[0] == b'"' for match in QUOTING.finditer(line)) % 2 == 1
    if stack or quoted or last_section is None:
        raise _reject("backup_incomplete", "FortiOS backup framing is incomplete")
    # Native exports without a footer can end cleanly at a truncated section boundary.
    # Require global settings, interfaces, administrators and the built-in address table.
    if top_level & {b"global", b"vdom"}:
        has_required_sections = (GLOBAL_SECTIONS <= global_sections and last_section == b"vdom" and
                                 any(section == b"firewall address" for _, section in vdom_sections))
    else:
        has_required_sections = GLOBAL_SECTIONS <= top_level and b"firewall address" in top_level
    sections = ({(section,) for section in top_level} | {(b"global", section) for section in global_sections} |
                {(b"vdom", vdom, section) for vdom, section in vdom_sections})
    return sections, has_required_sections


def _require_sections(has_required_sections):
    if not has_required_sections:
        raise _reject("backup_incomplete", "FortiOS backup is missing required global configuration sections")


def _export(host, port, login, pin):
    with _authorization(host, port, pin, login) as credentials:
        status, _, body = _request(host, port, pin, "POST", EXPORT, maximum=MAX_BYTES,
                                    headers={**credentials, "Content-Type": "application/json"}, body=b"{}")
        if status == 405:
            status, _, body = _request(host, port, pin, "GET", EXPORT, maximum=MAX_BYTES, headers=credentials)
        if status != 200:
            raise _reject("backup_refused", "FortiOS refused the global backup")
    return body


def _metrics(data):
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def _seal(data, key, magic):
    nonce = os.urandom(NONCE_BYTES)
    return magic + nonce + AESGCM(key).encrypt(nonce, data, magic)


def _read_backup(source, key, *, magic=MAGIC, maximum=MAX_BYTES):
    try:
        sealed = read_private(source, maximum + len(magic) + NONCE_BYTES + 16, owner=os.getuid())
        if not sealed.startswith(magic) or len(sealed) < len(magic) + NONCE_BYTES + 16:
            raise ValueError()
        start = len(magic)
        nonce = sealed[start:start + NONCE_BYTES]
        return AESGCM(key).decrypt(nonce, sealed[start + NONCE_BYTES:], magic)
    except (OSError, RuntimeError, ValueError, InvalidTag):
        kind = "FortiOS" if magic == MAGIC else "configuration"
        raise _reject("backup_invalid", f"Could not authenticate the encrypted {kind} backup") from None


def _save(directory, prefix, data, keep, key, *, magic=MAGIC, verify_readback=False, read_previous=None):
    if magic == MAGIC:
        sections, has_required_sections = _sections(data)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    name = f"{prefix}-{stamp}-{uuid4().hex}.netops-backup"
    pattern = re.compile(re.escape(prefix) + r"-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}\.netops-backup")
    retention_ok = True
    comparison_skipped = False
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            previous = []
            for path in directory.iterdir():
                if pattern.fullmatch(path.name):
                    info = path.lstat()
                    if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1:
                        previous.append((info.st_mtime_ns, path))
            previous.sort(reverse=True)
            if read_previous is not None:
                # Formats that carry device identity (IOS v2): authenticate every candidate and keep
                # archives that cannot be verified for this device; they are never pruned.
                retained_candidates = []
                for _, path in previous:
                    try:
                        read_previous(path)
                    except Rejected:
                        continue
                    retained_candidates.append(path)
            elif magic == MAGIC:
                retained_candidates = []
                for _, path in previous:
                    try:
                        prior_data = _read_backup(path, key)
                    except Rejected:
                        continue
                    if not retained_candidates:
                        previous_sections, _ = _sections(prior_data)
                        missing_sections = previous_sections - sections
                        if missing_sections:
                            missing = ", ".join(b" / ".join(section).decode("ascii", "backslashreplace")
                                                for section in sorted(missing_sections))
                            raise _reject("backup_incomplete", f"FortiOS backup is missing previously confirmed sections: {missing}")
                    retained_candidates.append(path)
                comparison_skipped = bool(previous and not retained_candidates)
                _require_sections(has_required_sections)
            elif verify_readback:
                retained_candidates = []
                for _, path in previous:
                    try:
                        _read_backup(path, key, magic=magic)
                    except Rejected:
                        # Preserve an archive whose key or contents cannot be verified.
                        retention_ok = False
                        continue
                    retained_candidates.append(path)
            else:
                # No device identity in the archive: an unverifiable newest archive stops publication.
                if previous:
                    # A changed key must not silently prune backups encrypted with the previous key.
                    _read_backup(previous[0][1], key, magic=magic)
                retained_candidates = [path for _, path in previous]
            sealed = _seal(data, key, magic)
            published = directory / name
            write_private(published, sealed)
            if verify_readback:
                try:
                    matches = _read_backup(published, key, magic=magic) == data
                except Rejected:
                    matches = False
                if not matches:
                    published.unlink()
                    sync_directory(directory)
                    raise _reject("backup_storage_failed", "Encrypted backup readback did not match")
            try:
                for path in retained_candidates[keep - 1:]:
                    path.unlink()
                sync_directory(directory)
            except OSError:
                retention_ok = False
        finally:
            os.close(fd)
    except (OSError, RuntimeError):
        kind = "FortiOS" if magic == MAGIC else "configuration"
        raise _reject("backup_storage_failed", f"Could not publish the encrypted {kind} backup") from None
    return name, retention_ok, comparison_skipped, sealed


def run(host, port, login, pin, directory, keep, confirmation):
    plan, digest = _plan(host, port, login, pin, directory, keep)
    if confirmation is None:
        return {"result": "ready", "plan_sha256": digest, "plan": plan}
    if not compare_digest(confirmation.encode(), digest.encode()):
        raise _reject("plan_changed", "The backup confirmation does not match the current plan")
    key = _key()
    data = _export(host, port, login, pin)
    prefix = hashlib.sha256(f"{host.lower()}:{port}".encode()).hexdigest()[:32]
    destination = _backup_destination(directory)
    if destination != Path(plan["directory"]):
        raise _reject("backup_destination_unsafe", "The backup destination changed after confirmation")
    name, retention_ok, comparison_skipped, sealed = _save(destination, prefix, data, keep, key)
    header = HEADER.fullmatch(data.split(b"\n", 1)[0].rstrip(b"\r"))
    model, version, build = (value.decode("ascii") for value in header.groups())
    support = tested.support("FortiOS", version + " build" + build, [("FGT60F", "7.6.8 build3744")],
                             model=model, function="configuration backup")
    result = {"result": "confirmed", "artifact": name, "retention_ok": retention_ok,
              "firmware_support": support, **_metrics(sealed)}
    warnings = []
    if warning := tested.warning(support):
        warnings.append(warning)
    if comparison_skipped:
        warnings.append("FortiOS backup section comparison skipped: no previous archive could be authenticated"
                        " with the current key. Existing archives are preserved.")
    if warnings:
        result["warnings"] = warnings
    return result


def unseal(source, output):
    directory = _backup_destination(output.parent)
    key = _key()
    try:
        _private_directory(source.parent)
    except (OSError, RuntimeError, ValueError):
        raise _reject("backup_invalid", "Could not authenticate the encrypted FortiOS backup") from None
    data = _read_backup(source, key)
    _, has_required_sections = _sections(data)
    _require_sections(has_required_sections)
    if _backup_destination(output.parent) != directory:
        raise _reject("backup_destination_unsafe", "The restore destination changed before writing")
    try:
        write_private(directory / output.name, data)
    except (OSError, RuntimeError):
        raise _reject("backup_storage_failed", "Could not create a private FortiOS restore file") from None
    return {"result": "confirmed", **_metrics(data)}
