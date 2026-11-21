"""Local FortiADC certificate staging through a pinned management session."""

import hashlib
from hmac import compare_digest
import json
import re
import secrets
import time

from netops_admin import audit, enrollment, fortiadc, fortiadc_plan
from netops_admin.errors import Rejected
from netops_admin.fortiadc import CERT_NAME, CERT_TABLE
from netops_core.fortiadc_https import Management, RequestError
from netops_core.tested import support

KIND = "certificate-import"


def certificate_https(device, credential):
    if credential.kind != "password":
        raise RequestError("password_credential_required")
    client = Management(device.address, device.fortiadc_https_port, device.fortiadc_https_sha256)
    return client.login(credential.login, credential.use())


def _certificate_material(certificate_path, key_path):
    from datetime import datetime, timezone
    import os

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import UnsupportedAlgorithm
    from netops.files import read_private
    from netops_core.inputs import InputError, read_regular

    try:
        certificate = read_regular(certificate_path, 256 * 1024)
        key = read_private(key_path, maximum=32 * 1024, owner=os.getuid())
        chain = x509.load_pem_x509_certificates(certificate)
        leaf = chain[0]
        private_key = serialization.load_pem_private_key(key, password=None)
        public_format = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        now = datetime.now(timezone.utc)
        if (not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc
                or leaf.public_key().public_bytes(*public_format)
                != private_key.public_key().public_bytes(*public_format)):
            raise ValueError("invalid or mismatched certificate")
        if b"PRIVATE KEY" in certificate:
            raise ValueError("expected public certificates only")
    except (OSError, ValueError, TypeError, InputError, UnsupportedAlgorithm):
        raise Rejected(["use a valid PEM certificate and matching operator-owned private PEM key"],
                       reason_codes=["fortiadc_certificate_input_invalid"]) from None
    # FortiADC reports the certificate fingerprint using SHA-1. Approval binds all certificate
    # bytes using SHA-256 and the key is verified against the leaf public key.
    return certificate, key, leaf.fingerprint(hashes.SHA1()).hex()


def _certificate_upload_body(name, certificate, key):
    from uuid import uuid4

    boundary = "netops-" + uuid4().hex
    entries = (("mkey", None, name.encode()), ("vdom", None, b"global"),
               ("type", None, b"CertKey"), ("cert", "certificate.pem", certificate),
               ("key", "key.pem", key))
    parts = []
    for field, filename, contents in entries:
        header = f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"'
        if filename:
            header += f'; filename="{filename}"\r\nContent-Type: application/octet-stream'
        parts.append(header.encode() + b"\r\n\r\n" + contents + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return "multipart/form-data; boundary=" + boundary, b"".join(parts)


def _installed_certificates(session):
    rows = session.read("system_certificate_local", vdom="global")
    if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("mkey"), str)
                                         for row in rows):
        raise RequestError("incomplete_output")
    indexed = {row["mkey"].casefold(): row for row in rows}
    if len(indexed) != len(rows):
        raise RequestError("incomplete_output")
    return indexed


def _installed_leaf(session, name, fingerprint):
    row = _installed_certificates(session).get(name.casefold())
    if row is None:
        return False
    observed = row.get("fingerprint")
    if (row.get("mkey") != name or row.get("status") != "OK" or not isinstance(observed, str)
            or observed.replace(":", "").lower() != fingerprint):
        raise RequestError("readback_mismatch")
    return True


def _endpoint(device):
    return {"device": device.name, "address": device.address, "https_port": device.fortiadc_https_port,
            "https_sha256": device.fortiadc_https_sha256}


def import_certificate(runtime, device, name, certificate_path, key_path, confirm=None):
    """Stage a new globally visible certificate from private files for a later group update."""
    from netops_admin import exec_fortiadc, execute
    from netops_admin.access import operation

    if (device.platform != "fortiadc" or not device.fortiadc_https_sha256 or not CERT_NAME.fullmatch(name)
            or confirm is not None and not re.fullmatch(r"[a-f0-9]{64}", confirm)):
        raise Rejected(["certificate import needs a configured FortiADC HTTPS pin and a valid name and approval"],
                       reason_codes=["fortiadc_certificate_input_invalid"])
    if name.casefold() in {item.casefold() for item in device.protected.get(CERT_TABLE, ())}:
        raise Rejected(["the certificate object name is protected"], reason_codes=["fortiadc_certificate_protected"])
    certificate, key, fingerprint = _certificate_material(certificate_path, key_path)
    with runtime.store.lock(device.name), execute._target_lock(device):
        if confirm is None:
            if runtime.store.running(device.name) or runtime.store.blocked(device.name):
                raise Rejected(["settle the outstanding Admin operation before importing a certificate"],
                               reason_codes=["operation_unfinished"])
        else:
            execute._write_preflight(runtime, device)
        try:
            access = runtime.access_factory(device)
            with operation(access), certificate_https(device, access.credential) as session:
                role = fortiadc.require_ha_write(access)
                info = session.read("platform/info", vdom="global")
                version = info.get("firmwareVersion") if isinstance(info, dict) else None
                if not isinstance(version, str):
                    raise RequestError("product_identity")
                firmware = fortiadc_plan.firmware_of("Version: " + version)
                if name.casefold() in _installed_certificates(session):
                    raise Rejected(["a local certificate already uses this name"],
                                   reason_codes=["fortiadc_certificate_exists"])
                plan = {**_endpoint(device), "name": name, "firmware": firmware,
                        "certificate_sha256": hashlib.sha256(certificate).hexdigest()}
                if role == "primary":
                    plan["fortiadc_ha_role"] = role
                digest = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
                result = {"result": "ready", "plan_sha256": digest, **plan,
                          "firmware_support": support("FortiADC", firmware, ("7.6.7 build0676",),
                                                      function="Admin certificate import")}
                if confirm is None:
                    return result
                if not compare_digest(digest, confirm):
                    raise Rejected(["the import does not match the approved preview"], reason_codes=["plan_changed"])
                try:
                    with operation(access):
                        before = access.snapshot()
                        fortiadc_plan.load(before, firmware)
                        accounts = execute._check_accounts(runtime, exec_fortiadc, access, device, before)
                except Rejected:
                    raise
                except Exception as exc:
                    raise Rejected(["the device could not be read before any change (%s)" % type(exc).__name__]) from None
                enrollment.require(runtime, device, accounts, firmware)
                with certificate_https(device, access.check_credential) as check:
                    if name.casefold() in _installed_certificates(check):
                        raise Rejected(["the check account already sees the name"],
                                       reason_codes=["fortiadc_certificate_exists"])
                    fortiadc.require_ha_write(access, role)
                    change_id = secrets.token_hex(16)
                    record = {
                        "change_id": change_id, "request_id": KIND + "-" + change_id, "request_sha256": digest,
                        "device": device.name, "kind": KIND, "status": "running", "result": None, "steps": [],
                        "created_at": audit.now_utc(), "created_at_epoch": time.time(),
                        "budget_at_epoch": runtime.store.budget_now(), "accounts": accounts,
                        "plan": {**plan, "platform": device.platform, "table": CERT_TABLE, "key": name,
                                 "op": "create", "plan_sha256": digest, "fingerprint": fingerprint,
                                 "firmware_support": result["firmware_support"]},
                    }
                    with runtime.store.admission():
                        execute._budgets(runtime, device)
                        runtime.store.save(record)
                        runtime.store.save_baseline(device.name, accounts)
                        runtime.store.remember_request(record["request_id"], change_id, digest, device.name)
                    event = {"device": device.name, "change_id": change_id, "plan_sha256": digest, "key": name}
                    runtime.audit.event(KIND, status="started", **event)
                    execute._step(runtime, record, "change_start")
                    try:
                        if session.upload_certificate(*_certificate_upload_body(name, certificate, key)) != 0:
                            raise RequestError("device_rejected")
                        execute._step(runtime, record, "change_applied")
                        if role == "primary":
                            exec_fortiadc.verify_ha_sync(access, runtime.sleep)
                        if not _installed_leaf(check, name, fingerprint):
                            raise RequestError("readback_mismatch")
                    except Rejected as exc:
                        code = exc.reason_codes[0]
                        execute._finish(runtime, record, "unknown", exc.reasons[0], reason_code=code)
                        runtime.audit.event(KIND, status="unknown", error_code=code, **event)
                        return {**result, "result": "unknown", "change_id": change_id, "error_code": code}
                    except RequestError as exc:
                        execute._finish(runtime, record, "unknown", exc.code)
                        runtime.audit.event(KIND, status="unknown", error_code=exc.code, **event)
                        return {**result, "result": "unknown", "change_id": change_id, "error_code": exc.code}
                    execute._step(runtime, record, "check_identity_passed")
                    execute._finish(runtime, record, "confirmed")
                    runtime.audit.event(KIND, status="confirmed", **event)
                    return {**result, "result": "confirmed", "change_id": change_id}
        except RequestError as exc:
            if exc.code == "timeout":
                raise Rejected(["the certificate import preflight timed out"],
                               reason_codes=["fortiadc_certificate_read_timeout"]) from None
            raise Rejected(["the certificate import preflight failed (%s)" % exc.code],
                           reason_codes=["fortiadc_certificate_unreadable"]) from None


def recover(runtime, device, record, blocked=None):
    from netops_admin import exec_fortiadc, execute
    from netops_admin.access import operation

    steps = {step["step"] for step in record["steps"]}
    if record["status"] == "running" and "change_start" not in steps:
        return execute._finish(runtime, record, "rejected", "interrupted before any mutation",
                               reason_code="interrupted_before_mutation")
    execute._step(runtime, record, "recovery_start")
    plan = record["plan"]
    try:
        if device.platform != "fortiadc" or any(plan.get(field) != value for field, value in _endpoint(device).items()):
            raise RequestError("product_identity")
        access = runtime.access_factory(device)
        if plan.get("fortiadc_ha_role") == "primary":
            with operation(access):
                exec_fortiadc.verify_ha_sync(access, runtime.sleep)
        with certificate_https(device, access.credential) as session:
            installed = _installed_leaf(session, plan["name"], plan["fingerprint"])
        with certificate_https(device, access.check_credential) as check:
            independently_installed = _installed_leaf(check, plan["name"], plan["fingerprint"])
        if installed != independently_installed or not installed and "change_applied" not in steps:
            raise RequestError("readback_mismatch")
    except Exception as exc:
        reason = exc.code if isinstance(exc, RequestError) else type(exc).__name__
        execute._step(runtime, record, "recovery_read_failed", reason)
        if record["status"] == "running":
            return execute._finish(runtime, record, "unknown", reason)
        return record
    result = "confirmed" if installed else "reverted"
    execute._step(runtime, record, "recovery_read_verified", result)
    if record.get("result") != result:
        execute._finish(runtime, record, result)
    if blocked is None:
        blocked = runtime.store.blocked(device.name)
    if blocked and blocked["change_id"] == record["change_id"] and runtime.store.unblock(device.name, blocked):
        runtime.audit.event("administrative", device=device.name, action="recovered certificate import",
                            reason_characters=0, change_id=record["change_id"])
    return record
