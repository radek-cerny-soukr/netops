from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict
from importlib import resources

from netops_admin import audit, engine
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

PROTOCOL = "netops-enrollment/1"
PROBE_PREFIX = "netops-enroll-"


def binding(device, accounts, firmware, config):
    fields = asdict(device)
    profiles = resources.files("netops_admin") / "profiles"
    profile_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in profiles.iterdir() if p.name.endswith(".json")}
    value = {"protocol": PROTOCOL, "device": fields, "accounts": accounts, "firmware": firmware,
             "profiles": profile_hashes, "notify": None if config.notify is None else asdict(config.notify),
             "export_status_file": config.export_status_file}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require(runtime, device, accounts, firmware):
    certificate = runtime.store.enrollment(device.name)
    if not certificate or certificate.get("protocol") != PROTOCOL or certificate.get("binding") != binding(
        device, accounts, firmware, runtime.config
    ):
        raise Rejected(["a successful enroll self-test is required for this device, build and configuration"])


def run(runtime, device_name, probe):
    from netops_admin import execute
    device = runtime.config.devices.get(device_name)
    if device is None:
        raise Rejected(["device is not configured"])
    key = PROBE_PREFIX + secrets.token_hex(6)
    table = "firewall address" if device.platform == "fortios" else "vlan"
    changes = {"subnet": probe} if device.platform == "fortios" else {"tag": probe}
    request = parse_request(json.dumps({
        "device": device_name, "table": table, "op": "create", "key": key, "changes": changes,
        "reason": "operator enrollment self-test", "user_request": "operator enrollment self-test",
        "request_id": "enroll-" + secrets.token_hex(12),
    }).encode())
    return execute._apply(runtime, device_name, request, execute.ANY_STATE, enrolling=True)


def complete(runtime, device, access, record):
    from netops_admin import execute
    if record.get("result") != "reverted" or record.get("reason") != "enrollment self-test":
        return record
    if record.get("notification") != "sent":
        return record
    plan = record["plan"]
    adapter = execute._adapter(device.platform)
    try:
        text = access.snapshot()
        if engine.verify(plan, text.encode(), expect="before")["result"] != "match":
            raise Rejected(["enrollment cleanup did not restore the initial configuration"])
        if engine.observed_state(plan, adapter.observe(access, plan)) is not None:
            raise Rejected(["the check account still sees the enrollment probe"])
        accounts = adapter.accounts_check(access, device, text)
        if accounts != record["accounts"] or not adapter.safeguard_absent(access, record):
            raise Rejected(["enrollment identities or safeguard cleanup changed"])
    except Exception:
        runtime.store.block(device.name, record["change_id"], "enrollment verification")
        raise Rejected(["the enrollment result could not be verified; the device is blocked"]) from None
    certificate = {"protocol": PROTOCOL, "binding": binding(device, accounts, plan["firmware"], runtime.config),
                   "firmware": plan["firmware"], "change_id": record["change_id"], "completed_at": audit.now_utc()}
    runtime.store.save_enrollment(device.name, certificate)
    record["enrollment"] = "valid"
    runtime.store.save(record)
    runtime.audit.event("administrative", device=device.name, action="enrolled", reason_characters=0,
                        change_id=record["change_id"])
    return record
