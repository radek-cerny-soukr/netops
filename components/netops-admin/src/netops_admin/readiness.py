from __future__ import annotations

from netops_admin import audit, audit_gate, engine, enrollment, execute
from netops_admin.errors import Rejected
from netops_admin.profiles import find_profile, load_profiles

OK = "ok"
MISSING = "missing"
REFUSED = "refused"
SKIPPED = "skipped"
IDENTITY_PROBES = {"fortios": ("firewall address", "all"), "exos": ("vlan", "Default")}


class _Report:
    def __init__(self):
        self.checks = []

    def add(self, name, status, detail=None):
        self.checks.append({"check": name, "status": status, "detail": detail})
        return status == OK

    def attempt(self, name, action, detail=None):
        try:
            value = action()
        except Rejected as exc:
            self.add(name, REFUSED, "; ".join(exc.reasons))
            return False, None
        except Exception as exc:
            self.add(name, REFUSED, _described(exc))
            return False, None
        self.add(name, OK, detail(value) if detail else None)
        return True, value

    def skip(self, *names):
        for name in names:
            self.add(name, SKIPPED, "an earlier check failed")


def _described(exc) -> str:
    from netops_admin.access import AccessError

    return str(exc) if isinstance(exc, AccessError) else type(exc).__name__


def _local(report, runtime, device):
    config = runtime.config
    report.attempt("journal and audit log writable", lambda: (runtime.store.check_writable(),
                                                              runtime.audit.check_writable()))
    state, why = audit.export_state(config.export_status_file, config.limits)
    if state == "not-configured":
        report.add("audit export", MISSING, "no export status file is configured")
    elif state == "blocked":
        report.add("audit export", REFUSED, why)
    else:
        report.add("audit export", OK, state)
    if config.notify is None:
        report.add("notification", MISSING, "enroll and every change need a configured notification")
    else:
        report.add("notification", OK, "configured; doctor sends nothing")
    blocked = runtime.store.blocked(device.name)
    undelivered = execute._undelivered(runtime, device.name)
    if blocked is not None:
        report.add("device state", REFUSED, "blocked (%s); a person must investigate and unblock it" % blocked.get("reason"))
    elif undelivered:
        report.add("device state", REFUSED, "the notification of operation %s was not delivered" % undelivered[0])
    elif runtime.store.running(device.name):
        report.add("device state", REFUSED, "an unfinished operation exists; run recover first")
    else:
        report.add("device state", OK)
    report.attempt("budgets", lambda: execute._budgets(runtime, device))


def _operations(platform, firmware) -> dict:
    tables = {}
    for (profile_platform, table), profile in sorted(load_profiles().items()):
        if profile_platform != platform:
            continue
        try:
            find_profile(platform, table, firmware)
        except Rejected:
            tables[table] = "not measured on this firmware"
        else:
            tables[table] = " ".join(profile.ops)
    return tables


def doctor(runtime, device_name: str) -> dict:
    device = runtime.config.devices.get(device_name)
    if device is None:
        raise Rejected(["device %r is not configured" % device_name])
    adapter = execute._adapter(device.platform)
    report = _Report()
    _local(report, runtime, device)
    remote = ("write account and host key", "firmware", "administrator accounts", "check account",
              "leftover safeguards", "device prechecks", "audit policy", "enrollment")
    reached, access = report.attempt("credentials", lambda: runtime.access_factory(device))
    if not reached:
        report.skip(*remote)
        return _result(report, device, None)
    reached, text = report.attempt(remote[0], access.snapshot)
    if not reached:
        report.skip(*remote[1:])
        return _result(report, device, None)
    reached, snapshot = report.attempt(
        "firmware", lambda: engine.adapter_for(device.platform).load(text, device.firmware),
        lambda value: value.firmware)
    firmware = snapshot.firmware if reached else None

    def accounts():
        value = adapter.accounts_check(access, device, text)
        known = runtime.store.baseline(device.name)
        if known is not None and known != value:
            raise Rejected(["the administrator accounts changed since the last operation"])
        return value

    counted, fingerprint = report.attempt("administrator accounts", accounts)
    table, key = IDENTITY_PROBES[device.platform]
    report.attempt("check account", lambda: _identity(adapter, access, table, key),
                   lambda _value: "reads %s %s" % (table, key))
    report.attempt("leftover safeguards", lambda: _no_leftovers(adapter, access))
    report.attempt("device prechecks", lambda: _prechecks(adapter, access, device, text))
    report.attempt("audit policy", lambda: audit_gate.findings(device.platform, text, device.name, device.audit_policy),
                   lambda found: "%d findings on the current configuration" % len(found))
    if not (counted and firmware):
        report.skip("enrollment")
    else:
        try:
            enrollment.require(runtime, device, fingerprint, firmware)
        except Rejected as exc:
            report.add("enrollment", MISSING, "; ".join(exc.reasons))
        else:
            report.add("enrollment", OK)
    return _result(report, device, firmware)


def _identity(adapter, access, table, key):
    if adapter.observe(access, {"table": table, "key": key}) is None:
        raise Rejected(["the check account does not see the built-in %s %s" % (table, key)])


def _no_leftovers(adapter, access):
    found = adapter.leftovers(access)
    if found:
        raise Rejected(["a safeguard of an earlier operation is still installed: %s" % ", ".join(found)])


def _prechecks(adapter, access, device, text):
    reasons = adapter.prechecks(access, device, text, adapter.prompt_spec(adapter.hostname(access, text)))
    if reasons:
        raise Rejected(reasons)


def _result(report, device, firmware) -> dict:
    return {
        "device": device.name,
        "platform": device.platform,
        "firmware": firmware,
        "ready": all(item["status"] == OK for item in report.checks),
        "checks": report.checks,
        "operations": {} if firmware is None else _operations(device.platform, firmware),
        "protected": {table: len(names) for table, names in sorted(device.protected.items())},
    }
