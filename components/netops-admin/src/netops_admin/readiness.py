from __future__ import annotations

from netops_admin import audit_gate, engine, enrollment, execute, prediction, privileges
from netops_admin.config import summary as configuration_summary
from netops_admin.errors import Rejected, StateUnreadable, shown
from netops_admin.profiles import find_profile, load_profiles

OK = "ok"
MISSING = "missing"
REFUSED = "refused"
SKIPPED = "skipped"
WARNING = privileges.WARNING
UNVERIFIED = privileges.UNVERIFIED
ADVISORY = (OK, WARNING, UNVERIFIED)
RIGHTS = ("write account rights", "check account rights")
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
            self.checks[-1]["reason_codes"] = list(exc.reason_codes)
            return False, None
        except Exception as exc:
            self.add(name, REFUSED, _described(exc))
            return False, None
        self.add(name, OK, detail(value) if detail else None)
        return True, value

    def rights(self, name, decide):
        try:
            status, detail = decide()
        except Rejected as exc:
            self.add(name, UNVERIFIED, "; ".join(exc.reasons))
            self.checks[-1]["reason_codes"] = list(exc.reason_codes)
        except Exception as exc:
            self.add(name, UNVERIFIED, "the rights cannot be read: %s" % _described(exc))
        else:
            self.add(name, status, detail)

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
    state, why = execute.export_state(config)
    if state == "not-configured" and not runtime.require_export:
        report.add("operation audit configuration", OK,
                   "local Admin operation log; MCP audit is enforced by the gateway; no independent export delivery claimed")
    elif state == "not-configured":
        report.add("audit export", MISSING, "no export status file is configured")
    elif state == "blocked":
        report.add("audit export", REFUSED, why)
    else:
        report.add("audit export", OK, state if why is None else "%s; %s" % (state, why))
    if config.notify is None:
        report.add("notification", MISSING, "enroll and every change need a configured notification")
    else:
        report.add("notification", OK, "configured; doctor sends nothing")
    records = None
    try:
        blocked = runtime.store.blocked(device.name)
        records = runtime.store.records()
        undelivered = execute._undelivered(runtime, device.name, records=records)
        running = [record for record in records
                   if record.get("device") == device.name and record.get("status") == "running"]
    except Rejected as exc:
        report.add("device state", REFUSED, "; ".join(exc.reasons))
        report.checks[-1]["reason_codes"] = list(exc.reason_codes)
    else:
        _device_state(report, blocked, undelivered, running)
    report.attempt("budgets", lambda: execute._budgets(runtime, device, records=records))


def _device_state(report, blocked, undelivered, running):
    if blocked is not None:
        report.add("device state", REFUSED, "blocked (%s); a person must investigate and unblock it" % blocked.get("reason"))
        report.checks[-1]["reason_codes"] = ["device_blocked"]
    elif undelivered:
        report.add("device state", REFUSED, "the notification of operation %s was not delivered" % undelivered[0])
        report.checks[-1]["reason_codes"] = ["notification_pending"]
    elif running:
        report.add("device state", REFUSED, "an unfinished operation exists; run recover first")
        report.checks[-1]["reason_codes"] = ["operation_unfinished"]
    else:
        report.add("device state", OK)


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


def doctor(runtime, device_name: str, *, local=False) -> dict:
    result = _doctor(runtime, device_name, local=local)
    result["configuration"] = configuration_summary(runtime.config)
    return result


def _doctor(runtime, device_name: str, *, local=False) -> dict:
    device = runtime.config.devices.get(device_name)
    if device is None:
        raise Rejected(["device %s is not configured" % shown(device_name)])
    if local:
        report = _Report()
        _local(report, runtime, device)
        result = _result(report, device, None)
        result.update(scope="local", local_ready=result["ready"], remote_readiness="unverified", ready=False)
        return result
    try:
        adapter = execute._adapter(device.platform)
    except Rejected as refusal:
        if device.platform == "fortiadc" and device.schema is None:
            raise Rejected(refusal.reasons + _fortiadc_rights(runtime, device), reason_codes=refusal.reason_codes) from None
        raise
    report = _Report()
    _local(report, runtime, device)
    if device.schema is not None:
        from netops_admin import schema_runtime
        firmware,operations=schema_runtime.doctor(runtime,device,report)
        result=_result(report,device,firmware)
        result["operations"]=operations
        return result
    preflight = getattr(adapter, "safeguard_preflight", None)
    rights = RIGHTS if device.platform == "fortios" else ()
    remote = ("write account and host key", "firmware", "administrator accounts", "check account") + rights + (
              "leftover safeguards", "device prechecks") + (("webhook safeguard",) if preflight else ()) + (
              "audit policy", "enrollment")
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
    if rights:
        report.rights(RIGHTS[0], lambda: privileges.fortios_write(access, firmware))
        report.rights(RIGHTS[1], lambda: privileges.fortios_check(access))
    report.attempt("leftover safeguards", lambda: _no_leftovers(adapter, access))
    report.attempt("device prechecks", lambda: _prechecks(adapter, access, device, text))
    if preflight is not None:
        if firmware:
            report.attempt("webhook safeguard", lambda: preflight(access, device, text, firmware), str)
        else:
            report.skip("webhook safeguard")
    report.attempt("audit policy", lambda: audit_gate.baseline(device.platform, _audited(adapter, access, device, text),
                                                               device.name, device.audit_policy),
                   audit_gate.summary)
    if not (counted and firmware):
        report.skip("enrollment")
    else:
        try:
            enrollment.require(runtime, device, fingerprint, firmware)
        except StateUnreadable as exc:
            report.add("enrollment", REFUSED, "; ".join(exc.reasons))
            report.checks[-1]["reason_codes"] = list(exc.reason_codes)
        except Rejected as exc:
            report.add("enrollment", MISSING, "; ".join(exc.reasons))
            report.checks[-1]["reason_codes"] = list(exc.reason_codes)
        else:
            report.add("enrollment", OK)
    return _result(report, device, firmware)


def _fortiadc_rights(runtime, device):
    report = _Report()
    reached, access = report.attempt("credentials", lambda: runtime.access_factory(device))
    if not reached:
        report.skip(*RIGHTS)
    else:
        report.rights(RIGHTS[0], lambda: privileges.fortiadc_write(access))
        report.rights(RIGHTS[1], lambda: privileges.fortiadc_check(access))
    return ["%s: %s%s" % (item["check"], item["status"], "" if item["detail"] is None else " (%s)" % item["detail"])
            for item in report.checks]


def _audited(adapter, access, device, text):
    ports = adapter.ports(access, "vlan-membership")
    if ports is None:
        return text
    return prediction.audited(text, {"table": "vlan-membership", "ports": ports, "firmware": device.firmware})


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
        "ready": all(item["status"] in ADVISORY for item in report.checks),
        "checks": report.checks,
        "operations": {} if firmware is None else _operations(device.platform, firmware),
        "protected": {table: len(names) for table, names in sorted(device.protected.items())},
    }
