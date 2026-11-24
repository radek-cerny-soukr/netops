from __future__ import annotations

from netops_admin import audit_gate, engine, enrollment, execute, fortiadc, fortios, fortios_tables, prediction, privileges
from netops_admin.access import operation
from netops_admin.config import summary as configuration_summary
from netops_admin.errors import Rejected, StateUnreadable, shown
from netops_admin.profiles import firmware_support, load_profiles
from netops_core import tested

OK = "ok"
MISSING = "missing"
REFUSED = "refused"
SKIPPED = "skipped"
WARNING = privileges.WARNING
UNVERIFIED = privileges.UNVERIFIED
ADVISORY = (OK, WARNING, UNVERIFIED)
NOT_MEASURED = "profile_not_measured"
RIGHTS = ("write account rights", "check account rights")
IDENTITY_PROBES = {"fortios": ("firewall address", "all"), "exos": ("vlan", "Default"), "eos": ("interface", "Ethernet1"),
                   "nxos": ("interface", "Ethernet1/1"),
                   "ios": ("interface", "description table"), "iosxe": ("interface", "description table"),
                   "junos": ("interface", "ge-0/0/0"),
                   "fortiadc": ("system status", "hostname"),
                   # Unleashed has no built-in WLAN: "*" asks only that the check account reads the WLAN listing
                   "ruckus": ("wlan", "*")}
RIGHTS_CHECKS = {"fortios": (lambda access, firmware: privileges.fortios_write(access, firmware), privileges.fortios_check),
                 "fortiadc": (lambda access, firmware: privileges.fortiadc_write(access), privileges.fortiadc_check)}


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


def _profiles(platform):
    return [(table, profile) for (profile_platform, table), profile in sorted(load_profiles().items())
            if profile_platform == platform]


def unmeasured(operations) -> str:
    """The doctor entry of a table whose profile has no live measurement: refused like preview and apply."""
    return "refused: %s is disabled until a live verification of this profile (%s)" % (operations, NOT_MEASURED)


def _operations(platform, firmware) -> dict:
    # A6 (startup): a firmware outside the tested versions of a profile does not make its operations unavailable;
    # they are listed with "(untested on FIRMWARE)" and firmware_support of the report names the tested versions.
    # Shown as refused: a profile without live measurement (1.0.13, refused by preview and apply before any device
    # contact, for every firmware) and the technical limit T1 (no REST inverse for the FortiOS webhook safeguard).
    tables = {}
    for table, profile in _profiles(platform):
        operations = profile.action or " ".join(profile.ops)
        registered = fortios_tables.hooks(table) if platform == "fortios" else None
        refused_ops = []
        if registered is not None and fortios.webhook_firmware(firmware):
            # 1.0.13 A1-R: on 8.0.1+ a registered table offers only the operations verified with their opposite
            allowed = fortios_tables.allowed_operations(registered, profile.ops)
            refused_ops = [op for op in profile.ops if op not in allowed]
            operations = " ".join(allowed) or operations
        if not profile.measured:
            tables[table] = unmeasured(operations)
        elif platform == "fortios" and fortios.webhook_refusal(profile, firmware) is not None:
            tables[table] = "refused on %s: the webhook safeguard has no REST inverse for this table (%s)" % (
                firmware, fortios.NO_REST_INVERSE)
        elif refused_ops and len(refused_ops) == len(profile.ops):
            # 1.0.13 A1-R r2: an incomplete pair in rest_verified leaves no operation; the table is refused as a whole
            tables[table] = ("refused on %s: the REST inverse of no operation and its opposite is verified for this"
                             " table (%s)" % (firmware, fortios.NO_REST_INVERSE))
        elif not tested.is_tested(firmware_support(profile, firmware)):
            tables[table] = "%s (untested on %s)" % (operations, firmware)
        else:
            tables[table] = operations
        if refused_ops and table in tables and not tables[table].startswith("refused"):
            tables[table] += "; %s refused on %s: the REST inverse of the operation and its opposite is not verified (%s)" % (
                " ".join(refused_ops), firmware, fortios.NO_REST_INVERSE)
        if platform == "exos" and table == "inline-power":
            tables["poe-cycle"] = tables[table].replace(operations, "poe-cycle", 1)
    return tables


def _firmware_support(platform, firmware) -> dict:
    support = {table: firmware_support(profile, firmware) for table, profile in _profiles(platform)}
    if platform == "exos":
        support["poe-cycle"] = support["inline-power"]
    return support


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
    adapter = execute._adapter(device.platform)
    report = _Report()
    _local(report, runtime, device)
    if device.schema is not None:
        from netops_admin import schema_runtime
        firmware,operations=schema_runtime.doctor(runtime,device,report)
        result=_result(report,device,firmware)
        result["operations"]=operations
        result["firmware_support"]={}  # schema workflow: the library is bound to its exact build (kept, startup §1.5)
        return result
    preflight = getattr(adapter, "safeguard_preflight", None)
    rights = RIGHTS if device.platform in RIGHTS_CHECKS else ()
    remote = ("write account and host key", "firmware", "administrator accounts", "check account") + rights + (
              "leftover safeguards", "device prechecks") + (("webhook safeguard",) if preflight else ()) + (
              "audit policy", "enrollment")
    reached, access = report.attempt("credentials", lambda: runtime.access_factory(device))
    if not reached:
        report.skip(*remote)
        return _result(report, device, None)
    with operation(access):
        return _remote_checks(runtime, device, report, adapter, access, remote, rights, preflight)


def _remote_checks(runtime, device, report, adapter, access, remote, rights, preflight):
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
        write_rights, check_rights = RIGHTS_CHECKS[device.platform]
        report.rights(RIGHTS[0], lambda: write_rights(access, firmware))
        report.rights(RIGHTS[1], lambda: check_rights(access))
    report.attempt("leftover safeguards", lambda: _no_leftovers(adapter, access))
    report.attempt("device prechecks", lambda: _prechecks(adapter, access, device, text),
                   str if device.platform == "fortiadc" else None)
    if preflight is not None:
        if firmware:
            report.attempt("webhook safeguard", lambda: preflight(access, device, text, firmware), str)
        else:
            report.skip("webhook safeguard")
    if getattr(adapter, "AUDIT_RULES", True) is False:
        report.add("audit policy", UNVERIFIED, adapter.AUDIT_NOT_RUN[2])
    else:
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
    if device.platform == "fortiadc":
        role = fortiadc.require_ha_write(access)
        return "standalone" if role == "standalone" else "primary with a synchronized secondary"
    reasons = adapter.prechecks(access, device, text, adapter.prompt_spec(adapter.hostname(access, text)))
    if reasons:
        raise Rejected(reasons)


def _result(report, device, firmware) -> dict:
    operations = {} if firmware is None else _operations(device.platform, firmware)
    versions = {} if firmware is None else _firmware_support(device.platform, firmware)
    if device.platform == "fortiadc" and not getattr(device, "fortiadc_https_sha256", None):
        from netops_admin.fortiadc import CERT_MEMBER
        operations.pop(CERT_MEMBER, None)
        versions.pop(CERT_MEMBER, None)
    return {
        "device": device.name,
        "platform": device.platform,
        "firmware": firmware,
        "ready": all(item["status"] in ADVISORY for item in report.checks),
        "checks": report.checks,
        "operations": operations,
        "firmware_support": versions,
        "protected": {table: len(names) for table, names in sorted(device.protected.items())},
    }
