from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from netops_admin.errors import Rejected, shown
from netops_admin.jsontext import loads
from netops_auditor.management import load_policy
from netops_core.hostkey import HostKeyError, checked_public_key
from netops_core.inputs import InputError, read_regular

CONFIG_VERSION = 1
CONFIG_MAX_BYTES = 1024 * 1024
SAFEGUARD_MAX_SECONDS = 900
CONFIG_FIELDS = frozenset(("version", "state_dir", "audit_file", "export_status_file", "export_status_require_audit_file",
                           "notify", "limits", "devices", "mcp_undo"))
DEVICE_FIELDS = frozenset((
    "platform", "address", "port", "host_key_fingerprint", "vault", "credential", "firmware",
    "safeguard_seconds", "confirm_margin_seconds", "protected", "legacy_ssh", "accounts", "check_credential",
    "check_address", "audit_policy", "schema", "opt_in", "wlans", "host_key",
    "fortiadc_https_port", "fortiadc_https_sha256",
))
# system interface and router static (1.0.12 G19) change the network path: opt-in and protected system interface
IPSEC_TABLES = ("vpn ipsec phase2-interface", "ipsec-tunnel")
NAT_TABLES = ("firewall vip", "firewall ippool")
PATH_TABLES = ("firewall policy", "system interface", "router static", *IPSEC_TABLES, *NAT_TABLES)
OPT_IN_TABLES = (*PATH_TABLES, "firewall service custom")
ADMIN_PLATFORMS = ("fortios", "exos", "eos", "ios", "iosxe", "fortiadc", "nxos", "junos", "ruckus")
# platforms whose device entry must list the expected local accounts (the snapshot shows them)
ACCOUNT_LIST_PLATFORMS = ("exos", "eos", "ios", "iosxe", "nxos", "junos")
# platforms whose snapshot does not name the full firmware: the device entry states it and the prechecks compare it
# with the live show version (Junos names it in the "set version" line of its snapshot)
FIRMWARE_PLATFORMS = ("exos", "ios", "iosxe")
PLATFORM_NAMES = {"exos": "ExtremeXOS", "eos": "EOS", "ios": "Cisco IOS", "iosxe": "Cisco IOS XE", "nxos": "NX-OS",
                  "junos": "Junos", "ruckus": "Ruckus Unleashed"}
# Junos commits the change with "commit confirmed 10" (the timer of the safeguard restarts with every commit
# confirmed, so the change commit carries the same minutes); a commit took up to 150 s on the measured vJunos, so the
# confirmation needs a margin that covers one commit with a reserve (exec_junos.py)
JUNOS_SAFEGUARD_SECONDS = 600
JUNOS_MIN_CONFIRM_MARGIN_SECONDS = 240
NOTIFY_FIELDS = frozenset(("server", "topic_file", "timeout_seconds", "x509_strict"))
DEFAULT_LIMITS = {
    "export_max_pending": 1000, "export_max_age_seconds": 900, "export_status_max_age_seconds": 120,
    "changes_per_device_per_hour": 6, "changes_per_day": 40, "rejections_per_hour": 30,
    "plan_commands": 32, "journal_records": 20000,
}
LIMIT_FIELDS = frozenset(DEFAULT_LIMITS)
NOTIFY_TIMEOUT_SECONDS = (1, 60)
DEVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
WLAN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
PIN = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


@dataclass(frozen=True)
class Device:
    name: str
    platform: str
    address: str
    port: int
    host_key_fingerprint: str
    vault: str
    credential: str
    firmware: str | None
    safeguard_seconds: int
    confirm_margin_seconds: int
    protected: dict
    legacy_ssh: str | None = None
    accounts: tuple = ()
    check_credential: str = ""
    check_address: str | None = None
    audit_policy: dict | None = None
    schema: dict | None = None
    opt_in: tuple = ()
    # Ruckus Unleashed: the WLANs Admin may write; every other WLAN is refused (1.0.12 G111)
    wlans: tuple = ()
    host_key: str | None = None
    fortiadc_https_port: int = 443
    fortiadc_https_sha256: str | None = None


@dataclass(frozen=True)
class Notify:
    server: str
    topic_file: str
    timeout_seconds: float
    x509_strict: bool


@dataclass(frozen=True)
class Config:
    state_dir: str
    audit_file: str
    export_status_file: str | None
    notify: Notify | None
    limits: dict
    devices: dict
    export_status_require_audit_file: bool = False
    # 1.0.12 G07 r2, decision of the administrator 2026-11-18: the MCP tools admin_undo, admin_unblock_preview and
    # admin_unblock are off unless the configuration opts in; the operator commands do not depend on it
    mcp_undo: bool = False


def summary(config) -> dict:
    return {"export_status_require_audit_file": config.export_status_require_audit_file}


def _require(condition, message, *, field="config", code="invalid"):
    if not condition:
        error = Rejected(["configuration: %s" % message])
        error.diagnostic = (field, code)
        raise error


def _absolute(value, label, *, field=None):
    _require(isinstance(value, str) and os.path.isabs(value) and "\x00" not in value,
             "%s must be an absolute path" % label, field=field or "config." + label.replace(" ", "."), code='absolute')
    return value


def _integer(value, label, low, high, *, field=None):
    _require(isinstance(value, int) and not isinstance(value, bool) and low <= value <= high,
             "%s must be an integer in %d..%d" % (label, low, high), field=field or "config." + label.replace(" ", "."), code='integer')
    return value


def _device(name, data) -> Device:
    _require(DEVICE_NAME.fullmatch(name) is not None, "device name %s is not an inventory alias" % shown(name), field='config.devices[].name', code='component')
    _require(isinstance(data, dict) and not set(data) - DEVICE_FIELDS,
             "device %s has unknown fields" % name, field='config.devices[]', code='unknown-fields')
    for field in ("platform", "address", "host_key_fingerprint", "vault", "credential", "check_credential"):
        _require(field in data, "device %s needs %s" % (name, field), field="config.devices[]." + field, code='required')
    _require(data["platform"] in ADMIN_PLATFORMS, "device %s platform must be fortios, exos, eos, ios, iosxe, fortiadc, nxos, junos or ruckus" % name, field='config.devices[].platform', code='admin-platform')
    _require(PIN.fullmatch(str(data["host_key_fingerprint"])) is not None,
             "device %s host_key_fingerprint must be an OpenSSH SHA256 pin" % name, field='config.devices[].host_key_fingerprint', code='ssh-pin')
    public_key = data.get("host_key")
    if "host_key" in data:
        try:
            public_key = checked_public_key(public_key, data["host_key_fingerprint"])
        except HostKeyError as exc:
            _require(False, "device %s: %s" % (name, exc), field="config.devices[].host_key", code="ssh-public-key")
    protected = data.get("protected", {})
    _require(isinstance(protected, dict) and all(
        isinstance(table, str) and isinstance(names, list) and all(isinstance(item, str) for item in names)
        for table, names in protected.items()
    ), "device %s protected must map a table to names" % name, field='config.devices[].protected', code='protected')
    opt_in = data.get("opt_in", [])
    _require(isinstance(opt_in, list) and all(isinstance(item, str) and item in OPT_IN_TABLES for item in opt_in)
             and len(set(opt_in)) == len(opt_in), "device %s opt_in must list distinct opt-in tables" % name,
             field='config.devices[].opt_in', code='opt-in')
    for table in opt_in:
        _require(data["platform"] == "fortios", "device %s: %s is a FortiOS table" % (name, table),
                 field='config.devices[].opt_in', code='opt-in')
    for table in PATH_TABLES:
        _require(table not in opt_in or protected.get("system interface") or
                 (table in (*IPSEC_TABLES, *NAT_TABLES) and protected.get("interface")),
                 "device %s: %s changes need protected system interface" % (name, table),
                 field='config.devices[].protected', code='required')
    firmware = data.get("firmware")
    _require(firmware is None or isinstance(firmware, str), "device %s firmware must be a string" % name, field='config.devices[].firmware', code='text')
    _require(data["platform"] not in FIRMWARE_PLATFORMS or firmware, "device %s: %s needs the firmware stated" % (name, PLATFORM_NAMES.get(data["platform"])), field='config.devices[].firmware', code='required')
    legacy = data.get("legacy_ssh")
    _require(legacy is None or isinstance(legacy, str), "device %s legacy_ssh must be a profile name" % name, field='config.devices[].legacy_ssh', code='text')
    accounts = data.get("accounts", [])
    _require(isinstance(accounts, list) and all(isinstance(item, str) and item for item in accounts)
             and len(set(accounts)) == len(accounts), "device %s accounts must be distinct names" % name, field='config.devices[].accounts', code='distinct-names')
    _require(data["platform"] not in ACCOUNT_LIST_PLATFORMS or accounts, "device %s: %s needs the expected accounts" % (name, PLATFORM_NAMES.get(data["platform"])), field='config.devices[].accounts', code='required')
    check_address = data.get("check_address")
    _require(check_address is None or (isinstance(check_address, str) and check_address
                                        and check_address != data["address"]),
             "device %s check_address must be another address than address" % name, field='config.devices[].check_address', code='different-address')
    wlans = data.get("wlans", [])
    _require(isinstance(wlans, list) and all(isinstance(item, str) and WLAN_NAME.fullmatch(item) for item in wlans)
             and len({item.casefold() for item in wlans}) == len(wlans),
             "device %s wlans must list distinct WLAN names" % name, field='config.devices[].wlans', code='distinct-wlans')
    _require(data["platform"] == "ruckus" or not wlans, "device %s: wlans is a Ruckus Unleashed field" % name,
             field='config.devices[].wlans', code='wlans')
    _require(data["platform"] != "ruckus" or wlans, "device %s: Ruckus Unleashed needs the WLANs Admin may write (wlans)" % name,
             field='config.devices[].wlans', code='required')
    _require(data["platform"] == "ruckus" or data["check_credential"] != data["credential"],
             "device %s: the check credential must be another account than the write credential" % name, field='config.devices[].check_credential', code='different-credential')
    safeguard = _integer(data.get("safeguard_seconds", 180), "safeguard_seconds", 60, SAFEGUARD_MAX_SECONDS, field="config.devices[].safeguard_seconds")
    margin = _integer(data.get("confirm_margin_seconds", 45), "confirm_margin_seconds", 15, safeguard - 15, field="config.devices[].confirm_margin_seconds")
    _require(data["platform"] != "junos" or safeguard == JUNOS_SAFEGUARD_SECONDS,
             "device %s: Junos needs safeguard_seconds %d (commit confirmed %d)" % (name, JUNOS_SAFEGUARD_SECONDS, JUNOS_SAFEGUARD_SECONDS // 60),
             field="config.devices[].safeguard_seconds", code="integer")
    _require(data["platform"] != "junos" or margin >= JUNOS_MIN_CONFIRM_MARGIN_SECONDS,
             "device %s: Junos needs confirm_margin_seconds of at least %d (a commit took up to 150 s)" % (name, JUNOS_MIN_CONFIRM_MARGIN_SECONDS),
             field="config.devices[].confirm_margin_seconds", code="integer")
    policy = None
    if "audit_policy" in data:
        try:
            policy = load_policy(_absolute(data["audit_policy"], "audit_policy", field="config.devices[].audit_policy"), data["platform"])
        except (OSError, ValueError, UnicodeError):
            error = Rejected(["configuration: audit policy cannot be loaded or is invalid"])
            error.diagnostic = ("config.devices[].audit_policy", "policy")
            raise error from None
    schema_binding = data.get("schema")
    if schema_binding is not None:
        fields = {"library","schema_sha256","calibration","calibration_sha256","vdoms"}
        _require(data["platform"] == "fortios" and isinstance(schema_binding,dict)
                 and set(schema_binding) == fields, "schema binding fields are invalid", field='config.devices[].schema', code='schema')
        for field in ("library","calibration"):
            _absolute(schema_binding[field], "schema "+field, field="config.devices[].schema." + field)
        for field in ("schema_sha256","calibration_sha256"):
            _require(isinstance(schema_binding[field],str) and re.fullmatch(r"[a-f0-9]{64}",schema_binding[field]),
                     "schema binding digest is invalid", field='config.devices[].schema', code='digest')
        domains = schema_binding["vdoms"]
        _require(isinstance(domains,list) and 1 <= len(domains) <= 64
                 and all(isinstance(x,str) and x and x.isprintable() and len(x.encode()) <= 128 and "%%" not in x for x in domains)
                 and len(set(domains)) == len(domains), "schema VDOM inventory is invalid", field='config.devices[].schema.vdoms', code='vdoms')
    adc_pin = data.get("fortiadc_https_sha256")
    _require(("fortiadc_https_port" not in data and "fortiadc_https_sha256" not in data) or
             (data["platform"] == "fortiadc" and isinstance(adc_pin, str)
              and re.fullmatch(r"[a-f0-9]{64}", adc_pin) is not None),
             "FortiADC certificate management requires a lowercase SHA-256 HTTPS certificate pin",
             field="config.devices[].fortiadc_https_sha256", code="digest")
    return Device(
        name=name, platform=data["platform"], address=str(data["address"]),
        port=_integer(data.get("port", 22), "port", 1, 65535, field="config.devices[].port"),
        host_key_fingerprint=data["host_key_fingerprint"], vault=_absolute(data["vault"], "vault", field="config.devices[].vault"),
        credential=str(data["credential"]), firmware=firmware, safeguard_seconds=safeguard,
        confirm_margin_seconds=margin, protected={table: list(names) for table, names in protected.items()},
        legacy_ssh=legacy, accounts=tuple(accounts), check_credential=str(data["check_credential"]),
        check_address=check_address, audit_policy=policy, schema=schema_binding,
        opt_in=tuple(opt_in), wlans=tuple(wlans), host_key=public_key,
        fortiadc_https_sha256=adc_pin,
        fortiadc_https_port=_integer(data.get("fortiadc_https_port", 443), "fortiadc_https_port", 1, 65535,
                                    field="config.devices[].fortiadc_https_port"),
    )


def load_config(path) -> Config:
    name = shown(Path(path).name)
    try:
        raw = read_regular(path, CONFIG_MAX_BYTES)
    except (OSError, InputError) as cause:
        error = Rejected(["configuration %s cannot be read: %s" % (name, getattr(cause, "strerror", None) or cause)])
        error.diagnostic = ("config", "read")
        raise error from None
    try:
        data = loads(raw, "configuration %s" % name)
    except Rejected as error:
        error.diagnostic = ("config", "json")
        raise
    _require(isinstance(data, dict), "must be a JSON object", field='config', code='object')
    _require(not set(data) - CONFIG_FIELDS, "unknown fields %s" % sorted(set(data) - CONFIG_FIELDS), field='config', code='unknown-fields')
    _require(data.get("version") == CONFIG_VERSION, "version must be %d" % CONFIG_VERSION, field='config.version', code='version1')
    devices = data.get("devices")
    _require(isinstance(devices, dict) and devices, "devices must be a non-empty object", field='config.devices', code='nonempty-object')
    notify = data.get("notify")
    if notify is not None:
        _require(isinstance(notify, dict) and not set(notify) - NOTIFY_FIELDS and "server" in notify
                 and "topic_file" in notify, "notify needs server and topic_file only", field='config.notify', code='notify-fields')
        _require(str(notify["server"]).startswith("https://"), "notify server must use https", field='config.notify.server', code='https')
        _require(isinstance(notify.get("x509_strict", True), bool), "notify x509_strict must be true or false", field='config.notify.x509_strict', code='boolean')
        timeout = notify.get("timeout_seconds", 10)
        low, high = NOTIFY_TIMEOUT_SECONDS
        _require(isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and low <= timeout <= high,
                 "notify timeout_seconds must be a number in %d..%d" % (low, high), field='config.notify.timeout_seconds', code='notify-timeout')
        notify = Notify(server=notify["server"], topic_file=_absolute(notify["topic_file"], "notify topic_file"),
                        timeout_seconds=float(timeout),
                        x509_strict=notify.get("x509_strict", True))
    limits = dict(DEFAULT_LIMITS)
    given = data.get("limits", {})
    _require(isinstance(given, dict) and not set(given) - LIMIT_FIELDS, "limits has unknown fields", field='config.limits', code='unknown-fields')
    for field, value in given.items():
        limits[field] = _integer(value, field, 1, 10 ** 6, field="config.limits." + field)
    export_status = data.get("export_status_file")
    require_audit_file = data.get("export_status_require_audit_file", False)
    _require(isinstance(require_audit_file, bool), "export_status_require_audit_file must be true or false", field='config.export_status_require_audit_file', code='boolean')
    mcp_undo = data.get("mcp_undo", False)
    _require(isinstance(mcp_undo, bool), "mcp_undo must be true or false", field='config.mcp_undo', code='boolean')
    return Config(
        state_dir=_absolute(data.get("state_dir"), "state_dir"),
        audit_file=_absolute(data.get("audit_file"), "audit_file"),
        export_status_file=None if export_status is None else _absolute(export_status, "export_status_file"),
        notify=notify, limits=limits,
        devices={name: _device(name, value) for name, value in devices.items()},
        export_status_require_audit_file=require_audit_file,
        mcp_undo=mcp_undo,
    )
