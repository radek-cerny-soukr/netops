from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from netops_admin.errors import Rejected, shown
from netops_admin.jsontext import loads
from netops_auditor.management import load_policy
from netops_core.inputs import InputError, read_regular

CONFIG_VERSION = 1
CONFIG_MAX_BYTES = 1024 * 1024
SAFEGUARD_MAX_SECONDS = 900
CONFIG_FIELDS = frozenset(("version", "state_dir", "audit_file", "export_status_file", "notify", "limits", "devices"))
DEVICE_FIELDS = frozenset((
    "platform", "address", "port", "host_key_fingerprint", "vault", "credential", "firmware",
    "safeguard_seconds", "confirm_margin_seconds", "protected", "legacy_ssh", "accounts", "check_credential",
    "check_address", "audit_policy", "schema",
))
NOTIFY_FIELDS = frozenset(("server", "topic_file", "timeout_seconds", "x509_strict"))
DEFAULT_LIMITS = {
    "export_max_pending": 1000, "export_max_age_seconds": 900, "export_status_max_age_seconds": 120,
    "changes_per_device_per_hour": 6, "changes_per_day": 40, "rejections_per_hour": 30,
    "plan_commands": 32, "journal_records": 20000,
}
LIMIT_FIELDS = frozenset(DEFAULT_LIMITS)
NOTIFY_TIMEOUT_SECONDS = (1, 60)
DEVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
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


def _require(condition, message):
    if not condition:
        raise Rejected(["configuration: %s" % message])


def _absolute(value, label):
    _require(isinstance(value, str) and os.path.isabs(value) and "\x00" not in value,
             "%s must be an absolute path" % label)
    return value


def _integer(value, label, low, high):
    _require(isinstance(value, int) and not isinstance(value, bool) and low <= value <= high,
             "%s must be an integer in %d..%d" % (label, low, high))
    return value


def _device(name, data) -> Device:
    _require(DEVICE_NAME.fullmatch(name) is not None, "device name %s is not an inventory alias" % shown(name))
    _require(isinstance(data, dict) and not set(data) - DEVICE_FIELDS,
             "device %s has unknown fields" % name)
    for field in ("platform", "address", "host_key_fingerprint", "vault", "credential", "check_credential"):
        _require(field in data, "device %s needs %s" % (name, field))
    _require(data["platform"] in ("fortios", "exos"), "device %s platform must be fortios or exos" % name)
    _require(PIN.fullmatch(str(data["host_key_fingerprint"])) is not None,
             "device %s host_key_fingerprint must be an OpenSSH SHA256 pin" % name)
    protected = data.get("protected", {})
    _require(isinstance(protected, dict) and all(
        isinstance(table, str) and isinstance(names, list) and all(isinstance(item, str) for item in names)
        for table, names in protected.items()
    ), "device %s protected must map a table to names" % name)
    firmware = data.get("firmware")
    _require(firmware is None or isinstance(firmware, str), "device %s firmware must be a string" % name)
    _require(data["platform"] != "exos" or firmware, "device %s: ExtremeXOS needs the firmware stated" % name)
    legacy = data.get("legacy_ssh")
    _require(legacy is None or isinstance(legacy, str), "device %s legacy_ssh must be a profile name" % name)
    accounts = data.get("accounts", [])
    _require(isinstance(accounts, list) and all(isinstance(item, str) and item for item in accounts)
             and len(set(accounts)) == len(accounts), "device %s accounts must be distinct names" % name)
    _require(data["platform"] != "exos" or accounts, "device %s: ExtremeXOS needs the expected accounts" % name)
    check_address = data.get("check_address")
    _require(check_address is None or (isinstance(check_address, str) and check_address
                                        and check_address != data["address"]),
             "device %s check_address must be another address than address" % name)
    _require(data["check_credential"] != data["credential"],
             "device %s: the check credential must be another account than the write credential" % name)
    safeguard = _integer(data.get("safeguard_seconds", 180), "safeguard_seconds", 60, SAFEGUARD_MAX_SECONDS)
    margin = _integer(data.get("confirm_margin_seconds", 45), "confirm_margin_seconds", 15, safeguard - 15)
    policy = None
    if "audit_policy" in data:
        try:
            policy = load_policy(_absolute(data["audit_policy"], "audit_policy"), data["platform"])
        except (OSError, ValueError, UnicodeError):
            raise Rejected(["configuration: audit policy cannot be loaded or is invalid"]) from None
    schema_binding = data.get("schema")
    if schema_binding is not None:
        fields = {"library","schema_sha256","calibration","calibration_sha256","vdoms"}
        _require(data["platform"] == "fortios" and isinstance(schema_binding,dict)
                 and set(schema_binding) == fields, "schema binding fields are invalid")
        for field in ("library","calibration"):
            _absolute(schema_binding[field], "schema "+field)
        for field in ("schema_sha256","calibration_sha256"):
            _require(isinstance(schema_binding[field],str) and re.fullmatch(r"[a-f0-9]{64}",schema_binding[field]),
                     "schema binding digest is invalid")
        domains = schema_binding["vdoms"]
        _require(isinstance(domains,list) and 1 <= len(domains) <= 64
                 and all(isinstance(x,str) and x and x.isprintable() and len(x.encode()) <= 128 and "%%" not in x for x in domains)
                 and len(set(domains)) == len(domains), "schema VDOM inventory is invalid")
    return Device(
        name=name, platform=data["platform"], address=str(data["address"]),
        port=_integer(data.get("port", 22), "port", 1, 65535),
        host_key_fingerprint=data["host_key_fingerprint"], vault=_absolute(data["vault"], "vault"),
        credential=str(data["credential"]), firmware=firmware, safeguard_seconds=safeguard,
        confirm_margin_seconds=margin, protected={table: list(names) for table, names in protected.items()},
        legacy_ssh=legacy, accounts=tuple(accounts), check_credential=str(data["check_credential"]),
        check_address=check_address, audit_policy=policy, schema=schema_binding,
    )


def load_config(path) -> Config:
    name = shown(Path(path).name)
    try:
        raw = read_regular(path, CONFIG_MAX_BYTES)
    except (OSError, InputError) as error:
        raise Rejected(["configuration %s cannot be read: %s" % (name, getattr(error, "strerror", None) or error)]) from None
    data = loads(raw, "configuration %s" % name)
    _require(isinstance(data, dict), "must be a JSON object")
    _require(not set(data) - CONFIG_FIELDS, "unknown fields %s" % sorted(set(data) - CONFIG_FIELDS))
    _require(data.get("version") == CONFIG_VERSION, "version must be %d" % CONFIG_VERSION)
    devices = data.get("devices")
    _require(isinstance(devices, dict) and devices, "devices must be a non-empty object")
    notify = data.get("notify")
    if notify is not None:
        _require(isinstance(notify, dict) and not set(notify) - NOTIFY_FIELDS and "server" in notify
                 and "topic_file" in notify, "notify needs server and topic_file only")
        _require(str(notify["server"]).startswith("https://"), "notify server must use https")
        _require(isinstance(notify.get("x509_strict", True), bool), "notify x509_strict must be true or false")
        timeout = notify.get("timeout_seconds", 10)
        low, high = NOTIFY_TIMEOUT_SECONDS
        _require(isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and low <= timeout <= high,
                 "notify timeout_seconds must be a number in %d..%d" % (low, high))
        notify = Notify(server=notify["server"], topic_file=_absolute(notify["topic_file"], "notify topic_file"),
                        timeout_seconds=float(timeout),
                        x509_strict=notify.get("x509_strict", True))
    limits = dict(DEFAULT_LIMITS)
    given = data.get("limits", {})
    _require(isinstance(given, dict) and not set(given) - LIMIT_FIELDS, "limits has unknown fields")
    for field, value in given.items():
        limits[field] = _integer(value, field, 1, 10 ** 6)
    export_status = data.get("export_status_file")
    return Config(
        state_dir=_absolute(data.get("state_dir"), "state_dir"),
        audit_file=_absolute(data.get("audit_file"), "audit_file"),
        export_status_file=None if export_status is None else _absolute(export_status, "export_status_file"),
        notify=notify, limits=limits,
        devices={name: _device(name, value) for name, value in devices.items()},
    )
