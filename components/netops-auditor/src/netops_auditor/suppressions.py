from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import jsontext
from .findings import FingerprintError, checked_component, fingerprint_of
from .inputs import InputError, read_regular

FILE_VERSION = 2
MAX_SUPPRESSIONS_BYTES = 4 * 1024 * 1024
MOMENT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DOCUMENT_FIELDS = ("version", "tenant", "suppressions")
TEXT_FIELDS = ("rule_id", "device", "object_key", "reason", "author")
ITEM_FIELDS = (
    "fingerprint",
    "rule_id",
    "rule_version",
    "device",
    "object_key",
    "reason",
    "author",
    "created",
    "expires",
)


class SuppressionError(Exception):
    pass


def _checked_now(now) -> datetime:
    if not isinstance(now, datetime):
        raise SuppressionError("now must be a datetime, got %r" % (now,))
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise SuppressionError("now must be timezone aware, got %r" % (now,))
    return now


def _checked_tenant(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SuppressionError("tenant must be a non-empty string, got %r" % (value,))
    try:
        return checked_component("tenant", value)
    except FingerprintError as error:
        raise SuppressionError(str(error)) from None


def _checked_text(index: int, name: str, value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SuppressionError("suppression %d: %s must be a non-empty string, got %r" % (index, name, value))
    return value


def _checked_version(index: int, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SuppressionError("suppression %d: rule_version must be an integer, got %r" % (index, value))
    return value


def _checked_moment(index: int, name: str, value) -> datetime:
    parsed = None
    if isinstance(value, str):
        try:
            parsed = datetime.strptime(value, MOMENT_FORMAT)
        except ValueError:
            parsed = None
    if parsed is None or parsed.strftime(MOMENT_FORMAT) != value:
        raise SuppressionError(
            "suppression %d: %s must be ISO 8601 UTC %s, got %r" % (index, name, MOMENT_FORMAT, value)
        )
    return parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    rule_id: str
    rule_version: int
    tenant: str
    device: str
    object_key: str
    reason: str
    author: str
    created: datetime
    expires: datetime

    def is_active(self, now) -> bool:
        return _checked_now(now) < self.expires


def _shape(index: int, item) -> None:
    if not isinstance(item, dict):
        raise SuppressionError("suppression %d: must be an object, got %r" % (index, item))
    missing = [name for name in ITEM_FIELDS if name not in item]
    if missing:
        raise SuppressionError("suppression %d: missing fields: %s" % (index, ", ".join(missing)))
    unknown = sorted(set(item) - set(ITEM_FIELDS))
    if unknown:
        raise SuppressionError("suppression %d: unknown fields: %s" % (index, ", ".join(unknown)))


def _suppression(index: int, item, tenant: str) -> Suppression:
    _shape(index, item)
    texts = {name: _checked_text(index, name, item[name]) for name in TEXT_FIELDS}
    rule_version = _checked_version(index, item["rule_version"])
    created = _checked_moment(index, "created", item["created"])
    expires = _checked_moment(index, "expires", item["expires"])
    if created >= expires:
        raise SuppressionError(
            "suppression %d: created %s is not before expires %s" % (index, item["created"], item["expires"])
        )
    try:
        expected = fingerprint_of(
            texts["rule_id"], rule_version, tenant, texts["device"], texts["object_key"]
        )
    except FingerprintError as error:
        raise SuppressionError("suppression %d: %s" % (index, error)) from None
    if item["fingerprint"] != expected:
        raise SuppressionError(
            "suppression %d: fingerprint %r does not match components, expected %s"
            % (index, item["fingerprint"], expected)
        )
    return Suppression(
        fingerprint=expected,
        rule_id=texts["rule_id"],
        rule_version=rule_version,
        tenant=tenant,
        device=texts["device"],
        object_key=texts["object_key"],
        reason=texts["reason"],
        author=texts["author"],
        created=created,
        expires=expires,
    )


def _read(path: Path) -> dict:
    try:
        data = read_regular(path, MAX_SUPPRESSIONS_BYTES)
    except (OSError, InputError) as error:
        raise SuppressionError("cannot read suppression file %s: %s" % (path, error)) from None
    try:
        raw = data.decode("utf-8")
    except UnicodeDecodeError:
        raise SuppressionError("suppression file %s is not valid UTF-8" % path) from None
    try:
        document = jsontext.loads(raw)
    except ValueError as error:
        raise SuppressionError("suppression file %s is not valid JSON: %s" % (path, error)) from None
    if not isinstance(document, dict):
        raise SuppressionError("suppression file %s must hold an object, got %r" % (path, document))
    if "version" not in document:
        raise SuppressionError("suppression file %s: missing document fields: version" % path)
    return document


def _document(path: Path) -> dict:
    document = _read(path)
    version = document["version"]
    if isinstance(version, bool) or version != FILE_VERSION:
        raise SuppressionError(
            "suppression file %s: unknown suppression file version %r, expected %d" % (path, version, FILE_VERSION)
        )
    missing = [name for name in DOCUMENT_FIELDS if name not in document]
    if "tenant" in missing:
        raise SuppressionError(
            "suppression file %s: missing document fields: tenant; a suppression file binds to one"
            " tenant, which the fingerprint carries" % path
        )
    if missing:
        raise SuppressionError("suppression file %s: missing document fields: %s" % (path, ", ".join(missing)))
    unknown = sorted(set(document) - set(DOCUMENT_FIELDS))
    if unknown:
        raise SuppressionError("suppression file %s: unknown document fields: %s" % (path, ", ".join(unknown)))
    if not isinstance(document["suppressions"], list):
        raise SuppressionError(
            "suppression file %s: suppressions must be a list, got %r" % (path, document["suppressions"])
        )
    if not isinstance(document["tenant"], str) or not document["tenant"].strip():
        raise SuppressionError(
            "suppression file %s: tenant must be a non-empty string, got %r" % (path, document["tenant"])
        )
    try:
        checked_component("tenant", document["tenant"])
    except FingerprintError as error:
        raise SuppressionError("suppression file %s: %s" % (path, error)) from None
    return document



def load(path, tenant) -> tuple:
    location = Path(path)
    _checked_tenant(tenant)
    document = _document(location)
    bound = document["tenant"]
    if bound != tenant:
        raise SuppressionError(
            "suppression file %s is bound to tenant %r, this run is for tenant %r"
            % (location, bound, tenant)
        )
    suppressions, seen = [], {}
    for index, item in enumerate(document["suppressions"]):
        entry = _suppression(index, item, bound)
        if entry.fingerprint in seen:
            raise SuppressionError(
                "suppression %d: duplicate fingerprint %s, already used by suppression %d"
                % (index, entry.fingerprint, seen[entry.fingerprint])
            )
        seen[entry.fingerprint] = index
        suppressions.append(entry)
    return tuple(suppressions)


def load_for_tenant(path, tenant) -> tuple:
    location = Path(path).expanduser()
    return location, load(location, tenant)


def active_fingerprints(suppressions, now) -> frozenset:
    moment = _checked_now(now)
    return frozenset(item.fingerprint for item in suppressions if item.is_active(moment))


def expired(suppressions, now) -> tuple:
    moment = _checked_now(now)
    return tuple(item for item in suppressions if not item.is_active(moment))
