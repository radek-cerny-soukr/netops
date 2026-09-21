from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .findings import fingerprint_of, fingerprint_v1

FILE_VERSION = 2
PREVIOUS_FILE_VERSION = 1
MOMENT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MIGRATE_COMMAND = (
    "netops-auditor migrate-suppressions --input <old file> --output <new file> --tenant <tenant>"
)
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
    return value


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
    expected = fingerprint_of(
        texts["rule_id"], rule_version, tenant, texts["device"], texts["object_key"]
    )
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
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise SuppressionError("cannot read suppression file %s: %s" % (path, error)) from None
    try:
        document = json.loads(raw)
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
    if not isinstance(version, bool) and version == PREVIOUS_FILE_VERSION:
        raise SuppressionError(
            "suppression file %s: version %d is refused, a fingerprint carries the tenant since"
            " version %d; migrate the file with %s"
            % (path, PREVIOUS_FILE_VERSION, FILE_VERSION, MIGRATE_COMMAND)
        )
    if isinstance(version, bool) or version != FILE_VERSION:
        raise SuppressionError(
            "suppression file %s: unknown suppression file version %r, expected %d" % (path, version, FILE_VERSION)
        )
    missing = [name for name in DOCUMENT_FIELDS if name not in document]
    if "tenant" in missing:
        raise SuppressionError(
            "suppression file %s: missing document fields: tenant; a suppression file binds to one"
            " tenant, which the fingerprint carries; migrate an older file with %s"
            % (path, MIGRATE_COMMAND)
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


def _migrated_item(index: int, item, tenant: str) -> dict:
    _shape(index, item)
    for name in TEXT_FIELDS:
        if not isinstance(item[name], str) or not item[name].strip():
            raise SuppressionError("suppression %d: %s must be a non-empty string" % (index, name))
    if isinstance(item["rule_version"], bool) or not isinstance(item["rule_version"], int):
        raise SuppressionError("suppression %d: rule_version must be an integer" % index)
    try:
        created = _checked_moment(index, "created", item["created"])
        expires = _checked_moment(index, "expires", item["expires"])
    except SuppressionError:
        raise SuppressionError(
            "suppression %d: created and expires must be ISO 8601 UTC %s" % (index, MOMENT_FORMAT)
        ) from None
    if created >= expires:
        raise SuppressionError("suppression %d: created is not before expires" % index)
    components = (item["rule_id"], item["rule_version"], item["device"], item["object_key"])
    if item["fingerprint"] != fingerprint_v1(*components):
        raise SuppressionError("suppression %d: fingerprint does not match components" % index)
    migrated = {name: item[name] for name in ITEM_FIELDS}
    migrated["fingerprint"] = fingerprint_of(
        item["rule_id"], item["rule_version"], tenant, item["device"], item["object_key"]
    )
    return migrated


def _published(target: Path, text: str) -> None:
    try:
        handle, temporary = tempfile.mkstemp(
            dir=target.parent, prefix="." + target.name + ".", suffix=".part"
        )
    except OSError as error:
        raise SuppressionError("cannot write suppression file %s: %s" % (target, error)) from None
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError:
            raise SuppressionError(
                "suppression file %s exists, the migration never writes over a file" % target
            ) from None
    except OSError as error:
        raise SuppressionError("cannot write suppression file %s: %s" % (target, error)) from None
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass


def migrate_file(source, destination, tenant) -> int:
    origin, target = Path(source), Path(destination)
    _checked_tenant(tenant)
    if origin.resolve() == target.resolve():
        raise SuppressionError("the migration never writes back into %s" % origin)
    if target.is_symlink():
        raise SuppressionError(
            "suppression file %s is a symbolic link, the migration writes only a plain file"
            % target
        )
    if target.exists():
        raise SuppressionError(
            "suppression file %s exists, the migration never writes over a file" % target
        )
    document = _read(origin)
    version = document["version"]
    if isinstance(version, bool) or version != PREVIOUS_FILE_VERSION:
        raise SuppressionError(
            "suppression file %s: the migration reads version %d, found %r"
            % (origin, PREVIOUS_FILE_VERSION, version)
        )
    unknown = sorted(set(document) - set(DOCUMENT_FIELDS))
    if unknown:
        raise SuppressionError("suppression file %s: unknown document fields: %s" % (origin, ", ".join(unknown)))
    if "suppressions" not in document or not isinstance(document["suppressions"], list):
        raise SuppressionError("suppression file %s: suppressions must be a list" % origin)
    bound = document.get("tenant")
    if bound is not None and bound != tenant:
        raise SuppressionError(
            "suppression file %s is bound to tenant %r, the migration was asked for tenant %r"
            % (origin, bound, tenant)
        )
    items, seen = [], {}
    for index, item in enumerate(document["suppressions"]):
        migrated = _migrated_item(index, item, tenant)
        if migrated["fingerprint"] in seen:
            raise SuppressionError(
                "suppression %d: duplicate fingerprint, already used by suppression %d"
                % (index, seen[migrated["fingerprint"]])
            )
        seen[migrated["fingerprint"]] = index
        items.append(migrated)
    written = {"version": FILE_VERSION, "tenant": tenant, "suppressions": items}
    _published(target, json.dumps(written, ensure_ascii=False, indent=2) + "\n")
    return len(items)


def active_fingerprints(suppressions, now) -> frozenset:
    moment = _checked_now(now)
    return frozenset(item.fingerprint for item in suppressions if item.is_active(moment))


def expired(suppressions, now) -> tuple:
    moment = _checked_now(now)
    return tuple(item for item in suppressions if not item.is_active(moment))
