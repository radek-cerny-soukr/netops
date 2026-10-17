from __future__ import annotations

import errno
import json
import os
import re
import stat
from dataclasses import InitVar, dataclass
from pathlib import Path

from .inputs import InputError, read_regular
from .validation import ValidationError

FILE_VERSION = 2
KINDS = ("password", "ssh-key", "api-token", "snmp-community")
LOGIN_KINDS = ("password", "ssh-key")
DOCUMENT_FIELDS = ("version", "credentials")
VAULT_MAX_BYTES = 1024 * 1024
ENTRY_FIELDS = ("kind", "login", "value")
REQUIRED_ENTRY_FIELDS = ("kind", "value")
ALLOWED_MODES = (0o600, 0o400)
PRIVATE_KEY_PREFIX = "-----BEGIN "
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\r?\n")
PRIVATE_KEY_HEADER_TEXT = "-----BEGIN ... PRIVATE KEY-----"
LOGIN_MARKS = ("@", ":", "/", " ", "\t", "\n", "\r")
HIDDEN = "<hidden credential value>"


class VaultError(ValidationError):
    pass


class _Secret:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return HIDDEN

    def __str__(self) -> str:
        return HIDDEN


def _checked_login(name, kind: str, value):
    if kind not in LOGIN_KINDS:
        if value is not None:
            raise VaultError(
                "credential %r: login must be null for kind %s, only %s log in as a user"
                % (name, kind, " and ".join(LOGIN_KINDS))
            , field='vault.credentials[].login', code='null')
        return None
    if value is None:
        raise VaultError(
            "credential %r: login is required for kind %s, the record must name the account it"
            " belongs to" % (name, kind)
        , field='vault.credentials[].login', code='required')
    if not isinstance(value, str) or not value.strip():
        raise VaultError(
            "credential %r: login must be a non-empty string, got %s" % (name, type(value).__name__)
        , field='vault.credentials[].login', code='text')
    login = value.strip()
    if (
        login.startswith("-")
        or any(mark in login for mark in LOGIN_MARKS)
        or any(character.isspace() for character in login)
    ):
        raise VaultError(
            "credential %r: login must be a plain user name that does not start with - and holds"
            " no @, :, / or whitespace anywhere; the value is not repeated, it may hold a misplaced"
            " secret" % (name,)
        , field='vault.credentials[].login', code='login')
    return login


@dataclass(frozen=True)
class Credential:
    name: str
    kind: str
    value: InitVar[object]
    login: str | None = None

    def __post_init__(self, value) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise VaultError(
                "credential name must be a non-empty string, got %s" % type(self.name).__name__
            , field='vault.credentials[].name', code='text')
        if self.kind not in KINDS:
            raise VaultError(
                "credential %r: kind must be one of: %s" % (self.name, ", ".join(KINDS))
            , field='vault.credentials[].kind', code='credential-kind')
        object.__setattr__(self, "login", _checked_login(self.name, self.kind, self.login))
        if not isinstance(value, str) or not value.strip():
            raise VaultError(
                "credential %r: value must be a non-empty string, got %s"
                % (self.name, type(value).__name__)
            , field='vault.credentials[].value', code='text')
        if self.kind == "ssh-key" and PRIVATE_KEY_HEADER.match(value) is None:
            raise VaultError(
                "credential %r: value of kind %s must hold the private key text and start with"
                " the header line %r; a public key, a certificate or a path is not a private key"
                % (self.name, self.kind, PRIVATE_KEY_HEADER_TEXT)
            , field='vault.credentials[].value', code='private-key')
        object.__setattr__(self, "_secret", _Secret(value))

    def use(self) -> str:
        return self._secret.reveal()


class Vault:
    def __init__(self, path, credentials) -> None:
        self._path = Path(path)
        self._credentials = {credential.name: credential for credential in credentials}

    def names(self) -> tuple:
        return tuple(sorted(self._credentials))

    def credential(self, name, *, where: str = "the credential reference") -> Credential:
        if not isinstance(name, str):
            raise VaultError(
                "vault file %s: credential name must be a string, got %s"
                % (self._path, type(name).__name__)
            , field='vault.credentials[].name', code='text')
        if name not in self._credentials:
            raise VaultError(
                "vault file %s: %s names no record of the credential store; the value is not"
                " repeated, a value that names no record may be a misplaced secret; known names: %s"
                % (self._path, where, ", ".join(self.names()) or "none")
            , field='vault.credentials', code='reference')
        return self._credentials[name]

    def __repr__(self) -> str:
        return "Vault(path=%s, names=(%s))" % (self._path, ", ".join(self.names()))


def _judge(path: Path):
    def judge(status) -> None:
        if status.st_uid != os.geteuid():
            raise VaultError(
                "vault file %s belongs to user %d, not to the user %d of this process"
                % (path, status.st_uid, os.geteuid())
            , field='vault', code='owner')
        if status.st_nlink != 1:
            raise VaultError(
                "vault file %s has %d hard links; the vault must be the only name of its file"
                % (path, status.st_nlink)
            , field='vault', code='single-link')
        mode = stat.S_IMODE(status.st_mode)
        if mode not in ALLOWED_MODES:
            raise VaultError(
                "vault file %s has mode 0%o, must be one of: %s"
                % (path, mode, ", ".join("0%o" % allowed for allowed in ALLOWED_MODES))
            , field='vault', code='private-mode')

    return judge


def _raw(path: Path) -> str:
    if "\x00" in str(path):
        raise VaultError("vault file path holds a NUL character", field='vault', code='read')
    try:
        return read_regular(path, VAULT_MAX_BYTES, follow=False, judge=_judge(path)).decode(
            "utf-8"
        )
    except UnicodeDecodeError:
        raise VaultError("vault file %s is not valid UTF-8" % path, field='vault', code='utf8') from None
    except FileNotFoundError:
        raise VaultError("vault file %s does not exist" % path, field='vault', code='read') from None
    except InputError as error:
        if str(error) == "not a regular file":
            raise VaultError("vault file %s must be a regular file" % path, field='vault', code='regular') from None
        raise VaultError("cannot read vault file %s: %s" % (path, error), field='vault', code='read') from None
    except OSError as error:
        if error.errno == errno.ELOOP and os.path.islink(path):
            raise VaultError(
                "vault file %s is a symbolic link, the vault must be a regular file whose mode this"
                " process can judge, a link hands that decision to its target" % path
            , field='vault', code='regular') from None
        raise VaultError("cannot read vault file %s: %s" % (path, error.strerror), field='vault', code='read') from None


class _DuplicateKey(ValueError):
    pass


def _unique(pairs) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey()
        result[key] = value
    return result


def _document(path: Path, raw: str) -> dict:
    try:
        document = json.loads(raw, object_pairs_hook=_unique)
    except json.JSONDecodeError as error:
        raise VaultError(
            "vault file %s is not valid JSON: %s at line %d column %d"
            % (path, error.msg, error.lineno, error.colno)
        , field='vault', code='json') from None
    except _DuplicateKey:
        raise VaultError("vault file %s holds a duplicate key within one object" % path, field='vault', code='duplicate') from None
    except ValueError:
        raise VaultError("vault file %s holds a number too long to read" % path, field='vault', code='json') from None
    except RecursionError:
        raise VaultError("vault file %s is nested too deeply" % path, field='vault', code='depth') from None
    try:
        json.dumps(document, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        raise VaultError("vault file %s holds an unpaired surrogate escape" % path, field='vault', code='utf8') from None
    if not isinstance(document, dict):
        raise VaultError(
            "vault file %s must hold an object, got %s" % (path, type(document).__name__)
        , field='vault', code='object')
    missing = [name for name in DOCUMENT_FIELDS if name not in document]
    if missing:
        raise VaultError(
            "vault file %s: missing document fields: %s" % (path, ", ".join(missing))
        , field='vault.' + missing[0], code='required')
    unknown = sorted(set(document) - set(DOCUMENT_FIELDS))
    if unknown:
        raise VaultError(
            "vault file %s: unknown document fields: %s" % (path, ", ".join(unknown))
        , field='vault', code='unknown-fields')
    version = document["version"]
    if isinstance(version, bool) or version != FILE_VERSION:
        raise VaultError("vault file %s: version must be %d" % (path, FILE_VERSION), field='vault.version', code='version2')
    if not isinstance(document["credentials"], dict):
        raise VaultError(
            "vault file %s: credentials must be an object, got %s"
            % (path, type(document["credentials"]).__name__)
        , field='vault.credentials', code='object')
    return document


def _credential(path: Path, name, entry) -> Credential:
    if not isinstance(name, str) or not name.strip():
        raise VaultError("vault file %s: credential names must be non-empty strings" % path, field='vault.credentials[].name', code='text')
    if not isinstance(entry, dict):
        raise VaultError(
            "vault file %s: credential %r must be an object, got %s"
            % (path, name, type(entry).__name__)
        , field='vault.credentials[]', code='object')
    missing = [item for item in REQUIRED_ENTRY_FIELDS if item not in entry]
    if missing:
        raise VaultError(
            "vault file %s: credential %r: missing fields: %s" % (path, name, ", ".join(missing))
        , field='vault.credentials[].' + missing[0], code='required')
    unknown = sorted(set(entry) - set(ENTRY_FIELDS))
    if unknown:
        raise VaultError(
            "vault file %s: credential %r: unknown fields: %s" % (path, name, ", ".join(unknown))
        , field='vault.credentials[]', code='unknown-fields')
    try:
        return Credential(
            name=name, kind=entry["kind"], value=entry["value"], login=entry.get("login")
        )
    except VaultError as error:
        raise VaultError("vault file %s: %s" % (path, error), diagnostic=getattr(error, "diagnostic", None)) from None


def load(path, *, names=None) -> Vault:
    if names is not None:
        if isinstance(names, (str, bytes)):
            raise VaultError("credential selection must be a collection of names", field='vault.credentials', code='selection')
        try:
            names = tuple(names)
        except TypeError:
            raise VaultError("credential selection must be a collection of names", field='vault.credentials', code='selection') from None
        if any(not isinstance(name, str) or not name.strip() for name in names):
            raise VaultError("credential selection must contain non-empty names", field='vault.credentials', code='selection')
        names = frozenset(names)
    location = Path(path)
    try:
        document = _document(location, _raw(location))
        credentials = [
            _credential(location, name, document["credentials"][name])
            for name in sorted(document["credentials"])
            if names is None or name in names
        ]
        return Vault(location, credentials)
    except RecursionError:
        raise VaultError("vault file %s is nested too deeply" % location, field='vault', code='depth') from None
