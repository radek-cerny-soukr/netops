from __future__ import annotations

import json
import stat
from dataclasses import InitVar, dataclass
from pathlib import Path

FILE_VERSION = 2
KINDS = ("password", "ssh-key", "api-token", "snmp-community")
LOGIN_KINDS = ("password", "ssh-key")
DOCUMENT_FIELDS = ("version", "credentials")
ENTRY_FIELDS = ("kind", "login", "value")
REQUIRED_ENTRY_FIELDS = ("kind", "value")
ALLOWED_MODES = (0o600, 0o400)
PRIVATE_KEY_PREFIX = "-----BEGIN "
LOGIN_MARKS = ("@", ":", "/", " ", "\t", "\n", "\r")
HIDDEN = "<hidden credential value>"


class VaultError(Exception):
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
            )
        return None
    if value is None:
        raise VaultError(
            "credential %r: login is required for kind %s, the record must name the account it"
            " belongs to" % (name, kind)
        )
    if not isinstance(value, str) or not value.strip():
        raise VaultError(
            "credential %r: login must be a non-empty string, got %s" % (name, type(value).__name__)
        )
    login = value.strip()
    if login.startswith("-") or any(mark in login for mark in LOGIN_MARKS):
        raise VaultError(
            "credential %r: login must be a plain user name without a leading -, @, :, / or"
            " whitespace, got %r" % (name, value)
        )
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
            )
        if self.kind not in KINDS:
            raise VaultError(
                "credential %r: kind must be one of: %s" % (self.name, ", ".join(KINDS))
            )
        object.__setattr__(self, "login", _checked_login(self.name, self.kind, self.login))
        if not isinstance(value, str) or not value.strip():
            raise VaultError(
                "credential %r: value must be a non-empty string, got %s"
                % (self.name, type(value).__name__)
            )
        if self.kind == "ssh-key" and not value.startswith(PRIVATE_KEY_PREFIX):
            raise VaultError(
                "credential %r: value of kind %s must hold the private key text and start with %r"
                % (self.name, self.kind, PRIVATE_KEY_PREFIX)
            )
        object.__setattr__(self, "_secret", _Secret(value))

    def use(self) -> str:
        return self._secret.reveal()


class Vault:
    def __init__(self, path, credentials) -> None:
        self._path = Path(path)
        self._credentials = {credential.name: credential for credential in credentials}

    def names(self) -> tuple:
        return tuple(sorted(self._credentials))

    def credential(self, name) -> Credential:
        if not isinstance(name, str):
            raise VaultError(
                "vault file %s: credential name must be a string, got %s"
                % (self._path, type(name).__name__)
            )
        if name not in self._credentials:
            raise VaultError(
                "vault file %s: unknown credential %r, known names: %s"
                % (self._path, name, ", ".join(self.names()) or "none")
            )
        return self._credentials[name]

    def __repr__(self) -> str:
        return "Vault(path=%s, names=(%s))" % (self._path, ", ".join(self.names()))


def _checked_file(path: Path) -> None:
    try:
        status = path.lstat()
    except FileNotFoundError:
        raise VaultError("vault file %s does not exist" % path) from None
    except OSError as error:
        raise VaultError("cannot stat vault file %s: %s" % (path, error.strerror)) from None
    if stat.S_ISLNK(status.st_mode):
        raise VaultError(
            "vault file %s is a symbolic link, the vault must be a regular file whose mode this"
            " process can judge, a link hands that decision to its target" % path
        )
    if not stat.S_ISREG(status.st_mode):
        raise VaultError("vault file %s must be a regular file" % path)
    mode = stat.S_IMODE(status.st_mode)
    if mode not in ALLOWED_MODES:
        raise VaultError(
            "vault file %s has mode 0%o, must be one of: %s"
            % (path, mode, ", ".join("0%o" % allowed for allowed in ALLOWED_MODES))
        )


def _raw(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise VaultError("vault file %s is not valid UTF-8" % path) from None
    except OSError as error:
        raise VaultError("cannot read vault file %s: %s" % (path, error.strerror)) from None


def _document(path: Path, raw: str) -> dict:
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise VaultError(
            "vault file %s is not valid JSON: %s at line %d column %d"
            % (path, error.msg, error.lineno, error.colno)
        ) from None
    if not isinstance(document, dict):
        raise VaultError(
            "vault file %s must hold an object, got %s" % (path, type(document).__name__)
        )
    missing = [name for name in DOCUMENT_FIELDS if name not in document]
    if missing:
        raise VaultError(
            "vault file %s: missing document fields: %s" % (path, ", ".join(missing))
        )
    unknown = sorted(set(document) - set(DOCUMENT_FIELDS))
    if unknown:
        raise VaultError(
            "vault file %s: unknown document fields: %s" % (path, ", ".join(unknown))
        )
    version = document["version"]
    if isinstance(version, bool) or version != FILE_VERSION:
        raise VaultError("vault file %s: version must be %d" % (path, FILE_VERSION))
    if not isinstance(document["credentials"], dict):
        raise VaultError(
            "vault file %s: credentials must be an object, got %s"
            % (path, type(document["credentials"]).__name__)
        )
    return document


def _credential(path: Path, name, entry) -> Credential:
    if not isinstance(name, str) or not name.strip():
        raise VaultError("vault file %s: credential names must be non-empty strings" % path)
    if not isinstance(entry, dict):
        raise VaultError(
            "vault file %s: credential %r must be an object, got %s"
            % (path, name, type(entry).__name__)
        )
    missing = [item for item in REQUIRED_ENTRY_FIELDS if item not in entry]
    if missing:
        raise VaultError(
            "vault file %s: credential %r: missing fields: %s" % (path, name, ", ".join(missing))
        )
    unknown = sorted(set(entry) - set(ENTRY_FIELDS))
    if unknown:
        raise VaultError(
            "vault file %s: credential %r: unknown fields: %s" % (path, name, ", ".join(unknown))
        )
    try:
        return Credential(
            name=name, kind=entry["kind"], value=entry["value"], login=entry.get("login")
        )
    except VaultError as error:
        raise VaultError("vault file %s: %s" % (path, error)) from None


def load(path) -> Vault:
    location = Path(path)
    _checked_file(location)
    document = _document(location, _raw(location))
    credentials = [
        _credential(location, name, document["credentials"][name])
        for name in sorted(document["credentials"])
    ]
    return Vault(location, credentials)
