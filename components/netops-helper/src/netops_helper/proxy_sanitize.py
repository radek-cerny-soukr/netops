"""Defense-in-depth secret redaction for MCP tool-call responses."""

from __future__ import annotations

from collections.abc import Iterable
import json
import re
from typing import Any
from netops.redaction_spans import Marked, edits, sub, replace, loads, dumps

from .sanitize import _wtp_128_length_password_capability, redact_snmp_credentials, _replace_credential, _SNMP_PREFIX


FORTI_ENC = re.compile(r"\bENC\s+[^\s\\]+")
PRIVATE_PEM = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.DOTALL,
)
CISCO_SECRET = re.compile(
    r"(?im)^([^\S\n]*(?:enable\s+)?(?:secret|password)(?:\s+\d+)?\s+)\S+"
)
SHADOW_HASH = re.compile(r"(?m)^([^:\r\n]+:)(?:[!*][^:\r\n]*|\$[^:\r\n]+)(?=:)")
LABELED_COMMUNITY = re.compile(
    r"""(?ix)
    (
      \b(?:snmp\s+)?community
      (?:
        \s+string\s+(?:configured|is)\s*[:=]\s*
        |\s+(?:configured|is)\s*[:=]\s*
        |[ \t]*[:=][ \t]*
        |[ \t]+
      )
    )
    ("(?:[^"\\]|\\.)*"|\S+)
    """
)
SENSITIVE_TEXT_FIELD = re.compile(
    r"""(?ix)
    ("?(?:password|passwd|secret|(?:api[_-]?|access[_-]?)?token|private[_-]?key)"?[ \t]*[:=][ \t]*)
    (?!<REDACTED>(?:[\s,}\]\\]|$))
    ("(?:[^"\\]|\\.)*"|[^,}\]\n]+)
    """
)
SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_token", "access_token", "private_key",
    "community", "auth_context",
}


def _normalize_secrets(secrets: Iterable[object]) -> tuple[str, ...]:
    values = {str(value) for value in secrets if len(str(value).encode("utf-8")) >= 3}
    forms = {
        form for value in values for form in (
            value, dumps(value)[1:-1], dumps(value, ensure_ascii=False)[1:-1],
        )
    }
    return tuple(sorted(forms, key=len, reverse=True))


def _sanitize_text(value: str, secrets: Iterable[object] = ()) -> str:
    for secret in _normalize_secrets(secrets):
        value = replace(value, secret, "<REDACTED>")
    value = sub(PRIVATE_PEM, "<PRIVATE-KEY-REDACTED>", value)
    value = sub(FORTI_ENC, "ENC <REDACTED>", value)
    value = sub(SHADOW_HASH, lambda match: match.group(1) + "<REDACTED>", value)
    value = sub(CISCO_SECRET, lambda match: match.group(1) + "<REDACTED>", value)
    value = sub(LABELED_COMMUNITY,
        _replace_credential, value,
    )
    return sub(SENSITIVE_TEXT_FIELD,
        lambda match: match.group(0) if _wtp_128_length_password_capability(match)
        else match.group(1) + '"<REDACTED>"', value,
    )


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document = dict(pairs)
    if len(document) != len(pairs):
        raise ValueError("duplicate key")
    return document


def _sanitize_object(value: Any, secrets: Iterable[object] = (), *, snmp=False) -> Any:
    normalized = _normalize_secrets(secrets)

    def sensitive_key(key: object) -> bool:
        name = str(key).lower().replace("-", "_")
        return (
            name in SENSITIVE_KEYS
            or name.endswith(("_password", "_secret", "_token", "_community", "_private_key"))
            or name.startswith(("password_", "secret_", "token_", "community_", "private_key_"))
        )

    def walk(item: Any) -> Any:
        if isinstance(item, str):
            return walk_text(item)
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            number = dumps(item)
            return "<REDACTED>" if any(secret in number for secret in normalized) else item
        if isinstance(item, list):
            return [walk(child) for child in item]
        if isinstance(item, dict):
            return {
                walk(key): "<REDACTED>" if sensitive_key(key) else walk(child)
                for key, child in item.items()
            }
        return item

    def walk_text(text: str) -> str:
        if text.lstrip()[:1] in ("{", "["):
            try:
                decoded = loads(text, object_pairs_hook=_unique_pairs)
            except (ValueError, RecursionError):
                decoded = None
            if isinstance(decoded, (dict, list)):
                cleaned = walk(decoded)
                if cleaned == decoded:
                    return text
                return dumps(cleaned, separators=(",", ":"), ensure_ascii=False)
        cleaned = _sanitize_text(text, normalized)
        return redact_snmp_credentials(cleaned) if snmp else cleaned

    return walk(value)


_SNMP_CANDIDATE = re.compile(
    r"^" + _SNMP_PREFIX + r"(?:config[ \t]+(?:system[ \t]+snmp[ \t]+(?:community|user)"
    r"|switch-controller[ \t]+snmp-community|wireless-controller[ \t]+snmp|snmp-community)\b"
    r"|set[ \t]+community[ \t]+|configure[ \t]+snmp(?:v3)?[ \t]+(?:add|delete)[ \t]+community\b)", re.I | re.M)


def _contains_snmp(value):
    if isinstance(value, str):
        if _SNMP_CANDIDATE.search(value.replace("\r", "\n")):
            return True
        if value.lstrip()[:1] in ("{", "["):
            try:
                decoded = loads(value, object_pairs_hook=_unique_pairs)
            except (ValueError, RecursionError):
                return False
            if isinstance(decoded, (dict, list)):
                return _contains_snmp(decoded)
        return False
    if isinstance(value, dict):
        return any(_contains_snmp(key) or _contains_snmp(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_contains_snmp(child) for child in value)
    return False


def sanitize_object(value: Any, secrets: Iterable[object] = ()) -> Any:
    if _contains_snmp(value):
        from .sanitize import _snmp_response
        return _snmp_response(value, tuple(secrets))
    return _sanitize_object(value, secrets)


def sanitize_text(value: str, secrets: Iterable[object] = ()) -> str:
    if _contains_snmp(value):
        return sanitize_object(value, secrets)
    return _sanitize_text(value, secrets)
