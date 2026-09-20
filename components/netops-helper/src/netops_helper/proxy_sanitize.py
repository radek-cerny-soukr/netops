"""Defense-in-depth secret redaction for MCP tool-call responses."""

from __future__ import annotations

from collections.abc import Iterable
import re
from typing import Any


FORTI_ENC = re.compile(r"\bENC\s+\S+")
PRIVATE_PEM = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
)
CISCO_SECRET = re.compile(
    r"(?im)^(\s*(?:enable\s+)?(?:secret|password)(?:\s+\d+)?\s+)\S+"
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
    ("(?:[^"\\]|\\.)*"|[^,}\]\n]+)
    """
)
SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_token", "access_token", "private_key",
    "community", "auth_context",
}


def _normalize_secrets(secrets: Iterable[object]) -> tuple[str, ...]:
    values = {str(value) for value in secrets if len(str(value).encode("utf-8")) >= 3}
    return tuple(sorted(values, key=len, reverse=True))


def sanitize_text(value: str, secrets: Iterable[object] = ()) -> str:
    for secret in _normalize_secrets(secrets):
        value = value.replace(secret, "<REDACTED>")
    value = PRIVATE_PEM.sub("<PRIVATE-KEY-REDACTED>", value)
    value = FORTI_ENC.sub("ENC <REDACTED>", value)
    value = SHADOW_HASH.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = CISCO_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = LABELED_COMMUNITY.sub(
        lambda match: match.group(1) + "<REDACTED>", value,
    )
    return SENSITIVE_TEXT_FIELD.sub(
        lambda match: match.group(1) + '"<REDACTED>"', value,
    )


def sanitize_object(value: Any, secrets: Iterable[object] = ()) -> Any:
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
            return sanitize_text(item, normalized)
        if isinstance(item, list):
            return [walk(child) for child in item]
        if isinstance(item, dict):
            return {
                key: "<REDACTED>" if sensitive_key(key) else walk(child)
                for key, child in item.items()
            }
        return item

    return walk(value)
