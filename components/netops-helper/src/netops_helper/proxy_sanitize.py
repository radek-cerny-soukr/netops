"""Defense-in-depth secret redaction for MCP tool-call responses."""

from __future__ import annotations

from collections.abc import Iterable
import json
import re
from typing import Any
from netops.redaction_spans import Marked

# The Helper's span operations: the same results as netops.redaction_spans for
# credential ranges, linear in the number of ranges, and they carry tracked ranges.
from .sanitize import edits, sub, replace, loads, dumps
from .sanitize import _wtp_128_length_password_capability, redact_snmp_credentials, _replace_credential, _SNMP_PREFIX
from .sanitize import _SECRET_WORD_TYPE


FORTI_ENC = re.compile(r"\bENC\s+[^\s\\]+")
PRIVATE_PEM = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.DOTALL,
)
CISCO_SECRET = re.compile(
    r"(?im)^([^\S\n]*(?:enable\s+)?(?:secret|password)(?:\s+\d+)?\s+)\S+"
)
# The value after a secret/password type word, a level or an algorithm (task 302-r2): EOS
# `enable password sha512 $6$...`, IOS `enable secret level 15 5 $1$...`, IOS XE
# `enable algorithm-type scrypt secret ...`. It hides only the value token (the hash or
# password after the type), like CISCO_SECRET: what follows on the line stays (task 302-r3).
# A later rule of the 1.0.8 chain that took text after an anchor inside the value keeps what
# it hid hidden through the floor of the 1.0.8 proxy and the product (_sanitize_text, task
# 302-r6). A numeric type alone is left to CISCO_SECRET, which is kept verbatim (1.0.6
# floor), runs afterwards and still hides its first token. The response chain computes its
# 1.0.8 floor without this rule (typed=False, sanitize._proxy_1_0_8).
CISCO_TYPED_SECRET = re.compile(
    r"(?im)^([^\S\n]*(?:enable[ \t]+(?P<algorithm>algorithm-type[ \t]+\S+[ \t]+)?)?(?:secret|password)"
    r"(?:[ \t]+(?P<level>level)[ \t]+\d+)?(?:[ \t]+(?:(?P<word>" + _SECRET_WORD_TYPE + r")|\d+(?=[ \t]+\S)))?[ \t]+)"
    r"(?(word)|(?(level)|(?(algorithm)|(?!))))\S+"
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


def _replace_typed(match):
    value = match.group(0)[len(match.group(1)):]
    return match.group(0) if value == "<REDACTED>" else match.group(1) + "<REDACTED>"


def _normalize_secrets(secrets: Iterable[object]) -> tuple[str, ...]:
    values = {str(value) for value in secrets if len(str(value).encode("utf-8")) >= 3}
    forms = {
        form for value in values for form in (
            value, dumps(value)[1:-1], dumps(value, ensure_ascii=False)[1:-1],
        )
    }
    return tuple(sorted(forms, key=len, reverse=True))


def _sanitize_text(value: str, secrets: Iterable[object] = (), *, typed=True, typed_changes=None) -> str:
    """Proxy text rules. ``typed=False`` gives the released 1.0.8 rules (without
    CISCO_TYPED_SECRET); ``typed_changes`` (a list) records that this rule changed text.

    The product redacts the proxy's output on its way to the AI client. When the new rule
    changed the text, every character that the released 1.0.8 proxy rules and the product
    hide of this text stays hidden (task 302-r6): both chains run over the text with origin
    ranges, and a character that the current chain leaves visible is masked in the proxy's
    output (sanitize._covering_floor). A text that carries ranges of an outer chain (the
    response chain, SNMP) gets the whole 1.0.8 floor carried through the rules instead.
    """
    from .sanitize import _origin
    changed, plain, output = [], str.__str__(value), None
    if typed and not isinstance(value, Marked) and CISCO_TYPED_SECRET.search(plain):
        # One pass with origin ranges gives the text and, if needed, the floor check.
        output = _proxy_rules(_origin(plain), secrets, True, changed)
        result = str.__str__(output)
    else:
        result = _proxy_rules(value, secrets, typed, changed)
    if not changed:
        # The rules before CISCO_TYPED_SECRET are the 1.0.8 rules and it changed nothing:
        # the text is the 1.0.8 proxy's text.
        return result
    if typed_changes is not None:
        typed_changes.append(True)
    from .sanitize import _PROXY_FLOOR, _covering_floor, _floored, _hidden_ranges, _mask_kept, _tracked_product, _atomize

    def later(text):
        return _tracked_product()(_atomize(text), secrets)[0]

    released = _hidden_ranges(plain, lambda text: later(_proxy_rules(text, secrets, False)))
    if not released:
        return result
    if output is None:
        output = _proxy_rules(_origin(plain), secrets, True)
    covered = _covering_floor(plain, released, output, later)
    if covered is output:
        return result
    if not isinstance(value, Marked):
        return str.__str__(covered)
    return _mask_kept(_proxy_rules(_floored(value, released, _PROXY_FLOOR), secrets, True), _PROXY_FLOOR)


def _proxy_rules(value, secrets, typed: bool, changed=None):
    """The proxy text rules in their order; ``typed=False`` gives the released 1.0.8 rules.
    ``changed`` (a list) records that CISCO_TYPED_SECRET changed the text."""
    for secret in _normalize_secrets(secrets):
        value = replace(value, secret, "<REDACTED>")
    value = sub(PRIVATE_PEM, "<PRIVATE-KEY-REDACTED>", value)
    value = sub(FORTI_ENC, "ENC <REDACTED>", value)
    value = sub(SHADOW_HASH, lambda match: match.group(1) + "<REDACTED>", value)
    if typed:
        typed_value = sub(CISCO_TYPED_SECRET, _replace_typed, value)
        if changed is not None and str.__str__(typed_value) != str.__str__(value):
            changed.append(True)
        value = typed_value
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


def _sanitize_object(value: Any, secrets: Iterable[object] = (), *, snmp=False, typed=True, typed_changes=None) -> Any:
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
        cleaned = _sanitize_text(text, normalized, typed=typed, typed_changes=typed_changes)
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
