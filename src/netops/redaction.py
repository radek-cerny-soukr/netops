import re
from netops.redaction_spans import edits, sub, replace, loads, dumps

SECRET_FIELDS = frozenset(("authorization", "password", "passphrase", "secret", "token", "access_token", "refresh_token", "auth_context", "private_key", "passwd", "psksecret", "snmp_community", "credentials", "proxy_authorization", "cookie", "set_cookie", "x_api_key", "api_key", "mcp_session_id", "url_query", "auth_pwd", "priv_pwd"))
KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
KEY_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
PATTERNS = (
    re.compile(r"(?i)(?:password|passwd|secret|token|community)\s*(?:=|:)\s*[^\s,;]+"),
    # a standalone `unset password` carries no value: the rule does not start inside the word `unset` and take the next
    # line (`next`/`end`); inside other words (`sunset`) the 1.0.6 rule stays. A value on the line of `unset password` is still replaced, as in 1.0.6.
    re.compile(r"(?im)((?:(?:(?<!un)|(?<=\wun))set|encrypted)\s+(?:password|passwd)\s+|(?<=(?<!\w)un)set\s+(?:password|passwd)[^\S\r\n]+)[^\r\n]+"),
    re.compile(r"(?im)((?:set|encrypted)[ \t]+(?:psksecret|secret|passphrase|auth-pwd|priv-pwd)[ \t]+)[^\r\n]+"),
    re.compile(r'(?i)("(?:password|passwd|passphrase|secret|token)"\s*:\s*")(?:[^"\\\r\n]|\\.)*(?=")'),
    re.compile(r"(?im)^([ \t]*passphrase[ \t]*=[ \t]*)[^\r\n]*"),
)

CANDIDATE = re.compile(
    r"\\|-----BEGIN |passwd|community|"
    + "|".join(re.escape(field).replace("_", "[-_]") for field in sorted(SECRET_FIELDS)),
    re.I,
)

MIN_CANDIDATE_LENGTH = min(map(len, (*SECRET_FIELDS, "-----BEGIN ", "passwd", "community")))

def has_candidate(text):
    if len(text) < MIN_CANDIDATE_LENGTH and "\\" not in text:
        return False
    for start in range(0, len(text), 16384):
        if CANDIDATE.search(text, start, start + 16448):
            return True
    return False

def private_keys(text):
    changes, position = [], 0
    while True:
        begin = KEY_BEGIN.search(text, position)
        end = begin and KEY_END.search(text, begin.end())
        if not end:
            break
        changes.append((begin.start(), end.end(), "[REDACTED]"))
        position = end.end()
    return edits(text, changes)

def _replacement(match):
    prefix = match.group(1) if match.re.groups else ''
    # Only the complete, value-free canonical PSK label survives. Trailing text,
    # quotes, ENC, malformed labels and literal backslash-newlines still get hidden.
    if (prefix.split()[-1:] == ['psksecret'] and
            re.fullmatch(r'<REDACTED:credential#[1-9][0-9]*>', match.group(0)[len(prefix):])):
        return match.group(0)
    return prefix + '[REDACTED]'


def redact(value, secrets=()):
    paths = []
    known = tuple(item for item in secrets if isinstance(item, str) and item)
    def visit(item, path, encoded=False):
        if type(item) is str and not has_candidate(item) and not any(secret in item for secret in known):
            return item
        if isinstance(item, dict):
            cleaned = {}
            for key, part in item.items():
                clean_key = visit(key if isinstance(key, str) else str(key), path + ['$key']) if encoded else key
                if encoded and (clean_key != key or any(pattern.search(dumps(str(key)) + ':') for pattern in PATTERNS[:2])):
                    encoded[0] = True
                field_path = path + [str(clean_key)]
                if clean_key != key:
                    cleaned[clean_key] = '[REDACTED]'
                    paths.append(field_path)
                    continue
                if str(key).lower().replace("-", "_") in SECRET_FIELDS and part is not None:
                    cleaned[key] = "[REDACTED]"
                    paths.append(field_path)
                else:
                    cleaned[key] = visit(part, field_path, encoded)
            return cleaned
        if isinstance(item, list):
            return [visit(part, path + [str(index)], encoded) if encoded or isinstance(part, (dict, list, str)) else part for index, part in enumerate(item)]
        if encoded and not isinstance(item, (dict, list, str)) and any(secret in dumps(item) for secret in known):
            paths.append(path)
            return '[REDACTED]'
        if isinstance(item, str):
            if item in known:
                paths.append(path)
                return '[REDACTED]'
            output = item
            if item.lstrip().startswith(("{", "[")) and str.rstrip(item).endswith(("}", "]")):
                try:
                    decoded = loads(item)
                except (ValueError, RecursionError):
                    decoded = None
                if isinstance(decoded, (dict, list)):
                    document = [False]
                    cleaned = visit(decoded, path + ["$json"], document)
                    output = (dumps(cleaned, separators=(",", ":"), ensure_ascii=False)
                              if cleaned != decoded else item)
                    # Legacy text rules can consume sibling values after a key or
                    # cross JSON punctuation. Withhold that complete document safely.
                    if document[0] or private_keys(output) != output or any(secret in output for secret in known):
                        output = dumps('[REDACTED]')
                    if output != item:
                        paths.append(path)
                    return output
            for secret in sorted(known, key=len, reverse=True):
                output = replace(output, secret, "[REDACTED]")
            output = private_keys(output)
            for pattern in PATTERNS:
                output = sub(pattern, _replacement, output)
            if output != item:
                paths.append(path)
            return output
        return item
    payload = visit(value, [])
    return payload, paths

def terminal_safe(value):
    return dumps(value, ensure_ascii=True, sort_keys=True)
