import json
import re

SECRET_FIELDS = frozenset(("authorization", "password", "passphrase", "secret", "token", "access_token", "refresh_token", "auth_context", "private_key", "snmp_community", "credentials", "proxy_authorization", "cookie", "set_cookie", "x_api_key", "api_key", "mcp_session_id", "url_query"))
KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
KEY_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
PATTERNS = (
    re.compile(r"(?i)(?:password|passwd|secret|token|community)\s*(?:=|:)\s*[^\s,;]+"),
    re.compile(r"(?im)(?:set|encrypted)\s+password\s+[^\r\n]+"),
)

def private_keys(text):
    parts, position = [], 0
    while True:
        begin = KEY_BEGIN.search(text, position)
        end = begin and KEY_END.search(text, begin.end())
        if not end:
            break
        parts += [text[position:begin.start()], "[REDACTED]"]
        position = end.end()
    if not parts:
        return text
    parts.append(text[position:])
    return "".join(parts)

def redact(value, secrets=()):
    paths = []
    known = tuple(item for item in secrets if isinstance(item, str) and item)
    def visit(item, path):
        if isinstance(item, dict):
            cleaned = {}
            for key, part in item.items():
                field_path = path + [str(key)]
                if str(key).lower().replace("-", "_") in SECRET_FIELDS and part is not None:
                    cleaned[key] = "[REDACTED]"
                    paths.append(field_path)
                else:
                    cleaned[key] = visit(part, field_path)
            return cleaned
        if isinstance(item, list):
            return [visit(part, path + [str(index)]) if isinstance(part, (dict, list, str)) else part for index, part in enumerate(item)]
        if isinstance(item, str):
            output = item
            if item.lstrip().startswith(("{", "[")) and str.rstrip(item).endswith(("}", "]")):
                try:
                    decoded = json.loads(item)
                except (ValueError, RecursionError):
                    decoded = None
                if isinstance(decoded, (dict, list)):
                    cleaned = visit(decoded, path + ["$json"])
                    if cleaned != decoded:
                        output = json.dumps(cleaned, separators=(",", ":"), ensure_ascii=False)
            for secret in sorted(known, key=len, reverse=True):
                output = output.replace(secret, "[REDACTED]")
            output = private_keys(output)
            for pattern in PATTERNS:
                output = pattern.sub("[REDACTED]", output)
            if output != item:
                paths.append(path)
            return output
        return item
    payload = visit(value, [])
    return payload, paths

def terminal_safe(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True)
