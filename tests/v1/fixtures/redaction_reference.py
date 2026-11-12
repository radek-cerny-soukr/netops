"""Unoptimized reference for the current redaction contract; frozen 1.0.6 lives separately."""
import json
import re

SECRET_FIELDS = frozenset(("authorization", "password", "passphrase", "secret", "token", "access_token", "refresh_token", "auth_context", "private_key", "passwd", "psksecret", "snmp_community", "credentials", "proxy_authorization", "cookie", "set_cookie", "x_api_key", "api_key", "mcp_session_id", "url_query", "auth_pwd", "priv_pwd"))
KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
KEY_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
PATTERNS = (
    re.compile(r"(?i)(?:password|passwd|secret|token|community)\s*(?:=|:)\s*[^\s,;]+"),
    re.compile(r"(?im)((?:(?:(?<!un)|(?<=\wun))set|encrypted)\s+(?:password|passwd)\s+|(?<=(?<!\w)un)set\s+(?:password|passwd)[^\S\r\n]+)[^\r\n]+"),
    re.compile(r"(?im)((?:set|encrypted)[ \t]+(?:psksecret|secret|passphrase|auth-pwd|priv-pwd)[ \t]+)[^\r\n]+"),
    re.compile(r'(?i)("(?:password|passwd|passphrase|secret|token)"\s*:\s*")(?:[^"\\\r\n]|\\.)*(?=")'),
    re.compile(r"(?im)^([ \t]*passphrase[ \t]*=[ \t]*)[^\r\n]*"),
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

    def replacement(match):
        prefix = match[1] if match.re.groups else ''
        tail = match[0][len(prefix):]
        if prefix.split()[-1:] == ['psksecret'] and re.fullmatch(r'<REDACTED:credential#[1-9][0-9]*>', tail):
            return match[0]
        return prefix + '[REDACTED]'

    def walk(node, location, document=False):
        if isinstance(node, dict):
            result = {}
            for key, child in node.items():
                public_key = walk(str(key), location + ['$key']) if document else key
                if document and (public_key != key or any(pattern.search(json.dumps(str(key)) + ':') for pattern in PATTERNS[:2])):
                    document[0] = True
                child_location = location + [str(public_key)]
                sensitive = (str(key).lower().replace('-', '_') in SECRET_FIELDS and child is not None)
                if public_key != key or sensitive:
                    result[public_key] = '[REDACTED]'
                    paths.append(child_location)
                else:
                    result[key] = walk(child, child_location, document)
            return result
        if isinstance(node, list):
            return [walk(child, location + [str(index)], document)
                    if document or isinstance(child, (dict, list, str)) else child
                    for index, child in enumerate(node)]
        if not isinstance(node, str):
            if document and any(secret in json.dumps(node) for secret in known):
                paths.append(location)
                return '[REDACTED]'
            return node
        if node in known:
            paths.append(location)
            return '[REDACTED]'
        decoded = None
        if node.lstrip().startswith(('{', '[')) and str.rstrip(node).endswith(('}', ']')):
            try:
                decoded = json.loads(node)
            except (ValueError, RecursionError):
                pass
        if isinstance(decoded, (dict, list)):
            state = [False]
            cleaned = walk(decoded, location + ['$json'], state)
            output = json.dumps(cleaned, separators=(',', ':'), ensure_ascii=False) if cleaned != decoded else node
            if state[0] or private_keys(output) != output or any(secret in output for secret in known):
                output = json.dumps('[REDACTED]')
        else:
            output = node
            for secret in sorted(known, key=len, reverse=True):
                output = output.replace(secret, '[REDACTED]')
            output = private_keys(output)
            for pattern in PATTERNS:
                output = pattern.sub(replacement, output)
        if output != node:
            paths.append(location)
        return output

    return walk(value, []), paths

def terminal_safe(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True)
