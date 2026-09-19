from __future__ import annotations

import re

MARKERS = "#$"
PATTERN = r"^([^%s\n]+ [%s] )" % (MARKERS, MARKERS)
PLATFORM_FORTIOS = "fortios"
PLATFORM_EXOS = "exos"
PREFIXES = {
    PLATFORM_FORTIOS: re.compile(PATTERN),
    PLATFORM_EXOS: re.compile(PATTERN),
}
ALIASES = {
    "fortinet": PLATFORM_FORTIOS,
    "extreme_exos": PLATFORM_EXOS,
}
PLATFORMS = tuple(PREFIXES)


def prefix(platform):
    if not isinstance(platform, str):
        return None
    return PREFIXES.get(ALIASES.get(platform, platform))


def cleaned(text, platform) -> str:
    pattern = prefix(platform)
    if pattern is None or not text:
        return text
    found = pattern.match(text.split("\n", 1)[0])
    if found is None:
        return text
    marker = found.group(1)
    lines = text.splitlines()
    lines[0] = lines[0][len(marker):]
    ending = "\n" if text.endswith("\n") else ""
    bare = marker.rstrip()
    while lines and lines[-1].rstrip() == bare:
        lines.pop()
        ending = "\n"
    return "\n".join(lines) + (ending if lines else "")
