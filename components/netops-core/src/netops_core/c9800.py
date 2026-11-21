"""Operational output shared by the Catalyst 9800 read and admin paths."""

import re

MAC = r"(?:[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}|[0-9a-f]{2}(?::[0-9a-f]{2}){5})"
CONTROLLER_IMAGE = re.compile(r"(?mi)^Cisco IOS Software[^\n]*\b(?:C9800|CW9800)[-\w]* Software\b")
DOCUMENTED_RELEASES = ("17.03.05b", "17.9.2")
CLIENT_SUMMARY = "show wireless client summary"
_CLIENT_COUNT = re.compile(r"Number of (?:Local )?Clients:\s*(\d+)")
_CLIENT_HEADER = re.compile(r"MAC Address\s+AP Name\s+(?:WLAN|Type ID)\s+State\s+Protocol\s+Method\s+Role")
_CLIENT_ROW = re.compile(
    rf"({MAC})\s+(\S+)\s+(?:WLAN\s+)?(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", re.I,
)
PAGER = re.compile(r"--More--|\ufffd|\x08|\x1b", re.I)


def colon_mac(value):
    compact = value.replace(".", "").replace(":", "").lower()
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2))


def client_summary(output):
    """Return the declared count, parsed rows and whether the listing proves its coverage."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if lines and re.fullmatch(r"Number of Excluded Clients:\s*\d+", lines[-1]):
        lines.pop()
    count = _CLIENT_COUNT.fullmatch(lines[0]) if lines else None
    if count is None:
        return None, [], False
    total = int(count[1])
    if total == 0 and len(lines) == 1:
        return total, [], not PAGER.search(output)
    if (len(lines) < 3 or not _CLIENT_HEADER.fullmatch(lines[1])
            or not re.fullmatch(r"-+", lines[2])):
        return total, [], False
    records = []
    for line in lines[3:]:
        row = _CLIENT_ROW.fullmatch(line)
        if row:
            mac, ap, wlan, state, protocol, method, role = row.groups()
            records.append(dict(mac=colon_mac(mac), ap_name=ap, wlan_id=int(wlan),
                                state=state, protocol=protocol, method=method, role=role))
    complete = (not PAGER.search(output) and total == len(lines) - 3 == len(records)
                and total == len({row["mac"] for row in records}))
    return total, records, complete
