"""Operational facts from the authorized Linux catalogue."""

from collections import Counter
import json
import re

from .. import linux_tables, normalization, query_catalog
from .model import DeviceFacts, ReadSpec, missing

LINK_STATE = "interfaces.admin_up_down"
LINK_ERRORS = "interfaces.with_errors"
DMI = "overview_dmi_model"
PROC_UPTIME = "overview_proc_uptime"
PROC_STAT = "overview_proc_stat"
LINK_STATISTICS = "overview_link_statistics"
DEFAULT_KERNEL_LINKS = {"bond0", "dummy0", "gre0", "gretap0", "erspan0", "ifb0", "ifb1",
                        "ip6gre0", "ip6tnl0", "sit0", "tunl0"}


def plan(scope):
    catalog = query_catalog.READ_QUERIES[scope.platform]
    steps = [ReadSpec("kernel", "kernel", ("version",))]
    if PROC_STAT in catalog:
        steps.extend((ReadSpec("cpu:1", PROC_STAT, ("cpu",)),
                      ReadSpec("cpu:2", PROC_STAT, ("cpu",), requires=("cpu:1",))))
    steps.append(ReadSpec("memory", "memory", ("memory",)))
    if LINK_STATISTICS in catalog:
        steps.append(ReadSpec("link_statistics", LINK_STATISTICS, (LINK_STATE, LINK_ERRORS)))
    steps.append(ReadSpec("links", "links", (LINK_STATE,)))
    if PROC_UPTIME in catalog and PROC_UPTIME in scope.enabled_queries:
        steps.append(ReadSpec("proc_uptime", PROC_UPTIME, ("uptime_seconds",)))
    else:
        steps.append(ReadSpec("uptime", "uptime", ("uptime_seconds",)))
    if DMI in catalog:
        steps.append(ReadSpec("dmi", DMI, ("model",)))
    return tuple(steps)


def _memory(text):
    headers = [line.split() for line in text.splitlines() if line.split()[:2] == ["total", "used"]]
    rows = [line.split()[1:] for line in text.splitlines() if line.startswith("Mem:")]
    if len(headers) != 1 or len(rows) != 1 or len(headers[0]) != len(rows[0]):
        return None
    cells = rows[0]
    if not all(re.fullmatch(r"[0-9]{1,18}", value) for value in cells):
        return None
    total, used = map(int, cells[:2])
    if 0 < total and used <= total:
        return {"used_pct": round(100 * used / total, 2), "total_bytes": total * 2**20, "used_bytes": used * 2**20}
    return None


def _uptime(text):
    # procps prints days and h:mm, minutes, or just h:mm when uptime is shorter than a day.
    match = re.fullmatch(
        r"\s*\d{2}:\d{2}:\d{2}\s+up\s+(?:(\d{1,8}) days?,\s*)?"
        r"(?:(\d{1,8}):(\d{2}),\s*|(\d{1,8}) min,\s*)?"
        r"\d+ users?,\s+load average: [\d., ]+\s*", text,
    )
    if match and any(part is not None for part in match.groups()):
        days, hours, minutes, short_minutes = (int(part or 0) for part in match.groups())
        if minutes < 60:
            return ((days * 24 + hours) * 60 + minutes + short_minutes) * 60
    return None


def _cpu_sample(text):
    rows = [line.split()[1:] for line in text.splitlines() if line.split()[:1] == ["cpu"]]
    if len(rows) == 1 and len(rows[0]) in (8, 9, 10) and all(re.fullmatch(r"[0-9]{1,20}", cell) for cell in rows[0]):
        return tuple(map(int, rows[0]))
    return None


def _cpu(first, second):
    before, after = _cpu_sample(first), _cpu_sample(second)
    if before is None or after is None or len(before) != len(after):
        return None
    delta = tuple(end - start for start, end in zip(before, after, strict=True))
    total = sum(delta[:8])
    if min(delta) < 0 or total <= 0:
        return None
    # Guest time is already included in user/nice. Idle and I/O wait are non-busy time.
    return {"used_pct": round(100 * (total - delta[3] - delta[4]) / total, 2), "sample_seconds": None}


def _unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate key in link statistics")
    return result


def _reportable_link(name, *, connected=(), kind=None):
    if name in connected:
        return True
    return (name not in DEFAULT_KERNEL_LINKS and name not in {"lo", "docker0"}
            and not name.startswith(("br-", "veth"))
            and not re.fullmatch(r"imq\d+", name)
            and kind not in ("bridge", "veth"))


def _link_json(text):
    try:
        rows = json.loads(text, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError):
        rows = None
    if not isinstance(rows, list) or not rows:
        return {}, {}, set(), True, True
    states, counters = {}, {}
    seen, ambiguous = set(), set()
    attached, kinds = {}, {}
    bad_state = bad_stats = False
    for row in rows:
        try:
            name = linux_tables.name(row["ifname"])
        except (KeyError, AttributeError, TypeError, ValueError):
            bad_state = bad_stats = True
            continue
        if name in seen:
            ambiguous.add(name)
            bad_state = bad_stats = True
            continue
        seen.add(name)
        if isinstance(master := row.get("master"), str):
            attached[name] = master
        if isinstance(linkinfo := row.get("linkinfo"), dict):
            kinds[name] = linkinfo.get("info_kind")
        flags, state = row.get("flags"), row.get("operstate")
        if (isinstance(flags, list) and all(isinstance(flag, str) and re.fullmatch(r"[A-Z0-9_-]+", flag)
                                             for flag in flags)
                and isinstance(state, str) and state in linux_tables.STATES):
            states[name] = ("UP" in flags, state == "DOWN")
        else:
            bad_state = True
        stats = row.get("stats64", row.get("stats"))
        try:
            values = {f"{side}_{label}": stats[side][key] for side in ("rx", "tx")
                      for key, label in (("errors", "errors"), ("dropped", "drops"))}
            if not all(type(count) is int and count >= 0 for count in values.values()):
                raise ValueError("invalid interface counter")
            counters[name] = values
        except (KeyError, TypeError, ValueError):
            bad_stats = True
    for name in ambiguous:
        states.pop(name, None)
        counters.pop(name, None)
        attached.pop(name, None)
    connected = attached.keys() | set(attached.values())
    ignored = {name for name in seen if not _reportable_link(name, connected=connected, kind=kinds.get(name))}
    return states, counters, ignored, bad_state, bad_stats


def _brief(text):
    rows, unknown = linux_tables.parse("interface", text)
    states = {row["name"]: (row["admin_status"] == "up", row["oper_status"] == "down") for row in rows}
    ambiguous = {name for name, count in Counter(row["name"] for row in rows).items() if count > 1}
    for name in ambiguous:
        del states[name]
    return states, bool(unknown or ambiguous or not rows)


def assemble(scope, reads):
    fields = {}
    unavailable = [missing(field, "source_limit") for field in ("temperatures", "fans", "power", "poe")]
    unavailable.extend(missing(field, "not_applicable") for field in ("redundancy", "licenses", "fortiguard", "managed"))
    incomplete = set()

    def text(read_id):
        read = reads.get(read_id)
        return read.text if read and read.status == "ok" else None

    def record(field, value, read_id):
        if value is None:
            unavailable.append(missing(field, "unparsed", read_id=read_id))
        else:
            fields[field] = value

    if (kernel := text("kernel")) is not None:
        fields["version"] = normalization.parse_identity("linux", kernel)["os_version"]
    if (memory := text("memory")) is not None:
        record("memory", _memory(memory), "memory")
    if "dmi" not in reads:
        unavailable.append(missing("model", "source_limit"))
    elif (dmi := text("dmi")) is not None:
        record("model", dmi.strip() if re.fullmatch(r"[ -~]{1,128}", dmi.strip()) else None, "dmi")
    if (proc_uptime := text("proc_uptime")) is not None:
        match = re.fullmatch(r"\s*([0-9]{1,16})\.\d{2} [0-9]{1,16}\.\d{2}\s*", proc_uptime)
        record("uptime_seconds", int(match[1]) if match else None, "proc_uptime")
    elif (uptime := text("uptime")) is not None:
        record("uptime_seconds", _uptime(uptime), "uptime")
    if "cpu:1" not in reads:
        unavailable.append(missing("cpu", "source_limit"))
    elif (first := text("cpu:1")) is not None and (second := text("cpu:2")) is not None:
        record("cpu", _cpu(first, second), "cpu:2")
        if "cpu" in fields:
            # The framework currently exposes no monotonic sample timestamps.
            unavailable.append(missing("cpu.sample_seconds", "source_limit", read_id="cpu:2"))
    for entry in unavailable:
        if entry["reason"] == "unparsed":
            incomplete.add(entry["read_id"])

    interfaces = {"scope": "device", "admin_up_down": None, "with_errors": None}
    fields["interfaces"] = interfaces
    states, counters, ignored, json_bad_state, json_bad_stats = {}, {}, set(), False, False
    if (stats := text("link_statistics")) is not None:
        states, counters, ignored, json_bad_state, json_bad_stats = _link_json(stats)
    brief, brief_bad = _brief(links) if (links := text("links")) is not None else ({}, False)
    if brief_bad:
        unavailable.append(missing(LINK_STATE, "unparsed", read_id="links"))
        incomplete.add("links")
    if states and brief and states.keys() != brief.keys():
        json_bad_state = json_bad_stats = True
    if json_bad_state:
        unavailable.append(missing(LINK_STATE, "unparsed", read_id="link_statistics"))
    if json_bad_stats:
        unavailable.append(missing(LINK_ERRORS, "unparsed", read_id="link_statistics"))
    if json_bad_state or json_bad_stats:
        incomplete.add("link_statistics")

    # Keep valid JSON rows primary and use the brief table for missing link rows.
    if states or brief:
        ignored_brief = {name for name in brief.keys() - states.keys() if not _reportable_link(name)}
        interfaces["admin_up_down"] = [
            {"name": name, "read_ids": ["link_statistics" if name in states else "links"]}
            for name, (admin, down) in sorted((brief | states).items())
            if admin and down and name not in ignored and name not in ignored_brief
        ]
    if counters:
        interfaces["with_errors"] = [
            {"name": name, "counters": values, "counter_kind": "cumulative", "read_ids": ["link_statistics"]}
            for name, values in sorted(counters.items())
            if name not in ignored and (values["rx_errors"] or values["tx_errors"])
        ]
    if "link_statistics" not in reads:
        unavailable.append(missing(LINK_ERRORS, "source_limit"))
    return DeviceFacts(fields, unavailable, incomplete_reads=tuple(sorted(incomplete)))
