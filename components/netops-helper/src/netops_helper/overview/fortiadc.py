"""Operational facts from the FortiADC catalogue and its verified terminal."""

from collections import Counter
from datetime import date
import re

from netops_core import tested
from netops_core.platforms import VersionRecordError, version_record

from .. import fortiadc_diagnostics, triage_slb
from .model import DeviceFacts, ReadSpec, expiry_state, missing

LINK_STATE = "interfaces.admin_up_down"
LINK_ERRORS = "interfaces.with_errors"
PORT = r"[A-Za-z0-9_.:-]+"
# Fortinet's FortiADC VM model list, including the public cloud variants:
# https://docs.fortinet.com/document/fortianalyzer/7.6.6/release-notes/286090/fortiadc-models
VM_MODELS = {
    "FortiADC-KVM", "FortiADC-VM",
    "FortiADC-ALI", "FortiADC-ALI_ONDEMAND",
    "FortiADC-AZURE", "FortiADC-AZURE_ONDEMAND",
    "FortiADC-GCP", "FortiADC-GCP_ONDEMAND",
    "FortiADC-IBM", "FortiADC-OCI",
    "FortiADC-XENAWS", "FortiADC-XENAWS_ONDEMAND",
}


def plan(scope):
    enabled = scope.enabled_queries
    interface = "interface_summary" if "interface_summary" in enabled else "interface_list"
    steps = [
        ReadSpec("system_status", "system_status", ("version", "model")),
        ReadSpec("system_performance", "system_performance", ("cpu", "memory", "uptime_seconds")),
        ReadSpec(interface, interface, (LINK_STATE,), cost=2 if interface == "interface_summary" else 1),
    ]
    if "interface_state_all" in enabled or interface == "interface_list":
        steps.append(ReadSpec("interface_state_all", "interface_state_all", (LINK_STATE,)))
    steps.append(ReadSpec("ha_status", "ha_status", ("redundancy",)))
    enrolled = scope.read_inventory.get("interfaces", ())
    if "interface_counters" in enabled or "interface_state" not in enabled or not enrolled:
        steps.append(ReadSpec("interface_counters", "interface_counters", (LINK_ERRORS,)))
    else:
        for index, name in enumerate(sorted(set(enrolled)), 1):
            steps.append(ReadSpec(f"interface_state:{index}", "interface_state", (LINK_ERRORS,), {"interface": name}))
    steps.extend((
        ReadSpec("vm_license", "vm_license", ("licenses",)),
        ReadSpec("autoupdate_contract", "autoupdate_contract", ("licenses", "fortiguard")),
    ))
    return tuple(steps)


def _without_echo(text):
    lines = text.splitlines()
    return "\n".join(line for line in lines if not re.match(r"^\s*(?:get |diagnose )", line))


def _performance(text):
    data, seen = {}, Counter()
    relevant = {"CPU usage", "Memory usage", "Uptime"}
    for line in _without_echo(text).splitlines():
        if line.split(":", 1)[0].strip() not in relevant:
            continue
        try:
            parsed = triage_slb.parse_key_values(line)
        except triage_slb.TriageParseError:
            continue
        data.update(parsed)
        seen.update(parsed.keys())
    data = {key: value for key, value in data.items() if seen[key] == 1}
    cpu = re.fullmatch(r"(\d{1,3})% used,\s*(\d{1,3})% idle", data.get("CPU usage", ""))
    memory = re.fullmatch(r"(\d{1,3})% used", data.get("Memory usage", ""))
    uptime = re.fullmatch(r"(?:(\d{1,8}) days?\s+)?(?:(\d{1,8}) hours?\s+)?(\d{1,8}) minutes?",
                          data.get("Uptime", ""))
    seconds = None
    if uptime:
        days, hours, minutes = (int(value or 0) for value in uptime.groups())
        seconds = ((days * 24 + hours) * 60 + minutes) * 60
    return {
        "cpu": {"used_pct": int(cpu[1]), "sample_seconds": None} if cpu and int(cpu[1]) + int(cpu[2]) == 100 else None,
        "memory": {"used_pct": int(memory[1]), "total_bytes": None, "used_bytes": None}
        if memory and int(memory[1]) <= 100 else None,
        "uptime_seconds": seconds,
    }


def _config_names(text):
    return Counter(re.findall(rf"(?m)^\s*==\s+\[\s+({PORT})\s+\]\s*$", text))


def _kernel_ports(text):
    pattern = rf"(?m)^if=({PORT}) family=\S+ type=\d+ index=\d+ mtu=\d+ link=\d+ master=\d+\s*\n([\s\S]*?)(?=^if=|\Z)"
    ports = {}
    rows = re.findall(pattern, text)
    names = Counter(name for name, _ in rows)
    invalid = not rows or len(rows) != len(re.findall(r"(?m)^if=", text))
    for name, body in rows:
        flags = re.findall(r"(?m)^flags=([a-z0-9_ -]*)(?:[ \t]+[a-z_]+=.*)?$", body)
        if names[name] != 1 or len(flags) != 1:
            invalid = True
        else:
            ports[name] = ("up" in flags[0].split(), "run" in flags[0].split())
    return ports, invalid


def _link_state(config_id, source, kernel):
    if source.status != "ok":
        return None, False, False, False
    names = _config_names(source.text)
    rows = fortiadc_diagnostics.interface_summary(source.text, source.text if config_id == "interface_summary" else "")
    kernel_up, kernel_bad = _kernel_ports(kernel.text) if kernel and kernel.status == "ok" else ({}, False)
    output = []
    config_bad = not names
    any_known = gap = False
    for row in rows:
        name, admin, link = row["name"], row["admin_status"], row["link_up"]
        if not names[name]:
            continue
        if names[name] != 1 or admin is None:
            config_bad = True
            continue
        evidence = [config_id]
        if admin == "up" and link is None and name in kernel_up:
            kernel_admin, link = kernel_up[name]
            if not kernel_admin:
                kernel_bad = True
                continue
            evidence.append(kernel.spec.id)
        if admin == "down" or link is not None:
            any_known = True
            if admin == "up" and not link:
                output.append({"name": name, "read_ids": evidence})
        else:
            gap = True
    return output if any_known else None, config_bad, kernel_bad, gap


def _counters(text):
    # FortiADC netlink device uses the Linux /proc/net/dev column order.
    head = r"\s*Inter-\|\s*Receive\s*\|\s*Transmit\s*"
    labels = (r"\s*face\s*\|\s*bytes\s+packe\s*ts\s+errs\s+drop\s+fifo\s+frame\s+compressed\s+multicast\s*"
              r"\|\s*bytes\s+packe\s*ts\s+errs\s+drop\s+fifo\s+colls\s+carrier\s+compressed\s*")
    lines = [line for line in _without_echo(text).splitlines() if line.strip()]
    if len(lines) < 3 or not re.fullmatch(head, lines[0]) or not re.fullmatch(labels, lines[1]):
        return {}, True
    records, seen, invalid = {}, set(), False
    for line in lines[2:]:
        row = re.fullmatch(rf"\s*({PORT}):\s*((?:[0-9]{{1,20}}\s+){{15}}[0-9]{{1,20}})\s*", line)
        if not row:
            invalid = True
            continue
        name = row[1]
        if name in seen:
            records.pop(name, None)
            invalid = True
            continue
        seen.add(name)
        values = [int(value) for value in row[2].split()]
        records[name] = dict(zip(("rx_errors", "rx_drops", "tx_errors", "tx_drops"),
                                 (values[2], values[3], values[10], values[11]), strict=True))
    return records, invalid


def _ha(text, read_id):
    parts = re.split(r"(?mi)^Peer Count:", text, maxsplit=1)
    local, remainder = parts if len(parts) == 2 else (text, "")
    counts = re.findall(r"(?mi)^Peer Count:\s*(\d{1,3})\s*$", text)
    modes = re.findall(r"(?mi)^Mode:\s*(\S+)\s*$", local)
    roles = re.findall(r"(?mi)^State:\s*(\S+)\s*$", local)
    if len(modes) != 1 or len(roles) != 1 or len(counts) != 1:
        return None, True
    count = int(counts[0])
    peer_roles = re.findall(r"(?mi)^State:\s*(\S+)\s*$", remainder)
    mode, role = modes[0].lower(), roles[0].lower()
    result = {"kind": "ha", "role": role, "state": "unknown", "read_ids": [read_id]}
    peer_roles = [peer.lower() for peer in peer_roles]
    if len(peer_roles) != count or any(peer not in {"primary", "secondary", "secondary(working)"} for peer in peer_roles):
        return result, True
    if mode == role == "standalone" and count == 0:
        result["state"] = "standalone"
        return result, False
    if mode not in {"active-passive", "active-active"} or role not in {"primary", "secondary"}:
        return result, True
    sync = [value.strip().casefold() for value in re.findall(r"(?mi)^Config-Sync:[ \t]*([^\r\n]+)$", local)]
    monitor = local.split("Monitor status", 1)
    degraded = len(monitor) == 2 and bool(re.search(r"(?mi)^(?:Down:\s*\S[^\r\n]*|System Harddisk:\s*fail)\s*$", monitor[1]))
    if count == 0 or sync == ["not sync"] or degraded:
        result["state"] = "degraded"
    elif sync in (["in sync"], ["sync"]):
        result["state"] = "ok"
    else:
        return result, True
    return result, False


def _vm_license(text, read_id):
    try:
        data = triage_slb.parse_key_values(_without_echo(text))
    except triage_slb.TriageParseError:
        return None
    if (data.get("Registered") == "1 (True)"
            and data.get("File") == "License file and resources are valid."
            and re.fullmatch(r"1 \(Valid: [^\n]+\)", data.get("Status", ""))):
        return {"name": "vm_license", "state": "valid", "expires_on": None, "read_ids": [read_id]}
    return None


_CONTRACT_ITEM = re.compile(r"([A-Z]{4})-[0-9]+-([0-9]{2})-([0-9]{4})([0-9]{2})([0-9]{2})(?::[0-9]+){4}")
_CONTRACT_ECHO = "execute autoupdate contract"
_VM_LICENSE_CONTRACT = "VMLS"


def _contracts(text, read_id):
    """`execute autoupdate contract` as (licenses, fortiguard) entries, or None for any unknown shape.

    Measured on FortiADC-KVM 7.6.7 build0676: one `|`-separated record whose `Contract` lists
    `CODE-1-LEVEL-YYYYMMDD:n:n:n:n` items joined by `*`, then the support level and type names.
    The VM license contract becomes a licence entry; every other service is a FortiGuard entry.
    """
    record, names = None, {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line == _CONTRACT_ECHO:
            continue
        if line.startswith("SerialNumber=") and record is None:
            record = line
        elif line.startswith("SupportTypeDesc=") and not names:
            for item in line.removeprefix("SupportTypeDesc=").split("*"):
                code, separator, description = item.partition(":")
                if not separator or not re.fullmatch(r"[A-Z]{4}", code) or code in names:
                    return None
                names[code] = description.strip()
        elif not line.startswith("SupportLevelDesc="):
            return None
    if record is None:
        return None
    parts = record.split("|")
    if parts[-1] == "":
        parts.pop()
    values = {}
    for part in parts:
        key, separator, value = part.partition("=")
        if not separator or key in values:
            return None
        values[key] = value
    if "Contract" not in values:
        return None
    licenses, fortiguard, seen = [], [], set()
    for item in filter(None, values["Contract"].split("*")):
        match = _CONTRACT_ITEM.fullmatch(item)
        if match is None or match[1] in seen:
            return None
        seen.add(match[1])
        try:
            day = date(int(match[3]), int(match[4]), int(match[5])).isoformat()
        except ValueError:
            return None
        name = " ".join(filter(None, (match[1], names.get(match[1]))))
        entry = {"name": name, "state": expiry_state(day), "expires_on": day, "read_ids": [read_id]}
        (licenses if match[1] == _VM_LICENSE_CONTRACT else fortiguard).append(entry)
    return licenses, fortiguard


def assemble(scope, reads):
    fields, unavailable, incomplete = {}, [], set()

    def unparsed(field, read_id):
        unavailable.append(missing(field, "unparsed", read_id=read_id))
        incomplete.add(read_id)

    def record(field, value, read_id):
        if value is None:
            unparsed(field, read_id)
        else:
            fields[field] = value

    status = reads["system_status"]
    if status.status == "ok":
        try:
            model, release, build = version_record(status.text)
            version = f"{release} build {build}"
            fields.update(model=model, version=version)
            fields["firmware_support"] = tested.support("FortiADC", version, (("FortiADC-KVM", "7.6.7 build 0676"),),
                                                        model=model, function="network_overview")
        except VersionRecordError:
            unparsed("model", status.spec.id)
            unparsed("version", status.spec.id)
    is_vm = fields.get("model") in VM_MODELS
    unavailable.extend(missing(field, "not_applicable" if is_vm else "source_limit")
                       for field in ("temperatures", "fans", "power", "poe"))
    unavailable.append(missing("managed", "not_applicable"))
    performance = reads["system_performance"]
    if performance.status == "ok":
        for field, value in _performance(performance.text).items():
            record(field, value, performance.spec.id)

    config_id = "interface_summary" if "interface_summary" in reads else "interface_list"
    config, kernel = reads[config_id], reads.get("interface_state_all")
    operational, config_bad, kernel_bad, gap = _link_state(config_id, config, kernel)
    if config_bad:
        unparsed(LINK_STATE, config_id)
    if kernel_bad:
        unparsed(LINK_STATE, kernel.spec.id)
    if gap and (kernel is None or not kernel.reason):
        unavailable.append(missing(LINK_STATE, "source_limit", read_id=config_id))
    if kernel and kernel.status == "ok" and config.status != "ok" and _kernel_ports(kernel.text)[1]:
        unparsed(LINK_STATE, kernel.spec.id)

    errors = None
    global_counters = reads.get("interface_counters")
    interface_scope = "device" if global_counters is not None else "enrolled_interfaces"
    if global_counters is not None and global_counters.status == "ok":
        counters, bad = _counters(global_counters.text)
        if bad or (_config_names(config.text or "").keys() - counters.keys()):
            unparsed(LINK_ERRORS, global_counters.spec.id)
        if counters:
            errors = [{"name": name, "counters": counters[name], "counter_kind": "cumulative",
                       "read_ids": [global_counters.spec.id]} for name in sorted(counters) if any(counters[name].values())]
    elif global_counters is None:
        unavailable.append(missing(LINK_ERRORS, "source_limit"))
        for read in reads.values():
            if read.spec.query == "interface_state" and read.status == "ok":
                # The measured FortiADC global netlink listing contains flags but no detailed counters.
                unavailable.append(missing(LINK_ERRORS, "source_limit", read_id=read.spec.id))
    fields["interfaces"] = {"scope": interface_scope, "admin_up_down": operational, "with_errors": errors}

    ha = reads["ha_status"]
    if ha.status == "ok":
        value, ambiguous = _ha(ha.text, ha.spec.id)
        if ambiguous:
            unparsed("redundancy", ha.spec.id)
        if value is not None:
            fields["redundancy"] = [value]
    license_read = reads["vm_license"]
    if license_read.status == "ok":
        license_entry = _vm_license(license_read.text, license_read.spec.id)
        record("licenses", [license_entry] if license_entry else None, license_read.spec.id)
    contracts = reads["autoupdate_contract"]
    if contracts.status == "ok":
        parsed = _contracts(contracts.text or "", contracts.spec.id)
        if parsed is None:
            unparsed("licenses", contracts.spec.id)
            unparsed("fortiguard", contracts.spec.id)
        else:
            if parsed[0]:
                fields["licenses"] = [*fields.get("licenses", []), *parsed[0]]
            fields["fortiguard"] = parsed[1]
    return DeviceFacts(fields, unavailable, incomplete_reads=tuple(sorted(incomplete)))
