"""Cisco NX-OS execution adapter (measured on Nexus 9000v N9K-C9300v, NX-OS 9.3(12), ref/mereni-c6).

NX-OS 9.3(12) has no commit timer and no EEM timer event; the only session-independent timed return is a one-time
job of `feature scheduler` that rolls the running configuration back to a checkpoint ("variant 3" of the
measurement). The safeguard is installed before the change, in one interactive session, in this order:

1. `checkpoint L` (a placeholder: the scheduler parser accepts the job only when the checkpoint exists);
2. `scheduler job name L` with `rollback running-config checkpoint L atomic`, `scheduler schedule name L` with
   `job name L` and `time start +M`;
3. `no checkpoint L` and `checkpoint L` again: the checkpoint now holds the job and the schedule, so the rollback
   patch never has to delete the running job (a job created after its checkpoint blocks the scheduler until
   `no feature scheduler`, measured as variant 1);
4. `copy running-config bootflash:L-pred.cfg`, the file of the immediate return (`configure replace` of it).

Ownership (review 318, finding 2): the name L must be free of every object right before the installation, and an
object is the own one only when the line that creates it was answered without an error in the own session. Admin
notes that line by line in record["safeguard"]["own"] and the journal saves each note at once (INSTALL_JOURNAL);
every removal touches only own objects, so a foreign object of the same name is never deleted.

Interrupted or unverified installation (finding 1): as long as the change was not sent, the safeguard is discarded
at once (discard_installation, also by recover): a pending own schedule is removed first, then the own job, so a job
that its checkpoint does not hold yet (the phase between `time start` and the second `checkpoint L`) does not run when
the removal succeeds before the minute of the job; after an interruption of the Admin process that holds only when
recover runs in time. When the job of such a phase has already run and stays "schedule in progress", the removal
fails or an object is not proven own, the operation ends unknown with the manual procedure (manual_cleanup); Admin
never sends `no feature scheduler`.

Protection during the whole change (finding 3): Admin never reads the device clock. The job runs at the next whole
minute plus M-1 minutes after the device took `time start +M`, so at least M-1 minutes after the installation
started; Admin counts that on its monotonic clock from the moment before the installation (TIMER_WATCH in
execute.py), 2 % shorter for the drift of the device clock, and never longer than the lead the device itself shows
(the schedule time less the creation time of the checkpoint, both on the device clock). Before the change is written
the own schedule must still be pending with enough time left for the write, the readback and the confirmation
margin; every line is sent only while LINE_MARGIN_SECONDS are left. A failed write or readback is returned at once by
`configure replace bootflash:L-pred.cfg` (measured Success, also for the access VLAN) while REVERT_NOW_SECONDS of
the timer are left; otherwise, and for the enrollment self-test and recover, the job is awaited by reading the
scheduler, and when the object is still not in its state before after the job ran (a late line, or a change of
someone else after the return), the same replace is tried before giving up. `configure replace ... commit-timeout`
is never used, because its automatic return leaves a changed access VLAN in place (measured).

Recover (finding 4) decides by the state of the scheduler (`show scheduler schedule name L`, `show scheduler
logfile`, `show rollback log`), never by the device clock, limited on the monotonic clock of Admin.

The schedule has a granularity of one minute; Admin takes M = ceil(safeguard_seconds / 60) + 1. The rollback returns
the WHOLE running configuration to the checkpoint, so a change of someone else made in the window is returned too.
Confirmation removes the schedule, then the job, then the checkpoint and the file; `copy running-config
startup-config` runs only after it. The same removal (after the run: job first, repeated while the switch answers
"schedule in progress") cleans up after the job ran.

`feature scheduler` is a precondition of the switch, enabled once by its administrator: Admin never enables or
disables it (`no feature scheduler` creates a system checkpoint and evicts the oldest of the five).
"""
from __future__ import annotations

import datetime
import hashlib
import re
import time

from netops_admin import nxos
from netops_admin.errors import Rejected
from netops_admin.exec_fortios import PromptSpec

FIRING_OBSERVED = True
# the safeguard is watched on the monotonic clock of Admin and by reading the scheduler, never by the device clock
# (execute.py: TIMER_WATCH); record["safeguard"]["fire_at"] says so, the device time of the job is in device_time
TIMER_WATCH = True
FIRE_AT_TEXT = "device scheduler job"
# install_safeguard notes the own objects line by line and execute.py saves each note at once
INSTALL_JOURNAL = True
# configure replace leaves the job, the schedule and the checkpoint; execute.py removes them after the proven return
REVERT_NOW_KEEPS_SAFEGUARD = True
# after the job ran, an object that is not in its state before is returned by the same configure replace
REVERT_AFTER_EXPIRY = True
# configure replace took 13-15 s measured (19 s in the E2E of task 318), with login, the snapshot and the readback
# of the result about 30 s; with less than this of the own timer left the job is awaited instead
REVERT_NOW_SECONDS = 60
# the device clock drift was not measured on NX-OS; the allowance of the IOS adapter (1.7 % measured on IOSv) is used
DRIFT_FRACTION = 0.02
# a write session: login 2.5 s + at most 5 lines (measured well under 1 s each)
WRITE_BUDGET_SECONDS = 20
# the snapshot (ssh exec show running-config), the account check, three reads of the check account and the final
# snapshot, each its own ssh login of about 2-2.5 s
READBACK_BUDGET_SECONDS = 40
# a configuration line is sent only while this much of the own timer is left
LINE_MARGIN_SECONDS = 15
QUERY_RUNNING = "show running-config"
QUERY_VERSION = "show version"
QUERY_FEATURE = "show feature"
QUERY_DIFF = "show running-config diff"
QUERY_SESSIONS = "show configuration session summary"
QUERY_ROLLBACK_VERIFY = "show rollback log verify"
QUERY_ROLLBACK_EXEC = "show rollback log exec"
QUERY_CHECKPOINTS = "show checkpoint summary user"
QUERY_SCHEDULER_LOG = "show scheduler logfile"
QUERY_FILES = "dir bootflash:"
QUERY_TRUNKS = "show interface trunk"
QUERY_LLDP = "show lldp neighbors"
QUERY_USERS = "show users"
QUERY_DESCRIPTIONS = "show interface description"
# after the job ran, NX-OS refuses to delete the schedule for a while ("schedule in progress", measured ~1.5 min
# after the run, deleted ~3 min after it)
CLEANUP_PAUSE_SECONDS = 20
CLEANUP_LIMIT_SECONDS = 300
IN_PROGRESS = "in progress"
PAUSE = time.sleep
MONTHS = nxos.MONTHS
RUN_ONCE = re.compile(r"^Schedule Type\s*:\s*Run once on [A-Z][a-z]{2} ([A-Z][a-z]{2}) +([0-9]{1,2}) "
                      r"([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{4})\s*$", re.MULTILINE)
SCHEDULE_NAME = re.compile(r"^Schedule Name\s*:\s*(\S+)\s*$", re.MULTILINE)
LAST_EXECUTION = re.compile(r"^Last Execution Time\s*:\s*(.+?)\s*$", re.MULTILINE)
EXECUTION_COUNT = re.compile(r"^Execution count\s*:\s*([0-9]+)\s*$", re.MULTILINE)
CHECKPOINT_ROW = re.compile(r"^[0-9]+\) (\S+):\s*$", re.MULTILINE)
FILE_ROW = re.compile(r"^\s*[0-9]+\s+[A-Z][a-z]{2}\s+[0-9]{1,2}\s+[0-9:]{8}\s+[0-9]{4}\s+(\S+)\s*$", re.MULTILINE)
NO_SESSIONS = "There are no active configuration sessions"


def _read(access, command: str) -> str:
    """The answer of a write-account query whose refusal text the adapter judges itself ("Error: entry not found",
    "ERROR: Log Not Available", "VLAN N not found"): NX-OS may end such an exec command with a nonzero status."""
    query_status = getattr(access, "query_status", None)
    if query_status is None:
        return access.query(command)
    _status, text = query_status(command)
    return text


def prompt_spec(hostname: str) -> PromptSpec:
    # measured prompts: "d-nxos# ", "d-nxos(config)# ", "d-nxos(config-if)# ", "d-nxos(config-job)# ",
    # "d-nxos(config-schedule)# " (a space after "#"); in the interactive session NX-OS 9.3(12) writes a carriage
    # return before every prompt ("...\r\n\rd-nxos# ", read in task 318), so the anchor is "\r" and the host name
    return PromptSpec(anchor=("\r%s" % hostname).encode("ascii"), ends=(b"# ",), continuation=None,
                      error=nxos.cli_error)


def safeguard_label(change_id: str) -> str:
    return nxos.safeguard_label(change_id)


def pred_file(label: str) -> str:
    return "bootflash:%s-pred.cfg" % label


def hostname(access, snapshot_text: str) -> str:
    return nxos.load(snapshot_text, None).hostname


ACCOUNT_LINES = ("username ", "aaa ", "no aaa ")


def accounts_check(access, device, snapshot_text) -> str:
    snapshot = nxos.load(snapshot_text, None)
    present = sorted({line.split()[1] for line in snapshot.lines
                      if line.startswith("username ") and len(line.split()) >= 2})
    if present != sorted(device.accounts):
        raise Rejected(["the switch accounts differ from the expected list (%d present, %d expected)"
                        % (len(present), len(device.accounts))])
    lines = [line for line in snapshot.lines if line.startswith(ACCOUNT_LINES)]
    for block in snapshot.blocks:
        if block.header.startswith("role name "):
            lines.extend([block.header] + block.children)
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def sessions(text: str) -> list:
    """Names of the open configuration sessions in show configuration session summary."""
    if NO_SESSIONS in text:
        return []
    if "Session Manager Database" not in text:
        raise Rejected(["the configuration session list is not readable"])
    rows, started = [], False
    for line in text.replace("\r", "").split("\n"):
        if set(line.strip()) == {"-"}:
            started = True
            continue
        if not started or not line.strip() or line.startswith("Number of active") or line.startswith("Name "):
            continue
        rows.append(line.split()[0])
    return rows


def rollback_running(text: str) -> bool:
    """A rollback or configure replace that started and has not ended (show rollback log verify)."""
    if "Log Not Available" in text:
        return False
    return "Start Time UTC" in text and "End Time UTC" not in text


def prechecks(access, device, snapshot_text, spec) -> list:
    reasons = []
    running = nxos.nxos_version(access.query(QUERY_VERSION))
    expected = device.firmware or nxos.firmware_of(snapshot_text)
    if running != expected:
        reasons.append("the switch runs NX-OS %s, not the configured %s" % (running, expected))
    if nxos.feature_state(access.query(QUERY_FEATURE), "scheduler") != "enabled":
        raise Rejected(["feature scheduler is not enabled on the switch; the timed return of Admin needs it. Its "
                        "administrator enables it once (configure terminal, feature scheduler, end, copy "
                        "running-config startup-config) and leaves it enabled: Admin never enables or disables it, "
                        "because every 'no feature scheduler' creates a system checkpoint and evicts the oldest"],
                       reason_codes=["scheduler_feature_disabled"])
    if access.query(QUERY_DIFF).strip():
        reasons.append("the switch has unsaved configuration changes (show running-config diff is not empty); the "
                       "timed return would roll them back too")
    open_sessions = sessions(access.query(QUERY_SESSIONS))
    if open_sessions:
        raise Rejected(["%d configuration sessions are open on the switch" % len(open_sessions)],
                       reason_codes=["foreign_config_session"])
    if rollback_running(_read(access, QUERY_ROLLBACK_VERIFY)):
        raise Rejected(["a rollback or configure replace is running on the switch"],
                       reason_codes=["rollback_in_progress"])
    return reasons


def plan_prechecks(access, device, plan, snapshot_text="") -> list:
    key, table = plan["key"], plan["table"]
    if table not in ("interface", "vlan-membership"):
        return []
    status = nxos.status_row(access.query("show interface %s status" % key), key)
    if status is None:
        raise Rejected(["the switch does not report interface %s" % key], reason_codes=["port_usage_unreadable"])
    plan["prechecks"].append("interface %s now: status %s, VLAN %s" % (key, status["status"], status["vlan"]))
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    if table == "vlan-membership":
        wanted = (after or {}).get("access-vlan", nxos.DEFAULT_VLAN)
        if not nxos.vlan_exists(_read(access, "show vlan id %s" % wanted), wanted):
            raise Rejected(["VLAN %s does not exist on the switch; NX-OS would accept it without an error and leave "
                            "the port inactive, so the change is refused" % wanted], reason_codes=["vlan_missing"])
        shown = nxos.switchport(access.query("show interface %s switchport" % key), key)
        if shown["switchport"] != "Enabled":
            raise Rejected(["port %s is not a switchport" % key], reason_codes=["port_routed"])
        if shown["mode"] != "access":
            raise Rejected(["port %s is in %s mode, not access" % (key, shown["mode"])],
                           reason_codes=["port_uplink"])
        plan["prechecks"].append("VLAN %s exists; port %s is an access port" % (wanted, key))
    if not nxos.disruptive(table, before, after):
        return []
    short = nxos.short_name(key)
    if short in nxos.trunk_ports(access.query(QUERY_TRUNKS)):
        raise Rejected(["port %s is a trunk (show interface trunk); a trunk is treated as an uplink and is not "
                        "changed" % key], reason_codes=["port_uplink"])
    if nxos.learned_macs(access.query("show mac address-table interface %s" % key)):
        raise Rejected(["port %s has learned MAC addresses; changing a port in use is refused" % key],
                       reason_codes=["port_learned_mac"])
    if short in nxos.lldp_ports(access.query(QUERY_LLDP)):
        raise Rejected(["port %s has an LLDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    plan["prechecks"].append("port %s is no trunk and has no learned MAC address and no LLDP neighbor" % key)
    return []


def ports(access, table: str):
    return None


# ---- the safeguard objects on the switch ----

KINDS = ("checkpoint", "job", "schedule", "file")
CREATED_AT = re.compile(r"^Created at [A-Z][a-z]{2}, ([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{1,2}) ([A-Z][a-z]{2}) "
                        r"([0-9]{4})\s*$")


def schedule(text: str, label: str):
    """The schedule L of show scheduler schedule name L: its time, whether it ran and the status of its job, or
    None when the switch does not know it ("Error: entry not found")."""
    if "entry not found" in text:
        return None
    names = SCHEDULE_NAME.findall(text)
    when = RUN_ONCE.search(text)
    last = LAST_EXECUTION.search(text)
    if names != [label] or when is None or last is None or when.group(1) not in MONTHS:
        raise Rejected(["the answer about scheduler schedule %s is not recognised" % label])
    month, day, hour, minute, second, year = when.groups()
    status = None
    for line in text.replace("\r", "").split("\n"):
        words = line.split()
        if words[:1] == [label] and len(words) >= 2:
            status = " ".join(words[1:])
    count = EXECUTION_COUNT.search(text)
    executed = last.group(1) != "Yet to be executed" or (count is not None and int(count.group(1)) > 0)
    return {"time": datetime.datetime(int(year), MONTHS.index(month) + 1, int(day), int(hour), int(minute),
                                      int(second)),
            "executed": executed, "status": status}


def _schedule(access, label):
    return schedule(_read(access, "show scheduler schedule name %s" % label), label)


def checkpoints(text: str) -> list:
    return CHECKPOINT_ROW.findall(text.replace("\r", ""))


def checkpoint_created(text: str, label: str):
    """The device time at which checkpoint L was created (show checkpoint summary user: "Created at Mon, 01:10:16
    16 Nov 2026"), or None when L is not listed or the time is not recognised."""
    current = None
    for line in text.replace("\r", "").split("\n"):
        row = CHECKPOINT_ROW.match(line)
        if row is not None:
            current = row.group(1)
            continue
        found = CREATED_AT.match(line.strip())
        if current == label and found is not None and found.group(5) in MONTHS:
            hour, minute, second, day, month, year = found.groups()
            return datetime.datetime(int(year), MONTHS.index(month) + 1, int(day), int(hour), int(minute),
                                     int(second))
    return None


def files(text: str) -> list:
    return FILE_ROW.findall(text.replace("\r", ""))


def objects(access, label) -> dict:
    """Which objects named L exist: scheduler job and schedule (running configuration), checkpoint and the bootflash
    file of the immediate return. The name alone never proves that an object is the own one (see _own)."""
    snapshot = nxos.load(access.query(QUERY_RUNNING), None)
    blocks = [block.header for block in snapshot.scheduler.get(label, [])]
    return {
        "job": "scheduler job name %s" % label in blocks,
        "schedule": "scheduler schedule name %s" % label in blocks,
        "checkpoint": label in checkpoints(access.query(QUERY_CHECKPOINTS)),
        "file": "%s-pred.cfg" % label in files(access.query(QUERY_FILES)),
    }


def leftovers(access) -> list:
    snapshot = nxos.load(access.query(QUERY_RUNNING), None)
    found = {"scheduler %s" % name for name in snapshot.safeguard_names()}
    found |= {"checkpoint %s" % name for name in checkpoints(access.query(QUERY_CHECKPOINTS))
              if name.startswith(nxos.SAFEGUARD_PREFIX)}
    found |= {"bootflash:%s" % name for name in files(access.query(QUERY_FILES))
              if name.startswith(nxos.SAFEGUARD_PREFIX)}
    return sorted(found)


def minutes(seconds: int) -> int:
    """M of `time start +M`: the real delay is in (M-1, M] minutes, so M-1 whole minutes cover safeguard_seconds."""
    return -(-int(seconds) // 60) + 1


def timer_seconds(device) -> float:
    """How long the job protects the change on the monotonic clock of Admin, counted from the moment before the
    installation started: `time start +M` runs at the next whole minute plus M-1 minutes after the device took the
    line, so at least M-1 minutes later, less the drift allowance of the device clock. execute.py takes the shorter
    of this and the lead the device itself reported (safeguard.lead_seconds)."""
    return (minutes(device.safeguard_seconds) - 1) * 60 * (1 - DRIFT_FRACTION)


def install_lines(label: str, seconds: int) -> list:
    return [
        "checkpoint %s" % label,
        "configure terminal",
        "scheduler job name %s" % label,
        "rollback running-config checkpoint %s atomic" % label,
        "exit",
        "scheduler schedule name %s" % label,
        "job name %s" % label,
        "time start +%d" % minutes(seconds),
        "end",
        "no checkpoint %s" % label,
        "checkpoint %s" % label,
        "copy running-config %s" % pred_file(label),
    ]


# what an accepted line of install_lines (1-based) proves the own session did: (object, now own, phase). An object
# is the own one only when the line that creates it was answered without an error in the own session, right after
# the name was read free of every object; the name derived from the change ID alone is never enough.
INSTALL_EFFECTS = {
    1: ("checkpoint", True, "placeholder checkpoint"),
    3: ("job", True, "job created"),
    6: ("schedule", True, "schedule created"),
    8: (None, None, "armed before the checkpoint holds the job"),
    10: ("checkpoint", False, "placeholder checkpoint removed"),
    11: ("checkpoint", True, "checkpoint holds the job and the schedule"),
    12: ("file", True, "installed"),
}


def _own(record) -> dict:
    own = (record.get("safeguard") or {}).get("own")
    return {kind: isinstance(own, dict) and own.get(kind) is True for kind in KINDS}


def install_safeguard(access, record, plan, device, spec, journal=None) -> list:
    """Install the safeguard (variant 3) and note, line by line, which objects the own session created.

    The name must be free of every object right before (a foreign object of the same name is left alone and the
    installation is not started). Each accepted creating line marks its object as own in record["safeguard"]["own"]
    and the journal saves it at once, so an interrupted installation is recognised by recover (its phase) and only
    own objects are ever removed. Verified afterwards: all four objects, an empty rollback patch (the checkpoint holds
    the job and the schedule), a pending schedule and its lead: the schedule time less the creation time of the
    checkpoint, both on the device clock (the device clock itself is never compared with Admin's)."""
    label = safeguard_label(record["change_id"])
    item = record["safeguard"]
    item["minutes"] = minutes(device.safeguard_seconds)
    item["own"] = {kind: False for kind in KINDS}
    item["phase"] = "name check"
    note = journal if journal is not None else (lambda: None)
    found = objects(access, label)
    if any(found.values()):
        return ["objects named %s exist before the installation (%s); they are not the own ones and are left alone"
                % (label, ", ".join(kind for kind in KINDS if found[kind]))]
    item["phase"] = "installing"
    note()

    def answered(number, _answer):
        effect = INSTALL_EFFECTS.get(number)
        if effect is None:
            return
        kind, own, phase = effect
        if kind is not None:
            item["own"][kind] = own
        item["phase"] = phase
        note()

    access.line_answered = answered
    try:
        access.apply(install_lines(label, device.safeguard_seconds), spec)
    finally:
        access.line_answered = None
    problems = []
    found = objects(access, label)
    missing = sorted(name for name, present in found.items() if not present)
    if missing:
        problems.append("safeguard objects are missing: %s" % ", ".join(missing))
    if "Rollback Patch is Empty" not in access.query("show diff rollback-patch running-config checkpoint %s"
                                                     % label):
        problems.append("the safeguard checkpoint does not hold the scheduler job and schedule")
    pending = _schedule(access, label)
    if pending is None or pending["executed"]:
        problems.append("the safeguard schedule is missing or has already run")
        return problems
    created = checkpoint_created(access.query(QUERY_CHECKPOINTS), label)
    if created is None:
        problems.append("the creation time of the safeguard checkpoint is not readable")
        return problems
    lead = (pending["time"] - created).total_seconds()
    # time start +M was taken before the checkpoint was made again, so the schedule runs at most M minutes and,
    # as measured, more than M-1 minutes less the few seconds of the installation after it
    if not (item["minutes"] - 2) * 60 < lead <= item["minutes"] * 60:
        problems.append("the safeguard schedule runs %d s after its checkpoint, not as time start +%d gives"
                        % (lead, item["minutes"]))
    item["device_time"] = pending["time"].strftime("%Y-%m-%d %H:%M:%S")
    item["lead_seconds"] = max(0.0, (lead - 1) * (1 - DRIFT_FRACTION))
    return problems


def _refused_in_progress(exc) -> bool:
    return IN_PROGRESS in str(exc)


def _cleanup(access, record, spec) -> None:
    """Remove the own objects only: the schedule and the job (a pending schedule first, so the job can no longer
    start; after the run the job first, as measured, again while the switch answers "schedule in progress"), then
    the checkpoint and the file; the checkpoint stays while a job or a schedule of the name exists."""
    label = safeguard_label(record["change_id"])
    own = _own(record)
    waited = 0
    while True:
        found = objects(access, label)
        item = _schedule(access, label) if found["schedule"] else None
        order = ("job", "schedule") if item is not None and item["executed"] else ("schedule", "job")
        try:
            for kind in order:
                if found[kind] and own[kind]:
                    access.apply(["configure terminal", "no scheduler %s name %s" % (kind, label), "end"], spec)
        except Exception as exc:
            if not _refused_in_progress(exc) or waited >= CLEANUP_LIMIT_SECONDS:
                raise
            PAUSE(CLEANUP_PAUSE_SECONDS)
            waited += CLEANUP_PAUSE_SECONDS
            continue
        break
    found = objects(access, label)
    if found["job"] or found["schedule"]:
        return
    if found["checkpoint"] and own["checkpoint"]:
        access.apply(["no checkpoint %s" % label], spec)
    if found["file"] and own["file"]:
        access.apply(["delete %s no-prompt" % pred_file(label)], spec)


def remove_safeguard(access, record, spec) -> bool:
    try:
        _cleanup(access, record, spec)
    except Exception:
        pass
    return safeguard_absent(access, record)


def _remaining(access, record) -> list:
    found = objects(access, safeguard_label(record["change_id"]))
    return [kind for kind in KINDS if found[kind]]


def manual_cleanup(label: str, remaining) -> str:
    return ("left on the switch: %s named %s. Check by hand that they are not someone else's, then: configure "
            "terminal / no scheduler schedule name %s / no scheduler job name %s / end / no checkpoint %s / delete "
            "%s no-prompt / copy running-config startup-config. A job that still answers 'schedule in progress' "
            "after its run is removed only by 'no feature scheduler', which creates a system checkpoint and evicts "
            "the oldest one (decision of the switch administrator); enable the feature again afterwards"
            % (", ".join(remaining), label, label, label, label, pred_file(label)))


def discard_installation(access, record, spec) -> tuple:
    """Remove the safeguard of a change that was never sent: an unverified or interrupted installation, in any
    phase. Only the objects the own session proved it created are removed; a pending schedule first, so a job that
    its checkpoint does not hold yet (the phase between time start and the second checkpoint, which blocks the
    scheduler when it runs, measured as variant 1) does not start when this removal succeeds before the minute of
    the job (after an interruption, only when recover runs in time); a job that already ran or a failed removal is
    left to the manual procedure. (True, short detail) when none of the name is left;
    else (False, short detail) and the manual procedure in record["safeguard"]["manual_cleanup"] (the journal; the
    audit log takes only short details)."""
    label = safeguard_label(record["change_id"])
    item = record.setdefault("safeguard", {})
    phase = item.get("phase")
    try:
        _cleanup(access, record, spec)
    except Exception:
        pass
    try:
        remaining = _remaining(access, record)
    except Exception as exc:
        item["manual_cleanup"] = manual_cleanup(label, list(KINDS))
        return False, "the state of the safeguard is not readable (%s); see safeguard.manual_cleanup" % (
            type(exc).__name__)
    if not remaining:
        return True, "installation phase %s; no object of the safeguard is left" % phase
    item["manual_cleanup"] = manual_cleanup(label, remaining)
    return False, "installation phase %s; left: %s; see safeguard.manual_cleanup" % (phase, ", ".join(remaining))


def remove_remaining(access, record, spec) -> bool:
    return discard_installation(access, record, spec)[0]


def safeguard_absent(access, record) -> bool:
    """No own object of the safeguard is left (an object of the name that the own session did not create is not the
    safeguard of this operation)."""
    try:
        found = objects(access, safeguard_label(record["change_id"]))
    except Exception:
        return False
    own = _own(record)
    return not any(found[kind] and own[kind] for kind in KINDS)


def safeguard_disarmed(access, record) -> bool:
    """The job can no longer run: its schedule is gone (job, checkpoint or file may remain)."""
    try:
        return _schedule(access, safeguard_label(record["change_id"])) is None
    except Exception:
        return False


def job_ran(access, label) -> bool:
    """The scheduler logfile holds the output of job L, or the rollback log names checkpoint L with an end time."""
    if re.search(r"^Job Name\s*:\s*%s\s" % re.escape(label), access.query(QUERY_SCHEDULER_LOG), re.MULTILINE):
        return True
    log = _read(access, QUERY_ROLLBACK_EXEC)
    return (re.search(r"^Checkpoint name\s*:\s*%s\s*$" % re.escape(label), log, re.MULTILINE) is not None
            and "End Time UTC" in log)


def safeguard_fired(access, record) -> bool:
    """The job can no longer change the configuration: its schedule is gone (removed by someone; the job never ran)
    or it ran to its end (the schedule reports an execution, no rollback is running, and the scheduler logfile or
    the rollback log shows the rollback to checkpoint L). Decided by reading the scheduler, never by the device
    clock; whether the configuration returned decides the snapshot. Unreadable is not ended: execute.py keeps asking
    until its wait limit on the monotonic clock of Admin."""
    label = safeguard_label(record["change_id"])
    try:
        item = _schedule(access, label)
        if item is None:
            return True
        if not item["executed"] or rollback_running(_read(access, QUERY_ROLLBACK_VERIFY)):
            return False
        return job_ran(access, label)
    except Exception:
        return False


def revert_now(access, record, spec) -> bool:
    """Return the change at once: configure replace with the own file saved right after the installation (it holds
    the job and the schedule, so the replace never deletes them). Sent while the job is pending (execute.py sends it
    only with REVERT_NOW_SECONDS of the own timer left) and after the job ran to its end (a line written late or a
    change of someone else after the timed return); never while a rollback is running. True when it was sent."""
    label = safeguard_label(record["change_id"])
    if not _own(record)["file"] or not objects(access, label)["file"]:
        return False
    item = _schedule(access, label)
    if rollback_running(_read(access, QUERY_ROLLBACK_VERIFY)):
        return False
    if item is not None and item["executed"] and not job_ran(access, label):
        return False
    access.apply(["configure replace %s" % pred_file(label)], spec)
    return True


def before_write(access, record, left, device):
    """None when the change may be written: the own schedule is still pending (read now) and, on the monotonic
    clock of Admin, enough of the timer is left for the write, the readback and the confirmation margin; else the
    reason (nothing is written then)."""
    needed = WRITE_BUDGET_SECONDS + READBACK_BUDGET_SECONDS + device.confirm_margin_seconds
    if left < needed:
        return "%d s of the safeguard left, %d s needed to write, read back and confirm" % (max(left, 0), needed)
    if not all(_own(record).values()):
        return "the safeguard is not proven the own one"
    try:
        item = _schedule(access, safeguard_label(record["change_id"]))
    except Exception as exc:
        return "the scheduler schedule is not readable (%s)" % type(exc).__name__
    if item is None or item["executed"]:
        return "the own scheduler job is no longer pending"
    return None


def line_allowed(left) -> bool:
    return left >= LINE_MARGIN_SECONDS


def persist(access, spec) -> bool:
    access.apply(["copy running-config startup-config"], spec)
    if access.query(QUERY_DIFF).strip():
        raise Rejected(["the running configuration still differs from the startup configuration after the save"])
    return True


def observe(access, plan):
    key = plan["key"]
    if plan["table"] == "vlan-membership":
        shown = nxos.switchport(access.check_query("show interface %s switchport" % key), key)
        return {"access-vlan": shown["access-vlan"]}
    description = nxos.description_row(access.check_query(QUERY_DESCRIPTIONS), key)
    status = nxos.status_row(access.check_query("show interface %s status" % key), key)
    if description is None or status is None:
        return None
    state = {"description": description} if description else {}
    if status["status"] == "disabled":
        state["admin-state"] = "disabled"
    return state


def foreign_sessions(access, device) -> int:
    return nxos.users(access.query(QUERY_USERS))[1]
