"""Juniper Junos ELS execution adapter (measured on vJunos-switch 26.2R1.7, ref/mereni-c8).

Safeguard first, as execute.py needs it: an empty "commit confirmed N comment \"netops-<id>\"" in configure exclusive
is committed before the change and verified by its row "rollback pending" in show system commit. The change runs line
by line in an interactive session (an ssh exec batch continues after an error and its answer is always status 0):
configure exclusive, an empty candidate, the set and delete lines, show | compare and again "commit confirmed N",
which restarts the timer from the new commit (measured: an expiry then returns the change as well). Admin never sends
commit check, and it never commits the change or the inverse lines of an immediate return with a plain commit while
the timer is pending, because a plain commit and commit check both confirm it (measured; commit check leaves no trace
at all); both use commit confirmed. The only plain commit during the pending timer is the confirmation of the proven
own timer: "commit comment \"netops-<id>-ok\"" in configure exclusive; the row "rollback pending" must then be gone.
It is sent after the readback of the change with at least confirm_margin_seconds left, or as the end of an immediate
return (started with at least REVERT_NOW_SECONDS left): at once when no change commit exists yet (a snapshot then
checks the state before), otherwise after the inverse commit confirmed and a snapshot proving the state before. An
expired timer is an automatic rollback committed as "root via other" above the change (with the broadcast "Commit was
not confirmed; automatic rollback complete"); Admin proves it with that commit row.

Ownership (review pattern 1 of IOS and NX-OS). Junos gives a pending commit confirmed no owner: every commit of any
session confirms it, also of the same account. A pending row is Admin's own only with proof from its own session:
the own install session answered "commit complete" and right after it the newest commit row (record 0) is the own
comment netops-<id> of the write account with "rollback pending"; Admin records that row (time, user, comment) as the
safeguard and every later own commit confirmed (the change, an immediate return) as its head. A plain commit (the
confirmation) or another own commit is sent only while the newest row is exactly the recorded head above the recorded
safeguard row. In the session itself the answer of "show | compare" carries the banner "# commit confirmed will be
rolled back in N minutes" while any commit confirmed is pending (measured): the safeguard commit is not sent when the
banner is there (someone else's timer appeared after the prechecks; refused, nothing changed), the confirmation and
the immediate return are not sent when it is gone (the own timer ended; a commit during the automatic rollback would
make it fail, measured). A race of seconds between the last read and the commit line stays possible: Junos has no
identity of the owner of the timer.

Time (review pattern 2). Admin never reads the device clock for the safeguard (TIMER_WATCH in execute.py): the timer
counts whole minutes from its commit row, written at the end of the commit, and expired 0-60 s after them (measured),
so it is counted on the monotonic clock of Admin from the moment before the safeguard was requested, shortened by
DRIFT_FRACTION. Before the change session the own timer must still be pending (read now) with at least
SESSION_BUDGET_SECONDS left for the session and its commit and READBACK_BUDGET_SECONDS + confirm_margin_seconds for
what follows the commit; each line up to the change commit is sent only with COMMIT_BUDGET_SECONDS left. The change
commit restarts the timer: its end moves by the device time between the safeguard row and the change row (both on
the device clock), never past the answer of the session (execute._restarted_end).

Immediate return (review pattern 3). A failed write or readback of a normal operation is returned at once while the
own timer is pending with SESSION_BUDGET_SECONDS left (execute.REVERT_NOW_SECONDS): when no own change commit exists
yet, the empty safeguard needs no return; else the inverse set/delete lines of the plan are committed with "commit
confirmed N comment \"netops-<id>-revert\"", still under the timer. execute.py then proves the state before by a fresh
snapshot and only then confirms; otherwise the timer returns it. When the read after the change commit failed, the
change row becomes the head before the return only by a new read (adopt_change_head). Chosen over "rollback N": the
inverse was measured (P3e, undo in the E2E of task 319) and touches only the planned object, while the index of
rollback N moves with every commit (measured: rollback 1 is wrong after a confirmation) and a rollback during a
pending timer was not measured.

Recover (review pattern 4) decides by show system commit only: armed while a rollback is pending at or above the own
safeguard row, fired with "root via other" above it and nothing pending, disarmed with the own "-ok" row above it.

Timing (measured on the lab, where the vJunos runs under load 15-26): a commit takes 15-150 s (a change session took
126-235 s in task 319), the timer counts whole minutes from the commit row and expires 0-60 s after N minutes, the
automatic rollback commit takes another 55-273 s. N is 10 minutes (safeguard_seconds 600, required by the
configuration). A commit is the save on Junos, so persist has nothing to do.

The write account needs the permission configure (and view, view-configuration for the snapshot); the lab uses the
existing super-user account. The check account of class read-only reads the operational state only (it cannot read
the configuration nor the log, measured).
"""
from __future__ import annotations

import datetime
import hashlib
import json

from netops_admin import junos
from netops_admin.errors import Rejected
from netops_admin.exec_fortios import PromptSpec

QUERY_COMMITS = "show system commit"
QUERY_CLOCK = "show system uptime | display json"
QUERY_VERSION = "show version"
QUERY_AUTHORIZATION = "show cli authorization"
QUERY_USERS = "show system users"
QUERY_LLDP = "show lldp neighbors"
QUERY_DESCRIPTIONS = "show interfaces descriptions"
NEEDED_PERMISSIONS = ("configure", "view", "view-configuration")
CONFIRM_MINUTES = junos.CONFIRM_MINUTES
SAFEGUARD_SECONDS = CONFIRM_MINUTES * 60
MIN_CONFIRM_MARGIN_SECONDS = 240
COMMIT_LINE_SECONDS = 420
LINE_SECONDS = 90
# the slack of the wait for the proof of an expiry (execute.py: the longest timer plus grace plus this, 1820 s on the
# monotonic clock of Admin from the start of the wait): 0-60 s of minute granularity (measured 7-9 s in task 319),
# the automatic rollback commit (55-112 s in task 308, 93 and 273 s in task 319) and a change commit of up to about
# 240 s (task 319) that restarted the timer; admin recover after SIGKILL in task 319 saw the proof 530 s after the
# expiry of the safeguard commit. The wait ends as soon as the proof is read.
FIRING_SLACK_SECONDS = 900
FIRING_OBSERVED = True
TIME = "%Y-%m-%d %H:%M:%S"
# the safeguard is watched on the monotonic clock of Admin and by reading show system commit, never by the device
# clock (execute.py: TIMER_WATCH); the expiry the device shows is kept in safeguard.device_expiry for the journal
TIMER_WATCH = True
FIRE_AT_TEXT = "device commit confirmed timer"
# someone else's commit confirmed appeared between the prechecks and the safeguard commit: refused like in the prechecks
REFUSED_REASON_CODE = "foreign_config_session"
# the timer runs on the device clock, whose drift was not measured on vJunos; the allowance of the IOS adapter (1.7 %
# measured on IOSv) is used
DRIFT_FRACTION = 0.02
# the change session up to the end of its commit: 126-235 s in the E2E of task 319 (commits 15-150 s in task 308)
SESSION_BUDGET_SECONDS = 240
# a line up to the change commit is sent only with this much of the timer left (a commit took up to 150 s)
COMMIT_BUDGET_SECONDS = 180
# after the change commit: the timer read, the snapshot, the account check, the check account and the final snapshot
# (63-90 s from the end of the change session to the confirmation in the E2E of task 319, with a device clock read)
READBACK_BUDGET_SECONDS = 90
# the restart of the timer is counted from two commit rows of whole seconds on the device clock
RESTART_SLACK_SECONDS = 15
# the immediate return commits the inverse under the own timer: started only with a whole session left
REVERT_NOW_SECONDS = SESSION_BUDGET_SECONDS
# the inverse commit leaves the own timer pending; execute.py confirms it only after the state before is proven
REVERT_NOW_KEEPS_SAFEGUARD = True


def _line_seconds(text: str) -> float:
    return COMMIT_LINE_SECONDS if text.split()[:1] == ["commit"] else LINE_SECONDS


def prompt_spec(hostname: str) -> PromptSpec:
    # measured prompts: "netops-admin@d-vjunos> " and, in configuration mode, "[edit]" above "netops-admin@d-vjunos# "
    return PromptSpec(anchor=hostname.encode("ascii"), ends=(b"> ", b"# "), continuation=None,
                      error=junos.cli_error, seconds=_line_seconds)


def safeguard_label(change_id: str) -> str:
    return junos.SESSION_PREFIX + change_id[:12]


def _confirmation(label: str) -> str:
    return label + "-ok"


def _reverting(label: str) -> str:
    return label + "-revert"


def pending_banner(answer: str) -> bool:
    """The answer of an interactive line carries the banner of a pending commit confirmed (measured after every line
    in configuration mode, of any user, while a commit confirmed of anyone is pending)."""
    return any(junos.BANNER.match(row.strip()) for row in answer.replace("\r", "").split("\n"))


def timer_seconds(device) -> float:
    """How long the own timer protects on the monotonic clock of Admin, counted from the moment before its commit was
    requested: the whole minutes from its commit row, which is written at the end of the commit, less the drift
    allowance of the device clock (the expiry came 0-60 s after the minutes, measured)."""
    return CONFIRM_MINUTES * 60 * (1 - DRIFT_FRACTION)


def hostname(access, snapshot_text: str) -> str:
    name = junos.load(snapshot_text, None).hostname
    if not name:
        raise Rejected(["the configuration does not name the device (set system host-name)"])
    return name


def _read(access, command: str) -> str:
    text = access.query(command)
    refused = junos.refused_answer(text)
    if refused is not None:
        raise Rejected(["the device refused %r: %s" % (command, refused)])
    return text


def clock(access) -> datetime.datetime:
    try:
        data = json.loads(_read(access, QUERY_CLOCK))
        value = data["system-uptime-information"][0]["current-time"][0]["date-time"][0]["attributes"][
            "junos:seconds"]
        epoch = int(value)
    except (ValueError, KeyError, IndexError, TypeError):
        raise Rejected(["the device does not report its UTC time"]) from None
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).replace(tzinfo=None, microsecond=0)


def accounts_check(access, device, snapshot_text) -> str:
    snapshot = junos.load(snapshot_text, None)
    present = sorted({line.split()[4] for line in snapshot.lines
                      if line.startswith("set system login user ") and len(line.split()) >= 5})
    if present != sorted(device.accounts):
        raise Rejected(["the switch accounts differ from the expected list (%d present, %d expected)"
                        % (len(present), len(device.accounts))])
    # names, classes and login classes; the authentication lines (password hashes, keys) are left out
    lines = sorted(line for line in snapshot.lines
                   if line.startswith("set system login ") and " authentication " not in line)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def history(access) -> list:
    return junos.commits(_read(access, QUERY_COMMITS))


def _login(access):
    return getattr(getattr(access, "credential", None), "login", None)


def prechecks(access, device, snapshot_text, spec) -> list:
    login, klass, permissions = junos.authorization(_read(access, QUERY_AUTHORIZATION))
    missing = [name for name in NEEDED_PERMISSIONS if name not in permissions]
    if missing:
        raise Rejected(["the write account %s (class %s) lacks the permissions %s"
                        % (login, klass, ", ".join(missing))], reason_codes=["write_account_privilege"])
    running = junos.running_version(_read(access, QUERY_VERSION))
    expected = device.firmware or junos.firmware_of(snapshot_text)
    if running != expected:
        return ["the switch runs Junos %s, not the configured %s" % (running, expected)]
    newest = history(access)[0]
    if newest.pending and not (newest.comment or "").startswith(junos.SESSION_PREFIX):
        raise Rejected(["a commit confirmed of someone else is pending; every commit of Admin, even commit check, "
                        "would confirm it"], reason_codes=["foreign_config_session"])
    # the shared configuration mode shows other users in configuration mode and someone else's uncommitted change;
    # it is left again without a change (measured, also with an uncommitted change of someone else)
    try:
        access.apply([junos.SCREEN, "configure", junos.LEAVE], spec)
    except Rejected:
        raise
    except Exception as exc:
        if "was refused by the device" in str(exc):
            raise Rejected(["another user is in configuration mode or the candidate configuration holds an "
                            "uncommitted change (%s)" % str(exc)[-160:]],
                           reason_codes=["foreign_config_session"]) from None
        raise
    return []


def plan_prechecks(access, device, plan, snapshot_text="") -> list:
    key, table = plan["key"], plan["table"]
    if table not in ("interface", "vlan-membership"):
        return []
    row = junos.interface_row(access.query("show interfaces %s terse" % key), key)
    if row is None:
        raise Rejected(["interface %s does not exist on the switch; Junos would accept its configuration without an "
                        "error, so the change is refused" % key], reason_codes=["port_missing"])
    plan["prechecks"].append("interface %s now: admin %s, link %s" % (key, row["admin"], row["link"]))
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    if table == "vlan-membership":
        wanted = (after or {}).get("access-vlan", junos.DEFAULT_VLAN)
        if not junos.vlan_exists(access.query("show vlans %s" % wanted), wanted):
            raise Rejected(["VLAN %s does not exist on the switch (show vlans %s is empty); the change is refused"
                            % (wanted, wanted)], reason_codes=["vlan_missing"])
        vlans = junos.switching(access.query("show ethernet-switching interface %s" % key), key)
        if not vlans or len(vlans) != 1 or vlans[0][1] != "untagged":
            raise Rejected(["port %s is not an access port with one untagged VLAN" % key],
                           reason_codes=["port_uplink"])
        plan["prechecks"].append("VLAN %s exists; port %s is an access port" % (wanted, key))
    if not junos.disruptive(table, before, after):
        return []
    if key in junos.lldp_ports(_read(access, QUERY_LLDP)):
        raise Rejected(["port %s has an LLDP neighbor (uplink or managed device); the change is refused" % key],
                       reason_codes=["port_lldp_neighbor"])
    if junos.learned_macs(access.query("show ethernet-switching table interface %s" % key), key):
        raise Rejected(["port %s has learned MAC addresses; changing a port in use is refused" % key],
                       reason_codes=["port_learned_mac"])
    plan["prechecks"].append("port %s has no LLDP neighbor and no learned MAC address" % key)
    return []


def ports(access, table: str):
    return None


def leftovers(access) -> list:
    return sorted({commit.comment for commit in history(access)
                   if commit.pending and (commit.comment or "").startswith(junos.SESSION_PREFIX)})


def _label_index(commits, label):
    return next((commit.index for commit in commits if commit.comment == label), None)


def _at(text: str) -> datetime.datetime:
    return datetime.datetime.strptime(text, TIME)


def _expiry(commit) -> str:
    return (_at(commit.at) + datetime.timedelta(minutes=commit.minutes)).strftime(TIME)


def _row(commit) -> dict:
    return {"at": commit.at, "user": commit.user, "comment": commit.comment}


def _same(commit, row) -> bool:
    return isinstance(row, dict) and (commit.at, commit.user, commit.comment) == (
        row.get("at"), row.get("user"), row.get("comment"))


class _Banner(Exception):
    pass


def _session(access, lines, spec, banner_wanted):
    """One interactive session; the answer of its line 3 (show | compare of the empty candidate) must carry the banner
    of a pending commit confirmed (banner_wanted True) or must not (False), else the session ends before the commit
    line is sent (_Banner)."""
    def answered(number, answer):
        if number == 3 and pending_banner(answer) is not banner_wanted:
            raise _Banner("a commit confirmed is pending" if not banner_wanted else "no commit confirmed is pending")

    access.line_answered = answered
    try:
        access.apply(lines, spec)
    finally:
        access.line_answered = None


def install_safeguard(access, record, plan, device, spec) -> list:
    """Commit the empty safeguard and prove that it is the own one: the own session answered "commit complete" (else
    apply raises) and right after it the newest row (record 0) is netops-<id> of the write account, a pending commit
    confirmed of CONFIRM_MINUTES. Only then safeguard.verified is set and the row is recorded as the safeguard and the
    head. When the empty candidate already shows the banner of a pending commit confirmed (someone else's, it appeared
    after the prechecks), the commit is not sent: install "refused", nothing changed."""
    label = safeguard_label(record["change_id"])
    item = record["safeguard"]
    item["minutes"] = CONFIRM_MINUTES
    try:
        _session(access, [junos.SCREEN, junos.ENTER, junos.COMPARE_EMPTY,
                          'commit confirmed %d comment "%s"' % (CONFIRM_MINUTES, label), junos.LEAVE], spec, False)
    except _Banner:
        item["install"] = "refused"
        return ["a commit confirmed of someone else is pending in the session of the safeguard; every commit of Admin "
                "would confirm it, so nothing was committed"]
    newest = history(access)[0]
    login = _login(access)
    if not (newest.comment == label and newest.pending and newest.confirmed and newest.minutes == CONFIRM_MINUTES
            and (login is None or newest.user == login)):
        return ["the safeguard commit is missing or its rollback is not pending"]
    item["commit"] = _row(newest)
    item["head"] = _row(newest)
    item["device_expiry"] = _expiry(newest)
    item["verified"] = True
    return []


def _owned(commits, record) -> bool:
    """The pending timer is the own one: the installation was proven (safeguard.verified), the newest row is the
    recorded head (the last own commit confirmed) with its rollback pending, and the recorded safeguard row is still
    in the history. The same account, the prefix netops- or the comment alone are never enough."""
    item = record.get("safeguard") or {}
    if item.get("verified") is not True or not commits:
        return False
    newest = commits[0]
    if not (newest.pending and newest.confirmed and newest.minutes == CONFIRM_MINUTES and _same(newest, item.get("head"))):
        return False
    index = _label_index(commits, safeguard_label(record["change_id"]))
    return index is not None and _same(commits[index], item.get("commit"))


def safeguard_rearmed(access, record) -> list:
    """After the change commit: its own commit confirmed restarted the timer. The newest row must be the change commit
    of the write account, pending, right above the own safeguard row, which was the head; it becomes the head, and
    the device time between the two rows (shortened for the drift) moves the end of the timer (execute.py)."""
    label = safeguard_label(record["change_id"])
    item = record["safeguard"]
    commits = history(access)
    newest = commits[0]
    login = _login(access)
    if not (newest.comment == junos.CHANGE_COMMENT and newest.pending and newest.minutes == CONFIRM_MINUTES
            and (login is None or newest.user == login)):
        return ["the change commit is not a pending commit confirmed of Admin"]
    item["device_expiry"] = _expiry(newest)
    if _label_index(commits, label) != 1 or not _same(commits[1], item.get("head")) \
            or not _same(commits[1], item.get("commit")):
        return ["another commit lies between the safeguard and the change"]
    item["head"] = _row(newest)
    moved = (_at(newest.at) - _at(commits[1].at)).total_seconds()
    item["restart_offset_seconds"] = max(0.0, moved - 1) * (1 - DRIFT_FRACTION)
    return []


def adopt_change_head(access, record) -> bool:
    """Before an immediate return (execute.py, read within the time left above REVERT_NOW_SECONDS): the change commit
    of this operation is taken as the head also when safeguard_rearmed could not record it (its read failed once, or
    the connection failed at the exit after the commit). Only while the recorded head is still the proven safeguard
    row, and only when show system commit, read again now, has exactly one row above that row: the change comment of
    this operation (the commit line of its plan) of the write account, a pending commit confirmed of CONFIRM_MINUTES.
    Anything else (a foreign commit, more rows, none) adopts nothing: the immediate return then refuses (_owned) and
    the timer returns the change. True when the head was adopted."""
    item = record.get("safeguard") or {}
    if item.get("verified") is not True or not _same_row(item.get("head"), item.get("commit")):
        return False
    planned = [line for line in record["plan"]["commands"] if _commit_line(line)]
    commits = history(access)
    if len(planned) != 1 or len(commits) < 2:
        return False
    newest, login = commits[0], _login(access)
    if not (planned[0] == 'commit confirmed %d comment "%s"' % (CONFIRM_MINUTES, newest.comment)
            and newest.comment == junos.CHANGE_COMMENT and newest.pending and newest.confirmed
            and newest.minutes == CONFIRM_MINUTES and (login is None or newest.user == login)):
        return False
    if _label_index(commits, safeguard_label(record["change_id"])) != 1 or not _same(commits[1], item.get("commit")):
        return False
    item["head"] = _row(newest)
    item["device_expiry"] = _expiry(newest)
    return True


def _same_row(one, other) -> bool:
    return isinstance(one, dict) and isinstance(other, dict) and all(
        one.get(name) == other.get(name) for name in ("at", "user", "comment"))


def before_write(access, record, left, device):
    """None when the change may be written: the own timer is still pending (read now) and, on the monotonic clock of
    Admin, enough of it is left for the change session with its commit and, since the change commit restarts the
    timer with the same uncertainty of its start, for the readback and the confirmation margin; else the reason."""
    needed = max(SESSION_BUDGET_SECONDS, READBACK_BUDGET_SECONDS + device.confirm_margin_seconds + RESTART_SLACK_SECONDS)
    if left < needed:
        return "%d s of the safeguard left, %d s needed to write, read back and confirm" % (max(left, 0), needed)
    try:
        commits = history(access)
    except Exception as exc:
        return "the commit history is not readable (%s)" % type(exc).__name__
    if not _owned(commits, record):
        return "the own commit confirmed is no longer pending"
    return None


def _commit_line(step) -> bool:
    return isinstance(step, str) and step.split()[:2] == ["commit", "confirmed"]


def line_guard_for(steps, left):
    """The guard of the change session (access.line_guard): every line up to the change commit is sent only with
    COMMIT_BUDGET_SECONDS of the own timer left; the change commit restarts the timer, so the lines after it are
    always sent (leaving the configuration mode)."""
    position = iter(list(steps))
    restarted = []

    def allowed() -> bool:
        step = next(position, None)
        if restarted:
            return True
        if left() < COMMIT_BUDGET_SECONDS:
            return False
        if _commit_line(step):
            restarted.append(True)
        return True

    return allowed


def line_allowed(left) -> bool:
    return left >= COMMIT_BUDGET_SECONDS


def _pending(commits, label) -> bool:
    index = _label_index(commits, label)
    return index is not None and any(commit.pending for commit in commits[:index + 1])


def _settled(commits, label, login) -> bool:
    """No rollback is pending and the end of the own timer is proven above the own safeguard row: the own
    confirmation (netops-<id>-ok of the write account) or the automatic rollback (root via other). A timer that ended
    without either (an automatic rollback still running, or a commit of someone else that confirmed it) is not
    settled."""
    if commits[0].pending:
        return False
    index = _label_index(commits, label)
    if index is None:
        return False
    above = commits[:index]
    return (any(commit.comment == _confirmation(label) and (login is None or commit.user == login) for commit in above)
            or any((commit.user, commit.via) == ("root", "other") for commit in above))


def remove_safeguard(access, record, spec) -> bool:
    """Confirm the own pending timer. A pending timer that is not proven the own one is never confirmed (False); the
    confirmation is sent only while the empty candidate still shows the banner of the pending timer (a plain commit
    during the automatic rollback would make it fail, measured). True only when the end of the own timer is proven
    (_settled), so a timer that ended unconfirmed is never taken for a confirmation."""
    label = safeguard_label(record["change_id"])
    login = _login(access)
    try:
        commits = history(access)
        if not commits[0].pending:
            return _settled(commits, label, login)
        if not _owned(commits, record):
            return False
        _session(access, [junos.SCREEN, junos.ENTER, junos.COMPARE_EMPTY, 'commit comment "%s"' % _confirmation(label),
                          junos.LEAVE], spec, True)
    except Exception:
        pass
    try:
        return _settled(history(access), label, login)
    except Exception:
        return False


def remove_remaining(access, record, spec) -> bool:
    """recover: the own pending timer is confirmed only with proof of the own installation (remove_safeguard);
    without it nothing is sent and the safeguard counts as removed only when no rollback is pending at all."""
    if (record.get("safeguard") or {}).get("verified") is True:
        return remove_safeguard(access, record, spec)
    try:
        return not history(access)[0].pending
    except Exception:
        return False


def safeguard_absent(access, record) -> bool:
    """Nothing of the own timer can still change the configuration: the own safeguard row is not in the history (the
    installation never committed), or its end is proven (_settled). A rollback pending at or above it, or a timer
    that ended without proof (an automatic rollback may still run), is present."""
    label = safeguard_label(record["change_id"])
    try:
        commits = history(access)
        if _label_index(commits, label) is None:
            return not commits[0].pending
        return _settled(commits, label, _login(access))
    except Exception:
        return False


def revert_now(access, record, spec) -> bool:
    """Return a failed change at once under the own timer (execute.py sends it only with REVERT_NOW_SECONDS left).

    Only while the own timer is pending (_owned). When the head is still the empty safeguard itself, no change commit
    exists and the configuration is the one of the empty safeguard: the return is its confirmation (execute.py then
    proves the state before by a fresh snapshot). Else the inverse lines of the plan are committed with "commit confirmed N comment netops-<id>-revert"
    (the empty candidate must still show the banner of the pending timer); the new row must then be pending right
    above the head and becomes the head. True when the return is under the own timer, False otherwise (then
    execute.py waits for the expiry)."""
    item = record.get("safeguard") or {}
    label = safeguard_label(record["change_id"])
    try:
        commits = history(access)
        if not _owned(commits, record):
            return False
        if _same(commits[0], item.get("commit")):
            # no own change commit exists: the configuration is the one of the empty safeguard (the state before),
            # so the return is its confirmation; when that cannot be proven the timer returns it
            return remove_safeguard(access, record, spec)
        change = 'commit confirmed %d comment "%s"' % (CONFIRM_MINUTES, _reverting(label))
        lines = [change if _commit_line(line) else line for line in record["plan"]["inverse"]]
        if lines.count(change) != 1 or lines[:3] != [junos.SCREEN, junos.ENTER, junos.COMPARE_EMPTY]:
            return False
        try:
            _session(access, lines, spec, True)
        except Exception:
            pass
        commits = history(access)
    except Exception:
        return False
    newest, login = commits[0], _login(access)
    if not (newest.comment == _reverting(label) and newest.pending and newest.minutes == CONFIRM_MINUTES
            and (login is None or newest.user == login) and len(commits) > 1 and _same(commits[1], item.get("head"))):
        return False
    item["head"] = _row(newest)
    item["device_expiry"] = _expiry(newest)
    return True


def safeguard_disarmed(access, record) -> bool:
    label = safeguard_label(record["change_id"])
    try:
        commits = history(access)
    except Exception:
        return False
    index = _label_index(commits, label)
    if index is None or _pending(commits, label):
        return False
    above = commits[:index]
    return (any(commit.comment == _confirmation(label) for commit in above)
            and not any((commit.user, commit.via) == ("root", "other") for commit in above))


def safeguard_fired(access, record) -> bool:
    """The timer expired and Junos rolled back: no rollback is pending and the automatic rollback is committed as
    "root via other" above the safeguard (measured; a confirmation that wins the race leaves no such row). Decided by
    show system commit only, never by the device clock; unreadable is not fired (execute.py keeps reading until its
    wait limit on the monotonic clock of Admin)."""
    label = safeguard_label(record["change_id"])
    try:
        commits = history(access)
    except Exception:
        return False
    index = _label_index(commits, label)
    if index is None or _pending(commits, label):
        return False
    return any((commit.user, commit.via) == ("root", "other") for commit in commits[:index])


def persist(access, spec) -> bool:
    # a Junos commit is the saved configuration; nothing is left to save
    return False


def observe(access, plan):
    key = plan["key"]
    if plan["table"] == "vlan-membership":
        vlans = junos.switching(access.check_query("show ethernet-switching interface %s" % key), key)
        if not vlans or len(vlans) != 1 or vlans[0][1] != "untagged":
            return None
        return {"access-vlan": vlans[0][0]}
    row = junos.interface_row(access.check_query("show interfaces %s terse" % key), key)
    if row is None:
        return None
    description = junos.description_of(access.check_query(QUERY_DESCRIPTIONS), key)
    state = {"description": description} if description else {}
    if row["admin"] == "down":
        state["admin-state"] = "disabled"
    return state


def foreign_sessions(access, device) -> int:
    return junos.users(_read(access, QUERY_USERS))

