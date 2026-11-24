"""Private, encrypted Junos configuration backups and their controlled restore (junos config, J43).

Measured on vJunos-switch 26.2R1.7 (vJunos-switch, verification):

* ``show configuration | no-more`` over SSH exec returns the whole committed configuration in the hierarchical
  format (first line ``## Last commit: <time> by <user>``, then ``version <release>;``), secrets included for a
  super-user account (``encrypted-password "..."; ## SECRET-DATA``).  A read-only class gets
  ``<section> { /* ACCESS-DENIED */ };`` with exit status 0.  An error is printed on stdout (``error:...``) with
  exit status 0.  That text is what ``load override`` accepts, so it is the backup.
* ``show system configuration rescue | no-more`` exports the previous rescue if present. It is sealed in a
  separate retention series before ``request system configuration rescue save`` stores the committed configuration;
  ``show system configuration rescue | count`` then answers ``Count: <n> lines`` (without one: ``error: No rescue
  configuration is set.``).
* SFTP is not enabled on the device, so the restore loads the backup through the terminal:
  ``configure exclusive``, ``load override terminal`` (``[Type ^D at a new line to end input]``), the backup
  lines, Ctrl-D (``load complete``), ``show | compare`` (empty for an identical text).

The backup text never leaves the operator host unencrypted: it is sealed with AES-GCM (``NETOPS_BACKUP_KEY``)
into a private directory outside Git worktrees (backup.py), and a reply carries only names, counts and
SHA-256 digests.  The artifact name binds the backup to its target (host and port).

Restore (``restore``): the preview reads the device and compares the normalized texts (the ``## Last commit``
line left out) without any write; it returns the numbers of added and removed lines and ``plan_sha256``
binding the target, the backup digest and the digest of the current configuration.  Apply with that
confirmation: the current configuration must still have the planned digest and no ``commit confirmed`` may be
pending; the current configuration is first sealed as the return artifact (``undo_artifact``, restorable with
this command); then ``commit confirmed <minutes> comment "netops-restore-<id>"``; the readback must equal the
backup; only then, while the own commit row is still the newest pending one, ``commit comment
"netops-restore-<id>-ok"`` confirms it.  A failed readback is returned at once by loading the saved current text
and a plain ``commit comment "netops-restore-<id>-revert"`` (a plain commit also ends the timer); when even that
is not possible the device timer rolls the change back.
"""

import hashlib
from hmac import compare_digest
import json
import os
from pathlib import Path
import re
import secrets
import time

from netops.files import write_private
from netops_admin import junos
from netops_admin.backup import _backup_destination, _key, _metrics, _read_backup, _reject, _save
from netops_admin.errors import Rejected
from netops_core import hostkey, session, ssh, tested, vault

MAGIC = b"NETOPS-JUNOS-BACKUP\x00\x01"
MAX_BYTES = 16 * 1024 * 1024
TESTED = [("ex9214", "26.2R1.7")]
SHOW = "show configuration | no-more"
VERSION = "show version | no-more"
COMMITS = "show system commit | no-more"
RESCUE_SAVE = "request system configuration rescue save"
RESCUE_SHOW = "show system configuration rescue | no-more"
RESCUE_COUNT = "show system configuration rescue | count"
RESCUE_ABSENT = b"error: No rescue configuration is set."
EXEC_SECONDS = 120.0
LINE_SECONDS = 60.0
COMMIT_SECONDS = 300.0
MINUTES = (2, 60)
CONFIRM_MARGIN_SECONDS = 45
ARTIFACT = re.compile(r"(junos-[0-9a-f]{32})(-rescue)?-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\.netops-backup")
HEADER = re.compile(r"## Last commit: [^\r\n]{1,200}")
RESCUE_HEADER = re.compile(r"## Last changed: [^\r\n]{1,200}")
RELEASE = re.compile(r"version ([A-Za-z0-9][A-Za-z0-9._:-]{0,63});")
MODEL = re.compile(r"(?m)^Model: ([A-Za-z0-9][A-Za-z0-9_.+-]{0,63})\r?$")
JUNOS = re.compile(r"(?m)^Junos: ([0-9][A-Za-z0-9._-]{0,63})\r?$")
COUNT = re.compile(r"\s*Count: ([0-9]{1,9}) lines\s*")
PROMPT = re.compile(rb"\n[^\r\n]{0,128}@[A-Za-z0-9._-]{1,64}[>#] ")
LOADED = re.compile(rb"load complete( \([0-9]+ errors?\))?\r?\n")
REFUSED = re.compile(r"(?m)^\s*(?:error:|syntax error|warning: configuration database locked|"
                     r"configuration check-out failed|[^\r\n]*: syntax error)")


def _target_prefix(host, port):
    return "junos-" + hashlib.sha256(f"{host.lower()}:{port}".encode()).hexdigest()[:32]


def _checked_target(host, port, login, pin):
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", host) or not 1 <= port <= 65535
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", login)):
        raise _reject("backup_request_invalid", "Invalid Junos backup target")
    try:
        hostkey.checked_pin(pin)
    except hostkey.HostKeyError:
        raise _reject("backup_request_invalid", "Invalid Junos SSH pin") from None


def _credential(login):
    try:
        return vault.Credential("backup", "password", os.environ.get("NETOPS_BACKUP_PASSWORD", ""), login=login)
    except (ValueError, vault.VaultError):
        raise _reject("backup_credentials_unavailable", "Set NETOPS_BACKUP_PASSWORD for the Junos account") from None


def configuration_text(data, *, rescue=False):
    """(text, release) of a complete hierarchical Junos configuration; anything else is backup_incomplete."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _reject("backup_incomplete", "Junos returned a configuration that is not UTF-8") from None
    text = text.replace("\r\n", "\n")
    if "/* ACCESS-DENIED */" in text:
        raise _reject("backup_refused", "The Junos account does not see the whole configuration")
    lines = text.split("\n")
    header = RESCUE_HEADER if rescue else HEADER
    if not 64 <= len(data) <= MAX_BYTES or not text.endswith("}\n") or not header.fullmatch(lines[0]):
        raise _reject("backup_incomplete", "Junos returned an incomplete configuration")
    release = RELEASE.fullmatch(lines[1]) if len(lines) > 1 else None
    if release is None or "system {" not in lines:
        raise _reject("backup_incomplete", "Junos configuration header or system section is missing")
    depth, quoted, comment = 0, False, False
    for line in lines[1:]:
        if "/* ACCESS-DENIED */" in line or (not quoted and not comment and REFUSED.match(line)):
            raise _reject("backup_refused", "The Junos account does not see the whole configuration")
        position = 0
        while position < len(line):
            character = line[position]
            if comment:
                if line.startswith("*/", position):
                    comment, position = False, position + 1
            elif quoted:
                if character == "\\":
                    position += 1
                elif character == '"':
                    quoted = False
            elif character == '"':
                quoted = True
            elif line.startswith("/*", position):
                comment, position = True, position + 1
            elif character == "#" and line.startswith("## ", position):
                break
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth < 0:
                    raise _reject("backup_incomplete", "Junos configuration framing is broken")
            position += 1
    if depth or quoted or comment:
        raise _reject("backup_incomplete", "Junos configuration framing is incomplete")
    return text, release.group(1)


def normalized(text):
    """The configuration without the commit or rescue timestamp header."""
    lines = text.replace("\r\n", "\n").split("\n")
    return "\n".join(lines[1:] if HEADER.fullmatch(lines[0]) or RESCUE_HEADER.fullmatch(lines[0]) else lines)


def _digest(text):
    return hashlib.sha256(normalized(text).encode("utf-8")).hexdigest()


class _Device:
    """Pinned SSH exec reads and one interactive configuration session of the backup account."""

    def __init__(self, host, port, login, pin):
        self.host, self.port, self.login = host, port, login
        self.credential = _credential(login)
        try:
            self.known = hostkey.scan(host, port, pin, ssh.DEFAULT_TIMEOUT_SECONDS)
        except hostkey.HostKeyError:
            raise _reject("backup_identity_mismatch", "Could not verify the Junos SSH host key") from None

    def read(self, command, limit=MAX_BYTES):
        try:
            result = ssh.run_command(self.host, self.port, None, self.credential, self.known, command,
                                     timeout_seconds=EXEC_SECONDS, capture_max_bytes=limit + 65536)
        except ssh.SshError:
            raise _reject("backup_transport_failed", "Junos SSH read failed") from None
        if result.rc != 0:
            raise _reject("backup_refused", "Junos refused the read")
        return result.stdout

    def text(self, command):
        answer = self.read(command, 1024 * 1024).decode("utf-8", "replace")
        if REFUSED.search(answer):
            raise _reject("backup_refused", "Junos refused %r" % command)
        return answer

    def configuration(self):
        return configuration_text(self.read(SHOW))

    def identity(self):
        answer = self.text(VERSION)
        model, release = MODEL.search(answer), JUNOS.search(answer)
        if model is None or release is None:
            raise _reject("backup_incomplete", "Junos show version names no model or release")
        return model.group(1), release.group(1)

    def commits(self):
        answer = self.text(COMMITS)
        try:
            return junos.commits(answer)
        except Rejected:
            raise _reject("backup_refused", "Junos commit history is not readable") from None

    def configure(self, steps):
        """One interactive session: configure exclusive, the steps, exit configuration-mode.

        A step is a command (its answer must not be a refusal), ("load", text) for load override terminal,
        ("commit", line) whose answer must say commit complete, or ("count", command) whose ``Count: <n> lines``
        is returned.  No other answer is returned: the loaded lines hold secrets.
        """
        counts = []
        size = sum(len(step[1]) if type(step) is tuple else len(step) for step in steps)
        try:
            with session.Session(self.host, self.port, None, self.credential, self.known,
                                 timeout_seconds=LINE_SECONDS, capture_max_bytes=4 * size + 1024 * 1024) as shell:
                shell.expect([PROMPT], LINE_SECONDS)
                for step in ["configure exclusive", *steps, "exit configuration-mode"]:
                    if type(step) is tuple and step[0] == "load":
                        self._load(shell, step[1])
                        continue
                    line = step[1] if type(step) is tuple else step
                    committing = type(step) is tuple and step[0] == "commit"
                    shell.send(line)
                    _, answer = shell.expect([PROMPT], COMMIT_SECONDS if committing else LINE_SECONDS)
                    text = answer.decode("utf-8", "replace")
                    if REFUSED.search(text) or (committing and "commit complete" not in text):
                        raise _reject("backup_restore_refused", "Junos refused %r" % line.split(" comment ")[0])
                    if type(step) is tuple and step[0] == "count":
                        found = re.search(r"Count: ([0-9]{1,9}) lines", text)
                        if found is None:
                            raise _reject("backup_restore_refused", "Junos did not count %r" % line)
                        counts.append(int(found.group(1)))
        except session.SessionError:
            raise _reject("backup_transport_failed", "Junos configuration session failed") from None
        return counts

    @staticmethod
    def _load(shell, text):
        shell.send("load override terminal")
        shell.expect([b"[Type ^D at a new line to end input]"], LINE_SECONDS)
        lines = normalized(text).rstrip("\n").split("\n")
        for number, line in enumerate(lines, 1):
            shell.send(line)
            if number % 40 == 0:
                # drain the echo so that neither side of the terminal blocks on a full buffer
                shell.expect([b"\n"], LINE_SECONDS, quiet_seconds=0.3)
        shell.send("\x04")
        _, answer = shell.expect([LOADED], COMMIT_SECONDS)
        failed = LOADED.search(answer).group(1)
        # the session ends the Ctrl-D line with a newline: Junos answers "load complete" with a prompt and the empty
        # line with a second one (measured); both are consumed, else the next command would match the stale prompt
        shell.expect([PROMPT], LINE_SECONDS)
        shell.expect([PROMPT], LINE_SECONDS)
        if failed:
            raise _reject("backup_restore_refused", "Junos refused the loaded configuration")


def _equal(device, configuration, wanted):
    """Whether the committed configuration is the wanted one: the same normalized text, or else (Junos prints its
    own canonical form, e.g. a value without spaces unquoted, measured) an empty ``show | compare`` after loading
    the wanted text into the candidate of a session that commits nothing."""
    if _digest(configuration) == _digest(wanted):
        return True
    try:
        return device.configure([("load", wanted), ("count", "show | compare | count")]) == [0]
    except Rejected:
        return False


def _support(model, release):
    support = tested.support("Junos", release, TESTED, model=model, function="configuration backup and restore")
    return support, ([tested.warning(support)] if tested.warning(support) else [])


def run(host, port, login, pin, directory, keep, confirmation, *, rescue=False):
    """Preview (no device contact) or, with the plan_sha256 as confirmation, the encrypted backup."""
    _checked_target(host, port, login, pin)
    if not 1 <= keep <= 365 or type(rescue) is not bool:
        raise _reject("backup_request_invalid", "Invalid Junos backup retention")
    destination = _backup_destination(directory)
    plan = dict(host=host, port=port, login=login, ssh_sha256=pin, directory=str(destination), keep=keep,
                rescue=rescue, platform="junos")
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
    if confirmation is None:
        return {"result": "ready", "plan_sha256": digest, "plan": plan}
    if not compare_digest(confirmation.encode(), digest.encode()):
        raise _reject("plan_changed", "The backup confirmation does not match the current plan")
    key = _key()
    device = _Device(host, port, login, pin)
    model, running = device.identity()
    rescue_lines = None
    rescue_artifact = None
    rescue_retention_ok = True
    prefix = _target_prefix(host, port)
    if rescue:
        previous = device.read(RESCUE_SHOW)
        if previous.strip() != RESCUE_ABSENT:
            previous_text, _ = configuration_text(previous, rescue=True)
            if _backup_destination(directory) != destination:
                raise _reject("backup_destination_unsafe", "The backup destination changed after confirmation")
            rescue_artifact, rescue_retention_ok, _, _ = _save(
                destination, prefix + "-rescue", previous_text.encode("utf-8"), keep, key, magic=MAGIC)
        device.text(RESCUE_SAVE)
        found = COUNT.fullmatch(device.text(RESCUE_COUNT))
        # without a rescue configuration the error line itself is counted: 'Count: 1 lines' (measured)
        if found is None or int(found.group(1)) < 2:
            raise _reject("backup_refused", "Junos did not report the saved rescue configuration")
        rescue_lines = int(found.group(1))
    text, release = device.configuration()
    if _backup_destination(directory) != Path(plan["directory"]):
        raise _reject("backup_destination_unsafe", "The backup destination changed after confirmation")
    name, retention_ok, _, sealed = _save(destination, prefix, text.encode("utf-8"), keep, key, magic=MAGIC)
    support, warnings = _support(model, running)
    result = {"result": "confirmed", "artifact": name, "retention_ok": retention_ok and rescue_retention_ok,
              "configuration_release": release,
              "configuration_sha256": _digest(text), "rescue_saved": rescue, "firmware_support": support,
              **_metrics(sealed)}
    if rescue_lines is not None:
        result["rescue_lines"] = rescue_lines
    if rescue_artifact is not None:
        result["rescue_artifact"] = rescue_artifact
    if warnings:
        result["warnings"] = warnings
    return result


def _sealed_text(source):
    _backup_destination(source.parent)
    match = ARTIFACT.fullmatch(source.name)
    if match is None:
        raise _reject("backup_invalid", "Not a Junos backup artifact name")
    data = _read_backup(source, _key(), magic=MAGIC)
    text, release = configuration_text(data, rescue=match.group(2) is not None)
    return match.group(1), text, release


def unseal(source, output):
    """Authenticate a sealed backup and write it to a private .conf file (for load override on the device)."""
    directory = _backup_destination(output.parent)
    _, text, _ = _sealed_text(source)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.conf", output.name):
        raise _reject("backup_request_invalid", "The Junos restore filename must end in .conf")
    if _backup_destination(output.parent) != directory:
        raise _reject("backup_destination_unsafe", "The restore destination changed before writing")
    try:
        write_private(directory / output.name, text.encode("utf-8"))
    except (OSError, RuntimeError):
        raise _reject("backup_storage_failed", "Could not create the private Junos restore file") from None
    return {"result": "confirmed", "configuration_sha256": _digest(text), **_metrics(text.encode("utf-8"))}


def _changes(current, wanted):
    before, after = normalized(current).split("\n"), normalized(wanted).split("\n")
    old, new = _count(before), _count(after)
    removed = sum(max(0, number - new.get(line, 0)) for line, number in old.items())
    added = sum(max(0, number - old.get(line, 0)) for line, number in new.items())
    return {"added_lines": added, "removed_lines": removed, "identical": before == after}


def _count(lines):
    counted = {}
    for line in lines:
        counted[line] = counted.get(line, 0) + 1
    return counted


def restore(host, port, login, pin, source, minutes, confirmation):
    """Preview (reads only) or, with the plan_sha256 as confirmation, the restore of a sealed backup."""
    _checked_target(host, port, login, pin)
    if type(minutes) is not int or not MINUTES[0] <= minutes <= MINUTES[1]:
        raise _reject("backup_request_invalid", "commit confirmed minutes must be 2 to 60")
    prefix, wanted, release = _sealed_text(source)
    if prefix != _target_prefix(host, port):
        raise _reject("backup_target_mismatch", "The backup belongs to another Junos target")
    device = _Device(host, port, login, pin)
    model, running = device.identity()
    current, _ = device.configuration()
    plan = dict(host=host, port=port, login=login, ssh_sha256=pin, artifact=source.name, minutes=minutes,
                backup_sha256=_digest(wanted), current_sha256=_digest(current), platform="junos")
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
    support, warnings = _support(model, running)
    extra = {"firmware_support": support, **({"warnings": warnings} if warnings else {})}
    changes = _changes(current, wanted)
    if confirmation is None:
        return {"result": "ready", "plan_sha256": digest, "plan": plan, "configuration_release": release,
                **changes, **extra}
    if not compare_digest(confirmation.encode(), digest.encode()):
        raise _reject("plan_changed", "The device configuration or the backup changed since the preview")
    if changes["identical"]:
        return {"result": "confirmed", "changed": False, **changes, **extra}
    newest = device.commits()[0]
    if newest.pending:
        raise Rejected(["a commit confirmed is pending on the device; every commit would confirm it"],
                       reason_codes=["foreign_config_session"])
    key = _key()
    destination = _backup_destination(source.parent)
    undo, _, _, _ = _save(destination, prefix, current.encode("utf-8"), 365, key, magic=MAGIC)
    label = "netops-restore-" + secrets.token_hex(6)
    started = time.monotonic()
    pending = None

    def unknown(reason_codes):
        # Once the configured window may have elapsed, the last pending observation is inconclusive.
        timer = None if pending and time.monotonic() - started >= minutes * 60 else pending
        return {"result": "unknown", "commit_label": label, "pending": timer, "rollback_minutes": minutes,
                "undo_artifact": undo, **changes, **extra, "reason_codes": reason_codes}

    try:
        device.configure([("load", wanted),
                          ("commit", 'commit confirmed %d comment "%s"' % (minutes, label))])
    except Rejected:
        # A disconnected session can leave a confirmed commit with an active rollback timer.
        try:
            newest = device.commits()[0]
            if newest.comment == label:
                pending = newest.pending
                return unknown(["backup_restore_refused"])
            after, _ = device.configuration()
        except Rejected as failure:
            return unknown(failure.reason_codes)
        state = "unchanged" if _digest(after) == _digest(current) else "unknown"
        return {"result": "rejected", "state": state, "undo_artifact": undo, **changes, **extra,
                "reason_codes": ["backup_restore_refused"]}
    pending = True  # commit complete was seen for the confirmed commit
    try:
        head = device.commits()[0]
        pending = head.pending if head.comment == label else None
        owned = pending is True
        after, _ = device.configuration()
        if owned and _equal(device, after, wanted) and time.monotonic() - started < minutes * 60 - CONFIRM_MARGIN_SECONDS:
            if device.commits()[0].comment == label:
                pending = None  # the confirmation may succeed even if its reply is lost
                device.configure([("commit", 'commit comment "%s-ok"' % label)])
                final = device.commits()[0]
                if not final.pending and final.comment == label + "-ok":
                    pending = False
                    confirmed, _ = device.configuration()
                    if _digest(confirmed) == _digest(after):
                        return {"result": "confirmed", "changed": True, "commit_label": label, "undo_artifact": undo,
                                "configuration_sha256": _digest(confirmed), **changes, **extra}
            else:
                pending = None
            return unknown(["backup_restore_refused"])
        # Readback differs (or the own row is gone): return the saved current configuration at once.
        if owned:
            pending = None
            try:
                device.configure([("load", current), ("commit", 'commit comment "%s-revert"' % label)])
                pending = False
            except Rejected:
                pass
        returned, _ = device.configuration()
    except Rejected as failure:
        return unknown(failure.reason_codes)
    state = "reverted" if _equal(device, returned, current) else "revert-failed"
    return {"result": state, "commit_label": label, "undo_artifact": undo, **changes, **extra,
            "reason_codes": ["backup_restore_refused"]}
