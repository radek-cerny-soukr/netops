"""Simulated vJunos-switch 26.2R1.7 (ELS) for netops-admin tests.

Every answer is built from an anonymised output measured on vJunos-switch 26.2R1.7 (fixtures/junos_26_2R1_7, task
netops-provoz-20261116-308). The configuration starts from the reconstructed lab configuration; the candidate, the
commit history and the commit confirmed timer follow the measured behaviour: configure exclusive works on the shared
candidate and drops it at exit, every commit confirmed restarts the timer, commit check and a plain commit confirm it,
the timer expires 0-60 s after its minutes and the automatic rollback is committed as "root via other" a while later,
returning the configuration before the newest commit confirmed (task netops-20261116-378), and a confirmation that
starts before the expiry wins the race.
"""
from __future__ import annotations

import copy
import datetime
import fnmatch
import ipaddress
import json
import re
from pathlib import Path
from types import SimpleNamespace

from netops_admin.access import AccessError

FIRMWARE = "26.2R1.7"
HOSTNAME = "host01"
LOGIN = "netops-admin"
FIXTURES = Path(__file__).parent / "fixtures" / "junos_26_2R1_7"
START_EPOCH = 1794788049.0  # show system uptime | display json of the measurement (2026-11-16 00:14:09 UTC)
PORTS = tuple("ge-0/0/%d" % number for number in range(10))
COMMIT_ROW = re.compile(r"^([0-9]+)\s+(\S+ \S+) UTC by (\S+) via (\S+)(?: commit confirmed, rollback in ([0-9]+)mins)?$")


class DeviceRefused(AccessError):
    """A line refused by the device, worded like access.DeviceAccess.apply."""

    def __init__(self, accepted_lines, line="", marker=""):
        super().__init__("line %d was refused by the device: %s (%s)" % (accepted_lines + 1, marker, line[:40]),
                         accepted_lines)


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def fixture_g138(name: str) -> str:
    return (FIXTURES.parent / "junos_g138" / name).read_text(encoding="utf-8")


BASELINE = fixture("show-configuration-display-set__reconstructed.txt")


def _history(text):
    found = []
    for row in text.split("\n"):
        match = COMMIT_ROW.match(row.rstrip())
        if match:
            found.append({"at": match.group(2), "user": match.group(3), "via": match.group(4),
                          "minutes": int(match.group(5)) if match.group(5) else None, "comment": None,
                          "pending": False})
        elif row.strip() == "rollback pending":
            found[-1]["pending"] = True
        elif row.strip() and found:
            found[-1]["comment"] = row.strip()
    return found


def _stamp(epoch) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _display(line: str) -> str:
    """A set line as show configuration | display set shows it: a quoted value without a space loses its quotes."""
    match = re.match(r'^(.* description )"([^" ]*)"$', line)
    return match.group(1) + match.group(2) if match else line


def _place(candidate, name, line):
    """Insert a set line where display set shows it: description and disable before the units of the interface,
    a unit line after the last line of the interface, a new interface after the last ge- interface."""
    prefix = "set interfaces %s " % name
    own = [index for index, item in enumerate(candidate) if item.startswith(prefix)]
    if not own:
        ports = [index for index, item in enumerate(candidate) if item.startswith("set interfaces ge-")]
        candidate.insert(ports[-1] + 1 if ports else len(candidate), line)
        return
    rest = line[len(prefix):]
    if rest.startswith("unit "):
        candidate.insert(own[-1] + 1, line)
        return
    units = [index for index in own if candidate[index][len(prefix):].startswith("unit ")]
    order = 0 if rest.startswith("description ") else 1
    before = [index for index in own if not candidate[index][len(prefix):].startswith("unit ")
              and (0 if candidate[index][len(prefix):].startswith("description ") else 1) <= order]
    candidate.insert(before[-1] + 1 if before else (units[0] if units else own[-1] + 1), line)


NAME = r"[A-Za-z][A-Za-z0-9_.-]{0,62}"
ADDRESS = r"[0-9a-f:.]{2,39}"
SEVERITY = "emergency|alert|critical|error|warning|notice|info|any|none"
FACILITY = r"authorization|daemon|ftp|kernel|local[0-7]|user"
PORT = r"(?:ge|xe)-0/0/[0-9]+"
TEXT = r'(?:"[^"]*"|\S+)'
_PORT_REST = (r"(?:description %s|disable|native-vlan-id [0-9]{1,4}|apply-groups %s"
              r"|unit 0 family ethernet-switching (?:interface-mode (?:access|trunk)|vlan members %s))" % (TEXT, NAME, NAME))
# the statements the simulated switch accepts (the measured forms of task-evidence/g137 and ref/mereni-c8)
# 1.0.12 G145 r2: the facilities of the message selectors of a remote host ("set system syslog host <ip> ?",
# task-evidence/g145/probe1/help.txt)
SELECTORS = ("authorization|change-log|conflict-log|daemon|dfc|external|firewall|ftp|interactive-commands|kernel|ntp|pfe"
             "|security|user")
SYNTAX = [re.compile(item) for item in (
    r"set interfaces %s %s" % (PORT, _PORT_REST),
    # 1.0.12 G138 (read by ? on d-vjunos, task-evidence/g138/znalost/s3-help.txt)
    r"set interfaces %s (?:speed (?:10m|100m|1g|10g|auto)|mtu (?:25[6-9]|2[6-9][0-9]|[3-8][0-9]{3}|9[01][0-9]{2}|91[0-8][0-9]|919[0-2])"
    r"|ether-options (?:no-)?auto-negotiation)" % PORT,
    r"set poe interface %s disable" % PORT,
    r"set interfaces interface-range %s (?:member %s|%s)" % (NAME, PORT, _PORT_REST),
    r"set interfaces irb unit [0-9]+ description %s" % TEXT,
    r"set groups %s interfaces (?:%s|\"?<[^ >]+>\"?) %s" % (NAME, PORT, _PORT_REST),
    r"set apply-groups %s" % NAME,
    r"set vlans %s (?:vlan-id [0-9]{1,4}|description %s|l3-interface irb\.[0-9]+)" % (NAME, TEXT),
    r"set switch-options voip interface %s\.0 vlan %s" % (PORT, NAME),
    r"set protocols mstp msti [0-9]+ vlan %s" % NAME,
    # 1.0.12 G145 (task-evidence/g145/probe1-3): the measured forms and the CLI completions ('?')
    r"set system host-name [A-Za-z0-9.-]+",
    r"set system domain-name [A-Za-z0-9.-]+",
    r"set system name-server %s" % ADDRESS,
    r"set system ntp server %s(?: prefer)?" % ADDRESS,
    r"set system ntp source-address %s" % ADDRESS,
    r"set system syslog host %s (?:(?:any|%s) (?:%s)|port [0-9]{1,5}|facility-override (?:%s))"
    % (ADDRESS, SELECTORS, SEVERITY, FACILITY),
)]
# single-valued leaves: a set replaces the old value
SINGLE = re.compile(r"^(set .*? (?:description|vlan-id|native-vlan-id|interface-mode|l3-interface|speed|mtu)|"
                    r"set switch-options voip interface \S+ vlan|set system (?:host-name|domain-name)|"
                    r"set system syslog host \S+ (?:any|port|facility-override|" + SELECTORS + r")) ")
NTP_SERVER = re.compile(r"^set system ntp server (\S+)( prefer)?$")


def _place_other(candidate, line):
    """A new statement goes after the last statement that shares the most leading words with it."""
    words = line.split()
    best, where = 0, len(candidate)
    for index, item in enumerate(candidate):
        shared = 0
        for one, other in zip(words, item.split()):
            if one != other:
                break
            shared += 1
        if shared >= best and shared >= 2:
            best, where = shared, index + 1
    candidate.insert(where, line)


def effective(lines, port) -> list:
    """The statements of a port from the port itself, an interface-range and applied groups (Junos inheritance as
    measured in task-evidence/g137: display inheritance | display set shows them as statements of the port)."""
    prefix = "set interfaces %s " % port
    found = [line[len(prefix):] for line in lines if line.startswith(prefix)
             and not line[len(prefix):].startswith("apply-groups ")]
    ranges = {line.split()[3] for line in lines if re.fullmatch(r"set interfaces interface-range \S+ member %s"
                                                                  % re.escape(port), line)}
    for name in sorted(ranges):
        head = "set interfaces interface-range %s " % name
        found += [line[len(head):] for line in lines if line.startswith(head)
                  and not line[len(head):].startswith("member ")]
    top = [line.split()[2] for line in lines if line.startswith("set apply-groups ")]
    own = [line.split()[-1] for line in lines if line.startswith(prefix + "apply-groups ")]
    configured = bool(found) or bool(own)
    for group in top + own:
        for line in lines:
            match = re.match(r"^set groups %s interfaces (\S+) (.*)$" % re.escape(group), line)
            if not match:
                continue
            target = match.group(1).strip('"')
            if target.startswith("<"):
                if (group in own or configured) and fnmatch.fnmatchcase(port, target[1:-1]):
                    found.append(match.group(2))
            elif target == port:
                found.append(match.group(2))
    return found


class FakeJunos:
    def __init__(self):
        self.firmware = FIRMWARE
        self.lines = BASELINE.rstrip("\n").split("\n")
        self.history = _history(fixture("show-system-commit__baseline.txt"))
        self.epoch = START_EPOCH
        self.uptime = 0.0
        self.timer = None
        self.rollback = None
        self.foreign_candidate = None
        self.foreign_editor = False
        self.commit_seconds = 60
        self.empty_commit_seconds = 15
        self.expiry_delay = 30
        self.rollback_seconds = 90
        self.permissions_missing = ()
        self.applied_blocks = []
        self.check_queries = []
        self.lldp_extra = []
        self.learned_macs = {}
        self.vlan_macs = {}
        self.check_unreadable = False
        # 1.0.12 G138: the ports with a link up, the PoE controller (vJunos has none) and the ports that power a device
        self.up_ports = {"ge-0/0/0", "ge-0/0/1"}
        self.poe_capable = False
        self.powered = set()
        self.poe_log = []
        self.check_override = None
        self.ssh_paths = []
        self.on_apply = None
        self.after_line = None
        self.broadcasts = []
        self.read_delay = 0
        self.credential = SimpleNamespace(login=LOGIN)
        # as access.DeviceAccess: asked before every line (execute.py sets it for the change session), called with the
        # number and the answer of every accepted line, and the answers of the last session
        self.line_guard = None
        self.line_sent = None
        self.line_answered = None
        self.last_answers = ()
        self.before_line = None

    # ---- clock, commit history and the timer ----
    def advance(self, seconds):
        self.epoch += seconds
        self.uptime += seconds
        self._fire()

    def _record(self, user, via, minutes=None, comment=None, pending=False, at=None):
        for item in self.history:
            item["pending"] = False
        self.history.insert(0, {"at": _stamp(self.epoch if at is None else at), "user": user, "via": via,
                                "minutes": minutes, "comment": comment, "pending": pending})

    def _fire(self):
        if self.timer is not None and self.rollback is None and self.epoch >= self.timer["expire"]:
            # measured: UI_COMMIT_NOT_CONFIRMED "automatic rollback in process", then a rollback commit of ~1-2 min
            self.rollback = {"done": self.timer["expire"] + self.rollback_seconds, "lines": self.timer["target"]}
            for item in self.history:
                item["pending"] = False
            self.timer = None
        if self.rollback is not None and self.epoch >= self.rollback["done"]:
            self.lines = list(self.rollback["lines"])
            self._record("root", "other", at=self.rollback["done"])
            self.broadcasts.append("Commit was not confirmed; automatic rollback complete.")
            self.rollback = None

    @property
    def hostname(self) -> str:
        """The committed host name: the prompt shows a new name right after its commit (measured, task-evidence/g145)."""
        return next((line.split()[3] for line in self.lines if line.startswith("set system host-name ")), HOSTNAME)

    def pending(self) -> bool:
        return self.timer is not None

    def interface(self, name) -> list:
        prefix = "set interfaces %s " % name
        return [line[len(prefix):] for line in self.lines if line.startswith(prefix)]

    def vlans(self) -> set:
        return {"default"} | {line.split()[2] for line in self.lines if line.startswith("set vlans ")}

    def snapshot(self):
        self._fire()
        return "\n".join(self.lines) + "\n"

    # ---- interactive session (access.apply) ----
    def apply(self, steps, spec):
        anchors = (spec.anchor,) + tuple(getattr(spec, "anchors", ()))
        # 1.0.12 G145: the anchor is "@<host name>", the part of the prompt after the account
        assert all(anchor.startswith(b"@") for anchor in anchors) and callable(spec.seconds)
        assert b"@" + self.hostname.encode("ascii") in anchors
        assert spec.seconds("commit comment \"x\"") >= 300 and spec.seconds("set interfaces x") >= 30
        self._fire()
        self.applied_blocks.append(list(steps))
        if self.on_apply is not None:
            self.on_apply(self, steps)
        assert steps[:1] == ["set cli screen-width 1024"], "a Junos session starts with the screen width"
        session = {"mode": "oper", "candidate": None}
        accepted = 0
        answers = []
        self.last_answers = answers
        guard, answered = self.line_guard, self.line_answered
        try:
            for number, step in enumerate(steps, 1):
                assert isinstance(step, str)
                if self.before_line is not None:
                    self.before_line(self, step)
                if guard is not None and not guard():
                    raise AccessError("line %d was not sent: the safeguard of the device has too little time left"
                                      % (accepted + 1), accepted)
                if self.line_sent is not None:
                    self.line_sent(number)
                answer = self._line(step, session)
                prompt = "%s@%s%s " % (LOGIN, self.hostname, ">" if session["mode"] == "oper" else "#")
                context = "" if session["mode"] == "oper" else "[edit]\n"
                banner = ("\n# commit confirmed will be rolled back in %d minutes\n" % self.timer["minutes"]
                          if self.timer is not None else "\n")
                text = "%s\n%s%s%s%s" % (step, answer, banner, context, prompt)
                if not any(anchor in prompt.encode("utf-8") for anchor in anchors):
                    # as access.DeviceAccess: the prompt of the answer carries no anchor, the session times out
                    raise AccessError("interactive session failed after %d lines: no prompt anchor in %r"
                                      % (accepted, prompt), accepted)
                answers.append(text)
                marker = spec.error(text)
                if marker is not None:
                    raise DeviceRefused(accepted, step, marker)
                accepted += 1
                if answered is not None:
                    answered(accepted, text)
                if self.after_line is not None:
                    self.after_line(self, step)
        finally:
            # the end of the connection leaves configure exclusive: its uncommitted changes are dropped
            if session["mode"] == "exclusive":
                self.foreign_candidate = None
        return accepted

    def _candidate(self, session):
        if session["candidate"] is None:
            session["candidate"] = list(self.foreign_candidate or self.lines)
        return session["candidate"]

    def _compare(self, candidate) -> str:
        removed = [line for line in self.lines if line not in candidate]
        added = [line for line in candidate if line not in self.lines]
        rows = ["-   %s;" % line for line in removed] + ["+   %s;" % line for line in added]
        return "[edit]\n" + "\n".join(rows) if rows else ""

    def _line(self, line, session) -> str:
        words = line.split()
        mode = session["mode"]
        if mode == "oper":
            if words == ["set", "cli", "screen-width", "1024"]:
                return "Screen width set to 1024"
            if words == ["configure"]:
                session["mode"] = "shared"
                if self.foreign_candidate is not None or self.foreign_editor:
                    return fixture("configure__foreign-exclusive-uncommitted-shared-candidate.txt")
                return "Entering configuration mode"
            if words == ["configure", "exclusive"]:
                session["mode"] = "exclusive"
                if self.foreign_editor:
                    return fixture("configure-exclusive__foreign-private-uncommitted.txt")
                return fixture("configure-exclusive__enter.txt")
            raise AssertionError("unexpected operational line %r" % line)
        if line in ("show | compare", "show | compare | no-more"):
            return self._compare(self._candidate(session))
        if words == ["exit", "configuration-mode"]:
            if mode == "exclusive":
                self.foreign_candidate = None
            session["mode"] = "oper"
            return "Exiting configuration mode"
        if words[:1] in (["set"], ["delete"]) and words[1:2] in (["interfaces"], ["vlans"], ["switch-options"], ["protocols"],
                                                                 ["groups"], ["apply-groups"], ["system"], ["poe"]):
            return self._edit(line, self._candidate(session))
        if words[:1] == ["rename"] and words[1:2] in (["vlans"], ["protocols"]):
            return self._rename(line, self._candidate(session))
        if words[:2] == ["commit", "confirmed"]:
            assert mode == "exclusive", "commit confirmed outside configure exclusive"
            match = re.fullmatch(r'commit confirmed ([0-9]+) comment "([^"]*)"', line)
            return self._commit(self._candidate(session), int(match.group(1)), match.group(2))
        if words[:1] == ["commit"] and words[1:2] == ["comment"]:
            assert mode == "exclusive", "commit outside configure exclusive"
            return self._commit(self._candidate(session), None, re.fullmatch(r'commit comment "([^"]*)"',
                                                                             line).group(1))
        if words == ["commit", "check"]:
            # measured: commit check confirms a pending commit confirmed without any trace
            self.timer = None
            for item in self.history:
                item["pending"] = False
            return "configuration check succeeds"
        raise AssertionError("unexpected configuration line %r" % line)

    def _edit(self, line, candidate) -> str:
        """set adds a statement (a single-valued leaf replaces its old value), delete removes a statement and all
        below it (measured: "warning: statement not found" when there is none)."""
        words = line.split()
        stored = "set " + line.split(" ", 1)[1]
        if words[0] == "set":
            rest = stored
            described = re.search(r" description (.*)$", rest)
            if described and not re.fullmatch(r'"[^"]*"|\S+', described.group(1)):
                return fixture("set-description-unquoted-spaces__syntax-error.txt").split("\n", 1)[0] + \
                    "\nsyntax error."
            if not any(pattern.fullmatch(rest) for pattern in SYNTAX):
                return fixture("set-bogus__syntax-error.txt")
            shown = _display(stored)
            single = SINGLE.match(shown)
            server = NTP_SERVER.match(shown)
            if server is not None:
                # measured: "prefer" is shown on the one line of the server; a bare set keeps it
                bare = "set system ntp server %s" % server.group(1)
                if server.group(2) is None and bare + " prefer" in candidate:
                    return ""
                if server.group(2) is not None and bare in candidate:
                    candidate[candidate.index(bare)] = shown
                    return ""
            if single is not None:
                # a single value is shown where the old one was (Junos shows the statements in schema order)
                same = [index for index, item in enumerate(candidate) if item.startswith(single.group(1) + " ")]
                if same:
                    candidate[same[0]] = shown
                    candidate[:] = [item for index, item in enumerate(candidate) if index not in same[1:]]
                    return ""
            toggle = re.fullmatch(r"set (interfaces \S+ ether-options) (?:no-)?auto-negotiation", shown)
            if toggle is not None:
                # measured (task-evidence/g138/znalost/s5-private.txt): the two statements replace each other
                candidate[:] = [item for item in candidate
                                if not re.fullmatch(r"set %s (?:no-)?auto-negotiation" % re.escape(toggle.group(1)), item)]
            if shown not in candidate:
                if shown.startswith("set interfaces ge-"):
                    _place(candidate, words[2], shown)
                else:
                    _place_other(candidate, shown)
            return ""
        target = stored
        server = NTP_SERVER.match(target)
        if server is not None and server.group(2) is not None:
            # measured: deleting "prefer" leaves the bare server line
            if target not in candidate:
                return "warning: statement not found"
            candidate[candidate.index(target)] = "set system ntp server %s" % server.group(1)
            return ""
        kept = [item for item in candidate if not (item == target or item.startswith(target + " "))]
        if len(kept) == len(candidate):
            return "warning: statement not found"
        candidate[:] = kept
        return ""

    def _rename(self, line, candidate) -> str:
        # d-vjunos requires the VLAN hierarchy keyword on both sides of an IGMP rename.
        match = re.fullmatch(r"rename (protocols igmp-snooping vlan) (\S+) to vlan (\S+)", line)
        if match is None:
            match = re.fullmatch(r"rename (vlans|protocols (?:mld-snooping|vstp) vlan) (\S+) to (\S+)", line)
        if match is None:
            return "syntax error, expecting <identifier>."
        path, prior, wanted = match.groups()
        old, new = "set %s %s" % (path, prior), "set %s %s" % (path, wanted)
        if any(item == new or item.startswith(new + " ") for item in candidate):
            return "error: target statement already exists"
        if not any(item == old or item.startswith(old + " ") for item in candidate):
            return "error: statement not found"
        candidate[:] = [new + item[len(old):] if item == old or item.startswith(old + " ") else item for item in candidate]
        return ""

    def _commit(self, candidate, minutes, comment) -> str:
        names = {"default"} | {line.split()[2] for line in candidate if line.startswith("set vlans ")}
        for line in candidate:
            match = (re.match(r"^set (?:groups \S+ )?interfaces (\S+(?: \S+)?) unit 0 family ethernet-switching vlan "
                              r"members (\S+)$", line)
                     or re.match(r"^set switch-options voip interface (\S+)\.0 vlan (\S+)$", line))
            if match and match.group(2) not in names:
                return fixture("commit-check__vlan-D3999-does-not-exist.txt").replace("ge-0/0/2", match.group(1)) \
                    .replace("D3999", match.group(2))
        changed = candidate != self.lines
        self.advance(self.commit_seconds if changed else self.empty_commit_seconds)
        if self.rollback is not None:
            # measured race: the commit that started before the expiry keeps the change ("automatic rollback failed
            # as other commit triggered during rollback")
            self.rollback = None
        before = list(self.lines)
        self.lines = list(candidate)
        self.foreign_candidate = None
        # measured in task 319: the commit row carries the end of the commit and the timer counts from it
        self._record(LOGIN, "cli", minutes, comment, pending=minutes is not None)
        if minutes is None:
            self.timer = None
            return "commit complete"
        # measured in task 378: the expiry returns the configuration before the NEWEST commit confirmed (after an
        # empty safeguard, a change and an inverse each committed with commit confirmed, the change came back), not
        # the configuration before the first one
        self.timer = {"minutes": minutes, "expire": self.epoch + minutes * 60 + self.expiry_delay, "target": before}
        return ("commit confirmed will be automatically rolled back in %d minutes unless confirmed\ncommit complete"
                % minutes)

    # ---- reads of the write account (ssh exec, status 0 even for an error) ----
    def history_text(self) -> str:
        rows = []
        for index, item in enumerate(self.history):
            suffix = " commit confirmed, rollback in %dmins" % item["minutes"] if item["minutes"] else ""
            rows.append("%-3d %s UTC by %s via %s%s" % (index, item["at"], item["user"], item["via"], suffix))
            if item["comment"]:
                rows.append("    " + item["comment"])
            if item["pending"]:
                rows.append("    rollback pending")
        text = "\n".join(rows) + "\n"
        if self.timer is not None:
            text += "\n# commit confirmed will be rolled back in %d minutes\n" % self.timer["minutes"]
        return text

    def version_text(self) -> str:
        """show version with the committed host name (measured: the check account sees a new name right after its
        commit, task-evidence/g145/live-l1)."""
        return (fixture("show-version-match__hostname-model-junos.txt").replace("26.2R1.7", self.firmware)
                .replace("Hostname: %s" % HOSTNAME, "Hostname: %s" % self.hostname)
                + "JUNOS OS Kernel 64-bit  [20260619.173755_builder_junos_262_r1]\n")

    def query(self, command):
        if self.read_delay:
            self.advance(self.read_delay)
        self._fire()
        if command == "show configuration | display set":
            return self.snapshot()
        match = re.fullmatch(r"show configuration interfaces (\S+) \| display inheritance \| display set", command)
        if match:
            return "".join("set interfaces %s %s\n" % (match.group(1), line)
                           for line in effective(self.lines, match.group(1))) + "\n"
        match = re.fullmatch(r"show configuration (system(?: [A-Za-z0-9:.-]+)*) \| display set", command)
        if match:
            # 1.0.12 G145: the scoped reads of task-evidence/g145/probe2 (only the lines of the stanza, empty if none)
            path = "set " + match.group(1)
            return "".join(line + "\n" for line in self.lines if line == path or line.startswith(path + " "))
        match = re.fullmatch(r"show configuration vlans (\S+) \| display set", command)
        if match:
            return "".join(line + "\n" for line in self.lines if line.startswith("set vlans %s " % match.group(1)))
        if command == "show system commit":
            return self.history_text()
        if command == "show system uptime | display json":
            data = json.loads(fixture("exec__show-system-uptime-json__rc0.json"))
            data["system-uptime-information"][0]["current-time"][0]["date-time"][0]["attributes"][
                "junos:seconds"] = str(int(self.epoch))
            return json.dumps(data, indent=4)
        if command == "show version":
            return self.version_text()
        if command == "show cli authorization":
            text = fixture("show-cli-authorization__admin-super-user.txt")
            for name in self.permissions_missing:
                text = re.sub(r"(?m)^    %s\s*--.*\n" % re.escape(name), "", text)
            return text
        if command == "show system users":
            text = fixture("show-system-users__admin-plus-console-ro.txt")
            return "\n".join(row for row in text.split("\n") if "pts/" not in row) + "\n"
        if command == 'show system connections | match "Local Address|ESTABLISHED" | no-more':
            return ("Proto Recv-Q Send-Q Local Address Foreign Address (state)\n"
                    + "".join("tcp4 0 0 %s.22 %s.55000 ESTABLISHED\n" % entry for entry in self.ssh_paths))
        match = re.fullmatch(r"show route (\S+)( exact)? \| display json", command)
        if match:
            return self._route_json(match[1], exact=bool(match[2]))
        if command == "show lldp neighbors":
            text = fixture("show-lldp-neighbors__baseline.txt")
            return text + "".join("%-19s-                   00:00:5e:00:53:%02x                        Gi0/9"
                                  "               host09\n" % (port, index + 10)
                                  for index, port in enumerate(self.lldp_extra))
        match = re.fullmatch(r"show vlans (\S+)", command)
        if match:
            name = match.group(1)
            if name not in self.vlans():
                return fixture("show-vlans-D3999__missing-empty.txt")
            return ("\nRouting instance        VLAN name             Tag          Interfaces\n"
                    "default-switch          %-21s %-8s \n" % (name, self.tag(name)))
        match = re.fullmatch(r"show ethernet-switching table interface (\S+)", command)
        if match:
            text = fixture("show-ethernet-switching-table-interface-ge-0-0-2__empty.txt").replace(
                "ge-0/0/2", match.group(1))
            count = self.learned_macs.get(match.group(1), 0)
            return text + "".join("   default             00:00:5e:00:53:%02x   D             -   %s.0\n"
                                  % (index + 40, match.group(1)) for index in range(count))
        answer = self._interface_query(command)
        if answer is not None:
            return answer
        raise AssertionError("unexpected query %r" % command)

    def _interface_query(self, command):
        if command == "show interfaces descriptions":
            rows = []
            for name in PORTS:
                described = [line for line in self.interface(name) if line.startswith("description ")]
                if described:
                    text = described[0][len("description "):].strip('"')
                    rows.append("%-15s %-5s %-4s %s" % (name, "down" if "disable" in self.interface(name) else "up",
                                                       "down", text))
            return ("Interface       Admin Link Description\n" + "\n".join(rows) + "\n") if rows else "\n"
        match = re.fullmatch(r"show interfaces (\S+) terse", command)
        if match:
            name = match.group(1)
            if name == "fxp0":
                return fixture("show-interfaces-fxp0-terse.txt")
            if name not in PORTS:
                return fixture("show-interfaces-em0-terse__not-found.txt").replace("em0", name)
            lines = self.interface(name)
            admin = "down" if "disable" in lines else "up"
            link = "up" if name in self.up_ports and admin == "up" else "down"
            text = "Interface               Admin Link Proto    Local                 Remote\n"
            text += "%-24s%-6s%s\n" % (name, admin, link)
            if any("ethernet-switching" in line for line in lines):
                text += "%-24s%-6s%s\n" % (name + ".0", "up", "down eth-switch")
            return text
        if command == "show interfaces terse":
            text = "Interface               Admin Link Proto    Local                 Remote\n"
            for name in PORTS:
                admin = "down" if "disable" in self.interface(name) else "up"
                text += "%-24s%-6s%s\n" % (name, admin, "up" if name in self.up_ports and admin == "up" else "down")
            return text + "".join("%-24s%-6s%-5s%-9s%s\n" % (name, "up", "up", family, address)
                                  for name, family, address in self._addresses())
        match = re.fullmatch(r"show interfaces (\S+)", command)
        if match and match[1] in PORTS:
            name = match[1]
            lines = self.interface(name)
            mtu = next((line.split()[1] for line in lines if line.startswith("mtu ")), "1514")
            # The measured default in s7-ro.txt is an operational rate, even with the link down.
            speed = next((line.split()[1] for line in lines if line.startswith("speed ")), "auto")
            speeds = {"10m": "10mbps", "100m": "100mbps", "1g": "1000mbps", "10g": "10Gbps", "auto": "1000mbps"}
            negotiation = "Disabled" if "ether-options no-auto-negotiation" in lines else "Enabled"
            text = fixture_g138("show-interfaces-ge-0-0-9-match-mtu__9000.txt").replace("ge-0/0/9", name)
            return (text.replace("MTU: 9000", "MTU: " + mtu).replace("Speed: 1000mbps", "Speed: " + speeds[speed])
                    .replace("Auto-negotiation: Enabled", "Auto-negotiation: " + negotiation))
        match = re.fullmatch(r"show poe interface (\S+)", command)
        if match:
            name = match.group(1)
            self.poe_log.append(name)
            if not self.poe_capable:
                return fixture_g138("show-poe-interface-ge-0-0-9__vjunos-no-controller.txt")
            disabled = "set poe interface %s disable" % name in self.lines
            on = name in self.powered and not disabled
            return ("PoE interface status:\nPoE interface                :  %s\nAdministrative status        : %s\n"
                    "Operational status           :  %s\nPower limit on the interface : 7.0W\nPriority                     : Low\n"
                    "Power consumed               : %s\nClass of power device        :   2\nPoE Mode                     : 802.3af\n"
                    % (name, "Disabled" if disabled else "Enabled", "Disabled" if disabled else "ON" if on else "OFF",
                       "5.3W" if on else "0.0W"))
        match = re.fullmatch(r"show ethernet-switching interface (\S+)", command)
        if match:
            rows = self.port_vlans(match.group(1))
            if rows is None:
                return fixture("show-ethernet-switching-interface-ge-0-0-2__unconfigured-empty.txt")
            template = fixture("show-ethernet-switching-interface-ge-0-0-2__access-default.txt").replace(
                "ge-0/0/2", match.group(1))
            head, _row = template.rstrip("\n").rsplit("\n", 1)
            return head + "\n" + "".join("default-switch                  %-22s %-5s 65535  1024   Discarding"
                                          "                   %s \n" % (vlan, self.tag(vlan), tagging)
                                          for vlan, tagging, _mode in rows)
        if command == "show vlans":
            text = "\nRouting instance        VLAN name             Tag          Interfaces\n"
            for name in sorted(self.vlans()):
                text += "default-switch          %-21s %-8s \n" % (name, self.tag(name))
                text += "".join("                                                           %s.0\n" % port
                                for port in PORTS if any(row[0] == name for row in self.port_vlans(port) or ()))
            return text
        match = re.fullmatch(r"show vlans (\S+) extensive", command)
        if match:
            name = match.group(1)
            if name not in self.vlans():
                return "\n"
            ports = [(port, row) for port in PORTS for row in self.port_vlans(port) or () if row[0] == name]
            text = fixture("show-vlans-g137-data-extensive__ro-access.txt").split("Interfaces:")[0]
            text = re.sub(r"VLAN Name: \S+\s+", "VLAN Name: %-23s" % name, text).replace("3901", self.tag(name))
            text += "Interfaces:\n" + "".join("    %s.0,%s,%s\n" % (port, row[1], row[2]) for port, row in ports)
            text += "Number of interfaces: Tagged %d    , Untagged %d    \nTotal MAC count: %d \n" % (
                sum(row[1] == "tagged" for _port, row in ports), sum(row[1] == "untagged" for _port, row in ports),
                self.vlan_macs.get(name, 0))
            return text
        return None

    def tag(self, name) -> str:
        if name == "default":
            return "1"
        return next(line.split()[-1] for line in self.lines if line.startswith("set vlans %s vlan-id " % name))

    def port_vlans(self, name):
        """(VLAN, tagging, mode) of the port as show ethernet-switching interface and show vlans extensive show them
        (measured in task-evidence/g137): an access port carries its member untagged and a voice VLAN tagged, a trunk
        its members tagged and the member that is the native VLAN untagged; a native VLAN that is no member is not
        shown at all. None for a port without ethernet-switching."""
        lines = effective(self.lines, name)
        if not any("ethernet-switching" in line for line in lines):
            return None
        mode = "trunk" if "unit 0 family ethernet-switching interface-mode trunk" in lines else "access"
        members = [line.split()[-1] for line in lines if line.startswith("unit 0 family ethernet-switching vlan "
                                                                         "members ")] or ["default"]
        native = [line.split()[-1] for line in lines if line.startswith("native-vlan-id ")]
        if mode == "access":
            rows = [(members[0], "untagged", "access")]
            voice = [line.split()[-1] for line in self.lines
                     if line.startswith("set switch-options voip interface %s.0 vlan " % name)]
            return rows + [(vlan, "tagged", "access") for vlan in voice]
        return [(vlan, "untagged" if native and self.tag(vlan) == native[0] else "tagged", "trunk")
                for vlan in members]

    # ---- reads of the check account (class read-only) ----
    def check_query(self, command):
        if self.read_delay:
            self.advance(self.read_delay)
        self._fire()
        self.check_queries.append(command)
        if self.check_unreadable:
            raise AccessError("check account unavailable")
        if self.check_override is not None and command in self.check_override:
            return self.check_override[command]
        if command == "show version":
            return self.version_text()
        if command == 'show system connections | match "Local Address|ESTABLISHED" | no-more':
            return self.query(command)
        answer = self._interface_query(command)
        if answer is None:
            raise AssertionError("unexpected check query %r" % command)
        return answer

    def _addresses(self):
        for line in self.lines:
            match = re.fullmatch(r"set interfaces (\S+) unit ([0-9]+) family (inet6?) address (\S+)", line)
            if match:
                yield match[1] + "." + match[2], match[3], match[4]

    def _route_json(self, destination, *, exact):
        """Simulate the measured Junos route RPC shape from the configured connected and static routes."""
        requested = ipaddress.ip_network(destination, strict=False)
        connected = [(ipaddress.ip_interface(address).network, name) for name, _, address in self._addresses()]
        routes = connected[:]
        for line in self.lines:
            match = re.fullmatch(r"set routing-options static route (\S+) next-hop (\S+)", line)
            if match:
                gateway = ipaddress.ip_address(match[2])
                routes.extend((ipaddress.ip_network(match[1]), name) for subnet, name in connected if gateway in subnet)
        matching = [(subnet, name) for subnet, name in routes if subnet.version == requested.version and (
            subnet == requested if exact else requested.subnet_of(subnet))]
        routes = {"attributes": {"xmlns": "http://xml.juniper.net/junos/26.2R0/junos-routing"}}
        if matching:
            subnet, name = max(matching, key=lambda item: item[0].prefixlen)
            routes["route-table"] = [{
                "table-name": [{"data": "inet.0" if subnet.version == 4 else "inet6.0"}],
                "rt": [{"rt-destination": [{"data": str(subnet)}],
                        "rt-entry": [{"active-tag": [{"data": "*"}], "nh": [{"via": [{"data": name}]}]}]}],
            }]
        return json.dumps({"route-information": [routes]}) + "\n"

    def state(self, name="ge-0/0/2") -> dict:
        return {"lines": self.interface(name), "timer": copy.deepcopy(self.timer), "newest": self.history[0]}
