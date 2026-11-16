"""Simulated vJunos-switch 26.2R1.7 (ELS) for netops-admin tests.

Every answer is built from an anonymised output measured on vJunos-switch 26.2R1.7 (fixtures/junos_26_2R1_7, task
netops-provoz-20261116-308). The configuration starts from the reconstructed lab configuration; the candidate, the
commit history and the commit confirmed timer follow the measured behaviour: configure exclusive works on the shared
candidate and drops it at exit, every commit confirmed restarts the timer, commit check and a plain commit confirm it,
the timer expires 0-60 s after its minutes and the automatic rollback is committed as "root via other" a while later,
and a confirmation that starts before the expiry wins the race.
"""
from __future__ import annotations

import copy
import datetime
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


class FakeJunos:
    def __init__(self):
        self.hostname = HOSTNAME
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
        self.check_unreadable = False
        self.check_override = None
        self.on_apply = None
        self.after_line = None
        self.broadcasts = []
        self.read_delay = 0
        self.credential = SimpleNamespace(login=LOGIN)
        # as access.DeviceAccess: asked before every line (execute.py sets it for the change session), called with the
        # number and the answer of every accepted line, and the answers of the last session
        self.line_guard = None
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
        assert spec.anchor == self.hostname.encode("ascii") and callable(spec.seconds)
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
            for step in steps:
                assert isinstance(step, str)
                if self.before_line is not None:
                    self.before_line(self, step)
                if guard is not None and not guard():
                    raise AccessError("line %d was not sent: the safeguard of the device has too little time left"
                                      % (accepted + 1), accepted)
                answer = self._line(step, session)
                prompt = "%s@%s%s " % (LOGIN, self.hostname, ">" if session["mode"] == "oper" else "#")
                context = "" if session["mode"] == "oper" else "[edit]\n"
                banner = ("\n# commit confirmed will be rolled back in %d minutes\n" % self.timer["minutes"]
                          if self.timer is not None else "\n")
                text = "%s\n%s%s%s%s" % (step, answer, banner, context, prompt)
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
        if words[:2] in (["set", "interfaces"], ["delete", "interfaces"]):
            return self._edit(line, self._candidate(session))
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
        words = line.split()
        name = words[2]
        rest = line.split(" ", 3)[3] if len(words) > 3 else ""
        stored = "set interfaces %s %s" % (name, rest)
        if words[0] == "set":
            if rest.startswith("description ") and not re.fullmatch(r'description (?:"[^"]*"|\S+)', rest):
                return fixture("set-description-unquoted-spaces__syntax-error.txt").split("\n", 1)[0] + \
                    "\nsyntax error."
            if not (rest.startswith("description ") or rest == "disable"
                    or rest.startswith("unit 0 family ethernet-switching vlan members ")):
                return fixture("set-bogus__syntax-error.txt")
            shown = _display(stored)
            if rest.startswith("description "):
                candidate[:] = [item for item in candidate if not item.startswith("set interfaces %s description "
                                                                                  % name)]
            if shown not in candidate:
                _place(candidate, name, shown)
            return ""
        target = "set interfaces %s %s" % (name, rest)
        kept = [item for item in candidate if not (item == target or item.startswith(target + " "))]
        if len(kept) == len(candidate):
            return "warning: statement not found"
        candidate[:] = kept
        return ""

    def _commit(self, candidate, minutes, comment) -> str:
        for line in candidate:
            match = re.match(r"^set interfaces (\S+) unit 0 family ethernet-switching vlan members (\S+)$", line)
            if match and match.group(2) not in self.vlans():
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
        target = self.timer["target"] if self.timer is not None else before
        self.timer = {"minutes": minutes, "expire": self.epoch + minutes * 60 + self.expiry_delay, "target": target}
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

    def query(self, command):
        if self.read_delay:
            self.advance(self.read_delay)
        self._fire()
        if command == "show configuration | display set":
            return self.snapshot()
        if command == "show system commit":
            return self.history_text()
        if command == "show system uptime | display json":
            data = json.loads(fixture("exec__show-system-uptime-json__rc0.json"))
            data["system-uptime-information"][0]["current-time"][0]["date-time"][0]["attributes"][
                "junos:seconds"] = str(int(self.epoch))
            return json.dumps(data, indent=4)
        if command == "show version":
            return (fixture("show-version-match__hostname-model-junos.txt").replace("26.2R1.7", self.firmware)
                    + "JUNOS OS Kernel 64-bit  [20260619.173755_builder_junos_262_r1]\n")
        if command == "show cli authorization":
            text = fixture("show-cli-authorization__admin-super-user.txt")
            for name in self.permissions_missing:
                text = re.sub(r"(?m)^    %s\s*--.*\n" % re.escape(name), "", text)
            return text
        if command == "show system users":
            text = fixture("show-system-users__admin-plus-console-ro.txt")
            return "\n".join(row for row in text.split("\n") if "pts/" not in row) + "\n"
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
            tag = "1" if name == "default" else next(
                line.split()[-1] for line in self.lines if line.startswith("set vlans %s vlan-id " % name))
            return ("\nRouting instance        VLAN name             Tag          Interfaces\n"
                    "default-switch          %-21s %-8s \n" % (name, tag))
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
            text = "Interface               Admin Link Proto    Local                 Remote\n"
            text += "%-24s%-6s%s\n" % (name, admin, "down")
            if any("ethernet-switching" in line for line in lines):
                text += "%-24s%-6s%s\n" % (name + ".0", "up", "down eth-switch")
            return text
        match = re.fullmatch(r"show ethernet-switching interface (\S+)", command)
        if match:
            name = match.group(1)
            lines = self.interface(name)
            members = [line.split()[-1] for line in lines if line.startswith("unit 0 family ethernet-switching vlan "
                                                                             "members ")]
            if not any("ethernet-switching" in line for line in lines):
                return fixture("show-ethernet-switching-interface-ge-0-0-2__unconfigured-empty.txt")
            trunk = "unit 0 family ethernet-switching interface-mode trunk" in lines
            template = fixture("show-ethernet-switching-interface-ge-0-0-2__access-default.txt").replace(
                "ge-0/0/2", name)
            head, row = template.rstrip("\n").rsplit("\n", 1)
            rows = []
            for vlan in members or ["default"]:
                tag = "1" if vlan == "default" else next(
                    item.split()[-1] for item in self.lines if item.startswith("set vlans %s vlan-id " % vlan))
                rows.append(("default-switch                  %-22s %-5s 65535  1024   Discarding                   %s "
                             % (vlan, tag, "tagged" if trunk else "untagged")))
            return head + "\n" + "\n".join(rows) + "\n"
        return None

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
        answer = self._interface_query(command)
        if answer is None:
            raise AssertionError("unexpected check query %r" % command)
        return answer

    def state(self, name="ge-0/0/2") -> dict:
        return {"lines": self.interface(name), "timer": copy.deepcopy(self.timer), "newest": self.history[0]}
