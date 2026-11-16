"""Simulated Cisco Nexus 9000v with NX-OS 9.3(12) for netops-admin tests.

Every answer is built from an anonymised output measured on the lab node (fixtures/nxos_9_3_12, tasks
netops-provoz-20261116-314 and 317): the running configuration starts from the real baseline; the lines of the
changed interface, the scheduler job and schedule blocks, checkpoints, rollback, configure replace, the bootflash
file and copy running-config startup-config follow the measured behaviour (variant 3 of the timed return:
the checkpoint holds the job and the schedule; minute granularity of `time start +M`; the job rolls back ~3 s after
the minute and ends ~6 s later; deleting the schedule is refused with "schedule in progress" for a while after the
run; a job created after its checkpoint makes the rollback fail and stays stuck). Like DeviceAccess, apply keeps the
answers of its lines in ``last_answers``, asks ``line_guard`` (when set) before every line and calls
``line_answered`` (when set) after every accepted line; ``line_seconds`` lets every line take that long.
"""
from __future__ import annotations

import copy
import datetime
import re
from pathlib import Path
from types import SimpleNamespace

from netops_admin.access import AccessError

FIRMWARE = "9.3(12)"
HOSTNAME = "host05"
FIXTURES = Path(__file__).parent / "fixtures" / "nxos_9_3_12"
START = datetime.datetime(2026, 11, 16, 1, 4, 39)  # show clock of the measurement
JOB_START_SECONDS = 3
JOB_RUN_SECONDS = 6
SCHEDULE_BUSY_SECONDS = 120
HEADER = ("!Command:", "!Running configuration last done at:", "!Time:")


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def short(name: str) -> str:
    return name.replace("Ethernet", "Eth")


def stamp(moment) -> str:
    return moment.strftime("%a %b %d %H:%M:%S %Y")


class FakeNxos:
    def __init__(self):
        self.hostname = HOSTNAME
        self.firmware = FIRMWARE
        text = fixture("show-running-config__baseline.txt")
        self.body = [line.rstrip() for line in text.split("\n") if not line.startswith(HEADER)]
        while self.body and not self.body[0].strip():
            self.body.pop(0)
        while self.body and not self.body[-1].strip():
            self.body.pop()
        self.jobs, self.schedules = {}, {}
        self.saved = self._config()
        self.now = START
        self.uptime = 0.0
        self.scheduler_enabled = True
        self.checkpoints = {}
        self.checkpoint_times = {}
        self.files = {}
        self.logfile = []
        self.rollback_log = None
        self.stuck_jobs = set()
        self.config_sessions = []
        self.rollback_running = False
        self.applied_blocks = []
        self.check_queries = []
        self.queries = []
        self.lldp_extra = []
        self.learned_macs = {}
        self.trunk_extra = []
        self.foreign_users = []
        self.check_unreadable = False
        self.check_override = None
        self.refuse_replace = False
        self.time_shift_minutes = 0
        self.saves = 0
        self.saved_while_armed = 0
        self.replaces = 0
        self.on_apply = None
        self.on_line = None
        self.on_query = None
        self.on_fire = None
        self.clock_refused = False
        self.line_guard = None
        self.line_answered = None
        self.last_answers = ()
        self.line_seconds = 0
        self.unsent_lines = 0
        self.credential = SimpleNamespace(login="netops-admin")

    # ---- configuration state ----
    def _config(self):
        return {"body": list(self.body), "jobs": copy.deepcopy(self.jobs), "schedules": {
            name: {"job": item["job"], "time": item["time"]} for name, item in self.schedules.items()}}

    def _restore(self, state):
        self.body = list(state["body"])
        self.jobs = copy.deepcopy(state["jobs"])
        kept = {}
        for name, item in state["schedules"].items():
            current = self.schedules.get(name)
            kept[name] = current if current is not None else dict(item, executed=None, completed=None,
                                                                    status="-NA-")
            kept[name]["job"], kept[name]["time"] = item["job"], item["time"]
        self.schedules = kept

    def scheduler_lines(self) -> list:
        lines = []
        for name, steps in self.jobs.items():
            lines += ["scheduler job name %s" % name] + ["  " + step for step in steps] + ["  ", "end-job", ""]
        for name, item in self.schedules.items():
            lines.append("scheduler schedule name %s" % name)
            if item["job"]:
                lines.append("  job name %s" % item["job"])
            if item["time"] is not None:
                lines.append("  time start %s" % item["time"].strftime("%Y:%m:%d:%H:%M"))
            lines.append("")
        return lines

    def running(self) -> str:
        """show running-config as the ssh exec of the write account returns it (header, body, scheduler blocks)."""
        self._fire()
        body = list(self.body)
        if self.scheduler_enabled is False:
            body = [line for line in body if line != "feature scheduler"]
        lines = ["", "!Command: show running-config", "!Running configuration last done at: %s" % stamp(self.now),
                 "!Time: %s" % stamp(self.now), ""] + body + [""] + self.scheduler_lines()
        return "\n".join(lines) + "\n"

    snapshot = running

    def _block(self, header):
        start = self.body.index(header)
        end = start + 1
        while end < len(self.body) and self.body[end].startswith(" "):
            end += 1
        return start, end

    def interface(self, name) -> list:
        header = "interface %s" % name
        if header not in self.body:
            return None
        start, end = self._block(header)
        return [line.strip() for line in self.body[start + 1:end]]

    def _set(self, name, drop, add=None):
        start, end = self._block("interface %s" % name)
        children = [line for line in self.body[start + 1:end] if not drop.match(line.strip())]
        if add:
            children.append("  " + add)
        order = {"description": 0, "shutdown": 1, "switchport": 2}
        children.sort(key=lambda line: order.get(line.split()[0], 3))
        self.body[start + 1:end] = children

    def vlans(self) -> set:
        found = {"1"}
        for line in self.body:
            match = re.fullmatch(r"vlan ([0-9,]+)", line)
            if match:
                found |= set(match.group(1).split(","))
        return found

    def clean(self) -> bool:
        return not self.jobs and not self.schedules and not self.checkpoints and not self.files

    # ---- clock and the scheduler ----
    def advance(self, seconds):
        self.now += datetime.timedelta(seconds=seconds)
        self.uptime += seconds
        self._fire()

    def _fire(self):
        for name, item in list(self.schedules.items()):
            if item["time"] is None or item.get("executed") or self.now < item["time"]:
                continue
            item["executed"] = item["time"]
            item["completed"] = item["time"] + datetime.timedelta(seconds=JOB_START_SECONDS + JOB_RUN_SECONDS)
            steps = self.jobs.get(item["job"], [])
            output, status = [], "Success (0)"
            for step in steps:
                words = step.split()
                if words[:3] == ["rollback", "running-config", "checkpoint"]:
                    result = self._rollback(words[3], item["time"])
                    output.append(fixture("rollback-checkpoint-atomic__success.txt" if result else
                                          "rollback-checkpoint-atomic__failed-undo-scheduler-job.txt"))
                    if not result:
                        self.stuck_jobs.add(item["job"])
            item["status"] = status
            if self.on_fire is not None:
                self.on_fire(self, name)
            self.logfile.append(fixture("show-scheduler-logfile__v3-rollback-success.txt").replace(
                "netops-c6-5", name).replace("Mon Nov 16 01:27:09 2026", stamp(item["completed"])).replace(
                fixture("rollback-checkpoint-atomic__success.txt"), "".join(output)))

    def _rollback(self, name, when) -> bool:
        target = self.checkpoints.get(name)
        if target is None:
            return False
        if set(self.jobs) - set(target["jobs"]) or set(self.schedules) - set(target["schedules"]):
            # the rollback patch would delete a scheduler job; NX-OS fails and undoes the patch (variant 1)
            self.rollback_log = {"name": name, "status": "Failed", "start": when, "end": when}
            return False
        self._restore(target)
        start = when + datetime.timedelta(seconds=JOB_START_SECONDS)
        self.rollback_log = {"name": name, "status": "Success", "start": start,
                             "end": start + datetime.timedelta(seconds=JOB_RUN_SECONDS)}
        return True

    # ---- interactive session (access.apply) ----
    def apply(self, steps, spec):
        assert spec.anchor == ("\r%s" % self.hostname).encode("ascii")
        self._fire()
        self.applied_blocks.append(list(steps))
        if self.on_apply is not None:
            self.on_apply(self, steps)
        mode, accepted, answers = ["exec"], 0, []
        self.last_answers = answers
        guard, answered = self.line_guard, self.line_answered
        for number, step in enumerate(steps, 1):
            assert isinstance(step, str)
            if guard is not None and not guard():
                self.unsent_lines += 1
                raise AccessError("line %d was not sent: the safeguard of the device has too little time left"
                                  % number, accepted)
            if self.on_line is not None:
                self.on_line(self, step)
            answer = self._line(step, mode)
            answers.append("%s\n%s" % (step, answer))
            if self.line_seconds:
                self.advance(self.line_seconds)
            marker = spec.error("%s\n%s" % (step, answer))
            if marker is not None:
                raise AccessError("line %d was refused by the device: %s" % (number, marker), accepted)
            accepted += 1
            if answered is not None:
                answered(number, answers[-1])
        return accepted

    def _line(self, line, mode) -> str:
        words = line.split()
        current = mode[0]
        if current == "exec":
            return self._exec(words, mode)
        if words == ["end"]:
            mode[0] = "exec"
            return ""
        if current.startswith("job:"):
            name = current.split(":", 1)[1]
            if words == ["exit"]:
                mode[0] = "config"
                return ""
            if words[:3] == ["rollback", "running-config", "checkpoint"] and len(words) == 5:
                if words[3] not in self.checkpoints:
                    return fixture("scheduler-job-rollback__checkpoint-missing-invalid.txt")
                self.jobs[name].append(line.strip())
                return ""
            raise AssertionError("unexpected job line %r" % line)
        if current.startswith("schedule:"):
            name = current.split(":", 1)[1]
            if words == ["exit"]:
                mode[0] = "config"
                return ""
            if words[:2] == ["job", "name"] and len(words) == 3:
                self.schedules[name]["job"] = words[2]
                return ""
            if words[:2] == ["time", "start"] and re.fullmatch(r"\+[0-9]+", words[2]):
                minute = self.now.replace(second=0, microsecond=0)
                self.schedules[name]["time"] = minute + datetime.timedelta(
                    minutes=int(words[2][1:]) + self.time_shift_minutes)
                return ""
            raise AssertionError("unexpected schedule line %r" % line)
        if current.startswith("interface:"):
            return self._interface_line(current.split(":", 1)[1], words, line)
        return self._config_line(words, mode)

    def _config_line(self, words, mode) -> str:
        if words[:1] == ["interface"] and len(words) == 2:
            if self.interface(words[1]) is None:
                return fixture("interface-ethernet1-99__invalid-range.txt")
            mode[0] = "interface:" + words[1]
            return ""
        if words[:3] == ["scheduler", "job", "name"] and len(words) == 4:
            if not self.scheduler_enabled:
                return "% Invalid command at '^' marker."
            self.jobs.setdefault(words[3], [])
            mode[0] = "job:" + words[3]
            return ""
        if words[:3] == ["scheduler", "schedule", "name"] and len(words) == 4:
            self.schedules.setdefault(words[3], {"job": None, "time": None, "executed": None, "completed": None,
                                                 "status": "-NA-"})
            mode[0] = "schedule:" + words[3]
            return ""
        if words[:4] == ["no", "scheduler", "job", "name"] and len(words) == 5:
            name = words[4]
            running = any(item["job"] == name and item.get("executed") and self.now < item["completed"]
                          for item in self.schedules.values())
            if name in self.stuck_jobs or running:
                return fixture("no-scheduler-job__schedule-in-progress.txt")
            self.jobs.pop(name, None)
            return ""
        if words[:4] == ["no", "scheduler", "schedule", "name"] and len(words) == 5:
            item = self.schedules.get(words[4])
            if item is not None and item.get("executed") and self.now < item["completed"] + datetime.timedelta(
                    seconds=SCHEDULE_BUSY_SECONDS):
                return fixture("no-scheduler-schedule__schedule-in-progress.txt")
            self.schedules.pop(words[4], None)
            return ""
        raise AssertionError("unexpected configuration line %r" % " ".join(words))

    def _interface_line(self, name, words, line) -> str:
        if words[0] == "description" and len(words) >= 2:
            self._set(name, re.compile(r"^description "), line.strip())
        elif words == ["no", "description"]:
            self._set(name, re.compile(r"^description "))
        elif words == ["shutdown"]:
            self._set(name, re.compile(r"^shutdown$"), "shutdown")
        elif words == ["no", "shutdown"]:
            self._set(name, re.compile(r"^shutdown$"))
        elif words[:3] == ["switchport", "access", "vlan"] and len(words) == 4:
            if name.startswith("mgmt"):
                return fixture("switchport-access-vlan__mgmt0-invalid.txt")
            if 3968 <= int(words[3]) <= 4094:
                return fixture("switchport-access-vlan__3999-reserved.txt")
            self._set(name, re.compile(r"^switchport access vlan "),
                      None if words[3] == "1" else "switchport access vlan %s" % words[3])
        elif words == ["no", "switchport", "access", "vlan"]:
            self._set(name, re.compile(r"^switchport access vlan "))
        else:
            raise AssertionError("unexpected interface line %r" % line)
        return ""

    def _exec(self, words, mode) -> str:
        if words == ["configure", "terminal"]:
            mode[0] = "config"
            return ""
        if words[:1] == ["checkpoint"] and len(words) == 2:
            if words[1] in self.checkpoints:
                # not measured on the lab node; the simulation refuses a second checkpoint of the same name
                return "% Checkpoint %s already exists" % words[1]
            self.checkpoints[words[1]] = self._config()
            self.checkpoint_times[words[1]] = self.now
            return fixture("checkpoint__done.txt")
        if words[:2] == ["no", "checkpoint"] and len(words) == 3:
            if self.checkpoints.pop(words[2], None) is None:
                return "% Checkpoint %s does not exist" % words[2]
            self.checkpoint_times.pop(words[2], None)
            return fixture("no-checkpoint__done.txt")
        if words == ["copy", "running-config", "startup-config"]:
            if self.schedules:
                self.saved_while_armed += 1
            self.saved = self._config()
            self.saves += 1
            return fixture("copy-running-config-startup-config__ok.txt")
        if words[:2] == ["copy", "running-config"] and words[2].startswith("bootflash:"):
            self.files[words[2][len("bootflash:"):]] = self._config()
            return fixture("copy-running-config-bootflash__ok.txt")
        if words[:1] == ["delete"] and words[1].startswith("bootflash:") and words[2:] == ["no-prompt"]:
            if self.files.pop(words[1][len("bootflash:"):], None) is None:
                return "No such file or directory"
            return fixture("delete-bootflash-no-prompt__ok.txt")
        if words[:2] == ["configure", "replace"] and len(words) == 3:
            state = self.files.get(words[2][len("bootflash:"):])
            if state is None or self.refuse_replace:
                return "Configure replace failed. Use 'show config-replace log exec' to see reasons for failure"
            self._restore(state)
            self.replaces += 1
            return fixture("configure-replace__no-timeout-ok.txt")
        if words[:3] == ["rollback", "running-config", "checkpoint"] and len(words) == 5:
            if self._rollback(words[3], self.now):
                return fixture("rollback-checkpoint-atomic__success.txt")
            return fixture("rollback-checkpoint-atomic__failed-undo-scheduler-job.txt")
        raise AssertionError("unexpected exec line %r" % " ".join(words))

    # ---- reads of the write account ----
    def query(self, command):
        self._fire()
        self.queries.append(command)
        if self.on_query is not None:
            self.on_query(self, command)
        if command == "show clock" and self.clock_refused:
            return "% Invalid command at '^' marker."
        if command == "show running-config":
            return self.running()
        if command == "show version":
            return fixture("show-version.txt").replace("version 9.3(12)", "version " + self.firmware)
        if command == "show feature":
            return fixture("show-feature.txt").replace(
                "scheduler              1          disabled",
                "scheduler              1          %s" % ("enabled " if self.scheduler_enabled else "disabled"))
        if command == "show clock":
            return fixture("show-clock__utc-ntp-warning.txt").replace(
                "01:04:39.788 UTC Mon Nov 16 2026", self.now.strftime("%H:%M:%S.000 UTC %a %b %d %Y"))
        if command == "show running-config diff":
            return "" if self._config() == self.saved else fixture("show-running-config-diff__unsaved.txt")
        if command == "show configuration session summary":
            if not self.config_sessions:
                return fixture("show-configuration-session-summary__none.txt")
            return fixture("show-configuration-session-summary__one.txt").replace("netops-c6-s1",
                                                                                   self.config_sessions[0])
        if command == "show rollback log verify":
            if self.rollback_running:
                return "\n".join(line for line in fixture("show-rollback-log-verify__success.txt").split("\n")
                                 if not line.startswith("End Time"))
            if self.rollback_log is None:
                return fixture("show-rollback-log-exec__not-available.txt")
            return fixture("show-rollback-log-verify__success.txt")
        if command == "show rollback log exec":
            if self.rollback_log is None:
                return fixture("show-rollback-log-exec__not-available.txt")
            return fixture("show-rollback-log-exec__v3-job-success.txt").replace(
                "netops-c6-5", self.rollback_log["name"]).replace("Success", self.rollback_log["status"])
        if command == "show checkpoint summary user":
            return self._checkpoint_summary()
        if command == "show scheduler logfile":
            return "".join(self.logfile)
        if command == "dir bootflash:":
            rows = "".join("       4073    Nov 16 02:00:57 2026  %s\n" % name for name in sorted(self.files))
            return ("       4096    Nov 09 01:40:12 2026  .rpmstore/\n" + rows
                    + "      79457    Nov 09 01:41:02 2026  nxos.9.3.12.bin\n\n"
                    "Usage for bootflash://sup-local\n 1234567 bytes used\n 4287040 bytes free\n")
        match = re.fullmatch(r"show scheduler schedule name (\S+)", command)
        if match:
            return self._schedule_answer(match.group(1))
        match = re.fullmatch(r"show diff rollback-patch running-config checkpoint (\S+)", command)
        if match:
            target = self.checkpoints.get(match.group(1))
            if target is not None and target == self._config():
                return fixture("show-diff-rollback-patch-running-checkpoint__empty.txt")
            return fixture("show-diff-rollback-patch-running-checkpoint__with-scheduler.txt")
        if command == "show users":
            text = fixture("show-users.txt")
            for user in self.foreign_users:
                text += "%s pts/4        Nov 16 01:20   .         24400 (192.0.2.40) session=ssh\n" % user
            return text
        if command == "show interface trunk":
            text = fixture("show-interface-trunk__baseline.txt")
            for port in self.trunk_extra:
                text = text.replace("Eth1/1        1       trunking      --\n",
                                    "Eth1/1        1       trunking      --\n%-14s1       trunking      --\n" % port)
            return text
        if command == "show lldp neighbors":
            text = fixture("show-lldp-neighbors__baseline.txt")
            rows = "".join("host09.example.invalid\n                     %-16s120        BR          Ethernet9\n" % port
                           for port in self.lldp_extra)
            total = 1 + len(self.lldp_extra)
            return text.replace("Total entries displayed: 1", rows + "Total entries displayed: %d" % total)
        match = re.fullmatch(r"show mac address-table interface (\S+)", command)
        if match:
            count = self.learned_macs.get(match.group(1), 0)
            text = fixture("show-mac-address-table-interface-Eth1-48__empty.txt")
            return text + "".join("*   10     0000.5e00.53%02x   dynamic  0         F      F    %s\n"
                                  % (index, short(match.group(1))) for index in range(count))
        match = re.fullmatch(r"show vlan id ([0-9]+)", command)
        if match:
            vlan = match.group(1)
            if 3968 <= int(vlan) <= 4094:
                return fixture("show-vlan-id-3999__reserved.txt")
            if vlan not in self.vlans():
                return fixture("show-vlan-id-30__not-found.txt").replace("30", vlan)
            return fixture("show-vlan-id-10__baseline.txt").replace("10   D10 ", "%-4s %-3s " % (vlan, "D" + vlan), 1)
        answer = self._interface_query(command)
        if answer is not None:
            return answer
        raise AssertionError("unexpected query %r" % command)

    def query_status(self, command):
        """The exit status is not measured for NX-OS exec refusals; the simulation ends them with status 1, so the
        adapter must judge their text (query would raise on it)."""
        text = self.query(command)
        refused = text.lstrip().startswith(("Error:", "ERROR:", "VLAN ", "%"))
        return (1 if refused else 0), text

    def _checkpoint_summary(self) -> str:
        if not self.checkpoints:
            return fixture("show-checkpoint-summary-user__empty.txt")
        template = fixture("show-checkpoint-summary-user__one.txt")
        return "\n".join(template.replace("1) netops-c6-2:", "%d) %s:" % (number, name)).replace(
            "Created at Mon, 01:10:16 16 Nov 2026", "Created at %s" % self.checkpoint_times.get(name, START).strftime(
                "%a, %H:%M:%S %d %b %Y")).rstrip("\n") for number, name in enumerate(self.checkpoints, 1)) + "\n"

    def _schedule_answer(self, name) -> str:
        item = self.schedules.get(name)
        if item is None:
            return fixture("show-scheduler-schedule-name__not-found-after-v1-run.txt")
        when = item["time"] or self.now
        if not item.get("executed"):
            return fixture("show-scheduler-schedule-name__pending.txt").replace("netops-c6-2", name).replace(
                "Mon Nov 16 01:12:00 2026", stamp(when))
        text = fixture("show-scheduler-schedule__v3-fired-success.txt").replace("netops-c6-5", name)
        text = text.replace("Run once on Mon Nov 16 01:27:00 2026", "Run once on %s" % stamp(when))
        text = text.replace("Last Execution Time : Mon Nov 16 01:27:00 2026", "Last Execution Time : %s" % stamp(when))
        return text.replace("Mon Nov 16 01:27:09 2026", stamp(item["completed"]))

    def _interface_query(self, command):
        if command == "show interface description":
            text = fixture("show-interface-description__baseline.txt")
            start = next(line for line in text.split("\n") if line.startswith("Port ")).index("Description")
            out = []
            for row in text.split("\n"):
                words = row.split()
                name = "Ethernet" + words[0][3:] if words and words[0].startswith("Eth") else None
                lines = self.interface(name) if name else None
                if lines is not None:
                    description = next((line[len("description "):] for line in lines
                                        if line.startswith("description ")), "--")
                    row = row[:start] + description
                out.append(row)
            return "\n".join(out)
        match = re.fullmatch(r"show interface (\S+) (status|switchport)", command)
        if match is None:
            return None
        name, kind = match.groups()
        lines = self.interface(name)
        if lines is None:
            return "Invalid range at '^' marker.\n"
        description = next((line[len("description "):] for line in lines if line.startswith("description ")), "--")
        disabled = "shutdown" in lines
        vlan = next((line.split()[-1] for line in lines if line.startswith("switchport access vlan ")), "1")
        trunk = "switchport mode trunk" in lines or short(name) in self.trunk_extra
        if kind == "status":
            status = "disabled" if disabled else ("inactive" if vlan not in self.vlans() else "notconnec")
            row = "%-14s%-19s%-10s%-10sauto    auto    10g        " % (
                short(name), description[:18], status, "trunk" if trunk else vlan)
            return fixture("show-interface-Eth1-48-status__baseline.txt").replace(
                fixture("show-interface-Eth1-48-status__baseline.txt").rstrip("\n").split("\n")[-1], row)
        names = {"1": "default", "10": "D10", "20": "D20"}
        text = fixture("show-interface-Eth1-48-switchport__baseline.txt").replace("Name: Ethernet1/48", "Name: " + name)
        if trunk:
            text = text.replace("Operational Mode: access", "Operational Mode: trunk")
        return text.replace("Access Mode VLAN: 1 (default)", "Access Mode VLAN: %s (%s)" % (
            vlan, names.get(vlan, "Vlan not created")))

    # ---- reads of the check account (network-operator) ----
    def check_query(self, command):
        self._fire()
        self.check_queries.append(command)
        if self.check_unreadable:
            raise AccessError("check account unavailable")
        if self.check_override is not None and command in self.check_override:
            return self.check_override[command]
        if command.startswith("show running-config"):
            return fixture("ro__show-running-config-denied.txt")
        if command.startswith("show scheduler"):
            return fixture("ro__show-scheduler-denied.txt")
        answer = self._interface_query(command)
        if answer is None:
            raise AssertionError("unexpected check query %r" % command)
        return answer
