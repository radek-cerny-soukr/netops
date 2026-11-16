"""A FortiADC simulated for the common Admin engine (Runtime): the pool member device of fake_fortiadc plus the
listings the Admin snapshot is composed of and the check account reads (show, get system status)."""
from __future__ import annotations

import re
from pathlib import Path

from fake_fortiadc import FakeFortiADC, VS_STAT, CHECK_ACCOUNT_REFUSAL

from netops_admin import exec_fortiadc

FIXTURES = Path(__file__).with_name("fixtures") / "fortiadc_767_0676"
PROMPT = "FortiADC-KVM # "


def measured(name: str) -> str:
    return (FIXTURES / name).read_bytes().decode("utf-8")


class FakeADC(FakeFortiADC):
    def __init__(self, hostname="adc-lab"):
        super().__init__(hostname)
        self.check_refuses_show = False
        self.check_unreadable = False
        self.snapshots = 0
        self.fail_snapshot_after = None
        self.status_text = None
        # True: answers carry the prompts the device prints around them (DeviceAccess removes only the first one);
        # False: answers as the earlier pool-member tests saw them
        self.prompts = True

    def snapshot(self):
        self.snapshots += 1
        if self.fail_snapshot_after is not None and self.snapshots > self.fail_snapshot_after:
            raise RuntimeError("device unavailable")
        return exec_fortiadc.snapshot(self)

    def _pool_lines(self, name, pool):
        lines = ['    edit "%s"' % name, "        config pool_member"]
        for number, member in pool.items():
            lines.append("            edit %d" % number)
            lines.append('                set real-server "%s"' % member["real-server"])
            if member.get("status", "enable") != "enable" or self.show_default:
                lines.append("                set status %s" % member.get("status", "enable"))
            for key, value in member.items():
                if key not in ("real-server", "status"):
                    lines.append("                set %s %s" % (key, value))
            lines.append("            next")
        return lines + ["        end", "    next"]

    def query(self, command):
        if command == "show load-balance pool":
            self.queries.append(command)
            if self.unreadable or (self.unreadable_after_apply and self.applied_blocks):
                raise RuntimeError("device unavailable")
            lines = ["config load-balance pool"]
            for name, pool in self.pools.items():
                lines += self._pool_lines(name, pool)
            return (PROMPT if self.prompts else "") + self._paged(lines + ["end"])
        if command == "show system admin":
            self.queries.append(command)
            lines = ["config system admin"]
            for login, fields in self.admins.items():
                lines.append('  edit "%s"' % login)
                lines += ["    set %s %s" % item for item in fields.items()]
                lines += ["    set password ENC dGVzdC1vbmx5", "    config  gui-dashboard", "      edit 1",
                          "        set name Main", "      next", "    end", "  next"]
            return PROMPT + "\n".join(lines + ["end"]) + "\n\n" + PROMPT
        if command == "get system status" and self.status_text is not None:
            self.queries.append(command)
            return self.status_text
        answer = super().query(command)
        if command.startswith("show ") and self.prompts:
            # the device prints its prompt before the listing, once or twice (measured 7.6.7 build0676)
            return PROMPT + PROMPT + answer + "\n" + PROMPT
        return answer

    def apply(self, steps, spec):
        known = {(pool, number) for pool, members in self.pools.items() for number in members}
        try:
            return super().apply(steps, spec)
        finally:
            for pool, members in self.pools.items():
                for number, member in members.items():
                    if (pool, number) not in known:
                        # a new member without a cookie gets rsN (measured 7.6.7 build0676, task 306)
                        member.setdefault("pool_member_cookie", "rs%d" % number)

    def check_query(self, command):
        self.check_queries.append(command)
        if VS_STAT.fullmatch(command):
            return CHECK_ACCOUNT_REFUSAL
        if self.check_unreadable:
            raise RuntimeError("check account unavailable")
        if self.check_refuses_show:
            return "Command fail. Return code is -284 (CLI parsing error.)\n"
        if command == "get system status":
            return super().query(command)
        assert re.fullmatch(r"show load-balance pool \S+", command), command
        return PROMPT + FakeFortiADC.query(self, command) + "\n" + PROMPT
