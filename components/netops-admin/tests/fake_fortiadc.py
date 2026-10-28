from __future__ import annotations

import re
from types import SimpleNamespace


class DeviceRefused(Exception):
    def __init__(self, accepted_lines=0):
        super().__init__("refused")
        self.accepted_lines = accepted_lines


def _name(token):
    return token.strip('"')


class FakeFortiADC:
    def __init__(self, hostname="adc-lab"):
        self.hostname = hostname
        self.pools = {
            "pool-a": {1: {"real-server": "rs-1", "status": "enable", "weight": "1"},
                       2: {"real-server": "rs-2", "status": "disable", "weight": "5"},
                       3: {"real-server": "rs-3", "status": "maintain", "weight": "1"}},
            "pool-b": {1: {"real-server": "rs-4", "status": "enable", "weight": "9"}},
        }
        self.credential = SimpleNamespace(login="netops-rw")
        self.show_default = False
        self.unreadable = False
        self.unreadable_after_apply = False
        self.refuse_apply = set()
        self.fail_after_write = set()
        self.coerce = {}
        self.ignore_writes = False
        self.garbage = None
        self.garbage_after_apply = None
        self.queries = []
        self.applied_blocks = []
        self.specs = []

    def query(self, command):
        self.queries.append(command)
        if self.unreadable or (self.unreadable_after_apply and self.applied_blocks):
            raise RuntimeError("device unavailable")
        if command == "get system status":
            return ("Version: FortiADC-KVM v7.6.7,build0676,260101 (GA)\nHostname: %s\n"
                    "Serial-Number: FADCVM0000000000\n" % self.hostname)
        match = re.fullmatch(r"show load-balance pool (\S+)", command)
        assert match, command
        if self.garbage_after_apply is not None and self.applied_blocks:
            return self.garbage_after_apply
        if self.garbage is not None:
            return self.garbage
        pool = self.pools.get(match.group(1))
        if pool is None:
            return "entry is not found in table\n"
        lines = ["config load-balance pool", '    edit "%s"' % match.group(1), "        config pool_member"]
        for number, member in pool.items():
            lines.append("            edit %d" % number)
            lines.append('                set real-server "%s"' % member["real-server"])
            if member["status"] != "enable" or self.show_default:
                lines.append("                set status %s" % member["status"])
            lines.append("                set weight %s" % member["weight"])
            lines.append("            next")
        lines += ["        end", "    next", "end"]
        return "\n".join(lines) + "\n"

    def apply(self, steps, spec):
        self.specs.append(spec)
        assert all(isinstance(step, str) for step in steps)
        self.applied_blocks.append(list(steps))
        if len(self.applied_blocks) in self.refuse_apply:
            raise DeviceRefused(0)
        stack, current = [], {}
        pending = []
        for raw in steps:
            tokens = raw.split()
            command = tokens[0]
            if command == "config":
                stack.append(" ".join(tokens[1:]))
            elif command == "edit":
                stack.append("edit " + _name(" ".join(tokens[1:])))
            elif command in ("next", "end"):
                stack.pop()
            elif command == "set":
                pending.append((tuple(stack), tokens[1], " ".join(tokens[2:])))
            else:
                raise DeviceRefused(len(pending))
        assert not stack, "unbalanced block"
        for path, key, value in pending:
            if len(path) != 4 or path[0] != "load-balance pool" or path[2] != "pool_member":
                raise DeviceRefused(0)
            pool = self.pools[path[1].split(" ", 1)[1]]
            member = pool[int(path[3].split(" ", 1)[1])]
            if self.ignore_writes:
                continue
            member[key] = self.coerce.get(value, value)
        if len(self.applied_blocks) in self.fail_after_write:
            raise DeviceRefused(len(steps))
        return len(steps)
