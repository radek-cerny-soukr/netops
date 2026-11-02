from __future__ import annotations

import re
from types import SimpleNamespace


VS_STAT = re.compile(r"diagnose server-load-balance vs_stat vdom root vs (\S+)")
CHECK_ACCOUNT_REFUSAL = ("Parsing error at 'server-load-balance'\n"
                         "Command fail. Return code is -284 (CLI parsing error.)\n")


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
            "pool-a": {1: {"real-server": "rs-1", "status": "enable", "pool_member_weight": "1"},
                       2: {"real-server": "rs-2", "status": "disable", "pool_member_weight": "5"},
                       3: {"real-server": "rs-3", "status": "maintain", "pool_member_weight": "1"},
                       4: {"real-server": "rs-5", "status": "enable", "pool_member_weight": "1"}},
            "pool-b": {1: {"real-server": "rs-4", "status": "enable", "pool_member_weight": "9"}},
        }
        self.credential = SimpleNamespace(login="netops-rw")
        self.real_servers = ["rs-1", "rs-2", "rs-3", "rs-4", "rs-5", "rs-new"]
        self.virtual_servers = {"vs-a": {"load-balance-pool": "pool-a"}, "vs-b": {"load-balance-pool": "pool-b"}}
        self.health = {"vs-a": {1: "UP", 2: "UP", 3: "UP", 4: "UP"}, "vs-b": {1: "UP"}}
        self.vs_stat_text = None
        self.vs_stat_error = False
        self.check_queries = []
        self.show_default = False
        self.unreadable = False
        self.unreadable_after_apply = False
        self.refuse_apply = set()
        self.fail_after_write = set()
        self.coerce = {}
        self.ignore_writes = False
        self.garbage = None
        self.pager_at = None
        self.garbage_after_apply = None
        self.queries = []
        self.applied_blocks = []
        self.specs = []
        self.check_credential = SimpleNamespace(login="netops-check")
        self.admins = {"netops-rw": {"is-system-admin": "yes", "access-profile": "super_admin_prof"},
                       "netops-check": {"access-profile": "netops-read"}}
        self.access_profiles = {"netops-read": {"system": "read", "load-balance": "read", "log": "read",
                                                "link-load-balance": "read", "global-load-balance": "read",
                                                "security": "read"}}
        self.rights_answers = {}
        self.rights_queries = []

    def check_query(self, command):
        self.check_queries.append(command)
        assert VS_STAT.fullmatch(command), command
        return CHECK_ACCOUNT_REFUSAL

    def diagnose_query(self, command):
        vs_stat = VS_STAT.fullmatch(command)
        assert vs_stat, command
        self.queries.append(command)
        if self.unreadable or (self.unreadable_after_apply and self.applied_blocks):
            raise RuntimeError("device unavailable")
        return self._vs_stat(vs_stat.group(1))

    def _vs_stat(self, name):
        if self.vs_stat_error:
            raise RuntimeError("vs_stat unavailable")
        if self.vs_stat_text is not None:
            return self.vs_stat_text
        lines = ["vdom name is root", "\tvirtual-server: %s, availability:HEALTHY" % name, "\t\tRequests: 0",
                 "\t\treal-server-pool: %s" % self.virtual_servers[name].get("load-balance-pool", "")]
        for number, state in self.health[name].items():
            lines.append("\t\tid:%d, hc_state: %s, last-state-change-time: 2026-10-30 00:48:28" % (number, state))
            lines.append("\t\t\tRequests: 0")
        return "\n".join(lines) + "\n"

    def _paged(self, lines):
        if self.pager_at is not None and len(lines) > self.pager_at:
            lines = lines[:self.pager_at] + ["--More-- \r         \r" + lines[self.pager_at]] + lines[self.pager_at + 1:]
        return "\n".join(lines) + "\n"

    def query(self, command):
        self.queries.append(command)
        if self.unreadable or (self.unreadable_after_apply and self.applied_blocks):
            raise RuntimeError("device unavailable")
        if VS_STAT.fullmatch(command):
            return ""
        if command == "show load-balance real-server":
            lines = ["config load-balance real-server"]
            for name in self.real_servers:
                lines += ['    edit "%s"' % name, "        set ip 192.0.2.1", "    next"]
            return "\n".join(lines + ["end"]) + "\n"
        if command == "get system status":
            return ("Version: FortiADC-KVM v7.6.7,build0676,260101 (GA)\nHostname: %s\n"
                    "Serial-Number: FADCVM0000000000\n" % self.hostname)
        if command == "show load-balance virtual-server":
            lines = ["config load-balance virtual-server"]
            for name, attributes in self.virtual_servers.items():
                lines.append('    edit "%s"' % name)
                lines += ["        set %s %s" % (key, value) for key, value in attributes.items()]
                lines.append("    next")
            return self._paged(lines + ["end"])
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
            if "pool_member_service_port" in member:
                lines.append("                set pool_member_service_port %s" % member["pool_member_service_port"])
            if member["status"] != "enable" or self.show_default:
                lines.append("                set status %s" % member["status"])
            for key, value in member.items():
                if key not in ("real-server", "pool_member_service_port", "status"):
                    lines.append("                set %s %s" % (key, value))
            lines.append("            next")
        lines += ["        end", "    next", "end"]
        return self._paged(lines)

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
                pending.append(("set", tuple(stack), tokens[1], _name(" ".join(tokens[2:]))))
            elif command == "delete":
                pending.append(("delete", tuple(stack), tokens[1], None))
            else:
                raise DeviceRefused(len(pending))
        assert not stack, "unbalanced block"
        for action, path, key, value in pending:
            if action == "delete":
                if path != ("load-balance pool", "edit " + path[1].split(" ", 1)[1], "pool_member") or key not in map(str, self.pools[path[1].split(" ", 1)[1]]):
                    raise DeviceRefused(0)
                if not self.ignore_writes:
                    del self.pools[path[1].split(" ", 1)[1]][int(key)]
                continue
            if len(path) != 4 or path[0] != "load-balance pool" or path[2] != "pool_member":
                raise DeviceRefused(0)
            pool = self.pools[path[1].split(" ", 1)[1]]
            number = int(path[3].split(" ", 1)[1])
            if self.ignore_writes:
                continue
            member = pool.setdefault(number, {"status": "enable"})
            member[key] = self.coerce.get(value, value)
        if len(self.applied_blocks) in self.fail_after_write:
            raise DeviceRefused(len(steps))
        return len(steps)

    def own_query(self, command, check=False):
        login = (self.check_credential if check else self.credential).login
        self.rights_queries.append((login, command))
        if self.unreadable:
            raise RuntimeError("device unavailable")
        if command in self.rights_answers:
            return self.rights_answers[command]
        admin = re.fullmatch(r'show system admin "(.+)"', command)
        if admin is not None:
            assert admin.group(1) == login, command
            fields = self.admins.get(login)
            if fields is None:
                return "entry not found\n"
            return ('config system admin\n  edit "%s"\n    set vdom root\n'
                    '    set trusted-hosts 192.0.2.9/32 ::1/128\n' % login
                    + "".join("    set %s %s\n" % item for item in fields.items())
                    + "    set password ENC c2VjcmV0LWhhc2g=\n    config gui-dashboard\n      edit 1\n"
                      "        set name dashboard\n      next\n    end\n  next\nend\n")
        profile = re.fullmatch(r'show system accprofile "(.+)"', command)
        assert profile is not None and check, command
        areas = self.access_profiles.get(profile.group(1))
        if areas is None:
            return "config system accprofile\nend\n"
        return ('config system accprofile\n  edit "%s"\n' % profile.group(1)
                + "".join("    set %s %s\n" % item for item in areas.items()) + "  next\nend\n")
