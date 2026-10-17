import random
import re
import time
import unittest

from netops_helper import engine, proxy_sanitize, sanitize, schema_read
from netops_admin import exos, membership
from netops_auditor import l1_exos, l1_fortios, management

SEED = 20261015


def corpus(fragments, count=3000, length=30):
    generator = random.Random(SEED)
    return ["".join(generator.choice(fragments) for _ in range(generator.randrange(0, length))) for _ in range(count)]


def scales_linearly(test, build, run, small=2000):
    def elapsed(size):
        value = build(size)
        start = time.perf_counter()
        run(value)
        return time.perf_counter() - start
    first, second = elapsed(small), elapsed(small * 4)
    test.assertLess(second, max(first, 0.005) * 8, (first, second))


def keep(match):
    return match.group(1) + "<REDACTED>"


OLD_CISCO_USER = re.compile(r"(?im)^(\s*username\s+\S+\s+(?:password|secret)(?:\s+\d+)?\s+)\S+")
OLD_SNMP_CLI = re.compile(r'(?im)^(\s*(?:snmp-server\s+community|set\s+community)\s+)(?:"[^"\r\n]*"|\S+)')
OLD_CISCO_SECRET = re.compile(r"(?im)^(\s*(?:enable\s+)?(?:secret|password)(?:\s+\d+)?\s+)\S+")
OLD_VDOM = re.compile(r"(?m)^Current virtual domain:[ \t]*([^\r\n]+?)[ \t]*$")
OLD_VLAN_DESCRIPTION = re.compile(r"^\s*Description:\s*(.*?)\s*$", re.MULTILINE)
OLD_SESSION_ROW = re.compile(r"^\s*(\*?)\d+\s+\w{3} \w{3} +\d", re.MULTILINE)
OLD_MODE_ROW = re.compile(r"\s+(Untagged|Tagged)\s+(.*?)\s*")
OLD_PORT_ROW = re.compile(r"\s*(\S+)\s+(Untagged|Tagged)\s+(.*?)\s*")
WHITE = ("\n", "\n", " ", "  ", "\t", "\r", "\x0b", "\x0c", "\u00a0", "\u2028")


def old_pty_body(data, command, prompt):
    text = data.decode("utf-8", "replace").replace("\r", "")
    marker = prompt.decode("ascii")
    if text.endswith(marker):
        text = text[: -len(marker)]
    lines = text.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].strip() == command:
        lines.pop(0)
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def old_upm_listing_complete(text, kind):
    count = re.search(r"^\s*Number of UPM %s:\s*(\d{1,9})\s*$" % kind, text, re.MULTILINE)
    if count is None:
        return False
    lines = text.splitlines()
    separators = [index for index, line in enumerate(lines) if exos.UPM_SEPARATOR.fullmatch(line)]
    rows = [line for line in lines[separators[1] + 1:separators[2]] if line.strip()] if len(separators) >= 3 else []
    declared = int(count.group(1))
    return not rows if declared == 0 else len(rows) >= declared


def old_line(line):
    row = OLD_MODE_ROW.fullmatch(line)
    if row:
        return None, row[1], row[2]
    row = OLD_PORT_ROW.fullmatch(line)
    if row:
        return row[1], row[2], row[3]
    row = membership.NAME_LINE.fullmatch(line)
    if row and set(row[1]) != {"-"}:
        return row[1], None, None
    return None, None, None


def old_cyclic_edges(graph):
    edges = {key: members & graph.keys() for key, members in graph.items()}
    reverse = {key: set() for key in graph}
    for key, members in edges.items():
        for member in members:
            reverse[member].add(key)
    seen, order = set(), []
    for key in edges:
        if key in seen:
            continue
        stack = [(key, False)]
        while stack:
            node, finishing = stack.pop()
            if finishing:
                order.append(node)
            elif node not in seen:
                seen.add(node)
                stack.append((node, True))
                stack.extend((child, False) for child in edges[node] if child not in seen)
    components = {}
    for key in reversed(order):
        if key in components:
            continue
        pending = [key]
        while pending:
            node = pending.pop()
            if node in components:
                continue
            components[node] = key
            pending.extend(reverse[node] - components.keys())
    return {(key, member) for key, members in edges.items() for member in members
            if components[key] == components[member]}


def old_dhcp_conflicts(tree):
    found = []
    for sid, server in management.entries(tree, "system dhcp server").items():
        if server.value("status", "enable") == "disable":
            continue
        reservations = management.entries(server, "reserved-address")
        active = [(key, node) for key, node in reservations.items()
                  if node.value("action", "reserved") == "reserved" and node.value("type", "mac") == "mac"]
        for key, node in active:
            for other_key, other in active:
                if key >= other_key:
                    continue
                same_ip = node.value("ip") and node.value("ip") == other.value("ip")
                mac = re.sub("[:-]", "", node.value("mac", "")).lower()
                other_mac = re.sub("[:-]", "", other.value("mac", "")).lower()
                if same_ip or (mac and mac == other_mac):
                    found.append("system dhcp server/" + sid + "/reserved-address/" + key + "/conflict/" + other_key)
    return found


def hits(name, text):
    return [hit for hit in management._fortios(name, l1_fortios.parse(text), {})]


def path_of(hit):
    return hit["object_key"]


class SameResult(unittest.TestCase):
    def test_helper_secret_redaction_matches_the_previous_expressions(self):
        fragments = WHITE + ("username ", "admin ", "password ", "secret ", "enable ", "5 ", "7 ", "x", "!",
                             "snmp-server community ", "set community ", '"pub lic" ', "USERNAME ", "Secret ")
        for text in corpus(fragments):
            with self.subTest(text=text[:60]):
                self.assertEqual(sanitize.CISCO_USER_SECRET.sub(keep, text), OLD_CISCO_USER.sub(keep, text))
                self.assertEqual(sanitize.SNMP_CLI_SECRET.sub(keep, text), OLD_SNMP_CLI.sub(keep, text))
                self.assertEqual(proxy_sanitize.CISCO_SECRET.sub(keep, text), OLD_CISCO_SECRET.sub(keep, text))

    def test_current_vdom_matches_the_previous_expression(self):
        fragments = WHITE + ("Current virtual domain:", "root", "x", "\r\n", "vd 1")
        for text in corpus(fragments):
            with self.subTest(text=text[:60]):
                self.assertEqual([value.strip() for value in schema_read.CURRENT_VDOM.findall(text)],
                                 [value.strip() for value in OLD_VDOM.findall(text)])

    def test_pty_body_matches_the_previous_function(self):
        fragments = ("\n", "\r\n", " ", "\t", "show x", "line", "#", "prompt#")
        for text in corpus(fragments):
            data = text.encode()
            with self.subTest(text=text[:60]):
                self.assertEqual(engine._pty_body(data, "show x", b"prompt#"), old_pty_body(data, "show x", b"prompt#"))

    def test_exos_parsers_match_the_previous_expressions(self):
        separator = "=" * 40
        fragments = WHITE + ("Number of UPM profiles:", "Number of UPM events:", " 2", " 0", "3", "\n" + separator + "\n",
                             "Description:", "None", "text", "*", "1 ", "12 ", "Thu Oct ", "15", "x")
        for text in corpus(fragments, length=40):
            with self.subTest(text=text[:60]):
                for kind in ("profiles", "events"):
                    self.assertEqual(exos.upm_listing_complete(text, kind), old_upm_listing_complete(text, kind))
                new, old = exos.VLAN_DESCRIPTION.search(text), OLD_VLAN_DESCRIPTION.search(text)
                self.assertEqual(None if new is None else new.group(1).rstrip(), None if old is None else old.group(1))
                self.assertEqual(exos.SESSION_ROW.findall(text), OLD_SESSION_ROW.findall(text))

    def test_membership_lines_match_the_previous_expressions(self):
        fragments = (" ", "  ", "\t", "\u00a0", "Untagged", "Tagged", "1:1", "v10", ",", "-", "x", "!", "Default")
        continuation = re.compile(r"\s+[A-Za-z][A-Za-z0-9_, -]*\s*")
        for line in corpus(fragments):
            with self.subTest(line=line[:60]):
                self.assertEqual(membership._line(line), old_line(line))
                self.assertEqual(bool(re.fullmatch(r"\s+[A-Za-z][A-Za-z0-9_, -]*", line.rstrip())),
                                 bool(continuation.fullmatch(line)))

    def test_group_cycle_edges_match_the_previous_function(self):
        generator = random.Random(SEED)
        for _ in range(300):
            names = ["g%d" % index for index in range(generator.randrange(1, 12))]
            graph = {name: {generator.choice(names) for _ in range(generator.randrange(0, 4))} for name in names}
            with self.subTest(graph=graph):
                self.assertEqual(management._cyclic_edges(graph), old_cyclic_edges(graph))

    def test_dhcp_conflicts_match_the_previous_pairs_in_order(self):
        generator = random.Random(SEED)
        for _ in range(200):
            rows = []
            for index in range(generator.randrange(0, 9)):
                rows.append(" edit %d\n set ip 192.0.2.%d\n set mac 00:00:5e:00:53:%02d\n%s next\n" % (
                    index + 1, generator.randrange(1, 4), generator.randrange(0, 3),
                    generator.choice(["", " set action block\n", " set type option82\n"])))
            text = ("config system dhcp server\n edit 1\n config reserved-address\n" + "".join(rows) +
                    " end\n next\nend\n")
            with self.subTest(text=text):
                self.assertEqual([path_of(hit) for hit in hits("dhcp-conflict", text)],
                                 old_dhcp_conflicts(l1_fortios.parse(text)))

    def test_exos_modules_keep_their_first_order(self):
        generator = random.Random(SEED)
        for _ in range(200):
            names = [generator.choice(["vlan", "fdb", "stp", "upm"]) for _ in range(generator.randrange(0, 12))]
            text = "".join("#\n# Module %s configuration.\n#\n" % name for name in names)
            with self.subTest(names=names):
                self.assertEqual(list(l1_exos.parse(text).modules), list(dict.fromkeys(names)))


class DefaultRendering(unittest.TestCase):
    def snapshot_and_command(self, inventory, value):
        from types import SimpleNamespace
        snapshot = SimpleNamespace(inventory=frozenset(inventory))
        command = SimpleNamespace(tokens=membership.DEFAULT_ROUTER + ("add", "ports", value))
        return snapshot, command

    def test_matches_the_previous_set_copy(self):
        generator = random.Random(SEED)
        for _ in range(500):
            inventory = {"1:%d" % generator.randrange(1, 9) for _ in range(generator.randrange(1, 6))}
            value = ",".join(sorted({"1:%d" % generator.randrange(1, 9) for _ in range(generator.randrange(1, 6))}))
            snapshot, command = self.snapshot_and_command(inventory, value)
            with self.subTest(inventory=inventory, value=value):
                self.assertEqual(membership._default_rendering(snapshot, command),
                                 membership.ports(value) == set(snapshot.inventory))

    def test_does_not_copy_the_inventory_per_command(self):
        def build(size):
            snapshot, command = self.snapshot_and_command(("1:%d" % number for number in range(1, size + 1)), "1:1")
            return snapshot, [command] * size
        scales_linearly(self, build, lambda value: [membership._default_rendering(value[0], item) for item in value[1]],
                        small=1000)


class LinearTime(unittest.TestCase):
    def test_blank_lines_do_not_slow_secret_redaction(self):
        for pattern in (sanitize.CISCO_USER_SECRET, sanitize.SNMP_CLI_SECRET, proxy_sanitize.CISCO_SECRET):
            with self.subTest(pattern=pattern.pattern):
                scales_linearly(self, lambda size: "\n" * size, lambda text: pattern.sub(keep, text), small=3000)

    def test_inner_spaces_do_not_slow_the_vdom_line(self):
        scales_linearly(self, lambda size: "Current virtual domain:a" + " " * size + "b\r\n",
                        lambda text: schema_read.CURRENT_VDOM.findall(text), small=3000)

    def test_blank_lines_and_spaces_do_not_slow_exos_parsers(self):
        scales_linearly(self, lambda size: "\n" * size, lambda text: exos.upm_listing_complete(text, "profiles"), small=3000)
        scales_linearly(self, lambda size: "\n" * size, lambda text: exos.SESSION_ROW.findall(text), small=3000)
        scales_linearly(self, lambda size: "\n" * size + "Description: a" + " " * size + "b",
                        lambda text: exos.VLAN_DESCRIPTION.search(text), small=3000)

    def test_spaces_do_not_slow_membership_rows(self):
        scales_linearly(self, lambda size: " Untagged a" + " " * size + "b!", membership._line, small=3000)
        scales_linearly(self, lambda size: " a" + " " * size + "!",
                        lambda line: re.fullmatch(r"\s+[A-Za-z][A-Za-z0-9_, -]*", line.rstrip()), small=3000)

    def test_many_blank_leading_lines_do_not_slow_the_pty_body(self):
        scales_linearly(self, lambda size: b"\n" * size + b"show x\nline\n", lambda data: engine._pty_body(data, "show x", b"#"),
                        small=20000)

    def test_many_groups_and_reservations_scale_linearly(self):
        def groups(size):
            return ("config firewall addrgrp\n" + "".join(' edit "g%d"\n set member "x%d"\n next\n' % (index, index)
                                                          for index in range(size)) + "end\n")
        scales_linearly(self, groups, lambda text: hits("group-dangling", text), small=1000)
        def chain(size):
            return ("config firewall addrgrp\n" + "".join(' edit "g%d"\n set member "g%d"\n next\n' % (index, index + 1)
                                                          for index in range(size)) + "end\n")
        scales_linearly(self, chain, lambda text: hits("group-cycle", text), small=1000)
        def reservations(size):
            return ("config system dhcp server\n edit 1\n config reserved-address\n" +
                    "".join(" edit %d\n set mac 00:00:5e:00:%02x:%02x\n next\n"
                            % (index + 1, index // 256 % 256, index % 256) for index in range(size)) +
                    " end\n next\nend\n")
        scales_linearly(self, reservations, lambda text: hits("dhcp-conflict", text), small=250)


if __name__ == "__main__":
    unittest.main()
