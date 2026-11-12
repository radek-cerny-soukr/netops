#!/usr/bin/env python3
"""Deterministic anonymiser for real device output stored as test fixtures.

Replaces what identifies a site while keeping what a parser needs:

* MAC addresses (colon, dash, Cisco dotted, 8-octet bridge ids, bare hex that is
  a known MAC) -> 00:00:5e:00:53:NN (RFC 7042 documentation range) in the spelling and
  case of the original; at most 255 distinct addresses per mapping.
  Group/well-known addresses (01-80-c2-.., ff-ff-.., 00-e0-2b-00-00-00) stay.
* IPv4 -> RFC 5737 documentation space only. The first three /24s seen map to
  192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 and keep the host octet, so
  subnets, gateways (.1) and "address belongs to prefix" relations survive. An address of
  any further /24 gets its own free documentation address (its subnet relation is not kept);
  a documentation address is never given to two inputs (ValueError instead).
  Masks, 0.0.0.0, loopback, multicast and software versions stay.
* IPv6 -> 2001:db8:<net>::<n> (link-local fe80::<n>); multicast stays. A host part below 0x10000 is kept
  unless another address already took it in the same output prefix; every other host part is numbered
  from 0x10, so two different input addresses never share one output address.
* serial numbers (labelled ones and Extreme/Cisco shaped ones, plus explicit).
* host names / sysName / SysLocation / LLDP system names / EXOS prompts, SSIDs, user names and
  optionally port descriptions (explicit literals plus labelled values). A host name that equals the
  switch model is still a host name in these fields (SysName, System Name, the LLDP summary name
  column, the prompt) and is replaced there; the model stays in System Type and in hardware
  descriptions.

Every replacement keeps the column alignment: when the new text has another
length, the spaces after it are widened or narrowed (never below one space).

Mapping is by order of first appearance, so the same input set in the same
order always gives the same output. The mapping object holds the real values;
keep a saved ``--map`` file outside the repository and never commit it.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

DOC_NETS = ("192.0.2", "198.51.100", "203.0.113")
DOC_MAC = "00005e0053"
KEEP_MACS = {"000000000000", "ffffffffffff", "00e02b000000", "00e02b000001", "00e02b000002"}
VERSION_CONTEXT = re.compile(
    r"(?i)\b(?:version|ver|release|build|rev|revision|bootrom|boot|img|image|fw|firmware|loader|rom)\b[^0-9\n]{0,24}$")
LABEL_VALUES = {
    # label regex -> kind of the labelled value
    r"SysName": "name", r"SysLocation": "name", r"System Name": "name", r"Host ?name": "name",
    r"SSID": "ssid", r"Serial(?: ?Number| ?No\.?)?": "serial", r"S/N": "serial", r"SN": "serial",
    r"Chassis Serial(?: Number)?": "serial",
}

PLACEHOLDER = re.compile(r"host\d{2}|port-desc-\d{2}|user\d{2}|ssid\d{2}")
NAME_LABELS = tuple(label for label, kind in LABEL_VALUES.items() if kind == "name")
_B = r"(?<![0-9A-Za-z_])"
_A = r"(?![0-9A-Za-z_])"
MAC_COLON = r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:])"
MAC_DASH = r"(?<![0-9A-Fa-f-])[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f-])"
MAC_DOT = r"(?<![0-9A-Fa-f.])[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}(?![0-9A-Fa-f.])"
BRIDGE8 = r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){7}(?![0-9A-Fa-f:])"
HEXDUMP = r"(?P<hexdump_lead>HEX Dump \[[0-9A-Fa-f]+\]:[ \t]*)(?P<hexdump_bytes>(?:[0-9A-Fa-f]{2}[ \t]?)+)"
HEX16 = _B + r"[0-9A-Fa-f]{16}" + _A
HEX12 = _B + r"[0-9A-Fa-f]{12}" + _A
IPV4 = r"(?<![0-9A-Za-z_.])\d{1,3}(?:\.\d{1,3}){3}(?![0-9A-Za-z_]|\.\d)"
IPV6 = r"(?<![0-9A-Za-z_:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[A-Za-z0-9_.-]+)?(?![0-9A-Za-z_:.])"
# EXOS prompt "[* ]<host name>.<n> # ": the host name is replaced even when it equals the model
EXOS_PROMPT = r"(?:^|(?<=\* ))[A-Za-z0-9][\w-]*(?=\.\d+ [#>](?:[ \t]|$))"
SERIAL_SHAPES = (r"\b\d{4}[A-Z]-\d{5}\b", r"\b\d{4}[A-Z]\d-\d{5}\b", r"\b[A-Z]{3}\d{4}[A-Z0-9]{4}\b")


def _fit(old: str, new: str, tail: str) -> tuple[str, int]:
    """Return the replacement plus how many following spaces to drop or add."""
    spaces = len(tail) - len(tail.lstrip(" "))
    if spaces == 0 or len(old) == len(new):
        return new, 0
    if len(new) < len(old):
        return new + " " * (len(old) - len(new)), 0
    drop = min(len(new) - len(old), spaces - 1)
    return new, drop


class Anonymizer:
    def __init__(self, names=(), serials=(), ssids=(), users=(), descriptions=(), keep=(), harvest=True):
        self.harvest = harvest
        self.models: set[str] = set()
        self.maps = {key: {} for key in ("mac", "ipv4net", "ipv4host", "ipv6net", "ipv6", "name", "serial", "ssid", "user",
                                          "desc")}
        self.keep = {str(item) for item in keep}
        self.literals = {"name": list(names), "serial": list(serials), "ssid": list(ssids),
                         "user": list(users), "desc": list(descriptions)}
        self._regex = None
        self._known_macs: set[str] = set()
        self._ipv6_used: dict[str, set[int]] = {}
        self._ipv4_seen: set[str] = set()          # host addresses of the primed text
        self._ipv4_used: dict[str, str] = {}       # documentation address -> the input that holds it

    # -- state ---------------------------------------------------------------
    def dump(self) -> dict:
        return {key: value for key, value in self.maps.items()}

    def load(self, data: dict) -> None:
        for key, value in data.items():
            if key in self.maps:
                self.maps[key].update(value)
        self._check_ipv4_map()
        self._check_ipv6_map()

    def _check_ipv4_map(self) -> None:
        """A loaded map must stay in the documentation ranges and must not send two addresses to one output."""
        if any(value not in DOC_NETS for value in self.maps["ipv4net"].values()) or \
                len(set(self.maps["ipv4net"].values())) != len(self.maps["ipv4net"]):
            raise ValueError("IPv4 mapping uses a network outside the documentation ranges or uses one twice")
        used = {}
        for key, value in self.maps["ipv4host"].items():
            if value.rsplit(".", 1)[0] not in DOC_NETS or value in used:
                raise ValueError("IPv4 mapping is ambiguous or leaves the documentation ranges")
            used[value] = key
        self._ipv4_used = used

    def _ipv6_prefix(self, key: str) -> str:
        if key.startswith("ll:"):
            return "fe80::"
        net = str(int(ipaddress.IPv6Address(key)) >> 64)
        if net not in self.maps["ipv6net"]:
            raise ValueError("IPv6 mapping refers to a network that is not in the map")
        return f"2001:db8:{self.maps['ipv6net'][net]:x}::"

    def _check_ipv6_map(self) -> None:
        """A loaded map must not send two different addresses to one output address."""
        used: dict[str, set[int]] = {}
        for key, value in self.maps["ipv6"].items():
            taken = used.setdefault(self._ipv6_prefix(key), set())
            if value in taken:
                raise ValueError("IPv6 mapping is ambiguous: two addresses share one output address")
            taken.add(value)
        self._ipv6_used = used

    def add(self, kind: str, *values: str) -> None:
        for value in values:
            if PLACEHOLDER.fullmatch(value or ""):
                continue                                        # already a placeholder
            if value and value not in self.literals[kind]:
                self.literals[kind].append(value)
        self._regex = None

    # -- replacement values --------------------------------------------------
    def _mac(self, digits: str) -> str:
        table = self.maps["mac"]
        if digits not in table:
            number = len(table) + 1
            if number > 0xFF:
                raise ValueError("too many distinct MAC addresses for the 00:00:5e:00:53:NN documentation range")
            table[digits] = f"{DOC_MAC}{number:02x}"
        return table[digits]

    def _claim(self, output: str, address: str) -> str:
        holder = self._ipv4_used.setdefault(output, address)
        if holder != address:
            raise ValueError("two IPv4 addresses would share one documentation address; anonymise all files in one run")
        return output

    def _ipv4(self, address: str) -> str:
        net, host = address.rsplit(".", 1)
        table = self.maps["ipv4net"]
        if net not in table and address not in self.maps["ipv4host"] and len(table) < len(DOC_NETS):
            table[net] = DOC_NETS[len(table)]
        if net in table:
            return self._claim(f"{table[net]}.{host}", address)
        hosts = self.maps["ipv4host"]
        if address not in hosts:
            hosts[address] = self._claim(self._free_ipv4(), address)
        return hosts[address]

    def _free_ipv4(self) -> str:
        """A documentation address that no mapped or primed address of a whole /24 holds, from the top down."""
        mapped = {doc: net for net, doc in self.maps["ipv4net"].items()}
        for doc in reversed(DOC_NETS):
            for host in range(254, 0, -1):
                output = f"{doc}.{host}"
                if output in self._ipv4_used or (doc in mapped and f"{mapped[doc]}.{host}" in self._ipv4_seen):
                    continue
                if doc not in mapped and len(mapped) < len(DOC_NETS):
                    continue                                # still free for a whole /24
                return output
        raise ValueError("no free IPv4 documentation address is left")

    def _ipv6(self, text: str) -> str:
        scope = ""
        if "%" in text:
            text, scope = text.split("%", 1)
            scope = "%" + scope
        address = ipaddress.IPv6Address(text)
        if address.is_multicast or address.is_unspecified or address.is_loopback:
            return text + scope
        packed = int(address)
        low = packed & ((1 << 64) - 1)
        if address.is_link_local:
            prefix = "fe80::"
            key = "ll:" + str(address)
        else:
            net = str(packed >> 64)
            nets = self.maps["ipv6net"]
            if net not in nets:
                nets[net] = len(nets) + 1
            prefix = f"2001:db8:{nets[net]:x}::"
            key = str(address)
        table = self.maps["ipv6"]
        if key not in table:
            used = self._ipv6_used.setdefault(prefix, set())
            value = low if low <= 0xFFFF and not address.is_link_local and low not in used else None
            if value is None:
                value = 0x10
                while value in used:
                    value += 1
            table[key] = value
            used.add(value)
        return prefix + f"{table[key]:x}" + scope

    def _word(self, kind: str, value: str, pattern: str) -> str:
        table = self.maps[kind]
        key = value.lower() if kind in ("name", "user", "ssid") else value
        if key not in table:
            if kind == "serial":
                digits = iter(str(len(table) + 1).zfill(sum(c.isdigit() for c in value)))
                # letters become S, digits count up: length and shape are kept
                table[key] = "".join(next(digits, "0") if c.isdigit() else "S" if c.isalpha() else c for c in value)
            else:
                table[key] = pattern.format(len(table) + 1)
        return table[key]

    # -- scanning ------------------------------------------------------------
    def _alternation(self, kind, cut=False):
        values = {v for v in self.literals[kind] if v and v.lower() not in self.models}
        if cut:       # EXOS cuts a long display string and marks it: "Uplink-S>"
            values = {v[:k] + ">" for v in values for k in range(1, len(v))}
        return "|".join(re.escape(v) for v in sorted(values, key=len, reverse=True))

    def _compile(self):
        parts = [("bridge8", BRIDGE8), ("mac_colon", MAC_COLON), ("mac_dash", MAC_DASH), ("mac_dot", MAC_DOT),
                 ("hex16", HEX16), ("hex12", HEX12), ("ipv6", IPV6), ("ipv4", IPV4)]
        parts.append(("hexdump", HEXDUMP))
        parts.append(("label", r"(?P<lead>(?<![A-Za-z0-9])(?:" + "|".join(LABEL_VALUES) + r")[ \t]*[:=][ \t]*\"?)(?P<lval>[^\"\r\n]*?)(?=\"?[ \t]*(?:\r?\n|$))"))
        for kind in ("serial", "name", "ssid", "user", "desc"):
            alternation = self._alternation(kind)
            if alternation:
                parts.append((kind, r"(?<![A-Za-z0-9_-])(?i:" + alternation + r")(?![A-Za-z0-9_-])"))
        cut = self._alternation("desc", cut=True)
        if cut:       # a cut display string is glued to the next column: "Uplink-S>VR-Default"
            parts.append(("cut", r"(?<![A-Za-z0-9_-])(?:" + cut + ")"))
        parts.append(("prompt", EXOS_PROMPT))
        parts.append(("shape", "|".join(SERIAL_SHAPES)))
        self._regex = re.compile("|".join(f"(?P<{name}>{pattern})" if name not in ("label",) else pattern
                                          for name, pattern in parts), re.MULTILINE)
        self._label_kinds = {re.compile(label, re.I): kind for label, kind in LABEL_VALUES.items()}

    def prime(self, text: str) -> None:
        """Learn MACs (for bare-hex forms), version numbers (kept as they are) and the IPv4 host addresses."""
        for match in re.finditer(IPV4, text):
            self._ipv4_seen.add(match[0])
        for pattern in (MAC_COLON, MAC_DASH, MAC_DOT):
            for match in re.finditer(pattern, text):
                self._known_macs.add(re.sub(r"[:.\-]", "", match[0]).lower())
        for match in re.finditer(r"(?i)\b(?:version|ver|release|build|bootrom|img|fw|firmware|rom|loader)\b[^0-9\n]{0,24}(\d+(?:\.\d+){3})", text):
            self.keep.add(match[1])
        for match in re.finditer(r"(?mi)^[ \t]*System Type[ \t]*:[ \t]*(\S+)[ \t]*$", text):
            self.models.add(match[1].lower())       # a host named like its model: the model stays readable
        for match in re.finditer(r"(?m)^[ \t]*SysName[ \t]*:[ \t]*(\S.*?)[ \t]*$", text):
            self.add("name", match[1])
        for match in re.finditer(r"(?m)^[a-z][\w.-]*[ \t]+(\d+(?:\.\d+){3})[ \t]+\d+[ \t]+\w", text):
            self.keep.add(match[1])                 # show process: the Version column
        if self.harvest:
            self._harvest(text)

    @staticmethod
    def _ios_hostnames(text: str):
        """The uptime subject names a host only in IOS/IOS XE identity output."""
        if re.search(r"(?m)^Cisco IOS(?: XE)? Software\b", text):
            for match in re.finditer(r"(?m)^(\S+)[ \t]+uptime is[ \t]+.+$", text):
                yield match[1]

    def _harvest(self, text: str) -> None:
        """Names, users and port labels that the output itself identifies as such (EXOS layouts)."""
        for match in re.finditer(r'(?m)^[ \t]*-?[ \t]*System Name[ \t]*:[ \t]*"?([^"\r\n]+?)"?[ \t]*$', text):
            self.add("name", match[1])
        for name in self._ios_hostnames(text):
            self.add("name", name)
        lines = text.splitlines()
        for number, line in enumerate(lines):
            if re.search(r"\bSystem Name\s*$", line) and number + 2 < len(lines):      # LLDP summary table
                column = line.rindex("System Name")
                for row in lines[number + 2:]:
                    if row.startswith("="):
                        break
                    if len(row) > column and row[column:].strip():
                        self.add("name", row[column:].strip())
            if re.match(r"\s*Port\s+Display String\s+Description String", line):         # show ports description
                column = line.index("Display String")
                for row in lines[number + 2:]:
                    if row.startswith("="):
                        break
                    value = row[column:column + 20].strip()
                    if value:
                        self.add("desc", value)
            if re.search(r"\bUser\s+Type\s+Auth\b", line):                               # show session
                for row in lines[number + 2:]:
                    parts = row.split()
                    if len(parts) > 6 and not row.startswith("="):
                        self.add("user", parts[6])
        for match in re.finditer(r"(?m)^\d\d/\d\d/\d{4} [\d:.]+ <[^>]*> .*?(?:\buser |\baccount \()([A-Za-z0-9_.-]{2,32})", text):
            self.add("user", match[1])                                             # show log lines
        for match in re.finditer(r"(?m)^\d+\s+(\S+)\s+(?:[0-9A-Fa-f]{2}:){7}[0-9A-Fa-f]{2}\s+\S+\s+\d+\s+\d+\s*$", text):
            self.add("name", match[1])                                             # show edp neighbor column

    # -- the substitution ----------------------------------------------------
    def _replace(self, match: re.Match, text: str):
        kind = match.lastgroup
        old = match[0]
        if kind in ("mac_colon", "mac_dash", "mac_dot"):
            digits = re.sub(r"[:.\-]", "", old).lower()
            if digits in KEEP_MACS or int(digits[:2], 16) & 1:
                return old
            new = self._format_mac(self._mac(digits), old)
        elif kind == "bridge8":
            octets = old.split(":")
            digits = "".join(octets[2:]).lower()
            if digits in KEEP_MACS:
                return old
            new = ":".join(octets[:2]) + ":" + self._format_mac(self._mac(digits), old.split(":", 2)[2])
        elif kind == "hex16":
            if old[4:].lower() not in self._known_macs:
                return old
            new = old[:4] + self._format_mac(self._mac(old[4:].lower()), old[4:])
        elif kind == "hex12":
            if old.lower() in KEEP_MACS or not (old.lower() in self._known_macs or (
                    any(c.isdigit() for c in old) and any(c.isalpha() for c in old))):
                return old
            new = self._format_mac(self._mac(old.lower()), old)
        elif kind == "ipv4":
            octets = [int(part) for part in old.split(".")]
            if any(part > 255 for part in octets) or any(len(p) > 1 and p.startswith("0") for p in old.split(".")):
                return old
            if old in self.keep or self._not_host(octets, old, text, match.start()):
                return old
            new = self._ipv4(old)
        elif kind == "ipv6":
            try:
                ipaddress.IPv6Address(old.split("%")[0])
            except ValueError:
                return old
            new = self._ipv6(old)
        elif kind == "shape":
            new = self._word("serial", old, "")
        else:
            pattern = {"name": "host{:02d}", "prompt": "host{:02d}", "ssid": "ssid{:02d}", "user": "user{:02d}",
                       "desc": "port-desc-{:02d}", "serial": "", "cut": ""}[kind]
            kind = "name" if kind == "prompt" else kind
            if kind == "cut":
                full = next(v for v in self.literals["desc"] if v.startswith(old[:-1]))
                new = self._word("desc", full, "port-desc-{:02d}")[:len(old) - 1] + ">"
            else:
                new = self._word(kind, old, pattern)
        return new

    @staticmethod
    def _format_mac(digits: str, original: str) -> str:
        upper = any(c in "ABCDEF" for c in original) and not any(c in "abcdef" for c in original)
        digits = digits.upper() if upper else digits
        if ":" in original:
            return ":".join(digits[i:i + 2] for i in range(0, 12, 2))
        if "-" in original:
            return "-".join(digits[i:i + 2] for i in range(0, 12, 2))
        if "." in original:
            return ".".join(digits[i:i + 4] for i in range(0, 12, 4))
        return digits

    @staticmethod
    def _not_host(octets, old, text, start) -> bool:
        value = int.from_bytes(bytes(octets), "big")
        if value == 0 or octets[0] == 127 or 224 <= octets[0] <= 239:
            return True                                              # unspecified, loopback, multicast
        inverse = (~value) & 0xFFFFFFFF
        if value >> 31 and inverse & (inverse + 1) == 0:             # netmask 255.255.x.x, broadcast
            return True
        if value & (value + 1) == 0:                                 # wildcard mask 0.0.0.255
            return True
        return bool(VERSION_CONTEXT.search(text[max(0, start - 40):start]))

    @staticmethod
    def _summary_name_cells(text: str):
        """(line index, start, end) of each cell in the System Name column of an LLDP summary table."""
        lines = text.splitlines()
        for number, line in enumerate(lines):
            if re.search(r"\bSystem Name\s*$", line):
                column = line.rindex("System Name")
                for index in range(number + 2, len(lines)):
                    row = lines[index]
                    if row.startswith("="):
                        break
                    if len(row) > column and row[column:].strip():
                        yield index, column + len(row[column:]) - len(row[column:].lstrip()), len(row.rstrip())

    def _name_columns(self, text: str) -> str:
        """Host names in the LLDP summary column, also when the name equals the model (the free-text scan skips models)."""
        lines = text.splitlines(keepends=True)
        for index, start, end in self._summary_name_cells(text):
            value = lines[index][start:end]
            if not PLACEHOLDER.fullmatch(value):
                new, _ = _fit(value, self._word("name", value, "host{:02d}"), "")
                lines[index] = lines[index][:start] + new + lines[index][end:]
        return "".join(lines)

    def text(self, text: str) -> str:
        self.prime(text)
        self._compile()     # priming may have added names (SysName) that must go everywhere
        text = self._name_columns(text)
        out, position = [], 0
        for match in self._regex.finditer(text):
            start, end = match.span()
            if start < position:
                continue
            out.append(text[position:start])
            position = end
            if match.group("hexdump") is not None:
                # organisationally specific TLVs carry MACs, names and addresses as raw bytes
                out.append(match.group("hexdump_lead") + re.sub(r"[0-9A-Fa-f]{2}", "00", match.group("hexdump_bytes")))
                continue
            if "lead" in match.re.groupindex and match.group("lead") is not None:
                value = match.group("lval")
                new = self._label_value(match.group("lead"), value)
                replacement, extra = _fit(value, new, text[end:])
                out.append(match.group("lead") + replacement)
                position += extra
                continue
            new = self._replace(match, text)
            replacement, extra = _fit(match[0], new, text[end:])
            out.append(replacement)
            position += extra
        out.append(text[position:])
        return "".join(out)

    def _label_value(self, lead: str, value: str) -> str:
        if not value.strip() or value.strip() in ("None", "N/A", "-", "(none)"):
            return value
        label = re.sub(r"[\s:=\"]+$", "", lead)
        kind = next((k for regex, k in self._label_kinds.items() if regex.fullmatch(label)), "name")
        if kind == "serial":
            return self._word("serial", value, "")
        if kind == "ssid":
            return self._word("ssid", value, "ssid{:02d}")
        if PLACEHOLDER.fullmatch(value):
            return value
        return self._word("name", value, "host{:02d}")

    # -- verification --------------------------------------------------------
    def identity_fields(self, text: str):
        """(field, value) of every field that names a host: SysName/System Name/..., the LLDP summary column, the prompt."""
        label = re.compile(r"(?<![A-Za-z0-9])(" + "|".join(NAME_LABELS) + r")[ \t]*[:=][ \t]*\"?([^\"\r\n]*?)(?=\"?[ \t]*(?:\r?\n|$))", re.M)
        for match in label.finditer(text):
            yield re.sub(r"\\", "", match[1]), match[2].strip()
        lines = text.splitlines()
        for index, start, end in self._summary_name_cells(text):
            yield "System Name column", lines[index][start:end]
        for match in re.finditer(EXOS_PROMPT, text, re.M):
            yield "prompt", match[0]
        for name in self._ios_hostnames(text):
            yield "IOS hostname", name
        for field, pattern in (
                ("Device ID", r"(?mi)^[ \t]*Device ID:[ \t]*(\S+?)(?:\([^\r\n)]+\))?[ \t]*$"),
                ("FQDN", r"(?mi)^[ \t]*FQDN:[ \t]*(\S+)[ \t]*$")):
            for match in re.finditer(pattern, text):
                yield field, match[1]

    @staticmethod
    def credential_markers(text: str) -> list[str]:
        """Credential types only; never include their values in diagnostics."""
        patterns = (
            ("credential:crypt", r"\$[156]\$"),
            ("credential:username-secret", r"(?i)\busername[ \t]+\S+[^\r\n]*[ \t]+secret[ \t]+[^\r\n]+"),
            ("credential:private-key", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
        )
        return [kind for kind, pattern in patterns if re.search(pattern, text)]

    def residual(self, text: str) -> list[str]:
        """What still looks like a real identifier (empty list = clean)."""
        found = self.credential_markers(text)
        for field, value in self.identity_fields(text):
            if value and value not in ("None", "N/A", "-", "(none)") and not PLACEHOLDER.fullmatch(value):
                found.append(f"{field} {value}")
        scan = text
        for pattern in (BRIDGE8,):
            for match in re.finditer(pattern, text):
                octets = match[0].split(":")
                digits = "".join(octets[2:]).lower()
                if not digits.startswith(DOC_MAC) and digits not in KEEP_MACS and not int(digits[:2], 16) & 1:
                    found.append("bridge id " + match[0])
        for pattern in (MAC_COLON, MAC_DASH, MAC_DOT):
            for match in re.finditer(pattern, text):
                digits = re.sub(r"[:.\-]", "", match[0]).lower()
                if not digits.startswith(DOC_MAC) and digits not in KEEP_MACS and not int(digits[:2], 16) & 1:
                    found.append("mac " + match[0])
        for pattern in (HEX16, HEX12):
            for match in re.finditer(pattern, text):
                digits = match[0][-12:].lower()
                mixed = any(c.isdigit() for c in digits) and any(c.isalpha() for c in digits)
                if (digits in self._known_macs or mixed) and not digits.startswith(DOC_MAC) and digits not in KEEP_MACS \
                        and not int(digits[:2], 16) & 1:
                    found.append("bare mac " + match[0])
        # MACs and bridge ids look like IPv6 addresses to the pattern: blank them before the address scan
        for pattern in (BRIDGE8, MAC_COLON, MAC_DASH, MAC_DOT):
            scan = re.sub(pattern, lambda match: " " * len(match[0]), scan)
        for match in re.finditer(IPV6, scan):
            try:
                address = ipaddress.IPv6Address(match[0].split("%")[0])
            except ValueError:
                continue
            documentation = address in ipaddress.IPv6Network("2001:db8::/32")
            link_local = address in ipaddress.IPv6Network("fe80::/10") and int(address) & ((1 << 64) - 1) <= 0xFFFF
            if not (documentation or link_local or address.is_multicast or address.is_unspecified or address.is_loopback):
                found.append("ipv6 " + match[0])
        for match in re.finditer(IPV4, text):
            octets = [int(p) for p in match[0].split(".")]
            if any(p > 255 for p in octets) or match[0] in self.keep:
                continue
            prefix = match[0].rsplit(".", 1)[0]
            if prefix in DOC_NETS or self._not_host(octets, match[0], text, match.start()):
                continue
            found.append("ipv4 " + match[0])
        for kind in ("name", "serial", "ssid", "user", "desc"):
            for value in self.literals[kind]:
                if value and value.lower() not in self.models and re.search(r"(?<![A-Za-z0-9_-])" + re.escape(value) + r"(?![A-Za-z0-9_-])", text, re.I):
                    found.append(f"{kind} {value}")
        return found


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("files", nargs="+", type=Path, help="raw output files (processed in sorted order)")
    parser.add_argument("--out", type=Path, required=True, help="directory for the anonymised copies")
    for flag in ("name", "serial", "ssid", "user", "description", "keep"):
        parser.add_argument("--" + flag, action="append", default=[], metavar="VALUE")
    parser.add_argument("--map", type=Path, help="JSON file holding the mapping (contains REAL values; keep it outside the repository)")
    parser.add_argument("--check", action="store_true", help="exit 1 when an output still holds an identifier")
    args = parser.parse_args(argv)
    engine = Anonymizer(args.name, args.serial, args.ssid, args.user, args.description, args.keep)
    if args.map and args.map.exists():
        engine.load(json.loads(args.map.read_text()))
    files = sorted(args.files)
    for path in files:
        engine.prime(path.read_text(errors="replace"))
    args.out.mkdir(parents=True, exist_ok=True)
    dirty = 0
    for path in files:
        result = engine.text(path.read_text(errors="replace"))
        (args.out / path.name).write_text(result)
        for item in engine.residual(result):
            dirty += 1
            print(f"{path.name}: residual {item.split()[0]}", file=sys.stderr)
    if args.map:
        args.map.write_text(json.dumps(engine.dump(), indent=1))
        args.map.chmod(0o600)
    return 1 if args.check and dirty else 0


if __name__ == "__main__":
    raise SystemExit(main())
