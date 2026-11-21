"""1.0.12 G112 adds the measured answers for the ACL, isolation, limit, passphrase-reference and enterprise lines of a WLAN
and for the DHCP relay entries (tests/fixtures/ruckus_g112).

A Ruckus R610 Unleashed (200.15.6.212 build 27) simulated at the access layer for the common Admin engine.

Listings come from the measured fixtures (tests/fixtures/ruckus_g111); the answers of the CLI are the measured texts
(see test_ruckus_g111.test_fake_answers_are_measured_ones). The device keeps a WLAN only when its context ends with
`end` or `exit`; a session that ends earlier saves nothing (measured: `abort` -> "No changes have been saved.").
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from netops_admin import exec_ruckus, ruckus
from netops_admin.access import AccessError

FIXTURES = Path(__file__).with_name("fixtures") / "ruckus_g111"
GROUP_CONFIG = (FIXTURES.parents[3] / "netops-helper" / "tests" / "fixtures" / "ruckus_g110" / "show_config.out")
OK = "The command was executed successfully. To save the changes, type 'end' or 'exit'."
UNRECOGNIZED = ("The command is either unrecognized or incomplete. To view a list of commands that you can run "
                " from this context, type '?' or 'help'.")
VLAN_REFUSED = "The VLAN ID must be between 1 and 4094. Please try again."
SSID_REFUSED = ("The SSID must be between 1 and 32 alphanumeric characters and ASCII characters ! (char 33) to ~ "
                "(char 126) except angle brackets.")
PASSPHRASE_REFUSED = ("PSK Passphrase can only contain between 8 and 63 characters or 64 HEX characters, and can't "
                      "start or end with space.")
DESCRIPTION_REFUSED = "The WLAN description length must be between 0 and 64."
MAX_CLIENTS_REFUSED = "The Max. client value must be a number between 1 and 512."
RATE_REFUSED = ("The rate of limiting must be between 0.10 and 200.00, 2 digits after the decimal point is retained. "
                "020 or 020.0 is error format.")
PERSSID_REFUSED = "The rate of limiting must be between 0.1 and 500.0 mbps. 0 means disable.  020 or 020.0 is error format."
HELPER_DHCP_EMPTY = FIXTURES.parents[3].parent / "netops-helper" / "tests" / "fixtures" / "ruckus_g110" / "show_dhcp_all.out"


def measured(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _blocks(text: str) -> list:
    """The WLAN blocks of a measured listing (the lines after the `N:` line of each)."""
    blocks, current = [], None
    for line in text.split("\n")[1:]:
        if re.fullmatch(r" {4}[0-9]+:", line):
            current = []
            blocks.append(current)
        elif current is not None:
            current.append(line)
    return blocks


def _block_values(block) -> dict:
    return {key: value for key, value in (
        (match.group(1), match.group(2)) for match in (re.match(r" {6}([^ ][^=]*?) *= ?(.*)$", line) for line in block)
        if match)}


def _withdrawn(block) -> list:
    while block and (block[-1] in ("", " ") or block[-1].startswith("ruckus")):
        block = block[:-1]
    return block


class FakeRuckus:
    def __init__(self, selected=("netops-g111-test",), hostile=None):
        self.credential = SimpleNamespace(login="admin", kind="password")
        self.check_credential = SimpleNamespace(login="admin", kind="password")
        base = _blocks(measured("show_wlan_all.out"))
        template = _blocks(measured("show_wlan_all_with_test.out"))[-1]
        self.template = _withdrawn(template)
        # an ordered table of WLANs: name -> list of listing lines (the lines of the block, without the ID line)
        self.wlans = {}
        for block in base:
            self.wlans[_block_values(block)["NAME"]] = _withdrawn(block)
        self.baseline_names = list(self.wlans)
        self.queries, self.check_queries, self.applied, self.sent = [], [], [], []
        self.unreadable = False
        self.check_unreadable = False
        self.truncate_listing = False
        self.listing_prefix = ""
        self.refuse = {}          # typed line (prefix) -> answer text the device gives instead
        self.stop_after = None    # lines accepted before the session breaks
        self.after_write = None   # called with the fake after a context was saved (a foreign change)
        self.check_view = None    # function(listing text) -> listing text of the check account
        self.config_view = None   # function(config text) -> alternate WLAN group configuration
        self.sessions = 0
        self.last_passphrase = None
        self.passphrases = []
        # 1.0.12 G112: objects the lines may name (the device refuses a name it does not know), the DHCP relay entries
        # and the vault entries a passphrase reference resolves to
        self.l2acls, self.l3acls, self.aaa = {"allow-list", "block-list"}, {"guest-l3"}, {"corp-radius"}
        self.relays = {}          # name -> {"description": str, "addresses": [first, second]}
        self.vault = {}
        self.dhcp_unreadable = False
        self.resolved = []

    # --- reads --------------------------------------------------------------------------------------------------
    def _listing(self, *, reveal_passphrases=False) -> str:
        lines = ["WLAN Service:", "  ID:"]
        for number, block in enumerate(self.wlans.values(), 1):
            lines.append("    %d:" % number)
            lines.extend(block)
            lines.append(" ")
        text = "\n".join(lines) + "\n \nruckus# "
        return text if reveal_passphrases else ruckus.redact(text)

    def _dhcp_listing(self) -> str:
        lines = ["DHCP servers for DHCP relay agent:"]
        if self.relays:
            lines.append("  ID:")
        for number, (name, relay) in enumerate(self.relays.items(), 1):
            lines += ["    %d:" % number, "      Name= " + name, "      Description= " + relay["description"]]
            lines += ["      IP Address= " + address for address in relay["addresses"]]
            lines.append(" ")
        return "\n".join(lines) + "\n \nruckus# "

    def secret_value(self, name):
        from netops_admin.errors import Rejected
        self.resolved.append(name)
        if name not in self.vault:
            raise Rejected(["the vault entry %s cannot be loaded (VaultError)" % name])
        return self.vault[name]

    def _answer(self, command: str, *, reveal_passphrases=False) -> str:
        if command == "show sysinfo":
            return measured("show_sysinfo.out").rstrip("\n") + "\n \nruckus# "
        if command == "show config":
            # Keep the measured group format and model the automatic System Default membership.
            config = GROUP_CONFIG.read_text(encoding="utf-8").split("\n", 1)[1]
            head, _, tail = config.partition("        WLAN1:")
            members = "".join(f"        WLAN{index}:\n          NAME= {name}\n          VLAN= \n"
                              for index, name in enumerate(self.wlans, 1))
            config = head + members + "\n\nVenue:" + tail.split("\nVenue:", 1)[1]
            if self.config_view is not None:
                config = self.config_view(config)
            return config.rstrip("\n") + "\n \nruckus# "
        if command == "show dhcp all":
            if self.dhcp_unreadable:
                return "The command is either unrecognized or incomplete.\nruckus# "
            return self._dhcp_listing()
        assert command == "show wlan all", command
        text = self._listing(reveal_passphrases=reveal_passphrases)
        if self.truncate_listing:
            text = text[: len(text) // 2]
        return text

    def query(self, command):
        self.queries.append(command)
        if self.unreadable:
            raise RuntimeError("device unavailable")
        return command + "\n" + self._answer(command)

    def check_query(self, command):
        self.check_queries.append(command)
        if self.check_unreadable:
            raise RuntimeError("check account unavailable")
        text = command + "\n" + self._answer(command, reveal_passphrases=True)
        return self.check_view(text) if self.check_view else text

    def snapshot(self):
        return exec_ruckus.snapshot(self)

    # --- writes -------------------------------------------------------------------------------------------------
    def _set(self, block, key, value):
        for index, line in enumerate(block):
            match = re.match(r"( {6}%s *= ?)(.*)$" % re.escape(key), line)
            if match:
                block[index] = match.group(1) + value
                return
        raise AssertionError("the listing has no %s line" % key)

    def apply(self, steps, spec):
        self.sessions += 1
        mode, pending, name, accepted = "enable", None, None, 0
        for number, step in enumerate(steps, 1):
            if self.stop_after is not None and accepted >= self.stop_after:
                raise AccessError("interactive session failed after %d lines: the session ended" % accepted, accepted)
            text = spec.typed(step) if spec.typed else step
            if getattr(spec, "resolve", None):
                text = spec.resolve(text, self)
            self.sent.append(text)
            answer = self._line(text, mode, pending, name)
            mode, pending, name = answer[1], answer[2], answer[3]
            data = ("%s\n%s\nruckus%s# " % (text, answer[0], {"enable": "", "config": "(config)",
                                                              "wlan": "(config-wlan)", "dhcp": "(config-dhcp)"}[mode])).encode()
            marker = spec.error(data.decode())
            if marker is not None:
                raise AccessError("line %d was refused by the device: %s" % (number, marker), accepted)
            accepted += 1
        self.applied.append(list(steps))
        return accepted

    def _line(self, text, mode, pending, name):
        for prefix, answer in self.refuse.items():
            if text.startswith(prefix):
                return answer, mode, pending, name
        words = text.split()
        if mode == "enable":
            if words == ["config"]:
                return "You have all rights in this mode.", "config", None, None
            return UNRECOGNIZED, mode, pending, name
        if mode == "config":
            if len(words) == 2 and words[0] == "wlan":
                if words[1] in self.wlans:
                    return ("The WLAN service '%s' has been loaded. To save the WLAN service, type 'end' or 'exit'."
                            % words[1]), "wlan", list(self.wlans[words[1]]), words[1]
                block = list(self.template)
                self._set(block, "NAME", words[1])
                self._set(block, "SSID", words[1])
                # the defaults of a new WLAN (measured, `wlan <new name>` then `show`): service enabled, VLAN 1, open
                self._set(block, "VLAN-ID", "1")
                self._set(block, "Service", "Enabled")
                self._set(block, "Encryption", "none")
                return ("The WLAN service '%s' has been created. To save the WLAN service, type 'end' or 'exit'."
                        % words[1]), "wlan", block, words[1]
            if len(words) == 2 and words[0] == "dhcp":
                if words[1] in self.relays:
                    return ("The DHCP server '%s' has been loaded. To save the DHCP server, type 'end' or 'exit'."
                            % words[1]), "dhcp", {"description": self.relays[words[1]]["description"], "loaded": True,
                                                  "addresses": list(self.relays[words[1]]["addresses"])}, words[1]
                return ("The DHCP server '%s' has been created. To save the DHCP server, type 'end' or 'exit'."
                        % words[1]), "dhcp", {"description": "", "addresses": ["", ""]}, words[1]
            if len(words) == 3 and words[:2] == ["no", "dhcp"]:
                if words[2] not in self.relays:
                    return ("The DHCP server '%s' could not be found. Please check the spelling, and then try again."
                            % words[2]), mode, pending, name
                del self.relays[words[2]]
                return "The DHCP server '%s' has been deleted." % words[2], mode, None, None
            if len(words) == 3 and words[:2] == ["no", "wlan"]:
                if words[2] not in self.wlans:
                    return UNRECOGNIZED, mode, pending, name
                del self.wlans[words[2]]
                return "The WLAN service '%s' has been deleted." % words[2], mode, None, None
            if words in (["exit"], ["end"]):
                return "Your changes have been saved.", "enable", None, None
            return UNRECOGNIZED, mode, pending, name
        if mode == "dhcp":
            return self._dhcp_line(words, text, pending, name)
        # config-wlan
        if words in (["end"], ["exit"]):
            self.wlans[name] = pending
            if self.after_write:
                self.after_write(self)
            return ("The WLAN service '%s' has been updated and saved.\nYour changes have been saved." % name,
                    "config", None, None)
        if words == ["abort"]:
            return "No changes have been saved.", "config", None, None
        answer = self._wlan_line(words, pending, text)
        return answer, mode, pending, name

    def _wlan_line(self, words, block, text):
        if words == ["type", "standard-usage"]:
            return OK
        if words and words[0] == "ssid" and len(words) == 2:
            if not 1 <= len(words[1]) <= 32:
                return SSID_REFUSED
            self._set(block, "SSID", words[1])
            return OK
        if words and words[0] == "description":
            value = text.partition(" ")[2].strip()
            if not value:
                return DESCRIPTION_REFUSED
            self._set(block, "Description", "" if value == '""' else value.strip('"'))
            return OK
        if words and words[0] == "vlan" and len(words) == 2:
            if not (words[1].isdigit() and 1 <= int(words[1]) <= 4094):
                return VLAN_REFUSED
            self._set(block, "VLAN-ID", words[1])
            return OK
        if words == ["service"]:
            self._set(block, "Service", "Enabled")
            return OK
        if words == ["no", "service"]:
            self._set(block, "Service", "Disabled")
            return OK
        extra = self._g112_line(words, block)
        if extra is not None:
            return extra
        if len(words) >= 3 and words[0] == "open" and words[1] in ("wpa2", "wpa3") and words[2] == "passphrase":
            if len(words) == 6 and words[4:] == ["algorithm", "aes"]:
                if not 8 <= len(words[3]) <= 63:
                    return PASSPHRASE_REFUSED
                self.last_passphrase = words[3]
                self.passphrases.append(words[3])
                self._set(block, "Authentication", "open")
                self._set(block, "Encryption", words[1])
                # a repeated or later passphrase line replaces the lines of the earlier one (measured: the listing
                # never repeats a field); the enterprise server name stays listed (measured, cli_wlan.out)
                block[:] = [line for line in block if not re.match(
                    r" {6}(?:Algorithm|Passphrase|Dynamic PSK|SAE anti-clogging-threshold) *=", line)]
                block.extend(("      Algorithm = aes", "      Passphrase = " + words[3], "      Dynamic PSK = Disabled"))
                if words[1] == "wpa3":  # measured: a later wpa2 line leaves PMF "Required" as it was
                    self._set(block, "80211w-pmf", "Required")
                if words[1] == "wpa3":
                    block.append("      SAE anti-clogging-threshold = 5")
                return OK
        return UNRECOGNIZED

    def _g112_line(self, words, block):
        """The measured answers of the G112 lines (tests/fixtures/ruckus_g112/cli_wlan.out, cli_wlan_errors.out)."""
        if words[:1] == ["max-clients"] and len(words) == 2:
            if not (words[1].isdigit() and 1 <= int(words[1]) <= 512):
                return MAX_CLIENTS_REFUSED
            self._set(block, "Max. Clients", words[1])
            return OK
        if words[:2] == ["client-isolation", "isolation-on-ap"] and len(words) == 3 and words[2] in ("enable", "disable"):
            self._set(block, "Isolation per AP", "Enabled" if words[2] == "enable" else "Disabled")
            return OK
        if words[:2] in (["acl", "l2acl"], ["acl", "l3acl"]) and len(words) == 3:
            known, field, label = ((self.l2acls, "L2/MAC", "L2 ACL") if words[1] == "l2acl"
                                   else (self.l3acls, "L3/L4/IP Address", "L3/L4/IP ACL"))
            if words[2] not in known:
                return "The %s '%s' could not be found. Please check the spelling, and then try again." % (label, words[2])
            self._set(block, field, words[2])
            return OK
        if words in (["no", "l2acl"], ["no", "l3acl"]):
            self._set(block, "L2/MAC" if words[1] == "l2acl" else "L3/L4/IP Address", "No ACLS")
            return OK
        if words[:2] in (["rate-limit", "perssid_uplink"], ["rate-limit", "perssid_downlink"]) and len(words) == 3:
            if not re.fullmatch(r"[0-9]+(?:\.[0-9])?", words[2]) or float(words[2]) > 500:
                return PERSSID_REFUSED
            self._set(block, "PerSSID Rate Limiting " + ("Uplink" if words[1].endswith("uplink") else "Downlink"),
                      words[2])
            return OK
        if len(words) == 5 and words[:1] == ["rate-limit"] and words[1] == "uplink" and words[3] == "downlink":
            if not all(re.fullmatch(r"[0-9]+(?:\.[0-9]{1,2})?", item) and 0.1 <= float(item) <= 200 for item in (words[2], words[4])):
                return RATE_REFUSED
            self._set(block, "Rate Limiting Uplink", "%.2fMbps" % float(words[2]))
            self._set(block, "Rate Limiting Downlink", "%.2fMbps" % float(words[4]))
            return OK
        if words == ["no", "rate-limit"]:
            self._set(block, "Rate Limiting Uplink", "Disabled")
            self._set(block, "Rate Limiting Downlink", "Disabled")
            return OK
        if len(words) == 7 and words[0] == "dot1x" and words[1] in ("wpa2", "wpa3") and words[2:5] == ["algorithm", "AES", "auth-server"] \
                and words[5] == "name":
            if words[6] not in self.aaa:
                return "The RADIUS server '%s' could not be found. Please check the spelling, and then try again." % words[6]
            self._set(block, "Authentication", "802.1x-eap")
            self._set(block, "Encryption", words[1])
            self._set(block, "Authentication Server", words[6])
            for index, line in enumerate(block):
                if re.match(r" {6}(?:Algorithm|Passphrase|Dynamic PSK|SAE anti-clogging-threshold) *=", line):
                    block[index] = None
            block[:] = [line for line in block if line is not None]
            block.append("      Algorithm = %s" % ("aes-gcmp256" if words[1] == "wpa3" else "aes"))
            block.append("      Dynamic PSK = Disabled")
            if words[1] == "wpa3":
                self._set(block, "80211w-pmf", "Required")
            return OK
        if words[:1] == ["80211w-pmf"] and len(words) == 2 and words[1] in ("0", "1", "2"):
            self._set(block, "80211w-pmf", ("Disabled", "Optional", "Required")[int(words[1])])
            return OK
        return None

    def _dhcp_line(self, words, text, pending, name):
        mode = "dhcp"
        if words in (["end"], ["exit"]) and pending.get("loaded"):
            # measured (cli_dhcp_update.out): the firmware refuses to save a change to an existing entry
            return "'is-partial' API body invalid", mode, pending, name
        if words in (["end"], ["exit"]):
            self.relays[name] = {"description": pending["description"], "addresses": list(pending["addresses"])}
            return ("The DHCP server '%s' has been updated and saved.\nYour changes have been saved." % name,
                    "config", None, None)
        if words == ["abort"]:
            return "No changes have been saved.", "config", None, None
        if words[:1] in (["first"], ["second"]) and len(words) == 2:
            if not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", words[1]) or any(int(part) > 255 for part in words[1].split(".")):
                return "The IP address is invalid. Please set the IP address, and then try again.", mode, pending, name
            pending["addresses"][0 if words[0] == "first" else 1] = words[1]
            return OK, mode, pending, name
        if words == ["no", "second"]:
            pending["addresses"][1] = ""
            return OK, mode, pending, name
        if words[:1] == ["description"]:
            value = text.partition(" ")[2].strip()
            pending["description"] = "" if value in ('""', "''") else value
            return OK, mode, pending, name
        return UNRECOGNIZED, mode, pending, name

    # --- helpers of the tests -----------------------------------------------------------------------------------
    def values(self, name):
        """The fields of the listing block of one WLAN (name -> value text)."""
        return _block_values(self.wlans[name])

    def state(self, name):
        values = _block_values(self.wlans[name])
        return {"ssid": values["SSID"], "vlan": values["VLAN-ID"], "service": values["Service"],
                "description": values.get("Description", ""), "encryption": values["Encryption"]}
