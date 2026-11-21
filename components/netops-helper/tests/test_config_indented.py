#!/usr/bin/env python3
"""Private indentation-based running-config consumers for NX-OS and EOS (task 147, 1.0.9 bod 06).

The module under test, ``netops_helper.config_indented``, is an internal consumer that the public NX-OS and
EOS ``config_read`` uses through their adapters and the engine; it adds no SSH command.  These tests drive the
real ``NxosStreamRedactor`` / ``EosStreamRedactor`` the way the engine drives the IOS consumer (fresh
redactor, section ``all``, ``ConfigurationLimits``, bytes fed through ``configuration.bounded_consumer``,
``finish()``) with the real shared ``ContentBuilder``/``Content``/``HiddenRecords``.  Nothing is mocked.

All configurations are SYNTHETIC, invented for these tests; none is a capture of any device.
* NX-OS: taken over from the task 142 gate (``ref/gate142_test_config_cisco_nxos_redaction.py``), whose
  shape follows the Cisco Nexus 9000 Series NX-OS 9.3(x) Fundamentals, Security, System Management and
  Unicast Routing Configuration Guides (``!Command:``/``!Time:`` header, two-space indentation, no
  ``!`` separators and no ``end``; ``username ... password 5``, ``tacacs-server key 7 "..."``,
  ``snmp-server user ... auth md5 ... priv ... localizedkey``, ``ip ospf authentication-key 3``,
  ``ip ospf message-digest-key ... md5 3``, ``key chain`` / ``key-string 7``).  The appended BGP /
  spanning-tree / static route rows follow the Unicast Routing (BGP ``neighbor`` block with
  ``remote-as`` and ``password 3``) and Layer 2 Switching (``spanning-tree``) guides of the same release.
* EOS: taken over from the task 143 gate (``ref/gate143_test_config_arista_eos_redaction.py``), built
  from the Arista EOS User Manual (https://www.arista.com/en/um-eos): ``username ... secret sha512``,
  ``enable password sha512``, ``tacacs-server host ... key 7``, ``snmp-server user ... v3 auth sha ...
  priv aes``, ``router bgp`` / ``neighbor ... password 7``, ``ip ospf authentication-key 7``,
  ``management api http-commands``, ``daemon TerminAttr`` with ``-cvauth=``, ``banner login`` ...
  ``EOF``; ``! Command:`` / ``! device:`` frame, three-space indentation, final ``end``.

Values containing ``FAKE``/``NOTREAL``/``SECRET`` are secret sentinels; no fragment of 8 or more
characters of them may appear in Content, summary, repr or an error.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from netops_helper import config_buffers, configuration
from netops_helper.config_buffers import Content, HiddenRecords
from netops_helper.config_limits import ConfigurationLimits

SOURCE = Path(__file__).resolve().parents[1] / "src" / "netops_helper"


def module():
    from netops_helper import config_indented
    return config_indented


def K(text):
    return ("k", text)


def H(text):
    return ("h", text)


# ---------------------------------------------------------------------------------------------
# SYNTHETIC NX-OS running-config (gate 142) + BGP / spanning-tree / static route rows
# ---------------------------------------------------------------------------------------------

NXOS_SESSION = "FAKEsessionNOTREAL1"
NXOS_SECRETS = (
    "$5$FAKEsalt$NOTREALhashAbCdEfGhIjKlMnOpQrStUvWxYz0123456",
    "0x5ec7e7aa11bb22cc33dd44ee55ff6601",
    "0x5ec7e7bb99887766554433221100ffee",
    "FAKEtqzxNOTREAL",
    "FAKEospfKey3NOTREAL",
    "FAKEmd5Key3NOTREAL",
    "FAKEchainKey7NOTREAL",
    "FAKEcmqzNOTREAL",
    "FAKEbgpPeer3NOTREAL",
    NXOS_SESSION,
)

NXOS_ROWS = (
    K(""),
    K("!Command: show running-config"),
    H("!Running configuration last done at: Sat Nov 14 09:12:44 2026"),
    H("!Time: Sat Nov 14 10:05:31 2026"),
    K(""),
    H("version 9.3(12) Bios:version"),
    K("hostname host01"),
    H("vdc host01 id 1"),
    H("  limit-resource vlan minimum 16 maximum 4094"),
    H("  limit-resource vrf minimum 2 maximum 4096"),
    K(""),
    K("feature tacacs+"),
    K("feature ospf"),
    K("feature interface-vlan"),
    K("feature lldp"),
    K(""),
    H("username admin password 5 " + NXOS_SECRETS[0] + "  role network-admin"),
    H("ip domain-lookup"),
    H('tacacs-server key 7 "' + NXOS_SECRETS[3] + '"'),
    H("tacacs-server host 192.0.2.10"),
    H("aaa group server tacacs+ TACACS"),
    H("    server 192.0.2.10"),
    H("copp profile strict"),
    H("snmp-server user admin network-admin auth md5 " + NXOS_SECRETS[1] + " priv " + NXOS_SECRETS[2]
      + " localizedkey"),
    H("snmp-server community " + NXOS_SECRETS[7] + " group network-operator"),
    H("rmon event 1 description FATAL(1) owner PMON@FATAL"),
    K(""),
    K("vlan 1,10,20"),
    K("vlan 10"),
    K("  name USERS"),
    K("vlan 20"),
    K("  name SERVERS"),
    K(""),
    H("key chain OSPF-KEYS"),
    H("  key 1"),
    H("    key-string 7 " + NXOS_SECRETS[6]),
    K("vrf context management"),
    K("  ip route 0.0.0.0/0 192.0.2.1"),
    K(""),
    K(""),
    K("interface Vlan10"),
    K("  no shutdown"),
    K("  ip address 203.0.113.1/24"),
    H("  ip router ospf 1 area 0.0.0.0"),
    K(""),
    K("interface Ethernet1/1"),
    K("  description uplink-core"),
    K("  no switchport"),
    K("  ip address 198.51.100.1/30"),
    H("  ip ospf authentication-key 3 " + NXOS_SECRETS[4]),
    H("  ip ospf message-digest-key 1 md5 3 " + NXOS_SECRETS[5]),
    H("  ip router ospf 1 area 0.0.0.0"),
    K("  no shutdown"),
    K(""),
    K("interface Ethernet1/2"),
    K("  switchport access vlan 10"),
    K(""),
    K("interface Ethernet1/3"),
    K("  switchport mode trunk"),
    K("  switchport trunk allowed vlan 10,20"),
    K(""),
    K("interface mgmt0"),
    K("  vrf member management"),
    K("  ip address 192.0.2.5/24"),
    H("line console"),
    H("line vty"),
    H("boot nxos bootflash:/nxos.9.3.12.bin"),
    K("router ospf 1"),
    K("  router-id 192.0.2.254"),
    K(""),
    # Appended rows (same guides): spanning-tree, a global static route, a BGP neighbor block.
    K("spanning-tree mode mst"),
    K("spanning-tree port type edge bpduguard default"),
    K("ip route 198.51.100.0/24 192.0.2.1"),
    K("interface Ethernet1/4"),
    K("  description server-a"),
    K("  switchport mode trunk"),
    K("  switchport trunk native vlan 99"),
    K("  channel-group 10 mode active"),
    K("  mtu 9216"),
    K("  speed 10000"),
    K("  duplex full"),
    K("  spanning-tree port type edge trunk"),
    K("  shutdown"),
    K("router bgp 65000"),
    K("  router-id 192.0.2.254"),
    K("  address-family ipv4 unicast"),
    K("    network 203.0.113.0/24"),
    H("    maximum-paths 4"),
    K("  neighbor 198.51.100.2"),
    K("    remote-as 65001"),
    H("    password 3 " + NXOS_SECRETS[8]),
    H("    address-family ipv4 unicast"),
    H("      send-community"),
    K(""),
)

# ---------------------------------------------------------------------------------------------
# SYNTHETIC EOS running-config (gate 143), expectations of the EOS consumer
# ---------------------------------------------------------------------------------------------

EOS_SESSION = "LOGIN-SECRET-FAKE-0143"
EOS_SECRETS = (
    "$6$SECRETsaltAdm1n$FAKEhashADMINa1b2c3d4e5f6g7h8i9j0kLmNoPqRsTuVwXyZ0123456789abcdefABCDEFghij",
    "$6$SECRETsaltEnab$FAKEhashENABLEz9y8x7w6v5u4t3s2r1q0pOnMlKjIhGfEdCbA9876543210zyxwvuZYXWVUts",
    "0xSECRET5f1d2e3c4b5a69788796a5b4c3d2e1f0FAKEAUTH",
    "0xSECRET0a1b2c3d4e5f60718293a4b5c6d7e8f9FAKEPRIV",
    "070C2E5F4D0A16SECRETFAKETACACS",
    "094F471A1A0ASECRETFAKEBGP",
    "0207165218120ESECRETFAKEOSPF",
    "SECRET-FAKE-EAPI-TOKEN",
    EOS_SESSION,
)

EOS_ROWS = (
    H("! Command: show running-config"),
    H("! device: ceos-lab1 (cEOSLab, EOS-4.36.1F)"),
    K("!"),
    H("! boot system flash:/cEOS-lab.swi"),
    K("!"),
    K("no aaa root"),
    K("!"),
    H("username admin privilege 15 role network-admin secret sha512 " + EOS_SECRETS[0]),
    K("!"),
    H("enable password sha512 " + EOS_SECRETS[1]),
    K("!"),
    K("management api http-commands"),
    K("   no shutdown"),
    K("   !"),
    K("   vrf MGMT"),
    K("      no shutdown"),
    K("!"),
    H("daemon TerminAttr"),
    H("   exec /usr/bin/TerminAttr -cvauth=token," + EOS_SECRETS[7] + " -taillogs"),
    H("   no shutdown"),
    K("!"),
    K("service routing protocols model multi-agent"),
    K("!"),
    K("hostname ceos-lab1"),
    K("ip name-server vrf default 192.0.2.53"),
    K("!"),
    H("snmp-server user u1 g1 v3 auth sha " + EOS_SECRETS[2] + " priv aes " + EOS_SECRETS[3]),
    K("!"),
    H("tacacs-server host 198.51.100.1 key 7 " + EOS_SECRETS[4]),
    K("!"),
    K("spanning-tree mode mstp"),
    K("!"),
    K("vlan 10"),
    K("   name users"),
    K("!"),
    K("vlan 20"),
    K("   name servers"),
    K("!"),
    K("interface Ethernet1"),
    K("   description uplink to spine1"),
    K("   no switchport"),
    K("   ip address 198.51.100.1/31"),
    H("   ip ospf authentication-key 7 " + EOS_SECRETS[6]),
    K("!"),
    K("interface Ethernet2"),
    K("   switchport access vlan 10"),
    K("!"),
    K("interface Loopback0"),
    K("   ip address 192.0.2.1/32"),
    K("!"),
    K("interface Management0"),
    K("   ip address 203.0.113.10/24"),
    K("!"),
    K("ip routing"),
    K("!"),
    K("ip route 0.0.0.0/0 203.0.113.1"),
    K("!"),
    K("router bgp 65000"),
    K("   router-id 192.0.2.1"),
    K("   neighbor 198.51.100.2 remote-as 65001"),
    H("   neighbor 198.51.100.2 password 7 " + EOS_SECRETS[5]),
    K("   !"),
    K("   address-family ipv4"),
    K("      neighbor 198.51.100.2 activate"),
    K("      network 192.0.2.1/32"),
    K("!"),
    K("router ospf 1"),
    K("   network 198.51.100.0/31 area 0.0.0.0"),
    K("!"),
    K("end"),
)

# (b) Lines that must stay readable verbatim (exact physical lines).
NXOS_READABLE = (
    "hostname host01", "vlan 10", "  name USERS", "interface Ethernet1/1", "  description uplink-core",
    "  ip address 198.51.100.1/30", "  switchport access vlan 10", "  switchport mode trunk",
    "  switchport trunk allowed vlan 10,20", "  ip route 0.0.0.0/0 192.0.2.1", "ip route 198.51.100.0/24 192.0.2.1",
    "router ospf 1", "  router-id 192.0.2.254", "router bgp 65000", "    network 203.0.113.0/24",
    "  neighbor 198.51.100.2", "    remote-as 65001", "feature ospf", "spanning-tree mode mst",
)
EOS_READABLE = (
    "hostname ceos-lab1", "vlan 10", "   name users", "interface Ethernet1", "   description uplink to spine1",
    "   ip address 198.51.100.1/31", "   switchport access vlan 10", "ip route 0.0.0.0/0 203.0.113.1",
    "router bgp 65000", "   neighbor 198.51.100.2 remote-as 65001", "      network 192.0.2.1/32", "router ospf 1",
    "   network 198.51.100.0/31 area 0.0.0.0", "spanning-tree mode mstp", "end",
)

DIALECTS = {
    "nxos": ("NxosStreamRedactor", NXOS_ROWS, NXOS_SECRETS, (NXOS_SESSION,), NXOS_READABLE),
    "eos": ("EosStreamRedactor", EOS_ROWS, EOS_SECRETS, (EOS_SESSION,), EOS_READABLE),
}


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------

def redactor_class(dialect):
    return getattr(module(), DIALECTS[dialect][0])


def doc(dialect, rows, eol="\n"):
    marker = redactor_class(dialect).MARKER
    raw = "".join(text + eol for unused, text in rows).encode("ascii")
    expected = "".join((text if kind == "k" else marker) + eol for kind, text in rows)
    return raw, expected


def chunks(data, size):
    if size is None:
        return [data]
    return [data[i:i + size] for i in range(0, len(data), size)]


def capture(dialect, data, forbidden=None, size=None, limits=None):
    """Engine-like capture: budget context, bounded consumer, finish.

    Returns ``(outcome, text, count, hidden, summary, rendered)``; ``outcome`` is ``'accepted'`` or the
    refusal category, ``rendered`` joins every observable string for leak checks."""
    if forbidden is None:
        forbidden = DIALECTS[dialect][3]
    limits = ConfigurationLimits() if limits is None else limits
    with configuration.capture(limits):
        redactor = redactor_class(dialect)(forbidden, "all", limits=limits)
        feed = configuration.bounded_consumer(redactor.feed)
        try:
            try:
                for part in chunks(data, size):
                    feed(part)
                content, hidden, count = redactor.finish()
            except (ValueError, configuration.core_ssh.OutputLimitError) as exc:
                # bounded_consumer turns a capture limit during feed into the SSH output limit error.
                if isinstance(exc, configuration.core_ssh.OutputLimitError):
                    outcome = "capture-limit-exceeded"
                else:
                    outcome = getattr(exc, "reason", type(exc).__name__)
                rendered = " ".join((str(exc), repr(exc), repr(redactor), repr(redactor.summary()),
                                     repr(getattr(exc, "line", None)), getattr(exc, "location", "")))
                return outcome, None, None, None, redactor.summary(), rendered
            summary = redactor.summary()
        finally:
            redactor.close()
    assert isinstance(content, Content) and isinstance(hidden, HiddenRecords)
    text = content.page(0, content.total)[0]
    assert content.sha256 == hashlib.sha256(text.encode("ascii")).hexdigest()
    rendered = " ".join((text, repr(content), repr(hidden), repr(list(hidden)), repr(redactor),
                         repr(summary), repr(count)))
    return "accepted", text, count, hidden, summary, rendered


def fragments(value, minimum=8):
    return {value[start:end] for start in range(len(value)) for end in range(start + minimum, len(value) + 1)}


def assert_no_secret(rendered, secrets):
    for secret in secrets:
        for fragment in fragments(secret):
            assert fragment not in rendered, "secret fragment leaked"


def accepted(dialect, data, **options):
    outcome, text, count, hidden, summary, rendered = capture(dialect, data, **options)
    assert outcome == "accepted", outcome
    return text, count, summary, rendered


def refused(dialect, data, reason, **options):
    outcome, text, count, hidden, summary, rendered = capture(dialect, data, **options)
    assert outcome == reason
    return rendered


NXOS_HEAD = "!Command: show running-config\n"


# ---------------------------------------------------------------------------------------------
# API and module boundaries
# ---------------------------------------------------------------------------------------------

def test_api_matches_the_ios_consumer_and_shares_building_blocks():
    mod = module()
    from netops_helper import config_cisco_ios
    for name in ("NxosStreamRedactor", "EosStreamRedactor"):
        cls = getattr(mod, name)
        assert cls is not config_cisco_ios.StreamRedactor
        assert not issubclass(cls, config_cisco_ios.StreamRedactor)
        for method in ("feed", "finish", "close", "summary"):
            assert callable(getattr(cls, method))
        with pytest.raises(ValueError):
            cls((), "system")
        with pytest.raises(ValueError):
            cls((), "all", limits={"memory_bytes": 1})
        with pytest.raises(ValueError):
            cls((b"bytes-not-str",), "all")
        redactor = cls(("x",), "all", limits=ConfigurationLimits())
        assert redactor.summary() == {"credential_redactions": 0, "unverified_count": 0,
                                      "unsupported_format_count": 0, "unverified_fields": [],
                                      "unverified_truncated": False}
        redactor.close()
    assert mod.NxosStreamRedactor.MARKER == mod.NXOS_MARKER == "<UNVERIFIED:cisco-nxos-opaque-line>"
    assert mod.EosStreamRedactor.MARKER == mod.EOS_MARKER == "<UNVERIFIED:arista-eos-opaque-line>"
    assert mod.ContentBuilder is config_buffers.ContentBuilder
    assert mod.HiddenRecords is config_buffers.HiddenRecords
    assert mod.ConfigurationLimits is ConfigurationLimits
    assert mod.ConfigurationRedactionError is configuration.ConfigurationRedactionError
    assert mod.ConfigurationBudgetError is configuration.ConfigurationBudgetError
    assert mod.ConfigurationRefusedError is configuration.ConfigurationRefusedError


def test_module_is_used_only_by_the_nxos_and_eos_config_read_path():
    # G136: the Junos display-set redactor reuses the bounded scaffolding and the secret checks.
    users = {path.name for path in SOURCE.glob("*.py")
             if path.name != "config_indented.py" and "config_indented" in path.read_text()}
    assert users == {"config_arista_eos_adapter.py", "config_cisco_nxos_adapter.py", "config_junos_adapter.py",
                     "engine.py"}


# ---------------------------------------------------------------------------------------------
# (a) secrets, (b) readable lines, (c) MARKER, (e) chunking, (f) CRLF/LF
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("eol", ["\n", "\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("size", [None, 1, 7, 4096], ids=["single", "1", "7", "4096"])
@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_synthetic_running_config_exact_result(dialect, size, eol):
    unused, rows, secrets, forbidden, readable = DIALECTS[dialect]
    raw, expected = doc(dialect, rows, eol)
    text, count, summary, rendered = accepted(dialect, raw, size=size)
    # (c) every non-allowlisted line is exactly one MARKER, the rest is copied verbatim.
    assert text == expected
    # (a) nothing of any secret, in content, summary, repr or count.
    assert_no_secret(rendered, secrets)
    for fragment in ("FAKE", "NOTREAL", "SECRET", "$5$", "$6$", "key-string", "password", "localizedkey",
                     "community", "cvauth", "authentication-key", "message-digest-key"):
        assert fragment not in text
    # (b) the allowlisted statements stay readable verbatim.
    lines = text.split(eol)
    missing = [line for line in readable if line not in lines]
    assert not missing
    hidden = sum(kind == "h" for kind, unused in rows)
    assert count == hidden == text.count(redactor_class(dialect).MARKER)
    assert summary["credential_redactions"] == 0
    assert summary["unverified_count"] == hidden
    assert summary["unsupported_format_count"] == 0
    prefix = "cisco-nxos / " if dialect == "nxos" else "arista-eos / "
    assert summary["unverified_fields"] and all(label.startswith(prefix) for label in summary["unverified_fields"])


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_chunking_gives_identical_results(dialect):
    unused, rows, secrets, forbidden, readable = DIALECTS[dialect]
    for eol in ("\n", "\r\n"):
        raw, unused = doc(dialect, rows, eol)
        results = []
        for size in (None, 1, 7, 4096):
            outcome, text, count, hidden, summary, rendered = capture(dialect, raw, size=size)
            results.append((outcome, text, count, list(hidden), summary))
        assert all(result == results[0] for result in results[1:])


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_lf_and_crlf_differ_only_in_line_endings(dialect):
    unused, rows, secrets, forbidden, readable = DIALECTS[dialect]
    lf = accepted(dialect, doc(dialect, rows, "\n")[0])
    crlf = accepted(dialect, doc(dialect, rows, "\r\n")[0])
    assert crlf[0] == lf[0].replace("\n", "\r\n")
    assert crlf[1:3] == lf[1:3]


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_forbidden_value_or_secret_keyword_hides_an_allowed_line(dialect):
    marker = redactor_class(dialect).MARKER
    pad = "  " if dialect == "nxos" else "   "
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    session = DIALECTS[dialect][3][0]
    body = ("hostname h1\n"
            "interface Ethernet1/9\n"
            + pad + "description peer " + session + "\n"
            + pad + "description the password is FAKEdescrNOTREAL\n"
            + pad + "description auth FAKEtokenNOTREAL\n"
            + pad + "description $6$FAKEcryptNOTREAL\n"
            + pad + "no shutdown\n"
            "interface Ethernet1/10\n")
    raw = (head + body + tail).encode("ascii")
    text, count, summary, rendered = accepted(dialect, raw)
    expected = (head + "hostname h1\ninterface Ethernet1/9\n" + (marker + "\n") * 4 + pad + "no shutdown\n"
                "interface Ethernet1/10\n" + tail)
    assert text == expected
    assert_no_secret(rendered, (session, "FAKEdescrNOTREAL", "FAKEtokenNOTREAL", "FAKEcryptNOTREAL"))
    # '$6$...' is a recognizable password hash (task 147-r2): a credential redaction, not a reserved marker.
    assert summary["credential_redactions"] == 4 and count == 4
    assert summary["unverified_count"] == 0


# Review 147-rv finding 2: a recognizable password hash in an allowed line (description) is hidden
# whole even with an empty ``forbidden``; the shared ContentBuilder markers only know '$6$' / '$9$'.
REVIEW_HASH = "$5$saltsalt$0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"
HASH_VARIANTS = (
    REVIEW_HASH,
    "$1$FAKEsalt$NOTREALmd5cryptHash01",
    "$y$j9T$FAKEyescryptSalt$NOTREALyescryptHash",
    "$2a$10$FAKEbcryptSaltNOTREALbcryptHashValue0",
    "$2b$12$FAKEbcryptSaltNOTREALbcryptHashValue1",
    "$2y$10$FAKEbcryptSaltNOTREALbcryptHashValue2",
    "$6$FAKEsha512$NOTREALsha512cryptHash",
    "$8$FAKEtype8salt$NOTREALtype8HashValue",
    "$9$FAKEtype9salt$NOTREALtype9HashValue",
    "7 0822455D0A165B1E0A1F1C",
)


@pytest.mark.parametrize("size", [None, 1, 7])
def test_review_nxos_sha256_crypt_in_description_is_hidden(size):
    marker = module().NXOS_MARKER
    raw = ("!Command: show running-config\ninterface Ethernet1/1\n  description " + REVIEW_HASH
           + "\n").encode("ascii")
    text, count, summary, rendered = accepted("nxos", raw, forbidden=(), size=size)
    assert text == "!Command: show running-config\ninterface Ethernet1/1\n" + marker + "\n"
    assert summary["credential_redactions"] == 1 and summary["unverified_count"] == 0 and count == 1
    assert_no_secret(rendered, (REVIEW_HASH,))
    assert "$5$" not in rendered


@pytest.mark.parametrize("size", [None, 1, 7])
def test_review_eos_sha256_crypt_in_description_is_hidden(size):
    marker = module().EOS_MARKER
    raw = ("interface Ethernet1/1\n   description " + REVIEW_HASH + "\nend\n").encode("ascii")
    text, count, summary, rendered = accepted("eos", raw, forbidden=(), size=size)
    assert text == "interface Ethernet1/1\n" + marker + "\nend\n"
    assert summary["credential_redactions"] == 1 and summary["unverified_count"] == 0 and count == 1
    assert_no_secret(rendered, (REVIEW_HASH,))
    assert "$5$" not in rendered


@pytest.mark.parametrize("value", HASH_VARIANTS, ids=range(len(HASH_VARIANTS)))
@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_password_hash_in_an_allowed_line_is_hidden_whatever_forbidden_holds(dialect, value):
    marker = redactor_class(dialect).MARKER
    pad = "  " if dialect == "nxos" else "   "
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    raw = (head + "interface Ethernet1/2\n" + pad + "description " + value + "\n"
           + pad + "description peer " + value + " uplink\n"
           + pad + "description cost $5 and 7 rooms\n" + tail).encode("ascii")
    for forbidden in ((), ("FAKEunrelatedNOTREAL",)):
        text, count, summary, rendered = accepted(dialect, raw, forbidden=forbidden)
        assert text == (head + "interface Ethernet1/2\n" + (marker + "\n") * 2
                        + pad + "description cost $5 and 7 rooms\n" + tail)
        assert summary["credential_redactions"] == 2 and summary["unverified_count"] == 0 and count == 2
        assert_no_secret(rendered, (value,))


# Review 147-r2rv (task 219): a type 7 value followed by punctuation must not escape, a plain number
# after '7' (seed outside 00-15, too short) stays readable.
TYPE7_VALUE = "0822455D0A165B1E0A1F1C"
TYPE7_LEAKS = (
    "peer 7 " + TYPE7_VALUE + ", uplink",
    "peer 7 " + TYPE7_VALUE + "; uplink",
    "peer 7 " + TYPE7_VALUE + ": uplink",
    "peer (7 " + TYPE7_VALUE + ")",
    "peer [7 " + TYPE7_VALUE + "]",
    "peer {7 " + TYPE7_VALUE + "}",
    "peer 7 " + TYPE7_VALUE + ".",
    "peer 7 " + TYPE7_VALUE + "/uplink",
    "peer '7 " + TYPE7_VALUE + "'",
    "peer 7 " + TYPE7_VALUE + "!",
    "peer 7 " + TYPE7_VALUE + "G-wall",
    "pw 7 0822455D0A16,",
    "x 7 1508AB",
    "peer 7 0005",
    "peer 7 0005, uplink",
    "room 7 1500",
)
TYPE7_READABLE = (
    "rack 7 2026",
    "rack 7 2026, row 4",
    "floor 7 1999",
    "cost 7 08224",
    "item7 0512AB34CD",
    "7 16AABBCC",
)


@pytest.mark.parametrize("size", [None, 1, 7])
@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_review_type7_with_trailing_punctuation_in_description_is_hidden(dialect, size):
    marker = redactor_class(dialect).MARKER
    pad = "  " if dialect == "nxos" else "   "
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    raw = (head + "interface Ethernet1/1\n" + pad + "description peer 7 " + TYPE7_VALUE + ", uplink\n"
           + tail).encode("ascii")
    text, count, summary, rendered = accepted(dialect, raw, forbidden=(), size=size)
    assert text == head + "interface Ethernet1/1\n" + marker + "\n" + tail
    assert summary["credential_redactions"] == 1 and summary["unverified_count"] == 0 and count == 1
    assert_no_secret(rendered, (TYPE7_VALUE,))


# Review 219-rv (task 219-r2): a one-character password is a single encrypted byte ('7 0005': seed 00,
# byte 05); it must be hidden with or without trailing punctuation, '7 2026' (seed 20) stays readable.
@pytest.mark.parametrize("size", [None, 1, 7])
@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_review_type7_single_byte_password_in_description_is_hidden(dialect, size):
    marker = redactor_class(dialect).MARKER
    pad = "  " if dialect == "nxos" else "   "
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    raw = (head + "interface Ethernet1/1\n" + pad + "description peer 7 0005\n"
           + pad + "description peer 7 0005, uplink\n" + pad + "description rack 7 2026\n" + tail).encode("ascii")
    text, count, summary, rendered = accepted(dialect, raw, forbidden=(), size=size)
    assert text == (head + "interface Ethernet1/1\n" + marker + "\n" + marker + "\n"
                    + pad + "description rack 7 2026\n" + tail)
    assert summary["credential_redactions"] == 2 and summary["unverified_count"] == 0 and count == 2
    assert "0005" not in text
    assert "7 0005" not in rendered  # shorter than the fragments() minimum, checked directly


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_type7_shapes_in_description_are_hidden_and_plain_numbers_kept(dialect):
    marker = redactor_class(dialect).MARKER
    pad = "  " if dialect == "nxos" else "   "
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    lines = ([(False, value) for value in TYPE7_LEAKS] + [(True, value) for value in TYPE7_READABLE])
    raw = (head + "interface Ethernet1/3\n" + "".join(pad + "description " + value + "\n"
                                                      for unused, value in lines) + tail).encode("ascii")
    text, count, summary, rendered = accepted(dialect, raw, forbidden=())
    assert text == (head + "interface Ethernet1/3\n"
                    + "".join((pad + "description " + value if keep else marker) + "\n" for keep, value in lines)
                    + tail)
    assert summary["credential_redactions"] == len(TYPE7_LEAKS) and count == len(TYPE7_LEAKS)
    assert summary["unverified_count"] == 0
    assert_no_secret(rendered, (TYPE7_VALUE,))


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_forbidden_value_in_a_block_header_hides_the_whole_block(dialect):
    marker = redactor_class(dialect).MARKER
    pad = "  " if dialect == "nxos" else "   "
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    raw = (head + "vlan 10\n" + pad + "name users\n" + "interface Vlan10\n" + pad + "shutdown\n"
           + tail).encode("ascii")
    text, count, summary, rendered = accepted(dialect, raw, forbidden=("Vlan10",))
    # The interface header carries the forbidden value: header and its whole block are hidden.
    assert text == head + "vlan 10\n" + pad + "name users\n" + (marker + "\n") * 2 + tail
    assert summary["credential_redactions"] == 1 and count == 2


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_unknown_lines_and_wrong_indentation_are_markers(dialect):
    marker = redactor_class(dialect).MARKER
    pad = "  " if dialect == "nxos" else "   "
    other = "   " if dialect == "nxos" else "  "
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    # A wrongly indented line opens an opaque context.  NX-OS: 3 spaces is deeper than the unit, so the
    # next 2-space line is again a direct child of the interface.  EOS: 2 spaces is shallower than the
    # unit, so the following 3-space lines are children of that opaque line and stay hidden (run 1).
    later = K if dialect == "nxos" else H
    rows = (
        K("interface Ethernet1/1"),
        H(other + "description wrong-indent"),
        H(pad + pad + "description too-deep"),
        H(pad + "ip router ospf 1 area 0.0.0.0"),
        later(pad + "description ok"),
        H("some unknown global statement"),
        H(pad + "description under-an-unknown-parent"),
        H(pad + "hostname nested"),
        H("logging server 192.0.2.9"),
        K("hostname h1"),
        H(pad + "description under-a-leaf"),
        H("interface Ethernet1/1 extra words"),
        H("vlan 5000"),
        H("vlan 20-10"),
        K("vlan 30"),
        H(pad + "name bad name with spaces"),
        H(pad + "state suspend"),
        H("ip route 198.51.100.0/24 999.0.0.1"),
        H("router eigrp 1"),
        H(pad + "router-id 198.51.100.1"),
    )
    raw = (head + "".join(text + "\n" for unused, text in rows) + tail).encode("ascii")
    expected = head + "".join((text if kind == "k" else marker) + "\n" for kind, text in rows) + tail
    text, count, summary, rendered = accepted(dialect, raw)
    assert text == expected
    assert count == sum(kind == "h" for kind, unused in rows)


# ---------------------------------------------------------------------------------------------
# (d) banners and other opaque multi-line blocks
# ---------------------------------------------------------------------------------------------

def test_eos_banner_with_eof_is_hidden_up_to_its_real_end():
    marker = module().EOS_MARKER
    raw = ("hostname h1\n!\nbanner login\nhostname FAKEbannerNOTREAL\n   interface Ethernet9\n!\nend\n"
           "EOF\n!\nbanner motd\nEOF\n!\nend\n").encode("ascii")
    text, count, summary, rendered = accepted("eos", raw)
    assert text == "hostname h1\n!\n" + (marker + "\n") * 6 + "!\n" + (marker + "\n") * 2 + "!\nend\n"
    assert_no_secret(rendered, ("FAKEbannerNOTREAL",))
    assert count == 2 and summary["unsupported_format_count"] == 2


@pytest.mark.parametrize("size", [None, 1, 7, 4096])
def test_eos_banner_without_end_refuses_the_stream(size):
    raw = b"hostname h1\n!\nbanner login\nFAKEbannerTextNOTREAL\n EOF\nEOF \n!\nend\n"
    rendered = refused("eos", raw, "stream-incomplete", size=size)
    assert_no_secret(rendered, ("FAKEbannerTextNOTREAL",))


@pytest.mark.parametrize("header", ["banner login FAKEinlineNOTREAL", "banner exec", "banner"])
def test_eos_unknown_banner_form_is_refused(header):
    raw = ("hostname h1\n" + header + "\nEOF\nend\n").encode("ascii")
    rendered = refused("eos", raw, "redaction-unverifiable")
    assert_no_secret(rendered, ("FAKEinlineNOTREAL",))


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_indented_banner_header_is_refused(dialect):
    pad = "  " if dialect == "nxos" else "   "
    head = NXOS_HEAD if dialect == "nxos" else ""
    raw = (head + "interface Ethernet1\n" + pad + "banner motd #\nFAKEbodyNOTREAL\n#\nend\n").encode("ascii")
    rendered = refused(dialect, raw, "redaction-unverifiable")
    assert_no_secret(rendered, ("FAKEbodyNOTREAL",))


def test_nxos_banner_with_delimiter_is_hidden():
    marker = module().NXOS_MARKER
    raw = (NXOS_HEAD + "hostname h1\nbanner motd #FAKEinlineNOTREAL#\nbanner exec ^C\nhostname FAKEmlNOTREAL\n"
           "  description x\n^C\ninterface mgmt0\n  ip address 192.0.2.5/24\n").encode("ascii")
    text, count, summary, rendered = accepted("nxos", raw)
    assert text == (NXOS_HEAD + "hostname h1\n" + (marker + "\n") * 5 + "interface mgmt0\n  ip address 192.0.2.5/24\n")
    assert_no_secret(rendered, ("FAKEinlineNOTREAL", "FAKEmlNOTREAL"))
    assert count == 2 and summary["unsupported_format_count"] == 2


@pytest.mark.parametrize("size", [None, 1, 7])
def test_nxos_banner_without_end_refuses_the_stream(size):
    raw = (NXOS_HEAD + "hostname h1\nbanner motd #\nFAKEopenBannerNOTREAL\ninterface mgmt0\n").encode("ascii")
    rendered = refused("nxos", raw, "stream-incomplete", size=size)
    assert_no_secret(rendered, ("FAKEopenBannerNOTREAL",))


def test_nxos_banner_without_delimiter_is_refused():
    raw = (NXOS_HEAD + "banner motd\nFAKEnoDelimNOTREAL\n").encode("ascii")
    rendered = refused("nxos", raw, "redaction-unverifiable")
    assert_no_secret(rendered, ("FAKEnoDelimNOTREAL",))


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_pem_block_with_end_is_hidden_and_without_end_refused(dialect):
    marker = redactor_class(dialect).MARKER
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    pem = ("crypto pki certificate FAKEcertNOTREAL\n-----BEGIN CERTIFICATE-----\nMIIFAKEpemBodyNOTREAL\n"
           "hostname leak\n-----END CERTIFICATE-----\n")
    raw = (head + pem + "hostname h1\n" + tail).encode("ascii")
    text, count, summary, rendered = accepted(dialect, raw)
    assert text == head + (marker + "\n") * 5 + "hostname h1\n" + tail
    assert_no_secret(rendered, ("FAKEcertNOTREAL", "MIIFAKEpemBodyNOTREAL"))
    assert count == 2
    raw = (head + "-----BEGIN PRIVATE KEY-----\nMIIFAKEpemBodyNOTREAL\nhostname h1\n" + tail).encode("ascii")
    rendered = refused(dialect, raw, "stream-incomplete")
    assert_no_secret(rendered, ("MIIFAKEpemBodyNOTREAL",))


# Review 147-rv finding 1: a PEM block ends only on the exact '-----END <same label>-----' line (after
# the indentation); a foreign or malformed boundary refuses the whole stream, so no body line is
# ever read as configuration.
REVIEW_PEM = ("-----BEGIN CERTIFICATE-----\n-----END PRIVATE KEY-----\nhostname CERTBODY123\n"
              "-----END CERTIFICATE-----\n")


@pytest.mark.parametrize("size", [None, 1, 7])
def test_review_eos_foreign_pem_end_refuses_the_stream(size):
    rendered = refused("eos", (REVIEW_PEM + "end\n").encode("ascii"), "redaction-unverifiable",
                       forbidden=(), size=size)
    assert_no_secret(rendered, ("CERTBODY123",))


@pytest.mark.parametrize("size", [None, 1, 7])
def test_review_nxos_foreign_pem_end_refuses_the_stream(size):
    rendered = refused("nxos", (NXOS_HEAD + REVIEW_PEM).encode("ascii"), "redaction-unverifiable",
                       forbidden=(), size=size)
    assert_no_secret(rendered, ("CERTBODY123",))


PEM_BAD_BOUNDARIES = (
    "x-----ENDx",
    "-----END PRIVATE KEY-----",
    "-----END CERTIFICATE",
    "-----END CERTIFICATE-----x",
    "-----END CERTIFICATE----- ",
    "   -----END  CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----",
    "MIIFAKEbody-----ENDNOTREAL",
)


@pytest.mark.parametrize("boundary", PEM_BAD_BOUNDARIES, ids=range(len(PEM_BAD_BOUNDARIES)))
@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_foreign_or_malformed_pem_end_refuses_the_stream(dialect, boundary):
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    raw = (head + "hostname h1\n-----BEGIN CERTIFICATE-----\nMIIFAKEpemBodyNOTREAL\n" + boundary
           + "\nhostname FAKEcertBodyNOTREAL\n-----END CERTIFICATE-----\n" + tail).encode("ascii")
    rendered = refused(dialect, raw, "redaction-unverifiable", forbidden=())
    assert_no_secret(rendered, ("MIIFAKEpemBodyNOTREAL", "FAKEcertBodyNOTREAL"))


PEM_BAD_OPENINGS = (
    "-----BEGIN CERTIFICATE----------END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE----- -----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----x-----ENDx",
    "-----BEGIN CERTIFICATE-----x",
    "-----BEGIN CERTIFICATE",
    "x-----ENDx",
    "-----END CERTIFICATE-----",
    "description -----BEGIN CERTIFICATE-----",
)


@pytest.mark.parametrize("opening", PEM_BAD_OPENINGS, ids=range(len(PEM_BAD_OPENINGS)))
@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_inline_or_malformed_pem_opening_refuses_the_stream(dialect, opening):
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    raw = (head + "hostname h1\n" + opening + "\nhostname FAKEcertBodyNOTREAL\n" + tail).encode("ascii")
    rendered = refused(dialect, raw, "redaction-unverifiable", forbidden=())
    assert_no_secret(rendered, ("FAKEcertBodyNOTREAL",))


@pytest.mark.parametrize("size", [None, 1, 7])
@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_indented_pem_block_ends_on_its_exact_end_line(dialect, size):
    marker = redactor_class(dialect).MARKER
    pad = "  " if dialect == "nxos" else "   "
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    raw = (head + "crypto ca certificate FAKEcaNameNOTREAL\n" + pad + "-----BEGIN EC PRIVATE KEY-----\n"
           + pad + "MIIFAKEecKeyBodyNOTREAL\nhostname FAKEkeyBodyNOTREAL\n\n"
           + pad + "-----END EC PRIVATE KEY-----\nhostname h1\n" + tail).encode("ascii")
    text, count, summary, rendered = accepted(dialect, raw, forbidden=(), size=size)
    assert text == head + (marker + "\n") * 6 + "hostname h1\n" + tail
    assert count == 2 and summary["unsupported_format_count"] == 1
    assert_no_secret(rendered, ("FAKEcaNameNOTREAL", "MIIFAKEecKeyBodyNOTREAL", "FAKEkeyBodyNOTREAL"))


def test_eos_management_fields_are_selective_and_heredoc_stays_opaque():
    marker = module().EOS_MARKER
    raw = ("hostname h1\n!\nmanagement api http-commands\n   protocol https\n   !\n   vrf MGMT\n      no shutdown\n!\n"
           "event-handler h\n   action bash\nhostname FAKEscriptNOTREAL\n      EOF\n   delay 5\n!\nend\n").encode("ascii")
    text, count, summary, rendered = accepted("eos", raw)
    assert text == ("hostname h1\n!\nmanagement api http-commands\n" + marker + "\n"
                    "   !\n   vrf MGMT\n      no shutdown\n!\n" + (marker + "\n") * 5 + "!\nend\n")
    assert_no_secret(rendered, ("FAKEscriptNOTREAL",))
    raw = b"hostname h1\n!\nevent-handler h\n   action bash\n      FAKEopenScriptNOTREAL\n!\nend\n"
    rendered = refused("eos", raw, "stream-incomplete")
    assert_no_secret(rendered, ("FAKEopenScriptNOTREAL",))


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_open_quoted_value_is_one_opaque_record(dialect):
    marker = redactor_class(dialect).MARKER
    head = NXOS_HEAD if dialect == "nxos" else ""
    tail = "" if dialect == "nxos" else "end\n"
    raw = (head + 'alias exec x "FAKEquoteNOTREAL\nhostname leak\nstill" open\nhostname h1\n' + tail).encode("ascii")
    text, count, summary, rendered = accepted(dialect, raw)
    assert text == head + (marker + "\n") * 3 + "hostname h1\n" + tail
    assert count == 1 and summary["unsupported_format_count"] == 1
    raw = (head + 'alias exec x "FAKEquoteNOTREAL\nhostname leak\n' + tail).encode("ascii")
    rendered = refused(dialect, raw, "stream-incomplete")
    assert_no_secret(rendered, ("FAKEquoteNOTREAL",))


# ---------------------------------------------------------------------------------------------
# stream completeness and refusals
# ---------------------------------------------------------------------------------------------

def test_nxos_requires_the_command_header():
    refused("nxos", b"hostname h1\ninterface mgmt0\n", "redaction-unverifiable")
    refused("nxos", b"!Command: show running-config all\nhostname h1\n", "redaction-unverifiable")
    refused("nxos", b"!Time: Sat Nov 14 10:05:31 2026\n!Command: show running-config\n", "redaction-unverifiable")
    refused("nxos", b"", "stream-incomplete")
    refused("nxos", b"\n\n", "stream-incomplete")
    text, count, summary, rendered = accepted("nxos", b"\r\n!Command: show running-config\r\n")
    assert text == "\r\n!Command: show running-config\r\n" and count == 0


@pytest.mark.parametrize("data", [b"!Command: show running-config\nhostname h1",
                                  b"!Command: show running-config\nhostname h1\n  ",
                                  b"!Command: show running-config\nhostname FAKEtruncNOTREAL"])
def test_nxos_unterminated_last_line_is_incomplete(data):
    rendered = refused("nxos", data, "stream-incomplete")
    assert_no_secret(rendered, ("FAKEtruncNOTREAL",))


def test_nxos_trailing_cr_terminates_the_last_line():
    text, count, summary, rendered = accepted("nxos", b"!Command: show running-config\rhostname h1\r")
    assert text == "!Command: show running-config\rhostname h1\r"


def test_eos_requires_end_and_nothing_after_it():
    refused("eos", b"hostname h1\n!\n", "stream-incomplete")
    refused("eos", b"hostname h1\n!\n   end\n", "stream-incomplete")
    refused("eos", b"", "stream-incomplete")
    refused("eos", b"hostname h1\nend\nhostname h2\n", "redaction-unverifiable")
    text, count, summary, rendered = accepted("eos", b"hostname h1\nend\n\n")
    assert text == "hostname h1\nend\n\n"
    text, count, summary, rendered = accepted("eos", b"hostname h1\nend")
    assert text == "hostname h1\nend"


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
@pytest.mark.parametrize("line", ["\thostname h1", "  \tdescription x", "hostname h1 --More-- ",
                                  "hostname h1\x00", "hostname h1\x1b[0m"])
def test_unsupported_input_refuses_the_stream(dialect, line):
    head = NXOS_HEAD if dialect == "nxos" else ""
    raw = (head + "interface Ethernet1\n" + line + "\nend\n").encode("ascii")
    refused(dialect, raw, "redaction-unverifiable")


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_device_error_line_is_a_refusal(dialect):
    head = NXOS_HEAD if dialect == "nxos" else ""
    raw = (head + "% Invalid command at '^' marker.\nend\n").encode("ascii")
    outcome, text, count, hidden, summary, rendered = capture(dialect, raw)
    assert outcome == "ConfigurationRefusedError"


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_invalid_utf8_and_deep_nesting_are_refused(dialect):
    head = NXOS_HEAD if dialect == "nxos" else ""
    refused(dialect, (head + "hostname h1\n").encode("ascii") + b"\xc3\n", "redaction-unverifiable")
    refused(dialect, (head + "hostname h1\n").encode("ascii") + b"\xc3", "stream-incomplete")
    deep = "".join(" " * level + "x\n" for level in range(70))
    refused(dialect, (head + deep + "end\n").encode("ascii"), "redaction-unverifiable")


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_limits_are_enforced(dialect):
    head = NXOS_HEAD if dialect == "nxos" else ""
    limits = ConfigurationLimits(physical_line_bytes=64, logical_record_bytes=128, all_bytes=4096,
                                 section_bytes=4096)
    refused(dialect, (head + "hostname " + "a" * 100 + "\n").encode("ascii"), "capture-limit-exceeded",
            limits=limits)
    refused(dialect, (head + "hostname h1\n" * 400).encode("ascii"), "capture-limit-exceeded", limits=limits)
    if dialect == "eos":
        banner = "banner motd\n" + "FAKEbannerLineNOTREAL\n" * 8 + "EOF\nend\n"
    else:
        banner = "banner motd #\n" + "FAKEbannerLineNOTREAL\n" * 8 + "#\n"
    rendered = refused(dialect, (head + banner).encode("ascii"), "capture-limit-exceeded", limits=limits)
    assert_no_secret(rendered, ("FAKEbannerLineNOTREAL",))


@pytest.mark.parametrize("dialect", ["nxos", "eos"])
def test_feed_after_finish_or_close_is_refused(dialect):
    cls = redactor_class(dialect)
    redactor = cls((), "all")
    head = NXOS_HEAD if dialect == "nxos" else "end\n"
    redactor.feed(head.encode("ascii"))
    redactor.finish()
    with pytest.raises(configuration.ConfigurationRedactionError):
        redactor.feed(b"hostname h1\n")
    redactor = cls((), "all")
    redactor.close()
    with pytest.raises(configuration.ConfigurationRedactionError):
        redactor.finish()
