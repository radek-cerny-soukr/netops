#!/usr/bin/env python3
"""Account and AAA credential lines in platform configuration text (verification-06).

Every credential below is synthetic and intentionally invalid (FAKE...NOTREAL);
none of it is a captured vendor configuration. The tests call the real public
``sanitize.redact`` and ``sanitize.redact_response`` (the latter is also the
persistent/canonical response path of the engine) without mocking any layer.
"""

from __future__ import annotations

import json

import pytest

from netops_helper.sanitize import redact, redact_response

FUNCTIONS = {"redact": redact, "redact_response": lambda text: redact_response(text, ())}

SHA512_HASH = "$6$FAKESALTNOTREAL$FAKEHASHPAYLOADsha512xNOTREAL"
TYPE5_HASH = "$5$FAKESALT5$FAKEHASHPAYLOADtype5xNOTREAL"
TYPE9_HASH = "$9$FAKESALT9$FAKEHASHPAYLOADtype9xNOTREAL"
TYPE7_VALUE = "0822FAKE7NOTREAL455D"

# (source line, every secret fragment that must vanish, safe context that must stay, exact result)
LEAK_CASES = {
    "user-privilege-secret-sha512": (
        f"username admin privilege 15 secret sha512 {SHA512_HASH}",
        (SHA512_HASH, "FAKEHASHPAYLOAD", "sha512xNOTREAL", "FAKESALTNOTREAL"),
        ("username admin", "privilege 15", "secret sha512"),
        "username admin privilege 15 secret sha512 <REDACTED>",
    ),
    "user-secret-sha512": (
        f"username admin secret sha512 {SHA512_HASH}",
        (SHA512_HASH, "FAKEHASHPAYLOAD", "sha512xNOTREAL"),
        # 1.0.8 hid the token after `secret` (here `sha512`) on a CLI line; the 1.0.8 floor keeps
        # that (review finding 2), the account rule hides the hash.
        ("username admin", "secret"),
        "username admin secret <REDACTED> <REDACTED>",
    ),
    "user-role-secret-sha512": (
        f"username ops role network-admin secret sha512 {SHA512_HASH}",
        (SHA512_HASH, "FAKEHASHPAYLOAD", "sha512xNOTREAL"),
        ("username ops", "role network-admin", "secret sha512"),
        "username ops role network-admin secret sha512 <REDACTED>",
    ),
    "user-privilege-role-secret-sha512": (
        f"username admin privilege 15 role network-admin secret sha512 {SHA512_HASH}",
        (SHA512_HASH, "FAKEHASHPAYLOAD", "sha512xNOTREAL"),
        ("username admin", "privilege 15", "role network-admin", "secret sha512"),
        "username admin privilege 15 role network-admin secret sha512 <REDACTED>",
    ),
    "user-privilege-secret-type5": (
        f"username admin privilege 15 secret 5 {TYPE5_HASH}",
        (TYPE5_HASH, "FAKEHASHPAYLOAD", "type5xNOTREAL"),
        ("username admin", "privilege 15", "secret 5"),
        "username admin privilege 15 secret 5 <REDACTED>",
    ),
    "user-privilege-secret-type9": (
        f"username admin privilege 15 secret 9 {TYPE9_HASH}",
        (TYPE9_HASH, "FAKEHASHPAYLOAD", "type9xNOTREAL"),
        ("username admin", "privilege 15", "secret 9"),
        "username admin privilege 15 secret 9 <REDACTED>",
    ),
    "user-role-password-type5": (
        f"username ops role network-operator password 5 {TYPE5_HASH}",
        (TYPE5_HASH, "FAKEHASHPAYLOAD", "type5xNOTREAL"),
        ("username ops", "role network-operator", "password 5"),
        "username ops role network-operator password 5 <REDACTED>",
    ),
    "user-privilege-password-type0": (
        "username helpdesk privilege 1 password 0 FAKEPLAINNOTREAL",
        ("FAKEPLAINNOTREAL", "PLAINNOTREAL"),
        ("username helpdesk", "privilege 1", "password 0"),
        "username helpdesk privilege 1 password 0 <REDACTED>",
    ),
    "tacacs-key-0": (
        "tacacs-server key 0 FAKETACACSKEYNOTREAL",
        ("FAKETACACSKEYNOTREAL", "KEYNOTREAL"),
        ("tacacs-server key 0",),
        "tacacs-server key 0 <REDACTED>",
    ),
    "tacacs-key-7": (
        f"tacacs-server key 7 {TYPE7_VALUE}",
        (TYPE7_VALUE, "FAKE7NOTREAL"),
        ("tacacs-server key 7",),
        "tacacs-server key 7 <REDACTED>",
    ),
    "tacacs-key-bare": (
        "tacacs-server key FAKETACACSKEYNOTREAL",
        ("FAKETACACSKEYNOTREAL", "KEYNOTREAL"),
        ("tacacs-server key",),
        "tacacs-server key <REDACTED>",
    ),
    "radius-key-0": (
        "radius-server key 0 FAKERADIUSKEYNOTREAL",
        ("FAKERADIUSKEYNOTREAL", "KEYNOTREAL"),
        ("radius-server key 0",),
        "radius-server key 0 <REDACTED>",
    ),
    "radius-key-7": (
        f"radius-server key 7 {TYPE7_VALUE}",
        (TYPE7_VALUE, "FAKE7NOTREAL"),
        ("radius-server key 7",),
        "radius-server key 7 <REDACTED>",
    ),
    "radius-key-bare": (
        "radius-server key FAKERADIUSKEYNOTREAL",
        ("FAKERADIUSKEYNOTREAL", "KEYNOTREAL"),
        ("radius-server key",),
        "radius-server key <REDACTED>",
    ),
    "radius-key-double-quoted-escaped": (
        'radius-server key "FAKEHEAD\\" FAKETAILNOTREAL" ',
        ("FAKEHEAD", "FAKETAILNOTREAL", "TAILNOTREAL"),
        ("radius-server key",),
        "radius-server key <REDACTED> ",
    ),
    "tacacs-key-single-quoted-spaces": (
        "tacacs-server key 0 'FAKEHEAD FAKETAILNOTREAL'",
        ("FAKEHEAD", "FAKETAILNOTREAL", "TAILNOTREAL"),
        ("tacacs-server key 0",),
        "tacacs-server key 0 <REDACTED>",
    ),
    "tacacs-key-escaped-space": (
        "tacacs-server key FAKEHEAD\\ FAKETAILNOTREAL",
        ("FAKEHEAD", "FAKETAILNOTREAL", "TAILNOTREAL"),
        ("tacacs-server key",),
        "tacacs-server key <REDACTED>",
    ),
    "radius-key-unclosed-quote": (
        'radius-server key "FAKEHEAD FAKETAILNOTREAL',
        ("FAKEHEAD", "FAKETAILNOTREAL", "TAILNOTREAL"),
        ("radius-server key",),
        "radius-server key <REDACTED>",
    ),
    "exos-configure-account-encrypted": (
        'configure account admin encrypted "$5$FAKEEXOSSALT$FAKEEXOSHASHPAYLOADNOTREAL"',
        ("FAKEEXOSSALT", "FAKEEXOSHASHPAYLOAD", "PAYLOADNOTREAL"),
        ("configure account admin encrypted",),
        "configure account admin encrypted <REDACTED>",
    ),
    "exos-configure-account-encrypted-bare": (
        "configure account ops encrypted FAKEEXOSBAREHASHNOTREAL",
        ("FAKEEXOSBAREHASHNOTREAL", "HASHNOTREAL"),
        ("configure account ops encrypted",),
        "configure account ops encrypted <REDACTED>",
    ),
    "exos-create-account-admin-encrypted": (
        'create account admin netadmin encrypted "FAKEEXOSCREATEADMINNOTREAL"',
        ("FAKEEXOSCREATEADMINNOTREAL", "ADMINNOTREAL"),
        ("create account admin netadmin encrypted",),
        "create account admin netadmin encrypted <REDACTED>",
    ),
    "exos-create-account-user-encrypted": (
        "create account user reader encrypted FAKEEXOSCREATEUSERNOTREAL",
        ("FAKEEXOSCREATEUSERNOTREAL", "USERNOTREAL"),
        ("create account user reader encrypted",),
        "create account user reader encrypted <REDACTED>",
    ),
}

NEIGHBOR_BEFORE = "interface Ethernet1\n   switchport access vlan 10"
NEIGHBOR_AFTER = "ip address 192.0.2.1/24\nrole network-admin"


def _assert_hidden(cleaned: str, hidden) -> None:
    for fragment in hidden:
        assert fragment not in cleaned, fragment
        # A JSON or escaped rendering must not carry it either.
        assert json.dumps(fragment)[1:-1] not in cleaned, fragment


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
@pytest.mark.parametrize("case", sorted(LEAK_CASES))
def test_credential_line_is_fully_redacted_and_line_bounded(name: str, case: str) -> None:
    source, hidden, visible, expected = LEAK_CASES[case]
    clean = FUNCTIONS[name]
    document = f"{NEIGHBOR_BEFORE}\n{source}\n{NEIGHBOR_AFTER}"
    cleaned = clean(document)
    _assert_hidden(cleaned, hidden)
    for context in visible:
        assert context in cleaned, context
    assert cleaned == f"{NEIGHBOR_BEFORE}\n{expected}\n{NEIGHBOR_AFTER}"
    # Standalone line and CRLF terminal output.
    assert clean(source) == expected
    crlf = clean(f"{NEIGHBOR_BEFORE}\r\n{source}\r\n{NEIGHBOR_AFTER}")
    _assert_hidden(crlf, hidden)
    # The terminal cleanup drops CR as a C0 control; the line content is what matters.
    assert crlf.replace("\r", "") == f"{NEIGHBOR_BEFORE}\n{expected}\n{NEIGHBOR_AFTER}"
    # Idempotent: a second pass changes nothing.
    assert clean(cleaned) == cleaned


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
@pytest.mark.parametrize("case", sorted(LEAK_CASES))
def test_credential_line_inside_json_and_nested_mcp_text(name: str, case: str) -> None:
    source, hidden, visible, expected = LEAK_CASES[case]
    clean = FUNCTIONS[name]
    text = f"{NEIGHBOR_BEFORE}\n{source}\n{NEIGHBOR_AFTER}"
    documents = (
        json.dumps({"output": text}),
        json.dumps({"output": source}),
        json.dumps({"result": {"content": [{"type": "text", "text": text}]}}),
        json.dumps({"result": {"content": [{"type": "text", "text": json.dumps({"output": text})}]}}),
        json.dumps([text]),
    )
    for document in documents:
        cleaned = clean(document)
        _assert_hidden(cleaned, hidden)
        for context in visible:
            assert context in cleaned, (context, cleaned)
        assert clean(cleaned) == cleaned


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
@pytest.mark.parametrize("case", ["user-privilege-secret-sha512", "user-role-secret-sha512", "tacacs-key-0",
                                  "radius-key-bare", "exos-configure-account-encrypted",
                                  "exos-create-account-user-encrypted"])
def test_json_structure_and_neighbors_survive(name: str, case: str) -> None:
    source, _, _, expected = LEAK_CASES[case]
    text = f"{NEIGHBOR_BEFORE}\n{source}\n{NEIGHBOR_AFTER}"
    cleaned = FUNCTIONS[name](json.dumps({"result": {"content": [{"type": "text", "text": text}]}}))
    assert json.loads(cleaned) == {
        "result": {"content": [{"type": "text", "text": f"{NEIGHBOR_BEFORE}\n{expected}\n{NEIGHBOR_AFTER}"}]}
    }


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_marked_snmp_document_path_also_redacts_account_lines(name: str) -> None:
    # An SNMP context forces redact() into the Marked span-carrying response chain.
    source = (
        "config system snmp community\n    edit 1\n        set name \"FAKECOMMUNITYNOTREAL\"\n    next\nend\n"
        f"username admin privilege 15 secret sha512 {SHA512_HASH}\n"
        "tacacs-server key 0 FAKETACACSKEYNOTREAL\n"
        "configure account admin encrypted FAKEEXOSBAREHASHNOTREAL\n"
        "ip address 192.0.2.1/24"
    )
    cleaned = FUNCTIONS[name](source)
    _assert_hidden(cleaned, ("FAKECOMMUNITYNOTREAL", SHA512_HASH, "FAKEHASHPAYLOAD",
                             "FAKETACACSKEYNOTREAL", "FAKEEXOSBAREHASHNOTREAL"))
    assert "username admin privilege 15 secret sha512 <REDACTED>\n" in cleaned
    assert "tacacs-server key 0 <REDACTED>\n" in cleaned
    assert "configure account admin encrypted <REDACTED>\n" in cleaned
    assert cleaned.endswith("\nip address 192.0.2.1/24")
    assert FUNCTIONS[name](cleaned) == cleaned


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_existing_credential_markers_stay_idempotent(name: str) -> None:
    source = (
        "username admin privilege 15 secret sha512 <REDACTED:credential#1>\n"
        "tacacs-server key 0 <REDACTED:credential#2>\n"
        "configure account admin encrypted <REDACTED:credential#3>"
    )
    assert FUNCTIONS[name](source) == source


HARMLESS = (
    "username admin sshkey ssh-rsa " + "AAAAB3NzaC1yc2EAAAADAQABAAABAQCfakePublicKeyNOTREAL admin@lab",
    "username admin role network-admin",
    "username admin privilege 15 role network-admin",
    "username ops nopassword",
    "ip ssh pubkey-chain",
    "  key-hash ssh-rsa 0123456789ABCDEF0123456789ABCDEF",
    "crypto key generate rsa modulus 2048",
    "-----BEGIN PUBLIC KEY-----",
    "tacacs-server host 192.0.2.10",
    "tacacs-server timeout 5",
    "radius-server host 192.0.2.11 auth-port 1812 acct-port 1813",
    "radius-server retransmit 3",
    "radius-server dead-criteria time 5",
    "configure account admin password-policy min-length 8",
    "create account user reader",
    "show account",
    "configure vlan lab add ports 1:1 untagged",
    "interface Ethernet1\n   switchport access vlan 10",
    "ip address 192.0.2.1/24",
    "role network-admin",
    "description key account username tacacs-server radius-server encrypted",
)


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_harmless_configuration_text_is_unchanged(name: str) -> None:
    document = "\n".join(HARMLESS)
    assert FUNCTIONS[name](document) == document
    for line in HARMLESS:
        assert FUNCTIONS[name](line) == line


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_credential_line_never_consumes_the_next_line(name: str) -> None:
    for source in ("tacacs-server key\nrole network-admin",
                   "username admin privilege 15 secret\nrole network-admin",
                   "configure account admin encrypted\nconfigure vlan lab tag 10"):
        assert FUNCTIONS[name](source) == source
    # A lone `0` may itself be the key; it is hidden, the next line is not touched.
    for source, expected in (
            ("radius-server key 0\nip address 192.0.2.1/24", "radius-server key <REDACTED>\nip address 192.0.2.1/24"),
            ('tacacs-server key "FAKEUNCLOSEDNOTREAL\nrole network-admin', "tacacs-server key <REDACTED>\nrole network-admin"),
            ("username admin secret 5 FAKEHEAD\\\nrole network-admin", "username admin secret 5 <REDACTED>\nrole network-admin")):
        assert FUNCTIONS[name](source) == expected


# Existing behavior that must not regress (protective checks, not new rules).
@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_existing_nxos_numeric_secret_and_plain_secret_paths(name: str) -> None:
    clean = FUNCTIONS[name]
    assert (clean(f"username admin password 5 {TYPE5_HASH} role network-admin")
            == "username admin password 5 <REDACTED> role network-admin")
    assert clean(f"username reader password 7 {TYPE7_VALUE}") == "username reader password 7 <REDACTED>"
    assert clean(f"username admin secret 9 {TYPE9_HASH}") == "username admin secret 9 <REDACTED>"
    assert clean(f"username admin secret 5 {TYPE5_HASH}") == "username admin secret 5 <REDACTED>"
    assert clean("username admin secret FAKEPLAINNOTREAL") == "username admin secret <REDACTED>"
    assert clean("enable secret 5 FAKEENABLENOTREAL") == "enable secret 5 <REDACTED>"
    assert (clean("radius-server host 192.0.2.9 key 7 FAKE0A1BNOTREAL")
            == "radius-server host 192.0.2.9 key 7 <REDACTED>")


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_existing_exos_community_path(name: str) -> None:
    cleaned = FUNCTIONS[name]("configure snmp add community readonly FAKECOMMUNITYNOTREAL\nshow vlan")
    assert "FAKECOMMUNITYNOTREAL" not in cleaned
    assert cleaned.startswith("configure snmp add community ")
    assert cleaned.endswith("\nshow vlan")


# Review finding N1: two account edits in one JSON string token around an original
# EXOS SNMP community span must not widen that span over harmless configuration.
REVIEW59_OUTPUT = (
    "configure account alice encrypted FAKEFIRSTNOTREAL\n"
    "configure vlan lab tag 10\n"
    "configure snmp add community readonly FAKECOMMUNITYNOTREAL\n"
    "configure vlan lab add ports 1:1 untagged\n"
    "configure account bob encrypted FAKESECONDNOTREAL"
)
REVIEW59_DOCUMENT = (
    '{"output":"configure account alice encrypted FAKEFIRSTNOTREAL\\nconfigure vlan lab tag 10\\n'
    'configure snmp add community readonly FAKECOMMUNITYNOTREAL\\nconfigure vlan lab add ports 1:1 untagged\\n'
    'configure account bob encrypted FAKESECONDNOTREAL","port":1}'
)
REVIEW59_HIDDEN = ("FAKEFIRSTNOTREAL", "FAKECOMMUNITYNOTREAL", "FAKESECONDNOTREAL")


class TestReview59SnmpSpan:
    @staticmethod
    def _assert_output(output: str) -> None:
        _assert_hidden(output, REVIEW59_HIDDEN)
        lines = output.split("\n")
        assert len(lines) == 5, lines
        assert lines[0] == "configure account alice encrypted <REDACTED>"
        assert lines[1] == "configure vlan lab tag 10"
        assert lines[2].startswith("configure snmp add community ")
        assert lines[3] == "configure vlan lab add ports 1:1 untagged"
        assert lines[4] == "configure account bob encrypted <REDACTED>"

    def test_exact_repro_input_is_the_synthetic_review_document(self) -> None:
        assert json.loads(REVIEW59_DOCUMENT) == {"output": REVIEW59_OUTPUT, "port": 1}

    @pytest.mark.parametrize("name", sorted(FUNCTIONS))
    def test_exact_repro_keeps_safe_lines_and_hides_all_values(self, name: str) -> None:
        clean = FUNCTIONS[name]
        cleaned = clean(REVIEW59_DOCUMENT)
        _assert_hidden(cleaned, REVIEW59_HIDDEN)
        decoded = json.loads(cleaned)
        assert sorted(decoded) == ["output", "port"]
        assert decoded["port"] == 1
        assert cleaned.endswith('","port":1}')
        self._assert_output(decoded["output"])
        assert clean(cleaned) == cleaned

    @pytest.mark.parametrize("name", sorted(FUNCTIONS))
    def test_nested_json_text_keeps_safe_lines_and_hides_all_values(self, name: str) -> None:
        clean = FUNCTIONS[name]
        wrapped = json.dumps({"result": {"content": [{"type": "text", "text": REVIEW59_DOCUMENT}]}})
        twice = json.dumps({"result": {"content": [{"type": "text", "text": wrapped}]}})
        for document, depth in ((wrapped, 1), (twice, 2)):
            cleaned = clean(document)
            _assert_hidden(cleaned, REVIEW59_HIDDEN)
            for fragment in REVIEW59_HIDDEN:
                assert json.dumps(json.dumps(fragment))[1:-1] not in cleaned, fragment
            inner = json.loads(cleaned)
            for _ in range(depth):
                assert list(inner) == ["result"]
                inner = json.loads(inner["result"]["content"][0]["text"])
            assert inner["port"] == 1
            assert sorted(inner) == ["output", "port"]
            self._assert_output(inner["output"])
            assert clean(cleaned) == cleaned

    @pytest.mark.parametrize("name", sorted(FUNCTIONS))
    def test_plain_text_of_same_lines_matches_json_output(self, name: str) -> None:
        clean = FUNCTIONS[name]
        plain = clean(REVIEW59_OUTPUT)
        self._assert_output(plain)
        assert json.loads(clean(REVIEW59_DOCUMENT))["output"] == plain
