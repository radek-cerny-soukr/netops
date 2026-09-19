from pathlib import Path

import pytest

from netops_auditor.l1_exos import NO_MODULE, ParseError, parse, tokenize

FIXTURES = Path(__file__).parent / "fixtures"

CLEAN = "exos_clean.conf"
CANARY = "secret_canary_exos.conf"


def load(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def commands_of(text):
    return parse(text).commands


def test_a_command_carries_its_line_module_tokens_and_text():
    text = load(CLEAN)
    telnet = [item for item in commands_of(text) if item.text == "disable telnet"]
    assert len(telnet) == 1
    entry = telnet[0]
    assert entry.module == "telnetd"
    assert entry.tokens == ("disable", "telnet")
    assert text.splitlines()[entry.line - 1] == "disable telnet"


def test_every_command_takes_the_module_declared_above_it():
    modules = {item.text: item.module for item in commands_of(load(CLEAN))}
    assert modules["configure sntp-client primary 192.0.2.1"] == "netTools"
    assert modules["configure syslog add 192.0.2.9 local1"] == "ems"
    assert modules['create vlan "OFFICE"'] == "vlan"


def test_the_modules_are_listed_once_in_the_order_of_the_dump():
    configuration = parse(load(CLEAN))
    assert configuration.modules == (
        "devmgr",
        "vlan",
        "aaa",
        "ems",
        "exsshd",
        "netTools",
        "snmpMaster",
        "telnetd",
    )
    assert len(set(configuration.modules)) == len(configuration.modules)


def test_a_command_before_any_module_header_carries_no_module():
    configuration = parse("enable ssh2\n#\n# Module vlan configuration.\n#\ncreate vlan v\n")
    assert [item.module for item in configuration.commands] == [NO_MODULE, "vlan"]


def test_a_comment_that_is_not_a_module_header_stays_a_comment():
    configuration = parse("#\n# a note about telnet\n#\ndisable telnet\n")
    assert configuration.modules == ()
    assert [item.text for item in configuration.commands] == ["disable telnet"]
    assert configuration.commands[0].module == NO_MODULE


def test_a_quoted_value_is_one_token_and_loses_its_quotes():
    configuration = parse('configure snmp sysLocation "Example Site"\n')
    assert configuration.commands[0].tokens == (
        "configure",
        "snmp",
        "sysLocation",
        "Example Site",
    )


def test_an_empty_quoted_value_is_an_empty_token():
    assert tokenize('configure snmp sysName ""') == ["configure", "snmp", "sysName", ""]


def test_an_unterminated_quote_is_a_parse_error():
    with pytest.raises(ParseError) as caught:
        parse('configure snmp sysName "open\n')
    assert "line 1" in str(caught.value)


def test_a_configuration_that_is_not_a_string_is_refused():
    with pytest.raises(ParseError):
        parse(b"disable telnet\n")


@pytest.mark.parametrize("name", (CLEAN, CANARY))
def test_the_parser_is_lossless(name):
    text = load(name)
    assert parse(text).serialize() == text


@pytest.mark.parametrize(
    "text",
    (
        "",
        "\n",
        "disable telnet",
        "disable telnet\n\n\n",
        "#\r\n# Module vlan configuration.\r\n#\r\ncreate vlan v\r\n",
        "   \n\tdisable telnet\t\n",
    ),
)
def test_the_parser_is_lossless_over_odd_input(text):
    assert parse(text).serialize() == text


def test_blank_and_comment_lines_are_not_commands():
    configuration = parse("#\n# Module vlan configuration.\n#\n\n   \ncreate vlan v\n")
    assert len(configuration.commands) == 1
    assert configuration.commands[0].line == 6


def test_matching_and_first_read_the_flat_list():
    configuration = parse(load(CLEAN))
    assert len(configuration.matching("configure", "vlan")) == 5
    assert configuration.first("enable", "ssh2").module == "exsshd"
    assert configuration.first("enable", "telnet") is None
    assert configuration.matching("enable", "telnet") == ()


def test_a_command_reads_its_argument_by_position():
    command = parse("configure sntp-client primary 192.0.2.1\n").commands[0]
    assert command.argument(3) == "192.0.2.1"
    assert command.argument(9) is None
    assert command.argument(-1) is None
