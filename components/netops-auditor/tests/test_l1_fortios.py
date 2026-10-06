from pathlib import Path

import pytest

from netops_auditor.l1_fortios import ParseError, TruncatedError, parse, tokenize

FIXTURES = Path(__file__).parent / "fixtures"


def load(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_sections_entries_and_paths():
    root = parse(load("fortios_clean.conf"))
    policy = root.section("firewall policy").entries["1"]
    assert policy.path == ("firewall policy", "1")
    assert policy.value("name") == "lan-to-wan"
    assert root.section("system interface").entries["wan1"].value("role") == "wan"


def test_every_attribute_carries_its_line():
    text = load("fortios_clean.conf")
    root = parse(text)
    policy = root.section("firewall policy").entries["1"]
    line = policy.line_of("utm-status")
    assert text.splitlines()[line - 1].strip() == "set utm-status enable"


def test_multi_token_value_keeps_tokens():
    root = parse(load("fortios_clean.conf"))
    wan = root.section("system interface").entries["wan1"]
    assert wan.values("ip") == ("192.0.2.1", "255.255.255.0")
    internal = root.section("system interface").entries["internal"]
    assert internal.values("allowaccess") == ("ping", "https", "ssh")


def test_quoted_value_spanning_lines_is_one_attribute():
    root = parse(load("fortios_clean.conf"))
    address = root.section("firewall address").entries["lan-net"]
    assert address.value("comment") == "site\nlocal network"


def test_nested_config_inside_entry():
    root = parse(load("fortios_clean.conf"))
    ntp = root.section("system ntp")
    assert ntp.value("ntpsync") == "enable"
    assert ntp.section("ntpserver").entries["1"].value("server") == "ntp.example.invalid"


def test_unset_attribute_has_no_value():
    root = parse(load("fortios_clean.conf"))
    policy = root.section("firewall policy").entries["1"]
    assert policy.value("comments") is None
    assert policy.values("comments") == ()
    assert policy.line_of("comments") is not None


def test_unterminated_block_is_parse_error():
    with pytest.raises(ParseError) as error:
        parse("config firewall policy\n    edit 1\n        set name \"x\"\n    next\n")
    assert "line 1" in str(error.value)


def test_end_outside_block_is_parse_error():
    with pytest.raises(ParseError):
        parse("end\n")


def test_unterminated_quote_is_parse_error():
    with pytest.raises(ParseError):
        parse("config firewall address\n    edit \"broken\n")


def test_tokenize_keeps_empty_quoted_value():
    assert tokenize('set comment ""') == ["set", "comment", ""]
    assert tokenize('set name "a b"') == ["set", "name", "a b"]
    assert tokenize('set name "say \\"hi\\""') == ["set", "name", 'say "hi"']


REPEATED_SECTION = """config firewall address
    edit "a1"
        set subnet 192.0.2.0 255.255.255.0
    next
end
config system global
    set hostname "fw-example"
end
config firewall address
    edit "a2"
        set subnet 198.51.100.0 255.255.255.0
    next
end
"""

REPEATED_VDOM = """config vdom
edit root
next
edit lab
next
end
config global
config system global
    set hostname "fw-example"
end
end
config vdom
edit root
config log syslogd setting
    set status enable
end
next
end
config vdom
edit root
config system interface
    edit "wan1"
        set role wan
    next
end
next
end
"""

REPEATED_EDIT = """config firewall address
    edit "a1"
        set subnet 192.0.2.0 255.255.255.0
        set comment "first"
    next
end
config firewall address
    edit "a1"
        set comment "second"
        set color 6
    next
end
"""


def test_repeated_section_keeps_both_entries():
    root = parse(REPEATED_SECTION)
    assert list(root.section("firewall address").entries) == ["a1", "a2"]
    assert root.section("system global").value("hostname") == "fw-example"


def test_repeated_vdom_blocks_sum_their_entries():
    root = parse(REPEATED_VDOM)
    vdom = root.section("vdom")
    assert list(vdom.entries) == ["root", "lab"]
    assert vdom.line == 1


def test_repeated_vdom_block_merges_nested_sections():
    root = parse(REPEATED_VDOM)
    entry = root.section("vdom").entries["root"]
    assert entry.section("system interface").entries["wan1"].value("role") == "wan"
    assert entry.section("log syslogd setting").value("status") == "enable"


def test_repeated_edit_merges_attributes_and_keeps_the_first_line():
    entry = parse(REPEATED_EDIT).section("firewall address").entries["a1"]
    assert entry.values("subnet") == ("192.0.2.0", "255.255.255.0")
    assert entry.value("comment") == "second"
    assert entry.value("color") == "6"
    assert entry.line == 2
    assert entry.line_of("comment") == REPEATED_EDIT.splitlines().index('        set comment "second"') + 1


DEVICE_VDOM = """#config-version=FGVMK6-8.0.0-FW-build0167-260420:opmode=0:vdom=1:user=x
#conf_file_ver=1
#buildno=0167
#global_vdom=1
config vdom
edit root
next
edit VD1
next
end
config global
config system global
    set hostname "fw-example"
end
end
config vdom
edit root
config system settings
    set opmode nat
end
config firewall address
    edit "a1"
        set subnet 192.0.2.0 255.255.255.0
    next
end
end
config vdom
edit VD1
config system settings
    set opmode nat
end
end
"""


def test_vdom_block_closed_by_end_as_fortios_prints_it():
    root = parse(DEVICE_VDOM)
    vdom = root.section("vdom")
    assert sorted(vdom.entries) == ["VD1", "root"]
    assert vdom.entries["root"].section("firewall address").entries["a1"].value("subnet") == "192.0.2.0 255.255.255.0"
    assert vdom.entries["VD1"].section("system settings").value("opmode") == "nat"
    assert root.section("global").section("system global").value("hostname") == "fw-example"
    assert root.section("system settings") is None


def test_vdom_block_closed_by_end_equals_the_form_with_next():
    with_next = """config vdom
edit root
next
edit VD1
next
end
config global
config system global
    set hostname "fw-example"
end
end
config vdom
edit root
config system settings
    set opmode nat
end
config firewall address
    edit "a1"
        set subnet 192.0.2.0 255.255.255.0
    next
end
next
end
config vdom
edit VD1
config system settings
    set opmode nat
end
next
end
"""
    first, second = parse(DEVICE_VDOM), parse(with_next)
    assert sorted(first.section("vdom").entries) == sorted(second.section("vdom").entries)
    for name in ("root", "VD1"):
        assert sorted(first.section("vdom").entries[name].sub) == sorted(second.section("vdom").entries[name].sub)


def test_end_still_closes_one_level_for_an_entry_outside_the_vdom_block():
    with pytest.raises(TruncatedError):
        parse('config firewall address\n    edit "a1"\n        set subnet 192.0.2.0 255.255.255.0\nend\n')


def test_an_open_vdom_entry_at_the_end_of_the_text_is_still_truncated():
    with pytest.raises(TruncatedError):
        parse("config vdom\nedit root\nconfig system settings\n    set opmode nat\nend\n")
