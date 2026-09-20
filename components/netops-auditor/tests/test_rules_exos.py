from pathlib import Path

import pytest

from netops_auditor import checks_exos
from netops_auditor.engine import load_catalog, registered_checks, run
from netops_auditor.l1_exos import parse

FIXTURES = Path(__file__).parent / "fixtures"
DEVICE = "sw-example"
PLATFORM = "exos"

SNTP_RULE = "exos.time.no-sntp-client"
SYSLOG_RULE = "exos.logging.no-syslog-target"
COMMUNITY_RULE = "exos.snmp.default-community"
TELNET_RULE = "exos.mgmt.telnet-enabled"

SNTP_BLOCK = "configure sntp-client primary 192.0.2.1\nenable sntp-client\n"
SYSLOG_LINE = "configure syslog add 192.0.2.9 local1\n"
COMMUNITY_LINE = "configure snmpv3 add community office-index name office-read user v1v2c_ro\n"
TELNET_LINE = "disable telnet\n"

MARKERS = tuple("KANARCI-TAJEMSTVI-EXOS-%02d" % number for number in range(1, 12))


def clean_text():
    return (FIXTURES / "exos_clean.conf").read_text(encoding="utf-8")


def canary_text():
    return (FIXTURES / "secret_canary_exos.conf").read_text(encoding="utf-8")


def audit(text):
    return run(parse(text), DEVICE, load_catalog(PLATFORM))


def mutate(text, old, new):
    assert text.count(old) == 1
    return text.replace(old, new)


def only_new(text):
    before = set(audit(clean_text()))
    new = [finding for finding in audit(text) if finding not in before]
    assert len(new) == 1
    return new[0]


def test_catalog_declares_every_check_of_the_module():
    rules = load_catalog(PLATFORM)
    declared = {rule.check for rule in rules}
    registered = set(registered_checks())
    assert declared <= registered
    assert {name for name in registered if hasattr(checks_exos, name)} == declared


def test_every_rule_of_the_catalog_is_a_fact():
    assert {rule.rule_class for rule in load_catalog(PLATFORM)} == {"fakt"}


def test_no_rule_of_the_catalog_gates_the_scope():
    assert [rule.id for rule in load_catalog(PLATFORM) if rule.scope_gate] == []


def test_every_rule_names_the_reference_of_the_running_release():
    for rule in load_catalog(PLATFORM):
        assert rule.refs
        for reference in rule.refs:
            assert reference.startswith("ExtremeXOS v33.7.1 Command References, chapter Commands:")
        assert rule.known_false_positives.strip()


def test_clean_fixture_yields_no_finding():
    assert audit(clean_text()) == ()


def test_a_configured_primary_server_alone_silences_the_time_rule():
    text = mutate(clean_text(), SNTP_BLOCK, "configure sntp-client primary 192.0.2.1\n")
    assert audit(text) == ()


def test_an_enabled_client_alone_silences_the_time_rule():
    text = mutate(clean_text(), SNTP_BLOCK, "enable sntp-client\n")
    assert audit(text) == ()


def test_a_primary_entry_without_a_host_does_not_silence_the_time_rule():
    text = mutate(clean_text(), SNTP_BLOCK, "configure sntp-client primary\n")
    assert only_new(text).rule_id == SNTP_RULE


def test_a_secondary_entry_alone_does_not_silence_the_time_rule():
    text = mutate(clean_text(), SNTP_BLOCK, "configure sntp-client secondary 192.0.2.1\n")
    assert only_new(text).rule_id == SNTP_RULE


def test_the_ntp_client_silences_the_time_rule():
    text = mutate(
        clean_text(),
        SNTP_BLOCK,
        "enable ntp vr VR-Default\nconfigure ntp server add 192.0.2.1\n",
    )
    assert audit(text) == ()


def test_an_enabled_ntp_client_alone_silences_the_time_rule():
    text = mutate(clean_text(), SNTP_BLOCK, "enable ntp vr VR-Default\n")
    assert audit(text) == ()


def test_a_configured_ntp_server_alone_silences_the_time_rule():
    text = mutate(clean_text(), SNTP_BLOCK, "configure ntp server add 192.0.2.1\n")
    assert audit(text) == ()


def test_an_ntp_server_entry_without_a_host_does_not_silence_the_time_rule():
    text = mutate(clean_text(), SNTP_BLOCK, "configure ntp server add\n")
    finding = only_new(text)
    assert finding.rule_id == SNTP_RULE
    assert dict(finding.evidence) == {"reason": "no command"}
    assert finding.line == 0


def test_no_time_client_at_all_is_still_one_finding():
    text = mutate(clean_text(), SNTP_BLOCK, "")
    finding = only_new(text)
    assert finding.rule_id == SNTP_RULE
    assert dict(finding.evidence) == {"reason": "no command"}


def test_a_missing_syslog_target_is_one_finding_without_a_line():
    finding = only_new(mutate(clean_text(), SYSLOG_LINE, ""))
    assert finding.rule_id == SYSLOG_RULE
    assert finding.object_key == "syslog"
    assert finding.line == 0


def test_a_target_without_a_host_does_not_silence_the_logging_rule():
    assert only_new(mutate(clean_text(), SYSLOG_LINE, "configure syslog add\n")).rule_id == (
        SYSLOG_RULE
    )


def test_the_log_target_command_does_not_silence_the_logging_rule():
    text = mutate(clean_text(), SYSLOG_LINE, "")
    assert "enable log target syslog" in text
    assert only_new(text).rule_id == SYSLOG_RULE


@pytest.mark.parametrize(
    "line,field",
    (
        ("configure snmp add community readonly public\n", "community string"),
        ("configure snmp add community readwrite private\n", "community string"),
        (
            "configure snmpv3 add community public name office-read user v1v2c_ro\n",
            "community index",
        ),
        (
            "configure snmpv3 add community office-index name private user v1v2c_ro\n",
            "community name",
        ),
        (
            "configure snmpv3 add community public name private user v1v2c_ro\n",
            "community index, community name",
        ),
    ),
)
def test_a_trivial_community_is_reported_by_the_field_that_holds_it(line, field):
    finding = only_new(mutate(clean_text(), COMMUNITY_LINE, COMMUNITY_LINE + line))
    assert finding.rule_id == COMMUNITY_RULE
    assert dict(finding.evidence)["field"] == field
    assert dict(finding.evidence)["dictionary"] == "trivial"


def test_the_community_itself_never_reaches_the_finding():
    line = "configure snmp add community readonly public\n"
    finding = only_new(mutate(clean_text(), COMMUNITY_LINE, COMMUNITY_LINE + line))
    rendered = "%s %s %s" % (finding.object_key, finding.section, dict(finding.evidence))
    assert "public" not in rendered
    assert dict(finding.evidence)["command"] == "configure snmp add community"


def test_the_dictionary_ignores_letter_case():
    line = "configure snmp add community readonly PuBLic\n"
    assert only_new(mutate(clean_text(), COMMUNITY_LINE, COMMUNITY_LINE + line)).rule_id == (
        COMMUNITY_RULE
    )


@pytest.mark.parametrize(
    "line",
    (
        "configure snmp add community readonly hex 70:75:62\n",
        "configure snmp add community readonly encrypted public\n",
        "configure snmpv3 add community hex 70:75:62 name office-read user v1v2c_ro\n",
        "configure snmpv3 add community office-index name hex 70:75:62 user v1v2c_ro\n",
        "configure snmp add community readonly\n",
    ),
)
def test_a_community_the_rule_cannot_read_plainly_is_not_compared(line):
    assert audit(mutate(clean_text(), COMMUNITY_LINE, COMMUNITY_LINE + line)) == ()


def test_two_trivial_communities_are_two_findings_keyed_by_their_order():
    text = mutate(
        clean_text(),
        COMMUNITY_LINE,
        COMMUNITY_LINE
        + "configure snmp add community readonly public\n"
        + "configure snmp add community readwrite private\n",
    )
    findings = audit(text)
    assert [finding.object_key for finding in findings] == [
        "snmp/community/2",
        "snmp/community/3",
    ]
    assert len({finding.fingerprint() for finding in findings}) == 2


def test_a_removed_disable_leaves_telnet_at_its_default():
    finding = only_new(mutate(clean_text(), TELNET_LINE, ""))
    assert finding.rule_id == TELNET_RULE
    assert dict(finding.evidence) == {"reason": "default enabled"}
    assert finding.line == 0


def test_an_explicit_enable_is_reported_with_its_line():
    text = mutate(clean_text(), TELNET_LINE, "enable telnet\n")
    finding = only_new(text)
    assert finding.rule_id == TELNET_RULE
    assert dict(finding.evidence) == {"reason": "explicitly enabled"}
    assert text.splitlines()[finding.line - 1] == "enable telnet"


def test_the_last_telnet_command_of_the_flat_list_decides():
    enabled = mutate(clean_text(), TELNET_LINE, "disable telnet\nenable telnet\n")
    assert only_new(enabled).rule_id == TELNET_RULE
    disabled = mutate(clean_text(), TELNET_LINE, "enable telnet\ndisable telnet\n")
    assert audit(disabled) == ()


def test_the_canary_is_audited_and_carries_no_secret_into_a_finding():
    text = canary_text()
    for marker in MARKERS:
        assert text.count(marker) == 1
    findings = audit(text)
    assert len(findings) >= 1
    rendered = "\n".join(str(finding.as_dict()) for finding in findings)
    for marker in MARKERS:
        assert marker not in rendered
