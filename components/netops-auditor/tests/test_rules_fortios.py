from pathlib import Path

import pytest

from netops_auditor import checks_fortios
from netops_auditor.engine import CheckError, Rule, load_catalog, registered_checks, run
from netops_auditor.l1_fortios import parse

FIXTURES = Path(__file__).parent / "fixtures"
TENANT = "tenant-rules"
DEVICE = "fw-example"
VDOM_RULE = "fortios.scope.vdom-unsupported"

SDWAN_BLOCK = '''config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set interface "wan1"
        next
    end
end
'''

SCHEDULE_GROUP_BLOCK = '''config firewall schedule group
    edit "night-shift"
        set member "always"
    next
end
'''

NTPSERVER_BLOCK = '''    config ntpserver
        edit 1
            set server "ntp.example.invalid"
        next
    end
'''


def clean_text():
    return (FIXTURES / "fortios_clean.conf").read_text(encoding="utf-8")


def audit(text):
    return run(parse(text), TENANT, DEVICE, load_catalog("fortios"))


def mutate(text, old, new):
    assert text.count(old) == 1
    return text.replace(old, new)


def wrapped_in_vdom(text):
    return "config vdom\nedit root\n" + text + "next\nend\n"


def rule_for(check_name, evidence_fields, scope_gate=False):
    return Rule(
        id="test.%s" % check_name,
        version=1,
        check=check_name,
        rule_class="fakt",
        severity="medium",
        evidence_fields=evidence_fields,
        title="",
        remediation="",
        refs=(),
        known_false_positives="",
        scope_gate=scope_gate,
    )


def line_of(text, content):
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip() == content:
            return number
    raise AssertionError("not in text: %s" % content)


def single_new_finding(text):
    before = set(audit(clean_text()))
    new = [finding for finding in audit(text) if finding not in before]
    assert len(new) == 1
    return new[0]


def test_clean_fixture_yields_no_finding():
    assert audit(clean_text()) == ()


def test_catalog_declares_every_registered_check():
    rules = load_catalog("fortios")
    declared = {rule.check for rule in rules}
    registered = set(registered_checks())
    assert declared <= registered
    assert {name for name in registered if hasattr(checks_fortios, name)} == declared


def test_every_rule_names_the_reference_of_the_running_release():
    for rule in load_catalog("fortios"):
        assert rule.refs
        for reference in rule.refs:
            assert reference.startswith("FortiOS 8.0.0 CLI Reference: config ")
        assert rule.known_false_positives.strip()


def test_dangling_reference_reports_the_missing_object():
    text = mutate(clean_text(), 'set srcaddr "lan-net"', 'set srcaddr "lan-net-typo"')
    finding = single_new_finding(text)
    assert finding.rule_id == "fortios.ref.dangling"
    assert finding.object_key == "firewall policy/1/srcaddr/lan-net-typo"
    assert finding.line == line_of(text, 'set srcaddr "lan-net-typo"')
    assert dict(finding.evidence) == {"policy": "1", "attribute": "srcaddr", "value": "lan-net-typo"}


def test_admin_access_on_wan_interface_is_reported():
    text = mutate(clean_text(), "set allowaccess ping\n", "set allowaccess ping https\n")
    finding = single_new_finding(text)
    assert finding.rule_id == "fortios.mgmt.wan-admin-access"
    assert finding.object_key == "system interface/wan1"
    assert finding.line == line_of(text, "set allowaccess ping https")
    assert dict(finding.evidence) == {"interface": "wan1", "services": "https"}


def test_utm_without_ssl_profile_is_reported():
    text = mutate(clean_text(), '        set ssl-ssh-profile "certificate-inspection"\n', "")
    finding = single_new_finding(text)
    assert finding.rule_id == "fortios.policy.utm-without-ssl"
    assert finding.object_key == "firewall policy/1"
    assert finding.line == line_of(text, "set utm-status enable")


def test_no_syslog_target_is_reported():
    text = mutate(clean_text(), "set status enable", "set status disable")
    finding = single_new_finding(text)
    assert finding.rule_id == "fortios.logging.no-syslog-target"
    assert finding.object_key == "log syslogd setting"
    assert finding.line == line_of(text, "set status disable")
    assert dict(finding.evidence) == {"reason": "status not enable"}


def test_no_ntp_sync_is_reported():
    text = mutate(clean_text(), "set ntpsync enable", "set ntpsync disable")
    finding = single_new_finding(text)
    assert finding.rule_id == "fortios.time.no-ntp-sync"
    assert finding.object_key == "system ntp"
    assert finding.line == line_of(text, "set ntpsync disable")
    assert dict(finding.evidence) == {"reason": "ntpsync not enable"}


def test_ntpserver_entry_without_an_address_is_reported():
    text = mutate(clean_text(), "set ntpsync enable", "set ntpsync enable\n    set type custom")
    text = mutate(text, 'set server "ntp.example.invalid"', "set ntpv3 enable")
    finding = single_new_finding(text)
    assert finding.rule_id == "fortios.time.no-ntp-sync"
    assert finding.object_key == "system ntp"
    assert finding.line == line_of(text, "config ntpserver")
    assert dict(finding.evidence) == {"reason": "no ntp server"}


def test_custom_ntp_without_a_server_section_is_reported():
    text = mutate(clean_text(), "set ntpsync enable", "set ntpsync enable\n    set type custom")
    text = mutate(text, NTPSERVER_BLOCK, "")
    finding = single_new_finding(text)
    assert finding.rule_id == "fortios.time.no-ntp-sync"
    assert finding.line == line_of(text, "config system ntp")
    assert dict(finding.evidence) == {"reason": "no ntp server"}


def test_ntp_without_type_and_without_servers_is_not_reported():
    text = mutate(clean_text(), NTPSERVER_BLOCK, "    set server-mode enable\n")
    assert audit(text) == ()


def test_sdwan_zone_counts_as_a_known_interface():
    text = mutate(clean_text(), 'set dstintf "wan1"', 'set dstintf "virtual-wan-link"')
    finding = single_new_finding(text)
    assert finding.rule_id == "fortios.ref.dangling"
    assert finding.object_key == "firewall policy/1/dstintf/virtual-wan-link"
    assert audit(text + SDWAN_BLOCK) == ()


def test_sdwan_member_sequence_is_not_an_interface_name():
    text = mutate(clean_text(), 'set dstintf "wan1"', 'set dstintf "1"') + SDWAN_BLOCK
    finding = single_new_finding(text)
    assert finding.rule_id == "fortios.ref.dangling"
    assert finding.object_key == "firewall policy/1/dstintf/1"


def test_schedule_group_counts_as_a_known_schedule():
    text = mutate(clean_text(), 'set schedule "always"', 'set schedule "night-shift"')
    finding = single_new_finding(text)
    assert finding.rule_id == "fortios.ref.dangling"
    assert finding.object_key == "firewall policy/1/schedule/night-shift"
    assert audit(text + SCHEDULE_GROUP_BLOCK) == ()


def test_vdom_configuration_yields_only_the_scope_finding():
    text = wrapped_in_vdom(clean_text())
    findings = audit(text)
    assert [finding.rule_id for finding in findings] == [VDOM_RULE]
    assert findings[0].object_key == "vdom"
    assert findings[0].line == line_of(text, "config vdom")
    assert findings[0].severity == "high"
    assert dict(findings[0].evidence) == {"vdoms": 1}


def test_scope_finding_counts_the_vdoms_of_every_block():
    text = "config vdom\nedit root\nnext\nedit lab\nnext\nend\n" + wrapped_in_vdom(clean_text())
    findings = audit(text)
    assert [finding.rule_id for finding in findings] == [VDOM_RULE]
    assert findings[0].line == 1
    assert dict(findings[0].evidence) == {"vdoms": 2}


def test_scope_gate_rule_silences_the_other_rules():
    tree = parse(wrapped_in_vdom(clean_text()))
    gate = rule_for("vdom_unsupported", ("vdoms",), scope_gate=True)
    other = rule_for("no_syslog_target", ("reason",))
    assert [finding.rule_id for finding in run(tree, TENANT, DEVICE, (other, gate))] == ["test.vdom_unsupported"]


def test_without_the_scope_gate_flag_every_rule_runs():
    tree = parse(wrapped_in_vdom(clean_text()))
    gate = rule_for("vdom_unsupported", ("vdoms",))
    other = rule_for("no_syslog_target", ("reason",))
    reported = [finding.rule_id for finding in run(tree, TENANT, DEVICE, (other, gate))]
    assert reported == ["test.no_syslog_target", "test.vdom_unsupported"]


def test_scope_gate_without_a_finding_lets_the_other_rules_run():
    tree = parse(mutate(clean_text(), "set ntpsync enable", "set ntpsync disable"))
    gate = rule_for("vdom_unsupported", ("vdoms",), scope_gate=True)
    other = rule_for("no_ntp_sync", ("reason",))
    assert [finding.rule_id for finding in run(tree, TENANT, DEVICE, (gate, other))] == ["test.no_ntp_sync"]


def test_checks_carry_no_gate_of_their_own():
    tree = parse(wrapped_in_vdom(clean_text()))
    hits = list(checks_fortios.no_syslog_target(tree))
    assert [hit["evidence"]["reason"] for hit in hits] == ["section missing"]
    assert [finding.rule_id for finding in audit(wrapped_in_vdom(clean_text()))] == [VDOM_RULE]


def test_vdom_configuration_with_a_defect_still_yields_only_the_scope_finding():
    broken = mutate(clean_text(), "set allowaccess ping\n", "set allowaccess ping https\n")
    assert [finding.rule_id for finding in audit(broken)] == ["fortios.mgmt.wan-admin-access"]
    assert [finding.rule_id for finding in audit(wrapped_in_vdom(broken))] == [VDOM_RULE]


def test_configuration_without_vdoms_has_no_scope_finding():
    text = mutate(clean_text(), "set allowaccess ping\n", "set allowaccess ping https\n")
    assert [finding.rule_id for finding in audit(text)] == ["fortios.mgmt.wan-admin-access"]
    assert [finding.rule_id for finding in audit(clean_text())] == []


def test_object_key_survives_unrelated_change():
    broken = mutate(clean_text(), 'set srcaddr "lan-net"', 'set srcaddr "lan-net-typo"')
    first = single_new_finding(broken)
    renamed = mutate(broken, 'set name "lan-to-wan"', 'set name "lan-to-internet"')
    shifted = "# exported for review\n" + renamed
    second = single_new_finding(shifted)
    assert second.object_key == first.object_key
    assert second.fingerprint() == first.fingerprint()
    assert second.line == first.line + 1


def test_undeclared_evidence_is_refused():
    text = mutate(clean_text(), 'set srcaddr "lan-net"', 'set srcaddr "lan-net-typo"')
    rule = Rule(
        id="fortios.ref.dangling",
        version=1,
        check="dangling_reference",
        rule_class="fakt",
        severity="high",
        evidence_fields=(),
        title="",
        remediation="",
        refs=(),
        known_false_positives="",
    )
    with pytest.raises(CheckError):
        run(parse(text), TENANT, DEVICE, (rule,))
