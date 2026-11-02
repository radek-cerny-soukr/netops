import re
from pathlib import Path

import pytest

from netops_auditor import checks_fortios  # noqa: F401
from netops_auditor.engine import EVALUATED, NOT_EVALUATED, evaluate, load_catalog, run
from netops_auditor.l1_fortios import parse

FIXTURES = Path(__file__).parent / "fixtures"
DOC = Path(__file__).parent.parent / "docs" / "cis-mapping.md"
CLEAN = (FIXTURES / "fortios_clean.conf").read_text(encoding="utf-8")
RULES = tuple(r for r in load_catalog("fortios") if ".management." not in r.id)

PW = "fortios.mgmt.password-policy"
CPU = "fortios.logging.single-cpu-high"
HOST = "fortios.mgmt.gui-display-hostname"
ADM = "fortios.mgmt.admin-no-trusthost"
EVT = "fortios.logging.event-disabled"
FAZ = "fortios.logging.faz-unencrypted"
SSL = "fortios.vpn.ssl-legacy-tls"
AV = "fortios.av.detection-disabled"
POL = "fortios.policy.wan-missing-profile"
DNS = "fortios.dnsfilter.log-all-domain-disabled"
APP = "fortios.appctrl.default-port-not-enforced"
SLICE_ONE = (PW, CPU, HOST, ADM, EVT, FAZ, SSL, AV)
NEW = SLICE_ONE + (POL, DNS, APP)
EV, NE = EVALUATED, NOT_EVALUATED


def go(text):
    findings, states = evaluate(parse(text), "t", "d", RULES)
    return findings, states


def keys(findings, rule_id):
    return sorted(f.object_key for f in findings if f.rule_id == rule_id)


def sub(old, new, text=CLEAN):
    assert text.count(old) == 1, old
    return text.replace(old, new)


def no_global():
    return sub(
        'config system global\n    set hostname "fw-example"\n    set timezone "04"\n    set log-single-cpu-high enable\n    set ssl-static-key-ciphers disable\nend\n',
        "",
    )


FAZ_ON = 'config log fortianalyzer setting\n    set status enable\n    set reliable enable\n    set enc-algorithm high\nend\n'
SSL_ON = "config vpn ssl settings\n    set ssl-min-proto-ver tls1-2\n    set ssl-max-proto-ver tls1-3\n    set algorithm high\nend\n"


def test_clean_is_evaluated_and_silent_for_every_new_rule():
    findings, states = go(CLEAN)
    assert findings == ()
    for rule_id in NEW:
        assert states[rule_id] == (EV, "")


@pytest.mark.parametrize("rule_id", SLICE_ONE)
def test_missing_system_global_is_not_evaluated(rule_id):
    findings, states = go(no_global())
    assert states[rule_id] == (NE, "section-missing: system global")
    assert [f for f in findings if f.rule_id == rule_id] == []


def test_slice_two_does_not_need_system_global():
    _, states = go(no_global())
    for rule_id in (POL, DNS, APP):
        assert states[rule_id][0] == EV


def test_password_policy_aspects():
    text = sub("minimum-length 14", "minimum-length 13")
    assert keys(go(text)[0], PW) == ["length"]
    text = sub("apply-to admin-password ipsec-preshared-key", "apply-to admin-password")
    assert keys(go(text)[0], PW) == ["scope"]
    text = sub("    set status enable\n    set apply-to", "    set status disable\n    set apply-to")
    assert keys(go(text)[0], PW) == ["status"]
    text = sub("minimum-length 14", "minimum-length abc")
    assert go(text)[1][PW] == (NE, "value-not-numeric")
    text = sub("    set status enable\n    set apply-to", "    set status maybe\n    set apply-to")
    assert go(text)[1][PW] == (NE, "value-not-recognized")


def test_password_policy_default_status_differs_by_release():
    text = sub("    set status enable\n    set apply-to", "    set apply-to")
    assert go(text)[1][PW] == (NE, "default-differs-by-release")
    text = sub("minimum-length 14", "minimum-length 8", text)
    assert keys(go(text)[0], PW) == ["length"]


def test_password_policy_missing_section_reports_length_only_when_status_is_default():
    text = sub(
        "config system password-policy\n    set status enable\n    set apply-to admin-password ipsec-preshared-key\n    set minimum-length 14\nend\n",
        "",
    )
    findings, states = go(text)
    assert states[PW][0] == EV
    assert keys(findings, PW) == ["length", "scope"]


def test_single_cpu_high_and_hostname_flags():
    assert keys(go(sub("log-single-cpu-high enable", "log-single-cpu-high disable"))[0], CPU) == ["log-single-cpu-high"]
    assert keys(go(sub("    set log-single-cpu-high enable\n", ""))[0], CPU) == ["log-single-cpu-high"]
    assert go(sub("log-single-cpu-high enable", "log-single-cpu-high bogus"))[1][CPU] == (NE, "value-not-recognized")
    shown = sub("    set log-single-cpu-high enable\n", "    set log-single-cpu-high enable\n    set gui-display-hostname enable\n")
    assert keys(go(shown)[0], HOST) == ["gui-display-hostname"]
    assert go(sub("    set log-single-cpu-high enable\n", "    set log-single-cpu-high enable\n    set gui-display-hostname x\n"))[1][HOST] == (NE, "value-not-recognized")


def test_admin_no_trusthost_cases():
    assert keys(go(sub("        set ip6-trusthost1 2001:db8::/32\n", ""))[0], ADM) == ["system admin/netadmin"]
    findings = go(sub("        set trusthost1 192.0.2.0 255.255.255.0\n", ""))[0]
    assert [dict(f.evidence)["unrestricted"] for f in findings if f.rule_id == ADM] == ["ipv4"]
    wildcard = sub("trusthost1 192.0.2.0 255.255.255.0", "trusthost1 0.0.0.0 0.0.0.0")
    assert keys(go(wildcard)[0], ADM) == ["system admin/netadmin"]
    assert go(sub("trusthost1 192.0.2.0 255.255.255.0", "trusthost1 192.0.2.0/24"))[0] == ()
    assert go(sub("trusthost1 192.0.2.0 255.255.255.0", "trusthost1 nonsense"))[1][ADM] == (NE, "value-not-recognized")


def test_admin_missing_section_is_not_evaluated():
    text = sub('config system admin\n    edit "netadmin"\n        set accprofile "super_admin"\n        set trusthost1 192.0.2.0 255.255.255.0\n        set ip6-trusthost1 2001:db8::/32\n    next\nend\n', "")
    assert go(text)[1][ADM] == (NE, "section-missing: system admin")


def test_event_filter_reports_each_explicit_disable():
    text = CLEAN + "config log eventfilter\n    set event enable\n    set system disable\n    set vpn disable\n    set user enable\nend\n"
    assert keys(go(text)[0], EVT) == ["system", "vpn"]


def test_fortianalyzer_targets():
    assert go(CLEAN + FAZ_ON)[0] == ()
    weak = CLEAN + FAZ_ON.replace("reliable enable", "reliable disable").replace("high", "low")
    assert keys(go(weak)[0], FAZ) == [
        "log fortianalyzer setting:enc-algorithm",
        "log fortianalyzer setting:reliable",
    ]
    off = CLEAN + FAZ_ON.replace("status enable", "status disable").replace("high", "low")
    assert go(off)[0] == ()
    bogus = CLEAN + FAZ_ON.replace("enc-algorithm high", "enc-algorithm none")
    assert go(bogus)[1][FAZ] == (NE, "value-not-recognized")


def test_ssl_vpn_tls_settings():
    assert go(CLEAN + SSL_ON)[0] == ()
    legacy = CLEAN + SSL_ON.replace("tls1-2", "tls1-0").replace("tls1-3", "tls1-2").replace("high", "medium")
    assert keys(go(legacy)[0], SSL) == ["algorithm", "max-version", "min-version"]
    off = CLEAN + "config vpn ssl settings\n    set status disable\n    set ssl-min-proto-ver tls1-0\nend\n"
    assert go(off)[0] == ()
    assert go(CLEAN + "config vpn ssl settings\n    set ssl-min-proto-ver sslv3\nend\n")[1][SSL] == (NE, "value-not-recognized")


def test_antivirus_detection_settings():
    assert keys(go(sub("set grayware enable", "set grayware disable"))[0], AV) == ["grayware"]
    assert keys(go(sub("machine-learning-detection enable", "machine-learning-detection monitor"))[0], AV) == ["machine-learning-detection"]
    assert go(sub("machine-learning-detection enable", "machine-learning-detection x"))[1][AV] == (NE, "value-not-recognized")
    missing = sub("config antivirus settings\n    set grayware enable\n    set machine-learning-detection enable\nend\n", "")
    assert keys(go(missing)[0], AV) == ["grayware"]


def test_wan_profiles_per_kind_and_destination_kinds():
    assert keys(go(sub('        set dnsfilter-profile "default"\n', ""))[0], POL) == ["1/dnsfilter"]
    assert keys(go(sub("set utm-status enable", "set utm-status disable"))[0], POL) == ["1/appctrl", "1/av", "1/dnsfilter", "1/ips"]
    lan = sub('        set dstintf "wan1"\n', '        set dstintf "internal"\n')
    lan = sub('        set ips-sensor "default"\n', "", lan)
    assert keys(go(lan)[0], POL) == []
    anyd = sub('        set dstintf "wan1"\n', '        set dstintf "any"\n')
    anyd = sub('        set ips-sensor "default"\n', "", anyd)
    findings = go(anyd)[0]
    assert [dict(f.evidence)["wan_via"] for f in findings if f.rule_id == POL] == ["any"]
    disabled = sub("        set action accept\n", "        set action accept\n        set status disable\n")
    disabled = sub('        set ips-sensor "default"\n', "", disabled)
    assert keys(go(disabled)[0], POL) == []
    deny = sub("        set action accept\n", "")
    deny = sub('        set ips-sensor "default"\n', "", deny)
    assert keys(go(deny)[0], POL) == []


def test_wan_policy_zone_and_sdwan_zone():
    zone = 'config system zone\n    edit "outside"\n        set interface "wan1"\n    next\nend\n'
    text = sub('        set dstintf "wan1"\n', '        set dstintf "outside"\n') + zone
    text = sub('        set ips-sensor "default"\n', "", text)
    assert [dict(f.evidence)["wan_via"] for f in go(text)[0] if f.rule_id == POL] == ["zone"]
    sdwan = 'config system sdwan\n    config zone\n        edit "virtual-wan-link"\n        next\n    end\nend\n'
    text = sub('        set dstintf "wan1"\n', '        set dstintf "virtual-wan-link"\n') + sdwan
    text = sub('        set ips-sensor "default"\n', "", text)
    assert [dict(f.evidence)["wan_via"] for f in go(text)[0] if f.rule_id == POL] == ["sdwan-zone"]


@pytest.mark.parametrize("rule_id", (POL, DNS, APP))
def test_slice_two_not_evaluated_conditions(rule_id):
    assert go(CLEAN + "config system settings\n    set ngfw-mode policy-based\nend\n")[1][rule_id] == (NE, "ngfw-mode-policy-based")
    assert go(CLEAN + "config system settings\n    set ngfw-mode weird\nend\n")[1][rule_id] == (NE, "value-not-recognized")
    assert go(sub('set dstintf "wan1"', 'set dstintf "nowhere"'))[1][rule_id] == (NE, "dstintf-unresolved")
    assert go(sub("set role wan", "set role bogus"))[1][rule_id] == (NE, "value-not-recognized")
    assert go(sub("set utm-status enable", "set utm-status maybe"))[1][rule_id] == (NE, "value-not-recognized")


def test_profile_group_is_read_and_missing_group_is_not_evaluated():
    grouped = sub('        set ips-sensor "default"\n', '        set profile-type group\n        set profile-group "grp"\n')
    grouped = sub('        set av-profile "default"\n', "", grouped)
    grouped = sub('        set dnsfilter-profile "default"\n', "", grouped)
    grouped = sub('        set application-list "default"\n', "", grouped)
    assert go(grouped)[1][POL] == (NE, "profile-group-not-found")
    group = 'config firewall profile-group\n    edit "grp"\n        set ips-sensor "default"\n        set av-profile "default"\n        set dnsfilter-profile "default"\n    next\nend\n'
    findings, states = go(grouped + group)
    assert states[POL][0] == EV
    assert keys(findings, POL) == ["1/appctrl"]


def test_profile_rules_report_one_finding_per_profile_with_policies():
    off = sub("set log-all-domain enable", "set log-all-domain disable")
    findings = go(off)[0]
    assert [(f.object_key, dict(f.evidence)["policies"]) for f in findings if f.rule_id == DNS] == [("default", "1")]
    missing = sub("    set log-all-domain enable\n", "")
    assert keys(go(missing)[0], DNS) == ["default"]
    nodef = sub('config dnsfilter profile\n    edit "default"\n        set log-all-domain enable\n    next\nend\n', "")
    assert go(nodef)[1][DNS] == (NE, "profile-not-in-config")
    unused = sub('        set application-list "default"\n', "")
    assert go(unused)[1][APP][0] == EV


@pytest.mark.parametrize("rule_id", NEW)
def test_run_and_evaluate_agree_and_not_evaluated_stays_silent(rule_id):
    rules = tuple(r for r in RULES if r.id == rule_id)
    for text in (CLEAN, no_global(), sub("set grayware enable", "set grayware disable"), sub("set role wan", "set role bogus")):
        tree = parse(text)
        findings, states = evaluate(tree, "t", "d", rules)
        assert tuple(run(tree, "t", "d", rules)) == tuple(findings)
        if states[rule_id][0] == NE:
            assert findings == ()


def test_findings_never_carry_a_compliance_verdict():
    findings = go(sub("set grayware enable", "set grayware disable"))[0]
    for finding in findings:
        assert not {"compliant", "score", "compliance"} & set(finding.evidence)


def rows(section):
    out = []
    for line in section.splitlines():
        if re.match(r"^\| \d+(\.\d+)+ \|", line):
            out.append([c.strip() for c in line.strip().strip("|").split("|")])
    return out


def test_cis_mapping_document_is_consistent_with_catalog():
    text = DOC.read_text(encoding="utf-8")
    assert "not a compliance profile" in text
    covered_part, not_covered_part = text.split("## Not covered")
    covered = rows(covered_part.split("## Covered")[1])
    not_covered = rows(not_covered_part.split("\n## ")[0])
    cat = {}
    for rule in load_catalog("fortios"):
        for ref in rule.refs:
            m = re.match(r"CIS FortiGate 7\.4\.x Benchmark v1\.0\.1: (\d+(?:\.\d+)+) ", ref)
            if m:
                cat[m.group(1)] = rule.id
    ids = [r[0] for r in covered]
    assert len(ids) == len(set(ids))
    assert set(ids) == set(cat)
    for row in covered:
        assert cat[row[0]] in row[1]
    nids = [r[0] for r in not_covered]
    assert len(nids) == len(set(nids))
    assert not set(ids) & set(nids)
    assert len(ids) == 29 and len(nids) == 35
    for row in not_covered:
        assert len(row) >= 3 and row[1] and row[2]
