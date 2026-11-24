"""The parameter scope text of docs/helper-configuration.md names the counts of the shipped catalogue."""
from __future__ import annotations

from pathlib import Path
import re

from netops_helper.query_catalog.model import LITERAL
from netops_helper.read_policy import LOOKUP_KINDS, READ_QUERIES

GUIDE = Path(__file__).resolve().parents[3] / "docs/helper-configuration.md"


def _queries():
    return [query for queries in READ_QUERIES.values() for query in queries.values()]


def _with(predicate):
    return sum(1 for query in _queries() if any(predicate(slot) for slot in (getattr(query, "slots", None) or {}).values()))


def test_documented_parameter_counts_match_the_catalogue():
    text = GUIDE.read_text(encoding="utf-8")
    slotted = sum(1 for query in _queries() if getattr(query, "slots", None))
    assert f"{slotted} of the {len(_queries())} catalogue queries take a parameter" in text
    inventory = _with(lambda slot: slot.kind not in LOOKUP_KINDS and slot.inventory not in (None, LITERAL))
    assert f"({inventory} queries have one)" in text
    literal = _with(lambda slot: slot.kind not in LOOKUP_KINDS and slot.inventory in (None, LITERAL))
    assert re.search(r"not looked up in the inventory \(%d queries\)" % literal, text)
    lookup = _with(lambda slot: slot.kind in LOOKUP_KINDS)
    assert f"({lookup} queries)" in text


def test_every_literal_kind_of_the_catalogue_is_named_in_the_exceptions():
    text = GUIDE.read_text(encoding="utf-8")
    exceptions = text.split("The exceptions below are checked against their own rule instead", 1)[1].split("Any other value is refused", 1)[0]
    kinds = {slot.kind for query in _queries() for slot in (getattr(query, "slots", None) or {}).values()
             if slot.kind not in LOOKUP_KINDS and slot.inventory in (None, LITERAL)}
    names = {"vlan_id": "`vlan_id`", "mac_literal": "`mac_literal`", "wifi_log_lines": "`lines`",
             "wifi_mac_literal": "`mac_literal` (lower-case MAC)", "ip_literal": "`ip_literal`",
             "acl_policy": "`acl_policy`", "diagnostic_dns_name": "`diagnostic_dns_name`"}
    catalogue = (GUIDE.parents[0].parent / "components/netops-helper/docs/query-catalog.md").read_text()
    assert "literal.junos_log_time" in catalogue and "literal.junos_log_severity" in catalogue
    assert "start-inclusive, end-exclusive" in catalogue
    kinds -= {"junos_log_time", "junos_log_severity"}
    # ADC-STATISTICS keeps the prose guide frozen for the text phase; the new literal kind
    # is documented by the generated catalogue, alongside its numeric-ID description.
    if "fortiadc_member_id" in kinds:
        assert "None.fortiadc_member_id" in catalogue
        assert "numeric pool member ID" in catalogue
        kinds = kinds - {"fortiadc_member_id"}
    if "vpc_id" in kinds:
        catalogue = (GUIDE.parents[0].parent / "components/netops-helper/docs/query-catalog.md").read_text()
        assert "literal.vpc_id" in catalogue or "None.vpc_id" in catalogue
        assert "vPC ID" in catalogue
        kinds = kinds - {"vpc_id"}
    if "etherchannel_group_id" in kinds:
        assert "None.etherchannel_group_id" in catalogue
        assert "numeric group ID 1–128" in catalogue
        kinds = kinds - {"etherchannel_group_id"}
    # EOS-HEALTH likewise: the EOS log window slots are documented by the generated catalogue in the text phase.
    eos_health = {"eos_log_minutes", "log_severity", "log_date", "log_time"}
    if kinds & eos_health:
        catalogue = (GUIDE.parents[0].parent / "components/netops-helper/docs/query-catalog.md").read_text()
        for kind in kinds & eos_health:
            assert "None." + kind in catalogue, kind
        kinds = kinds - eos_health
    assert "None.nxos_log_count" in catalogue
    kinds.discard("nxos_log_count")
    exos_log = {"exos_log_source", "exos_log_severity"}
    for kind in kinds & exos_log:
        assert "None." + kind in catalogue
    kinds -= exos_log
    # NXOS-SECURITY documents the new literal slots in the generated catalogue.
    nxos_security = {"ipv4_neighbor", "ipv6_neighbor", "nxos_acl_name"}
    for kind in kinds & nxos_security:
        assert "None." + kind in catalogue
    kinds -= nxos_security
    assert "None.c9800_ap_name" in catalogue
    kinds.discard("c9800_ap_name")
    if "ip_literal" in kinds:
        row = next(line for line in catalogue.splitlines() if "<code>evpn_bgp_prefix</code>" in line)
        assert "prefix -&gt; None.ip_literal" in row and "IPv4 or IPv6 address" in row
        kinds.remove("ip_literal")
    if "fortios_extender_serial" in kinds:
        assert "literal.fortios_extender_serial" in catalogue
        assert "FortiExtender serial number" in catalogue
        kinds.remove("fortios_extender_serial")
    assert kinds <= set(names), kinds
    for kind in kinds:
        assert names[kind] in exceptions, kind
