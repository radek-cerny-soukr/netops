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
             "wifi_mac_literal": "`mac_literal` (lower-case MAC)", "ip_literal": "`ip_literal`"}
    assert kinds <= set(names), kinds
    for kind in kinds:
        assert names[kind] in exceptions, kind
