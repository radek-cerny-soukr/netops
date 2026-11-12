"""docs/fortios-wifi-rest.md documents exactly the REST allowlist of wifi_rest.py."""
from __future__ import annotations

from pathlib import Path
import re

from netops_helper import wifi_rest

GUIDE = Path(__file__).resolve().parents[3] / "docs/fortios-wifi-rest.md"


def test_the_endpoint_table_is_the_code_allowlist():
    text = GUIDE.read_text(encoding="utf-8")
    documented = set(re.findall(r"(?m)^\| `(/api/v2/[^`]+)` \|", text))
    assert documented == set(wifi_rest.PATHS)
    assert {path for path in wifi_rest.PATHS if "?" in path} == {wifi_rest.WIRELESS_LOG}
    assert "exact allowlist of the %s fixed paths" % {7: "seven"}[len(wifi_rest.PATHS)] in text
    assert "query string above" not in text and "six monitor endpoints" not in text


def test_release_notes_and_changelog_include_all_wifi_rounds():
    root = GUIDE.parents[1]
    changelog = (root / 'CHANGELOG.md').read_text()
    assert changelog.index('## 1.0.7') < changelog.index('Wi-Fi triage reads station-filtered')
    notes = (root / 'release/notes-1.0.7.md').read_text()
    for text in (changelog, notes):
        for phrase in ('station-filtered', 'Failed client/AP REST joins', '15-read', 'three times', 'Radio utilization'):
            assert phrase.lower() in text.lower() or (phrase == 'Radio utilization' and 'shared radio utilization' in text)
    guide = GUIDE.read_text()
    for phrase in ('client_supplied', 'User & Device', 'heuristics', 'width_unknown', 'findings_max_severity'):
        assert phrase in guide
