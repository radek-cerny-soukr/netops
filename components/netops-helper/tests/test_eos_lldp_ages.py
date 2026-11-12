"""Complete day-old cEOS LLDP capture and age syntax regressions."""
from pathlib import Path

from netops_helper import tables as t

ROOT = Path(__file__).parent / "fixtures"


def test_ceos_day_old_lldp_capture_keeps_all_nine_neighbors_complete():
    text = (ROOT / 'real/arista_eos/ceos_4.36.1F/lldp_neighbors_detail_task81.txt').read_text()
    result = t.parse('arista_eos', 'lldp_neighbor', 'lldp_neighbors_detail', text)
    assert result['status'] == 'ok' and result['coverage']['complete'], result['unparsed']
    assert len(result['records']) == 9 and result['unparsed'] == []
    assert sum('Discovered 1 day,' in line for line in text.splitlines()) == 7
    for duration in ('0:00:01', '1 day, 0:00:01', '42 days, 12:34:56'):
        variant = text.replace('1 day, 3:59:59', duration)
        assert t.parse('arista_eos', 'lldp_neighbor', 'lldp_neighbors_detail', variant)['coverage']['complete']
    broken = text.replace('Discovered 1 day,', 'Discovered unexpected age,', 1)
    result = t.parse('arista_eos', 'lldp_neighbor', 'lldp_neighbors_detail', broken)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert len(result['unparsed']) == 1 and len(result['records']) == 9


