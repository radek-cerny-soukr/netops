"""Invalid arguments through the real client request boundary, before transport."""
import json

import pytest

from netops_helper import proxy as module
from test_proxy_contracts import _request

BASE = dict(target='device-a', platform='fortiadc', section='all', include_all=True, redaction='full')


@pytest.mark.parametrize('updates,remove,field', [
    ({}, 'redaction', 'redaction'), ({'redaction': 'minimal'}, None, 'redaction'),
    ({'redaction': False}, None, 'redaction'), ({'include_defaults': 1}, None, 'include_defaults'),
    ({'include_all': 1}, None, 'include_all'), ({}, 'include_all', 'include_all'),
    ({'section': []}, None, 'include_all'), ({'section': 'invented', 'include_all': False}, None, 'section'),
    ({'section': [] , 'include_all': False}, None, 'section'),
    ({'limit': False}, None, 'limit'), ({'limit': 48001}, None, 'limit'),
    ({'offset': -1}, None, 'offset'), ({'platform': 'bad'}, None, 'platform'),
    ({'snapshot_id': 1}, None, 'snapshot_id'), ({'offset': 1}, None, 'snapshot_id'),
    ({'contains': ''}, None, 'contains'), ({'context': 1}, None, 'context'),
    ({'contains': 'value', 'context': 11}, None, 'context'),
    ({'filter_sha256': 'wrong'}, None, 'filter_sha256'),
    ({'content_sha256': 'wrong'}, None, 'content_sha256'),
    ({'content_sha256': 'a'*64}, None, 'snapshot_id'),
    ({'offset': 1, 'snapshot_id': 'cfg_'+'a'*32, 'contains': 'value'}, None, 'content_sha256'),
    ({'offset': 1, 'snapshot_id': 'cfg_'+'a'*32, 'contains': 'value', 'content_sha256': 'a'*64}, None, 'filter_sha256'),
    ({}, 'section', 'section'), ({'extra': 'synthetic-private-canary'}, None, 'arguments'),
])
def test_config_read_names_the_invalid_field(updates, remove, field):
    args = BASE | updates
    if remove:
        args.pop(remove)
    assert_refusal('config_read', args, field)


def assert_refusal(tool, args, field=None):
    proxy = module.Proxy()
    emitted = []
    proxy._emit = emitted.append  # The client output sink is the fake transport.
    assert proxy.request(_request(1, tool, args)) is None
    error = emitted[-1]['error']
    assert error['code'] == -32602
    assert isinstance(error['data']['field'], str) and error['data']['field']
    assert isinstance(error['data']['hint'], str) and error['data']['hint']
    if field:
        assert error['data']['field'] == field
    assert 'synthetic-private-canary' not in json.dumps(error)
    assert not proxy.pending and not proxy.pending_tools and not proxy.response_secrets
    assert not proxy.rate_history


@pytest.mark.parametrize('tool,args', [
    ('tcp_probe', dict(target='device-a', port=True)),
    ('tcp_probe', dict(target='device-a', port=443, timeout=False)),
    ('read_query_catalog', dict(limit=0)),
    ('ftp_list', dict(target='device-a', remote_path='/safe', use_tls=1)),
    ('sftp_stat', dict(target='device-a', remote_path=1)),
    ('tls_probe', dict(target='device-a', server_name=1)),
    ('triage_routing', dict(target='device-a', address='bad')),
    ('triage_vpn', dict(target='device-a', tunnel='bad;input')),
    ('schema_read', dict(target='device-a', path='bad;input')),
    ('schema_read', dict(target='device-a', path='system', view='bad')),
    ('schema_read', dict(target='device-a', path='system', vdom=1)),
    ('schema_read', dict(target='device-a', path='system', owners=[1])),
    ('snmp_get', dict(target='device-a', oids=[1])),
    ('wifi_rogue', dict(target='device-a', full=1)),
    ('config_diff', dict(target='device-a', platform='fortiadc', base_snapshot='bad', other_snapshot='cfg_'+'a'*32)),
    ('config_diff', dict(target='device-a', platform='fortiadc', base_snapshot='cfg_'+'a'*32, other_snapshot='bad')),
    ('fortios_diagnostics', dict(target='device-a', recipe='invalid', address='', interface='')),
    ('triage_slb', dict(target='device-a', virtual_server='bad;input')),
])
def test_other_refusals_also_have_guidance(tool, args):
    assert_refusal(tool, args)
