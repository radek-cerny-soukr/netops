from pathlib import Path
from unittest import TestCase, mock
import json
import tempfile


from netops_helper import engine, configuration as c
from netops_helper import proxy as proxy_module
from netops_helper.auth import TargetAuth
from test_proxy import _paths, _rewrite, _tool_call
from test_snmpv3_authpriv import _vault_with, V3_RECORD

STATUS = ('Version: FortiGate-VM64-KVM v7.6.8,build3744,260101 (GA)\n'
          'Virtual domain configuration: disable\n')
AUTH_KEY = 'fixture-auth-key-1'
PRIV_KEY = 'fixture-priv-key-1'
COMMUNITY = 'fixture-visible-community'
RAW = ('config system snmp community\n edit 1\n set name "' + COMMUNITY + '"\n next\nend\n'
       'config system global\n set alias "' + AUTH_KEY + '"\n set hostname "' + PRIV_KEY + '"\nend\n')


def wire(auth, platform, command, **kwargs):
    if command == 'get system status':
        return 0, STATUS
    consumer = kwargs['stdout_consumer']
    data = RAW.encode()
    for index in range(0, len(data), 5):
        consumer(data[index:index + 5])
    return 0, ''


class _Monkey:
    def __init__(self):
        self.undone = []

    def setattr(self, target, name, value):
        self.undone.append((target, name, getattr(target, name)))
        setattr(target, name, value)

    def undo(self):
        for target, name, value in reversed(self.undone):
            setattr(target, name, value)


class SnmpV3ConfigRead(TestCase):
    def setUp(self):
        patch = mock.patch.object(engine, 'record')
        patch.start()
        self.addCleanup(patch.stop)
        c._SNAPSHOTS.clear()

    def auth_through_proxy(self, with_usm=True):
        directory = Path(tempfile.mkdtemp())
        monkey = _Monkey()
        self.addCleanup(monkey.undo)
        inventory, vault, _, _ = _paths(directory, monkey)
        _vault_with(vault, V3_RECORD)
        document = json.loads(inventory.read_text())
        document['devices'][0]['helper']['read_inventory'] = {
            'interfaces': ['port1'], 'services': [], 'addresses': [],
            'config_access': ['read', 'compare']}
        if not with_usm:
            document['devices'][0]['helper']['snmp_credential'] = None
        _rewrite(inventory, document)
        transformed = proxy_module.Proxy().request(_tool_call(
            1, 'config_read', {'target': 'device-a', 'platform': 'fortios', 'section': 'all',
                               'include_all': True, 'redaction': 'full'}))
        self.assertIsNotNone(transformed)
        context = json.loads(transformed)['params']['arguments']['auth_context']
        return TargetAuth.decode('device-a', context)

    def pages(self, auth):
        with mock.patch.object(engine, 'read_from_device', side_effect=wire):
            first = engine.config_read(auth, 'fortios', 'all', True, redaction='full', limit=200)
        parts = [first['untrusted_device_output']]
        page = first
        while page['next_offset'] is not None:
            page = engine.config_read(auth, 'fortios', 'all', True, snapshot_id=first['snapshot_id'],
                                      offset=page['next_offset'], limit=200, redaction='full')
            parts.append(page['untrusted_device_output'])
        return ''.join(parts), first

    def test_v3_keys_are_hidden_and_the_community_stays_visible(self):
        auth = self.auth_through_proxy()
        self.assertIsNotNone(auth.snmp_usm)
        text, first = self.pages(auth)
        shown = text + json.dumps(first)
        self.assertNotIn(AUTH_KEY, shown)
        self.assertNotIn(PRIV_KEY, shown)
        self.assertIn(COMMUNITY, text)

    def test_a_target_without_usm_still_reads_the_full_configuration(self):
        auth = self.auth_through_proxy(with_usm=False)
        self.assertIsNone(auth.snmp_usm)
        text, _ = self.pages(auth)
        self.assertIn(COMMUNITY, text)
