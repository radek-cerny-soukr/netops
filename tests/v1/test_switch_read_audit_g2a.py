"""Read real EXOS captures through the engine and persist the real JSONL audit.

Only the SSH transport is fake. Transport classifications are already stored
as audit.detail, the field supported by the shared Recorder schema.
"""
import errno
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from netops_core import hostkey, ssh
from netops_core.audit import Recorder
from netops_helper import audit, engine
from netops_helper.auth import EgressPolicy, TargetAuth

# Exact repository captures embedded because tests/v1 also ships in the product image.
# Helper fixtures: identity/extreme_exos.txt and
# real/lab_endpoints_20261110/exos/mac_table.txt (2026-11-10, show fdb, rc=0).
IDENTITY = 'Switch : 800630-00-11 LAB00000005 Rev 1.0 BootROM: 1.0.1.8 IMG: 21.1.2.6\nImage : ExtremeXOS version 21.1.2.6 by release-manager\n'
FDB = """MAC                                      VLAN Name( Tag)  Age  Flags          Port / Virtual Port List
------------------------------------------------------------------------------------------------------
00:00:5e:00:53:0e                              D10(0010) 0160  d m            1
00:00:5e:00:53:0e                              D20(0020) 0178  d m            1
00:00:5e:00:53:01                              D10(0010) 0155  d m            1
00:00:5e:00:53:03                              D10(0010) 0058  d m            1
00:00:5e:00:53:04                              D10(0010) 0049  d m            1
00:00:5e:00:53:04                              D20(0020) 0111  d m            1
00:00:5e:00:53:05                              D10(0010) 0117  d m            1

Flags : d - Dynamic, s - Static, p - Permanent, n - NetLogin, m - MAC, i - IP,
        x - IPX, l - lockdown MAC, L - lockdown-timeout MAC, M- Mirror, B - Egress Blackhole,
        b - Ingress Blackhole, v - MAC-Based VLAN, P - Private VLAN, T - VLAN translation,
        D - drop packet, h - Hardware Aging (Age=0), o - IEEE 802.1ah Backbone MAC,
        S - Software Controlled Deletion, r - MSRP,
        X - VXLAN, E - EVPN

Total: 7 Static: 0  Perm: 0  Dyn: 7  Dropped: 0  Locked: 0  Locked with Timeout: 0
FDB Aging time: 300
"""
PRIVATE = 'CNRY-transport-private-text'


class SwitchReadAuditG2a(unittest.TestCase):
    def auth(self):
        return TargetAuth(
            alias='g2a-exos', host='127.0.0.1', port=2222, login='reader', secret=PRIVATE,
            host_key_fingerprint=hostkey.fingerprint_of('ZzJhLXN5bnRoZXRpYy1ob3N0LWtleQ=='),
            ssh_platform='extreme_exos', enabled_queries=('mac_table',), device_types=('switch',),
            egress=EgressPolicy(addresses=('127.0.0.1',), tcp_ports=(2222,)),
        )

    def read(self, failure):
        calls = []
        def transport(auth, profile, command, **kwargs):
            calls.append(command)
            if command == 'show version':
                return 0, IDENTITY
            self.assertEqual(command, 'show fdb')
            if failure is not None:
                raise failure
            return 0, FDB

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit.jsonl'
            with patch.object(audit, '_RECORDER', Recorder(path, 'helper')), \
                 patch.object(engine, '_exec_read', side_effect=transport):
                result = engine.switch_read(self.auth(), 'mac_entry')
            events = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(calls, ['show version', 'show fdb'])
        self.assertNotIn(PRIVATE, json.dumps([result, events]))
        completed = [event for event in events if event['event'] == 'switch_read' and event['status'] != 'started']
        self.assertEqual(len(completed), 1)
        started = next(event for event in events if event['event'] == 'switch_read' and event['status'] == 'started')
        self.assertEqual(started['operation_id'], completed[0]['operation_id'])
        return result, completed[0]

    def test_switch_read_audit_retains_the_client_transport_class(self):
        for failure, expected in (
            (OSError(errno.EHOSTUNREACH, PRIVATE), 'unreachable'),
            (hostkey.HostKeyError(PRIVATE), 'host_key_mismatch'),
            (ssh.SshError('Permission denied ' + PRIVATE), 'auth'),
            (ConnectionRefusedError(PRIVATE), 'connection_refused'),
            (TimeoutError(PRIVATE), 'timeout'),
            (socket.gaierror(socket.EAI_NONAME, PRIVATE), 'dns'),
        ):
            with self.subTest(code=expected):
                result, completed = self.read(failure)
                self.assertFalse(result['ok'])
                self.assertEqual(result['status'], 'timeout' if expected == 'timeout' else 'transport_error')
                self.assertEqual(result['error_code'], expected)
                self.assertEqual(completed['status'], 'failed')
                self.assertEqual(completed['detail'], result['error_code'])
                self.assertEqual(result['records'], [])

    def test_successful_capture_keeps_audit_free_of_transport_failures(self):
        result, completed = self.read(None)
        self.assertTrue(result['ok'])
        self.assertGreater(len(result['records']), 0)
        self.assertEqual(completed['status'], 'ok')
        self.assertNotIn('detail', completed)


if __name__ == '__main__':
    unittest.main()
