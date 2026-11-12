import json
from unittest import TestCase, mock
from netops.redaction import redact
from netops_helper import configuration as c, engine
from netops_helper.sanitize import redact_response
from test_config_block import enrolled
from test_config_full_engine import STATUS


class PSKLabels(TestCase):
    def test_engine_preserves_occurrence_labels_through_response_and_paging(self):
        c._SNAPSHOTS.clear(); c._DIFFS.clear()
        raw = ('config vpn ipsec phase1-interface\n edit tunnel-a\n set psksecret ENC CANARY-first\nnext\n'
               ' edit tunnel-b\n set psksecret "CANARY-second two"\nnext\nend\n')
        def wire(auth, platform, command, **kwargs):
            if command == 'get system status': return 0, STATUS
            kwargs['stdout_consumer'](raw.encode()); return 0, ''
        with mock.patch.object(engine, 'read_from_device', side_effect=wire), mock.patch.object(engine, 'record'):
            page = first = engine.config_read(enrolled(), 'fortios', 'all', True, redaction='full', limit=43)
            parts = []
            while True:
                parts.append(page['untrusted_device_output'])
                if page['next_offset'] is None:break
                page = engine.config_read(enrolled(), 'fortios', 'all', True, redaction='full',
                    snapshot_id=first['snapshot_id'], offset=page['next_offset'], limit=43)
        output = ''.join(parts)
        self.assertEqual(first['credential_redactions'], 2)
        for n in (1,2): self.assertIn('set psksecret <REDACTED:credential#'+str(n)+'>', output)
        self.assertNotIn('CANARY', output)
        self.assertEqual(output, redact_response(output))
        self.assertEqual(output, redact(output)[0])

    def test_only_complete_canonical_label_is_preserved(self):
        for value in ('<REDACTED:credential#1>CANARY', '<REDACTED:credential#1> CANARY',
                      '<REDACTED:credential#1>\\nCANARY', '"<REDACTED:credential#1> CANARY"',
                      '<REDACTED:credential#0>CANARY', '<redacted:credential#1> CANARY',
                      'ENC CANARY-one CANARY-two'):
            raw = 'set psksecret '+value+'\n'
            for output in (redact(raw)[0], redact_response(raw)):
                self.assertNotIn('CANARY', output)
                self.assertIn('set psksecret ', output)
