import json,contextlib
from types import SimpleNamespace
from unittest import TestCase,mock
from netops_helper import engine,configuration
from test_h1_config_block import enrolled,STATUS,fixture,A

class FramedConfigurationBlock(TestCase):
 def setUp(self):
  audit=mock.patch.object(engine,"record");audit.start();self.addCleanup(audit.stop)
  configuration._SNAPSHOTS.clear()
  self.addCleanup(configuration._SNAPSHOTS.clear)

 def execute(self,wire,chunk=7):
  def command(*args,**kwargs):
   if args[5]=='get system status':
    return SimpleNamespace(rc=0,stdout=STATUS.encode())
   self.assertEqual(args[5],'show system interface')
   consumer=kwargs['stdout_consumer']
   for pos in range(0,len(wire),chunk):consumer(wire[pos:pos+chunk])
   return SimpleNamespace(rc=0,stdout=b'')
  with mock.patch.object(engine,'record'),mock.patch.object(engine,'_paced_connection',side_effect=lambda *a:contextlib.nullcontext()),mock.patch.object(engine,'_resolve_target_ipv4',return_value=['192.0.2.20']),mock.patch.object(engine,'host_key_line',return_value='fixture'),mock.patch.object(engine.core_ssh,'run_command',side_effect=command):
   return engine.config_read(enrolled(),'fortios','system interface')

 def test_framed_stream_capture_pages_compare(self):
  body=fixture('up',A)
  framed=('LAB-fixture # '+body.replace('\n','\r\n')+'LAB-fixture # \r\n').encode()
  snapshots=[]
  for size in (1,7,65536):
   result=self.execute(framed,size)
   snapshots.append(result['snapshot_id'])
   self.assertEqual(result['firmware']['version'],'7.6.7')
   self.assertNotIn('LAB-fixture',result['untrusted_device_output'])
   self.assertNotIn(A,json.dumps(result))
  self.assertTrue(engine.config_diff(enrolled(),'fortios',snapshots[0],snapshots[-1])['identical'])
  plain=self.execute(body.encode())
  self.assertEqual(plain['content_sha256'],result['content_sha256'])

 def test_corrupt_frames_refuse_without_snapshot(self):
  body=fixture('up',A)
  for wire in (
   ('LAB-fixture # '+body+'OTHER # \n').encode(),
   ('LAB-fixture # '+body+'LAB-fixture # \n'+body).encode(),
   ('LAB-fixture # config system interface\nLAB-fixture # \nend\n').encode()):
   configuration._SNAPSHOTS.clear()
   with self.assertRaises(ValueError):self.execute(wire)
   self.assertFalse(configuration._SNAPSHOTS)
