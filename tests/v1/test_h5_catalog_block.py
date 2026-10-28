import asyncio
import json
from unittest import TestCase, mock
from fastmcp import Client
from netops_helper import server, proxy, engine
from netops_helper.read_policy import public_query_catalog, public_query_metadata, normalize_platform

class CatalogPagingBlock(TestCase):
    def test_proxy_mcp_pages_reconstruct_public_catalog_block(self):
        expected=public_query_catalog()
        metadata=public_query_metadata()
        async def run():
            relay=proxy.Proxy()
            observed={};observed_meta={};cursor=0;revision=None;identifier=0
            async with Client(server.mcp) as client:
                tools=await client.list_tools()
                schema=next(t.input_schema for t in tools if t.name=='read_query_catalog')
                self.assertTrue({'platform','query_prefix','offset','limit'}<=set(schema['properties']),
                                'H5_MCP_PAGE_ARGUMENTS_MISSING')
                while True:
                    identifier+=1
                    message={'jsonrpc':'2.0','id':identifier,'method':'tools/call',
                             'params':{'name':'read_query_catalog','arguments':{'offset':cursor,'limit':7}}}
                    wire=relay.request(json.dumps(message).encode())
                    self.assertIsNotNone(wire,'H5_PROXY_PAGES_REQUIRED')
                    params=json.loads(wire)['params']
                    result=await client.call_tool(params['name'],params['arguments'])
                    self.assertFalse(result.is_error)
                    data=result.data
                    answer=relay.response(json.dumps({'jsonrpc':'2.0','id':identifier,'result':{
                        'content':[{'type':'text','text':json.dumps(data)}],
                        'structuredContent':data,'isError':False}}).encode())
                    self.assertIsNotNone(answer)
                    self.assertEqual(json.loads(answer)["result"]["structuredContent"],data)
                    self.assertEqual(data['offset'],cursor)
                    self.assertEqual(data['returned'],sum(len(v) for v in data['queries'].values()))
                    self.assertLessEqual(data['returned'],7)
                    self.assertLessEqual(len(json.dumps(data,separators=(',',':')).encode()),48000)
                    if revision is None:revision=data['catalog_sha256']
                    self.assertEqual(data['catalog_sha256'],revision)
                    for platform,queries in data['queries'].items():
                        target=observed.setdefault(platform,{})
                        self.assertFalse(set(target)&set(queries),'H5_DUPLICATE_PAGE_ROWS')
                        target.update(queries)
                        observed_meta.setdefault(platform,{}).update(data['query_metadata'][platform])
                    if data['next_offset'] is None:break
                    self.assertEqual(data['next_offset'],cursor+data['returned'])
                    self.assertGreater(data['returned'],0)
                    cursor=data['next_offset']
                self.assertEqual(data['total'],sum(len(v) for v in expected.values()))
            self.assertEqual(observed,expected,'H5_CATALOG_ROWS_LOST')
            self.assertEqual(observed_meta,metadata,'H5_CATALOG_METADATA_LOST')
        with mock.patch.object(proxy.Proxy,'_target',side_effect=AssertionError('H5_DEVICE_ACCESS')),mock.patch.object(
                engine,'read_from_device',side_effect=AssertionError('H5_DEVICE_ACCESS')):
            asyncio.run(run())

    def test_filters_default_page_and_refusal_block(self):
        async def run():
            async with Client(server.mcp) as client:
                default=(await client.call_tool('read_query_catalog',{})).data
                self.assertIn('next_offset',default,'H5_DEFAULT_PAGE_REQUIRED')
                self.assertLessEqual(default['returned'],25)
                terminal=(await client.call_tool('read_query_catalog',{'offset':default['total']})).data
                self.assertEqual((terminal['returned'],terminal['next_offset']),(0,None))
                platform=normalize_platform('fortios')
                params={'platform':'fortios','query_prefix':'system_','limit':100}
                data=(await client.call_tool('read_query_catalog',params)).data
                expected={n:v for n,v in public_query_catalog()[platform].items() if n.startswith('system_')}
                self.assertEqual(data['queries'],{platform:expected} if expected else {})
                self.assertEqual(data['total'],len(expected))
                self.assertEqual(data['catalog_sha256'],default['catalog_sha256'])
                empty=(await client.call_tool('read_query_catalog',{'query_prefix':'zzzz_unmatched'})).data
                self.assertEqual((empty['total'],empty['returned'],empty['queries'],empty['next_offset']),(0,0,{},None))
                for bad in ({'offset':1000000},{'platform':'unmeasured_platform'}):
                    with self.assertRaises(Exception):
                        await client.call_tool('read_query_catalog',bad)
                for bad in ({'offset':True},{'limit':True},{'offset':-1},{'offset':'1'},
                            {'limit':0},{'limit':101},{'query_prefix':'a;execute'},
                            {'query_prefix':'x'*65},{'platform':3},{'target':'fixture'}):
                    with self.subTest(arguments=bad),self.assertRaises(proxy.ToolArgumentsError):
                        proxy.Proxy._validate_tool_arguments('read_query_catalog',bad)
                    with self.subTest(module_arguments=bad),self.assertRaises(Exception):
                        await client.call_tool('read_query_catalog',bad)
        asyncio.run(run())

    def test_large_metadata_byte_budget_preserves_all_rows_block(self):
        catalog={'fortinet':{'query_'+str(i).zfill(4):[] for i in range(200)}}
        metadata={'fortinet':{n:{'description':'public metadata '*250,'command_template':'get fixture',
                                 'parameters':{},'high_volume':False} for n in catalog['fortinet']}}
        async def run():
            seen={};cursor=0
            async with Client(server.mcp) as client:
                while True:
                    result=await client.call_tool('read_query_catalog',{'offset':cursor,'limit':100})
                    data=result.data
                    self.assertLessEqual(len(json.dumps(data,separators=(',',':')).encode()),48000)
                    self.assertLess(data['returned'],100)
                    self.assertGreater(data['returned'],0)
                    seen.update(data['query_metadata']['fortinet'])
                    if data['next_offset'] is None:break
                    self.assertEqual(data['next_offset'],cursor+data['returned'])
                    cursor=data['next_offset']
            self.assertEqual(seen,metadata['fortinet'],'H5_BYTE_CAP_DROPPED_METADATA')
            metadata['fortinet']['query_0000']['description']='x'*48000
            async with Client(server.mcp) as client:
                with self.assertRaises(Exception):
                    await client.call_tool('read_query_catalog',{'offset':0,'limit':100})
        with mock.patch.object(server,'public_query_catalog',return_value=catalog),mock.patch.object(
                server,'public_query_metadata',return_value=metadata):
            asyncio.run(run())
