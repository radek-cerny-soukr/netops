from __future__ import annotations

from base64 import urlsafe_b64encode, b64encode
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace, ModuleType
from unittest.mock import patch

from netops_core.schema import Library, SchemaError
from netops_core.hostkey import fingerprint_of
from netops_helper.auth import TargetAuth
from netops_helper.inventory import InventoryError
from netops_helper import schema_read as reader
from netops_helper.proxy import Proxy, ToolArgumentsError, PolicyScopeError

PIN=fingerprint_of(b64encode(b"schema-contract-host-key").decode())


def document():
    return {"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":"8.0.0","build":"0167",
        "config":{"firewall address":{"kind":"table","scope":"vdom","available":True,"attrs":{
            "comment":{"type":"string"},"password":{"type":"password"},"psksecret":{"type":"string"},
            "ciphertext":{"type":"string"},"fortitoken":{"type":"string"}}},
            "system sdwan":{"kind":"section","scope":"vdom","available":True,"attrs":{}},
            "system sdwan health-check":{"kind":"table","attrs":{}},
            "system sdwan health-check sla":{"kind":"table","attrs":{"latency-threshold":{"type":"integer"}}}}}


def auth(paths=None):
    data={"alias":"device-a","host":"192.0.2.10","port":22,"login":"operator","credential_kind":"password",
        "secret":"explicit-secret","host_key_fingerprint":PIN,"account_role":"read-only",
        "ssh_platform":"fortios","enabled_queries":["system_status"],"fortios_output_standard_verified":True,
        "read_inventory":{"schema_paths":paths or ["firewall address","system sdwan health-check sla"]},
        "egress":{"addresses":["192.0.2.10"],"tcp_ports":[],"udp_ports":[],"tcp_port_ranges":[],
                  "udp_port_ranges":[],"allow_icmp":False,"allow_dns":False,"tls_server_names":[]}}
    return TargetAuth.decode("device-a",urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("="))


def must_fail(function,*args,**kwargs):
    try:function(*args,**kwargs)
    except (ValueError,TypeError,InventoryError):return
    raise AssertionError("a refused schema operation succeeded")


def registry(directory):
    library=directory/"library.json";library.write_text(json.dumps(document()))
    data={"format":1,"targets":{"device-a":{"schema":"library.json","sha256":sha256(library.read_bytes()).hexdigest(),
                                             "host_key_fingerprint":PIN}}}
    path=directory/"registry.json";path.write_text(json.dumps(data))
    return path,data


def test_registry_digest_pin_and_identity():
    with tempfile.TemporaryDirectory() as temporary:
        directory=Path(temporary);path,data=registry(directory)
        library=reader.binding(auth(),path)
        assert reader.verify_status(library,"Version: FortiGate-VM64-KVM v8.0.0,build0167,release\nCurrent virtual domain: root\n")=="root"
        for status in ["Version: FortiGate-80F v8.0.0,build0167,release",
                       "Version: FortiGate-VM64-KVM v8.0.1,build0167,release",
                       "Version: FortiGate-VM64-KVM v8.0.0,build0168,release",
                       "unrecognized status","Version: FortiGate-VM64-KVM v8.0.0,build0167\n"*2]:
            must_fail(reader.verify_status,library,status)
        for field,value in [("sha256","0"*64),("host_key_fingerprint","replace-me"),("schema","../library.json")]:
            mutated=json.loads(json.dumps(data));mutated["targets"]["device-a"][field]=value
            path.write_text(json.dumps(mutated));must_fail(reader.binding,auth(),path)
        path.write_text('{"format":1,"format":1,"targets":{}}');must_fail(reader.binding,auth(),path)


def test_vdom_parent_keys_secrets_and_no_inferred_defaults():
    text="""config vdom
 edit "VD1"
  config firewall address
   edit "one"
    set comment "explicit-secret"
    set password "not-an-auth-secret"
    set psksecret "preshared-material"
    set ciphertext ENC "opaque-material"
    set new-secret-field "unknown-material"
    set fortitoken "token-identifier"
   next
  end
  config system sdwan
   config health-check
    edit "first"
     config sla
      edit 1
       set latency-threshold 10
      next
     end
    next
    edit "second"
     config sla
      edit 1
       set latency-threshold 20
      next
     end
    next
   end
  end
 next
 edit "VD2"
  config firewall address
   edit "one"
    set comment "VD2-value"
   next
  end
 next
end
"""
    library=Library(document())
    result=reader.snapshot(library,text,"firewall address","get","VD1",["one"],auth().secrets)
    assert len(result["objects"])==1
    rendered=json.dumps(result)
    assert all(value not in rendered for value in ("explicit-secret","not-an-auth-secret","VD2-value",
              "preshared-material","opaque-material","unknown-material"))
    assert "token-identifier" in rendered
    result=reader.snapshot(library,text,"system sdwan health-check sla","show","VD1",["second","1"])
    assert result["objects"][0]["attributes"]=={"latency-threshold":["20"]}
    assert result["objects"][0]["show"]=='set latency-threshold "20"'
    assert len(reader.snapshot(library,text,"firewall address","get",None,[])["objects"])==2
    assert "no defaults inferred" in result["value_source"]
    must_fail(reader.snapshot,library,"config firewall address\n","firewall address","get",None,[])


def test_unwrapped_snapshot_requires_live_vdom_and_cannot_claim_root():
    library=Library(document())
    text='config firewall address\n edit "one"\n set comment "local"\n next\nend\n'
    must_fail(reader.snapshot,library,text,"firewall address","get",None,[])
    must_fail(reader.snapshot,library,text,"firewall address","get","root",[],current_vdom="VD2")
    report=reader.snapshot(library,text,"firewall address","get","VD2",[],current_vdom="VD2")
    assert report["objects"][0]["vdom"]=="VD2"
    assert report["snapshot_scope"]=="current-vdom"
    status="Version: FortiGate-VM64-KVM v8.0.0,build0167,release\n"
    for body in [status,status+"Current virtual domain: root\n"*2,status+"Current virtual domain: \n"]:
        must_fail(reader.verify_status,library,body)


def test_proxy_and_server_both_reject_unenrolled_paths_and_bad_selectors():
    library=Library(document())
    good=Proxy._validate_tool_arguments("schema_read",{"target":"device-a","path":"firewall address"})
    section=SimpleNamespace(egress={},catalog_platform=lambda:"fortinet",enabled_queries=("system_status",),
                            read_inventory={"schema_paths":("firewall address",)})
    Proxy._authorize_tool("schema_read",good,None,section)
    must_fail(Proxy._authorize_tool,"schema_read",dict(good,path="system sdwan"),None,section)
    for args in [{"target":"device-a","path":"firewall address; reboot"},
                 {"target":"device-a","path":"firewall address","view":"write"},
                 {"target":"device-a","path":"firewall address","owners":["x\nreboot"]},
                 {"target":"device-a","path":"firewall address","vdom":["VD1"]},
                 {"target":"device-a","path":"firewall address","auth_context":"caller-controlled"}]:
        must_fail(Proxy._validate_tool_arguments,"schema_read",args)
    for path,view,vdom,keys in [("system sdwan","get",None,[]),
                               ("firewall address","write",None,[]),
                               ("firewall address","get","VD1",["x\nreboot"])]:
        must_fail(reader.selectors,auth(),library,path,view,vdom,keys)


def test_engine_refuses_before_snapshot_and_paginates_without_another_connection():
    if importlib.util.find_spec("icmplib") is None:
        module=ModuleType("icmplib");module.ping=lambda *a,**kw:None;sys.modules["icmplib"]=module
    from netops_helper import engine
    with tempfile.TemporaryDirectory() as temporary:
        path,_=registry(Path(temporary));calls=[];events=[]
        text='config firewall address\n edit "one"\n set comment "'+"x"*3000+'"\n next\nend\n'
        def read(target,platform,command):
            calls.append(command)
            return 0,"Version: FortiGate-VM64-KVM v8.0.0,build0167,release\nCurrent virtual domain: root\n" if command=="get system status" else text
        with patch.dict(os.environ,{"NETOPS_SCHEMA_REGISTRY":str(path)}),patch.object(engine,"read_from_device",read),patch.object(engine,"record",lambda *a,**kw:events.append(kw)):
            result=engine.schema_read(auth(),"firewall address","get",None,None,0,1000)
            assert result["ok"] and result["next_offset"]
            second=engine.schema_read(auth(),"firewall address","get",None,None,result["next_offset"],1000)
            assert second["pagination_source"]=="cached"
            assert calls==["get system status","show full-configuration"]
            assert [e["status"] for e in events]==["started","ok","started","ok"]
            calls.clear()
            must_fail(engine.schema_read,auth(),"system sdwan","get",None,None,0,1000)
            assert calls==[]
        with patch.dict(os.environ,{"NETOPS_SCHEMA_REGISTRY":str(path)}),patch.object(engine,"read_from_device",lambda *a:(0,"Version: FortiGate-80F v8.0.0,build0167,release")),patch.object(engine,"record",lambda *a,**kw:None):
            must_fail(engine.schema_read,auth(),"firewall address","get",None,None,0,1000)
        with patch.dict(os.environ,{"NETOPS_SCHEMA_REGISTRY":str(path)}),patch.object(engine,"read_from_device",side_effect=RuntimeError("explicit-secret")),patch.object(engine,"record",lambda *a,**kw:None):
            try:engine.schema_read(auth(),"firewall address","get",None,None,0,1000)
            except ValueError as error:
                assert "explicit-secret" not in str(error) and "SSH schema identity read failed" in str(error)
            else:raise AssertionError("the failing transport was accepted")
        engine._SSH_PAGE_CACHE.clear()


def test_schema_inventory_supports_all_measured_paths_with_a_distinct_bound():
    from netops_helper.inventory import _checked_read_inventory
    paths=["system object"+str(i) for i in range(4096)]
    assert len(auth(paths).read_inventory["schema_paths"])==4096
    assert len(_checked_read_inventory("test",{"schema_paths":paths})["schema_paths"])==4096
    must_fail(auth,paths+["system extra"])
    must_fail(_checked_read_inventory,"test",{"schema_paths":paths+["system extra"]})
    must_fail(_checked_read_inventory,"test",{"services":["service"+str(i) for i in range(257)]})



def test_inline_table_keys_preserve_selection_and_redaction():
    data=document()
    data["config"]["system replacemsg auth"]={"kind":"table","scope":"global","available":True,"key":"msg-type",
        "attrs":{"msg-type":{"type":"string","max_length":28},"buffer":{"type":"string"}}}
    library=Library(data)
    text='config global\n config system replacemsg auth "login page"\n set buffer "explicit-secret"\n end\n config system replacemsg auth "other"\n set buffer "visible"\n end\nend\n'
    report=reader.snapshot(library,text,"system replacemsg auth","get",None,["login page"],("explicit-secret",),current_vdom="root")
    assert len(report["objects"])==1
    item=report["objects"][0]
    assert item["vdom"]=="global" and item["owners"]==[["system replacemsg auth","login page"]]
    assert item["attributes"]["buffer"]==["<REDACTED>"]
    assert "explicit-secret" not in json.dumps(report)

def main():
    for function in [test_registry_digest_pin_and_identity,test_vdom_parent_keys_secrets_and_no_inferred_defaults,
                     test_unwrapped_snapshot_requires_live_vdom_and_cannot_claim_root,
                     test_proxy_and_server_both_reject_unenrolled_paths_and_bad_selectors,
                     test_engine_refuses_before_snapshot_and_paginates_without_another_connection,
                     test_schema_inventory_supports_all_measured_paths_with_a_distinct_bound,
                     test_inline_table_keys_preserve_selection_and_redaction]:
        function()
    print("schema_read_contracts=passed")


if __name__=="__main__":
    main()
