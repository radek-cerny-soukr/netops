from netops_core import fortios
from netops_core.schema import Library, config_instances


def library():
    return Library({"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":"8.0.0","build":"0167",
        "config":{"system interface":{"kind":"table","scope":"global","available":True,"attrs":{}},
                  "system sdwan":{"kind":"section","scope":"vdom","available":True,"attrs":{}},
                  "system sdwan health-check":{"kind":"table","attrs":{}},
                  "system sdwan health-check sla":{"kind":"table","attrs":{"latency-threshold":{"type":"integer"}}}}})


def test_nested_table_owners_and_vdoms_do_not_flatten():
    text='''
config global
 config system interface
  edit "port1"
   set vdom "VD1"
  next
 end
end
config vdom
 edit "VD1"
  config system sdwan
   config health-check
    edit "probe"
     config sla
      edit 1
       set latency-threshold 10
      next
     end
    next
   end
  end
 next
 edit "VD2"
  config system sdwan
   config health-check
    edit "probe"
     config sla
      edit 1
       set latency-threshold 20
      next
     end
    next
   end
  end
 next
end
'''
    items=list(config_instances(library(),fortios.parse(text)))
    sla=[x for x in items if x.path=="system sdwan health-check sla"]
    assert [x.scope for x in sla]==["VD1","VD2"]
    assert [x.node.value("latency-threshold") for x in sla]==["10","20"]
    assert sla[0].owners==(("system sdwan health-check","probe"),("system sdwan health-check sla","1"))
    assert next(x for x in items if x.path=="system interface").scope is None


def test_unterminated_and_excessively_nested_snapshots_are_refused():
    import pytest
    with pytest.raises(fortios.TruncatedError):
        fortios.parse('config system global\n set alias "unterminated\n')
    with pytest.raises(fortios.ParseError):
        fortios.parse("config x\n"*66+"end\n"*66)
