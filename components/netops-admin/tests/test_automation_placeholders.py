import pytest
from conftest import FIXTURES,request_bytes
from netops_admin import engine,fortios
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

@pytest.mark.parametrize("case",["new-value","old-value"])
def test_legacy_fortios_plan_refuses_expanding_text_before_any_write(case):
 text=(FIXTURES/"fortios_8_0_0.conf").read_text()
 changes={"comment":"reserved"}
 if case=="new-value":changes["comment"]="%%date%%"
 else:text=text.replace('set comment "unused"','set comment "%%date%%"')
 request=parse_request(request_bytes(op="update",key="spare-host",changes=changes))
 with pytest.raises(Rejected,match="automation placeholders"):
  engine.build_plan("fortios",text.encode(),request)

def test_direct_safeguard_renderer_cannot_bypass_literal_restoration_check():
 with pytest.raises(Rejected,match="automation placeholders"):
  fortios.render_safeguard("a"*32,["config firewall address",'edit "example"',
   'set comment "%%time%%"',"next","end"],"2026-10-03 00:00:00")
