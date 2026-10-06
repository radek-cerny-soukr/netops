import pytest
from netops_core import fortios

EMPTY=chr(39)*2
@pytest.mark.parametrize("text,expected",[
 ("set interface "+EMPTY,["set","interface",""]),
 ("set interface "+EMPTY+"   ",["set","interface",""]),
 ("set list "+EMPTY+" other",["set","list","","other"]),
 ('set comment "'+EMPTY+'"',["set","comment",EMPTY]),
 ("set comment text's",["set","comment","text's"]),
 ("set comment "+EMPTY+"suffix",["set","comment",EMPTY+"suffix"]),
 ("set comment "+EMPTY+"tail",["set","comment",EMPTY+"tail"]),
 ('set comment "before '+EMPTY+' after"',["set","comment","before "+EMPTY+" after"]),
 ("set list "+EMPTY+" "+EMPTY,["set","list","",""]),
 ("set list "+EMPTY+chr(9)+"other",["set","list","","other"]),
])
def test_empty_single_quote_token_and_literal_apostrophes(text,expected):
 assert fortios.tokenize(text)==expected

def test_real_full_configuration_empty_reference_is_an_empty_value():
 tree=fortios.parse("config firewall address\n edit example\n  set associated-interface "+EMPTY+"\n next\nend\n")
 assert tree.section("firewall address").entries["example"].values("associated-interface")==("",)
