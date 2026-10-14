import json

import pytest
from conftest import request_bytes

from netops_admin.errors import Rejected
from netops_admin.profiles import OPS
from netops_admin.request import MAX_CHANGES, MAX_REQUEST_BYTES, REQUEST_ID, Request, parse_request
from netops_admin.schema_request import Transaction

SCHEMA_LIMIT = 131072


def padded(raw, size):
    assert len(raw) <= size
    return raw + b" " * (size - len(raw))


def schema_bytes(size):
    body = {
        "operations": [{"path": "firewall address", "scope": None, "owners": [], "op": "create",
                        "changes": {"subnet": "192.0.2.30/32"}}],
        "reason": "operator asked for a host object",
        "user_request": "create an address object for the new host",
        "request_id": "req-0001-example",
    }
    return padded(json.dumps(body).encode("ascii"), size)


def refusal(raw):
    with pytest.raises(Rejected) as caught:
        parse_request(raw)
    return caught.value.reasons


def test_a_request_of_exactly_the_limit_is_parsed():
    parsed = parse_request(padded(request_bytes(), MAX_REQUEST_BYTES))
    assert isinstance(parsed, Request)
    assert parsed.key == "new-host"


def test_a_request_one_byte_over_the_limit_is_refused_naming_the_limit():
    assert refusal(padded(request_bytes(), MAX_REQUEST_BYTES + 1)) == ["request is larger than 16384 bytes"]


@pytest.mark.parametrize("size", [MAX_REQUEST_BYTES + 1, 20000, SCHEMA_LIMIT])
def test_a_large_schema_transaction_is_handed_to_the_schema_parser(size):
    parsed = parse_request(schema_bytes(size))
    assert isinstance(parsed, Transaction)
    assert parsed.request_id == "req-0001-example"


def test_a_schema_transaction_over_its_own_limit_is_refused_as_an_oversized_request():
    assert refusal(schema_bytes(SCHEMA_LIMIT + 1)) == ["request is larger than 16384 bytes"]


def test_a_large_ordinary_request_is_never_handed_to_the_schema_parser():
    assert refusal(padded(request_bytes(), 20000)) == ["request is larger than 16384 bytes"]


def test_a_request_that_is_not_json_is_refused_as_a_request():
    assert refusal(b"{not json") == ["request is not UTF-8 JSON"]


def test_a_request_that_is_not_an_object_is_refused_by_name():
    assert refusal(b"[1, 2]") == ["request must be a JSON object"]


def test_differing_request_fields_are_listed_by_name():
    body = json.loads(request_bytes())
    del body["reason"]
    body["extra"] = 1
    assert refusal(json.dumps(body).encode()) == ["request fields differ: missing ['reason'], unknown ['extra']"]


def test_a_device_that_is_not_an_alias_is_refused_by_name():
    assert refusal(request_bytes(device="-lab")) == ["device must be an inventory alias"]


def test_an_empty_table_is_refused_naming_the_table():
    assert refusal(request_bytes(table=" ")) == ["table must be a non-empty string"]


def test_a_table_of_sixty_five_characters_is_refused_naming_the_limit():
    assert refusal(request_bytes(table="t" * 65)) == ["table is longer than 64 characters"]
    assert parse_request(request_bytes(table="t" * 64)).table == "t" * 64


def test_an_unknown_op_is_refused_listing_the_ops():
    assert refusal(request_bytes(op="replace")) == ["op must be one of %s" % ", ".join(OPS)]
    assert refusal(request_bytes(op="replace")) == ["op must be one of create, update, delete"]


def test_changes_that_are_not_an_object_are_refused_by_name():
    assert refusal(request_bytes(changes=["subnet"])) == ["changes must be an object"]


def test_exactly_the_maximum_number_of_changes_is_accepted():
    changes = {"a%d" % index: "x" for index in range(MAX_CHANGES)}
    assert len(parse_request(request_bytes(changes=changes)).changes) == MAX_CHANGES


def test_one_change_over_the_maximum_is_refused_naming_the_maximum():
    changes = {"a%d" % index: "x" for index in range(MAX_CHANGES + 1)}
    assert refusal(request_bytes(changes=changes)) == ["changes name more than 16 attributes"]


def test_a_bad_attribute_name_is_shown_cut_to_sixty_four_characters():
    name = "A" + "b" * 80
    assert refusal(request_bytes(changes={name: "x"})) == ["attribute name %r is not a CLI attribute name" % name[:64]]


def test_an_attribute_value_of_another_type_is_refused_naming_the_attribute():
    assert refusal(request_bytes(changes={"subnet": 1.5})) == [
        "attribute subnet: value must be a string, an integer or null"]


def test_a_malformed_request_id_is_refused_naming_the_pattern():
    assert refusal(request_bytes(request_id="short")) == ["request_id must match %s" % REQUEST_ID.pattern]
    assert refusal(request_bytes(request_id="short")) == ["request_id must match ^[A-Za-z0-9._:-]{8,64}$"]


def test_an_empty_user_request_is_refused_naming_the_field():
    assert refusal(request_bytes(user_request="")) == ["user_request must be a non-empty string"]
