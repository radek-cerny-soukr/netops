import unittest
from unittest.mock import patch
import jsonschema
from netops import gateway

def baseline(schema,arguments):
    validator=jsonschema.validators.validator_for(schema)
    validator.check_schema(schema)
    return next(validator(schema).iter_errors(arguments),None)

def signature(error):
    if error is None:return None
    return (error.validator,list(error.absolute_path),list(error.absolute_schema_path),error.message,error.validator_value)

class ValidationItems(unittest.TestCase):
    def compare(self,schema,instance):
        def captured(fn):
            try:return ("arguments",signature(fn(schema,instance)))
            except jsonschema.SchemaError as error:return ("schema",signature(error))
        self.assertEqual(captured(gateway.argument_error),captured(baseline),(schema,instance))
    def test_supported_drafts_preserve_first_error_and_validity(self):
        arrays=[[],["x"],["x","y"],["x",0],["x",True],[None],{},None,"text"]
        schemas=[
            {"type":"array","items":{"type":"string"}},
            {"type":"array","items":{"type":"string"},"minItems":2},
            {"type":"array","items":{"type":"string"},"maxItems":1},
            {"type":"array","items":{"type":"string"},"uniqueItems":True},
            {"type":"object","required":["missing"],"properties":{"oids":{"type":"array","items":{"type":"string"}}}},
        ]
        for validator in (jsonschema.Draft3Validator,jsonschema.Draft4Validator,jsonschema.Draft6Validator,jsonschema.Draft7Validator,jsonschema.Draft201909Validator,jsonschema.Draft202012Validator):
            for schema in schemas:
                if validator is jsonschema.Draft3Validator and "required" in schema:
                    schema={"type":"object","properties":{"missing":{"type":"string","required":True},"oids":{"type":"array","items":{"type":"string"}}}}
                schema={**schema,"$schema":validator.META_SCHEMA["id" if validator in (jsonschema.Draft3Validator,jsonschema.Draft4Validator) else "$id"]}
                for values in arrays:
                    with self.subTest(draft=validator.__name__,schema=schema,values=values):self.compare(schema,values)
    def test_item_constraints_and_schema_references_delegate(self):
        item_schemas=[{"type":"string","maxLength":1},{"type":"string","enum":["x"]},{"type":"string","pattern":"^x$"},
                      {"$ref":"#/$defs/item"},False,{},{"anyOf":[{"type":"integer"},{"type":"string","minLength":2}]}]
        for items in item_schemas:
            for values in ([],["x"],["xx"],["x",True],[0],["x","x"]):
                self.compare({"type":"array","items":items,"$defs":{"item":{"type":"string","minLength":2}}},values)
    def test_prefix_tuple_contains_and_unevaluated_items_preserve_semantics(self):
        schemas=[
            {"type":"array","prefixItems":[{"type":"integer"}],"items":{"type":"string"}},
            {"type":"array","prefixItems":[],"items":{"type":"string"}},
            {"type":"array","items":{"type":"string"},"contains":{"const":"x"},"minContains":2,"maxContains":2},
            {"type":"array","items":{"type":"string"},"unevaluatedItems":False},
            {"type":"array","allOf":[{"items":{"type":"string"}}],"unevaluatedItems":False},
            {"type":"array","items":{"type":"string"},"not":{"contains":{"const":"blocked"}}},
            {"type":"array","items":{"type":"string"},"if":{"minItems":2},"then":{"maxItems":2}},
            {"$schema":"http://json-schema.org/draft-07/schema#","items":[{"type":"integer"}],"additionalItems":False},
        ]
        for schema in schemas:
            for values in ([],["x"],["x","x"],[1,"x"],["x","y","z"],["blocked"],[True]):
                self.compare(schema,values)
    def test_subclasses_and_cache_do_not_change_the_original_validator(self):
        class Text(str):pass
        class Array(list):pass
        for value in ([Text("x")],Array(["x"]),Array([False])):
            self.compare({"type":"array","items":{"type":"string"}},value)
        original=jsonschema.Draft202012Validator.VALIDATORS["items"]
        a=gateway.argument_validator(jsonschema.Draft202012Validator)
        b=gateway.argument_validator(jsonschema.Draft202012Validator)
        self.assertIs(a,b)
        self.assertIs(jsonschema.Draft202012Validator.VALIDATORS["items"],original)

    def test_differential_control_rejects_a_validator_that_accepts_invalid_items(self):
        with patch.object(gateway,"argument_error",return_value=None):
            with self.assertRaises(AssertionError):
                self.compare({"type":"array","items":{"type":"string"}},["x",True])
