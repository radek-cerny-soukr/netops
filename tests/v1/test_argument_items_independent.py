import random
import time
import unittest

import jsonschema

from netops import gateway


def original(schema, arguments):
    validator = jsonschema.validators.validator_for(schema)
    validator.check_schema(schema)
    return next(validator(schema).iter_errors(arguments), None)


def outcome(function, schema, instance):
    try:
        error = function(schema, instance)
    except jsonschema.SchemaError as failure:
        return ("schema_error", failure.validator, tuple(failure.path), tuple(failure.schema_path), failure.message)
    if error is None:
        return None
    return (error.validator, tuple(error.path), tuple(error.schema_path), error.message, repr(error.validator_value))


class Str(str):
    pass


STRING = {"type": "string"}


def wrap(oids, **extra):
    return {"type": "object", "properties": {"target": {"type": "string"}, "oids": oids}, "required": ["target", "oids"], **extra}


SCHEMAS = [
    wrap({"type": "array", "items": STRING}),
    wrap({"type": "array", "items": STRING}, additionalProperties=False),
    wrap({"type": "array", "prefixItems": [{"type": "integer"}], "items": STRING}),
    wrap({"type": "array", "prefixItems": [], "items": STRING}),
    wrap({"type": "array", "items": {"type": "string", "maxLength": 2}}),
    wrap({"type": "array", "items": {"type": ["string"]}}),
    wrap({"type": "array", "items": {"type": "string", "enum": ["[x]", "a"]}}),
    wrap({"type": "array", "items": {"type": "string", "pattern": "^a"}}),
    wrap({"type": "array", "items": {"$ref": "#/$defs/s"}}, **{"$defs": {"s": STRING}}),
    wrap({"type": "array", "items": STRING, "unevaluatedItems": False}),
    wrap({"type": "array", "items": STRING, "contains": {"const": "a"}, "minContains": 2}),
    wrap({"type": "array", "items": STRING, "uniqueItems": True}),
    wrap({"type": "array", "items": STRING, "maxItems": 3}),
    wrap({"type": "array", "items": {"type": "array", "items": STRING}}),
    wrap({"type": "array", "items": True}),
    wrap({"type": "array", "items": False}),
    wrap({"type": "array", "items": 5}),
    dict(wrap({"type": "array", "items": STRING}), **{"$schema": "http://json-schema.org/draft-07/schema#"}),
    dict(wrap({"type": "array", "items": [STRING, {"type": "integer"}], "additionalItems": STRING}), **{"$schema": "http://json-schema.org/draft-07/schema#"}),
    dict(wrap({"type": "array", "items": STRING}), **{"$schema": "http://json-schema.org/draft-04/schema#"}),
    dict(wrap({"type": "array", "items": STRING}), **{"$schema": "https://json-schema.org/draft/2019-09/schema"}),
    dict(wrap({"type": "array", "items": STRING, "unevaluatedItems": False}), **{"$schema": "https://json-schema.org/draft/2019-09/schema"}),
]

FIXED = [[], ["a"], ["[x]"] * 50, ["a", 1], [1, "a"], ["a"] * 30 + [None], ["a", True], [["a"]], [["a"], ["b", 2]],
         [Str("a")], ["a", "a"], ["a", "b", "c", "d"], ["ab", "abc"], ("a",), "a", None, {"a": 1}, [1.5], ["a", ["b"]]]


def instances(rng, count):
    atoms = ["a", "[x]", "", "ab", "abc", 0, 1, True, False, None, 1.5, Str("a"), ["a"], ["b", 1], {"k": "v"}]
    for _ in range(count):
        size = rng.choice([0, 1, 2, 3, 5, 40])
        mostly = rng.random() < 0.6
        items = [("a" if rng.random() < 0.9 else rng.choice(atoms)) if mostly else rng.choice(atoms) for _ in range(size)]
        yield items


class ItemsDifferential(unittest.TestCase):
    def compare(self, function):
        mismatches = []
        rng = random.Random(20261016)
        for number, schema in enumerate(SCHEMAS):
            for oids in FIXED + list(instances(rng, 150)):
                for arguments in ({"target": "t", "oids": oids}, {"oids": oids}, {"target": 1, "oids": oids}):
                    expected = outcome(original, schema, arguments)
                    actual = outcome(function, schema, arguments)
                    if expected != actual:
                        mismatches.append((number, repr(arguments)[:80], expected, actual))
        return mismatches

    def test_first_error_and_schema_errors_match_the_original_everywhere(self):
        mismatches = self.compare(gateway.argument_error)
        self.assertEqual(mismatches[:5], [], "%d mismatches" % len(mismatches))

    def test_the_differential_detects_an_always_accept_items_mutant(self):
        def mutant(schema, arguments):
            validator = jsonschema.validators.validator_for(schema)
            validator.check_schema(schema)
            def accept(validator, items, instance, schema):
                return
                yield
            return next(jsonschema.validators.extend(validator, {"items": accept})(schema).iter_errors(arguments), None)
        self.assertGreater(len(self.compare(mutant)), 0)

    def test_the_differential_detects_a_type_confusion_mutant(self):
        def mutant(schema, arguments):
            validator = jsonschema.validators.validator_for(schema)
            validator.check_schema(schema)
            original_items = validator.VALIDATORS["items"]
            def loose(validator, items, instance, schema):
                if items == STRING and type(instance) is list and all(isinstance(i, (str, int)) for i in instance):
                    return
                yield from original_items(validator, items, instance, schema)
            return next(jsonschema.validators.extend(validator, {"items": loose})(schema).iter_errors(arguments), None)
        self.assertGreater(len(self.compare(mutant)), 0)

    def test_maximal_string_array_is_validated_quickly_and_still_rejects_a_late_bad_item(self):
        schema = SCHEMAS[1]
        oids = ["[x]"] * 699027
        start = time.perf_counter()
        self.assertIsNone(gateway.argument_error(schema, {"target": "t", "oids": oids}))
        elapsed = time.perf_counter() - start
        print("maximal valid array %.3f s" % elapsed, flush=True)
        self.assertLess(elapsed, 2.0)
        oids[-1] = 7
        error = gateway.argument_error(schema, {"target": "t", "oids": oids})
        self.assertEqual((error.validator, tuple(error.path)), ("type", ("oids", 699026)))


if __name__ == "__main__":
    unittest.main()
