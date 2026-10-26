import argparse
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urldefrag, urljoin

from jsonschema import Draft7Validator, FormatChecker
from jsonschema.exceptions import FormatError, ValidationError
from referencing import Registry
from referencing.exceptions import NoSuchResource, Unresolvable
from referencing.jsonschema import DRAFT7

SCHEMA_DIR = Path(__file__).parent / "schema" / "cyclonedx-1.7"
FORMATS = ("date", "date-time", "idn-email", "iri-reference", "uri")
PINS = {
    "bom-1.7.schema.json": "df472ef4aaf593904c479293723a1a5c191d6672715c93b3c0b5c318f3914221",
    "spdx.schema.json": "54a6288292bc6c90b0d3952f5f939f17436fa76704ffe68a46e5b78539c7cc1b",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
    "cryptography-defs.schema.json": "018ea7f78b5208ec647cfd10f669cc9c26aba6aceb79c4da7f9c0ef4c99b60de",
}


class SBOMError(ValueError):
    pass


class StrictFormatChecker(FormatChecker):
    def check(self, instance, format):
        if format not in self.checkers:
            raise FormatError("unsupported schema format")
        return super().check(instance, format)


def reject_constant(value):
    raise SBOMError("sbom contains an invalid JSON numeric constant")


def reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SBOMError("sbom contains a duplicate key within one object")
        value[key] = item
    return value


def offline(uri):
    raise NoSuchResource(ref=uri)


def schema_nodes(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from schema_nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from schema_nodes(child)


def load_validator(schema_dir=SCHEMA_DIR):
    schemas = {}
    for name, expected in PINS.items():
        raw = (Path(schema_dir) / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise SBOMError("sbom schema integrity failure: " + name)
        value = json.loads(raw)
        uri = "http://cyclonedx.org/schema/" + name
        if value.get("$id") != uri:
            raise SBOMError("sbom schema identity failure: " + name)
        schemas[uri] = value
    registry = Registry(retrieve=offline).with_resources(
        (uri, DRAFT7.create_resource(value)) for uri, value in schemas.items()
    )
    formats = set()
    for uri, value in schemas.items():
        for node in schema_nodes(value):
            if isinstance(node.get("format"), str):
                formats.add(node["format"])
            if isinstance(node.get("$ref"), str):
                target, _ = urldefrag(urljoin(uri, node["$ref"]))
                if target not in schemas:
                    raise SBOMError("sbom schema reference is not vendored")
                registry.resolver(base_uri=uri).lookup(node["$ref"])
    if formats != set(FORMATS):
        raise SBOMError("sbom schema format coverage changed")
    try:
        checker = StrictFormatChecker(formats=FORMATS)
    except KeyError as error:
        raise SBOMError("sbom format dependency missing") from error
    return Draft7Validator(schemas["http://cyclonedx.org/schema/bom-1.7.schema.json"],
                           registry=registry, format_checker=checker)


def too_deep(value, limit=200):
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(node, dict):
            stack.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, list):
            stack.extend((item, depth + 1) for item in node)
    return False


def validate_sbom(path, image, digest):
    try:
        value = json.loads(Path(path).read_bytes(), parse_constant=reject_constant,
                           object_pairs_hook=reject_duplicate_keys)
        if too_deep(value):
            raise SBOMError("sbom is nested too deeply")
        load_validator().validate(value)
        if value["specVersion"] != "1.7":
            raise SBOMError("sbom specVersion must be 1.7")
        if not value.get("components"):
            raise SBOMError("sbom components must be nonempty")
        root = value.get("metadata", {}).get("component", {})
        if root.get("type") != "container" or root.get("name") != image or root.get("version") != digest:
            raise SBOMError("sbom root container must match image and architecture digest exactly")
    except ValidationError as error:
        raise SBOMError("sbom does not match the complete CycloneDX 1.7 schema") from error
    except RecursionError as error:
        raise SBOMError("sbom is nested too deeply") from error
    except (OSError, ValueError, Unresolvable) as error:
        if isinstance(error, SBOMError):
            raise
        raise SBOMError("sbom cannot be validated offline") from error


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--image", required=True)
    parser.add_argument("--digest", required=True)
    args = parser.parse_args()
    try:
        validate_sbom(args.path, args.image, args.digest)
    except SBOMError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("sbom=pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
