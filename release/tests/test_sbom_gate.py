import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from jsonschema.exceptions import FormatError
from referencing.exceptions import Unresolvable
import sbom_gate
from test_sbom_contract import sbom
from test_candidate_manifest import A, IMAGE


class SBOMGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "sbom.json"

    def tearDown(self):
        self.tmp.cleanup()

    def validate(self, value):
        self.path.write_text(json.dumps(value))
        sbom_gate.validate_sbom(self.path, IMAGE, A)

    def test_gate_imports_without_deprecation_warning(self):
        proc = subprocess.run([sys.executable, "-B", "-W", "error::DeprecationWarning", "-c", "import sbom_gate"],
                              cwd=Path(sbom_gate.__file__).parent, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_sbom_lock_installs_wheels_only(self):
        root = Path(sbom_gate.__file__).resolve().parents[1]
        installs = []
        for name in (".github/workflows/ci.yml", ".github/workflows/candidate.yml", "release/SBOM-VALIDATION.md"):
            installs += [line for line in (root / name).read_text().splitlines() if "requirements-sbom.lock" in line
                         and "pip install" in line]
        self.assertEqual(len(installs), 4)
        for line in installs:
            self.assertIn("--only-binary=:all: --require-hashes", line)

    def test_full_schema_rejects_deep_component_and_license_errors(self):
        for change in ("type", "license"):
            value = sbom(A)
            if change == "type":
                value["components"][0]["type"] = "invented-component-type"
            else:
                value["components"][0]["licenses"] = [{"license": {"id": "not-an-spdx-license"}}]
            with self.subTest(change=change), self.assertRaises(sbom_gate.SBOMError):
                self.validate(value)

    def test_vendored_schema_mutation_is_rejected(self):
        target = Path(self.tmp.name) / "schema"
        shutil.copytree(sbom_gate.SCHEMA_DIR, target)
        path = target / "spdx.schema.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(sbom_gate.SBOMError, "integrity"):
            sbom_gate.load_validator(target)

    def test_unknown_remote_reference_never_retrieves(self):
        validator = sbom_gate.load_validator()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            with self.assertRaises(Unresolvable):
                validator._registry.resolver().lookup("https://untrusted.invalid/schema.json")

    def test_all_schema_formats_reject_invalid_values(self):
        checker = sbom_gate.load_validator().format_checker
        invalid = {"date": "2026-02-30", "date-time": "not-a-date",
                   "idn-email": "no-at-sign", "iri-reference": "http://[",
                   "uri": "relative/path"}
        self.assertEqual(set(checker.checkers), set(invalid))
        for name, value in invalid.items():
            with self.subTest(format=name), self.assertRaises(FormatError):
                checker.check(value, name)
        with self.assertRaises(FormatError):
            checker.check("anything", "unknown-format")

    def test_missing_format_checker_fails_closed(self):
        checkers = copy.copy(sbom_gate.StrictFormatChecker.checkers)
        del checkers["iri-reference"]
        with patch.object(sbom_gate.StrictFormatChecker, "checkers", checkers):
            with self.assertRaisesRegex(sbom_gate.SBOMError, "dependency"):
                sbom_gate.load_validator()

    def test_invalid_timestamp_rejected_by_full_schema(self):
        value = sbom(A)
        value["metadata"]["timestamp"] = "not-a-date"
        with self.assertRaises(sbom_gate.SBOMError):
            self.validate(value)

    def test_input_schema_url_is_inert_data_not_a_retrieval_target(self):
        value = sbom(A)
        value["$schema"] = "https://untrusted.invalid/schema.json"
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.validate(value)

    def test_non_json_numeric_constants_are_rejected(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            value = sbom(A)
            value["components"][0]["evidence"] = {"identity": {"field": "name", "confidence": "CONSTANT"}}
            raw = json.dumps(value).replace('"CONSTANT"', constant)
            self.path.write_text(raw)
            with self.subTest(constant=constant), self.assertRaises(sbom_gate.SBOMError):
                sbom_gate.validate_sbom(self.path, IMAGE, A)

    def test_valid_json_number_overflow_exceeds_confidence_maximum(self):
        value = sbom(A)
        value["components"][0]["evidence"] = {"identity": {"field": "name", "confidence": "CONSTANT"}}
        self.path.write_text(json.dumps(value).replace('"CONSTANT"', "1e999"))
        with self.assertRaises(sbom_gate.SBOMError):
            sbom_gate.validate_sbom(self.path, IMAGE, A)

    def test_malformed_json_is_rejected(self):
        self.path.write_text("{")
        with self.assertRaises(sbom_gate.SBOMError):
            sbom_gate.validate_sbom(self.path, IMAGE, A)

    def test_duplicate_json_keys_are_rejected(self):
        raw = json.dumps(sbom(A)).replace('"name": ', '"name": "other-image", "name": ', 1)
        self.assertEqual(json.loads(raw)["metadata"]["component"]["name"], IMAGE)
        self.path.write_text(raw)
        with self.assertRaisesRegex(sbom_gate.SBOMError, "duplicate key"):
            sbom_gate.validate_sbom(self.path, IMAGE, A)

    def test_deep_nesting_is_refused_without_traceback(self):
        leaf = json.dumps(sbom(A)["components"][0])
        component = leaf
        for _ in range(1000):
            component = leaf[:-1] + ', "components": [' + component + "]}"
        cases = {"decoder": json.dumps(sbom(A)).replace('"CycloneDX"', '"CycloneDX", "x": ' + "[" * 100000 + "]" * 100000),
                 "validator": json.dumps(sbom(A)).replace(leaf, component, 1)}
        for stage, raw in cases.items():
            self.path.write_text(raw)
            with self.subTest(stage=stage), self.assertRaisesRegex(sbom_gate.SBOMError, "nested too deeply"):
                sbom_gate.validate_sbom(self.path, IMAGE, A)

    def test_extra_root_properties_and_remote_schema_input_rejected(self):
        for key in ("unexpected", "$ref"):
            value = sbom(A)
            value[key] = "https://untrusted.invalid/schema.json"
            with self.subTest(key=key), self.assertRaises(sbom_gate.SBOMError):
                self.validate(value)


if __name__ == "__main__":
    unittest.main()
