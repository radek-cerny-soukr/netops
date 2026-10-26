import json
import os
import shutil
import unittest

import test_candidate_manifest as candidate


def sbom(digest):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {"component": {"type": "container", "name": candidate.IMAGE, "version": digest}},
        "components": [{"type": "library", "name": "synthetic-package", "version": "1.0"}],
    }


class SBOMContract(unittest.TestCase):
    write = candidate.CandidateManifest.write
    run_tool = candidate.CandidateManifest.run_tool
    tearDown = candidate.CandidateManifest.tearDown

    def setUp(self):
        candidate.CandidateManifest.setUp(self)
        for arch, digest in (("amd64", candidate.A), ("arm64", candidate.B)):
            self.write_sbom(arch, sbom(digest))

    def write_sbom(self, arch, value):
        self.write("sbom-%s.cdx.json" % arch, json.dumps(value))

    def refused_without_candidate(self):
        rc, manifest, error = self.run_tool()
        self.assertEqual(rc, 1, "invalid SBOM accepted: %s" % error)
        self.assertIsNone(manifest)
        self.assertIn("sbom", error.lower())
        self.assertFalse(os.path.exists(self.release), "invalid SBOM wrote candidate output")

    def test_valid_minimal_sboms_match_both_architectures(self):
        rc, manifest, error = self.run_tool()
        self.assertEqual(rc, 0, error)
        self.assertEqual(manifest["image"]["platforms"]["amd64"]["digest"], candidate.A)
        self.assertEqual(manifest["image"]["platforms"]["arm64"]["digest"], candidate.B)

    def test_schema_requires_component_name(self):
        value = sbom(candidate.A)
        value["components"] = [{"type": "library"}]
        self.write_sbom("amd64", value)
        self.refused_without_candidate()

    def test_schema_rejects_wrong_bom_format(self):
        value = sbom(candidate.A)
        value["bomFormat"] = "not-CycloneDX"
        self.write_sbom("amd64", value)
        self.refused_without_candidate()

    def test_spec_version_must_be_exactly_1_7(self):
        value = sbom(candidate.A)
        value["specVersion"] = "1.6"
        self.write_sbom("amd64", value)
        self.refused_without_candidate()

    def test_components_must_not_be_empty(self):
        value = sbom(candidate.A)
        value["components"] = []
        self.write_sbom("amd64", value)
        self.refused_without_candidate()

    def test_root_component_must_be_container(self):
        value = sbom(candidate.A)
        value["metadata"]["component"]["type"] = "application"
        self.write_sbom("amd64", value)
        self.refused_without_candidate()

    def test_root_name_must_equal_candidate_image(self):
        value = sbom(candidate.A)
        value["metadata"]["component"]["name"] = candidate.IMAGE + "-other"
        self.write_sbom("amd64", value)
        self.refused_without_candidate()

    def test_root_version_must_equal_exact_arch_digest(self):
        value = sbom(candidate.A)
        value["metadata"]["component"]["version"] = candidate.IMAGE + "@" + candidate.A
        self.write_sbom("amd64", value)
        self.refused_without_candidate()

    def test_duplicate_key_and_deep_nesting_fail_without_traceback(self):
        raw = json.dumps(sbom(candidate.A))
        for case in (raw.replace('"name": ', '"name": "other-image", "name": ', 1),
                     raw.replace('"CycloneDX"', '"CycloneDX", "x": ' + "[" * 100000 + "]" * 100000)):
            shutil.rmtree(self.release, ignore_errors=True)
            self.write("sbom-amd64.cdx.json", case)
            with self.subTest(case=case[:60]):
                rc, manifest, error = self.run_tool()
                self.assertEqual((rc, manifest), (1, None), error)
                self.assertTrue(error.startswith("candidate_manifest=failed: sbom "), error)
                self.assertFalse(os.path.exists(self.release))

    def test_swapped_sbom_architectures_are_rejected(self):
        self.write_sbom("amd64", sbom(candidate.B))
        self.write_sbom("arm64", sbom(candidate.A))
        self.refused_without_candidate()


if __name__ == "__main__":
    unittest.main()
