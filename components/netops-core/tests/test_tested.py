import pytest

from netops_core import tested


def test_listed_version_is_tested_without_a_message():
    result = tested.support("FortiOS", "7.6.8 build3744", ["7.6.8 build3744", "8.0.2 build0251"])
    assert result == {"status": "tested", "platform": "FortiOS", "device_version": "7.6.8 build3744", "model": None,
                      "tested_versions": ["7.6.8 build3744", "8.0.2 build0251"], "message": None}
    assert tested.is_tested(result) and tested.warning(result) is None and tested.valid(result)


@pytest.mark.parametrize("version", ["7.6.9 build3800", "7.6.8 build3745", "7.6.8", "8.0.2 build0251 "])
def test_any_other_version_is_untested_exact_string_comparison(version):
    result = tested.support("FortiOS", version, ["7.6.8 build3744", "8.0.2 build0251"], function="triage_health")
    assert result["status"] == "untested" and result["device_version"] == version
    assert result["message"] == ("FortiOS %s is not among the versions triage_health was tested on"
                                 " (7.6.8 build3744, 8.0.2 build0251). It may or may not work as designed and"
                                 " tested; check the result." % version)
    assert not tested.is_tested(result) and tested.valid(result)
    assert tested.warning(result) == {"code": "firmware_untested", "message": result["message"]}


def test_model_is_compared_only_when_the_list_names_it():
    pairs = [("FortiGate-60F", "7.6.8 build3744"), ("FortiGate-80F", "8.0.2 build0251")]
    assert tested.support("FortiOS", "7.6.8 build3744", pairs, model="FortiGate-60F")["status"] == "tested"
    other = tested.support("FortiOS", "7.6.8 build3744", pairs, model="FortiGate-80F")
    assert other["status"] == "untested" and " on FortiGate-80F " in other["message"]
    assert other["tested_versions"] == ["FortiGate-60F 7.6.8 build3744", "FortiGate-80F 8.0.2 build0251"]
    assert tested.support("ExtremeXOS", "33.7.1.6", ["33.7.1.6"], model="X435-8P-4S")["status"] == "tested"


@pytest.mark.parametrize("version", [None, ""])
def test_unreadable_version_is_unknown(version):
    result = tested.support("ExtremeXOS", version, ["33.7.1.6"])
    assert result["status"] == "unknown" and result["device_version"] is None
    assert "could not be read" in result["message"] and tested.valid(result)
    assert tested.warning(result)["code"] == "firmware_untested"


@pytest.mark.parametrize("listed", [[], [""], [("model",)], [3]])
def test_a_function_needs_tested_versions(listed):
    with pytest.raises(ValueError):
        tested.support("FortiOS", "7.6.8 build3744", listed)


@pytest.mark.parametrize("damage", [
    {"status": "maybe"}, {"tested_versions": "7.6.8"}, {"message": None}, {"extra": 1}, {"platform": None},
])
def test_valid_rejects_damaged_structures(damage):
    result = tested.support("FortiOS", "7.6.9 build1", ["7.6.8 build3744"])
    assert not tested.valid(dict(result, **damage))
    assert not tested.valid(None) and not tested.valid([])
